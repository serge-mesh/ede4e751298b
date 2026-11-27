//! Reading the query log for the UI (core.md §12; api.md §7): the record and detail shapes, the
//! search, the top lists, devices, the device and profile summaries, the trial view and the
//! reply a client got.
//!
//! Every read is bounded: searches page with a cursor (at most [`MAX_LIMIT`] records a page,
//! newest partition first), aggregates read each partition in the window once and merge its rows
//! in a temporary SQLite table, so a window's distinct names never sit in RAM, and lists cap
//! their items. Text from outside core (names, devices, rule text, verdict details) is returned as
//! data; the UI renders it as text only (core.md §12).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Instant, SystemTime};

use anyhow::Result;
use base64::Engine;
use jiff::{SignedDuration, Timestamp};
use rusqlite::{Connection, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use super::attribution::{Attribution, Match};
use super::partition::{LogStore, Partition, hour_start};
use super::record::{self, Rec};

/// Records one search page holds at most.
pub const MAX_LIMIT: usize = 500;
/// Devices `GET devices` lists at most, and addresses per device.
pub const MAX_DEVICES: usize = 5000;
const MAX_ADDRESSES: usize = 32;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// One query record as the log search returns it (api.md §5 `q` records).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct LogRecord {
    /// The record's id in this API (its hour, edge, boot and seq).
    pub id: String,
    pub ts: String,
    pub edge: String,
    pub boot: String,
    pub seq: i64,
    pub listener: String,
    /// `udp`, `tcp`, `dot` or `doh`.
    pub proto: String,
    /// The source address.
    pub client: String,
    /// The client's name, else the device's MAC, else null.
    pub device: Option<String>,
    pub profile: Option<String>,
    pub qname: String,
    pub qtype: String,
    pub rcode: String,
    /// `allow`, `block`, `rewrite`, `refused` or `servfail`.
    pub decision: String,
    /// What decided (api.md §5 `reason`).
    pub reason: Option<Json>,
    pub answers: Vec<String>,
    pub targets: Vec<String>,
    pub cname: Vec<String>,
    pub truncated: bool,
    pub tc: bool,
    pub answer_id: Option<String>,
    pub received_at: Option<String>,
    pub age_s: Option<i64>,
    /// Core never got the referenced answer: only the preview is known.
    pub answer_missing: bool,
    /// The client's DO bit.
    #[serde(rename = "do")]
    pub client_do: bool,
    pub upstream: Option<Json>,
    pub fw: Option<Json>,
    pub us: Option<Json>,
    /// Bundles whose cold check the edge couldn't make.
    pub cold_unchecked: Vec<String>,
    /// The wire check's result: `ok`, `mismatch`, `skipped`, or null before it ran.
    pub wire_check: Option<String>,
    /// When the trial check ran (null before it, or for a record it doesn't check).
    pub trial_check: Option<String>,
    /// Core's check of unchecked cold lookups: `ok`, `missed` or `unavailable`.
    pub cold_check: Option<String>,
    /// Only the preview is known (`truncated` or `answer_missing`).
    pub incomplete: bool,
}

fn parse_json(s: &Option<String>) -> Option<Json> {
    s.as_deref().and_then(|s| serde_json::from_str(s).ok())
}

/// The API shape of a record.
pub fn record_view(r: &Rec) -> LogRecord {
    LogRecord {
        id: r.api_id(),
        ts: r.ts.clone(),
        edge: r.edge.clone(),
        boot: r.boot.clone(),
        seq: r.seq,
        listener: r.listener.clone(),
        proto: r.proto.clone(),
        client: r.client_ip.clone(),
        device: r.device.clone(),
        profile: r.profile.clone(),
        qname: r.qname.clone(),
        qtype: r.qtype.clone(),
        rcode: r.rcode.clone(),
        decision: r.decision.clone(),
        reason: r.reason.as_ref().and_then(|x| serde_json::to_value(x).ok()),
        answers: r.answers.clone(),
        targets: r.targets.clone(),
        cname: r.cname.clone(),
        truncated: r.truncated,
        tc: r.tc,
        answer_id: r.answer_id.clone(),
        received_at: r.received_at.clone(),
        age_s: r.age_s,
        answer_missing: r.answer_missing,
        client_do: r.client_do,
        upstream: parse_json(&r.upstream_json),
        fw: parse_json(&r.fw_json),
        us: parse_json(&r.timings_json),
        cold_unchecked: r.cold_unchecked.clone(),
        wire_check: r.wire_check.clone(),
        trial_check: r.trial_check.clone(),
        cold_check: r.cold_check.clone(),
        incomplete: r.incomplete(),
    }
}

/// A page of records.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct LogPage {
    pub items: Vec<LogRecord>,
    /// Pass as `cursor` for the next page; null on the last page.
    pub next_cursor: Option<String>,
}

/// `GET logs` filters (core.md §12 query log).
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct LogQuery {
    /// Oldest event time (RFC 3339); default the retention window's start.
    pub from: Option<String>,
    /// Newest event time (RFC 3339); default now.
    pub to: Option<String>,
    /// An edge id (`all` or absent: every edge).
    pub edge: Option<String>,
    /// The client's address.
    pub client: Option<String>,
    pub device: Option<String>,
    pub qname: Option<String>,
    /// How `qname` matches: `exact`, `suffix` (default: the name and every name below it) or
    /// `substring`.
    #[serde(rename = "match")]
    pub match_: Option<String>,
    pub decision: Option<String>,
    pub profile: Option<String>,
    /// The deciding bundle.
    pub bundle: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

/// A refusal of a query parameter (`400`).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BadQuery(pub String);

#[derive(Serialize, Deserialize)]
struct Cursor {
    h: String,
    ts: String,
    e: String,
    b: String,
    s: i64,
}

fn bad(m: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(BadQuery(m.into()))
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

fn short(field: &str, v: &Option<String>, max: usize) -> Result<Option<String>> {
    match v.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) if s.len() > max || s.chars().any(char::is_control) => {
            Err(bad(format!("{field}: at most {max} printable characters")))
        }
        Some(s) => Ok(Some(s.to_string())),
    }
}

fn time(field: &str, v: &Option<String>) -> Result<Option<Timestamp>> {
    match v.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => match picket_api::time::parse(s) {
            Ok(t) => Ok(Some(t)),
            // A real time past the timestamp range (the UI's date picker can send
            // 9999-12-31T23:59:00.000Z): the range's end, as a bound it means the same.
            Err(picket_api::time::ParseError::OutOfRange) => Ok(Some(Timestamp::MAX)),
            Err(picket_api::time::ParseError::Invalid) => Err(bad(format!("{field}: an RFC 3339 time"))),
        },
    }
}

/// The partitions in `[from, to]`, newest first.
fn partitions_between(store: &LogStore, from: Timestamp, to: Timestamp) -> Result<Vec<Timestamp>> {
    let lo = hour_start(&from);
    let mut v: Vec<Timestamp> = store
        .list()?
        .into_iter()
        .map(|(h, _)| h)
        .filter(|h| *h >= lo && *h <= to)
        .collect();
    v.reverse();
    Ok(v)
}

/// `GET logs`: the records matching `q`, newest first, a page at a time.
pub fn search(
    store: &LogStore,
    q: &LogQuery,
    retention: std::time::Duration,
    now: Timestamp,
) -> Result<LogPage> {
    // Checked as every UI API `limit` is (`web::api::limit_param`).
    let limit = match q.limit {
        None => 100,
        Some(n) if (1..=MAX_LIMIT).contains(&n) => n,
        Some(_) => return Err(bad(format!("limit: 1 to {MAX_LIMIT}"))),
    };
    let oldest = crate::util::window_start(now, retention);
    let from = time("from", &q.from)?.unwrap_or(oldest).max(oldest);
    let to = time("to", &q.to)?.unwrap_or(now);
    let edge = short("edge", &q.edge, 256)?.filter(|e| e != "all");
    let client = short("client", &q.client, 64)?;
    let device = short("device", &q.device, 256)?;
    let qname = short("qname", &q.qname, 253)?.map(|n| n.trim_end_matches('.').to_ascii_lowercase());
    let mode = short("match", &q.match_, 16)?.unwrap_or_else(|| "suffix".into());
    if !matches!(mode.as_str(), "exact" | "suffix" | "substring") {
        return Err(bad("match: exact, suffix or substring"));
    }
    let decision = short("decision", &q.decision, 16)?;
    if let Some(d) = &decision
        && !matches!(d.as_str(), "allow" | "block" | "rewrite" | "refused" | "servfail")
    {
        return Err(bad("decision: allow, block, rewrite, refused or servfail"));
    }
    let profile = short("profile", &q.profile, 128)?;
    let bundle = short("bundle", &q.bundle, 128)?;
    let cursor: Option<Cursor> = match q.cursor.as_deref().filter(|c| !c.is_empty()) {
        None => None,
        Some(c) => Some(
            crate::web::api::decode_cursor(c)
                .and_then(|s| serde_json::from_str(&s).ok())
                .ok_or_else(|| bad("cursor: the next_cursor of a previous page"))?,
        ),
    };
    let mut items: Vec<LogRecord> = Vec::new();
    let mut last: Option<Rec> = None;
    for hour in partitions_between(store, from, to)? {
        let hs = crate::util::ts(&hour);
        if let Some(c) = &cursor
            && hs > c.h
        {
            continue;
        }
        let Some(p) = store.open(&hour, false)? else {
            continue;
        };
        let mut clause = String::from("WHERE e.ts >= ?1 AND e.ts <= ?2");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> =
            vec![Box::new(crate::util::ts(&from)), Box::new(crate::util::ts(&to))];
        let mut add = |cond: &str, v: Box<dyn rusqlite::ToSql>, clause: &mut String| {
            args.push(v);
            clause.push_str(&cond.replace('?', &format!("?{}", args.len())));
        };
        if let Some(e) = &edge {
            add(" AND e.edge_id = ?", Box::new(e.clone()), &mut clause);
        }
        if let Some(c) = &client {
            add(" AND e.client_ip = ?", Box::new(c.clone()), &mut clause);
        }
        if let Some(d) = &device {
            add(" AND e.device = ?", Box::new(d.clone()), &mut clause);
        }
        if let Some(n) = &qname {
            match mode.as_str() {
                "exact" => add(" AND e.qname = ?", Box::new(n.clone()), &mut clause),
                "substring" => add(" AND instr(e.qname, ?) > 0", Box::new(n.clone()), &mut clause),
                _ => {
                    add(" AND (e.qname = ?", Box::new(n.clone()), &mut clause);
                    add(
                        " OR e.qname LIKE ? ESCAPE '\\')",
                        Box::new(format!("%.{}", like_escape(n))),
                        &mut clause,
                    );
                }
            }
        }
        if let Some(d) = &decision {
            add(" AND e.decision = ?", Box::new(d.clone()), &mut clause);
        }
        if let Some(pr) = &profile {
            add(" AND e.profile = ?", Box::new(pr.clone()), &mut clause);
        }
        if let Some(b) = &bundle {
            add(" AND e.bundle = ?", Box::new(b.clone()), &mut clause);
        }
        if let Some(c) = cursor.as_ref().filter(|c| c.h == hs) {
            args.push(Box::new(c.ts.clone()));
            let a = args.len();
            args.push(Box::new(c.e.clone()));
            args.push(Box::new(c.b.clone()));
            args.push(Box::new(c.s));
            clause.push_str(&format!(
                " AND (e.ts, e.edge_id, e.boot, e.seq) < (?{}, ?{}, ?{}, ?{})",
                a,
                a + 1,
                a + 2,
                a + 3
            ));
        }
        args.push(Box::new(limit - items.len() + 1));
        clause.push_str(&format!(
            " ORDER BY e.ts DESC, e.edge_id DESC, e.boot DESC, e.seq DESC LIMIT ?{}",
            args.len()
        ));
        let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        let recs = record::load(&p, &clause, &refs)?;
        for r in recs {
            if items.len() >= limit {
                // One more exists: the page has a next cursor.
                let l = last.as_ref().unwrap_or(&r);
                let c = Cursor {
                    h: crate::util::ts(&hour_start(&l.time().unwrap_or(hour))),
                    ts: l.ts.clone(),
                    e: l.edge.clone(),
                    b: l.boot.clone(),
                    s: l.seq,
                };
                return Ok(LogPage {
                    items,
                    next_cursor: Some(crate::web::api::encode_cursor(&serde_json::to_string(&c)?)),
                });
            }
            items.push(record_view(&r));
            last = Some(r);
        }
    }
    Ok(LogPage {
        items,
        next_cursor: None,
    })
}

/// The reply a client got (core.md §6 "The reply a client got").
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct Reply {
    /// `response` (the reply the edge made), `tc` (cut to the header, question and OPT),
    /// `answer` (the referenced answer as the edge served it) or `preview` (only the logged
    /// preview is known).
    pub source: String,
    /// Only the preview is known (a reply the edge made whose `response` was left out for size,
    /// or a `truncated`/`answer_missing` record).
    pub incomplete: bool,
    /// The reply's wire, base64.
    pub wire: Option<String>,
    /// Its records, in presentation format.
    pub records: Vec<String>,
    pub rcode: Option<String>,
    pub tc: bool,
}

/// The upstream answer a record references, as evidence.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct AnswerView {
    pub id: String,
    pub received_at: Option<String>,
    pub age_s: Option<i64>,
    /// The scrubbed answer as logged, base64.
    pub wire: String,
    /// Its records, in presentation format.
    pub records: Vec<String>,
}

/// One lookup on the record (api.md §5 `lookups[]`). Every field is always sent, null where it
/// has no value.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(transform = crate::web::openapi::sent_always)]
pub struct LookupView {
    pub provider: String,
    pub verdict: Option<String>,
    pub score: Option<f64>,
    pub reason: Option<String>,
    /// The module's detail of the answer, a small JSON object as logged (providers.md §4, api.md
    /// §5), null when the lookup has none (a cache hit, a timeout, a module that gives none): the
    /// same value an alert's `details.providers[].detail` and an evidence copy's
    /// `lookups[].detail` hold. The UI renders it as text only (core.md §12).
    #[schemars(with = "Option<serde_json::Map<String, Json>>")]
    pub detail: Option<Json>,
    /// `cache` for a verdict from the edge's RAM tier or verdict set, else `provider`.
    pub source: String,
    pub ms: Option<u64>,
    pub timed_out: bool,
    pub retry: bool,
}

/// A record's attribution as the detail shows it.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct AttributionView {
    /// `complete`, `incomplete` or `unavailable` (storage.md §3 `attribution.status`).
    pub state: String,
    /// Every match with its feed, text, line, format and role.
    pub matches: Vec<Match>,
    /// The ladder step and bundle replay found decisive.
    pub decisive: Option<(u8, String)>,
    /// `ok`, `mismatch` or `skipped` (core.md §6 step 4).
    pub self_check: String,
    /// The versions or feed runs that are gone (state `unavailable`).
    pub unavailable: Vec<super::attribution::UnavailableView>,
}

/// A would-block of a trial bundle on the record.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct WouldBlockView {
    pub bundle: String,
    pub head: String,
    pub key: Option<String>,
    pub stage: Option<String>,
    pub status: Option<String>,
    pub matches: Vec<Match>,
}

/// `GET logs/{id}`: the record, the reply the client got, the upstream answer, the attribution
/// with roles, each lookup's verdict, reason and detail, the trial would-blocks and the versions.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct LogDetail {
    #[serde(flatten)]
    pub record: LogRecord,
    pub attribution: Option<AttributionView>,
    pub lookups: Vec<LookupView>,
    pub versions: Option<Json>,
    /// The upstream answer `answer_id` names (separate evidence for a CNAME rewrite).
    pub answer: Option<AnswerView>,
    /// The reply the client got (core.md §6).
    pub response: Reply,
    pub would_blocks: Vec<WouldBlockView>,
}

/// The records of a message in presentation format (decoded with `domain`; bounded).
pub fn records_text(msg: &[u8]) -> Vec<String> {
    use domain::base::Message;
    use domain::base::name::ParsedName;
    use domain::rdata::AllRecordData;
    let Ok(m) = Message::from_octets(msg) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(sections) = m.sections() {
        let (q, a, ns, ar) = sections;
        for qq in q.flatten().take(4) {
            out.push(format!(";{} {} {}", qq.qname(), qq.qclass(), qq.qtype()));
        }
        for sec in [a, ns, ar] {
            for rec in sec.flatten().take(256) {
                match rec.to_record::<AllRecordData<&[u8], ParsedName<&[u8]>>>() {
                    Ok(Some(r)) => out.push(format!(
                        "{} {} {} {} {}",
                        r.owner(),
                        r.ttl().as_secs(),
                        r.class(),
                        r.rtype(),
                        r.data()
                    )),
                    _ => out.push(format!(
                        "{} {} {} {} \\# {}",
                        rec.owner(),
                        rec.ttl().as_secs(),
                        rec.class(),
                        rec.rtype(),
                        rec.rdlen()
                    )),
                }
                if out.len() >= 512 {
                    return out;
                }
            }
        }
    }
    out.into_iter()
        .map(|s| crate::util::sanitize_for_message(&s, 1024))
        .collect()
}

fn rcode_of(msg: &[u8]) -> Option<String> {
    domain::base::Message::from_octets(msg)
        .ok()
        .map(|m| m.header().rcode().to_string())
}

/// A TC reply: ID 0 (the log has none), QR, TC, RD and RA, the answer's CD and rcode, the
/// question, and an OPT (the edge's UDP payload, the client's DO) when the client sent one.
fn tc_form(question: &[u8], cd: bool, rcode: u16, opt: Option<bool>) -> Vec<u8> {
    let mut m = Vec::with_capacity(12 + question.len() + 11);
    m.extend_from_slice(&[
        0,
        0,
        0x80 | 0x02 | 0x01,
        0x80 | if cd { 0x10 } else { 0 } | (rcode & 0x0F) as u8,
    ]);
    m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, u8::from(opt.is_some())]);
    m.extend_from_slice(question);
    if let Some(do_bit) = opt {
        m.push(0);
        m.extend_from_slice(&41u16.to_be_bytes());
        m.extend_from_slice(&picket_wire::EDGE_UDP_PAYLOAD.to_be_bytes());
        m.extend_from_slice(&[
            ((rcode >> 4) & 0xFF) as u8,
            0,
            if do_bit { 0x80 } else { 0 },
            0,
            0,
            0,
        ]);
    }
    m
}

/// The question section of a record's query, in wire form: its `qname` (api.md §5 escapes
/// decoded), `qtype` and class IN; `None` when the name doesn't decode.
fn logged_question(r: &Rec) -> Option<Vec<u8>> {
    let labels = picket_api::names::decode_labels(&r.qname)?;
    let mut q = Vec::with_capacity(r.qname.len().saturating_add(6));
    for l in &labels {
        let len = u8::try_from(l.len()).ok().filter(|n| (1..=63).contains(n))?;
        q.push(len);
        q.extend_from_slice(l);
    }
    q.push(0);
    if q.len() > 255 {
        return None;
    }
    q.extend_from_slice(&r.qtype_num().to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    Some(q)
}

/// Rebuilds the reply a client got from the record (core.md §6).
pub fn reply_of(r: &Rec, cfg: Option<&super::replay::PublishedConfig>) -> Reply {
    if let Some(resp) = &r.response {
        return Reply {
            source: "response".into(),
            incomplete: false,
            wire: Some(b64(resp)),
            records: records_text(resp),
            rcode: rcode_of(resp),
            tc: r.tc,
        };
    }
    let preview = |incomplete: bool| Reply {
        source: "preview".into(),
        incomplete,
        wire: None,
        records: r
            .cname
            .iter()
            .map(|c| format!("CNAME {c}"))
            .chain(r.answers.iter().map(|a| format!("ADDRESS {a}")))
            .chain(r.targets.iter().map(|t| format!("TARGET {t}")))
            .collect(),
        rcode: Some(r.rcode.clone()),
        tc: r.tc,
    };
    // A TC reply is the header, the question and any OPT, with TC set (core.md §6; api.md §5;
    // edge.md §8): of a reply the edge made, or one whose answer core lacks, the client got
    // none of the records, so the preview isn't shown as the reply.
    if r.tc
        && (r.edge_made() || r.answer_wire.is_none())
        && let Some(question) = logged_question(r)
    {
        let edns: Option<picket_api::logs::EdnsInfo> =
            r.edns_json.as_deref().and_then(|s| serde_json::from_str(s).ok());
        let rcode = picket_wire::types::rcode_from_text(&r.rcode).unwrap_or(0);
        let w = tc_form(&question, false, rcode, edns.as_ref().map(|_| r.client_do));
        return Reply {
            source: "tc".into(),
            incomplete: false,
            records: records_text(&w),
            rcode: rcode_of(&w),
            wire: Some(b64(&w)),
            tc: true,
        };
    }
    // A reply the edge made whose `response` was left out for size: preview only.
    if r.edge_made() {
        return preview(true);
    }
    let Some(wire) = &r.answer_wire else {
        return preview(r.incomplete() || r.answer_id.is_some());
    };
    let Ok(value) = picket_wire::cache::CacheValue::from_logged_wire(wire, SystemTime::now(), Instant::now())
    else {
        return preview(true);
    };
    let profile = cfg.and_then(|c| r.profile.as_ref().and_then(|p| c.profiles.get(p)));
    let clamp = profile.map(|p| p.ttl).unwrap_or_default();
    let upstream: Option<picket_api::logs::UpstreamInfo> = r
        .upstream_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    let stale_ttl = cfg
        .and_then(|c| c.cache.as_ref())
        .map(|c| c.stale_ttl_s)
        .unwrap_or(30);
    let cause = upstream
        .as_ref()
        .and_then(|u| u.cause.clone())
        .unwrap_or_else(|| "optimistic".into());
    let stale = upstream
        .as_ref()
        .is_some_and(|u| u.stale)
        .then_some(picket_wire::cache::StaleServe {
            ttl: stale_ttl,
            cause: cause.as_str(),
        });
    let proto: picket_api::logs::Proto =
        serde_json::from_value(Json::String(r.proto.clone())).unwrap_or(picket_api::logs::Proto::Udp);
    let edns: Option<picket_api::logs::EdnsInfo> =
        r.edns_json.as_deref().and_then(|s| serde_json::from_str(s).ok());
    let to = picket_wire::reply::ReplyTo::logged(
        value.question(),
        value.cd(),
        proto,
        r.client_do,
        edns.as_ref(),
        picket_wire::EDGE_UDP_PAYLOAD,
    );
    let p = picket_wire::cache::ServeParams {
        age_s: u32::try_from(r.age_s.unwrap_or(0).max(0)).unwrap_or(u32::MAX),
        clamp,
        stale,
    };
    if r.tc {
        // The TC form: the header, the question and any OPT, with TC set (edge.md §8).
        let w = tc_form(
            value.question(),
            value.cd(),
            value.rcode(),
            edns.as_ref().map(|_| r.client_do),
        );
        return Reply {
            source: "tc".into(),
            incomplete: false,
            records: records_text(&w),
            rcode: rcode_of(&w),
            wire: Some(b64(&w)),
            tc: true,
        };
    }
    let mut out = vec![0u8; 65_535];
    match picket_wire::cache::rebuild_reply(&mut out, &to, &value, &p, false) {
        Ok(rep) => {
            let w = &out[..rep.len];
            Reply {
                source: if r.tc { "tc" } else { "answer" }.into(),
                incomplete: r.incomplete(),
                wire: Some(b64(w)),
                records: records_text(w),
                rcode: rcode_of(w),
                tc: rep.tc,
            }
        }
        Err(_) => preview(true),
    }
}

/// `GET logs/{id}`.
pub fn detail(store: &LogStore, core: &Connection, id: &str) -> Result<Option<LogDetail>> {
    let Some((hour, edge, boot, seq)) = record::parse_record_id(id) else {
        return Err(bad("id: a record id from the log search"));
    };
    let Some(p) = store.open(&hour, false)? else {
        return Ok(None);
    };
    let recs = record::load(
        &p,
        "WHERE e.edge_id = ?1 AND e.boot = ?2 AND e.seq = ?3",
        &[&edge, &boot, &seq],
    )?;
    let Some(r) = recs.into_iter().next() else {
        return Ok(None);
    };
    let attribution: Option<AttributionView> = if p.has_table("attribution") {
        p.conn
            .query_row(
                "SELECT matches_json, status FROM attribution WHERE edge_id = ?1 AND boot = ?2 AND seq = ?3",
                params![edge, boot, seq],
                |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?)),
            )
            .ok()
            .map(|(j, status)| {
                let a: Attribution = j.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default();
                AttributionView {
                    state: status,
                    matches: a.matches,
                    decisive: a.decisive,
                    self_check: a.self_check,
                    unavailable: a.unavailable,
                }
            })
    } else {
        None
    };
    let would_blocks = if p.has_table("would_blocks") {
        let mut st = p.conn.prepare(
            "SELECT bundle_id, head_id, key, stage, status, matches_json FROM would_blocks
             WHERE edge_id = ?1 AND boot = ?2 AND seq = ?3 ORDER BY bundle_id LIMIT 64",
        )?;
        let rows = st.query_map(params![edge, boot, seq], |row| {
            Ok(WouldBlockView {
                bundle: row.get(0)?,
                head: row.get(1)?,
                key: row.get(2)?,
                stage: row.get(3)?,
                status: row.get(4)?,
                matches: row
                    .get::<_, Option<String>>(5)?
                    .and_then(|j| serde_json::from_str(&j).ok())
                    .unwrap_or_default(),
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let lookups = lookups_of(&r);
    let versions: Option<Json> = serde_json::from_str(&r.versions_json).ok();
    let cfg = super::replay::parse_versions(&r.versions_json).and_then(|v| {
        super::replay::load_config(core, &r.edge, &v.config)
            .ok()
            .flatten()
    });
    let answer = match (&r.answer_id, &r.answer_wire) {
        (Some(id), Some(w)) => Some(AnswerView {
            id: id.clone(),
            received_at: r.received_at.clone(),
            age_s: r.age_s,
            wire: b64(w),
            records: records_text(w),
        }),
        _ => None,
    };
    let reply = reply_of(&r, cfg.as_ref());
    Ok(Some(LogDetail {
        record: record_view(&r),
        attribution,
        lookups,
        versions,
        answer,
        response: reply,
        would_blocks,
    }))
}

fn lookups_of(r: &Rec) -> Vec<LookupView> {
    let items: Vec<picket_api::logs::LookupItem> = r
        .lookups_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    items
        .into_iter()
        .take(32)
        .map(|l| LookupView {
            provider: l.provider.clone(),
            verdict: serde_json::to_value(l.verdict)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string)),
            score: l.score.and_then(crate::lookups::store::score_f64),
            reason: l.reason.clone(),
            // Ingest admits only an object (`logs::decode`); anything else is never sent.
            detail: l.detail.filter(Json::is_object),
            source: if l.cached { "cache" } else { "provider" }.into(),
            ms: Some(u64::from(l.ms)),
            timed_out: l.timed_out,
            retry: l.retry,
        })
        .collect()
}

// Aggregates ---------------------------------------------------------------------------------

/// A window ending now and the edge it covers (api.md §7 "Dashboard and System charts").
#[derive(Clone, Debug)]
pub struct Scope {
    pub from: Timestamp,
    pub to: Timestamp,
    pub step_s: i64,
    pub edge: Option<String>,
}

impl Scope {
    /// `window` (`1h`, `6h`, `24h`, `72h`; default 24 h) ending now, and `edge` (`all` or an
    /// id). A window longer than the query-log retention is refused (`422`, by the caller).
    pub fn parse(window: Option<&str>, edge: Option<&str>, now: Timestamp) -> Option<Scope> {
        let w = crate::metrics::query::Window::parse(window.unwrap_or("24h"))?;
        Some(Scope {
            from: now - SignedDuration::from_secs(w.secs),
            to: now,
            step_s: w.step_s,
            edge: edge
                .filter(|e| !e.is_empty() && *e != "all" && *e != "each")
                .map(str::to_string),
        })
    }

    pub fn secs(&self) -> i64 {
        (self.to - self.from).as_secs()
    }
}

/// A key and its count.
#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq)]
pub struct TopItem {
    pub key: String,
    pub count: i64,
    /// The bundle that decided most of its blocks (device and profile views).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
}

/// `GET top` (api.md §7).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct TopList {
    pub items: Vec<TopItem>,
}

/// The temporary table [`aggregate_into`] merges counts in.
fn agg_table() -> Result<Connection> {
    let tmp = Connection::open("")?;
    tmp.execute_batch(
        "CREATE TEMP TABLE agg(key TEXT PRIMARY KEY, n INTEGER NOT NULL, bundle TEXT, bn INTEGER NOT NULL DEFAULT 0);",
    )?;
    Ok(tmp)
}

/// Runs the count (selecting `(key, count, bundle)`) on one partition of the scope and merges it
/// into `tmp`'s `agg`.
fn aggregate_into(
    tmp: &Connection,
    p: &Partition,
    scope: &Scope,
    sql_where: &str,
    key_expr: &str,
    extra: &[&dyn rusqlite::ToSql],
) -> Result<()> {
    let mut clause = format!("WHERE ts >= ?1 AND ts <= ?2 {sql_where}");
    let mut args: Vec<&dyn rusqlite::ToSql> = Vec::new();
    let from = crate::util::ts(&scope.from);
    let to = crate::util::ts(&scope.to);
    args.push(&from);
    args.push(&to);
    for a in extra {
        args.push(*a);
    }
    if let Some(e) = &scope.edge {
        args.push(e);
        clause.push_str(&format!(" AND edge_id = ?{}", args.len()));
    }
    let bundle_col = if p.has_column("events", "bundle") {
        "bundle"
    } else {
        "NULL"
    };
    let sql = format!(
        "SELECT {key_expr} AS k, count(*), {bundle_col}, count({bundle_col}) FROM events {clause} GROUP BY k, {bundle_col}"
    );
    let mut st = p.conn.prepare(&sql)?;
    let mut rows = st.query(args.as_slice())?;
    let mut ins = tmp.prepare_cached(
        "INSERT INTO agg(key, n, bundle, bn) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(key) DO UPDATE SET n = n + excluded.n,
           bundle = CASE WHEN excluded.bn > bn THEN excluded.bundle ELSE bundle END,
           bn = max(bn, excluded.bn)",
    )?;
    while let Some(r) = rows.next()? {
        let k: Option<String> = r.get(0)?;
        let Some(k) = k else { continue };
        let n: i64 = r.get(1)?;
        let b: Option<String> = r.get(2)?;
        let bn: i64 = r.get(3)?;
        ins.execute(params![k, n, b, bn])?;
    }
    Ok(())
}

/// The top `limit` of `tmp`'s `agg`.
fn agg_top(tmp: &Connection, limit: usize) -> Result<Vec<TopItem>> {
    let mut st = tmp.prepare("SELECT key, n, bundle FROM agg ORDER BY n DESC, key LIMIT ?1")?;
    let v = st
        .query_map([limit], |r| {
            Ok(TopItem {
                key: r.get(0)?,
                count: r.get(1)?,
                bundle: r.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(v)
}

/// Runs `sql` (selecting `(key, count, bundle)`) on every partition of the scope and merges the
/// counts in a temporary table; returns the top `limit`.
fn aggregate(
    store: &LogStore,
    scope: &Scope,
    sql_where: &str,
    key_expr: &str,
    extra: &[&dyn rusqlite::ToSql],
    limit: usize,
) -> Result<Vec<TopItem>> {
    let tmp = agg_table()?;
    for hour in partitions_between(store, scope.from, scope.to)? {
        let Some(p) = store.open(&hour, false)? else {
            continue;
        };
        aggregate_into(&tmp, &p, scope, sql_where, key_expr, extra)?;
    }
    agg_top(&tmp, limit)
}

/// `GET top`'s `limit`: default 10, at most 100 (api.md §7).
pub const TOP_DEFAULT: usize = 10;
pub const TOP_MAX: usize = 100;

/// `GET top?kind=blocked|allowed|clients` (core.md §12 dashboard top panels): names in records
/// whose `decision` is `block` or `allow`, and devices over all records (each record's
/// `device`, else its `client`).
pub fn top(store: &LogStore, kind: &str, scope: &Scope, limit: usize) -> Result<TopList> {
    let limit = limit.clamp(1, TOP_MAX);
    let items = match kind {
        "blocked" => aggregate(store, scope, "AND decision = 'block'", "qname", &[], limit)?,
        "allowed" => aggregate(store, scope, "AND decision = 'allow'", "qname", &[], limit)?,
        "clients" => aggregate(store, scope, "", "coalesce(device, client_ip)", &[], limit)?,
        _ => return Err(bad("kind: blocked, allowed or clients")),
    };
    let items = items
        .into_iter()
        .map(|mut i| {
            i.bundle = None;
            i
        })
        .collect();
    Ok(TopList { items })
}

/// One device the edges have seen (core.md §12 Clients).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct Device {
    /// The device's key in logs: its client name, else its MAC, else its address.
    pub key: String,
    /// A MAC core currently knows for it: the key itself when it is a MAC; for a device keyed by a
    /// client name, the first MAC of the client entry that has that name now. Null otherwise: for
    /// a client name no entry has now, or whose entry lists no MACs (a MAC logged at its address
    /// before may belong to another device by now), and for an address-keyed device.
    pub mac: Option<String>,
    /// The MACs core knows for it (lowercase, at most 16): the key when it is a MAC; for a device
    /// keyed by a client name, the `macs` of the client entry that has that name now (none when
    /// no entry has it or the entry lists none); for an address-keyed device, the MAC most
    /// recently logged as the device of the address it was last seen with, by the edge that saw
    /// it (at most one, and only a hint: that address may be shared or reused, so it is never
    /// the device's `mac`).
    pub macs: Vec<String>,
    /// Addresses it was seen with (most recent first, at most 32).
    pub addresses: Vec<String>,
    /// The client entry's name when one names it.
    pub name: Option<String>,
    /// PTR and DHCP host names: core doesn't learn them yet (null).
    pub ptr: Option<String>,
    pub dhcp_name: Option<String>,
    /// The client entry naming the device, if any.
    pub client: Option<String>,
    /// The edge that saw it last.
    pub edge: Option<String>,
    pub last_seen: Option<String>,
    /// Logged queries in the retention window.
    pub queries: i64,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct DeviceList {
    pub items: Vec<Device>,
}

fn is_mac(s: &str) -> bool {
    s.len() == 17
        && s.split(':').count() == 6
        && s.split(':')
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// MACs one device lists at most.
const MAX_DEVICE_MACS: usize = 16;

/// `GET devices`: the devices in the logged records of the retention window, with the MACs core
/// currently knows for each (core.md §12 Clients: the private-MAC mark and "addable as a client"
/// need the MAC). **Currently knows** means: what the record's key is (a MAC-keyed device's
/// MAC), or what the configuration says now (a device keyed by its client name, api.md §5
/// `device`, has the `macs` of the client entry that has that name now, which are
/// authoritative). A MAC inferred from older records is never a client-named device's: the
/// name→MAC mapping that put the name in those records (an entry's `macs` or `source_ips`) may be
/// gone, and the address may have gone to another device since, so a name no entry has now, or
/// whose entry lists no MACs, has no MAC. An address-keyed device lists the MAC last logged at
/// its address by its edge (an address on another edge is another network) as a hint, but never
/// takes it as its `mac`: that address may be shared or reused.
pub fn devices(store: &LogStore, clients: &[crate::config::model::ClientDef]) -> Result<DeviceList> {
    struct Acc {
        addrs: Vec<(String, String)>,
        edge: Option<String>,
        last: String,
        /// Its newest sighting's address (on `edge`, at `last`).
        last_addr: Option<String>,
        n: i64,
    }
    let mut acc: HashMap<String, Acc> = HashMap::new();
    // (edge, address) → (MAC, newest time) from MAC-keyed records (bounded like the devices).
    let mut addr_mac: HashMap<(String, String), (String, String)> = HashMap::new();
    for (hour, _) in store.list()?.into_iter().rev() {
        let Some(p) = store.open(&hour, false)? else {
            continue;
        };
        let mut st = p.conn.prepare(
            "SELECT coalesce(device, client_ip), client_ip, edge_id, max(ts), count(*) FROM events
             GROUP BY coalesce(device, client_ip), client_ip, edge_id",
        )?;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            let key: Option<String> = r.get(0)?;
            let Some(key) = key else { continue };
            let addr: Option<String> = r.get(1)?;
            let edge: String = r.get(2)?;
            let last: String = r.get(3)?;
            let n: i64 = r.get(4)?;
            if is_mac(&key)
                && let Some(addr) = &addr
            {
                let at = (edge.clone(), addr.clone());
                if addr_mac.contains_key(&at) || addr_mac.len() < MAX_DEVICES * MAX_ADDRESSES {
                    let e = addr_mac
                        .entry(at)
                        .or_insert_with(|| (key.to_ascii_lowercase(), String::new()));
                    if last > e.1 {
                        *e = (key.to_ascii_lowercase(), last.clone());
                    }
                }
            }
            if !acc.contains_key(&key) && acc.len() >= MAX_DEVICES {
                continue;
            }
            let a = acc.entry(key).or_insert(Acc {
                addrs: Vec::new(),
                edge: None,
                last: String::new(),
                last_addr: None,
                n: 0,
            });
            a.n += n;
            if last > a.last {
                a.last = last.clone();
                a.edge = Some(edge);
                a.last_addr = addr.clone();
            }
            if let Some(addr) = addr {
                if let Some(e) = a.addrs.iter_mut().find(|(x, _)| *x == addr) {
                    if last > e.1 {
                        e.1 = last;
                    }
                } else if a.addrs.len() < MAX_ADDRESSES {
                    a.addrs.push((addr, last));
                }
            }
        }
    }
    let mut items: Vec<Device> = acc
        .into_iter()
        .map(|(key, mut a)| {
            a.addrs.sort_by(|x, y| y.1.cmp(&x.1));
            // The entry that has the key as its name now, else the first that covers the device.
            let named = clients.iter().find(|c| c.name == key);
            let entry = named.or_else(|| {
                clients.iter().find(|c| {
                    c.macs.iter().any(|m| m.eq_ignore_ascii_case(&key))
                        || a.addrs.iter().any(|(ip, _)| {
                            c.source_ips.iter().any(|r| {
                                ip.parse::<IpAddr>().is_ok_and(|ip| {
                                    r.parse::<ipnet::IpNet>().is_ok_and(|n| n.contains(&ip))
                                        || r.parse::<IpAddr>().is_ok_and(|x| x == ip)
                                })
                            })
                        })
                })
            });
            let by_address = key.parse::<IpAddr>().is_ok();
            let macs: Vec<String> = if is_mac(&key) {
                vec![key.to_ascii_lowercase()]
            } else if by_address {
                // A hint only: the MAC last logged at its address by its edge (the doc above).
                a.edge
                    .as_ref()
                    .zip(a.last_addr.as_ref())
                    .and_then(|(edge, addr)| addr_mac.get(&(edge.clone(), addr.clone())))
                    .map(|(m, _)| vec![m.clone()])
                    .unwrap_or_default()
            } else {
                // A client name: the MACs of the entry that has it now, which are authoritative.
                let mut v: Vec<String> = Vec::new();
                for m in named
                    .into_iter()
                    .flat_map(|c| c.macs.iter().map(|m| m.to_ascii_lowercase()))
                {
                    if is_mac(&m) && !v.contains(&m) && v.len() < MAX_DEVICE_MACS {
                        v.push(m);
                    }
                }
                v
            };
            Device {
                mac: if by_address { None } else { macs.first().cloned() },
                macs,
                name: entry.map(|c| c.name.clone()),
                client: entry.map(|c| c.name.clone()),
                addresses: a.addrs.into_iter().map(|(x, _)| x).collect(),
                ptr: None,
                dhcp_name: None,
                edge: a.edge,
                last_seen: (!a.last.is_empty()).then_some(a.last),
                queries: a.n,
                key,
            }
        })
        .collect();
    items.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.key.cmp(&b.key)));
    Ok(DeviceList { items })
}

/// One temporary allow on a device (core.md §12 device and profile views): those in force at
/// some time in the window, newest first.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct AllowView {
    pub allow_id: String,
    pub target: String,
    pub kind: String,
    pub expires_at: Option<String>,
    pub ended_at: Option<String>,
    pub edge: String,
    /// The device it is for (its client name or MAC, else null: then `client` names it).
    pub device: Option<String>,
    /// The address it was created from.
    pub client: Option<String>,
    /// As `GET temp-allows` gives it: `active`, `revoked`, `ended` or `expired`.
    pub state: crate::lookups::api::AllowState,
    pub revoke_acked_at: Option<String>,
}

/// Allows one summary lists at most.
const SUMMARY_MAX_ALLOWS: i64 = 50;

/// A device as a summary's allows match it: on the edge it was seen on (temporary allows are per
/// edge, api.md §5 `allow`, and the same address on another edge is another network's device),
/// or on any edge.
pub type EdgeDevice = (Option<String>, String);

/// The separator of an (edge, device key) pair in [`allows_of`]'s list (neither holds it: edge
/// ids are ids, keys are client names, MACs or addresses from decoded records).
const PAIR_SEP: char = '\u{1f}';

/// Reads the allows of `devices` (each matched against an allow's `device` and `client`, on its
/// edge or on any edge) in force since `from`.
fn allows_of(core: &Connection, devices: &[EdgeDevice], from: &str) -> Result<Vec<AllowView>> {
    let now = crate::util::now_ts();
    let mut on_edge: Vec<String> = Vec::new();
    let mut anywhere: Vec<&str> = Vec::new();
    for (edge, key) in devices {
        match edge {
            Some(e) => on_edge.push(format!("{e}{PAIR_SEP}{key}")),
            None => anywhere.push(key),
        }
    }
    // Each `IN (json_each)` list is built once into a temporary index (no scan per allow).
    let sql = format!(
        "SELECT allow_id, target, kind, expires_at, ended_at, edge_id, device, client,
                revoke_requested_at, revoke_acked_at
         FROM temp_allows
         WHERE target IS NOT NULL AND kind IS NOT NULL
           AND (device IN (SELECT value FROM json_each(?1)) OR client IN (SELECT value FROM json_each(?1))
             OR edge_id || char(31) || device IN (SELECT value FROM json_each(?4))
             OR edge_id || char(31) || client IN (SELECT value FROM json_each(?4)))
           AND {}
         ORDER BY created_at DESC LIMIT ?3",
        crate::lookups::api::ALLOW_SINCE_SQL.replace("?from", "?2")
    );
    let mut st = core.prepare(&sql)?;
    let v = st
        .query_map(
            params![
                serde_json::to_string(&anywhere)?,
                from,
                SUMMARY_MAX_ALLOWS,
                serde_json::to_string(&on_edge)?
            ],
            |r| {
                let ended: Option<String> = r.get(4)?;
                let expires: Option<String> = r.get(3)?;
                let requested: Option<String> = r.get(8)?;
                let acked: Option<String> = r.get(9)?;
                let (state, ended_at) = crate::lookups::api::allow_state(
                    ended.as_deref(),
                    expires.as_deref(),
                    requested.as_deref(),
                    acked.as_deref(),
                    &now,
                );
                Ok(AllowView {
                    allow_id: r.get(0)?,
                    target: r.get(1)?,
                    kind: r.get(2)?,
                    expires_at: expires,
                    ended_at,
                    edge: r.get(5)?,
                    device: r.get(6)?,
                    client: r.get(7)?,
                    state,
                    revoke_acked_at: acked,
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(v)
}

/// One device in a profile's view.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct DeviceCount {
    pub key: String,
    pub queries: i64,
    pub blocked: i64,
}

/// `GET query-summary` (core.md §12 Clients: a view per device, and per profile for its devices).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct Summary {
    pub queries: i64,
    pub blocked: i64,
    /// Decisions over time, one line per decision, stepped as the dashboard charts are.
    pub decisions: Vec<crate::metrics::query::Line>,
    pub step_s: i64,
    pub top: Vec<TopItem>,
    pub top_blocked: Vec<TopItem>,
    pub temporary_allows: Vec<AllowView>,
    /// The profile's devices (profile view).
    pub devices: Vec<DeviceCount>,
}

/// The device or profile condition of a summary.
#[derive(Clone, Debug)]
pub enum Subject {
    Device(String),
    Profile(String),
}

/// `GET query-summary`.
/// Partitions one summary reads at most: its window (at most 72 h, `422` past the query-log
/// retention) holds at most 73 hourly partitions, plus one for an hour boundary (README §2
/// Bounded).
pub const SUMMARY_MAX_PARTITIONS: usize = 74;

/// The temporary allows of a device, from core.db: for a device view, read before and apart
/// from the partition scan (so no core.db reader waits on log files); a profile's come after the
/// scan from [`profile_allows`], once its devices are known. A device view counts the device's
/// records on every edge, or on the scope's edge: its allows are those of the same edges.
pub fn summary_allows(core: &Connection, subject: &Subject, scope: &Scope) -> Result<Vec<AllowView>> {
    match subject {
        Subject::Device(d) => allows_of(
            core,
            &[(scope.edge.clone(), d.clone())],
            &crate::util::ts(&scope.from),
        ),
        Subject::Profile(_) => Ok(Vec::new()),
    }
}

/// A profile's view's temporary allows (core.md §12: "per profile for its devices ... and
/// temporary allows"): those of the devices its records in the window name (by their device
/// key, `device` else `client`, as the summary counts them), each on the edge whose records name
/// it, from core.db after the partition scan ([`summary`] returns the devices).
pub fn profile_allows(core: &Connection, devices: &[EdgeDevice], scope: &Scope) -> Result<Vec<AllowView>> {
    if devices.is_empty() {
        return Ok(Vec::new());
    }
    allows_of(core, devices, &crate::util::ts(&scope.from))
}

/// `GET query-summary` over the log partitions (no core.db connection: the temporary allows come
/// from [`summary_allows`], or for a profile from [`profile_allows`] with the devices this
/// returns beside the summary: every (edge, device key) its records in the window name, at most
/// [`MAX_DEVICES`]). Each partition of the window is opened once, at most
/// [`SUMMARY_MAX_PARTITIONS`], newest first.
pub fn summary(
    store: &LogStore,
    subject: &Subject,
    scope: &Scope,
    temporary_allows: Vec<AllowView>,
) -> Result<(Summary, Vec<EdgeDevice>)> {
    let (cond, val) = match subject {
        Subject::Device(d) => ("AND coalesce(device, client_ip) = ?3", d.clone()),
        Subject::Profile(p) => ("AND profile = ?3", p.clone()),
    };
    let steps = (scope.secs() / scope.step_s).max(1);
    let start = scope.from.as_second() / scope.step_s * scope.step_s;
    let mut per: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut queries = 0i64;
    let mut blocked = 0i64;
    let mut devices: HashMap<String, (i64, i64)> = HashMap::new();
    // The (edge, device key) pairs of a profile's records, for their allows.
    let mut seen_on: HashSet<(String, String)> = HashSet::new();
    let top_tmp = agg_table()?;
    let blocked_tmp = agg_table()?;
    let blocked_cond = format!("{cond} AND decision = 'block'");
    for hour in partitions_between(store, scope.from, scope.to)?
        .into_iter()
        .take(SUMMARY_MAX_PARTITIONS)
    {
        let Some(p) = store.open(&hour, false)? else {
            continue;
        };
        aggregate_into(&top_tmp, &p, scope, cond, "qname", &[&val])?;
        aggregate_into(&blocked_tmp, &p, scope, &blocked_cond, "qname", &[&val])?;
        let mut clause = format!("WHERE ts >= ?1 AND ts <= ?2 {cond}");
        let from = crate::util::ts(&scope.from);
        let to = crate::util::ts(&scope.to);
        let mut args: Vec<&dyn rusqlite::ToSql> = vec![&from, &to, &val];
        if let Some(e) = &scope.edge {
            args.push(e);
            clause.push_str(" AND edge_id = ?4");
        }
        let sql = format!(
            "SELECT CAST(strftime('%s', substr(ts, 1, 19)) AS INTEGER) / ?{n} AS b, decision, count(*),
                    coalesce(device, client_ip), sum(decision = 'block'), edge_id
             FROM events {clause} GROUP BY b, decision, coalesce(device, client_ip), edge_id",
            n = args.len() + 1
        );
        let step = scope.step_s;
        args.push(&step);
        let mut st = p.conn.prepare(&sql)?;
        let mut rows = st.query(args.as_slice())?;
        while let Some(r) = rows.next()? {
            let b: i64 = r.get(0)?;
            let d: String = r.get::<_, Option<String>>(1)?.unwrap_or_default();
            let n: i64 = r.get(2)?;
            let dev: Option<String> = r.get(3)?;
            let nb: i64 = r.get::<_, Option<i64>>(4)?.unwrap_or(0);
            let edge: Option<String> = r.get(5)?;
            queries += n;
            blocked += nb;
            let idx = b * scope.step_s - start;
            if idx >= 0 {
                let i = usize::try_from(idx / scope.step_s).unwrap_or(usize::MAX);
                let line = per
                    .entry(d)
                    .or_insert_with(|| vec![0.0; usize::try_from(steps + 1).unwrap_or(1)]);
                if let Some(slot) = line.get_mut(i) {
                    *slot += n as f64;
                }
            }
            if let Some(dev) = dev
                && (devices.contains_key(&dev) || devices.len() < MAX_DEVICES)
            {
                if matches!(subject, Subject::Profile(_))
                    && let Some(edge) = edge
                    && seen_on.len() < MAX_DEVICES
                {
                    seen_on.insert((edge, dev.clone()));
                }
                let e = devices.entry(dev).or_insert((0, 0));
                e.0 += n;
                e.1 += nb;
            }
        }
    }
    let decisions = per
        .into_iter()
        .map(|(d, pts)| crate::metrics::query::Line {
            name: "decisions".into(),
            labels: crate::metrics::labels("", &[("decision", &d)]),
            edge: scope.edge.clone(),
            points: pts
                .into_iter()
                .enumerate()
                .map(|(i, v)| (start + crate::util::sat_i64(i) * scope.step_s, Some(v)))
                .collect(),
        })
        .collect();
    let top = agg_top(&top_tmp, 10)?;
    let top_blocked = agg_top(&blocked_tmp, 10)?;
    let keys: Vec<EdgeDevice> = seen_on.into_iter().map(|(e, d)| (Some(e), d)).collect();
    let mut devs: Vec<DeviceCount> = match subject {
        Subject::Profile(_) => devices
            .into_iter()
            .map(|(key, (queries, blocked))| DeviceCount {
                key,
                queries,
                blocked,
            })
            .collect(),
        Subject::Device(_) => Vec::new(),
    };
    devs.sort_by(|a, b| b.queries.cmp(&a.queries).then(a.key.cmp(&b.key)));
    devs.truncate(100);
    Ok((
        Summary {
            queries,
            blocked,
            decisions,
            step_s: scope.step_s,
            top,
            top_blocked,
            temporary_allows,
            devices: devs,
        },
        keys,
    ))
}

/// One name a trial bundle would have blocked.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct TrialName {
    pub name: String,
    pub count: i64,
    /// The stage of its first hit (`query`, `cname`, `answer_ip`, `svcb`).
    pub stage: Option<String>,
    /// The feeds and rules that matched (roles `would_block` or `overridden`).
    pub matches: Vec<TrialRule>,
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord)]
pub struct TrialRule {
    pub feed: String,
    pub rule: String,
    pub role: String,
}

/// `GET trial-results` (core.md §12 Profiles → Trial bundles): would-blocks over the window, in
/// total, by name with the matching feeds and rules, and the devices affected.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct TrialResults {
    pub total: i64,
    pub names: Vec<TrialName>,
    pub devices: Vec<TopItem>,
    /// What the check can't see (core.md §6 "Limits").
    pub limits: Vec<String>,
}

/// `GET trial-results?profile&bundle&window&edge`.
pub fn trial_results(store: &LogStore, profile: &str, bundle: &str, scope: &Scope) -> Result<TrialResults> {
    let mut total = 0i64;
    let mut names: HashMap<String, (i64, Option<String>, std::collections::BTreeSet<TrialRule>)> =
        HashMap::new();
    let mut devices: HashMap<String, i64> = HashMap::new();
    for hour in partitions_between(store, scope.from, scope.to)? {
        let Some(p) = store.open(&hour, false)? else {
            continue;
        };
        if !p.has_table("would_blocks") {
            continue;
        }
        let from = crate::util::ts(&scope.from);
        let to = crate::util::ts(&scope.to);
        let mut args: Vec<&dyn rusqlite::ToSql> = vec![&from, &to, &profile, &bundle];
        let mut sql = String::from(
            "SELECT e.qname, coalesce(e.device, e.client_ip), w.stage, w.matches_json FROM would_blocks w
             JOIN events e ON e.edge_id = w.edge_id AND e.boot = w.boot AND e.seq = w.seq
             WHERE e.ts >= ?1 AND e.ts <= ?2 AND e.profile = ?3 AND w.bundle_id = ?4",
        );
        if let Some(e) = &scope.edge {
            args.push(e);
            sql.push_str(" AND e.edge_id = ?5");
        }
        sql.push_str(" LIMIT 200000");
        let mut st = p.conn.prepare(&sql)?;
        let mut rows = st.query(args.as_slice())?;
        while let Some(r) = rows.next()? {
            let name: String = r.get(0)?;
            let dev: Option<String> = r.get(1)?;
            let stage: Option<String> = r.get(2)?;
            let mj: Option<String> = r.get(3)?;
            total += 1;
            if !names.contains_key(&name) && names.len() >= 10_000 {
                continue;
            }
            let e = names
                .entry(name)
                .or_insert((0, stage.clone(), Default::default()));
            e.0 += 1;
            if e.2.len() < 32 {
                let ms: Vec<Match> = mj.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default();
                for m in ms {
                    e.2.insert(TrialRule {
                        feed: m.feed,
                        rule: m.text,
                        role: m.role,
                    });
                }
            }
            if let Some(d) = dev
                && (devices.contains_key(&d) || devices.len() < MAX_DEVICES)
            {
                *devices.entry(d).or_insert(0) += 1;
            }
        }
    }
    let mut names: Vec<TrialName> = names
        .into_iter()
        .map(|(name, (count, stage, rules))| TrialName {
            name,
            count,
            stage,
            matches: rules.into_iter().collect(),
        })
        .collect();
    names.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));
    names.truncate(100);
    let mut devs: Vec<TopItem> = devices
        .into_iter()
        .map(|(key, count)| TopItem {
            key,
            count,
            bundle: None,
        })
        .collect();
    devs.sort_by(|a, b| b.count.cmp(&a.count).then(a.key.cmp(&b.key)));
    devs.truncate(100);
    Ok(TrialResults {
        total,
        names,
        devices: devs,
        limits: vec![
            "Only logged queries are checked: a profile with log: blocked or off sends core no allowed queries.".into(),
            "Results arrive after ingest.".into(),
            "The ladder isn't replayed with the bundle added: a name response checks would still let through counts too, and sync lookups are approximated from the logged verdicts.".into(),
        ],
    })
}

/// One sync lookup's result on an evidence copy, as the edge logged it (api.md §5 `lookups[]`).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct EvidenceLookup {
    pub provider: String,
    /// `clean`, `block` or `unknown`.
    pub verdict: String,
    pub score: Option<f64>,
    pub reason: Option<String>,
    /// From the edge's RAM tier or verdict set.
    pub cached: bool,
    /// When the provider answered (a provider's answer only).
    pub obtained_at: Option<String>,
    /// The provider's `cache_generation` it was obtained under.
    #[serde(rename = "gen")]
    pub generation: String,
    pub ms: u64,
    pub timed_out: bool,
    pub rejected: Option<bool>,
    pub retry: bool,
    /// The module's detail: a small JSON object (providers.md §4 "Detail"; ingest refuses
    /// anything else), or null.
    #[schemars(with = "Option<serde_json::Map<String, Json>>")]
    pub detail: Option<Json>,
}

/// One evidence copy (core.md §9 "full copies of its related log records, `response`
/// included"): the record as the log search shows it, plus what the copy keeps beside it. The
/// type of `EvidenceView.items`; copies are served as stored (a copy made by an older release
/// lacks the fields it didn't write).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct EvidenceRecord {
    #[serde(flatten)]
    pub record: LogRecord,
    /// Each provider's verdict, reason and detail (api.md §5).
    pub lookups: Vec<EvidenceLookup>,
    /// The record's version block (api.md §5 `versions`).
    pub versions: Option<Json>,
    /// The client's OPT, when it sent one (`{udp, pad}`).
    pub edns: Option<Json>,
    /// The reply the edge made (base64), when it logged one.
    pub response: Option<String>,
}

/// `GET alerts/{id}/evidence?cursor&limit` (core.md §9, §12; api.md §7 cursor pagination).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct EvidenceView {
    /// One page of the copied records, newest stored first (by the order core stored them, not
    /// their event times: a backfill or an edge's late spool stores older records later, and
    /// they come first here; the next pages hold the copies stored before): each the whole logged
    /// record, as the log search shows it plus `lookups` (each provider's verdict, reason and detail, api.md §5),
    /// `versions` (the record's version block), `edns` (the client's OPT, when it sent one) and
    /// `response` (base64, when the edge made the reply).
    #[schemars(with = "Vec<EvidenceRecord>")]
    pub items: Vec<Json>,
    /// Pass as `cursor` for the next page: the copies stored before this page's. Null on the
    /// last page. Copies stored while paging come on a fresh first page, never behind a cursor.
    pub next_cursor: Option<String>,
    /// Copies the alert keeps in all, as this page was read (the same snapshot as its items).
    pub total: i64,
    /// A `wire_mismatch` alert's examples: each record's logged fields, the kind, the answer's
    /// wire (base64: **Download as fuzz case** saves it) and `domain`'s decode or error. First
    /// page only (empty with a `cursor`).
    pub examples: Vec<WireExample>,
    /// Exact counts per client and per name; `client_other` and `name_other` hold the rest.
    /// First page only (empty with a `cursor`).
    pub counts: BTreeMap<String, BTreeMap<String, i64>>,
    /// More than 1,000 distinct clients or names: the breakdown is incomplete.
    pub incomplete: bool,
    /// The upstream answers this page's copies reference, once each (base64); on the first page
    /// also the answers no copy references (the validator's DNSKEY and DS answers, the
    /// cross-check resolver's).
    pub answers: Vec<EvidenceAnswer>,
    /// What capture copies for this alert, if it keeps evidence.
    pub rule: Option<super::evidence::EvidenceRule>,
}

/// Copies one evidence page holds by default, and at most.
pub const EVIDENCE_PAGE: usize = 100;
pub const EVIDENCE_PAGE_MAX: usize = 500;

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct WireExample {
    pub kind: String,
    pub record: Json,
    pub wire: Option<String>,
    pub decoded: Option<Json>,
    pub at: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct EvidenceAnswer {
    pub answer_id: String,
    /// `log`, `validator` or `crosscheck`.
    pub source: String,
    pub wire: String,
    pub records: Vec<String>,
}

/// Reads one page of alert `id`'s evidence (newest stored copies first, before `cursor`: the
/// `next_cursor` of the page before; at most `limit` copies); `None` when there is no such alert.
/// The examples, counts, rule and the answers no copy references come with the first page.
///
/// Pages go by the copies' ids, which only grow (core.md §9 Evidence: copies are added "as
/// [records are] ingested", whatever their event times), so a copy stored while the UI pages
/// lands before its first page, never behind its cursor, and refreshing needs only the first
/// page. The page and `total` are read in one snapshot.
pub fn evidence(c: &Connection, id: i64, cursor: Option<&str>, limit: usize) -> Result<Option<EvidenceView>> {
    // One read transaction: every statement below sees the same snapshot (WAL).
    let tx = c.unchecked_transaction()?;
    let c: &Connection = &tx;
    let exists = c.prepare("SELECT 1 FROM alerts WHERE id = ?1")?.exists([id])?;
    if !exists {
        return Ok(None);
    }
    let limit = limit.clamp(1, EVIDENCE_PAGE_MAX);
    let first = cursor.is_none();
    // The cursor: the last copy's id.
    let before: Option<i64> = match cursor {
        None => None,
        Some(c) => Some(
            crate::web::api::decode_cursor(c)
                .and_then(|k| k.parse::<i64>().ok())
                .ok_or_else(|| bad("bad cursor"))?,
        ),
    };
    let total: i64 = c.query_row(
        "SELECT count(*) FROM alert_evidence WHERE alert_id = ?1",
        [id],
        |r| r.get(0),
    )?;
    let mut st = c.prepare(
        "SELECT id, record_json FROM alert_evidence
         WHERE alert_id = ?1 AND (?2 IS NULL OR id < ?2)
         ORDER BY id DESC LIMIT ?3",
    )?;
    let rows: Vec<(i64, String)> = st
        .query_map(params![id, before, limit + 1], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let more = rows.len() > limit;
    let rows = &rows[..rows.len().min(limit)];
    let next_cursor = more
        .then(|| rows.last())
        .flatten()
        .map(|(row, _)| crate::web::api::encode_cursor(&row.to_string()));
    let items: Vec<Json> = rows
        .iter()
        .filter_map(|(_, s)| serde_json::from_str(s).ok())
        .collect();
    // The answers this page references.
    let referenced: Vec<&str> = items
        .iter()
        .filter_map(|v| v.get("answer_id").and_then(Json::as_str))
        .collect();
    let referenced = serde_json::to_string(&referenced)?;
    if !first {
        let mut st = c.prepare(
            "SELECT answer_id, source, wire FROM alert_evidence_answers
             WHERE alert_id = ?1 AND source = 'log' AND answer_id IN (SELECT value FROM json_each(?2))
             ORDER BY answer_id LIMIT 2000",
        )?;
        let answers = st
            .query_map(params![id, referenced], answer_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        return Ok(Some(EvidenceView {
            items,
            next_cursor,
            total,
            examples: Vec::new(),
            counts: BTreeMap::new(),
            incomplete: false,
            answers,
            rule: None,
        }));
    }
    let mut st = c.prepare(
        "SELECT kind, record_json, wire, decoded_json, at FROM wire_examples WHERE alert_id = ?1 ORDER BY id LIMIT 100",
    )?;
    let examples = st
        .query_map([id], |r| {
            Ok(WireExample {
                kind: r.get(0)?,
                record: r
                    .get::<_, String>(1)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or(Json::Null),
                wire: r.get::<_, Option<Vec<u8>>>(2)?.map(|w| b64(&w)),
                decoded: r
                    .get::<_, Option<String>>(3)?
                    .and_then(|s| serde_json::from_str(&s).ok()),
                at: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut counts: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
    let mut st =
        c.prepare("SELECT kind, key, count FROM alert_evidence_counts WHERE alert_id = ?1 LIMIT 5000")?;
    let mut rows = st.query([id])?;
    let mut incomplete = false;
    while let Some(r) = rows.next()? {
        let kind: String = r.get(0)?;
        let key: String = r.get(1)?;
        let n: i64 = r.get(2)?;
        if kind.ends_with("_other") {
            incomplete = true;
        }
        counts.entry(kind).or_default().insert(key, n);
    }
    let mut st = c.prepare(
        "SELECT answer_id, source, wire FROM alert_evidence_answers
         WHERE alert_id = ?1 AND (source <> 'log' OR answer_id IN (SELECT value FROM json_each(?2)))
         ORDER BY answer_id LIMIT 2000",
    )?;
    let answers = st
        .query_map(params![id, referenced], answer_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let rule = c
        .query_row(
            "SELECT rule_json FROM alert_evidence_rules WHERE alert_id = ?1",
            [id],
            |r| r.get::<_, String>(0),
        )
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    Ok(Some(EvidenceView {
        items,
        next_cursor,
        total,
        examples,
        counts,
        incomplete,
        answers,
        rule,
    }))
}

/// One `alert_evidence_answers` row as the evidence view shows it.
fn answer_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<EvidenceAnswer> {
    let w: Vec<u8> = r.get(2)?;
    Ok(EvidenceAnswer {
        answer_id: r.get(0)?,
        source: r.get(1)?,
        records: records_text(&w),
        wire: b64(&w),
    })
}

/// The partition holding a record, for callers that only need the store (tests).
pub fn open(store: &LogStore, hour: &Timestamp) -> Result<Option<Partition>> {
    store.open(hour, false)
}
