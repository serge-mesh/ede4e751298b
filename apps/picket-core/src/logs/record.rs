//! A stored `q` record as the analysis and the query-log API read it back from its partition
//! (storage.md §3 `events`, api.md §5), and the values replay checks in it (core.md §6).
//!
//! Partitions are read by the columns they have ([`super::partition::Partition::select_list`]):
//! a column an older partition lacks reads as its default.

use std::net::IpAddr;
use std::time::{Instant, SystemTime};

use jiff::Timestamp;
use picket_api::logs::{Decision, MatchKind, Reason, Stage};
use rusqlite::Connection;
use serde::Serialize;

use super::partition::Partition;
use super::replay::Value;

/// One stored query record.
#[derive(Clone, Debug, Default)]
pub struct Rec {
    pub rowid: i64,
    pub edge: String,
    pub boot: String,
    pub seq: i64,
    pub ts: String,
    pub versions_json: String,
    pub versions_blake3: String,
    pub listener: String,
    pub proto: String,
    pub client_ip: String,
    pub device: Option<String>,
    pub profile: Option<String>,
    pub qname: String,
    pub qtype: String,
    pub rcode: String,
    pub decision: String,
    pub reason: Option<Reason>,
    pub answers: Vec<String>,
    pub targets: Vec<String>,
    pub cname: Vec<String>,
    pub truncated: bool,
    pub response: Option<Vec<u8>>,
    pub tc: bool,
    pub answer_id: Option<String>,
    pub received_at: Option<String>,
    pub age_s: Option<i64>,
    pub answer_missing: bool,
    pub client_do: bool,
    pub lookups_json: Option<String>,
    pub cold_unchecked: Vec<String>,
    pub upstream_json: Option<String>,
    pub fw_json: Option<String>,
    pub timings_json: Option<String>,
    pub edns_json: Option<String>,
    pub wire_check: Option<String>,
    pub trial_check: Option<String>,
    pub cold_check: Option<String>,
    /// The referenced answer's wire, when the partition holds it.
    pub answer_wire: Option<Vec<u8>>,
}

/// The `events` columns read, with the default for a partition that lacks one.
const COLUMNS: &[(&str, &str)] = &[
    ("edge_id", "''"),
    ("boot", "''"),
    ("seq", "0"),
    ("ts", "''"),
    ("listener", "''"),
    ("proto", "''"),
    ("client_ip", "''"),
    ("device", "NULL"),
    ("profile", "NULL"),
    ("qname", "''"),
    ("qtype", "''"),
    ("rcode", "''"),
    ("decision", "''"),
    ("reason_json", "NULL"),
    ("step", "NULL"),
    ("bundle", "NULL"),
    ("rule_key", "NULL"),
    ("match_kind", "NULL"),
    ("stage", "NULL"),
    ("block_id", "NULL"),
    ("answers_json", "'[]'"),
    ("targets_json", "'[]'"),
    ("cname_json", "'[]'"),
    ("truncated", "0"),
    ("response", "NULL"),
    ("tc", "0"),
    ("answer_id", "NULL"),
    ("received_at", "NULL"),
    ("age_s", "NULL"),
    ("answer_missing", "0"),
    ("client_do", "0"),
    ("lookups_json", "NULL"),
    ("cold_unchecked_json", "NULL"),
    ("upstream_json", "NULL"),
    ("fw_json", "NULL"),
    ("timings_json", "NULL"),
    ("edns_json", "NULL"),
    ("wire_check", "NULL"),
    ("trial_check", "NULL"),
    ("cold_check", "NULL"),
];

/// The SELECT that reads records from `events e` (with its version set and answer); append a
/// `WHERE`/`ORDER BY` clause.
pub fn select_sql(p: &Partition) -> String {
    let cols: Vec<String> = COLUMNS
        .iter()
        .map(|(c, d)| {
            if p.has_column("events", c) {
                format!("e.\"{c}\"")
            } else {
                format!("{d} AS \"{c}\"")
            }
        })
        .collect();
    let vs = if p.has_table("version_sets") && p.has_column("events", "version_set") {
        "LEFT JOIN version_sets v ON v.id = e.version_set"
    } else {
        "LEFT JOIN (SELECT NULL AS id, NULL AS versions_json, NULL AS blake3) v ON 0"
    };
    let ans = if p.has_table("answers") && p.has_column("events", "answer_id") {
        "LEFT JOIN answers a ON a.id = e.answer_id"
    } else {
        "LEFT JOIN (SELECT NULL AS id, NULL AS wire) a ON 0"
    };
    format!(
        "SELECT e.rowid, {}, v.versions_json, v.blake3, a.wire FROM events e {vs} {ans}",
        cols.join(", ")
    )
}

fn json_list(s: Option<String>) -> Vec<String> {
    s.and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_default()
}

/// Reads one row selected by [`select_sql`].
pub fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Rec> {
    let reason_json: Option<String> = r.get(14)?;
    let mut reason: Option<Reason> = reason_json.and_then(|s| serde_json::from_str(&s).ok());
    if reason.is_none() {
        // A partition without `reason_json`: the reason from its columns.
        let step: Option<i64> = r.get(15)?;
        if let Some(step) = step {
            let kind: Option<String> = r.get(18)?;
            let stage: Option<String> = r.get(19)?;
            reason = Some(Reason {
                step: u8::try_from(step).unwrap_or(0),
                bundle: r.get(16)?,
                key: r.get(17)?,
                kind: kind
                    .and_then(|k| serde_json::from_value(serde_json::Value::String(k)).ok())
                    .unwrap_or(MatchKind::Exact),
                stage: stage
                    .and_then(|k| serde_json::from_value(serde_json::Value::String(k)).ok())
                    .unwrap_or(Stage::Query),
                block_id: r.get(20)?,
                ..Default::default()
            });
        }
    }
    Ok(Rec {
        rowid: r.get(0)?,
        edge: r.get(1)?,
        boot: r.get(2)?,
        seq: r.get(3)?,
        ts: r.get(4)?,
        listener: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
        proto: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
        client_ip: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
        device: r.get(8)?,
        profile: r.get(9)?,
        qname: r.get::<_, Option<String>>(10)?.unwrap_or_default(),
        qtype: r.get::<_, Option<String>>(11)?.unwrap_or_default(),
        rcode: r.get::<_, Option<String>>(12)?.unwrap_or_default(),
        decision: r.get::<_, Option<String>>(13)?.unwrap_or_default(),
        reason,
        answers: json_list(r.get(21)?),
        targets: json_list(r.get(22)?),
        cname: json_list(r.get(23)?),
        truncated: r.get::<_, Option<i64>>(24)?.unwrap_or(0) != 0,
        response: r.get(25)?,
        tc: r.get::<_, Option<i64>>(26)?.unwrap_or(0) != 0,
        answer_id: r.get(27)?,
        received_at: r.get(28)?,
        age_s: r.get(29)?,
        answer_missing: r.get::<_, Option<i64>>(30)?.unwrap_or(0) != 0,
        client_do: r.get::<_, Option<i64>>(31)?.unwrap_or(0) != 0,
        lookups_json: r.get(32)?,
        cold_unchecked: json_list(r.get(33)?),
        upstream_json: r.get(34)?,
        fw_json: r.get(35)?,
        timings_json: r.get(36)?,
        edns_json: r.get(37)?,
        wire_check: r.get(38)?,
        trial_check: r.get(39)?,
        cold_check: r.get(40)?,
        versions_json: r.get::<_, Option<String>>(41)?.unwrap_or_default(),
        versions_blake3: r.get::<_, Option<String>>(42)?.unwrap_or_default(),
        answer_wire: r.get(43)?,
    })
}

/// Reads records with `clause` (`WHERE … ORDER BY … LIMIT …`, parameters `params`).
pub fn load(p: &Partition, clause: &str, params: &[&dyn rusqlite::ToSql]) -> rusqlite::Result<Vec<Rec>> {
    load_conn(&p.conn, &select_sql(p), clause, params)
}

/// [`load`] with a prepared SELECT on another connection (the read side).
pub fn load_conn(
    c: &Connection,
    select: &str,
    clause: &str,
    params: &[&dyn rusqlite::ToSql],
) -> rusqlite::Result<Vec<Rec>> {
    let mut st = c.prepare_cached(&format!("{select} {clause}"))?;
    let rows = st.query_map(params, from_row)?;
    rows.collect()
}

/// Where a record's answer values came from (core.md §6 "Values").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueSource {
    /// The upstream answer `answer_id` names.
    Answer,
    /// The reply the edge made (`response`).
    Response,
    /// The logged preview (`answers`, `targets`, `cname`).
    Preview,
}

/// The names and addresses in a record's complete logged answer.
#[derive(Clone, Debug, Default)]
pub struct AnswerValues {
    pub cname: Vec<Value>,
    pub addrs: Vec<(Value, bool)>,
    pub targets: Vec<Value>,
    pub source: Option<ValueSource>,
}

impl AnswerValues {
    /// Every value with the response-check stage it belongs to.
    pub fn staged(&self) -> Vec<(Stage, &Value)> {
        let mut v: Vec<(Stage, &Value)> = Vec::new();
        v.extend(self.cname.iter().map(|x| (Stage::Cname, x)));
        v.extend(
            self.addrs
                .iter()
                .map(|(x, hint)| (if *hint { Stage::Svcb } else { Stage::AnswerIp }, x)),
        );
        v.extend(self.targets.iter().map(|x| (Stage::Svcb, x)));
        v
    }
}

fn facts_of(wire: &[u8]) -> Option<AnswerValues> {
    let v = picket_wire::cache::CacheValue::from_logged_wire(wire, SystemTime::now(), Instant::now()).ok()?;
    let f = v.facts();
    let mut out = AnswerValues::default();
    for n in &f.chain {
        if let Some(v) = Value::name_from_log(&n.log_text()) {
            out.cname.push(v);
        }
    }
    for a in &f.addrs {
        out.addrs.push((Value::Ip(a.ip), a.source.is_hint()));
    }
    for n in &f.targets {
        if let Some(v) = Value::name_from_log(&n.log_text()) {
            out.targets.push(v);
        }
    }
    Some(out)
}

impl Rec {
    pub fn time(&self) -> Option<Timestamp> {
        crate::util::parse_ts(&self.ts)
    }

    pub fn decision(&self) -> Option<Decision> {
        serde_json::from_value(serde_json::Value::String(self.decision.clone())).ok()
    }

    /// The ladder step that decided (6, the default, when no reason was logged).
    pub fn step(&self) -> u8 {
        self.reason.as_ref().map_or(6, |r| r.step)
    }

    /// The query type as a number (0 when unknown).
    pub fn qtype_num(&self) -> u16 {
        picket_rules::rrtype::parse_rr_type(&self.qtype)
            .or_else(|| self.qtype.parse().ok())
            .unwrap_or(0)
    }

    /// The query name as a value.
    pub fn qname_value(&self) -> Option<Value> {
        Value::name_from_log(&self.qname)
    }

    /// Allowed, or rewritten with records (core.md §6 retro-match, §7 `category_answered`): a
    /// `$dnsrewrite` that returns only an rcode counts as a block.
    pub fn answered(&self) -> bool {
        match self.decision() {
            Some(Decision::Allow) => true,
            Some(Decision::Rewrite) => {
                self.rcode == "NOERROR"
                    && (!self.answers.is_empty()
                        || !self.cname.is_empty()
                        || !self.targets.is_empty()
                        || self.response.is_some()
                        || self.answer_id.is_some())
            }
            _ => false,
        }
    }

    /// Only the preview is known (core.md §6: `truncated` or `answer_missing`).
    pub fn incomplete(&self) -> bool {
        self.truncated || self.answer_missing
    }

    /// A reply the edge made itself (rewrite with records, CNAME rewrite, local name).
    pub fn edge_made(&self) -> bool {
        matches!(self.decision(), Some(Decision::Rewrite))
            || self
                .reason
                .as_ref()
                .is_some_and(|r| matches!(r.kind, MatchKind::Local))
    }

    /// The values of the record's complete logged answer: the answer its `answer_id` names, else
    /// its `response`, else the preview (core.md §6 "Values").
    pub fn answer_values(&self) -> AnswerValues {
        if let Some(w) = &self.answer_wire
            && let Some(mut v) = facts_of(w)
        {
            v.source = Some(ValueSource::Answer);
            return v;
        }
        if let Some(w) = &self.response
            && let Some(mut v) = facts_of(w)
        {
            v.source = Some(ValueSource::Response);
            return v;
        }
        let mut v = AnswerValues {
            source: Some(ValueSource::Preview),
            ..Default::default()
        };
        v.cname = self
            .cname
            .iter()
            .filter_map(|n| Value::name_from_log(n))
            .collect();
        v.addrs = self
            .answers
            .iter()
            .filter_map(|a| a.parse::<IpAddr>().ok())
            .map(|ip| (Value::Ip(ip), false))
            .collect();
        v.targets = self
            .targets
            .iter()
            .filter_map(|n| Value::name_from_log(n))
            .collect();
        v
    }

    /// The record's id in the query-log API: its hour, edge, boot and seq.
    pub fn api_id(&self) -> String {
        record_id(&self.ts, &self.edge, &self.boot, self.seq)
    }
}

/// A record id for the API: base64url of `hour \t edge \t boot \t seq`, so any edge id or boot
/// text survives a URL path.
pub fn record_id(ts: &str, edge: &str, boot: &str, seq: i64) -> String {
    use base64::Engine;
    let hour = ts.get(..13).unwrap_or("");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{hour}\t{edge}\t{boot}\t{seq}"))
}

/// Parses [`record_id`]: (partition hour, edge, boot, seq); `None` for anything else.
pub fn parse_record_id(id: &str) -> Option<(Timestamp, String, String, i64)> {
    use base64::Engine;
    if id.len() > 1024 {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(id).ok()?;
    let s = String::from_utf8(raw).ok()?;
    let mut it = s.split('\t');
    let hour = it.next()?;
    let edge = it.next()?.to_string();
    let boot = it.next()?.to_string();
    let seq: i64 = it.next()?.parse().ok()?;
    if it.next().is_some() || edge.is_empty() || edge.len() > 256 || boot.len() > 256 {
        return None;
    }
    let h = super::partition::parse_partition_name(&format!("{hour}.db"))?;
    Some((h, edge, boot, seq))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_ids_round_trip_and_refuse_junk() {
        let id = record_id("2026-11-13T10:22:01.123456Z", "e-01", "7f3a91", 1042);
        let (h, e, b, s) = parse_record_id(&id).unwrap();
        assert_eq!(crate::util::ts(&h), "2026-11-13T10:00:00.000000Z");
        assert_eq!((e.as_str(), b.as_str(), s), ("e-01", "7f3a91", 1042));
        assert!(parse_record_id("!!").is_none());
        assert!(parse_record_id("").is_none());
        use base64::Engine;
        let junk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("2026-11-13T10\te\tb\tx");
        assert!(parse_record_id(&junk).is_none());
    }

    #[test]
    fn rcode_only_rewrites_are_blocks() {
        let mut r = Rec {
            decision: "rewrite".into(),
            rcode: "NXDOMAIN".into(),
            ..Default::default()
        };
        assert!(!r.answered());
        r.rcode = "NOERROR".into();
        r.answers = vec!["192.0.2.1".into()];
        assert!(r.answered());
        r.decision = "allow".into();
        assert!(r.answered());
        r.decision = "block".into();
        assert!(!r.answered());
    }
}
