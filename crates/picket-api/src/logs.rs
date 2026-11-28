//! Log records (api.md §5): gzip JSON lines posted to `POST /v1/logs`, at most 1,000 per batch.
//! Every record has `t`, `ts` (RFC 3339, µs), `boot` and `seq`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::time::Timestamp;

/// Most records in one batch.
pub const MAX_BATCH_RECORDS: usize = 1000;
/// Largest decoded `answer.wire` (larger answers aren't sent; records set `truncated`).
pub const MAX_ANSWER_WIRE: usize = 4096;
/// Largest decoded `q.response`.
pub const MAX_RESPONSE_WIRE: usize = 2048;
/// Most preview IPs (`answers`) and target names (`targets`).
pub const MAX_PREVIEW: usize = 4;

/// One log record. Unknown kinds deserialize as `Unknown` and are dropped by core.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum LogRecord {
    #[serde(rename = "q")]
    Query(Box<QueryRecord>),
    #[serde(rename = "answer")]
    Answer(AnswerRecord),
    #[serde(rename = "allow")]
    Allow(AllowRecord),
    #[serde(rename = "lookup")]
    Lookup(LookupRecord),
    #[serde(rename = "condition")]
    Condition(ConditionRecord),
    #[serde(rename = "event")]
    Event(EventRecord),
    #[serde(other)]
    Unknown,
}

impl LogRecord {
    /// The record's header, or `None` for an unknown kind.
    pub fn header(&self) -> Option<&RecordHeader> {
        Some(match self {
            Self::Query(r) => &r.h,
            Self::Answer(r) => &r.h,
            Self::Allow(r) => &r.h,
            Self::Lookup(r) => &r.h,
            Self::Condition(r) => &r.h,
            Self::Event(r) => &r.h,
            Self::Unknown => return None,
        })
    }
}

/// Fields every record carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordHeader {
    #[serde(with = "crate::time::micros")]
    pub ts: Timestamp,
    pub boot: String,
    pub seq: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    #[default]
    Udp,
    Tcp,
    Dot,
    Doh,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    #[default]
    Allow,
    Block,
    Rewrite,
    Refused,
    Servfail,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    #[default]
    Query,
    Cname,
    AnswerIp,
    Svcb,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    #[default]
    Exact,
    Subs,
    Pattern,
    Rich,
    Ip,
    TempAllow,
    Lookup,
    /// Answered by a forward zone (not a ladder decision).
    Forward,
    /// A special name the edge answers itself (edge.md §4).
    Local,
}

/// What decided a query (api.md §5).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Reason {
    /// Ladder step (rules.md §5): 1 temporary allow, 2 allow bundle, 3 block bundle, 4 lookup,
    /// 5 response check (with `stage`), 6 default. 0 for forward zones and local names.
    pub step: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
    /// The compiled key (reversed form not used; the name as matched).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub kind: MatchKind,
    pub stage: Stage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_id: Option<String>,
    /// True when the deciding key came from the bundle's cold part.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cold: Option<bool>,
    /// The deciding lookup provider (kind `lookup`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The temporary allow (kind `temp_allow`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_id: Option<String>,
    /// The deciding value at a response-phase stage (a CNAME target, address or SVCB target).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// `upstream` on a `q` record; `None` for answers the edge makes itself.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpstreamInfo {
    pub group: String,
    pub upstream: Option<String>,
    pub ms: u32,
    pub cached: bool,
    pub stale: bool,
    /// On a stale answer, the `cause` its EDE 3 carried (`optimistic` or the last upstream
    /// failure: `timeout`, `invalid`, `stale`, `connect`, `down`; edge.md §4 EDE), so core
    /// rebuilds the EXTRA-TEXT `cause=<cause>` the client got (core.md §6). Left out on a fresh
    /// answer. Bounded: a token of at most [`MAX_CAUSE`] bytes of `a-z`, `0-9`, `_` and `-`
    /// (a later release may add causes); anything else, including a non-string, reads as
    /// `None` without failing the record.
    ///
    /// Not yet in api.md §5 (owner to add).
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "cause_token")]
    pub cause: Option<String>,
}

/// Longest `upstream.cause` read from a record ([`UpstreamInfo::cause`]).
pub const MAX_CAUSE: usize = 32;

/// True when `s` is a cause token core keeps.
pub fn is_cause_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_CAUSE
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn cause_token<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(v.and_then(|v| match v {
        serde_json::Value::String(s) if is_cause_token(&s) => Some(s),
        _ => None,
    }))
}

/// `edns` on a `q` record: the parts of the client's OPT its reply depends on, so core rebuilds
/// the reply's size, EDE and padding as the edge chose them (core.md §6). Left out when the query
/// had no OPT. Bounded by its types (a `u16` and a flag); unknown members are ignored.
///
/// Not yet in api.md §5 (owner to add): `{"udp": 1232, "pad": true}`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EdnsInfo {
    /// The client's UDP payload size as the edge read it from the OPT (0–65535). A reader
    /// treats a value below 512 as 512 (RFC 6891 §6.2.5), as the edge does; the edge writes
    /// 512 or more.
    pub udp: u16,
    /// The query carried a Padding option (RFC 7830): a DoT or DoH reply was padded.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub pad: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FwInfo {
    pub added: u32,
}

/// Timings in µs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Timings {
    pub total: u64,
    pub filter: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LookupVerdict {
    #[default]
    Block,
    Clean,
    Unknown,
    Timeout,
    Error,
    Rejected,
}

/// One sync lookup's result on a `q` record.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LookupItem {
    pub provider: String,
    pub verdict: LookupVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub cached: bool,
    /// When the provider answered; only a provider's answer carries it.
    #[serde(with = "crate::time::micros_opt", skip_serializing_if = "Option::is_none")]
    pub obtained_at: Option<Timestamp>,
    /// The provider's `cache_generation` the verdict was obtained under.
    #[serde(rename = "gen")]
    pub generation: String,
    pub ms: u32,
    pub timed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected: Option<bool>,
    pub retry: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

/// A query record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueryRecord {
    #[serde(flatten)]
    pub h: RecordHeader,
    #[serde(default)]
    pub listener: String,
    #[serde(default)]
    pub proto: Proto,
    /// The source address.
    #[serde(default)]
    pub client: String,
    /// The client's name, else the device's MAC, else `None`.
    #[serde(default)]
    pub device: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    /// Log-text name (`names` module).
    #[serde(default)]
    pub qname: String,
    #[serde(default)]
    pub qtype: String,
    /// The client's DO bit.
    #[serde(default, rename = "do")]
    pub dnssec_ok: bool,
    #[serde(default)]
    pub rcode: String,
    #[serde(default)]
    pub decision: Decision,
    #[serde(default)]
    pub reason: Option<Reason>,
    #[serde(default)]
    pub answers: Vec<String>,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub cname: Vec<String>,
    #[serde(default)]
    pub lookups: Vec<LookupItem>,
    #[serde(default)]
    pub upstream: Option<UpstreamInfo>,
    #[serde(default)]
    pub fw: Option<FwInfo>,
    #[serde(default)]
    pub us: Timings,
    #[serde(default)]
    pub versions: Versions,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer_id: Option<String>,
    #[serde(
        default,
        with = "crate::time::micros_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub received_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_s: Option<u32>,
    /// The reply the client got (base64 wire, ≤ 2 KiB decoded), only on replies the edge made
    /// or added to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tc: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cold_unchecked: Vec<String>,
    /// The client's OPT as the reply depends on it ([`EdnsInfo`]); `None` when the query had
    /// none. Not yet in api.md §5 (owner to add).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edns: Option<EdnsInfo>,
}

/// An upstream answer `q` records reference by `answer_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerRecord {
    #[serde(flatten)]
    pub h: RecordHeader,
    /// First 16 hex characters of the BLAKE3 of the decoded `wire`.
    pub id: String,
    /// The scrubbed answer, base64, ≤ 4 KiB decoded.
    pub wire: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AllowAction {
    #[default]
    Created,
    Changed,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AllowKind {
    #[default]
    Dns,
    Ip,
}

/// A temporary allow created, changed, revoked or expired (edge.md §12).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowRecord {
    #[serde(flatten)]
    pub h: RecordHeader,
    #[serde(default)]
    pub action: AllowAction,
    #[serde(default)]
    pub allow_id: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub device: Option<String>,
    #[serde(default)]
    pub kind: AllowKind,
    /// The name (DNS) or IP.
    #[serde(default)]
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdomains: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_id: Option<String>,
    /// The profile stored with a DNS allow's block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, with = "crate::time::micros_opt")]
    pub expires_at: Option<Timestamp>,
    /// `extension`, `core`, `config` or `expiry`.
    #[serde(default)]
    pub via: String,
}

/// The late answer to a sync lookup that timed out (edge.md §10).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LookupRecord {
    #[serde(flatten)]
    pub h: RecordHeader,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub qname: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub verdict: LookupVerdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, with = "crate::time::micros_opt")]
    pub obtained_at: Option<Timestamp>,
    #[serde(default)]
    #[serde(rename = "gen")]
    pub generation: String,
    #[serde(default)]
    pub ms: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConditionChange {
    #[default]
    Appeared,
    Cleared,
}

/// One change to an edge condition.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConditionRecord {
    #[serde(flatten)]
    pub h: RecordHeader,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default)]
    pub change: ConditionChange,
    #[serde(with = "crate::time::micros")]
    pub time: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

/// A one-off event. `kind` selects the meaning of `fields`; core ignores unknown kinds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventRecord {
    #[serde(flatten)]
    pub h: RecordHeader,
    pub kind: String,
    #[serde(flatten)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

/// Event kinds (api.md §5).
pub mod event_kind {
    pub const ACTIVATED: &str = "activated";
    pub const ACTIVATION_FAILED: &str = "activation_failed";
    pub const UPDATE_OK: &str = "update_ok";
    pub const UPDATE_FAILED: &str = "update_failed";
    pub const LISTENER_REJECTED: &str = "listener_rejected";
    pub const RULES_REPAIRED: &str = "rules_repaired";
    pub const PANIC: &str = "panic";
    pub const PAGE_FILE_REFETCHED: &str = "page_file_refetched";
    /// picket-edge-helper answered `hello` with another protocol version (edge-firewall.md §4),
    /// so the edge refused to run: `{helper_proto, edge_proto, helper_version, connection}`,
    /// `connection` being `control` or `fast` (whichever saw it first), once per start. The edge
    /// exits before it binds a listener or says ready, so the record usually reaches core from
    /// the spool once a compatible edge runs again (an update rolled back, a repaired install).
    pub const HELPER_PROTOCOL_MISMATCH: &str = "helper_protocol_mismatch";
    /// A DoT or DoH listener refused a client whose ClientHello offers no TLS 1.3 (listeners
    /// speak only TLS 1.3): `{listener, transport, client, device, mac?, sni?, offered, refused,
    /// unlogged?}`, at most one per listener and device an hour. `device` is as on `q` records;
    /// `mac` is the device's MAC when the edge knows it. `offered` is one of
    /// [`super::tls_offered`]; `refused` counts the handshakes refused since the previous record
    /// for that listener and device, this one included; `unlogged` counts refusals of other
    /// devices the edge's table had no room for since its previous record.
    pub const TLS_VERSION_REFUSED: &str = "tls_version_refused";
}

/// What a refused ClientHello offered (`tls_version_refused` events): the newest version it
/// offered, from its `supported_versions` list or, without one, its legacy version.
pub mod tls_offered {
    /// TLS 1.2.
    pub const TLS12: &str = "tls12";
    /// TLS 1.1 or older.
    pub const TLS11_OR_OLDER: &str = "tls11_or_older";
    /// A `supported_versions` list without TLS 1.3 or any of SSL 3.0 to TLS 1.2 (e.g. TLS 1.3
    /// drafts only), or one without TLS 1.3 that the edge couldn't read further.
    pub const NO_TLS13: &str = "no_tls13";
}

// ---------------------------------------------------------------------------------------------
// versions (api.md §5)

/// The config version and, per bundle, the head each active part came from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Versions {
    /// Short config id.
    pub config: String,
    pub bundles: BTreeMap<String, BundleVersion>,
    #[serde(skip_serializing_if = "NotLoaded::is_empty")]
    pub not_loaded: NotLoaded,
}

/// A plain short head id when every part of that head is active; otherwise the parts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BundleVersion {
    Plain(String),
    Parts(BundleParts),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BundleParts {
    /// The head being activated (or the last one, if activation stopped part-way).
    pub head: String,
    /// Shard number → head.
    pub shards: BTreeMap<String, String>,
    /// Cold shard number → head, or `[previous, new]` mid-move.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub cold_shards: BTreeMap<String, ColdShardVersion>,
    /// IP shard id (`v4/45`, `v6`) → head.
    pub ip_shards: BTreeMap<String, String>,
    /// Segment name (`patterns.bin`, `rich.json`) → head.
    pub segments: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ColdShardVersion {
    One(String),
    /// `[previous head, new head]`: the union of both, mid-move.
    Moving([String; 2]),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NotLoaded {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cold: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub verdict_sets: Vec<String>,
}

impl NotLoaded {
    pub fn is_empty(&self) -> bool {
        self.cold.is_empty() && self.verdict_sets.is_empty()
    }
}

/// The ack core returns for a batch.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogsAck {
    pub acked: AckPoint,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AckPoint {
    pub boot: String,
    pub seq: u64,
}

/// Parses one JSON line; unknown record kinds yield `LogRecord::Unknown`.
pub fn parse_line(line: &str) -> Result<LogRecord, serde_json::Error> {
    serde_json::from_str(line)
}

/// Builds `versions` field keys for parts.
pub fn part_key_shard(n: u32) -> String {
    n.to_string()
}

/// Maps an event's extra fields; a small helper for building `EventRecord`s.
pub fn event_fields(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"{"t":"q","ts":"2026-11-13T10:22:01.123456Z","boot":"7f3a91","seq":1042,"listener":"lan-dns","proto":"udp",
 "client":"192.168.1.140","device":"emma-tablet","profile":"kids","qname":"ads.example.com","qtype":"A","do":false,"rcode":"NOERROR",
 "decision":"block","reason":{"step":3,"bundle":"block-common","key":"example.com","kind":"subs","stage":"query","block_id":"k3j9q2"},
 "answers":["0.0.0.0"],"targets":[],"truncated":false,"cname":[],"lookups":[],
 "upstream":null,"fw":null,"us":{"total":41,"filter":6},
 "versions":{"config":"9f3a91c27d0e4b6a","bundles":{"allow-common":"4be1d2a07c9e3f15","block-common":{"head":"c02f7a9e1b4d6e83",
   "shards":{"0":"c02f7a9e1b4d6e83","1":"71d9e0b3a4c25f68"},"ip_shards":{"v4/45":"c02f7a9e1b4d6e83","v6":"c02f7a9e1b4d6e83"},
   "segments":{"patterns.bin":"c02f7a9e1b4d6e83","rich.json":"c02f7a9e1b4d6e83"}}}}}"#;

    #[test]
    fn example_q_record() {
        let line = EXAMPLE.replace('\n', "");
        let r = parse_line(&line).unwrap();
        let LogRecord::Query(q) = &r else {
            panic!("not a q record")
        };
        assert_eq!(q.h.seq, 1042);
        assert_eq!(q.decision, Decision::Block);
        assert_eq!(q.reason.as_ref().unwrap().kind, MatchKind::Subs);
        assert!(matches!(
            q.versions.bundles["allow-common"],
            BundleVersion::Plain(_)
        ));
        let BundleVersion::Parts(p) = &q.versions.bundles["block-common"] else {
            panic!()
        };
        assert_eq!(p.shards["1"], "71d9e0b3a4c25f68");
        let back = serde_json::to_string(&r).unwrap();
        assert_eq!(parse_line(&back).unwrap(), r);
    }

    #[test]
    fn other_records() {
        for line in [
            r#"{"t":"allow","ts":"2026-11-13T10:22:01.123456Z","boot":"7f3a91","seq":1050,"action":"created","allow_id":"a-19","client":"192.168.1.140","device":"emma-tablet","kind":"ip","target":"100.100.100.100","expires_at":"2026-11-13T11:22:01.000000Z","via":"extension"}"#,
            r#"{"t":"answer","ts":"2026-11-13T10:22:01.874213Z","boot":"7f3a91","seq":1051,"id":"5be0c4a19d72e368","wire":"AAGBgAABAAEAAAAB"}"#,
            r#"{"t":"lookup","ts":"2026-11-13T10:22:01.874213Z","boot":"7f3a91","seq":1052,"profile":"adults","qname":"bad.example.org","provider":"q9","verdict":"block","reason":"blocked","obtained_at":"2026-11-13T10:22:02.118204Z","gen":"b71e4d09a2c63f58","ms":171,"detail":{"server":"9.9.9.9"}}"#,
            r#"{"t":"event","ts":"2026-11-13T10:22:01.874213Z","boot":"7f3a91","seq":1053,"kind":"activation_failed","bundle":"block-common","head":"c02f7a9e1b4d6e83","part":"shards/1","stage":"verify","reason":"blake3 mismatch"}"#,
            r#"{"t":"condition","ts":"2026-11-13T10:22:01.874213Z","boot":"7f3a91","seq":1054,"kind":"upstream_down","key":"cloudflare","change":"appeared","time":"2026-11-13T10:22:00.000000Z"}"#,
        ] {
            let r = parse_line(line).unwrap();
            assert!(r.header().is_some(), "{line}");
            let back = serde_json::to_string(&r).unwrap();
            assert_eq!(parse_line(&back).unwrap(), r);
        }
        let LogRecord::Event(e) = parse_line(r#"{"t":"event","ts":"2026-11-13T10:22:01.874213Z","boot":"b","seq":1,"kind":"panic","task":"x"}"#).unwrap() else { panic!() };
        assert_eq!(e.fields["task"], "x");
        assert_eq!(parse_line(r#"{"t":"future","x":1}"#).unwrap(), LogRecord::Unknown);
    }

    /// `edns` and `upstream.cause` (core.md §6 rebuilds a reply's size, EDE and padding from
    /// them) are optional: records without them still parse, and they round-trip.
    #[test]
    fn reply_rebuild_fields() {
        let line = EXAMPLE.replace('\n', "");
        let LogRecord::Query(q) = parse_line(&line).unwrap() else {
            panic!()
        };
        assert_eq!(q.edns, None);
        let with = line.replace(
            r#""upstream":null"#,
            r#""edns":{"udp":1232,"pad":true},"upstream":{"group":"cloudflare","upstream":"cf-dot-1","ms":0,"cached":true,"stale":true,"cause":"timeout"}"#,
        );
        let r = parse_line(&with).unwrap();
        let LogRecord::Query(q) = &r else { panic!() };
        assert_eq!(q.edns, Some(EdnsInfo { udp: 1232, pad: true }));
        assert_eq!(q.upstream.as_ref().unwrap().cause.as_deref(), Some("timeout"));
        let back = serde_json::to_string(&r).unwrap();
        assert_eq!(parse_line(&back).unwrap(), r);
        // Left out when absent or false.
        let plain = serde_json::to_string(&EdnsInfo { udp: 512, pad: false }).unwrap();
        assert_eq!(plain, r#"{"udp":512}"#);
        let q = parse_line(&line).unwrap();
        assert!(!serde_json::to_string(&q).unwrap().contains("edns"));
    }

    /// `upstream.cause` is bounded: an over-long or odd value, or a non-string, reads as
    /// `None` and the record still parses (README §2 Untrusted input; CC11).
    #[test]
    fn cause_is_a_bounded_token() {
        let line = EXAMPLE.replace('\n', "");
        let with = |cause: &str| {
            let l = line.replace(
                r#""upstream":null"#,
                &format!(r#""upstream":{{"group":"g","stale":true,"cause":{cause}}}"#),
            );
            let LogRecord::Query(q) = parse_line(&l).unwrap() else {
                panic!()
            };
            q.upstream.unwrap().cause
        };
        assert_eq!(with(r#""timeout""#).as_deref(), Some("timeout"));
        assert_eq!(with(r#""future-cause_2""#).as_deref(), Some("future-cause_2"));
        let long = format!("\"{}\"", "a".repeat(MAX_CAUSE + 1));
        assert_eq!(with(&long), None);
        assert_eq!(
            with(&format!("\"{}\"", "a".repeat(MAX_CAUSE))).map(|c| c.len()),
            Some(MAX_CAUSE)
        );
        for bad in [
            r#""a b""#,
            r#""Timeout""#,
            r#""""#,
            "17",
            "null",
            r#"["x"]"#,
            r#""cause=x\n""#,
        ] {
            assert_eq!(with(bad), None, "{bad}");
        }
    }

    #[test]
    fn moving_cold_shard() {
        let v: Versions = serde_json::from_str(
            r#"{"config":"c","bundles":{"b":{"head":"h2","shards":{},"cold_shards":{"3":["h1","h2"],"4":"h2"},"ip_shards":{},"segments":{}}}}"#,
        )
        .unwrap();
        let BundleVersion::Parts(p) = &v.bundles["b"] else {
            panic!()
        };
        assert!(matches!(p.cold_shards["3"], ColdShardVersion::Moving(_)));
        assert!(matches!(p.cold_shards["4"], ColdShardVersion::One(_)));
    }
}
