//! `dnssec_queue` and `dnssec_results` (storage.md §3; core.md §8 "Queue").
//!
//! - **Admission** ([`admit_in`]): a logged answer is keyed on (`answer_id`, `received_at`); a
//!   fallback or SERVFAIL query on (qname, qtype), admitted once per `dnssec.dedupe_window`. An
//!   item admitted while the wall clock isn't synchronised is stamped once it is ([`restamp_in`],
//!   README §2 Clocks). A
//!   record whose check already has a result takes it at once; one whose check is queued joins
//!   the item, which gathers its edge, client and upstream group and the record's coverage count
//!   ([`Context`]). A new item beyond the queue's cap, or its edge's share of it, is dropped.
//! - **Work:** due items by `next_at`; a result row replaces the item when its check ends.

use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

use super::validator::Outcome;

/// The queue's cap (README §2 Bounded).
pub const QUEUE_CAP: i64 = 50_000;
/// Edges, clients and upstream groups one item names at most.
pub const MAX_NAMED: usize = 64;
/// Example records one item keeps (for the alert's names and evidence).
pub const MAX_RECORDS: usize = 20;
/// Coverage bins one item keeps per edge; later records join the newest bin.
pub const MAX_BINS: usize = 512;
/// The coverage bin width: core's sampling step, the smallest chart step (core.md §10).
pub const BIN_MS: i64 = 30_000;

/// What kind of check an item is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A logged answer, validated as of its `received_at`.
    Answer,
    /// Core's own query: the answer isn't held.
    Fallback,
    /// Core's own query for an upstream SERVFAIL, never retried.
    Servfail,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Answer => "answer",
            Self::Fallback => "fallback",
            Self::Servfail => "servfail",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "fallback" => Self::Fallback,
            "servfail" => Self::Servfail,
            _ => Self::Answer,
        }
    }
}

/// One record joining an item.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecRef {
    pub edge: String,
    pub boot: String,
    pub seq: i64,
    pub ts: String,
    /// The record's device, else its client address.
    pub client: String,
    /// Its upstream group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

/// What an item gathers from the records that share its check (core.md §8: "A queued item
/// gathers the edges, clients and upstream groups of later records for it").
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    /// The upstream's rcode and whether its answer was NODATA (the negative cross-check).
    #[serde(default)]
    pub rcode: String,
    #[serde(default)]
    pub nodata: bool,
    #[serde(default)]
    pub edges: Vec<String>,
    #[serde(default)]
    pub clients: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub records: Vec<RecRef>,
    /// Records awaiting the check's result for their coverage count: edge → bin start (ms) →
    /// count (core.md §8 "Coverage").
    #[serde(default)]
    pub cov: BTreeMap<String, BTreeMap<i64, u64>>,
    /// Records that joined.
    #[serde(default)]
    pub n: u64,
}

fn push_named(v: &mut Vec<String>, s: &str) {
    if !s.is_empty() && v.len() < MAX_NAMED && !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

impl Context {
    /// Adds one record (idempotent for a record already listed among the examples).
    pub fn join(&mut self, r: &RecRef, ts_ms: i64) {
        if self
            .records
            .iter()
            .any(|x| x.edge == r.edge && x.boot == r.boot && x.seq == r.seq)
        {
            return;
        }
        push_named(&mut self.edges, &r.edge);
        push_named(&mut self.clients, &r.client);
        if let Some(g) = &r.group {
            push_named(&mut self.groups, g);
        }
        if self.records.len() < MAX_RECORDS {
            self.records.push(r.clone());
        }
        let bins = self.cov.entry(r.edge.clone()).or_default();
        let bin = ts_ms - ts_ms.rem_euclid(BIN_MS);
        if bins.len() >= MAX_BINS && !bins.contains_key(&bin) {
            // Bounded: a record past the cap counts in the edge's newest bin.
            if let Some((_, n)) = bins.iter_mut().next_back() {
                *n += 1;
            }
        } else {
            *bins.entry(bin).or_default() += 1;
        }
        self.n += 1;
    }

    pub fn parse(s: Option<&str>) -> Self {
        s.and_then(|s| serde_json::from_str(s).ok()).unwrap_or_default()
    }

    pub fn json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }
}

/// One queued item.
#[derive(Clone, Debug)]
pub struct Item {
    pub id: i64,
    pub kind: Kind,
    pub answer_id: Option<String>,
    pub received_at: Option<String>,
    pub wire: Option<Vec<u8>>,
    pub qname: String,
    pub qtype: String,
    pub first_seen: String,
    pub attempts: i64,
    pub next_at: String,
    pub edge: String,
    pub ctx: Context,
}

fn item_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Item> {
    Ok(Item {
        id: r.get(0)?,
        answer_id: r.get(1)?,
        received_at: r.get(2)?,
        wire: r.get(3)?,
        qname: r.get(4)?,
        qtype: r.get(5)?,
        first_seen: r.get(6)?,
        attempts: r.get(7)?,
        next_at: r.get(8)?,
        ctx: Context::parse(r.get::<_, Option<String>>(9)?.as_deref()),
        kind: Kind::parse(&r.get::<_, String>(10)?),
        edge: r.get(11)?,
    })
}

const ITEM_COLS: &str = "id, answer_id, received_at, wire, qname, qtype, first_seen, attempts, next_at, context_json, kind, edge_id";

/// What admitting a record did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admitted {
    /// A new item.
    Queued,
    /// Joined a queued item.
    Joined,
    /// The check already has a result: (its outcome, checked by a fallback query, the result's
    /// row id).
    Known(Outcome, bool, i64),
    /// Over the queue's cap or the edge's share.
    Dropped,
}

/// One record to admit.
pub struct Admit<'a> {
    pub kind: Kind,
    pub answer_id: Option<&'a str>,
    pub received_at: Option<&'a str>,
    pub wire: Option<&'a [u8]>,
    pub qname: &'a str,
    pub qtype: &'a str,
    pub rcode: &'a str,
    pub nodata: bool,
    pub rec: RecRef,
    pub ts_ms: i64,
}

/// Queue sizes, counted once per admission batch.
#[derive(Clone, Debug, Default)]
pub struct Sizes {
    /// The queue's cap ([`QUEUE_CAP`]; tests lower it).
    pub cap: i64,
    pub total: i64,
    pub per_edge: BTreeMap<String, i64>,
    /// Edges with items or admitting now (the share is the cap over them, at least a quarter).
    pub edges: usize,
}

impl Sizes {
    pub fn load(tx: &Transaction<'_>, cap: i64) -> rusqlite::Result<Self> {
        let mut s = Sizes {
            cap,
            ..Sizes::default()
        };
        let mut st = tx.prepare("SELECT edge_id, count(*) FROM dnssec_queue GROUP BY edge_id")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for r in rows {
            let (e, n) = r?;
            s.total += n;
            s.per_edge.insert(e, n);
        }
        s.edges = s.per_edge.len();
        Ok(s)
    }

    fn share(&self) -> i64 {
        let edges = i64::try_from(self.edges.max(1)).unwrap_or(1);
        (self.cap / edges).max(self.cap / 4).max(1)
    }

    fn admits(&mut self, edge: &str) -> bool {
        if !self.per_edge.contains_key(edge) {
            self.edges += 1;
        }
        let mine = self.per_edge.get(edge).copied().unwrap_or(0);
        if self.total >= self.cap || mine >= self.share() {
            return false;
        }
        self.total += 1;
        *self.per_edge.entry(edge.to_string()).or_default() += 1;
        true
    }
}

/// Admits one record (module docs). `dedupe_from` is now less `dnssec.dedupe_window`; `None`
/// while the wall clock isn't synchronised (README §2 Clocks): then no result is reused by its
/// time, and a new item is stored unstamped, its `first_seen` and `next_at` set when the clock
/// is synchronised ([`restamp_in`]).
pub fn admit_in(
    tx: &Transaction<'_>,
    a: &Admit<'_>,
    now: &str,
    dedupe_from: Option<&str>,
    sizes: &mut Sizes,
) -> rusqlite::Result<Admitted> {
    let queued: Option<(i64, Option<String>)> = match a.kind {
        Kind::Answer => {
            let known: Option<(i64, String)> = tx
                .query_row(
                    "SELECT id, outcome FROM dnssec_results WHERE answer_id = ?1 AND received_at = ?2 ORDER BY id DESC LIMIT 1",
                    params![a.answer_id, a.received_at],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((id, o)) = known
                && let Some(o) = Outcome::parse(&o)
            {
                return Ok(Admitted::Known(o, false, id));
            }
            tx.query_row(
                "SELECT id, context_json FROM dnssec_queue WHERE answer_id = ?1 AND received_at = ?2",
                params![a.answer_id, a.received_at],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
        }
        Kind::Fallback | Kind::Servfail => {
            let q = tx
                .query_row(
                    "SELECT id, context_json FROM dnssec_queue WHERE answer_id IS NULL AND qname = ?1 AND qtype = ?2",
                    params![a.qname, a.qtype],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if q.is_none()
                && let Some(dedupe_from) = dedupe_from
            {
                let known: Option<(i64, String)> = tx
                    .query_row(
                        "SELECT id, outcome FROM dnssec_results WHERE answer_id IS NULL AND qname = ?1 AND qtype = ?2 AND at >= ?3
                         ORDER BY at DESC LIMIT 1",
                        params![a.qname, a.qtype, dedupe_from],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                if let Some((id, o)) = known
                    && let Some(o) = Outcome::parse(&o)
                {
                    return Ok(Admitted::Known(o, true, id));
                }
            }
            q
        }
    };
    if let Some((id, ctx)) = queued {
        let mut c = Context::parse(ctx.as_deref());
        c.join(&a.rec, a.ts_ms);
        tx.execute(
            "UPDATE dnssec_queue SET context_json = ?2 WHERE id = ?1",
            params![id, c.json()],
        )?;
        return Ok(Admitted::Joined);
    }
    if !sizes.admits(&a.rec.edge) {
        return Ok(Admitted::Dropped);
    }
    let mut c = Context {
        rcode: a.rcode.to_string(),
        nodata: a.nodata,
        ..Context::default()
    };
    c.join(&a.rec, a.ts_ms);
    tx.execute(
        "INSERT INTO dnssec_queue(answer_id, received_at, wire, qname, qtype, first_seen, attempts, next_at, context_json, kind, edge_id, stamped)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?6, ?7, ?8, ?9, ?10)",
        params![
            a.answer_id,
            a.received_at,
            a.wire,
            a.qname,
            a.qtype,
            now,
            c.json(),
            a.kind.as_str(),
            a.rec.edge,
            dedupe_from.is_some()
        ],
    )?;
    Ok(Admitted::Queued)
}

/// Stamps the items admitted while the wall clock wasn't synchronised with `now` (README §2
/// Clocks: their age is measured from here, and they are due at once). Returns how many.
pub fn restamp_in(tx: &Transaction<'_>, now: &str) -> rusqlite::Result<usize> {
    tx.execute(
        "UPDATE dnssec_queue SET first_seen = ?1, next_at = ?1, stamped = 1 WHERE stamped = 0",
        [now],
    )
}

/// Due items, earliest first.
pub fn due(c: &rusqlite::Connection, now: &str, limit: usize) -> rusqlite::Result<Vec<Item>> {
    let mut st = c.prepare(&format!(
        "SELECT {ITEM_COLS} FROM dnssec_queue WHERE next_at <= ?1 ORDER BY next_at, id LIMIT ?2"
    ))?;
    let rows = st.query_map(params![now, i64::try_from(limit).unwrap_or(64)], item_row)?;
    rows.collect()
}

/// Items for the UI, earliest due first.
pub fn list(c: &rusqlite::Connection, limit: usize) -> rusqlite::Result<(Vec<Item>, i64)> {
    let total: i64 = c.query_row("SELECT count(*) FROM dnssec_queue", [], |r| r.get(0))?;
    let mut st = c.prepare(&format!(
        "SELECT {ITEM_COLS} FROM dnssec_queue ORDER BY next_at, id LIMIT ?1"
    ))?;
    let rows = st.query_map([i64::try_from(limit).unwrap_or(100)], item_row)?;
    Ok((rows.collect::<rusqlite::Result<_>>()?, total))
}

/// Deletes the items first seen before `cutoff` (older than the retention window) and returns
/// them, at most `limit`. Unstamped items ([`restamp_in`]) have no age yet.
pub fn take_old_in(tx: &Transaction<'_>, cutoff: &str, limit: usize) -> rusqlite::Result<Vec<Item>> {
    let items: Vec<Item> = {
        let mut st = tx.prepare(&format!(
            "SELECT {ITEM_COLS} FROM dnssec_queue WHERE first_seen < ?1 AND stamped = 1 ORDER BY first_seen LIMIT ?2"
        ))?;
        st.query_map(params![cutoff, i64::try_from(limit).unwrap_or(1000)], item_row)?
            .collect::<rusqlite::Result<_>>()?
    };
    for it in &items {
        tx.execute("DELETE FROM dnssec_queue WHERE id = ?1", [it.id])?;
    }
    Ok(items)
}

/// Re-reads an item's context (records may have joined while it was checked).
pub fn context_in(tx: &Transaction<'_>, id: i64) -> rusqlite::Result<Option<Context>> {
    Ok(tx
        .query_row("SELECT context_json FROM dnssec_queue WHERE id = ?1", [id], |r| {
            r.get::<_, Option<String>>(0)
        })
        .optional()?
        .map(|c| Context::parse(c.as_deref())))
}

/// Ends an item with its result row; returns the item's context as it stood, or `None` when the
/// item is no longer queued (a restore emptied the queue while it was checked, core.md §2): then
/// nothing is stored.
pub fn finish_in(
    tx: &Transaction<'_>,
    it: &Item,
    outcome: Outcome,
    detail: &serde_json::Value,
    now: &str,
) -> rusqlite::Result<Option<Context>> {
    let Some(ctx) = context_in(tx, it.id)? else {
        return Ok(None);
    };
    tx.execute(
        "INSERT INTO dnssec_results(answer_id, received_at, qname, qtype, at, outcome, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            it.answer_id,
            it.received_at,
            it.qname,
            it.qtype,
            now,
            outcome.as_str(),
            detail.to_string()
        ],
    )?;
    tx.execute("DELETE FROM dnssec_queue WHERE id = ?1", [it.id])?;
    Ok(Some(ctx))
}

/// The result row of a known check: its outcome's detail (zone, …).
pub fn result_detail_in(tx: &Transaction<'_>, id: i64) -> rusqlite::Result<Option<serde_json::Value>> {
    Ok(tx
        .query_row("SELECT detail FROM dnssec_results WHERE id = ?1", [id], |r| {
            r.get::<_, Option<String>>(0)
        })
        .optional()?
        .flatten()
        .and_then(|d| serde_json::from_str(&d).ok()))
}

/// Sets an item's next attempt (`attempts` counts only requests that were made and failed);
/// false when the item is no longer queued.
pub fn reschedule_in(tx: &Transaction<'_>, id: i64, attempts: i64, next_at: &str) -> rusqlite::Result<bool> {
    Ok(tx.execute(
        "UPDATE dnssec_queue SET attempts = ?2, next_at = ?3 WHERE id = ?1",
        params![id, attempts, next_at],
    )? > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(edge: &str, seq: i64) -> RecRef {
        RecRef {
            edge: edge.into(),
            boot: "b".into(),
            seq,
            ts: String::new(),
            client: format!("10.0.0.{seq}"),
            group: Some("cloudflare".into()),
            profile: None,
        }
    }

    #[test]
    fn contexts_gather_and_bin() {
        let mut c = Context::default();
        c.join(&rec("e1", 1), 1_000);
        c.join(&rec("e1", 1), 1_000);
        c.join(&rec("e2", 2), 31_000);
        c.join(&rec("e1", 3), 29_000);
        assert_eq!(c.n, 3, "a record listed already doesn't count twice");
        assert_eq!(c.edges, vec!["e1", "e2"]);
        assert_eq!(c.groups, vec!["cloudflare"]);
        assert_eq!(c.cov["e1"][&0], 2);
        assert_eq!(c.cov["e2"][&30_000], 1);
    }

    #[test]
    fn shares_cap_each_edge() {
        let mut s = Sizes {
            cap: QUEUE_CAP,
            total: QUEUE_CAP - 1,
            ..Sizes::default()
        };
        assert!(s.admits("e1"));
        assert!(!s.admits("e2"), "the queue is full");
        let mut s = Sizes {
            cap: QUEUE_CAP,
            total: QUEUE_CAP / 2 + 1,
            per_edge: [("e1".to_string(), QUEUE_CAP / 2), ("e2".to_string(), 1)].into(),
            edges: 2,
        };
        assert!(!s.admits("e1"), "e1 has its half");
        assert!(s.admits("e2"), "another edge still has its share");
    }
}
