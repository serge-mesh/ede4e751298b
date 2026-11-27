//! Retro-match (core.md §6 "Retro-match"; §7 `category_answered` for feeds).
//!
//! When a feed run adds `dns` or `ip` entries, core matches them against the queries still in
//! the retention window that were allowed, or rewritten with records: `dns` entries against the
//! query name and every target name in the answer, `ip` entries against every answer address,
//! read from the answer `answer_id` names, else `response`, else the preview, using the distinct
//! names and IPs each hourly partition stores when it closes (`answered_names`,
//! `answered_ips`). An open hour is matched when it closes.
//!
//! - **Runs:** each applied run is recorded in `retro_runs` with the time core first saw it (an
//!   entry counts only for answers before it).
//! - **Progress** (README §2 Restarts): each partition's progress is a `core.db` row
//!   (`retro_progress`), committed in the same transaction as the alert effects and the metric
//!   increments ([`crate::metrics::outbox`]) of the step that made it; the partition's own writes
//!   (answered rows) come first and are idempotent. So a stop at any point repeats work without
//!   effects and never loses effects (build-and-test.md §5). It works on every log schema, since
//!   partitions are never migrated (storage.md §5).
//! - **Closing an hour** (its end plus [`CLOSE_GRACE`]): its answered records' names and
//!   addresses go into `answered_names`/`answered_ips` in pages of [`STEP_RECORDS`] by rowid; the
//!   hour's run progress starts at the newest run seen before the hour began.
//! - **Late records** (stored after their hour closed): their names and addresses are added to
//!   the hour's tables, and they are matched against the additions already matched there (and the
//!   run in progress) that came after their event time.
//! - **A run** is matched against a closed hour in bounded steps, resumable at each: first the
//!   hour's distinct answered names, then its addresses, at most [`STEP_VALUES`] per step (fewer
//!   when its work would pass [`STEP_WORK`], see below), each tested against the run's additions
//!   compiled once ([`RunMatcher`]: its distinct keys and address rules in memory when they fit,
//!   else index probes; its block patterns, capped at [`RUN_PATTERNS`] with every one past the
//!   cap counted, tested condition-free through replay's one pattern budget); the values they hit
//!   are kept (`retro_values`). Only then, if any, the hour's answered records before the run are
//!   read in pages and their values checked against those hits, with each entry's conditions
//!   evaluated for the record.
//! - **Bounded matching:** a step looks each value up once and compiles each matching entry once,
//!   aggregates its matches as it finds them (per feed run and per alert key, never one per
//!   match), and counts its work against [`STEP_WORK`]: every index probe and row a value's
//!   lookup reads, every pattern it tests (hit or miss) and every (record, entry) evaluation. A
//!   step of the value phases stops after the value that brings its work to the cap, a late or
//!   record step after the record that does, its cursor there; the next step resumes after it.
//!   A record whose matching keeps failing is skipped and counted after
//!   [`super::analysis::MAX_ATTEMPTS`] steps (`analysis_skipped{work="retro"}`), as is an alert
//!   key whose raise keeps failing (README §2: a bad item never stalls the receiver).
//! - **Counting:** an added entry counts for a record only if it would block the answer: a block
//!   rule (not an exception, `$badfilter`, rewrite or host mapping) of a feed and rule type that
//!   a bundle in the record's profile's `block` list takes (that list as in the record's config
//!   version), whose `$client`, `$ctag` or `$dnstype`, if any, matches the record. Each match
//!   counts in `retro_hits{feed}` at the time of the run, and raises `category_answered` (keyed on
//!   the feed and the registrable domain) for profiles whose `alert_categories` include the
//!   feed's category: a step's matches are grouped by alert key and each key is raised once with
//!   their count. A feed the profile only trials never counts.
//!
//! Work on one partition holds that partition's retro lock, so a close, a run's match and a late
//! record never race.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use jiff::{SignedDuration, Timestamp};
use picket_api::logs::Stage;
use picket_rules::rule::PatternSpec;
use picket_rules::{Kind, Outcome, Rule};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::analysis::{FailPoint, feed_category, raise_security};
use super::attribution::{Env, value_qtype};
use super::evidence::EvidenceRule;
use super::partition::{Partition, hour_key};
use super::record::Rec;
use super::replay::{ClientCtx, ReplayCaches, Value};
use crate::alerts::{self as alerts_mod, Changes, RaiseSpec};
use crate::compiler::source::OrderKey;
use crate::config::model::Model;
use crate::metrics::outbox::{self, Item};
use crate::state::AppState;

/// How long after an hour ends it closes (records still in flight land first; later ones take
/// the late path).
pub const CLOSE_GRACE: SignedDuration = SignedDuration::from_mins(2);
/// Records one close, late or record step reads.
const STEP_RECORDS: usize = 5_000;
/// Distinct answered values one step tests against a run's additions.
const STEP_VALUES: usize = 20_000;
/// A run's added `dns` keys held in memory to test names against; past it each name's suffixes
/// are looked up in `feed_entries` (bounded per step by [`STEP_VALUES`]).
pub const RUN_KEYS: usize = 100_000;
/// A run's added address rules held in memory (their network addresses); past it, index probes.
const RUN_IPS: usize = 50_000;
/// A run's added patterns tested (the compiler warns past 10k per feed, bundles.md §2); past it
/// the rest are left out and counted (`analysis_skipped{work="retro_patterns"}`).
pub const RUN_PATTERNS: usize = 20_000;
/// Hit values of one run kept for its record phase in one partition; past it every answered
/// record's values are tested in full.
const MAX_HIT_VALUES: usize = 50_000;
/// Work one retro step does at most (README §2 Bounded; core.md §3 bounded steps): each index
/// probe a value's lookup makes in `feed_entries` and each row it reads, each added pattern it
/// tests, hit or miss (at most [`RUN_PATTERNS`] per value), and each (record, entry) evaluation
/// counts one (a value's lookup at least one). A step that reaches it stops after the value (the
/// value phases) or the record (late records, the record phase) it is on, its cursor there; the
/// next step goes on from there.
pub const STEP_WORK: usize = 100_000;
/// Applied runs late records are matched against, at most (newest first).
const LATE_RUNS: usize = 2_000;

/// One added entry that may match.
#[derive(Clone, Debug)]
pub struct Added {
    pub run: i64,
    pub feed: String,
    pub entry: i64,
    pub rule: Rule,
    pub raw: String,
    pub line: Option<i64>,
}

/// A run core has seen, with when it saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeenRun {
    pub id: i64,
    pub feed: String,
    pub at: Timestamp,
}

/// One `category_answered` key's matches in a step: the first match (shown in the alert), the
/// feed's category, the name the feed marks bad, the matches' count and up to 16 matched
/// addresses.
struct Group {
    rec: Arc<Rec>,
    run: SeenRun,
    entry: Arc<Added>,
    value: String,
    cat: &'static str,
    bad_name: String,
    n: u32,
    ips: BTreeSet<String>,
}

/// A step's matches, aggregated as they are found (core.md §6 retro-match: each match counts in
/// `retro_hits{feed}` at the time of its run; `category_answered` is raised once per key with the
/// matches' count), so a step holds one entry per feed run and per alert key, never one per
/// match.
#[derive(Default)]
pub struct Tally {
    /// `retro_hits` per (feed, run time in Unix ms).
    per_run: BTreeMap<(String, i64), u64>,
    groups: BTreeMap<String, Group>,
    /// Matches counted.
    pub hits: usize,
}

impl Tally {
    /// Counts one match of `entry` (added by `run`) at `value` of record `rec`, and groups it
    /// under its `category_answered` key when the record's profile alerts on the feed's category
    /// (current model).
    fn add(&mut self, model: &Model, run: &SeenRun, entry: &Arc<Added>, rec: &Arc<Rec>, value: &str) {
        self.hits += 1;
        *self
            .per_run
            .entry((run.feed.clone(), run.at.as_millisecond()))
            .or_insert(0) += 1;
        let Some(profile) = rec.profile.as_deref().and_then(|p| model.profiles.get(p)) else {
            return;
        };
        if matches!(profile.edge.log, picket_api::edge_config::LogLevel::Off) {
            return;
        }
        let Some(cat) = feed_category(model, &run.feed) else {
            return;
        };
        if !profile.alert_categories.iter().any(|c| c == cat) {
            return;
        }
        // The name the feed marks bad: the matched name (the query name or a target in its
        // answer); for an address, the query name.
        let ip = value.parse::<std::net::IpAddr>().ok();
        let bad_name = if ip.is_some() {
            rec.qname.clone()
        } else {
            value.to_string()
        };
        let key = alerts_mod::category_answered_key(alerts_mod::AnsweredBy::Feed(&run.feed), &bad_name);
        let g = self.groups.entry(key).or_insert_with(|| Group {
            rec: rec.clone(),
            run: run.clone(),
            entry: entry.clone(),
            value: value.to_string(),
            cat,
            bad_name,
            n: 0,
            ips: BTreeSet::new(),
        });
        g.n = g.n.saturating_add(1);
        if let Some(ip) = ip
            && g.ips.len() < 16
        {
            g.ips.insert(picket_rules::ip::canonical_ip(ip).to_string());
        }
    }
}

/// Records every applied run newer than the newest seen (`retro_runs`), at the time core saw it
/// (within a tick of its application). The first time (an empty table: a new instance, or the
/// first start of this release) existing runs are recorded at their own download or source time,
/// so entries that predate the window's answers aren't matched as new.
pub fn record_new_runs(c: &mut Connection) -> rusqlite::Result<usize> {
    let tx = c.transaction()?;
    let newest: Option<i64> = tx.query_row("SELECT max(run_id) FROM retro_runs", [], |r| r.get(0))?;
    let now = crate::util::now_ts();
    let n = match newest {
        Some(newest) => tx.execute(
            "INSERT OR IGNORE INTO retro_runs(run_id, feed_id, at)
             SELECT id, feed_id, ?2 FROM feed_runs WHERE id > ?1 AND status = 'applied' ORDER BY id LIMIT 1000",
            params![newest, now],
        )?,
        None => tx.execute(
            "INSERT OR IGNORE INTO retro_runs(run_id, feed_id, at)
             SELECT id, feed_id, min(?1, coalesce(downloaded_at, updated_at, ?1)) FROM feed_runs
             WHERE status = 'applied' ORDER BY id DESC LIMIT 1000",
            params![now],
        )?,
    };
    tx.commit()?;
    Ok(n)
}

/// The runs seen after `after` (by id), oldest first, at most `limit`.
pub fn runs_after(c: &Connection, after: i64, limit: usize) -> rusqlite::Result<Vec<SeenRun>> {
    let mut st = c.prepare_cached(
        "SELECT run_id, feed_id, at FROM retro_runs WHERE run_id > ?1 ORDER BY run_id LIMIT ?2",
    )?;
    let rows = st.query_map(params![after, limit], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, feed, at) = row?;
        if let Some(at) = crate::util::parse_ts(&at) {
            out.push(SeenRun { id, feed, at });
        }
    }
    Ok(out)
}

/// The newest run seen before `t`.
pub fn newest_run_before(c: &Connection, t: &Timestamp) -> rusqlite::Result<i64> {
    c.query_row(
        "SELECT coalesce(max(run_id), 0) FROM retro_runs WHERE at < ?1",
        [crate::util::ts(t)],
        |r| r.get(0),
    )
}

/// True when a stored rule counts as a block for retro-match (see the module docs).
pub fn blocks(rule: &Rule) -> bool {
    !rule.is_exception()
        && !rule.is_badfilter()
        && !rule.is_rewrite()
        && !matches!(rule.key_kind(), Kind::HostMapping)
        && !matches!(rule.rule_type, picket_rules::RuleType::Browser)
}

fn added_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Option<Added>> {
    let rule_type: String = r.get(2)?;
    let kind: String = r.get(3)?;
    let key: String = r.get(4)?;
    let flags: i64 = r.get(5)?;
    let value_json: String = r.get(6)?;
    let Some((_, rule)) = crate::compiler::source::stored_rule(&rule_type, &kind, &key, flags, &value_json)
    else {
        return Ok(None);
    };
    Ok(Some(Added {
        entry: r.get(0)?,
        feed: r.get(1)?,
        run: r.get(7)?,
        raw: r.get(8)?,
        line: r.get(9)?,
        rule,
    }))
}

const ADDED_COLS: &str = "id, feed_id, rule_type, kind, key, flags, value_json, first_run, raw, line_no";

/// The suffix keys of a name's labels, most specific first (whole labels, as keys are stored:
/// reversed; a suffix that includes a label holding a `.` byte matches no key).
fn suffix_keys(labels: &[Vec<u8>]) -> Vec<String> {
    let first_ok = labels
        .iter()
        .rposition(|l| l.contains(&b'.'))
        .map_or(0, |j| j + 1);
    (first_ok..labels.len())
        .map(|start| {
            let key: Vec<String> = labels[start..]
                .iter()
                .rev()
                .map(|l| String::from_utf8_lossy(&l.to_ascii_lowercase()).into_owned())
                .collect();
            key.join(".")
        })
        .collect()
}

/// An address as the 16 bytes `feed_entries.ip_first`/`ip_last` hold, and its prefix networks.
fn ip_networks(ip: std::net::IpAddr) -> ([u8; 16], Vec<[u8; 16]>) {
    let canon = picket_rules::ip::canonical_ip(ip);
    let (bits, v): (u32, u128) = match canon {
        std::net::IpAddr::V4(a) => (32, u128::from(u32::from(a))),
        std::net::IpAddr::V6(a) => (128, u128::from(a)),
    };
    let v4 = canon.is_ipv4();
    let full = if v4 {
        (v | 0xffff_0000_0000).to_be_bytes()
    } else {
        v.to_be_bytes()
    };
    let nets = (0..=bits)
        .map(|plen| {
            let host = bits - plen;
            let mask: u128 = if host >= 128 { 0 } else { !((1u128 << host) - 1) };
            if v4 {
                ((v & mask) | 0xffff_0000_0000).to_be_bytes()
            } else {
                (v & mask).to_be_bytes()
            }
        })
        .collect();
    (full, nets)
}

/// The key a value has in `answered_names`/`answered_ips` and `retro_values`.
fn value_key(v: &Value) -> String {
    match v {
        Value::Name(_) => v.text(),
        Value::Ip(ip) => picket_rules::ip::canonical_ip(*ip).to_string(),
    }
}

/// True when pattern `spec` matches value text `text`, condition-free (conditions are evaluated
/// for each record later), through replay's one compiled-pattern budget (core.md §6).
fn pattern_hits(caches: &ReplayCaches, spec: &PatternSpec, text: &str) -> bool {
    caches.pattern_hits(spec, text)
}

/// The text a pattern runs on for `value` (rules.md §3).
fn value_text(value: &Value) -> String {
    match value {
        Value::Name(l) => picket_api::names::adguard_text(l.iter().map(Vec::as_slice)),
        Value::Ip(ip) => picket_rules::ip::go_ip_string(picket_rules::ip::canonical_ip(*ip)),
    }
}

/// Runs' additions, compiled once to test answered values against (see the module docs): one
/// run for its phases on a partition, or the window's runs for late records.
pub struct RunMatcher {
    /// The runs, by id.
    pub runs: HashMap<i64, SeenRun>,
    /// One of the runs added a `dns` or `ip` entry.
    adds: bool,
    /// The added `dns` keys, when one run's are at most [`RUN_KEYS`]; else each name's suffixes
    /// are looked up in `feed_entries`.
    keys: Option<HashSet<String>>,
    /// The network addresses (`ip_first`) of one run's added address rules, when at most
    /// [`RUN_IPS`]; else index probes.
    ip_firsts: Option<HashSet<[u8; 16]>>,
    /// The added block patterns (at most [`RUN_PATTERNS`] in all).
    patterns: Vec<(Added, PatternSpec)>,
    /// Patterns past [`RUN_PATTERNS`], left out.
    pub patterns_left_out: usize,
}

impl RunMatcher {
    /// One run's additions, with its keys and address rules in memory when they fit.
    pub fn load(c: &Connection, run: &SeenRun) -> rusqlite::Result<RunMatcher> {
        let mut m = Self::load_many(c, std::slice::from_ref(run))?;
        if !m.adds {
            return Ok(m);
        }
        // Distinct keys and network addresses, deduplicated in SQL before the limit: a set that
        // reached the limit may be missing some and is never used as complete (index probes
        // instead).
        let mut keys = HashSet::new();
        let mut st = c.prepare_cached(
            "SELECT DISTINCT key FROM feed_entries WHERE first_run = ?1 AND feed_id = ?2 AND rule_type = 'dns'
               AND kind NOT IN ('pattern', 'regex') LIMIT ?3",
        )?;
        let mut rows = st.query(params![run.id, run.feed, RUN_KEYS + 1])?;
        let mut read = 0usize;
        while let Some(r) = rows.next()? {
            read += 1;
            keys.insert(r.get::<_, String>(0)?);
        }
        m.keys = (read <= RUN_KEYS).then_some(keys);
        let mut ips = HashSet::new();
        let mut st = c.prepare_cached(
            "SELECT DISTINCT ip_first FROM feed_entries WHERE first_run = ?1 AND feed_id = ?2 AND rule_type = 'ip'
               AND ip_first IS NOT NULL LIMIT ?3",
        )?;
        let mut rows = st.query(params![run.id, run.feed, RUN_IPS + 1])?;
        let mut read = 0usize;
        while let Some(r) = rows.next()? {
            read += 1;
            let b: Vec<u8> = r.get(0)?;
            if let Ok(a) = <[u8; 16]>::try_from(b.as_slice()) {
                ips.insert(a);
            }
        }
        m.ip_firsts = (read <= RUN_IPS).then_some(ips);
        Ok(m)
    }

    /// Several runs' additions: their patterns in memory, keys and address rules looked up.
    pub fn load_many(c: &Connection, runs: &[SeenRun]) -> rusqlite::Result<RunMatcher> {
        let mut m = RunMatcher {
            runs: HashMap::new(),
            adds: false,
            keys: None,
            ip_firsts: None,
            patterns: Vec::new(),
            patterns_left_out: 0,
        };
        let mut adds = c.prepare_cached(
            "SELECT 1 FROM feed_entries WHERE first_run = ?1 AND feed_id = ?2 AND rule_type IN ('dns', 'ip') LIMIT 1",
        )?;
        // Block patterns only ([`blocks`], in SQL: no allow flag, no `$dnsrewrite`; `$badfilter`
        // and host mappings are kinds of their own), so the cap applies to the patterns kept and
        // every one past it is counted.
        let pats_sql = format!(
            "FROM feed_entries WHERE first_run = ?1 AND feed_id = ?2 AND kind IN ('pattern', 'regex')
               AND rule_type IN ('dns', 'ip') AND (flags & {allow}) = 0
               AND CASE WHEN json_valid(value_json) THEN json_extract(value_json, '$.dnsrewrite') IS NULL ELSE 1 END",
            allow = picket_rules::Flags::ALL_ALLOW.bits()
        );
        let mut pats = c.prepare_cached(&format!(
            "SELECT {ADDED_COLS} {pats_sql} AND id > ?3 ORDER BY id LIMIT ?4"
        ))?;
        let mut rest = c.prepare_cached(&format!("SELECT count(*) {pats_sql} AND id > ?3"))?;
        for run in runs {
            if !adds.exists(params![run.id, run.feed])? {
                continue;
            }
            m.adds = true;
            m.runs.insert(run.id, run.clone());
            let mut after = 0i64;
            while m.patterns.len() < RUN_PATTERNS {
                let room = RUN_PATTERNS - m.patterns.len();
                let mut rows = pats.query(params![run.id, run.feed, after, room])?;
                let mut read = 0usize;
                while let Some(row) = rows.next()? {
                    read += 1;
                    after = row.get(0)?;
                    if let Some(a) = added_from_row(row)?
                        && blocks(&a.rule)
                        && let Some(spec) = a.rule.pattern_spec()
                    {
                        m.patterns.push((a, spec));
                    }
                }
                if read < room {
                    break;
                }
            }
            if m.patterns.len() >= RUN_PATTERNS {
                let n: i64 = rest.query_row(params![run.id, run.feed, after], |r| r.get(0))?;
                m.patterns_left_out = m
                    .patterns_left_out
                    .saturating_add(usize::try_from(n).unwrap_or(0));
            }
        }
        Ok(m)
    }

    /// The block entries the runs added that can match `value` (their conditions aside); adds
    /// the lookup's work to `work` ([`STEP_WORK`]).
    pub fn entries_for(
        &self,
        c: &Connection,
        caches: &ReplayCaches,
        value: &Value,
        work: &mut usize,
    ) -> rusqlite::Result<Vec<Added>> {
        let mut out = Vec::new();
        self.visit(c, caches, value, work, &mut |a| {
            out.push(a);
            true
        })?;
        Ok(out)
    }

    /// True when some block entry the runs added can match `value` (stops at the first); adds
    /// the lookup's work to `work` ([`STEP_WORK`]).
    pub fn hits_any(
        &self,
        c: &Connection,
        caches: &ReplayCaches,
        value: &Value,
        work: &mut usize,
    ) -> rusqlite::Result<bool> {
        let mut any = false;
        self.visit(c, caches, value, work, &mut |_| {
            any = true;
            false
        })?;
        Ok(any)
    }

    /// Calls `f` with each block entry the runs added that can match `value`, once each, until
    /// it returns false. Adds to `work` one per index probe, per row read and per pattern tested,
    /// hit or miss ([`STEP_WORK`]).
    fn visit(
        &self,
        c: &Connection,
        caches: &ReplayCaches,
        value: &Value,
        work: &mut usize,
        f: &mut dyn FnMut(Added) -> bool,
    ) -> rusqlite::Result<()> {
        if !self.adds {
            return Ok(());
        }
        let mut seen: HashSet<i64> = HashSet::new();
        // Returns false once `f` asks to stop.
        let mut keep = |a: Added| -> bool {
            if self.runs.contains_key(&a.run) && blocks(&a.rule) && seen.insert(a.entry) {
                return f(a);
            }
            true
        };
        match value {
            Value::Name(labels) => {
                let mut st =
                    c.prepare_cached(&format!("SELECT {ADDED_COLS} FROM feed_entries WHERE key = ?1"))?;
                for key in suffix_keys(labels) {
                    if self.keys.as_ref().is_some_and(|ks| !ks.contains(&key)) {
                        continue;
                    }
                    *work = work.saturating_add(1);
                    let mut rows = st.query([&key])?;
                    while let Some(r) = rows.next()? {
                        *work = work.saturating_add(1);
                        if let Some(a) = added_from_row(r)?
                            && !keep(a)
                        {
                            return Ok(());
                        }
                    }
                }
            }
            Value::Ip(ip) => {
                let (full, nets) = ip_networks(*ip);
                let mut st = c.prepare_cached(&format!(
                    "SELECT {ADDED_COLS}, ip_last FROM feed_entries WHERE rule_type = 'ip' AND ip_first = ?1"
                ))?;
                for net in nets {
                    if self.ip_firsts.as_ref().is_some_and(|s| !s.contains(&net)) {
                        continue;
                    }
                    *work = work.saturating_add(1);
                    let mut rows = st.query([&net[..]])?;
                    while let Some(r) = rows.next()? {
                        *work = work.saturating_add(1);
                        let last: Option<Vec<u8>> = r.get(10)?;
                        if last.as_deref().is_some_and(|l| l < &full[..]) {
                            continue;
                        }
                        if let Some(a) = added_from_row(r)?
                            && !keep(a)
                        {
                            return Ok(());
                        }
                    }
                }
            }
        }
        if !self.patterns.is_empty() {
            let text = value_text(value);
            for (a, spec) in &self.patterns {
                *work = work.saturating_add(1);
                if pattern_hits(caches, spec, &text) && !keep(a.clone()) {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

/// The values of an answered record: the query name, the answer's names and addresses.
pub fn record_values(r: &Rec) -> Vec<(Stage, Value)> {
    let mut v: Vec<(Stage, Value)> = Vec::new();
    if let Some(q) = r.qname_value() {
        v.push((Stage::Query, q));
    }
    let av = r.answer_values();
    for (s, x) in av.staged() {
        if !v.iter().any(|(_, y)| y == x) {
            v.push((s, x.clone()));
        }
    }
    v
}

/// The matching of one step (see the module docs): the runs' additions looked up once per value
/// and compiled once per entry, every match aggregated into a [`Tally`] as it is found, the work
/// counted against [`STEP_WORK`].
struct StepMatch<'a> {
    env: &'a Env<'a>,
    m: &'a RunMatcher,
    /// Per value key, the entries that can match it (their conditions aside).
    memo: HashMap<String, Arc<[Arc<Added>]>>,
    /// Per entry, its one-rule candidate set (the regex, if a pattern, from replay's one pattern
    /// budget, core.md §6).
    evals: HashMap<i64, Arc<super::replay::Candidates>>,
    tally: Tally,
    /// Work done ([`STEP_WORK`]).
    work: usize,
}

impl<'a> StepMatch<'a> {
    fn new(env: &'a Env<'a>, m: &'a RunMatcher) -> Self {
        StepMatch {
            env,
            m,
            memo: HashMap::new(),
            evals: HashMap::new(),
            tally: Tally::default(),
            work: 0,
        }
    }

    /// The entries that can match `v`, looked up once per step (the lookup's probes, rows and
    /// pattern tests count as work, at least one).
    fn entries(&mut self, v: &Value) -> anyhow::Result<Arc<[Arc<Added>]>> {
        let vk = value_key(v);
        if let Some(e) = self.memo.get(&vk) {
            return Ok(e.clone());
        }
        let mut work = 0usize;
        let found: Arc<[Arc<Added>]> = self
            .m
            .entries_for(self.env.c, self.env.caches, v, &mut work)?
            .into_iter()
            .map(Arc::new)
            .collect();
        self.work = self.work.saturating_add(work.max(1));
        self.memo.insert(vk, found.clone());
        Ok(found)
    }

    /// The one-rule candidate set of `entry`, compiled once per step.
    fn eval_of(&mut self, entry: &Added) -> Arc<super::replay::Candidates> {
        if let Some(c) = self.evals.get(&entry.entry) {
            return c.clone();
        }
        let matcher = self
            .env
            .caches
            .matcher(picket_rules::BundleAction::Block, vec![entry.rule.clone()]);
        let c = Arc::new(super::replay::Candidates {
            rows: vec![crate::compiler::source::Row {
                order: OrderKey {
                    position: 0,
                    line_no: 0,
                    rule_type: entry.rule.rule_type.as_str(),
                    kind: entry.rule.kind.as_str(),
                    key: entry.rule.key.clone(),
                    flags: entry.rule.flags.bits(),
                    value_json: String::new(),
                },
                feed: entry.feed.clone(),
                rule: entry.rule.clone(),
                first_seen_at: String::new(),
                entry_id: entry.entry,
            }],
            matcher,
            partial: false,
        });
        self.evals.insert(entry.entry, c.clone());
        c
    }

    /// Does `entry` count for record `r` at value `value`? (see the module docs).
    fn counts(&mut self, r: &Rec, entry: &Added, stage: Stage, value: &Value) -> anyhow::Result<bool> {
        let env = self.env;
        let Some(versions) = super::replay::parse_versions(&r.versions_json) else {
            return Ok(false);
        };
        let Some(cfg) = env.caches.config(env.c, &r.edge, &versions.config)? else {
            return Ok(false);
        };
        let Some(profile) = r.profile.as_ref().and_then(|p| cfg.profiles.get(p)) else {
            return Ok(false);
        };
        let takes = profile.block.iter().any(|b| {
            env.model.bundles.get(b).is_some_and(|def| {
                def.action == crate::config::model::BundleAction::Block
                    && def.feeds.iter().any(|f| {
                        f.feed == entry.feed
                            && f.rule_types.as_ref().is_none_or(|ts| {
                                ts.iter().any(|t| {
                                    serde_json::to_value(t)
                                        .ok()
                                        .and_then(|v| v.as_str().map(str::to_string))
                                        .as_deref()
                                        == Some(entry.rule.rule_type.as_str())
                                })
                            })
                    })
            })
        });
        if !takes {
            return Ok(false);
        }
        // The entry's conditions for this record: `$client`, `$ctag`, `$dnstype` (rules.md §4).
        let client = ClientCtx::of(Some(&cfg), &r.client_ip, r.device.as_deref());
        let cands = self.eval_of(entry);
        let res = client.eval(&cands, value, value_qtype(stage, value, r.qtype_num()));
        Ok(matches!(res.outcome, Outcome::Block))
    }

    /// Matches answered record `r` against the runs (each run's additions after the record's
    /// event time), testing only `want`ed values. Its matches go into the tally only once the
    /// whole record is matched, so a record that fails leaves nothing behind.
    fn record(&mut self, r: &Arc<Rec>, want: &dyn Fn(&Value) -> bool) -> anyhow::Result<()> {
        let Some(t) = r.time() else { return Ok(()) };
        if !self.m.runs.values().any(|run| run.at > t) {
            return Ok(());
        }
        let mut found: Vec<(SeenRun, Arc<Added>, String)> = Vec::new();
        for (stage, v) in record_values(r) {
            if !want(&v) {
                continue;
            }
            for a in self.entries(&v)?.iter() {
                let Some(run) = self.m.runs.get(&a.run) else {
                    continue;
                };
                if run.at <= t {
                    continue;
                }
                self.work = self.work.saturating_add(1);
                if self.counts(r, a, stage, &v)? {
                    found.push((run.clone(), a.clone(), v.text()));
                }
            }
        }
        for (run, a, v) in found {
            self.tally.add(self.env.model, &run, &a, r, &v);
        }
        Ok(())
    }
}

/// Matches `recs` (in rowid order) through `sm`, each record on its own (README §2: a bad item
/// never stalls the receiver): a record whose matching fails fails the step while it has
/// attempts left ([`super::analysis::MAX_ATTEMPTS`], counted across steps), then is skipped and
/// counted (`analysis_skipped{work="retro"}`). Stops after the record that brings the work to
/// [`STEP_WORK`] (the test's cap when set). Returns (the last rowid done, whether it stopped
/// early, records skipped).
fn match_records(
    an: &super::analysis::Analysis,
    hour: Timestamp,
    sm: &mut StepMatch<'_>,
    recs: &[Arc<Rec>],
    want: &dyn Fn(&Rec, &Value) -> bool,
) -> anyhow::Result<(Option<i64>, bool, usize)> {
    let cap = an.retro_work().unwrap_or(STEP_WORK);
    let mut last = None;
    let mut skipped = 0usize;
    for r in recs {
        let one = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if an.poisoned_in("retro", &r.qname) {
                anyhow::bail!("a poisoned record (test)");
            }
            sm.record(r, &|v| want(r, v))
        }));
        let failed = match one {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(format!("{e:#}")),
            Err(_) => Some("the retro-match panicked".to_string()),
        };
        if let Some(e) = failed {
            if !an.failed_item_attempt(hour, &format!("r:{}", r.rowid)) {
                anyhow::bail!("retro-match of record {} failed: {e}", r.rowid);
            }
            tracing::warn!(error = %e, hour = %hour, edge = %r.edge, boot = %r.boot, seq = r.seq,
                "log record skipped by retro-match: its matching keeps failing");
            skipped += 1;
        }
        last = Some(r.rowid);
        if sm.work >= cap {
            return Ok((last, true, skipped));
        }
    }
    Ok((last, false, skipped))
}

/// Distinct (value, profile) rows.
pub type Answered = BTreeSet<(String, String)>;

/// The answered names and addresses of `recs`, by profile.
pub fn answered_rows(recs: &[Rec]) -> (Answered, Answered) {
    let mut names = BTreeSet::new();
    let mut ips = BTreeSet::new();
    for r in recs {
        if !r.answered() {
            continue;
        }
        let p = r.profile.clone().unwrap_or_default();
        for (_, v) in record_values(r) {
            match v {
                Value::Name(_) => {
                    names.insert((value_key(&v), p.clone()));
                }
                Value::Ip(_) => {
                    ips.insert((value_key(&v), p.clone()));
                }
            }
        }
    }
    (names, ips)
}

/// Inserts answered rows into a partition (idempotent).
pub fn insert_answered(
    p: &Partition,
    names: &BTreeSet<(String, String)>,
    ips: &BTreeSet<(String, String)>,
) -> rusqlite::Result<()> {
    for (n, prof) in names {
        p.insert("answered_names", &[("qname", n), ("profile", prof)], true)?;
    }
    for (ip, prof) in ips {
        p.insert("answered_ips", &[("ip", ip), ("profile", prof)], true)?;
    }
    Ok(())
}

/// Where a run's match stands inside a partition (`retro_progress.cursor`, JSON).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunCursor {
    /// The highest rowid the run covers by its phases: records stored later were matched against
    /// it as late records.
    pub limit: i64,
    /// The last (value, profile) done in the `names` or `ips` phase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<(String, String)>,
    /// The last rowid done in the `records` phase.
    #[serde(default)]
    pub rowid: i64,
}

/// A partition's retro progress (`retro_progress`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub seen: i64,
    pub closed: bool,
    pub run: i64,
    pub phase: Option<String>,
    pub cursor: Option<RunCursor>,
}

pub fn progress_get(c: &Connection, hk: &str) -> rusqlite::Result<Progress> {
    Ok(c.query_row(
        "SELECT seen, closed, run, phase, cursor FROM retro_progress WHERE hour = ?1",
        [hk],
        |r| {
            let cursor: Option<String> = r.get(4)?;
            Ok(Progress {
                seen: r.get(0)?,
                closed: r.get::<_, i64>(1)? != 0,
                run: r.get(2)?,
                phase: r.get(3)?,
                cursor: cursor.and_then(|j| serde_json::from_str(&j).ok()),
            })
        },
    )
    .optional()?
    .unwrap_or_default())
}

fn progress_put(c: &Connection, hk: &str, p: &Progress) -> rusqlite::Result<()> {
    let cursor = p.cursor.as_ref().and_then(|c| serde_json::to_string(c).ok());
    c.execute(
        "INSERT INTO retro_progress(hour, seen, closed, run, phase, cursor) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(hour) DO UPDATE SET seen = excluded.seen, closed = excluded.closed, run = excluded.run,
            phase = excluded.phase, cursor = excluded.cursor",
        params![hk, p.seen, i64::from(p.closed), p.run, p.phase, cursor],
    )?;
    Ok(())
}

/// What one retro step did.
#[derive(Default)]
pub struct StepOutcome {
    /// Matches counted.
    pub hits: usize,
    /// More work is left on this partition.
    pub more: bool,
}

/// The work one step commits to core.db, after its partition writes.
#[derive(Default)]
struct Commit {
    tally: Tally,
    /// Values the run in progress (`values_run`) hits, found this step.
    hit_values: Vec<(String, String)>,
    values_run: i64,
    drop_values: bool,
    skipped: Vec<Item>,
}

/// Runs one bounded piece of the retro work due on partition `hour` (see the module docs): its
/// close or late records first, then the next run. Holds the partition's retro lock.
pub async fn step(state: &AppState, hour: Timestamp, model: Arc<Model>) -> anyhow::Result<StepOutcome> {
    let an = state.analysis.clone();
    let lock = an.retro_lock(hour);
    let _g = lock.lock().await;
    let now = Timestamp::now();
    if picket_api::time::saturating_add(hour, SignedDuration::from_hours(1) + CLOSE_GRACE) > now
        || state.restore.logs_pending()
    {
        return Ok(StepOutcome::default());
    }
    let generation = state.restore.generation();
    let hk = hour_key(&hour);
    let prog = {
        let hk = hk.clone();
        state
            .db
            .read(move |c| Ok::<_, anyhow::Error>(progress_get(c, &hk)?))
            .await?
    };
    let window = state.settings().retention.query_logs.as_duration();
    let oldest = crate::util::window_start(now, window);
    let (step_records, _) = step_sizes(state);
    // 1. Records not in the hour's tables yet: the close, or late records.
    let store = state.logs.writer().store().clone();
    let after = prog.seen;
    let recs: Option<Vec<Rec>> = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Vec<Rec>>> {
        let Some(p) = store.open(&hour, false)? else {
            return Ok(None);
        };
        Ok(Some(super::record::load(
            &p,
            "WHERE e.rowid > ?1 ORDER BY e.rowid LIMIT ?2",
            &[&after, &step_records],
        )?))
    })
    .await??;
    let Some(recs) = recs else {
        return Ok(StepOutcome::default());
    };
    if !recs.is_empty() || !prog.closed {
        let full = recs.len() >= step_records;
        let seen = recs.last().map(|r| r.rowid).unwrap_or(prog.seen);
        let (names, ips) = answered_rows(&recs);
        if !names.is_empty() || !ips.is_empty() {
            state
                .logs
                .writer()
                .with_partition(hour, move |p| {
                    let tx = p.conn.unchecked_transaction()?;
                    insert_answered(p, &names, &ips)?;
                    tx.commit()?;
                    Ok(())
                })
                .await?;
        }
        let mut commit = Commit::default();
        let mut stopped_at: Option<i64> = None;
        if prog.closed && recs.iter().any(Rec::answered) {
            // Late records: matched against the runs already matched here (and the one in
            // progress) that came after them.
            let an2 = an.clone();
            let model2 = model.clone();
            let in_progress = prog.phase.is_some();
            let answered: Vec<Arc<Rec>> = recs.into_iter().filter(Rec::answered).map(Arc::new).collect();
            let run_limit = prog.run;
            // Only runs seen after the earliest of these answers can follow one of them.
            let since = answered
                .iter()
                .filter_map(|r| r.time())
                .min()
                .map_or(oldest, |t| t.max(oldest));
            let (tally, stopped, skipped) = state
                .db
                .read(move |c| {
                    let env = Env {
                        c,
                        caches: &an2.caches,
                        model: &model2,
                    };
                    // The runs already matched here, and the one in progress (the next after
                    // them), within the window; the newest LATE_RUNS of them.
                    let mut runs: Vec<SeenRun> = Vec::new();
                    let mut st = c.prepare_cached(
                        "SELECT run_id, feed_id, at FROM retro_runs WHERE run_id <= ?1 AND at > ?2
                         ORDER BY run_id DESC LIMIT ?3",
                    )?;
                    let rows = st.query_map(params![run_limit, crate::util::ts(&since), LATE_RUNS], |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                        ))
                    })?;
                    for row in rows {
                        let (id, feed, at) = row?;
                        if let Some(at) = crate::util::parse_ts(&at) {
                            runs.push(SeenRun { id, feed, at });
                        }
                    }
                    if in_progress
                        && let Some(next) = runs_after(c, run_limit, 1)?.into_iter().next()
                        && next.at > oldest
                    {
                        runs.push(next);
                    }
                    let matcher = RunMatcher::load_many(c, &runs)?;
                    let mut sm = StepMatch::new(&env, &matcher);
                    let (last, stopped, skipped) =
                        match_records(&an2, hour, &mut sm, &answered, &|_, _| true)?;
                    Ok::<_, anyhow::Error>((sm.tally, stopped.then_some(last).flatten(), skipped))
                })
                .await?;
            commit.tally = tally;
            if skipped > 0 {
                commit
                    .skipped
                    .push(super::analysis::skipped_item("retro", skipped));
            }
            stopped_at = stopped;
        }
        let mut next = prog.clone();
        // A step stopped by its work cap resumes after the last record it matched.
        next.seen = stopped_at.unwrap_or(seen);
        let close_now = !prog.closed && !full;
        let hits = commit.tally.hits;
        let committed = commit_step(
            state, generation, &hk, &prog, next, close_now, hour, model, commit,
        )
        .await?;
        return Ok(StepOutcome {
            hits: if committed { hits } else { 0 },
            more: true,
        });
    }
    // 2. The next run after the hour's progress.
    run_step(state, generation, hour, &hk, prog, oldest, model).await
}

/// Commits a step: alert effects, metrics and the new progress in one core.db transaction,
/// guarded by the progress the step read. False when another step got there first.
#[expect(
    clippy::too_many_arguments,
    reason = "one retro step's progress and results, committed together"
)]
async fn commit_step(
    state: &AppState,
    generation: u64,
    hk: &str,
    read: &Progress,
    mut next: Progress,
    close_now: bool,
    hour: Timestamp,
    model: Arc<Model>,
    commit: Commit,
) -> anyhow::Result<bool> {
    if commit.tally.hits > 0 && state.analysis.failing(FailPoint::RetroBeforeEffects) {
        anyhow::bail!("stopped before the retro effects (test)");
    }
    let alerts = state.alerts.clone();
    let gate = state.restore.clone();
    let an = state.analysis.clone();
    let clock = state.clock.clone();
    let hk = hk.to_string();
    let read = read.clone();
    let _ = &model;
    let done = state
        .db
        .write(move |c| {
            if !gate.is_current(generation) {
                return Ok(None);
            }
            let tx = c.transaction()?;
            if progress_get(&tx, &hk)? != read {
                return Ok(None);
            }
            if close_now {
                // The hour closed: runs seen before it began can't follow any of its answers.
                next.closed = true;
                next.run = newest_run_before(&tx, &hour)?;
            }
            let mut ch = Changes::default();
            let mut new: Vec<(i64, EvidenceRule)> = Vec::new();
            let mut items = apply_hits_in(&an, hour, &alerts, &tx, &commit.tally, &mut ch, &mut new)?;
            items.extend(commit.skipped.iter().cloned());
            outbox::queue_in(&tx, &items, &clock)?;
            for (v, p) in &commit.hit_values {
                tx.prepare_cached(
                    "INSERT OR IGNORE INTO retro_values(hour, run, profile, value) VALUES (?1, ?2, ?3, ?4)",
                )?
                .execute(params![hk, commit.values_run, p, v])?;
            }
            if commit.drop_values {
                tx.execute("DELETE FROM retro_values WHERE hour = ?1", [&hk])?;
            }
            progress_put(&tx, &hk, &next)?;
            tx.commit()?;
            alerts.committed(&ch);
            Ok::<_, anyhow::Error>(Some((ch, new)))
        })
        .await?;
    let Some((ch, new)) = done else { return Ok(false) };
    state.alerts.announce(ch);
    for (id, rule) in new {
        if let Err(e) = super::evidence::start_since(state, generation, id, rule).await {
            tracing::warn!(error = %format!("{e:#}"), alert = id, "evidence capture failed to start");
        }
    }
    Ok(true)
}

/// Raises the effects of a step's `tally` in `tx`: `retro_hits{feed}` at each run's time, and
/// `category_answered` (keyed on the feed and the registrable domain) once per key with its
/// matches' count. Each key is raised on its own (a savepoint): one that keeps failing is skipped
/// and counted after [`super::analysis::MAX_ATTEMPTS`] steps (`analysis_skipped{work="retro"}`),
/// while it has attempts left the step fails and is retried (README §2). Returns the metric
/// increments.
fn apply_hits_in(
    an: &super::analysis::Analysis,
    hour: Timestamp,
    alerts: &crate::alerts::Alerts,
    tx: &rusqlite::Transaction<'_>,
    tally: &Tally,
    ch: &mut Changes,
    new: &mut Vec<(i64, EvidenceRule)>,
) -> anyhow::Result<Vec<Item>> {
    let mut items: Vec<Item> = tally
        .per_run
        .iter()
        .map(|((feed, at), n)| {
            (
                "retro_hits".to_string(),
                crate::metrics::labels("", &[("feed", feed)]),
                *at,
                *n as f64,
            )
        })
        .collect();
    let mut skipped = 0usize;
    for (key, g) in &tally.groups {
        let domain = crate::psl::grouping_key(&g.bad_name);
        let device = super::evidence::device_of(&g.rec);
        let spec = RaiseSpec::new(
            "category_answered",
            alerts_mod::category_answered_severity(g.cat == "security"),
            key.clone(),
            format!(
                "{} got an answer for {}, which feed {} now blocks",
                crate::util::sanitize_for_message(&device, 128),
                crate::util::sanitize_for_message(&domain, 256),
                crate::util::sanitize_for_message(&g.run.feed, 128)
            ),
            json!({
                "source": "feed", "feed": g.run.feed, "category": g.cat, "domain": domain,
                "name": g.rec.qname, "value": g.value, "rule": g.entry.raw, "line": g.entry.line,
                "run": g.run.id, "added_at": crate::util::ts(&g.run.at), "answered_at": g.rec.ts,
                "profile": g.rec.profile, "device": device, "client": g.rec.client_ip,
                "edge": g.rec.edge, "record": super::record::record_id(&g.rec.ts, &g.rec.edge, &g.rec.boot, g.rec.seq),
                "matches": g.n,
            }),
        )
        .feed(&g.run.feed)
        .seen_on_edge(&g.rec.edge)
        .occurrences(g.n);
        // Its evidence: the records for names under the domain, in the query or the answer, and
        // those whose answer holds a matched address (core.md §9 Evidence).
        let rule = EvidenceRule {
            domain,
            answers: true,
            ips: g.ips.iter().cloned().collect(),
            ..Default::default()
        };
        let mut one_ch = Changes::default();
        let mut one_new = Vec::new();
        let applied = super::analysis::isolated(
            tx,
            || an.failed_item_attempt(hour, &format!("k:{key}")),
            || {
                if an.poisoned_in("retro_effects", &g.rec.qname) {
                    anyhow::bail!("a poisoned alert key (test)");
                }
                raise_security(alerts, tx, &spec, rule, &mut one_ch, &mut one_new)?;
                Ok(())
            },
        )?;
        if applied.is_some() {
            ch.extend(one_ch);
            new.extend(one_new);
        } else {
            tracing::warn!(key = %key, hour = %hour, "category_answered skipped: raising it keeps failing");
            skipped += 1;
        }
    }
    if skipped > 0 {
        items.push(super::analysis::skipped_item("retro", skipped));
    }
    Ok(items)
}

/// One step of matching the next run after `prog.run` against closed partition `hour`.
async fn run_step(
    state: &AppState,
    generation: u64,
    hour: Timestamp,
    hk: &str,
    prog: Progress,
    oldest: Timestamp,
    model: Arc<Model>,
) -> anyhow::Result<StepOutcome> {
    let after_run = prog.run;
    let run = state
        .db
        .read(move |c| Ok::<_, anyhow::Error>(runs_after(c, after_run, 1)?.into_iter().next()))
        .await?;
    let Some(run) = run else {
        return Ok(StepOutcome::default());
    };
    let finish = |mut next: Progress, run_id: i64| {
        next.run = run_id;
        next.phase = None;
        next.cursor = None;
        next
    };
    // A run older than the window, or seen before the hour began, follows none of its answers.
    if run.at <= oldest || run.at <= hour {
        let next = finish(prog.clone(), run.id);
        let commit = Commit {
            drop_values: prog.phase.is_some(),
            ..Default::default()
        };
        commit_step(state, generation, hk, &prog, next, false, hour, model, commit).await?;
        return Ok(StepOutcome { hits: 0, more: true });
    }
    let matcher = run_matcher(state, &run).await?;
    let an = state.analysis.clone();
    let (step_records, step_values) = step_sizes(state);
    let store = state.logs.writer().store().clone();
    let phase = prog.phase.clone().unwrap_or_else(|| "names".to_string());
    let cursor = prog.cursor.clone().unwrap_or(RunCursor {
        limit: prog.seen,
        after: None,
        rowid: 0,
    });
    let mut next = prog.clone();
    let mut commit = Commit::default();
    if !matcher.adds {
        let next = finish(prog.clone(), run.id);
        commit.drop_values = prog.phase.is_some();
        commit_step(state, generation, hk, &prog, next, false, hour, model, commit).await?;
        return Ok(StepOutcome { hits: 0, more: true });
    }
    if matcher.patterns_left_out > 0 && prog.phase.is_none() {
        commit.skipped.push(super::analysis::skipped_item(
            "retro_patterns",
            matcher.patterns_left_out,
        ));
    }
    match phase.as_str() {
        "names" | "ips" => {
            let table = if phase == "names" {
                "answered_names"
            } else {
                "answered_ips"
            };
            let col = if phase == "names" { "qname" } else { "ip" };
            let after = cursor.after.clone();
            let cap = an.retro_work().unwrap_or(STEP_WORK);
            // A value that misses costs a probe of every pattern, so no more values are read than
            // the cap can take that way.
            let limit = (cap / matcher.patterns.len().max(1)).clamp(1, step_values.max(1));
            let page: Vec<(String, String)> = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<(String, String)>> {
                let Some(p) = store.open(&hour, false)? else { return Ok(Vec::new()) };
                if !p.has_table(table) {
                    return Ok(Vec::new());
                }
                let (a, b) = after.unwrap_or_default();
                let mut st = p.conn.prepare(&format!(
                    "SELECT {col}, profile FROM {table} WHERE ({col}, profile) > (?1, ?2) ORDER BY {col}, profile LIMIT ?3"
                ))?;
                let v = st
                    .query_map(params![a, b, limit], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<Vec<(String, String)>>>()?;
                Ok(v)
            })
            .await??;
            let page_full = page.len() >= limit;
            commit.values_run = run.id;
            let m = matcher.clone();
            let is_names = phase == "names";
            // The page's values in order, each looked up once (a value repeated for another
            // profile reuses its result), until the work reaches the cap: the step stops after
            // that value and the next resumes after it (README §2 Bounded).
            let (hits, last, stopped) = state
                .db
                .read(move |c| {
                    let mut out = Vec::new();
                    let mut work = 0usize;
                    let mut last: Option<(String, String)> = None;
                    let mut prev: Option<(String, bool)> = None;
                    let n = page.len();
                    for (i, (v, prof)) in page.into_iter().enumerate() {
                        let value = if is_names {
                            Value::name_from_log(&v)
                        } else {
                            v.parse().ok().map(Value::Ip)
                        };
                        if let Some(value) = value {
                            let hit = match &prev {
                                Some((pv, hit)) if *pv == v => *hit,
                                _ => {
                                    let mut w = 0usize;
                                    let hit = m.hits_any(c, &an.caches, &value, &mut w)?;
                                    work = work.saturating_add(w.max(1));
                                    prev = Some((v.clone(), hit));
                                    hit
                                }
                            };
                            if hit {
                                out.push((value_key(&value), prof.clone()));
                            }
                        }
                        last = Some((v, prof));
                        if work >= cap {
                            return Ok::<_, anyhow::Error>((out, last, i + 1 < n));
                        }
                    }
                    Ok::<_, anyhow::Error>((out, last, false))
                })
                .await?;
            commit.hit_values = hits;
            let full = page_full || stopped;
            next.phase = Some(phase.clone());
            next.cursor = Some(RunCursor {
                limit: cursor.limit,
                after: last.or(cursor.after.clone()),
                rowid: 0,
            });
            if !full {
                if is_names {
                    next.phase = Some("ips".into());
                    next.cursor = Some(RunCursor {
                        limit: cursor.limit,
                        after: None,
                        rowid: 0,
                    });
                } else {
                    // The values are found: the records phase, unless none was hit.
                    let hk2 = hk.to_string();
                    let run_id = run.id;
                    let stored: i64 = state
                        .db
                        .read(move |c| {
                            Ok::<_, anyhow::Error>(c.query_row(
                                "SELECT count(*) FROM retro_values WHERE hour = ?1 AND run = ?2",
                                params![hk2, run_id],
                                |r| r.get(0),
                            )?)
                        })
                        .await?;
                    if stored == 0 && commit.hit_values.is_empty() {
                        next = finish(next, run.id);
                    } else {
                        next.phase = Some("records".into());
                        next.cursor = Some(RunCursor {
                            limit: cursor.limit,
                            after: None,
                            rowid: 0,
                        });
                    }
                }
            }
            commit_step(state, generation, hk, &prog, next, false, hour, model, commit).await?;
            Ok(StepOutcome { hits: 0, more: true })
        }
        _ => {
            // The records phase: the hour's answered records before the run, by rowid, up to the
            // phases' limit; only values among the hits are tested.
            let hk2 = hk.to_string();
            let run_id = run.id;
            let values: Vec<(String, String)> = state
                .db
                .read(move |c| {
                    let mut st = c.prepare(
                        "SELECT value, profile FROM retro_values WHERE hour = ?1 AND run = ?2 LIMIT ?3",
                    )?;
                    let v = st
                        .query_map(params![hk2, run_id, MAX_HIT_VALUES + 1], |r| {
                            Ok((r.get(0)?, r.get(1)?))
                        })?
                        .collect::<rusqlite::Result<Vec<(String, String)>>>()?;
                    Ok::<_, anyhow::Error>(v)
                })
                .await?;
            let all = values.len() > MAX_HIT_VALUES;
            let mut wanted: HashMap<String, HashSet<String>> = HashMap::new();
            if !all {
                for (v, p) in values {
                    wanted.entry(p).or_default().insert(v);
                }
            }
            let (from, limit, at) = (cursor.rowid, cursor.limit, crate::util::ts(&run.at));
            let recs: Vec<Rec> = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<Rec>> {
                let Some(p) = store.open(&hour, false)? else {
                    return Ok(Vec::new());
                };
                Ok(super::record::load(
                    &p,
                    "WHERE e.rowid > ?1 AND e.rowid <= ?2 AND e.decision IN ('allow', 'rewrite') AND e.ts < ?3
                     ORDER BY e.rowid LIMIT ?4",
                    &[&from, &limit, &at, &step_records],
                )?)
            })
            .await??;
            let full = recs.len() >= step_records;
            let last = recs.last().map(|r| r.rowid);
            let m = matcher.clone();
            let model2 = model.clone();
            let (tally, stopped, skipped) = state
                .db
                .read(move |c| {
                    let env = Env {
                        c,
                        caches: &an.caches,
                        model: &model2,
                    };
                    let recs: Vec<Arc<Rec>> = recs
                        .into_iter()
                        .filter(|r| {
                            r.answered()
                                && (all || wanted.contains_key(&r.profile.clone().unwrap_or_default()))
                        })
                        .map(Arc::new)
                        .collect();
                    let want = |r: &Rec, v: &Value| {
                        all || wanted
                            .get(r.profile.as_deref().unwrap_or(""))
                            .is_some_and(|w| w.contains(&value_key(v)))
                    };
                    let mut sm = StepMatch::new(&env, &m);
                    let (done, stopped, skipped) = match_records(&an, hour, &mut sm, &recs, &want)?;
                    Ok::<_, anyhow::Error>((sm.tally, stopped.then_some(done).flatten(), skipped))
                })
                .await?;
            commit.tally = tally;
            if skipped > 0 {
                commit
                    .skipped
                    .push(super::analysis::skipped_item("retro", skipped));
            }
            if full || stopped.is_some() {
                // More records, or the step's work cap stopped it after `stopped`.
                next.phase = Some("records".into());
                next.cursor = Some(RunCursor {
                    limit: cursor.limit,
                    after: None,
                    rowid: stopped.or(last).unwrap_or(from),
                });
            } else {
                next = finish(next, run.id);
                commit.drop_values = true;
            }
            let hits = commit.tally.hits;
            let ok = commit_step(state, generation, hk, &prog, next, false, hour, model, commit).await?;
            Ok(StepOutcome {
                hits: if ok { hits } else { 0 },
                more: true,
            })
        }
    }
}

/// The step sizes: (records, values).
fn step_sizes(state: &AppState) -> (usize, usize) {
    state
        .analysis
        .retro_steps()
        .unwrap_or((STEP_RECORDS, STEP_VALUES))
}

/// The compiled matcher of run `run`, kept while its partitions are stepped through.
async fn run_matcher(state: &AppState, run: &SeenRun) -> anyhow::Result<Arc<RunMatcher>> {
    let an = state.analysis.clone();
    if let Ok(g) = an.retro_run.lock()
        && let Some(m) = g.as_ref()
        && m.runs.len() == 1
        && m.runs.get(&run.id) == Some(run)
    {
        return Ok(m.clone());
    }
    let r = run.clone();
    let m = Arc::new(
        state
            .db
            .read(move |c| Ok::<_, anyhow::Error>(RunMatcher::load(c, &r)?))
            .await?,
    );
    if let Ok(mut g) = an.retro_run.lock() {
        *g = Some(m.clone());
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffixes_skip_labels_with_dots() {
        let labels = vec![
            b"a".to_vec(),
            b"b.c".to_vec(),
            b"example".to_vec(),
            b"com".to_vec(),
        ];
        assert_eq!(
            suffix_keys(&labels),
            vec!["com.example".to_string(), "com".to_string()]
        );
    }

    #[test]
    fn cursors_round_trip() {
        let c = RunCursor {
            limit: 9,
            after: Some(("a.example".into(), "p1".into())),
            rowid: 0,
        };
        let j = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<RunCursor>(&j).unwrap(), c);
    }

    #[test]
    fn address_networks_cover_every_prefix() {
        let (full, nets) = ip_networks("192.0.2.7".parse().unwrap());
        assert_eq!(nets.len(), 33);
        assert_eq!(nets[32], full);
        assert_eq!(&nets[24][12..], &[192, 0, 2, 0]);
    }
}
