//! The IP pass in bounded steps (bundles.md §2 step 4, §4 IP shards; core.md §3: a heavy step is
//! bounded): the bundle's IP rules are staged a page per step in `bundle_build_ip_rules`
//! ([`load_step`]), then folded into runs in address order a page per step ([`fold_step`]).
//!
//! - **Staging** reads each member feed's IP rules by stored kind and entry id
//!   ([`super::source::View::ip_page`]); past [`super::build::MAX_IP_RULES`] the build is refused,
//!   as before.
//! - **Compiling** goes one range group at a time (every rule with one first and last address,
//!   read together): `$badfilter` only relates rules with one identity, so a group compiles as
//!   the whole bundle would ([`super::compile::compile_ips_ordered`]).
//! - **Folding** is [`Sweep`], a resumable form of picket-bundle's
//!   [`fold_runs`](picket_bundle::runs::fold_runs) with the same runs and the same rich sets in the
//!   same order: the boundary points are every first address and every last address + 1, visited
//!   in order; a point is taken only once every rule starting at or before it is read (the
//!   *horizon*: the first address of the next unread rule), and a step stops after a fixed amount
//!   of work ([`SWEEP_WORK`]) and goes on from there next step.
//! - **Shards** are complete once the sweep is past their last address: each is diffed against
//!   its stored runs (its set checksum first), and a changed shard's runs go to
//!   `bundle_build_ip_runs` for the rest of the build and the commit, so no step holds every run.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Result, anyhow};
use picket_bundle::Value;
use picket_bundle::checksum::SetChecksum;
use picket_bundle::ips::{IpShardId, Run};
use picket_bundle::rich::RichBuilder;
use picket_bundle::runs::{IpRuleInput, diff_runs};
use picket_rules::Flags;
use rusqlite::{Connection, params};

use super::build::{Ctx, MAX_IP_RULES, Mode};
use super::compile::CompileCounts;
use super::source::{OrderKey, Row, View};
use crate::state::SharedState;

/// IP rule rows one staging step reads.
pub const LOAD_ROWS: usize = 50_000;
/// Staged rules one fold step reads (plus the rest of the last range group).
pub const FOLD_ROWS: usize = 50_000;
/// Work one fold step's sweep does: a boundary point costs one plus the rules active at it.
pub const SWEEP_WORK: usize = 500_000;
/// Completed shards one fold step diffs and stores.
pub const SHARDS_PER_STEP: usize = 16;

/// One compiled IP rule awaiting the sweep, with its place in bundle order.
pub struct Input {
    pub order: OrderKey,
    pub rule: IpRuleInput,
}

/// The resumable sweep of one address family: the same runs, rich sets and set order as
/// [`picket_bundle::runs::fold_runs`] over the family's rules (module docs).
pub struct Sweep {
    /// Rules read but not started yet, by first address.
    buf: VecDeque<Input>,
    /// Rules covering the last point visited, in bundle order (fold_runs takes them in input
    /// order, which is bundle order).
    active: Vec<Input>,
    /// The last run, still open to extension.
    pending: Option<Run>,
}

impl Default for Sweep {
    fn default() -> Self {
        Self::new()
    }
}

impl Sweep {
    pub fn new() -> Self {
        Self {
            buf: VecDeque::new(),
            active: Vec::new(),
            pending: None,
        }
    }

    /// Adds a rule; rules come by first address (equal ones in any order).
    pub fn push(&mut self, i: Input) {
        self.buf.push_back(i);
    }

    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// The next boundary point after the last one visited, short of `horizon`.
    fn next_point(&self, horizon: Option<u128>) -> Option<u128> {
        let nf = self.buf.front().map(|r| r.rule.range.first);
        let ne = self
            .active
            .iter()
            .filter_map(|r| r.rule.range.last.checked_add(1))
            .min();
        [nf, ne, horizon].into_iter().flatten().min()
    }

    /// Visits the points below `horizon` (`None`: no rule is left to read) until `work` runs out;
    /// finished runs go to `emit`. Returns `true` when every point below the horizon is visited.
    pub fn run(
        &mut self,
        horizon: Option<u128>,
        work: &mut usize,
        rich: &mut RichBuilder,
        emit: &mut dyn FnMut(Run),
    ) -> bool {
        loop {
            let Some(p) = self.next_point(None) else {
                return true;
            };
            if horizon.is_some_and(|h| p >= h) {
                return true;
            }
            if *work == 0 {
                return false;
            }
            *work = work.saturating_sub(1 + self.active.len());
            while self.buf.front().is_some_and(|r| r.rule.range.first <= p) {
                if let Some(r) = self.buf.pop_front() {
                    let at = self.active.partition_point(|a| a.order < r.order);
                    self.active.insert(at, r);
                }
            }
            self.active.retain(|r| r.rule.range.last >= p);
            if self.active.is_empty() {
                continue;
            }
            let end = match self.next_point(horizon) {
                Some(n) => n.saturating_sub(1),
                None => self.active.iter().map(|r| r.rule.range.last).max().unwrap_or(p),
            };
            let mut flags = Flags::NONE;
            let mut rich_rules = Vec::new();
            for r in &self.active {
                flags |= r.rule.flags.and(Flags::ALL_LEVELS);
                if let Some(rr) = &r.rule.rich {
                    rich_rules.push(rr.clone());
                }
            }
            let value = if rich_rules.is_empty() {
                Value::flags_only(flags)
            } else {
                let set = rich.set(&rich_rules);
                Value::new(flags | Flags::HAS_RICH, set)
            };
            if value.flags().is_empty() {
                continue;
            }
            match &mut self.pending {
                Some(l) if l.value == value && l.last.checked_add(1) == Some(p) => l.last = end,
                _ => {
                    if let Some(old) = self.pending.replace(Run {
                        first: p,
                        last: end,
                        value,
                    }) {
                        emit(old);
                    }
                }
            }
        }
    }

    /// The lowest address a run not emitted yet can start at (`None`: none can).
    pub fn low(&self, horizon: Option<u128>) -> Option<u128> {
        match &self.pending {
            Some(r) => Some(r.first),
            None => self.next_point(horizon),
        }
    }

    /// Emits the open run (the family's end).
    pub fn flush(&mut self, emit: &mut dyn FnMut(Run)) {
        if let Some(r) = self.pending.take() {
            emit(r);
        }
    }
}

/// Adds a run to its shard(s), split at IPv4 /8 boundaries (picket-bundle's rule).
pub fn split_into(out: &mut BTreeMap<IpShardId, Vec<Run>>, v4: bool, run: Run) {
    if !v4 {
        out.entry(IpShardId::V6).or_default().push(run);
        return;
    }
    let mut s = run.first;
    loop {
        let shard = IpShardId::of(true, s);
        let (_, hi) = shard.bounds();
        let e = run.last.min(hi);
        out.entry(shard).or_default().push(Run {
            first: s,
            last: e,
            value: run.value,
        });
        if e >= run.last {
            break;
        }
        s = e.saturating_add(1);
    }
}

/// Where staging stands: member (among those taking `ip` rules), stored kind, entry id.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoadAt {
    feed: usize,
    kind: usize,
    cursor: i64,
    pub rows: usize,
    pub done: bool,
}

/// Stages one page of the bundle's IP rules (see the module docs); `true` when all are staged.
pub async fn load_step(state: &SharedState, ctx: &mut Ctx) -> Result<bool> {
    let at = ctx.ip_load;
    if at.done {
        return Ok(true);
    }
    let (spec, runs, bundle) = (ctx.spec.clone(), ctx.runs.clone(), ctx.spec.id.clone());
    let limit = state.compiler.step_rows(LOAD_ROWS);
    let (rows, next, bad) = state
        .db
        .read(move |c| {
            let view = View::new(&spec, &runs);
            let feeds: Vec<String> = view
                .feeds()
                .filter(|(f, _)| {
                    spec.member(f)
                        .is_some_and(|m| spec.compiled_types(m).contains(&picket_rules::RuleType::Ip))
                })
                .map(|(f, _)| f.to_string())
                .collect();
            let mut at = at;
            let mut bad = 0u64;
            loop {
                let Some(f) = feeds.get(at.feed) else {
                    at.done = true;
                    return Ok::<_, anyhow::Error>((Vec::new(), at, bad));
                };
                let Some(k) = super::source::IP_KINDS.get(at.kind) else {
                    at = LoadAt {
                        feed: at.feed + 1,
                        rows: at.rows,
                        ..LoadAt::default()
                    };
                    continue;
                };
                let (rows, next) = view.ip_page(c, f, k, at.cursor, limit, &mut bad)?;
                match next {
                    Some(n) => at.cursor = n,
                    None => {
                        at.kind += 1;
                        at.cursor = -1;
                    }
                }
                return Ok((rows, at, bad));
            }
        })
        .await?;
    ctx.bad_rows += bad;
    let mut next = next;
    next.rows += rows.len();
    if next.rows > MAX_IP_RULES {
        return Err(anyhow!("more than {MAX_IP_RULES} IP rules; the build is refused"));
    }
    if !rows.is_empty() {
        state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                {
                    let mut st = tx.prepare_cached(
                        "INSERT OR IGNORE INTO bundle_build_ip_rules(bundle_id, fam, \"first\", \"last\", entry_id, feed_id,
                            position, line_no, rule_type, kind, key, flags, value_json, first_seen_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    )?;
                    for r in &rows {
                        let Some(ip) = r.rule.ip_range() else { continue };
                        st.execute(params![
                            bundle,
                            if ip.v4 { 0 } else { 1 },
                            &ip.first.to_be_bytes()[..],
                            &ip.last.to_be_bytes()[..],
                            r.entry_id,
                            r.feed,
                            i64::from(r.order.position),
                            r.order.line_no,
                            r.order.rule_type,
                            r.order.kind,
                            r.order.key,
                            i64::from(r.order.flags),
                            r.order.value_json,
                            r.first_seen_at,
                        ])?;
                    }
                }
                tx.commit()?;
                Ok::<_, anyhow::Error>(())
            })
            .await?;
    }
    ctx.ip_load = next;
    Ok(next.done)
}

/// A position in the staged rules: (family, first, last, entry id).
pub type StageCursor = (i64, Vec<u8>, Vec<u8>, i64);

/// The position before family `fam`'s first staged rule.
pub fn fam_start(fam: i64) -> StageCursor {
    (fam, Vec::new(), Vec::new(), -1)
}

/// One page of family `cursor.0`'s staged rules after `cursor`: whole range groups (every rule
/// with one first and last address), at least `limit` rows unless the family ends first, each
/// group as rows in bundle order. Returns the groups, the new cursor, and the family and first
/// address of the next unread row of any family (`None`: the end).
#[expect(
    clippy::type_complexity,
    reason = "the groups, cursor and next row described above, taken apart at once by the caller"
)]
pub fn read_groups(
    c: &Connection,
    bundle: &str,
    cursor: &StageCursor,
    limit: usize,
    bad: &mut u64,
) -> Result<(Vec<Vec<Row>>, StageCursor, Option<(i64, u128)>)> {
    const COLS: &str =
        "fam, \"first\", \"last\", entry_id, feed_id, position, line_no, rule_type, kind, key, flags,
        value_json, first_seen_at";
    let mut page = c.prepare_cached(&format!(
        "SELECT {COLS} FROM bundle_build_ip_rules WHERE bundle_id = ?1 AND fam = ?2
           AND (\"first\", \"last\", entry_id) > (?3, ?4, ?5) ORDER BY \"first\", \"last\", entry_id LIMIT ?6"
    ))?;
    let mut rest = c.prepare_cached(&format!(
        "SELECT {COLS} FROM bundle_build_ip_rules WHERE bundle_id = ?1 AND fam = ?2 AND \"first\" = ?3
           AND \"last\" = ?4 AND entry_id > ?5 ORDER BY entry_id"
    ))?;
    let mut peek = c.prepare_cached(
        "SELECT fam, \"first\" FROM bundle_build_ip_rules WHERE bundle_id = ?1
           AND (fam, \"first\", \"last\", entry_id) > (?2, ?3, ?4, ?5) ORDER BY fam, \"first\", \"last\", entry_id LIMIT 1",
    )?;
    let mut groups: Vec<Vec<Row>> = Vec::new();
    let mut cur = cursor.clone();
    let mut last_key: Option<(Vec<u8>, Vec<u8>)> = None;
    let mut take = |r: &rusqlite::Row<'_>,
                    groups: &mut Vec<Vec<Row>>,
                    cur: &mut StageCursor,
                    last_key: &mut Option<(Vec<u8>, Vec<u8>)>|
     -> rusqlite::Result<()> {
        let first: Vec<u8> = r.get(1)?;
        let last: Vec<u8> = r.get(2)?;
        *cur = (r.get(0)?, first.clone(), last.clone(), r.get(3)?);
        let key = (first, last);
        if last_key.as_ref() != Some(&key) {
            groups.push(Vec::new());
            *last_key = Some(key);
        }
        if let (Some(row), Some(g)) = (stored_row(r, bad)?, groups.last_mut()) {
            g.push(row);
        }
        Ok(())
    };
    {
        let mut rows = page.query(params![bundle, cursor.0, cursor.1, cursor.2, cursor.3, limit])?;
        while let Some(r) = rows.next()? {
            take(r, &mut groups, &mut cur, &mut last_key)?;
        }
    }
    // The rest of the last group.
    if last_key.is_some() {
        let (fam, first, last, id) = cur.clone();
        let mut rows = rest.query(params![bundle, fam, first, last, id])?;
        while let Some(r) = rows.next()? {
            take(r, &mut groups, &mut cur, &mut last_key)?;
        }
    }
    let next = peek
        .query_row(params![bundle, cur.0, cur.1, cur.2, cur.3], |r| {
            Ok((r.get::<_, i64>(0)?, u128_of(&r.get::<_, Vec<u8>>(1)?)))
        })
        .ok();
    for g in groups.iter_mut() {
        g.sort_by(|a, b| a.order.cmp(&b.order));
    }
    Ok((groups, cur, next))
}

fn u128_of(b: &[u8]) -> u128 {
    <[u8; 16]>::try_from(b).map(u128::from_be_bytes).unwrap_or(0)
}

/// A staged row as a rule of the bundle (as [`View`] reads it).
fn stored_row(r: &rusqlite::Row<'_>, bad: &mut u64) -> rusqlite::Result<Option<Row>> {
    let rule_type: String = r.get(7)?;
    let kind: String = r.get(8)?;
    let key: String = r.get(9)?;
    let flags: i64 = r.get(10)?;
    let value_json: String = r.get(11)?;
    let Some((flags, rule)) = super::source::stored_rule(&rule_type, &kind, &key, flags, &value_json) else {
        *bad += 1;
        return Ok(None);
    };
    Ok(Some(Row {
        order: OrderKey {
            position: u32::try_from(r.get::<_, i64>(5)?).unwrap_or(u32::MAX),
            line_no: r.get(6)?,
            rule_type: rule.rule_type.as_str(),
            kind: rule.kind.as_str(),
            key,
            flags,
            value_json,
        },
        feed: r.get(4)?,
        rule,
        first_seen_at: r.get(12)?,
        entry_id: r.get(3)?,
    }))
}

/// The fold of the staged rules while it runs (see the module docs).
pub struct IpFold {
    /// The previous head's IP shards and their set checksums.
    prev: BTreeMap<IpShardId, SetChecksum>,
    /// The family being swept (0: IPv4, 1: IPv6, 2: done).
    fam: i64,
    cursor: StageCursor,
    /// The next unread row (`None`: every row is read).
    next: Option<(i64, u128)>,
    /// The last sweep visited every point below the horizon: read more first.
    starved: bool,
    sweep: Sweep,
    /// Runs of shards not complete yet; completed shards waiting to be stored.
    shards: BTreeMap<IpShardId, Vec<Run>>,
    complete: VecDeque<(IpShardId, Vec<Run>)>,
    seen: BTreeSet<IpShardId>,
    out: super::assemble::IpOutcome,
    counts: CompileCounts,
}

impl IpFold {
    pub fn new(ctx: &Ctx) -> IpFold {
        let prev = ctx
            .prev
            .as_ref()
            .filter(|_| ctx.mode != Mode::Fresh)
            .map(|p| {
                p.head
                    .ip_shards
                    .iter()
                    .map(|s| (s.ip_shard, s.checksum))
                    .collect()
            })
            .unwrap_or_default();
        IpFold {
            prev,
            fam: 0,
            cursor: fam_start(0),
            next: Some((0, 0)),
            starved: true,
            sweep: Sweep::new(),
            shards: BTreeMap::new(),
            complete: VecDeque::new(),
            seen: BTreeSet::new(),
            out: super::assemble::IpOutcome {
                recomputed: true,
                ..Default::default()
            },
            counts: CompileCounts::default(),
        }
    }

    /// The horizon of the family being swept: the first address of its next unread rule.
    fn horizon(&self) -> Option<u128> {
        self.next.filter(|(f, _)| *f == self.fam).map(|(_, a)| a)
    }

    /// True when the family's rules are all read.
    fn fam_read(&self) -> bool {
        self.next.is_none_or(|(f, _)| f != self.fam)
    }
}

/// One fold step; `true` when every shard is folded, diffed and stored ([`Ctx::ips`] then holds
/// the outcome).
pub async fn fold_step(state: &SharedState, ctx: &mut Ctx) -> Result<bool> {
    let mut f = ctx.ip_fold.take().ok_or_else(|| anyhow!("IP fold missing"))?;
    let bundle = ctx.spec.id.clone();
    let rows_per_step = state.compiler.step_rows(FOLD_ROWS);
    let work_per_step = state.compiler.step_rows(SWEEP_WORK);
    let shards_per_step = state.compiler.step_rows(SHARDS_PER_STEP);
    // Read a page when the sweep needs one.
    if f.fam < 2 && !f.fam_read() && (f.starved || f.sweep.buffered() < rows_per_step.div_ceil(2)) {
        let (b, cursor) = (bundle.clone(), f.cursor.clone());
        let (groups, cursor, next, bad) = state
            .db
            .read(move |c| {
                let mut bad = 0u64;
                let (g, cur, next) = read_groups(c, &b, &cursor, rows_per_step, &mut bad)?;
                Ok::<_, anyhow::Error>((g, cur, next, bad))
            })
            .await?;
        ctx.bad_rows += bad;
        f.cursor = cursor;
        f.next = next;
        for rows in groups {
            for (order, rule) in super::compile::compile_ips_ordered(&ctx.wide, &rows, &mut f.counts) {
                f.out.rules += 1;
                f.sweep.push(Input { order, rule });
            }
        }
        f.starved = false;
    }
    // Sweep.
    if f.fam < 2 {
        let mut rich = ctx.rich.take().ok_or_else(|| anyhow!("rich builder missing"))?;
        let horizon = f.horizon();
        let read_all = f.fam_read();
        let mut emitted: Vec<Run> = Vec::new();
        let mut work = work_per_step;
        let drained = f
            .sweep
            .run(horizon, &mut work, &mut rich, &mut |r| emitted.push(r));
        let fam_done = drained && read_all;
        if fam_done {
            f.sweep.flush(&mut |r| emitted.push(r));
        }
        ctx.rich = Some(rich);
        let v4 = f.fam == 0;
        for r in emitted {
            split_into(&mut f.shards, v4, r);
        }
        f.starved = drained && !read_all;
        // Shards the sweep is past.
        let low = if fam_done { None } else { f.sweep.low(horizon) };
        let done: Vec<IpShardId> = f
            .shards
            .keys()
            .filter(|id| id.is_v4() == v4 && low.is_none_or(|l| id.bounds().1 < l))
            .copied()
            .collect();
        for id in done {
            if let Some(runs) = f.shards.remove(&id) {
                f.seen.insert(id);
                f.complete.push_back((id, runs));
            }
        }
        if fam_done {
            f.fam += 1;
            f.cursor = fam_start(f.fam);
            f.sweep = Sweep::new();
            f.starved = true;
        }
    }
    // Diff and store completed shards, a few per step.
    let mut batch: Vec<(IpShardId, Vec<Run>)> = Vec::new();
    while batch.len() < shards_per_step {
        match f.complete.pop_front() {
            Some(x) => batch.push(x),
            None => break,
        }
    }
    if !batch.is_empty() {
        let prev = f.prev.clone();
        let b = bundle.clone();
        let (changed, ops) = state
            .db
            .read(move |c| {
                let mut changed: Vec<(IpShardId, Vec<Run>)> = Vec::new();
                let mut ops: Vec<(IpShardId, u64)> = Vec::new();
                for (id, new) in batch {
                    let cs = super::assemble::runs_checksum(id, &new);
                    match prev.get(&id) {
                        Some(old) if *old == cs && !new.is_empty() => {}
                        None if new.is_empty() => {}
                        Some(_) if !new.is_empty() => {
                            let old_runs = super::store::ip_runs(c, &b, id)?;
                            let (dels, ups) = diff_runs(&old_runs, &new);
                            ops.push((id, (dels.len() + ups.len()) as u64));
                            changed.push((id, new));
                        }
                        _ => changed.push((id, new)),
                    }
                }
                Ok::<_, anyhow::Error>((changed, ops))
            })
            .await?;
        for (id, n) in ops {
            f.out.ops.insert(id, n);
        }
        for (id, runs) in &changed {
            f.out.changed.insert(*id, runs.len() as u64);
        }
        if !changed.is_empty() {
            let b = bundle.clone();
            state
                .db
                .write(move |c| {
                    let tx = c.transaction()?;
                    {
                        let mut st = tx.prepare_cached(
                            "INSERT OR REPLACE INTO bundle_build_ip_runs(bundle_id, ip_shard, \"first\", \"last\", value)
                             VALUES (?1, ?2, ?3, ?4, ?5)",
                        )?;
                        for (id, runs) in &changed {
                            let sid = id.to_string();
                            for r in runs {
                                st.execute(params![
                                    b,
                                    sid,
                                    &r.first.to_be_bytes()[..],
                                    &r.last.to_be_bytes()[..],
                                    r.value.0.cast_signed()
                                ])?;
                            }
                        }
                    }
                    tx.commit()?;
                    Ok::<_, anyhow::Error>(())
                })
                .await?;
        }
    }
    if f.fam >= 2 && f.complete.is_empty() && f.shards.is_empty() {
        // Shards of the previous head that hold no run any more go.
        for id in f.prev.keys() {
            if !f.seen.contains(id) {
                f.out.changed.insert(*id, 0);
            }
        }
        ctx.counts.badfiltered += f.counts.badfiltered;
        ctx.counts.entity_refused += f.counts.entity_refused;
        ctx.ips = Some(std::mem::take(&mut f.out));
        return Ok(true);
    }
    ctx.ip_fold = Some(f);
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_bundle::runs::fold_runs;
    use picket_rules::ip::IpRange;

    fn rng(seed: u64) -> impl FnMut() -> u64 {
        let mut x = seed | 1;
        move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        }
    }

    fn order(i: usize) -> OrderKey {
        OrderKey {
            position: 0,
            line_no: i as i64,
            rule_type: "ip",
            kind: "ip_range",
            key: String::new(),
            flags: 0,
            value_json: String::new(),
        }
    }

    /// The sweep, fed in pages with small work budgets, gives fold_runs' runs and rich sets.
    #[test]
    fn the_sweep_equals_fold_runs() {
        for seed in 1..40u64 {
            let mut next = rng(seed);
            let n = (next() % 400) as usize + 1;
            let mut rules: Vec<IpRuleInput> = Vec::new();
            for i in 0..n {
                let v4 = !next().is_multiple_of(4);
                let span: u128 = if v4 { 1 << 32 } else { u128::MAX };
                let base = if next().is_multiple_of(3) {
                    (next() as u128) % span
                } else {
                    ((next() % 4) as u128) << 24
                };
                let len = match next() % 5 {
                    0 => 0,
                    1 => (next() % 300) as u128,
                    2 => (1u128 << 24) + (next() % 1000) as u128,
                    3 => (next() as u128) % (1u128 << 30),
                    _ => (next() % 20) as u128,
                };
                let first = base.min(span - 1);
                let last = first.saturating_add(len).min(span - 1);
                let flags =
                    [Flags::B_EXACT, Flags::A_EXACT, Flags::IMP_B_EXACT, Flags::NONE][(next() % 4) as usize];
                let rich = next().is_multiple_of(6).then(|| picket_rules::rule::RichRule {
                    flags: Flags::B_EXACT,
                    hosts_ip: Some(std::net::IpAddr::from([10, 0, 0, (i % 3) as u8])),
                    ..Default::default()
                });
                rules.push(IpRuleInput {
                    range: IpRange { v4, first, last },
                    flags,
                    rich,
                });
            }
            let mut want_rich = RichBuilder::new();
            let want = fold_runs(&rules, &mut want_rich);
            // The sweep: each family sorted by first (stable: input order among equals).
            let mut got_rich = RichBuilder::new();
            let mut got: BTreeMap<IpShardId, Vec<Run>> = BTreeMap::new();
            for v4 in [true, false] {
                let mut fam: Vec<(usize, &IpRuleInput)> = rules
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| r.range.v4 == v4)
                    .collect();
                fam.sort_by_key(|(_, r)| r.range.first);
                let mut s = Sweep::new();
                let page = (next() % 37) as usize + 1;
                let mut i = 0;
                loop {
                    let end = (i + page).min(fam.len());
                    // Whole groups of equal first addresses.
                    let mut end = end;
                    while end < fam.len() && end > 0 && fam[end].1.range.first == fam[end - 1].1.range.first {
                        end += 1;
                    }
                    for (k, r) in &fam[i..end] {
                        s.push(Input {
                            order: order(*k),
                            rule: (*r).clone(),
                        });
                    }
                    i = end;
                    let horizon = fam.get(i).map(|(_, r)| r.range.first);
                    loop {
                        let mut work = (next() % 50) as usize + 1;
                        let mut out = Vec::new();
                        let drained = s.run(horizon, &mut work, &mut got_rich, &mut |r| out.push(r));
                        for r in out {
                            split_into(&mut got, v4, r);
                        }
                        if drained {
                            break;
                        }
                    }
                    if horizon.is_none() {
                        let mut out = Vec::new();
                        s.flush(&mut |r| out.push(r));
                        for r in out {
                            split_into(&mut got, v4, r);
                        }
                        break;
                    }
                }
            }
            assert_eq!(got, want, "seed {seed}");
            assert_eq!(
                got_rich.to_bytes().unwrap(),
                want_rich.to_bytes().unwrap(),
                "seed {seed}: the same rich sets in the same order"
            );
        }
    }
}
