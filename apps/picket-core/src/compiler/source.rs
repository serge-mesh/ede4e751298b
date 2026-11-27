//! Reading a bundle's rules from `feed_entries` at a build's snapshot (bundles.md §2; storage.md
//! §3), for the parts a build reads: one key's rules (the key pass), every pattern, every IP rule,
//! the `$dnsrewrite` and `$denyallow` entity rules, the exceptions and `$badfilter` rules, the
//! changed entries, every key, and the whole bundle in bundle order (urlfilter's rewrite order).
//!
//! Rows are rebuilt with [`Rule::from_stored`] (no re-parsing); a row that doesn't make a rule is
//! skipped and counted. Every query filters by the replay predicate at the member feed's snapshot
//! run (`first_run ≤ r < removed_run`) and by the rule types the bundle takes from that feed.
//! **Bundle order** is (feed position, line number, then the entry's identity), the same in every
//! build, so outputs are deterministic (bundles.md §2 "Determinism").

use std::collections::HashMap;

use picket_rules::name::reverse_dotted;
use picket_rules::{Kind, Rule, RuleType};
use rusqlite::{Connection, params};

use super::spec::{Runs, Spec};

/// A rule's place in bundle order.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OrderKey {
    pub position: u32,
    pub line_no: i64,
    pub rule_type: &'static str,
    pub kind: &'static str,
    pub key: String,
    pub flags: u16,
    pub value_json: String,
}

/// Where a paged read in bundle order stands within one feed ([`View::order_page`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderCursor {
    pub line_no: i64,
    pub rule_type: String,
    pub kind: String,
    pub key: String,
    pub flags: i64,
    pub value_json: String,
    pub id: i64,
}

/// One rule of the bundle as a build reads it.
#[derive(Clone, Debug)]
pub struct Row {
    pub order: OrderKey,
    pub feed: String,
    pub rule: Rule,
    /// `feed_entries.first_seen_at` (intelligent-tiering rank).
    pub first_seen_at: String,
    /// `feed_entries.id` (to fetch `raw` for alerts).
    pub entry_id: i64,
}

/// The member feeds a build reads, with their snapshot runs and the types it takes.
pub struct View<'a> {
    pub spec: &'a Spec,
    pub runs: &'a Runs,
    members: HashMap<&'a str, (u32, Vec<RuleType>)>,
}

/// The stored kinds an IP rule (or a `$badfilter` targeting one) has, for [`View::ip_page`].
pub const IP_KINDS: [&str; 3] = ["ip_literal", "ip_range", "badfilter"];

/// Columns every rule query selects, in this order.
const COLS: &str = "id, feed_id, rule_type, kind, key, flags, value_json, coalesce(line_no, 0), first_seen_at, first_run, removed_run";
/// The replay predicate for one feed (`?2` its snapshot run).
const LIVE: &str = "first_run <= ?2 AND (removed_run IS NULL OR removed_run > ?2)";

impl<'a> View<'a> {
    pub fn new(spec: &'a Spec, runs: &'a Runs) -> View<'a> {
        let members = spec
            .members
            .iter()
            .map(|m| (m.feed.as_str(), (m.position, spec.compiled_types(m))))
            .collect();
        View { spec, runs, members }
    }

    /// A view that also takes `browser` rules (the whole bundle in bundle order, for urlfilter's
    /// order, which counts host-level browser network rules).
    pub fn with_browser(spec: &'a Spec, runs: &'a Runs) -> View<'a> {
        let members = spec
            .members
            .iter()
            .map(|m| {
                let mut t = spec.compiled_types(m);
                if m.takes(RuleType::Browser) {
                    t.push(RuleType::Browser);
                }
                (m.feed.as_str(), (m.position, t))
            })
            .collect();
        View { spec, runs, members }
    }

    /// The feeds read and their runs, in definition order.
    pub fn feeds(&self) -> impl Iterator<Item = (&'a str, i64)> + '_ {
        self.spec.members.iter().filter_map(|m| {
            let (_, t) = self.members.get(m.feed.as_str())?;
            if t.is_empty() {
                return None;
            }
            Some((m.feed.as_str(), self.runs.get(&m.feed).copied().unwrap_or(0)))
        })
    }

    fn run_of(&self, feed: &str) -> i64 {
        self.runs.get(feed).copied().unwrap_or(0)
    }

    /// Builds a row from the selected columns when its feed, type and validity pass.
    fn row(&self, r: &rusqlite::Row<'_>, bad: &mut u64) -> rusqlite::Result<Option<Row>> {
        let feed: String = r.get(1)?;
        let Some((position, types)) = self.members.get(feed.as_str()) else {
            return Ok(None);
        };
        let rule_type: String = r.get(2)?;
        let Some(rt) = RuleType::parse(&rule_type) else {
            *bad += 1;
            return Ok(None);
        };
        if !types.contains(&rt) {
            return Ok(None);
        }
        let run = self.run_of(&feed);
        let first_run: i64 = r.get(9)?;
        let removed: Option<i64> = r.get(10)?;
        if first_run > run || removed.is_some_and(|x| x <= run) {
            return Ok(None);
        }
        let kind: String = r.get(3)?;
        let key: String = r.get(4)?;
        let flags: i64 = r.get(5)?;
        let value_json: String = r.get(6)?;
        let Some((flags, rule)) = stored_rule(&rule_type, &kind, &key, flags, &value_json) else {
            *bad += 1;
            return Ok(None);
        };
        Ok(Some(Row {
            order: OrderKey {
                position: *position,
                line_no: r.get(7)?,
                rule_type: rule.rule_type.as_str(),
                kind: rule.kind.as_str(),
                key,
                flags,
                value_json,
            },
            feed,
            rule,
            first_seen_at: r.get(8)?,
            entry_id: r.get(0)?,
        }))
    }

    /// One domain key's rules (bundles.md §2 step 1): name and host-mapping rules at the key, IP
    /// literal rules whose address is the key, and the `$badfilter` rules targeting either, in
    /// bundle order.
    pub fn key_rules(&self, c: &Connection, key: &str, bad: &mut u64) -> rusqlite::Result<Vec<Row>> {
        let mut out = Vec::new();
        let alt = ip_literal_text(key);
        let mut st = c.prepare_cached(&format!("SELECT {COLS} FROM feed_entries WHERE key = ?1"))?;
        for k in std::iter::once(key).chain(alt.as_deref()) {
            let mut rows = st.query([k])?;
            while let Some(r) = rows.next()? {
                if let Some(row) = self.row(r, bad)?
                    && domain_key(&row.rule).as_deref() == Some(key)
                {
                    out.push(row);
                }
            }
        }
        out.sort_by(|a, b| a.order.cmp(&b.order));
        Ok(out)
    }

    /// Runs `sql` (which must select [`COLS`] with `?1` the feed and `?2` its run) per feed and
    /// keeps the rows `keep` accepts, in bundle order.
    fn per_feed(
        &self,
        c: &Connection,
        sql: &str,
        cap: usize,
        bad: &mut u64,
        keep: impl Fn(&Rule) -> bool,
    ) -> rusqlite::Result<Result<Vec<Row>, usize>> {
        let mut out = Vec::new();
        let mut st = c.prepare_cached(sql)?;
        for (feed, run) in self.feeds() {
            let mut rows = st.query(params![feed, run])?;
            while let Some(r) = rows.next()? {
                if let Some(row) = self.row(r, bad)?
                    && keep(&row.rule)
                {
                    if out.len() >= cap {
                        return Ok(Err(cap));
                    }
                    out.push(row);
                }
            }
        }
        out.sort_by(|a, b| a.order.cmp(&b.order));
        Ok(Ok(out))
    }

    /// Every pattern and regex rule, and the `$badfilter` rules targeting one (bundles.md §4
    /// `patterns.bin`). `Err(cap)` when there are more than `cap`.
    pub fn patterns(
        &self,
        c: &Connection,
        cap: usize,
        bad: &mut u64,
    ) -> rusqlite::Result<Result<Vec<Row>, usize>> {
        self.per_feed(
            c,
            &format!(
                "SELECT {COLS} FROM feed_entries WHERE kind <> 'name' AND feed_id = ?1
                   AND kind IN ('pattern', 'regex', 'badfilter') AND {LIVE}"
            ),
            cap,
            bad,
            |r| matches!(r.key_kind(), Kind::Pattern | Kind::Regex),
        )
    }

    /// Every IP rule (IP literals and ranges) and the `$badfilter` rules targeting one.
    pub fn ip_rules(
        &self,
        c: &Connection,
        cap: usize,
        bad: &mut u64,
    ) -> rusqlite::Result<Result<Vec<Row>, usize>> {
        self.per_feed(
            c,
            &format!(
                "SELECT {COLS} FROM feed_entries WHERE kind <> 'name' AND feed_id = ?1
                   AND kind IN ('ip_literal', 'ip_range', 'badfilter') AND {LIVE}"
            ),
            cap,
            bad,
            |r| matches!(r.key_kind(), Kind::IpLiteral | Kind::IpRange),
        )
    }

    /// One page of feed `feed`'s IP rules of one stored kind ([`IP_KINDS`]: IP literals, ranges,
    /// or the `$badfilter` rules targeting one), after entry id `cursor`, in id order (core.md §3:
    /// a bounded step). Every row read moves the cursor; only the view's rows are returned. The
    /// next cursor is `None` at the end of that kind.
    pub fn ip_page(
        &self,
        c: &Connection,
        feed: &str,
        kind: &str,
        cursor: i64,
        limit: usize,
        bad: &mut u64,
    ) -> rusqlite::Result<(Vec<Row>, Option<i64>)> {
        let run = self.run_of(feed);
        let mut st = c.prepare_cached(&format!(
            "SELECT {COLS} FROM feed_entries WHERE kind <> 'name' AND feed_id = ?1 AND kind = ?3 AND id > ?4
               AND {LIVE} ORDER BY id LIMIT ?5"
        ))?;
        let mut rows = st.query(params![feed, run, kind, cursor, limit])?;
        let mut out = Vec::new();
        let (mut n, mut last) = (0usize, cursor);
        while let Some(r) = rows.next()? {
            n += 1;
            last = r.get(0)?;
            if let Some(row) = self.row(r, bad)?
                && matches!(row.rule.key_kind(), Kind::IpLiteral | Kind::IpRange)
            {
                out.push(row);
            }
        }
        Ok((out, (n >= limit).then_some(last)))
    }

    /// Every `$dnsrewrite` rule (rewrites, `@@…$dnsrewrite` and `$badfilter` rules carrying one).
    pub fn rewrites(
        &self,
        c: &Connection,
        cap: usize,
        bad: &mut u64,
    ) -> rusqlite::Result<Result<Vec<Row>, usize>> {
        self.per_feed(
            c,
            &format!(
                "SELECT {COLS} FROM feed_entries WHERE instr(value_json, '\"dnsrewrite\"') > 0
                   AND feed_id = ?1 AND {LIVE}"
            ),
            cap,
            bad,
            Rule::is_rewrite,
        )
    }

    /// Every rule naming a `$denyallow` entity (`$badfilter` rules too, whose suppressors carry it
    /// to their targets).
    pub fn entity_rules(
        &self,
        c: &Connection,
        cap: usize,
        bad: &mut u64,
    ) -> rusqlite::Result<Result<Vec<Row>, usize>> {
        self.per_feed(
            c,
            &format!(
                "SELECT {COLS} FROM feed_entries WHERE instr(value_json, '\"denyallow_entities\"') > 0
                   AND feed_id = ?1 AND {LIVE}"
            ),
            cap,
            bad,
            |r| !r.spec.denyallow_entities.is_empty(),
        )
    }

    /// Every exception (any `@@` level) and `$badfilter` rule: the cancellers of the cross-feed
    /// guardrail (bundles.md §2).
    pub fn cancellers(
        &self,
        c: &Connection,
        cap: usize,
        bad: &mut u64,
    ) -> rusqlite::Result<Result<Vec<Row>, usize>> {
        let mut a = match self.per_feed(
            c,
            &format!("SELECT {COLS} FROM feed_entries WHERE (flags & 204) <> 0 AND feed_id = ?1 AND {LIVE}"),
            cap,
            bad,
            |r| !r.kind.is_browser(),
        )? {
            Ok(v) => v,
            Err(n) => return Ok(Err(n)),
        };
        let b = match self.per_feed(
            c,
            &format!(
                "SELECT {COLS} FROM feed_entries WHERE kind <> 'name' AND feed_id = ?1 AND kind = 'badfilter' AND {LIVE}"
            ),
            cap,
            bad,
            |r| r.is_badfilter(),
        )? {
            Ok(v) => v,
            Err(n) => return Ok(Err(n)),
        };
        a.extend(b);
        a.sort_by(|x, y| x.order.cmp(&y.order));
        a.dedup_by(|x, y| x.order == y.order);
        if a.len() > cap {
            return Ok(Err(cap));
        }
        Ok(Ok(a))
    }

    /// Keyed rules whose key starts with a digit: the ones that may match an address's text
    /// (`ip_pattern_classes`, rules.md §6).
    pub fn numeric_keys(
        &self,
        c: &Connection,
        cap: usize,
        bad: &mut u64,
    ) -> rusqlite::Result<Result<Vec<Row>, usize>> {
        self.per_feed(
            c,
            &format!(
                "SELECT {COLS} FROM feed_entries WHERE feed_id = ?1 AND rule_type = 'dns'
                   AND key >= '0' AND key < ':' AND {LIVE}"
            ),
            cap,
            bad,
            |r| matches!(r.key_kind(), Kind::Name | Kind::HostMapping),
        )
    }

    /// The rules at the keys strictly below `key` (with `limit`), for the cross-feed scan of a
    /// keyed exception with a subdomain flag.
    pub fn below(
        &self,
        c: &Connection,
        key: &str,
        limit: usize,
        bad: &mut u64,
    ) -> rusqlite::Result<Vec<Row>> {
        let lo = format!("{key}.");
        let hi = format!("{key}/");
        let mut out = Vec::new();
        let mut st = c.prepare_cached(&format!(
            "SELECT {COLS} FROM feed_entries WHERE feed_id = ?1 AND rule_type = 'dns' AND key > ?3 AND key < ?4
               AND {LIVE} LIMIT ?5"
        ))?;
        for (feed, run) in self.feeds() {
            let mut rows = st.query(params![feed, run, lo, hi, limit])?;
            while let Some(r) = rows.next()? {
                if let Some(row) = self.row(r, bad)? {
                    out.push(row);
                }
                if out.len() >= limit {
                    break;
                }
            }
        }
        out.sort_by(|a, b| a.order.cmp(&b.order));
        Ok(out)
    }

    /// One page of feed `feed`'s rules in bundle order (its line order, then identity, then row
    /// id), after `cursor` (`None`: from the start): every row read, whether the view takes it
    /// or not, moves the cursor, and only taken rows are returned. Returns the rows and the next
    /// cursor (`None` at the feed's end). [`Self::for_each_in_order`] in bounded pages: each
    /// page reads the feed's live rows again (no index orders them by line), sorting only those
    /// after the cursor (core.md §3: a heavy step is bounded).
    pub fn order_page(
        &self,
        c: &Connection,
        feed: &str,
        cursor: Option<&OrderCursor>,
        limit: usize,
        bad: &mut u64,
    ) -> rusqlite::Result<(Vec<Row>, Option<OrderCursor>)> {
        let run = self.run_of(feed);
        let sql = format!(
            "SELECT {COLS} FROM feed_entries WHERE feed_id = ?1 AND {LIVE}
               AND (coalesce(line_no, 0), rule_type, kind, key, flags, value_json, id) > (?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ORDER BY coalesce(line_no, 0), rule_type, kind, key, flags, value_json, id LIMIT ?10"
        );
        let mut st = c.prepare_cached(&sql)?;
        let start = cursor.cloned().unwrap_or(OrderCursor {
            line_no: i64::MIN,
            rule_type: String::new(),
            kind: String::new(),
            key: String::new(),
            flags: i64::MIN,
            value_json: String::new(),
            id: i64::MIN,
        });
        let mut out = Vec::new();
        let mut last: Option<OrderCursor> = None;
        let mut n = 0usize;
        let mut rows = st.query(params![
            feed,
            run,
            start.line_no,
            start.rule_type,
            start.kind,
            start.key,
            start.flags,
            start.value_json,
            start.id,
            limit
        ])?;
        while let Some(r) = rows.next()? {
            n += 1;
            last = Some(OrderCursor {
                line_no: r.get(7)?,
                rule_type: r.get(2)?,
                kind: r.get(3)?,
                key: r.get(4)?,
                flags: r.get(5)?,
                value_json: r.get(6)?,
                id: r.get(0)?,
            });
            if let Some(row) = self.row(r, bad)? {
                out.push(row);
            }
        }
        Ok((out, if n >= limit { last } else { None }))
    }

    /// Calls `f` for every rule of the bundle in bundle order (every type the bundle takes,
    /// browser rules included when the view takes them). Memory: one feed's rows are sorted by
    /// SQLite, not held here.
    pub fn for_each_in_order(
        &self,
        c: &Connection,
        bad: &mut u64,
        mut f: impl FnMut(&Row),
    ) -> rusqlite::Result<()> {
        let mut st = c.prepare(&format!(
            "SELECT {COLS} FROM feed_entries WHERE feed_id = ?1 AND {LIVE}
             ORDER BY coalesce(line_no, 0), rule_type, kind, key, flags, value_json"
        ))?;
        for (feed, run) in self.feeds() {
            let mut rows = st.query(params![feed, run])?;
            while let Some(r) = rows.next()? {
                if let Some(row) = self.row(r, bad)? {
                    f(&row);
                }
            }
        }
        Ok(())
    }
}

/// The domain key a keyed rule folds into (its reversed name; an IPv4 literal's address
/// reversed), or `None` for patterns, ranges and browser rules.
pub fn domain_key(r: &Rule) -> Option<String> {
    if r.kind.is_browser() {
        return None;
    }
    match r.key_kind() {
        Kind::Name | Kind::HostMapping => Some(r.key.clone()),
        Kind::IpLiteral => Some(reverse_dotted(&r.key)),
        _ => None,
    }
}

/// The stored key of the IPv4 literal rules whose domain key is `key` (`4.3.2.1` → `1.2.3.4`).
fn ip_literal_text(key: &str) -> Option<String> {
    let text = reverse_dotted(key);
    let ok = text.parse::<std::net::Ipv4Addr>().is_ok() && text != key;
    ok.then_some(text)
}

/// What one changed entry touches.
#[derive(Clone, Debug, Default)]
pub struct Touch {
    /// The domain key, for keyed rules.
    pub key: Option<String>,
    pub pattern: bool,
    pub ip: bool,
    pub browser: bool,
}

/// Classifies a stored entry by what it touches, without building the whole rule unless its
/// kind needs it (`$badfilter` rows name their target's kind in `value_json`).
pub fn touch(kind: &str, key: &str, rule_type: &str, flags: u16, value_json: &str) -> Touch {
    let k = match Kind::parse(kind) {
        Some(Kind::Badfilter) => match Rule::from_stored(rule_type, kind, key, flags, value_json) {
            Ok(r) => r.key_kind(),
            Err(_) => return Touch::default(),
        },
        Some(k) => k,
        None => return Touch::default(),
    };
    match k {
        Kind::Name | Kind::HostMapping => Touch {
            key: Some(key.to_string()),
            ..Touch::default()
        },
        Kind::IpLiteral => Touch {
            key: Some(reverse_dotted(key)),
            ip: true,
            ..Touch::default()
        },
        Kind::IpRange => Touch {
            ip: true,
            ..Touch::default()
        },
        Kind::Pattern | Kind::Regex => Touch {
            pattern: true,
            ..Touch::default()
        },
        k if k.is_browser() => Touch {
            browser: true,
            ..Touch::default()
        },
        _ => Touch::default(),
    }
}

/// One changed entry (bundles.md §2 "Changed entries").
#[derive(Clone, Debug)]
pub struct Changed {
    pub entry_id: i64,
    pub feed: String,
    pub rule_type: String,
    pub kind: String,
    pub key: String,
    pub flags: u16,
    pub value_json: String,
    /// Open at the snapshot (added in the range), else closed in it (removed).
    pub added: bool,
}

/// A page of changed entries and the cursor after it.
pub type ChangedPage = (Vec<Changed>, Option<(i64, i64)>);

/// A page of the entries a feed's runs in `(from, to]` added or closed: by `first_run` (`by_removed`
/// false) or `removed_run` (true), after `cursor` (run, id). Returns the page and the next
/// cursor (`None` at the end).
pub fn changed_page(
    c: &Connection,
    feed: &str,
    from: i64,
    to: i64,
    by_removed: bool,
    cursor: (i64, i64),
    limit: usize,
) -> rusqlite::Result<ChangedPage> {
    let col = if by_removed { "removed_run" } else { "first_run" };
    let extra = if by_removed {
        "removed_run IS NOT NULL AND "
    } else {
        ""
    };
    let sql = format!(
        "SELECT id, rule_type, kind, key, flags, value_json, first_run, removed_run, {col} FROM feed_entries
         WHERE {extra}{col} > ?2 AND {col} <= ?3 AND ({col}, id) > (?4, ?5) AND feed_id = ?1
         ORDER BY {col}, id LIMIT ?6"
    );
    let mut st = c.prepare_cached(&sql)?;
    let mut out = Vec::new();
    let mut last = None;
    let mut rows = st.query(params![feed, from, to, cursor.0, cursor.1, limit])?;
    while let Some(r) = rows.next()? {
        let id: i64 = r.get(0)?;
        let first_run: i64 = r.get(6)?;
        let removed: Option<i64> = r.get(7)?;
        let pos: i64 = r.get(8)?;
        last = Some((pos, id));
        let open_at_to = first_run <= to && removed.is_none_or(|x| x > to);
        out.push(Changed {
            entry_id: id,
            feed: feed.to_string(),
            rule_type: r.get(1)?,
            kind: r.get(2)?,
            key: r.get(3)?,
            flags: r.get(4)?,
            value_json: r.get(5)?,
            added: open_at_to,
        });
    }
    let next = if out.len() >= limit { last } else { None };
    Ok((out, next))
}

/// A stored row read back as a rule, with its flags; `None` when it doesn't parse (flags out of
/// range included: they were written from a u16).
pub(crate) fn stored_rule(
    rule_type: &str,
    kind: &str,
    key: &str,
    flags: i64,
    value_json: &str,
) -> Option<(u16, Rule)> {
    let flags = u16::try_from(flags).ok()?;
    Rule::from_stored(rule_type, kind, key, flags, value_json)
        .ok()
        .map(|r| (flags, r))
}

/// Where a [`keys_page`] walk resumes: after this (stored key, entry id).
pub type KeyCursor = (String, i64);

/// The start of a [`keys_page`] walk: before every row, the empty key of a restricted pattern
/// with no text (`$dnstype=A`) included.
pub const KEYS_START: KeyCursor = (String::new(), i64::MIN);

/// A page of every entry a feed holds at `run` in the given types, after `cursor` in (key, id)
/// order: the entries of a full recompute, each one once (rows sharing a key never straddle a
/// page unread). Returns `(stored key, kind, flags, value_json)` rows and the next cursor.
#[expect(
    clippy::type_complexity,
    reason = "the row tuple is described above; a named type would be used once"
)]
pub fn keys_page(
    c: &Connection,
    feed: &str,
    run: i64,
    rule_type: &str,
    cursor: &KeyCursor,
    limit: usize,
) -> rusqlite::Result<(Vec<(String, String, u16, String)>, Option<KeyCursor>)> {
    let mut st = c.prepare_cached(&format!(
        "SELECT key, kind, flags, value_json, id FROM feed_entries
         WHERE feed_id = ?1 AND rule_type = ?3 AND (key, id) > (?4, ?5) AND {LIVE}
         ORDER BY key, id LIMIT ?6"
    ))?;
    let mut out: Vec<(String, String, u16, String)> = Vec::new();
    let mut last_id = 0i64;
    let mut rows = st.query(params![feed, run, rule_type, cursor.0, cursor.1, limit])?;
    while let Some(r) = rows.next()? {
        out.push((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?));
        last_id = r.get(4)?;
    }
    let next = if out.len() >= limit {
        out.last().map(|r| (r.0.clone(), last_id))
    } else {
        None
    };
    Ok((out, next))
}

/// The keys strictly below `key` that some member feed lists at the snapshot (bundles.md §2
/// "listed descendants": a prefix scan on the reversed name), at most `limit` after `cursor`.
pub fn descendants_page(
    c: &Connection,
    view: &View<'_>,
    key: &str,
    cursor: &str,
    limit: usize,
) -> rusqlite::Result<(Vec<String>, Option<String>)> {
    let lo = format!("{key}.");
    let hi = format!("{key}/");
    let start = if cursor.is_empty() || cursor < lo.as_str() {
        lo.clone()
    } else {
        cursor.to_string()
    };
    let mut st = c.prepare_cached(&format!(
        "SELECT DISTINCT key FROM feed_entries WHERE feed_id = ?1 AND rule_type = 'dns'
           AND key > ?3 AND key < ?4 AND {LIVE} ORDER BY key LIMIT ?5"
    ))?;
    let mut all: Vec<String> = Vec::new();
    for (feed, run) in view.feeds() {
        let mut rows = st.query(params![feed, run, start, hi, limit])?;
        while let Some(r) = rows.next()? {
            all.push(r.get(0)?);
        }
    }
    all.sort();
    all.dedup();
    all.truncate(limit);
    let next = if all.len() >= limit {
        all.last().cloned()
    } else {
        None
    };
    Ok((all, next))
}

/// `raw` and `line_no` of an entry (alert details).
pub fn raw_of(c: &Connection, entry_id: i64) -> rusqlite::Result<(String, Option<i64>)> {
    c.query_row(
        "SELECT raw, line_no FROM feed_entries WHERE id = ?1",
        [entry_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn touches() {
        let t = touch("name", "org.example", "dns", 3, "{}");
        assert_eq!(t.key.as_deref(), Some("org.example"));
        let t = touch("ip_literal", "1.2.3.4", "ip", 1, "{}");
        assert_eq!(t.key.as_deref(), Some("4.3.2.1"));
        assert!(t.ip);
        assert!(touch("pattern", "ads*", "dns", 1, "{}").pattern);
        assert!(touch("cosmetic", "##.ad", "browser", 0, "{}").browser);
        assert_eq!(ip_literal_text("4.3.2.1").as_deref(), Some("1.2.3.4"));
        assert_eq!(ip_literal_text("org.example"), None);
    }
}
