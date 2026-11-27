//! The per-bundle lookup on the edge (bundles.md §6), deciding exactly as
//! [`picket_rules::matcher::BundleMatcher`] does (rules.md §3–§6).
//!
//! **Names are wire labels.** The labels are reversed once into a stack buffer
//! (`org.example.www.ads`). For each label boundary, most specific first, skipping suffixes that
//! include a label holding a `.` byte (rules.md §3): hash → shard → overlay → filter → FST. At the
//! query name only `_EXACT` flags apply; at a parent only `_SUBS` flags. Then the key's rich rules
//! (`HAS_RICH`), then the patterns on the name's AdGuard text form whose shortcut occurs, plus those
//! without one.
//!
//! **Decision** (rules.md §4): the `$dnsrewrite` rules left after `@@…$dnsrewrite` cancellations
//! answer first, ordered by urlfilter's matched-rule order; otherwise the top flag level among the
//! other matches (`IMP_A` 1, `IMP_B` 2, `A` 3, `B` 4) decides (BLOCK, or an exception: no result);
//! a host-IP mapping answers only if nothing but rewrites matched. An allow bundle allows on any
//! match; a scope bundle's match puts the name in scope.
//!
//! **Cold stage** (block bundles with a cold part): only when the hot part found no rewrite, block
//! or exception. A cold match then blocks, even over a host-IP mapping. Page reads go through the
//! edge's [`PageReader`] in a blocking thread ([`Bundle::lookup_cold`]); a failed read, or a cold
//! part that isn't loaded, fails open and marks the lookup unchecked.
//!
//! **Addresses** (rules.md §6): an IPv4-mapped IPv6 address takes the IPv4 lookup. IPv4: first
//! octet → IP shard → overlay → /16 container → side table. A set hit blocks at once unless the
//! `ip_pattern_classes` of a head whose hot shards or patterns are active (or of the current head)
//! hold a class that can defeat it; otherwise the address's IP value, the keys and patterns that
//! match its Go text form decide together, as for a name.
//!
//! **Activation steps** (edge.md §13): [`Bundle::with_head`] moves the head id; parts keep deciding
//! until each is swapped. A head without a cold part keeps the previous one until the hot swaps are
//! done ([`Bundle::drop_previous_cold`]), so a key moving cold → hot is never in neither part.
//!
//! The hot path allocates nothing for keys, plain patterns and set hits: names, reversed forms and
//! text forms live in stack buffers, candidate lists in inline vectors. Rich rules with conditions,
//! rewrites and host mappings build their answers on the heap.

use std::net::IpAddr;
use std::sync::Arc;

use picket_api::logs::{BundleParts, BundleVersion, ColdShardVersion, MatchKind};
use picket_rules::Flags;
use picket_rules::flags::Level;
use picket_rules::matcher::{BundleAction, Outcome};
use picket_rules::modifiers::{NameSemantics, QueryCtx};
use picket_rules::order::{MatchOrder, sequence};
use picket_rules::rewrite::{RewriteAnswer, RewriteCandidate, apply_rewrite_exceptions_by, merge_rewrites};
use picket_rules::rule::RichRule;
use picket_wire::QName;
use smallvec::SmallVec;

use crate::hash::KeyHash;
use crate::head::{Head, PATTERNS, RICH};
use crate::ips::IpShardId;
use crate::page::PageReader;
use crate::reader::{ColdProbe, ColdShard, HotShard, IpShard, LoadError, PatternsPart};
use crate::rich::RichSegment;
use crate::shard_dir::{ShardDir, ShardEntry};
use crate::value::Value;

/// Most labels in a name (127 one-byte labels fill 255 wire bytes).
const MAX_LABELS: usize = 127;
/// The reversed form's buffer.
const REV_CAP: usize = 256;
/// `http://` + the longest text form (every byte escaped as `\DDD`).
const URL_CAP: usize = 7 + 4 * 255 + 128;
const URL_PREFIX: &[u8] = b"http://";

/// Which part a match came from (api.md §5 `versions` keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PartId {
    Shard(u32),
    ColdShard(u32),
    IpShard(IpShardId),
    Patterns,
}

impl PartId {
    /// The part as `activated` events and `versions` name it (`shards/1`, `cold_shards/1`,
    /// `ip_shards/v4/45`, `segments/patterns.bin`).
    pub fn key(&self) -> String {
        match self {
            PartId::Shard(n) => format!("shards/{n}"),
            PartId::ColdShard(n) => format!("cold_shards/{n}"),
            PartId::IpShard(id) => format!("ip_shards/{id}"),
            PartId::Patterns => format!("segments/{PATTERNS}"),
        }
    }
}

/// What a match was on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReasonKey {
    /// A key: the suffix of the name with this many labels.
    Suffix { labels: u8 },
    /// Pattern `index` of the patterns segment.
    Pattern { index: u32 },
    /// The address itself (an IP rule).
    Address,
}

/// What decided (api.md §5 `reason`): the deciding key, its kind, whether it came from the cold
/// part, and the part and head it came from. With the bundle id these are the block id's inputs
/// (edge.md §4, §12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason {
    pub kind: MatchKind,
    pub key: ReasonKey,
    pub cold: bool,
    pub part: PartId,
    /// The head the part came from (full id).
    pub head: Arc<str>,
    /// The deciding level (network-rule decisions).
    pub level: Option<Level>,
}

impl Reason {
    /// The deciding key as logged (`reason.key`): the matched suffix in log text, the pattern's
    /// source, or the address text. `labels` are the name's labels (most specific first), as
    /// matched.
    pub fn key_text(&self, bundle: &Bundle, labels: &[&[u8]]) -> String {
        match self.key {
            ReasonKey::Suffix { labels: n } => {
                let n = usize::from(n).min(labels.len());
                let start = labels.len().saturating_sub(n);
                picket_api::names::encode_labels(labels.get(start..).unwrap_or(&[]).iter().copied())
            }
            ReasonKey::Pattern { index } => bundle
                .patterns
                .patterns
                .get(index)
                .map(|p| p.source().to_string())
                .unwrap_or_default(),
            ReasonKey::Address => picket_api::names::encode_labels(labels.iter().copied()),
        }
    }
}

/// The cold stage's state for one lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ColdCheck {
    /// No cold stage: no cold part, not a block bundle, or the hot part decided.
    NotApplicable,
    /// The edge must run [`Bundle::lookup_cold`] (in a blocking thread) and
    /// [`Decision::with_cold`].
    Needed,
    /// A cold key blocked.
    Matched,
    /// The cold part has no match.
    Clear,
    /// The cold check couldn't be made (a page failed to read, or the cold part isn't loaded):
    /// it failed open; log the bundle in `cold_unchecked`. `refetch` lists page files that
    /// failed their checksum (delete, fetch again, log `page_file_refetched`).
    Unchecked { refetch: Vec<String> },
}

/// One bundle's result for a name or an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub outcome: Outcome,
    pub reason: Option<Reason>,
    pub cold: ColdCheck,
}

impl Decision {
    fn none() -> Decision {
        Decision {
            outcome: Outcome::None,
            reason: None,
            cold: ColdCheck::NotApplicable,
        }
    }

    /// Combines the hot decision with the cold stage's result.
    pub fn with_cold(mut self, cold: ColdResult) -> Decision {
        if self.cold != ColdCheck::Needed {
            return self;
        }
        match cold.matched {
            Some(r) => {
                self.outcome = Outcome::Block;
                self.reason = Some(r);
                self.cold = ColdCheck::Matched;
            }
            None if cold.failed => {
                self.cold = ColdCheck::Unchecked {
                    refetch: cold.refetch,
                };
            }
            None => self.cold = ColdCheck::Clear,
        }
        self
    }
}

/// What the cold stage found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ColdResult {
    pub matched: Option<Reason>,
    /// A page read failed (and nothing matched elsewhere).
    pub failed: bool,
    /// Page files that failed their checksum.
    pub refetch: Vec<String>,
}

/// A bundle's cold part on the edge.
#[derive(Clone, Debug)]
pub enum Cold {
    /// The head has no cold part.
    None,
    /// The head has one but it isn't loaded (no usable SSD, the memory-only window after start):
    /// every query reaching the cold stage is unchecked.
    NotLoaded,
    Loaded(Arc<ColdPart>),
}

/// The loaded cold shards. While a head moves keys (a new cold base, or a split or merge), the
/// previous part stays as `previous` and a lookup checks both (the union, the new value winning).
#[derive(Clone, Debug)]
pub struct ColdPart {
    dir: ShardDir,
    shards: Vec<Arc<ColdShard>>,
    previous: Option<Arc<ColdPart>>,
}

impl ColdPart {
    /// Assembles cold shards under their directory.
    pub fn new(
        dir_entries: &[ShardEntry],
        shards: Vec<Arc<ColdShard>>,
        previous: Option<Arc<ColdPart>>,
    ) -> Result<ColdPart, LoadError> {
        let dir = ShardDir::new(dir_entries.to_vec()).map_err(|e| LoadError::Mismatch(e.to_string()))?;
        let shards = align(&dir, shards, |s| s.number)?;
        Ok(ColdPart {
            dir,
            shards,
            previous,
        })
    }

    /// The shards, in directory order.
    pub fn shards(&self) -> &[Arc<ColdShard>] {
        &self.shards
    }

    pub fn dir(&self) -> &ShardDir {
        &self.dir
    }

    /// The previous part kept during a move.
    pub fn previous(&self) -> Option<&Arc<ColdPart>> {
        self.previous.as_ref()
    }

    /// The part without its previous half (the move is complete).
    pub fn settled(&self) -> ColdPart {
        ColdPart {
            dir: self.dir.clone(),
            shards: self.shards.clone(),
            previous: None,
        }
    }

    fn shard_for(&self, h: KeyHash) -> Option<&Arc<ColdShard>> {
        self.shards.get(self.dir.position_for_index(h.dir_index()))
    }

    fn probe(
        &self,
        h: KeyHash,
        reader: &dyn PageReader,
        failed: &mut bool,
        refetch: &mut Vec<String>,
    ) -> Option<(Value, &Arc<ColdShard>)> {
        if let Some(s) = self.shard_for(h) {
            match s.probe(h, reader) {
                ColdProbe::Hit(v) => return Some((v, s)),
                ColdProbe::Miss => {}
                ColdProbe::Failed(e) => {
                    *failed = true;
                    if e.needs_refetch() && !refetch.iter().any(|f| f == s.pages_file()) {
                        refetch.push(s.pages_file().to_string());
                    }
                }
            }
        }
        self.previous.as_ref()?.probe(h, reader, failed, refetch)
    }

    /// Bytes in RAM (cold filters and overlays, the previous half included).
    pub fn memory_usage(&self) -> usize {
        let own: usize = self.shards.iter().map(|s| s.memory_usage()).sum();
        own.saturating_add(self.previous.as_ref().map_or(0, |p| p.memory_usage()))
    }
}

fn align<T>(
    dir: &ShardDir,
    mut parts: Vec<Arc<T>>,
    num: impl Fn(&T) -> u32,
) -> Result<Vec<Arc<T>>, LoadError> {
    let mut out = Vec::with_capacity(dir.entries().len());
    for e in dir.entries() {
        let i = parts
            .iter()
            .position(|p| num(p) == e.shard)
            .ok_or_else(|| LoadError::Mismatch(format!("no shard {}", e.shard)))?;
        out.push(parts.swap_remove(i));
    }
    if !parts.is_empty() {
        return Err(LoadError::Mismatch("shards outside the directory".into()));
    }
    Ok(out)
}

/// Everything a bundle head needs, loaded ([`Bundle::assemble`]).
pub struct LoadedParts {
    pub hot: Vec<Arc<HotShard>>,
    pub cold: Cold,
    pub ip: Vec<Arc<IpShard>>,
    pub patterns: PatternsPart,
}

/// One bundle as the edge matches it: immutable; swaps build a new one sharing every unchanged
/// part.
#[derive(Clone, Debug)]
pub struct Bundle {
    name: Arc<str>,
    action: BundleAction,
    hash_seed: u64,
    head: Arc<str>,
    /// The head's own layout, for `versions` (a plain id when every part is this head's).
    head_layout: Arc<Layout>,
    /// The IPv4 fast path for the parts active now ([`Bundle::refresh_fast_path`]).
    ip_fast_path: bool,
    /// Each head whose parts may be active, and whether its `ip_pattern_classes` allow the fast
    /// path.
    head_fast_paths: Arc<[(Arc<str>, bool)]>,
    hot_dir: ShardDir,
    hot: Vec<Arc<HotShard>>,
    cold: Cold,
    v4: Arc<[Option<Arc<IpShard>>; 256]>,
    v6: Option<Arc<IpShard>>,
    patterns: PatternsPart,
}

#[derive(Debug, PartialEq, Eq)]
struct Layout {
    shards: Vec<u32>,
    cold_shards: Vec<u32>,
    ip_shards: Vec<IpShardId>,
}

impl Layout {
    fn of(head: &Head) -> Layout {
        let mut shards: Vec<u32> = head.shards.iter().map(|s| s.shard).collect();
        shards.sort_unstable();
        let mut cold_shards: Vec<u32> = head.cold_shards.iter().map(|s| s.shard).collect();
        cold_shards.sort_unstable();
        let mut ip_shards: Vec<IpShardId> = head.ip_shards.iter().map(|s| s.ip_shard).collect();
        ip_shards.sort_unstable();
        Layout {
            shards,
            cold_shards,
            ip_shards,
        }
    }
}

/// A name as labels, its reversed form and its suffix boundaries, in stack buffers.
struct NameView<'a> {
    labels: [&'a [u8]; MAX_LABELS],
    n: usize,
    rev: [u8; REV_CAP],
    /// `ends[k - 1]`: the reversed form's length for the last `k` labels.
    ends: [u16; MAX_LABELS],
    /// Labels from the right before the first holding a `.` byte.
    clean: usize,
}

impl<'a> NameView<'a> {
    fn new(src: impl DoubleEndedIterator<Item = &'a [u8]> + ExactSizeIterator) -> Option<NameView<'a>> {
        let n = src.len();
        if n == 0 || n > MAX_LABELS {
            return None;
        }
        let mut v = NameView {
            labels: [&[]; MAX_LABELS],
            n,
            rev: [0; REV_CAP],
            ends: [0; MAX_LABELS],
            clean: 0,
        };
        for (i, l) in src.enumerate() {
            *v.labels.get_mut(i)? = l;
        }
        let mut at = 0usize;
        let mut dirty = false;
        for k in 0..n {
            let l = *v.labels.get(n.checked_sub(k)?.checked_sub(1)?)?;
            if k > 0 {
                *v.rev.get_mut(at)? = b'.';
                at = at.checked_add(1)?;
            }
            let end = at.checked_add(l.len())?;
            for (d, s) in v.rev.get_mut(at..end)?.iter_mut().zip(l) {
                *d = s.to_ascii_lowercase();
            }
            at = end;
            *v.ends.get_mut(k)? = u16::try_from(at).ok()?;
            if l.contains(&b'.') {
                dirty = true;
            }
            if !dirty {
                v.clean = k.checked_add(1)?;
            }
        }
        Some(v)
    }

    fn labels(&self) -> &[&'a [u8]] {
        self.labels.get(..self.n).unwrap_or(&[])
    }

    /// The key of the suffix made of the last `k` labels.
    fn suffix(&self, k: usize) -> Option<&[u8]> {
        if k == 0 || k > self.clean {
            return None;
        }
        let end = usize::from(*self.ends.get(k.checked_sub(1)?)?);
        self.rev.get(..end)
    }
}

/// `http://` + AdGuard's text form of a name, in a stack buffer (rules.md §3,
/// [`picket_api::names::push_adguard_text`]).
struct TextBuf {
    buf: [u8; URL_CAP],
    len: usize,
}

impl TextBuf {
    fn new(labels: &[&[u8]]) -> Option<TextBuf> {
        let mut t = TextBuf {
            buf: [0; URL_CAP],
            len: 0,
        };
        t.push(URL_PREFIX)?;
        for (i, l) in labels.iter().enumerate() {
            if i > 0 {
                t.push(b".")?;
            }
            for &b in *l {
                let b = b.to_ascii_lowercase();
                match b {
                    b'.' | b' ' | b'\'' | b'@' | b';' | b'(' | b')' | b'"' | b'\\' => t.push(&[b'\\', b])?,
                    0x20..=0x7e => t.push(&[b])?,
                    _ => t.push(&[
                        b'\\',
                        b'0'.wrapping_add(b / 100),
                        b'0'.wrapping_add((b / 10) % 10),
                        b'0'.wrapping_add(b % 10),
                    ])?,
                }
            }
        }
        Some(t)
    }

    fn from_text(text: &[u8]) -> Option<TextBuf> {
        let mut t = TextBuf {
            buf: [0; URL_CAP],
            len: 0,
        };
        t.push(URL_PREFIX)?;
        t.push(text)?;
        Some(t)
    }

    fn push(&mut self, b: &[u8]) -> Option<()> {
        let end = self.len.checked_add(b.len())?;
        self.buf.get_mut(self.len..end)?.copy_from_slice(b);
        self.len = end;
        Some(())
    }

    fn url(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    fn text(&self) -> &[u8] {
        self.buf.get(URL_PREFIX.len()..self.len).unwrap_or(&[])
    }
}

/// Where a candidate came from.
#[derive(Clone, Copy)]
struct Source<'a> {
    kind: MatchKind,
    key: ReasonKey,
    part: PartId,
    head: &'a Arc<str>,
    cold: bool,
}

impl Source<'_> {
    fn reason(&self, level: Option<Level>) -> Reason {
        Reason {
            kind: self.kind,
            key: self.key,
            cold: self.cold,
            part: self.part,
            head: self.head.clone(),
            level,
        }
    }
}

#[derive(Clone, Copy)]
struct RichCand<'a> {
    rule: &'a RichRule,
    applying: Flags,
    src: Source<'a>,
    rank: u32,
}

/// Candidates gathered for one name or address.
struct Gather<'a> {
    /// Best plain candidate per level (index = level number − 1): (rank, source).
    best: [Option<(u32, Source<'a>)>; 4],
    any: bool,
    rich: SmallVec<[RichCand<'a>; 4]>,
}

impl<'a> Gather<'a> {
    fn new() -> Self {
        Gather {
            best: [None; 4],
            any: false,
            rich: SmallVec::new(),
        }
    }

    /// Adds a plain match's applying flags at every level they hold.
    fn plain(&mut self, applying: Flags, rank: u32, src: Source<'a>) {
        if applying.is_empty() {
            return;
        }
        self.any = true;
        for (i, lvl) in [
            Level::ImportantAllow,
            Level::ImportantBlock,
            Level::Allow,
            Level::Block,
        ]
        .into_iter()
        .enumerate()
        {
            let bits = lvl.exact_flag().union(lvl.exact_flag().exact_as_subs());
            if applying.intersects(bits)
                && let Some(slot) = self.best.get_mut(i)
                && slot.is_none_or(|(r, _)| rank > r)
            {
                *slot = Some((rank, src));
            }
        }
    }

    fn top_plain(&self) -> Option<(Level, u32, Source<'a>)> {
        let levels = [
            Level::ImportantAllow,
            Level::ImportantBlock,
            Level::Allow,
            Level::Block,
        ];
        self.best
            .iter()
            .zip(levels)
            .find_map(|(b, l)| b.map(|(r, s)| (l, r, s)))
    }
}

fn important(f: Flags) -> bool {
    f.intersects(Flags(
        Flags::IMP_B_EXACT.0 | Flags::IMP_B_SUBS.0 | Flags::IMP_A_EXACT.0 | Flags::IMP_A_SUBS.0,
    ))
}

/// urlfilter's specifier count for a rich rule (attribution rank only, rules.md §4).
fn specifiers(r: &RichRule) -> u32 {
    let n = [
        important(r.flags),
        r.dnstype.is_some(),
        r.ctag.is_some(),
        r.client.is_some(),
        !r.denyallow.is_empty() || !r.denyallow_entities.is_empty(),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    u32::try_from(n).unwrap_or(0)
}

fn rank(spec: u32, depth: usize) -> u32 {
    spec.saturating_mul(1000)
        .saturating_add(u32::try_from(depth).unwrap_or(u32::MAX))
}

/// The address an IP lookup found, as a candidate.
struct IpHit<'a> {
    value: Value,
    shard: &'a IpShard,
}

impl Bundle {
    /// Assembles a bundle from a head and its loaded parts. Every part named by the head must be
    /// present (hot shards matching the directory; one IP shard per listed id).
    pub fn assemble(head: &Head, head_id: Arc<str>, parts: LoadedParts) -> Result<Bundle, LoadError> {
        let hot_dir = head.dir()?;
        let hot = align(&hot_dir, parts.hot, |s| s.number)?;
        let mut v4: [Option<Arc<IpShard>>; 256] = std::array::from_fn(|_| None);
        let mut v6 = None;
        for s in parts.ip {
            match s.id {
                IpShardId::V4(o) => {
                    if let Some(slot) = v4.get_mut(usize::from(o)) {
                        *slot = Some(s);
                    }
                }
                IpShardId::V6 => v6 = Some(s),
            }
        }
        let cold = match (&parts.cold, head.has_cold()) {
            (Cold::None, true) => Cold::NotLoaded,
            (_, false) => Cold::None,
            (c, true) => c.clone(),
        };
        let mut b = Bundle {
            name: head.bundle.as_str().into(),
            action: head.action,
            hash_seed: head.hash_seed,
            head_fast_paths: Arc::new([(head_id.clone(), head.ip_fast_path())]),
            head: head_id,
            head_layout: Arc::new(Layout::of(head)),
            ip_fast_path: false,
            hot_dir,
            hot,
            cold,
            v4: Arc::new(v4),
            v6,
            patterns: parts.patterns,
        };
        b.refresh_fast_path();
        Ok(b)
    }

    /// Derives the IPv4 fast path from the parts active now (review round 1, B2): the IP-text
    /// patterns that can defeat a set hit (bundles.md §6, rules.md §6) live in the hot shards'
    /// keys and in the patterns segment, so the fast path holds only when the head of every hot
    /// shard, of the patterns part and the current head all allow it. A part from a head this
    /// bundle has no record of counts as defeating. Records no part names any more are dropped.
    fn refresh_fast_path(&mut self) {
        let fp = self.head_fast_paths.clone();
        let ok = |h: &str| fp.iter().any(|(id, ok)| **id == *h && *ok);
        self.ip_fast_path = ok(&self.head) && ok(&self.patterns.head) && self.hot.iter().all(|s| ok(&s.head));
        let used = |id: &str| {
            *id == *self.head || *id == *self.patterns.head || self.hot.iter().any(|s| *s.head == *id)
        };
        if fp.iter().any(|(id, _)| !used(id)) {
            self.head_fast_paths = fp.iter().filter(|(id, _)| used(id)).cloned().collect();
        }
    }

    /// The bundle id.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The head being activated (or the last one).
    pub fn head(&self) -> &str {
        &self.head
    }

    pub fn action(&self) -> BundleAction {
        self.action
    }

    pub fn hash_seed(&self) -> u64 {
        self.hash_seed
    }

    /// The hot shards, in directory order.
    pub fn hot_shards(&self) -> &[Arc<HotShard>] {
        &self.hot
    }

    pub fn hot_dir(&self) -> &ShardDir {
        &self.hot_dir
    }

    pub fn cold(&self) -> &Cold {
        &self.cold
    }

    /// The IP shards held.
    pub fn ip_shards(&self) -> impl Iterator<Item = &Arc<IpShard>> {
        self.v4.iter().flatten().chain(self.v6.iter())
    }

    pub fn patterns(&self) -> &PatternsPart {
        &self.patterns
    }

    /// A new head's first step (edge.md §13): the head id and action move to `head`; parts keep
    /// the heads they came from until swapped or moved with `in_head`, and the IPv4 fast path
    /// follows the parts active (`Bundle::refresh_fast_path`).
    ///
    /// A head without a cold part keeps the previous cold part (loaded or not) until its hot swaps
    /// are done: the edge then drops it with [`Bundle::drop_previous_cold`], the cold-delete step
    /// of the moves that empty the cold part, so a key moving cold → hot is never in neither part,
    /// however long the swaps take or if one fails (bundles.md §2 "Moves", §6 "Activation";
    /// edge.md §13 "Order"; review round 1, B1).
    pub fn with_head(&self, head: &Head, head_id: Arc<str>) -> Result<Bundle, LoadError> {
        if head.bundle != *self.name || head.hash_seed != self.hash_seed {
            return Err(LoadError::Mismatch("head is for another bundle or format".into()));
        }
        let mut b = self.clone();
        let mut fp: Vec<(Arc<str>, bool)> = self
            .head_fast_paths
            .iter()
            .filter(|(id, _)| **id != *head_id)
            .cloned()
            .collect();
        fp.push((head_id.clone(), head.ip_fast_path()));
        b.head_fast_paths = fp.into();
        b.head = head_id;
        b.head_layout = Arc::new(Layout::of(head));
        b.action = head.action;
        if head.has_cold() && matches!(b.cold, Cold::None) {
            b.cold = Cold::NotLoaded;
        }
        b.refresh_fast_path();
        Ok(b)
    }

    /// The last step of a head without a cold part, once its hot swaps are done: drops the cold
    /// part a previous head left ([`Bundle::with_head`]). A head with a cold part keeps it.
    pub fn drop_previous_cold(&self) -> Bundle {
        if !self.head_layout.cold_shards.is_empty() {
            return self.clone();
        }
        let mut b = self.clone();
        b.cold = Cold::None;
        b
    }

    /// Swaps hot shards: the directory becomes `dir` and `add` replace the shards they name (a
    /// split or merge swaps all its shards at once, bundles.md §6).
    pub fn with_hot(&self, dir: &[ShardEntry], add: Vec<Arc<HotShard>>) -> Result<Bundle, LoadError> {
        let new_dir = ShardDir::new(dir.to_vec()).map_err(|e| LoadError::Mismatch(e.to_string()))?;
        let mut pool: Vec<Arc<HotShard>> = add;
        for s in &self.hot {
            if !pool.iter().any(|p| p.number == s.number) && new_dir.entry(s.number).is_some() {
                pool.push(s.clone());
            }
        }
        let hot = align(&new_dir, pool, |s| s.number)?;
        let mut b = self.clone();
        b.hot_dir = new_dir;
        b.hot = hot;
        b.refresh_fast_path();
        Ok(b)
    }

    /// Replaces the cold part.
    pub fn with_cold(&self, cold: Cold) -> Bundle {
        let mut b = self.clone();
        b.cold = cold;
        b
    }

    /// Adds or replaces an IP shard.
    pub fn with_ip_shard(&self, s: Arc<IpShard>) -> Bundle {
        let mut b = self.clone();
        match s.id {
            IpShardId::V4(o) => {
                let mut v4: [Option<Arc<IpShard>>; 256] = (*b.v4).clone();
                if let Some(slot) = v4.get_mut(usize::from(o)) {
                    *slot = Some(s);
                }
                b.v4 = Arc::new(v4);
            }
            IpShardId::V6 => b.v6 = Some(s),
        }
        b
    }

    /// Removes an IP shard (a head without it).
    pub fn without_ip_shard(&self, id: IpShardId) -> Bundle {
        let mut b = self.clone();
        match id {
            IpShardId::V4(o) => {
                let mut v4: [Option<Arc<IpShard>>; 256] = (*b.v4).clone();
                if let Some(slot) = v4.get_mut(usize::from(o)) {
                    *slot = None;
                }
                b.v4 = Arc::new(v4);
            }
            IpShardId::V6 => b.v6 = None,
        }
        b
    }

    /// Replaces the patterns segment.
    pub fn with_patterns(&self, p: PatternsPart) -> Bundle {
        let mut b = self.clone();
        b.patterns = p;
        b.refresh_fast_path();
        b
    }

    /// True when the cold part is listed in `versions.not_loaded.cold`.
    pub fn cold_not_loaded(&self) -> bool {
        matches!(self.cold, Cold::NotLoaded)
    }

    /// The `versions` entry for this bundle (api.md §5): a plain short head id when every active
    /// part is this head's full set, otherwise each part with the head it came from (a cold shard
    /// mid-move as `[previous, new]`).
    pub fn versions(&self) -> BundleVersion {
        let short = |h: &str| picket_api::ids::short_id(h).to_string();
        let head = short(&self.head);
        let mut parts = BundleParts {
            head: head.clone(),
            ..BundleParts::default()
        };
        let mut plain = true;
        for s in &self.hot {
            plain &= *s.head == *self.head;
            parts.shards.insert(s.number.to_string(), short(&s.head));
        }
        let mut hot_nums: Vec<u32> = self.hot.iter().map(|s| s.number).collect();
        hot_nums.sort_unstable();
        plain &= hot_nums == self.head_layout.shards;
        if let Cold::Loaded(c) = &self.cold {
            plain &= c.previous.is_none();
            let prev_head = c
                .previous
                .as_ref()
                .and_then(|p| p.shards.first())
                .map(|s| s.head.clone());
            let mut nums = Vec::new();
            for s in &c.shards {
                nums.push(s.number);
                let from = s.moving_from.clone().or_else(|| prev_head.clone());
                let v = match from {
                    Some(f) => {
                        plain = false;
                        ColdShardVersion::Moving([short(&f), short(&s.head)])
                    }
                    None => {
                        plain &= *s.head == *self.head;
                        ColdShardVersion::One(short(&s.head))
                    }
                };
                parts.cold_shards.insert(s.number.to_string(), v);
            }
            nums.sort_unstable();
            plain &= nums == self.head_layout.cold_shards;
        } else if !self.head_layout.cold_shards.is_empty() || matches!(self.cold, Cold::NotLoaded) {
            // Not every part is active, or a previous head's cold part that was never loaded is
            // kept until the hot swaps: the parts are listed (without cold shards) and the edge
            // names the bundle in `not_loaded.cold` ([`Bundle::cold_not_loaded`]).
            plain = false;
        }
        let mut ips: Vec<IpShardId> = Vec::new();
        for s in self.ip_shards() {
            plain &= *s.head == *self.head;
            ips.push(s.id);
            parts.ip_shards.insert(s.id.to_string(), short(&s.head));
        }
        ips.sort_unstable();
        plain &= ips == self.head_layout.ip_shards;
        plain &= *self.patterns.head == *self.head;
        parts
            .segments
            .insert(PATTERNS.to_string(), short(&self.patterns.head));
        parts
            .segments
            .insert(RICH.to_string(), short(&self.patterns.head));
        if plain {
            BundleVersion::Plain(head)
        } else {
            BundleVersion::Parts(parts)
        }
    }

    /// Bytes held in RAM by the hot part and the cold filters, counting each `rich.json` the
    /// active parts read once: mid-activation, hot shards, IP shards and the patterns part can read
    /// different heads' segments, and each is held (review round 1, B8).
    pub fn memory_usage(&self) -> usize {
        let hot: usize = self.hot.iter().map(|s| s.memory_usage()).sum();
        let ip: usize = self.ip_shards().map(|s| s.memory_usage()).sum();
        let cold = match &self.cold {
            Cold::Loaded(c) => c.memory_usage(),
            _ => 0,
        };
        let mut rich: Vec<&Arc<RichSegment>> = Vec::new();
        for r in self
            .hot
            .iter()
            .map(|s| s.rich_arc())
            .chain(self.ip_shards().map(|s| s.rich_arc()))
            .chain(std::iter::once(&self.patterns.rich))
        {
            if !rich.iter().any(|x| Arc::ptr_eq(x, r)) {
                rich.push(r);
            }
        }
        let rich: usize = rich.iter().map(|r| r.memory_usage()).sum();
        hot.saturating_add(ip)
            .saturating_add(cold)
            .saturating_add(self.patterns.patterns.memory_usage())
            .saturating_add(rich)
    }

    /// Bytes of overlays (hot, cold and IP), counted against `overlay_budget_mib`.
    pub fn overlay_bytes(&self) -> usize {
        let hot: usize = self.hot.iter().map(|s| s.overlay_bytes()).sum();
        let ip: usize = self.ip_shards().map(|s| s.overlay_bytes()).sum();
        let cold = match &self.cold {
            Cold::Loaded(c) => c.shards.iter().map(|s| s.overlay_bytes()).sum(),
            _ => 0,
        };
        hot.saturating_add(ip).saturating_add(cold)
    }

    fn hot_shard(&self, h: KeyHash) -> Option<&Arc<HotShard>> {
        self.hot.get(self.hot_dir.position_for_index(h.dir_index()))
    }

    /// Looks up a query or response-target name (the hot part; see [`ColdCheck::Needed`]).
    pub fn lookup_name(&self, name: &QName, ctx: &QueryCtx<'_>) -> Decision {
        match NameView::new(name.labels()) {
            Some(v) => self.lookup_view(&v, ctx),
            None => Decision::none(),
        }
    }

    /// Looks up a name given as labels, most specific first.
    pub fn lookup_labels(&self, labels: &[&[u8]], ctx: &QueryCtx<'_>) -> Decision {
        match NameView::new(labels.iter().copied()) {
            Some(v) => self.lookup_view(&v, ctx),
            None => Decision::none(),
        }
    }

    fn lookup_view(&self, v: &NameView<'_>, ctx: &QueryCtx<'_>) -> Decision {
        let Some(text) = TextBuf::new(v.labels()) else {
            return Decision::none();
        };
        let mut g = Gather::new();
        self.gather_keys(v, ctx, text.text(), &mut g);
        self.gather_patterns(v, &text, ctx, &mut g);
        self.decide(g, text.text())
    }

    /// The cold stage for a name, once [`Bundle::lookup_name`] returned [`ColdCheck::Needed`]:
    /// one probe per suffix the cold filter passes, at most one page read each.
    pub fn lookup_cold(&self, name: &QName, reader: &dyn PageReader) -> ColdResult {
        match NameView::new(name.labels()) {
            Some(v) => self.cold_view(&v, reader),
            None => ColdResult::default(),
        }
    }

    /// [`Bundle::lookup_cold`] for labels.
    pub fn lookup_cold_labels(&self, labels: &[&[u8]], reader: &dyn PageReader) -> ColdResult {
        match NameView::new(labels.iter().copied()) {
            Some(v) => self.cold_view(&v, reader),
            None => ColdResult::default(),
        }
    }

    /// The hot lookup, then the cold stage when needed (synchronously: call it from a blocking
    /// thread when the bundle has a cold part).
    pub fn lookup_labels_full(
        &self,
        labels: &[&[u8]],
        ctx: &QueryCtx<'_>,
        reader: &dyn PageReader,
    ) -> Decision {
        let d = self.lookup_labels(labels, ctx);
        if d.cold == ColdCheck::Needed {
            let c = self.lookup_cold_labels(labels, reader);
            return d.with_cold(c);
        }
        d
    }

    fn cold_view(&self, v: &NameView<'_>, reader: &dyn PageReader) -> ColdResult {
        let Cold::Loaded(part) = &self.cold else {
            return ColdResult {
                matched: None,
                failed: matches!(self.cold, Cold::NotLoaded),
                refetch: Vec::new(),
            };
        };
        let mut failed = false;
        let mut refetch = Vec::new();
        for k in (1..=v.clean).rev() {
            let Some(key) = v.suffix(k) else { continue };
            let at_name = k == v.n;
            let h = KeyHash::of(self.hash_seed, key);
            if let Some((val, s)) = part.probe(h, reader, &mut failed, &mut refetch) {
                let applying = val.levels().applying(at_name);
                if let Some(level) = applying.top_level() {
                    return ColdResult {
                        matched: Some(Reason {
                            kind: if at_name {
                                MatchKind::Exact
                            } else {
                                MatchKind::Subs
                            },
                            key: ReasonKey::Suffix {
                                labels: u8::try_from(k).unwrap_or(u8::MAX),
                            },
                            cold: true,
                            part: PartId::ColdShard(s.number),
                            head: s.head.clone(),
                            level: Some(level),
                        }),
                        failed: false,
                        refetch,
                    };
                }
            }
        }
        ColdResult {
            matched: None,
            failed,
            refetch,
        }
    }

    fn gather_keys<'s>(&'s self, v: &NameView<'_>, ctx: &QueryCtx<'_>, text: &[u8], g: &mut Gather<'s>) {
        if self.hot.is_empty() {
            return;
        }
        for k in (1..=v.clean).rev() {
            let Some(key) = v.suffix(k) else { continue };
            let at_name = k == v.n;
            let h = KeyHash::of(self.hash_seed, key);
            let Some(shard) = self.hot_shard(h) else { continue };
            let Some(val) = shard.get(key, h) else { continue };
            let labels = u8::try_from(k).unwrap_or(u8::MAX);
            let plain = val.levels().applying(at_name);
            let src = Source {
                kind: if at_name {
                    MatchKind::Exact
                } else {
                    MatchKind::Subs
                },
                key: ReasonKey::Suffix { labels },
                part: PartId::Shard(shard.number),
                head: &shard.head,
                cold: false,
            };
            g.plain(plain, rank(u32::from(important(plain)), k), src);
            if let Some(set) = val.rich_idx() {
                let rsrc = Source {
                    kind: MatchKind::Rich,
                    ..src
                };
                self.gather_rich(
                    shard.rich(),
                    set,
                    at_name,
                    k,
                    NameSemantics::Labels,
                    rsrc,
                    v.labels(),
                    text,
                    ctx,
                    g,
                );
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the match path passes its borrowed query state down rather than build a struct per call"
    )]
    fn gather_rich<'s>(
        &'s self,
        rich: &'s RichSegment,
        set: u32,
        at_name: bool,
        depth: usize,
        sem: NameSemantics,
        src: Source<'s>,
        labels: &[&[u8]],
        text: &[u8],
        ctx: &QueryCtx<'_>,
        g: &mut Gather<'s>,
    ) {
        let text = std::str::from_utf8(text).unwrap_or("");
        for &ri in rich.set(set) {
            let Some(rule) = rich.rule(ri) else { continue };
            let applying = rule.flags.applying(at_name);
            if applying.is_empty() || !rule.conditions_match(labels, text, ctx, sem) {
                continue;
            }
            g.any = true;
            g.rich.push(RichCand {
                rule,
                applying,
                src,
                rank: rank(specifiers(rule), depth),
            });
        }
    }

    fn gather_patterns<'s>(
        &'s self,
        v: &NameView<'_>,
        text: &TextBuf,
        ctx: &QueryCtx<'_>,
        g: &mut Gather<'s>,
    ) {
        let part = &self.patterns;
        if part.patterns.is_empty() {
            return;
        }
        part.patterns.for_each_match(text.text(), text.url(), |pi, p| {
            let src = Source {
                kind: MatchKind::Pattern,
                key: ReasonKey::Pattern { index: pi },
                part: PartId::Patterns,
                head: &part.head,
                cold: false,
            };
            match p.rich_set() {
                Some(set) => self.gather_rich(
                    &part.rich,
                    set,
                    true,
                    0,
                    NameSemantics::Text,
                    src,
                    v.labels(),
                    text.text(),
                    ctx,
                    g,
                ),
                None => {
                    let f = p.flags();
                    g.plain(f, rank(u32::from(important(f)), 0), src);
                }
            }
        });
    }

    fn gather_ip<'s>(
        &'s self,
        hit: &IpHit<'s>,
        v: &NameView<'_>,
        text: &[u8],
        ctx: &QueryCtx<'_>,
        g: &mut Gather<'s>,
    ) {
        let src = Source {
            kind: MatchKind::Ip,
            key: ReasonKey::Address,
            part: PartId::IpShard(hit.shard.id),
            head: &hit.shard.head,
            cold: false,
        };
        let plain = hit.value.levels().applying(true);
        g.plain(plain, rank(u32::from(important(plain)), 0), src);
        if let Some(set) = hit.value.rich_idx() {
            self.gather_rich(
                hit.shard.rich(),
                set,
                true,
                0,
                NameSemantics::Labels,
                src,
                v.labels(),
                text,
                ctx,
                g,
            );
        }
    }

    fn decide(&self, g: Gather<'_>, text: &[u8]) -> Decision {
        if !g.any {
            return self.with_cold_stage(Decision::none());
        }
        if self.action == BundleAction::Allow {
            let reason = best_reason(&g);
            return Decision {
                outcome: Outcome::Allow,
                reason,
                cold: ColdCheck::NotApplicable,
            };
        }
        // 1. Rewrites in urlfilter's matched-rule order, after `@@…$dnsrewrite` cancellations.
        let mut rws: SmallVec<[&RichCand<'_>; 4]> = SmallVec::new();
        for c in &g.rich {
            if c.rule.dnsrewrite.is_some() && !rws.iter().any(|x| x.rule == c.rule) {
                rws.push(c);
            }
        }
        if !rws.is_empty() {
            let text_s = std::str::from_utf8(text).unwrap_or("");
            let orders: Vec<MatchOrder> = rws
                .iter()
                .map(|c| {
                    c.rule.order.unwrap_or(MatchOrder {
                        gram: None,
                        seq: u32::MAX,
                    })
                })
                .collect();
            let seq: Vec<&RichCand<'_>> = sequence(text_s, &orders)
                .into_iter()
                .filter_map(|k| rws.get(k).copied())
                .collect();
            let cands: Vec<RewriteCandidate<'_>> = seq
                .iter()
                .filter_map(|c| {
                    Some(RewriteCandidate {
                        rewrite: c.rule.dnsrewrite.as_ref()?,
                        important: important(c.rule.flags),
                        exception: c.rule.flags.intersects(Flags::ALL_ALLOW),
                    })
                })
                .collect();
            let (left, _) = apply_rewrite_exceptions_by(&cands);
            let left_rw: Vec<&picket_rules::rewrite::DnsRewrite> = left
                .iter()
                .filter_map(|&i| cands.get(i).map(|c| c.rewrite))
                .collect();
            if let Some((answer, used)) = merge_rewrites(&left_rw) {
                let self_cname = matches!(&answer, RewriteAnswer::Cname(c) if c.as_bytes() == text);
                if !self_cname {
                    let reason = used
                        .first()
                        .and_then(|&u| left.get(u))
                        .and_then(|&i| seq.get(i))
                        .map(|c| c.src.reason(None));
                    return Decision {
                        outcome: self.finish(Outcome::Rewrite(answer)),
                        reason,
                        cold: ColdCheck::NotApplicable,
                    };
                }
            }
        }
        // 2. The top level among matches other than rewrites and mappings.
        let mut top: Option<(Level, u32, Source<'_>)> = g.top_plain();
        for c in &g.rich {
            if c.rule.dnsrewrite.is_some() || c.rule.hosts_ip.is_some() {
                continue;
            }
            let Some(l) = c.applying.top_level() else { continue };
            let better = match top {
                None => true,
                Some((tl, tr, _)) => l < tl || (l == tl && c.rank > tr),
            };
            if better {
                top = Some((l, c.rank, c.src));
            }
        }
        if let Some((level, _, src)) = top {
            let outcome = if level.is_allow() {
                Outcome::Exception
            } else {
                Outcome::Block
            };
            return Decision {
                outcome: self.finish(outcome),
                reason: Some(src.reason(Some(level))),
                cold: ColdCheck::NotApplicable,
            };
        }
        // 3. Host-IP mappings.
        let mut ips: Vec<IpAddr> = Vec::new();
        let mut reason = None;
        for c in &g.rich {
            if let Some(ip) = c.rule.hosts_ip {
                ips.push(ip);
                if reason.is_none() {
                    reason = Some(c.src.reason(Some(Level::Block)));
                }
            }
        }
        if !ips.is_empty() {
            ips.sort();
            ips.dedup();
            return self.with_cold_stage(Decision {
                outcome: self.finish(Outcome::HostMapping(ips)),
                reason,
                cold: ColdCheck::NotApplicable,
            });
        }
        self.with_cold_stage(Decision::none())
    }

    /// Marks a hot decision of no result or a host mapping as needing the cold stage.
    fn with_cold_stage(&self, mut d: Decision) -> Decision {
        if self.action != BundleAction::Block {
            return d;
        }
        d.cold = match self.cold {
            Cold::None => ColdCheck::NotApplicable,
            Cold::NotLoaded => ColdCheck::Unchecked { refetch: Vec::new() },
            Cold::Loaded(_) => ColdCheck::Needed,
        };
        d
    }

    fn finish(&self, o: Outcome) -> Outcome {
        if self.action != BundleAction::Scope {
            return o;
        }
        match o {
            Outcome::Block | Outcome::Rewrite(_) | Outcome::HostMapping(_) => Outcome::InScope,
            _ => Outcome::None,
        }
    }

    fn ip_value(&self, ip: IpAddr) -> Option<IpHit<'_>> {
        match ip {
            IpAddr::V4(a) => {
                let a = u32::from(a);
                let s = self.v4.get(usize::from((a >> 24) as u8))?.as_ref()?;
                let (value, _) = s.get(u128::from(a))?;
                Some(IpHit { value, shard: s })
            }
            IpAddr::V6(a) => {
                let s = self.v6.as_ref()?;
                let (value, _) = s.get(u128::from(a))?;
                Some(IpHit { value, shard: s })
            }
        }
    }

    /// Looks up an answer address or HTTPS/SVCB hint (rules.md §6; the hot part, see
    /// [`ColdCheck::Needed`]).
    pub fn lookup_ip(&self, ip: IpAddr, ctx: &QueryCtx<'_>) -> Decision {
        let ip = picket_rules::ip::canonical_ip(ip);
        let hit = self.ip_value(ip);
        // Fast path: a set hit blocks at once (bundles.md §6), or allows in an allow bundle.
        if let Some(h) = &hit
            && h.value == crate::ips::plain_value()
            && (self.ip_fast_path || self.action == BundleAction::Allow)
        {
            let src = Source {
                kind: MatchKind::Ip,
                key: ReasonKey::Address,
                part: PartId::IpShard(h.shard.id),
                head: &h.shard.head,
                cold: false,
            };
            let outcome = match self.action {
                BundleAction::Allow => Outcome::Allow,
                _ => self.finish(Outcome::Block),
            };
            return Decision {
                outcome,
                reason: Some(src.reason(Some(Level::Block))),
                cold: ColdCheck::NotApplicable,
            };
        }
        self.with_ip_text(ip, |v, text| {
            let mut g = Gather::new();
            if let Some(h) = &hit {
                self.gather_ip(h, v, text.text(), ctx, &mut g);
            }
            self.gather_keys(v, ctx, text.text(), &mut g);
            self.gather_patterns(v, text, ctx, &mut g);
            self.decide(g, text.text())
        })
        .unwrap_or_else(Decision::none)
    }

    /// The cold stage for an address's text (its labels as a name), after
    /// [`Bundle::lookup_ip`] returned [`ColdCheck::Needed`].
    pub fn lookup_ip_cold(&self, ip: IpAddr, reader: &dyn PageReader) -> ColdResult {
        let ip = picket_rules::ip::canonical_ip(ip);
        self.with_ip_text(ip, |v, _| self.cold_view(v, reader))
            .unwrap_or_default()
    }

    /// Runs `f` on an address's Go text form as labels (IPv4: its four octets; IPv6: one label)
    /// and as a text buffer.
    fn with_ip_text<R>(&self, ip: IpAddr, f: impl FnOnce(&NameView<'_>, &TextBuf) -> R) -> Option<R> {
        match ip {
            IpAddr::V4(a) => {
                let o = a.octets();
                let mut digits = [[0u8; 3]; 4];
                let mut lens = [0usize; 4];
                for ((d, l), &b) in digits.iter_mut().zip(lens.iter_mut()).zip(o.iter()) {
                    *l = write_decimal(b, d);
                }
                let labels: [&[u8]; 4] = [
                    digits[0].get(..lens[0]).unwrap_or(&[]),
                    digits[1].get(..lens[1]).unwrap_or(&[]),
                    digits[2].get(..lens[2]).unwrap_or(&[]),
                    digits[3].get(..lens[3]).unwrap_or(&[]),
                ];
                let v = NameView::new(labels.iter().copied())?;
                let t = TextBuf::new(&labels)?;
                Some(f(&v, &t))
            }
            IpAddr::V6(a) => {
                let mut buf = [0u8; IPV6_TEXT_CAP];
                let n = go_ipv6_text(&a, &mut buf);
                let s = buf.get(..n).unwrap_or(&[]);
                let labels: [&[u8]; 1] = [s];
                let v = NameView::new(labels.iter().copied())?;
                let t = TextBuf::from_text(s)?;
                Some(f(&v, &t))
            }
        }
    }
}

/// The longest IPv6 text form (`ffff:` × 7 + `ffff`).
const IPV6_TEXT_CAP: usize = 39;

/// Go's `net.IP.String()` for a non-mapped IPv6 address ([`picket_rules::ip::go_ip_string`]),
/// written into a stack buffer so an address check allocates nothing (build-and-test.md §4;
/// review round 1, B9): lowercase hex groups, the longest run of two or more zero groups (the first
/// on a tie) as `::`. Returns the length.
fn go_ipv6_text(a: &std::net::Ipv6Addr, out: &mut [u8; IPV6_TEXT_CAP]) -> usize {
    let seg = a.segments();
    let (mut best_start, mut best_len) = (usize::MAX, 0usize);
    let mut i = 0usize;
    while i < 8 {
        if seg.get(i) == Some(&0) {
            let start = i;
            while seg.get(i) == Some(&0) {
                i = i.saturating_add(1);
            }
            let len = i.saturating_sub(start);
            if len >= 2 && len > best_len {
                best_start = start;
                best_len = len;
            }
        } else {
            i = i.saturating_add(1);
        }
    }
    let mut n = 0usize;
    let mut put = |b: u8, n: &mut usize| {
        if let Some(d) = out.get_mut(*n) {
            *d = b;
            *n = n.saturating_add(1);
        }
    };
    let mut i = 0usize;
    while i < 8 {
        if i == best_start {
            put(b':', &mut n);
            put(b':', &mut n);
            i = i.saturating_add(best_len);
            continue;
        }
        if i > 0 && i != best_start.saturating_add(best_len) {
            put(b':', &mut n);
        }
        let g = seg.get(i).copied().unwrap_or(0);
        let mut started = false;
        for shift in [12u32, 8, 4, 0] {
            let d = ((g >> shift) & 0xf) as u8;
            if d != 0 || started || shift == 0 {
                started = true;
                put(
                    if d < 10 {
                        b'0'.wrapping_add(d)
                    } else {
                        b'a'.wrapping_add(d.wrapping_sub(10))
                    },
                    &mut n,
                );
            }
        }
        i = i.saturating_add(1);
    }
    n
}

fn write_decimal(b: u8, out: &mut [u8; 3]) -> usize {
    if b >= 100 {
        out[0] = b'0'.wrapping_add(b / 100);
        out[1] = b'0'.wrapping_add((b / 10) % 10);
        out[2] = b'0'.wrapping_add(b % 10);
        3
    } else if b >= 10 {
        out[0] = b'0'.wrapping_add(b / 10);
        out[1] = b'0'.wrapping_add(b % 10);
        2
    } else {
        out[0] = b'0'.wrapping_add(b);
        1
    }
}

fn best_reason(g: &Gather<'_>) -> Option<Reason> {
    let mut top = g.top_plain();
    for c in &g.rich {
        let Some(l) = c.applying.top_level() else { continue };
        let better = match top {
            None => true,
            Some((tl, tr, _)) => l < tl || (l == tl && c.rank > tr),
        };
        if better {
            top = Some((l, c.rank, c.src));
        }
    }
    top.map(|(l, _, s)| s.reason(Some(l)))
        .or_else(|| g.rich.first().map(|c| c.src.reason(None)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_form_matches_picket_api() {
        let cases: Vec<Vec<&[u8]>> = vec![
            vec![b"Ads", b"example", b"org"],
            vec![b"a.b", b"ex ample", b"c\\m", b"x_y-1"],
            vec![b"\x00\xff", b"@;()\"'"],
        ];
        for labels in cases {
            let t = TextBuf::new(&labels).unwrap();
            let want = picket_api::names::adguard_text(labels.iter().copied());
            assert_eq!(t.text(), want.as_bytes());
            assert!(t.url().starts_with(b"http://"));
        }
    }

    #[test]
    fn name_view_suffixes() {
        let labels: Vec<&[u8]> = vec![b"Ads", b"www", b"example", b"org"];
        let v = NameView::new(labels.iter().copied()).unwrap();
        assert_eq!(v.suffix(4), Some(&b"org.example.www.ads"[..]));
        assert_eq!(v.suffix(1), Some(&b"org"[..]));
        assert_eq!(v.suffix(5), None);
        let labels: Vec<&[u8]> = vec![b"x", b"a.b", b"example"];
        let v = NameView::new(labels.iter().copied()).unwrap();
        assert_eq!(v.clean, 1);
        assert_eq!(v.suffix(1), Some(&b"example"[..]));
        assert_eq!(v.suffix(2), None, "a suffix with a `.` byte label matches no key");
        assert!(NameView::new(std::iter::empty()).is_none());
    }

    #[test]
    fn ipv6_text_is_go_text() {
        let mut cases: Vec<std::net::Ipv6Addr> = [
            "::",
            "::1",
            "1::",
            "2001:db8::1",
            "2001:db8:0:0:1:0:0:1",
            "2001:0:0:1:0:0:0:1",
            "0:0:1:0:0:1:0:0",
            "1:2:3:4:5:6:7:8",
            "fe80::1:2",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "1:0:2:0:3:0:4:0",
            "0:1:0:1:0:1:0:1",
            "::ffff:0:1",
            "64:ff9b::1.2.3.4",
            "::1.2.3.4",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        // Every pattern of zero and non-zero groups, with assorted digit counts.
        for mask in 0u32..256 {
            let seg: Vec<u16> = (0..8)
                .map(|i| {
                    if mask >> i & 1 == 1 {
                        [0x1, 0xab, 0x0f0, 0xbeef][i % 4]
                    } else {
                        0
                    }
                })
                .collect();
            cases.push(std::net::Ipv6Addr::new(
                seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
            ));
        }
        for a in cases {
            if a.to_ipv4_mapped().is_some() {
                continue;
            }
            let mut buf = [0u8; IPV6_TEXT_CAP];
            let n = go_ipv6_text(&a, &mut buf);
            assert_eq!(
                std::str::from_utf8(&buf[..n]).unwrap(),
                picket_rules::ip::go_ip_string(IpAddr::V6(a)),
                "{a}"
            );
        }
    }

    #[test]
    fn decimals() {
        for b in [0u8, 7, 10, 99, 100, 255] {
            let mut d = [0u8; 3];
            let n = write_decimal(b, &mut d);
            assert_eq!(&d[..n], b.to_string().as_bytes());
        }
    }
}
