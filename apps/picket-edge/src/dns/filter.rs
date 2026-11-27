//! Filtering (edge.md §9, rules.md §5–§6): the profile ladder over the active bundles, for query
//! names and for response-check targets, and the lookup-scope test.
//!
//! - Step 1: this device's temporary allows (`allows.json`'s DNS allows, by device and name).
//! - Step 2: the profile's allow bundles, in order: a match allows.
//! - Step 3: the profile's block bundles, in order: the first BLOCK, REWRITE or host-IP mapping
//!   wins. A bundle whose winning rule is an exception is passed over (and marks the name "let
//!   through by an exception" for `response_checks`).
//! - Cold parts: only when a block bundle's hot part found no rewrite, block or exception; one
//!   blocking page read per probe the cold filter passes, in a blocking thread. A page that fails
//!   to read, or a cold part that isn't loaded, fails open and marks the bundle unchecked.
//!
//! Each bundle is matched with picket-bundle's [`Bundle`] from the active state ([`ActiveBundles`],
//! which the activator in [`crate::bundles`] populates; with none, every name resolves).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use picket_api::logs::{MatchKind, Reason as LogReason, Stage};
use picket_api::time::Timestamp;
use picket_bundle::matcher::{Bundle, ColdCheck, Decision, Reason as BundleReason};
use picket_bundle::page::PageReader;
use picket_rules::QueryCtx;
use picket_rules::matcher::Outcome;
use picket_rules::rewrite::RewriteAnswer;
use picket_wire::{NameRef, QName, WireName};

use super::profiles::DeviceKey;
use super::runtime::ProfileRt;

/// The bundles the edge runs, as of one activation step (edge.md §13): each bundle loaded once,
/// shared by every listener and profile. The activator in [`crate::bundles`] builds it
/// (bundles.md §6); tests may also build bundles in memory.
#[derive(Clone, Default)]
pub struct ActiveBundles {
    pub bundles: HashMap<Arc<str>, Arc<Bundle>>,
    /// Reads cold page files (on the SSD; edge-unifi.md §1). `None`: cold parts can't be read and
    /// every cold check is unchecked.
    pub pages: Option<Arc<dyn PageReader>>,
}

impl std::fmt::Debug for ActiveBundles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names: Vec<&Arc<str>> = self.bundles.keys().collect();
        names.sort();
        f.debug_struct("ActiveBundles")
            .field("bundles", &names)
            .field("pages", &self.pages.is_some())
            .finish()
    }
}

impl ActiveBundles {
    pub fn get(&self, id: &str) -> Option<&Arc<Bundle>> {
        self.bundles.get(id)
    }

    /// The bundle and its shared id.
    pub fn entry(&self, id: &str) -> Option<(&Arc<str>, &Arc<Bundle>)> {
        self.bundles.get_key_value(id)
    }
}

/// The client context rules see (`$client`, `$ctag`, `$dnstype`).
#[derive(Clone, Copy, Debug)]
pub struct Who<'a> {
    pub ip: IpAddr,
    pub names: &'a [&'a str],
    pub tags: &'a [&'a str],
}

impl<'a> Who<'a> {
    fn ctx(&self, qtype: u16) -> QueryCtx<'a> {
        QueryCtx {
            qtype,
            client_ip: Some(self.ip),
            client_names: self.names,
            client_tags: self.tags,
        }
    }
}

/// What was matched, kept for the log's key text.
#[derive(Clone, Debug)]
// The name stays on the stack: boxing it would allocate on the block path (build-and-test.md §4).
#[expect(
    clippy::large_enum_variant,
    reason = "boxing the name would allocate on the block path (build-and-test.md §4)"
)]
pub enum HitTarget {
    Name(QName),
    Addr(IpAddr),
}

/// What a bundle rule decided, with what the log and the EDE need. Building one allocates
/// nothing (the key text is made only for the log).
#[derive(Clone, Debug)]
pub struct BundleHit {
    pub bundle: Arc<str>,
    pub matcher: Arc<Bundle>,
    pub reason: BundleReason,
    pub target: HitTarget,
}

impl BundleHit {
    /// The short head id the EDE and log name (edge.md §4 EDE).
    pub fn short_head(&self) -> &str {
        picket_api::ids::short_id(&self.reason.head)
    }

    /// `reason.key` as logged (api.md §5): the matched suffix, the pattern's source or the
    /// address.
    pub fn key(&self) -> String {
        match &self.target {
            HitTarget::Name(q) => {
                let labels: smallvec::SmallVec<[&[u8]; 16]> = q.labels().collect();
                self.reason.key_text(&self.matcher, &labels)
            }
            HitTarget::Addr(ip) => match self.reason.key {
                picket_bundle::matcher::ReasonKey::Pattern { .. } => self.reason.key_text(&self.matcher, &[]),
                _ => picket_wire::log::ip_text(*ip),
            },
        }
    }
}

/// A temporary allow that matched (ladder step 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TempAllowHit {
    pub allow_id: String,
}

/// The ladder's result for a name or an address.
#[derive(Clone, Debug)]
pub enum Verdict {
    /// Step 1.
    TempAllow(TempAllowHit),
    /// Step 2.
    Allow(BundleHit),
    /// Step 3: BLOCK.
    Block(BundleHit),
    /// Step 3: a `$dnsrewrite` answer.
    Rewrite(BundleHit, RewriteAnswer),
    /// Step 3: a host-IP mapping (sorted addresses).
    HostMapping(BundleHit, Vec<IpAddr>),
    /// No step decided. `exception`: a block bundle's exception let it through; `by`: the first
    /// such bundle's exception, which the query record names as its `reason` (core.md §6
    /// attributes an allow by an exception; api.md §5).
    Pass { exception: bool, by: Option<BundleHit> },
}

impl Verdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::TempAllow(_) | Verdict::Allow(_))
    }
}

/// The ladder's result plus the bundles whose cold check couldn't be made.
#[derive(Clone, Debug)]
pub struct LadderOut {
    pub verdict: Verdict,
    pub cold_unchecked: Vec<Arc<str>>,
    /// Page files that failed their checksum (deleted and fetched again: [`crate::bundles`]).
    pub refetch: Vec<String>,
}

/// What is matched: a name or an address.
#[derive(Clone, Copy, Debug)]
pub enum Target<'a> {
    Name(&'a QName),
    Addr(IpAddr),
}

/// Temporary allows, by device: `allows.json`'s DNS allows (edge.md §12).
pub trait TempAllows: Send + Sync {
    /// The allow covering `name` for `device`, if any.
    fn find(&self, device: &DeviceKey, name: NameRef<'_>) -> Option<TempAllowHit>;
}

/// No temporary allows.
pub struct NoTempAllows;

impl TempAllows for NoTempAllows {
    fn find(&self, _: &DeviceKey, _: NameRef<'_>) -> Option<TempAllowHit> {
        None
    }
}

/// An index over a snapshot of `allows.json`: device → (name, subdomains, expiry, allow id).
pub struct AllowIndex {
    by_device: HashMap<String, Vec<(WireName, bool, picket_api::time::Timestamp, String)>>,
    /// Expiry is judged only on a synchronised clock (README §2 Clocks).
    clock: Option<Arc<crate::clock::Clock>>,
}

impl AllowIndex {
    pub fn build(file: &crate::allows::AllowsFile, clock: Option<Arc<crate::clock::Clock>>) -> Self {
        let mut by_device: HashMap<String, Vec<_>> = HashMap::new();
        for a in &file.allows {
            if a.kind != picket_api::logs::AllowKind::Dns {
                continue;
            }
            let Ok(name) = WireName::from_text(&a.target) else {
                continue;
            };
            by_device.entry(a.device.clone()).or_default().push((
                name,
                a.subdomains.unwrap_or(false),
                a.expires_at,
                a.allow_id.clone(),
            ));
        }
        Self { by_device, clock }
    }

    pub fn is_empty(&self) -> bool {
        self.by_device.is_empty()
    }
}

impl TempAllows for AllowIndex {
    fn find(&self, device: &DeviceKey, name: NameRef<'_>) -> Option<TempAllowHit> {
        if self.by_device.is_empty() {
            return None;
        }
        let list = device.with_text(|t| self.by_device.get(t))?;
        let now = self
            .clock
            .as_ref()
            .filter(|c| c.synced())
            .map(|_| Timestamp::now());
        list.iter().find_map(|(t, subs, exp, id)| {
            if now.is_some_and(|n| *exp <= n) {
                return None;
            }
            let hit = if *subs {
                name.is_at_or_below(t.as_name())
            } else {
                name == t.as_name()
            };
            hit.then(|| TempAllowHit { allow_id: id.clone() })
        })
    }
}

fn hit(bundle: &Arc<str>, b: &Arc<Bundle>, reason: BundleReason, target: Target<'_>) -> BundleHit {
    BundleHit {
        bundle: Arc::clone(bundle),
        matcher: Arc::clone(b),
        reason,
        target: match target {
            Target::Name(q) => HitTarget::Name(q.clone()),
            Target::Addr(ip) => HitTarget::Addr(ip),
        },
    }
}

/// One bundle's decision for a target, with the cold stage run when needed.
async fn decide(
    b: &Arc<Bundle>,
    target: Target<'_>,
    ctx: &QueryCtx<'_>,
    pages: Option<&Arc<dyn PageReader>>,
) -> Decision {
    let d = match target {
        Target::Name(q) => b.lookup_name(q, ctx),
        Target::Addr(ip) => b.lookup_ip(ip, ctx),
    };
    if d.cold != ColdCheck::Needed {
        return d;
    }
    let Some(pages) = pages else {
        // No reader: the cold part can't be checked (edge.md §9 "Unchecked cold lookups").
        return d.with_cold(picket_bundle::matcher::ColdResult {
            matched: None,
            failed: true,
            refetch: vec![],
        });
    };
    let b2 = Arc::clone(b);
    let r = Arc::clone(pages);
    let res = match target {
        Target::Name(q) => {
            let q = q.clone();
            tokio::task::spawn_blocking(move || b2.lookup_cold(&q, &*r)).await
        }
        Target::Addr(ip) => tokio::task::spawn_blocking(move || b2.lookup_ip_cold(ip, &*r)).await,
    };
    let cold = res.unwrap_or(picket_bundle::matcher::ColdResult {
        matched: None,
        failed: true,
        refetch: vec![],
    });
    d.with_cold(cold)
}

/// Runs ladder steps 1–3 for `target` under `profile` (rules.md §5). `rtype` is the query type,
/// or for a response check the record's type (`$dnstype` matches it, rules.md §6).
pub async fn ladder(
    bundles: &ActiveBundles,
    profile: &ProfileRt,
    who: &Who<'_>,
    device: &DeviceKey,
    allows: &dyn TempAllows,
    target: Target<'_>,
    rtype: u16,
) -> LadderOut {
    let mut out = LadderOut {
        verdict: Verdict::Pass {
            exception: false,
            by: None,
        },
        cold_unchecked: vec![],
        refetch: vec![],
    };
    // Step 1.
    if let Target::Name(q) = target
        && let Some(h) = allows.find(device, q.as_name())
    {
        out.verdict = Verdict::TempAllow(h);
        return out;
    }
    let ctx = who.ctx(rtype);
    let pages = bundles.pages.as_ref();
    // Step 2.
    for id in &profile.cfg.allow {
        let Some((id, b)) = bundles.entry(id) else {
            continue;
        };
        let d = decide(b, target, &ctx, pages).await;
        if d.outcome == Outcome::Allow
            && let Some(r) = d.reason
        {
            out.verdict = Verdict::Allow(hit(id, b, r, target));
            return out;
        }
    }
    // Step 3.
    let mut exception = false;
    let mut by: Option<BundleHit> = None;
    for id in &profile.cfg.block {
        let Some((id, b)) = bundles.entry(id) else {
            continue;
        };
        let d = decide(b, target, &ctx, pages).await;
        if let ColdCheck::Unchecked { refetch } = &d.cold {
            out.cold_unchecked.push(Arc::clone(id));
            for f in refetch {
                if !out.refetch.contains(f) {
                    out.refetch.push(f.clone());
                }
            }
        }
        let reason = d.reason;
        match (d.outcome, reason) {
            (Outcome::Block, Some(r)) => {
                out.verdict = Verdict::Block(hit(id, b, r, target));
                return out;
            }
            (Outcome::Rewrite(ans), Some(r)) => {
                out.verdict = Verdict::Rewrite(hit(id, b, r, target), ans);
                return out;
            }
            (Outcome::HostMapping(ips), Some(r)) => {
                out.verdict = Verdict::HostMapping(hit(id, b, r, target), ips);
                return out;
            }
            (Outcome::Exception, r) => {
                exception = true;
                if by.is_none()
                    && let Some(r) = r
                {
                    by = Some(hit(id, b, r, target));
                }
            }
            _ => {}
        }
    }
    out.verdict = Verdict::Pass { exception, by };
    out
}

/// True when `name` is in bundle `id` (lookup scopes, edge.md §10): its rules match the name
/// (a block, rewrite, mapping, allow or scope match; an exception or nothing isn't). A bundle the
/// edge doesn't hold matches nothing.
pub fn in_bundle(bundles: &ActiveBundles, id: &str, name: &QName, who: &Who<'_>, qtype: u16) -> bool {
    let Some(b) = bundles.get(id) else {
        return false;
    };
    let d = b.lookup_name(name, &who.ctx(qtype));
    !matches!(d.outcome, Outcome::None | Outcome::Exception)
}

/// A block id (edge.md §4 EDE `block=`, §12): what a DNS allow names. Eight lowercase base32
/// characters from the BLAKE3 of what the block is: the bundle (or lookup provider), the head and
/// part, the deciding key, the query name and the value that blocked. Deterministic, so the same
/// block of the same name always has the same id; written into a stack buffer (no allocation).
pub fn block_id(parts: &[&[u8]]) -> BlockId {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(&u32::try_from(p.len()).unwrap_or(u32::MAX).to_le_bytes());
        h.update(p);
    }
    let d = h.finalize();
    let bytes = d.as_bytes();
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut v: u64 = 0;
    for &b in bytes.iter().take(5) {
        v = (v << 8) | u64::from(b);
    }
    let mut out = [0u8; 8];
    for (shift, slot) in [35u32, 30, 25, 20, 15, 10, 5, 0].into_iter().zip(out.iter_mut()) {
        *slot = ALPHABET[((v >> shift) & 31) as usize];
    }
    BlockId(out)
}

/// A block id's text, on the stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockId(pub [u8; 8]);

impl BlockId {
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("")
    }
}

/// The block id of a bundle hit for a query name and the value that blocked: the bundle, the
/// head, the part and the deciding key (by its position: a suffix length or a pattern index),
/// with the query name and the value. Allocates nothing.
pub fn bundle_block_id(h: &BundleHit, qname: &[u8], value: &[u8]) -> BlockId {
    use picket_bundle::matcher::{PartId, ReasonKey};
    let mut part = [0u8; 9];
    match h.reason.part {
        PartId::Shard(n) => {
            part[0] = 1;
            part[1..5].copy_from_slice(&n.to_le_bytes());
        }
        PartId::ColdShard(n) => {
            part[0] = 2;
            part[1..5].copy_from_slice(&n.to_le_bytes());
        }
        PartId::IpShard(_) => part[0] = 3,
        PartId::Patterns => part[0] = 4,
    }
    let mut key = [0u8; 5];
    match h.reason.key {
        ReasonKey::Suffix { labels } => {
            key[0] = 1;
            key[1] = labels;
        }
        ReasonKey::Pattern { index } => {
            key[0] = 2;
            key[1..5].copy_from_slice(&index.to_le_bytes());
        }
        ReasonKey::Address => key[0] = 3,
    }
    block_id(&[
        b"bundle",
        h.bundle.as_bytes(),
        h.reason.head.as_bytes(),
        &part,
        &key,
        qname,
        value,
    ])
}

/// The block id of a lookup block.
pub fn lookup_block_id(provider: &str, qname: &[u8]) -> BlockId {
    block_id(&[b"lookup", provider.as_bytes(), qname])
}

/// The log's `reason` for a bundle hit at `step` and `stage`.
pub fn log_reason(
    h: &BundleHit,
    step: u8,
    stage: Stage,
    block: Option<&BlockId>,
    value: Option<String>,
) -> LogReason {
    LogReason {
        step,
        bundle: Some(h.bundle.to_string()),
        key: Some(h.key()),
        kind: h.reason.kind,
        stage,
        block_id: block.map(|b| b.as_str().to_owned()),
        cold: h.reason.cold.then_some(true),
        provider: None,
        allow_id: None,
        value,
    }
}

/// The log's `reason` for a temporary allow.
pub fn temp_allow_reason(h: &TempAllowHit) -> LogReason {
    LogReason {
        step: 1,
        kind: MatchKind::TempAllow,
        allow_id: Some(h.allow_id.clone()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_ids_are_stable_short_and_distinct() {
        let a = block_id(&[b"bundle", b"block-common", b"ads.example.com"]);
        let b = block_id(&[b"bundle", b"block-common", b"ads.example.com"]);
        let c = block_id(&[b"bundle", b"block-common", b"ads.example.org"]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.as_str().len(), 8);
        assert!(
            a.as_str()
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        );
        // Length-prefixed parts: moving a byte between parts changes the id.
        assert_ne!(block_id(&[b"ab", b"c"]), block_id(&[b"a", b"bc"]));
    }

    #[test]
    fn allow_index_matches_device_name_and_subdomains() {
        let mut f = crate::allows::AllowsFile::default();
        let mut a = crate::allows::tests::allow("a-1", picket_api::logs::AllowKind::Dns, 3600);
        a.device = "aa:bb:cc:dd:ee:01".into();
        a.target = "ads.example.com".into();
        a.subdomains = Some(true);
        f.allows.push(a.clone());
        let mut b = crate::allows::tests::allow("a-2", picket_api::logs::AllowKind::Dns, -10);
        b.device = "aa:bb:cc:dd:ee:01".into();
        b.target = "expired.example.com".into();
        f.allows.push(b);
        let dev = DeviceKey::Mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        let other = DeviceKey::Mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);
        let idx = AllowIndex::build(&f, Some(crate::clock::Clock::fixed(true)));
        let q = |n: &str| QName::from_text(n).unwrap();
        assert!(idx.find(&dev, q("x.ads.example.com").as_name()).is_some());
        assert!(idx.find(&dev, q("ads.example.com").as_name()).is_some());
        assert!(idx.find(&other, q("ads.example.com").as_name()).is_none());
        assert!(idx.find(&dev, q("expired.example.com").as_name()).is_none());
        // Without a synchronised clock nothing counts as expired.
        let idx = AllowIndex::build(&f, Some(crate::clock::Clock::fixed(false)));
        assert!(idx.find(&dev, q("expired.example.com").as_name()).is_some());
    }
}
