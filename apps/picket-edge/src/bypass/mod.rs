//! Temporary allows and the bypass API (edge.md §12; api.md §6; browser-extension.md).
//!
//! - **Bypass API** on listeners with `"api": true` (DoH listeners): `GET`, `PUT` and `PATCH`
//!   `/v1/temporary-allows`. Every request must carry `X-Picket-Client: extension`; one with an
//!   `Origin` other than `chrome-extension://…` or `moz-extension://…` is refused, preflights are
//!   refused and no CORS header is ever sent. The caller is the device its source address belongs
//!   to; allows and limits are per device.
//! - **DNS allows** name a `block_id` from the device's recent-blocks ring (else 409); **IP
//!   allows** an IP that counts as blocked for the device (else 409), granted through the normal
//!   firewall path (a per-client pair whatever the granularity, expanded across the device's
//!   addresses, acked by the helper within 2 s, else 503 and nothing recorded).
//! - **Governing profiles:** the profile each of the device's addresses gets without a profile in
//!   the URL, plus for a DNS allow the profile stored with its block. Each must have
//!   `bypass.mode: self` (and `ips` for an IP allow), else 403; the smallest `max_duration`,
//!   `max_active` and `rate_per_hour` apply. Revoking is always allowed.
//! - A request is all or nothing; the error's `index` names the entry. Entries naming the same
//!   allow (by id, block or target) are taken once when they agree and refused (400) when they
//!   don't, before any limit is checked. Changes go to `allows.json` in one write and to the log
//!   as `allow` records (`security` class). The firewall steps that need the helper's ack (new
//!   and extended IP allows) come first and are undone to their previous expiries if anything
//!   fails; shortenings and revocations follow the write.
//! - **Bounded** (README §2; edge.md §16, §17): a `PUT`/`PATCH` is admitted by the device's
//!   limits before its body is read (else 429), its body is charged to its source's and the total
//!   body budget as DoH bodies are (else 503), and at most [`MAX_WAITING`] changes
//!   ([`MAX_WAITING_PER_DEVICE`] per device) wait for their turn (else 503). Once its body is
//!   read a change runs to its end in its own task, so a request that goes away mid-change (a
//!   stream reset) leaves the allow either recorded with its firewall entries or neither.
//! - **Durations:** `max_duration` is bounded at activation to the longest timeout a firewall
//!   entry can hold ([`crate::dns::runtime::bounds::BYPASS_MAX_DURATION_S`], ~24.8 days: an IP
//!   allow outliving its kernel entry would lapse unseen); every time sum is checked. A DNS
//!   allow that would end while browsers may still use its block's cached answer (the block's
//!   hold plus the reload margin, [`earliest_end`]) is refused, `403 too_short`, whether the
//!   request or the governing `max_duration` is short, rather than shortened behind a countdown
//!   that can't work (#50); an older block whose hold has mostly passed fits a shorter allow.
//! - After each config activation every allow is checked again, and a device's allows when it
//!   gains an address: one its governing profiles no longer permit is revoked (`via: config`),
//!   one that ends past now + their smallest `max_duration` is shortened (`via: config`). A
//!   re-check needs a synchronised clock (README §2 Clocks); one skipped meanwhile runs once the
//!   clock syncs, and neighbour events the re-check task missed (its channel overflowed) are made
//!   up by a full re-check that also expands IP allows to each device's current addresses (an
//!   allow that must be both shortened and expanded gets both). The re-check's changes, address
//!   expansions included, hold in memory even when `allows.json` can't be written, so a later
//!   revocation removes every address the memory lists; the write is retried until it lands
//!   ([`AllowsStore::commit_held`]).
//! - The recent-blocks ring answers the extension's DoH probes ([`RingHook`]).

pub mod ring;

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;

use jiff::SignedDuration;
use picket_api::bypass::{AllowEntry, AllowView, BypassError, BypassErrorDetail};
use picket_api::edge_config::BypassMode;
use picket_api::logs::{AllowAction, AllowKind, Proto};
use picket_api::time::Timestamp;
use picket_wire::reply;
use picket_wire::types::{rcode, rtype};
use picket_wire::{EdeOption, NameRef, Query, Transport, WireName};

use crate::allows::{AllowsStore, StoredAllow};
use crate::clock::Clock;
use crate::dns::interfaces::Interfaces;
use crate::dns::profiles::{Choice, DeviceKey};
use crate::dns::runtime::{DnsRuntime, ProfileRt, bounds};
use crate::dns::{BlockNote, RecentBlocks};
use crate::edge::Edge;
use crate::firewall::FwClient;
use crate::firewall::shadow::{FwKey, SetId};
use ring::{Entry, Ring, Source};

/// The bypass API's path.
pub const PATH: &str = "/v1/temporary-allows";
/// Largest request body.
pub const MAX_BODY: usize = 64 << 10;
/// Most entries in one request.
pub const MAX_ENTRIES: usize = 256;
/// A body must arrive within this.
const BODY_TIMEOUT: Duration = Duration::from_secs(10);
/// Most devices whose request rate is tracked (README §2 Bounded).
const MAX_RATE_DEVICES: usize = 65_536;
/// Most changes waiting for their turn, all devices together (policy choice).
pub const MAX_WAITING: usize = 64;
/// Most changes one device has waiting (policy choice).
pub const MAX_WAITING_PER_DEVICE: usize = 4;

/// Bypass state: the ring and the per-device request rates.
pub struct Bypass {
    pub ring: Ring,
    rates: Mutex<HashMap<String, VecDeque<Instant>>>,
    /// Allow changes run one at a time (they read, check and write `allows.json`).
    ops: tokio::sync::Mutex<()>,
    /// Changes waiting for `ops`, by device.
    waiting: Arc<Mutex<HashMap<String, usize>>>,
    /// A re-check was skipped on an unsynchronised clock: a full one runs once it syncs.
    skipped: AtomicBool,
}

/// What a re-check covers (edge.md §12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope<'a> {
    /// Every allow against the config just activated.
    All,
    /// One device's allows (it gained an address), its IP allows expanded to its addresses.
    Device(&'a str),
    /// Every allow, each MAC device's IP allows expanded to its current addresses: events may
    /// have been missed (a re-check skipped on an unsynchronised clock, neighbour events lost).
    CatchUp,
}

/// A change's place in the queue for `ops`, given back on drop.
struct Waiting {
    map: Arc<Mutex<HashMap<String, usize>>>,
    device: String,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let mut g = self.map.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = g.get_mut(&self.device) {
            *n -= 1;
            if *n == 0 {
                g.remove(&self.device);
            }
        }
    }
}

/// A refusal: status, code and message, and the entry it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub index: Option<usize>,
}

impl Refusal {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>, index: Option<usize>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            index,
        }
    }
}

fn json_response<T: serde::Serialize>(status: StatusCode, v: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(v).unwrap_or_default();
    let mut r = Response::new(Full::new(Bytes::from(body)));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    r
}

fn refusal_response(r: &Refusal) -> Response<Full<Bytes>> {
    json_response(
        r.status,
        &BypassError {
            error: BypassErrorDetail {
                code: r.code.into(),
                message: r.message.clone(),
                index: r.index,
            },
        },
    )
}

/// Unix seconds.
fn unix(t: Timestamp) -> i64 {
    t.as_second()
}

fn view(a: &StoredAllow, retry_after: Option<u64>) -> AllowView {
    AllowView {
        allow_id: a.allow_id.clone(),
        kind: a.kind,
        target: a.target.clone(),
        subdomains: a.subdomains,
        expires_at: unix(a.expires_at),
        retry_after_s: retry_after,
    }
}

/// How long before an allow's `expires_at` its reload must happen at the latest: room for the
/// reload and the extension's second attempt 2 s later while the allow still holds
/// ([`picket_api::edge_config::RELOAD_BEFORE_EXPIRY_S`]).
pub const RETRY_BEFORE_EXPIRY_S: i64 = 5;
const _: () = assert!(RETRY_BEFORE_EXPIRY_S.unsigned_abs() == RELOAD_BEFORE_EXPIRY_S_U);

/// The earliest a DNS allow of a block recorded at `block_time` with `ttl` may end (#50): the
/// end of the block's hold (a browser may use its cached block answer until then), plus the
/// reload margin. `None` once the hold has ended (a reload now gets the fresh answer), or for an
/// allow without its block's time and TTL.
///
/// Counted from the block's whole second, as `expires_at` is whole seconds: an allow of
/// [`picket_api::edge_config::min_allow_for_block_s`] asked in the block's own second then
/// fits, and the result is a whole second a caller can ask for. The hold's slack past the TTL
/// covers the fraction.
pub fn earliest_end(block_time: Option<Timestamp>, ttl: Option<u32>, now: Timestamp) -> Option<Timestamp> {
    let (t, ttl) = (block_time?, ttl?);
    let t = Timestamp::from_second(t.as_second()).unwrap_or(t);
    let hold = SignedDuration::from_secs(i64::try_from(ring::hold_s(ttl)).unwrap_or(i64::MAX));
    let hold_end = picket_api::time::saturating_add(t, hold);
    (hold_end > now)
        .then(|| picket_api::time::saturating_add(hold_end, SignedDuration::from_secs(RETRY_BEFORE_EXPIRY_S)))
}

/// Whole seconds from `now` to `t`, rounded up.
fn secs_ceil(t: Timestamp, now: Timestamp) -> u64 {
    let d = t - now;
    let s = d.as_secs() + i64::from(d.subsec_nanos() > 0);
    u64::try_from(s).unwrap_or(0)
}

/// The refusal of a DNS allow that would end before its block's cached answer expires (#50):
/// `403 too_short`, saying how long it would need, and whether the request or the governing
/// profiles' `max_duration` is what is short. Nothing is recorded or counted against limits.
fn too_short(earliest: Timestamp, max_end: Timestamp, ttl: u32, now: Timestamp, index: usize) -> Refusal {
    let need = secs_ceil(earliest, now);
    let message = if max_end < earliest {
        let max = secs_ceil(max_end, now);
        format!(
            "browsers may use this block's cached answer (block TTL {ttl} s) for {} s more, past              the longest allow this device's profiles permit ({max} s): ask again in {} s, or              have the profile's bypass.max_duration raised or block_response.ttl lowered",
            need.saturating_sub(RELOAD_BEFORE_EXPIRY_S_U),
            need.saturating_sub(max)
        )
    } else {
        format!(
            "the allow would end before browsers stop using this block's cached answer (block              TTL {ttl} s): ask for at least {need} s"
        )
    };
    Refusal::new(StatusCode::FORBIDDEN, "too_short", message, Some(index))
}

const RELOAD_BEFORE_EXPIRY_S_U: u64 = picket_api::edge_config::RELOAD_BEFORE_EXPIRY_S;

/// `retry_after_s` (edge.md §12): `max(0, block_time + hold − now)` for a DNS allow,
/// `hold = max(60 s, block TTL + 5 s)` ([`ring::hold_s`]), but never later than
/// [`RETRY_BEFORE_EXPIRY_S`] before the allow expires; 0 for an IP allow. The API creates or
/// re-times a DNS allow only when it outlasts the hold by that margin ([`earliest_end`], #50),
/// so the bound applies only to an allow a config re-check shortened, which reports no
/// `retry_after_s`.
pub fn retry_after(a: &StoredAllow, now: Timestamp) -> u64 {
    if a.kind == AllowKind::Ip {
        return 0;
    }
    let (Some(t), Some(ttl)) = (a.block_time, a.block_ttl) else {
        return 0;
    };
    let hold = SignedDuration::from_secs(i64::try_from(ring::hold_s(ttl)).unwrap_or(i64::MAX));
    let end = picket_api::time::saturating_add(t, hold);
    let latest =
        picket_api::time::saturating_add(a.expires_at, SignedDuration::from_secs(-RETRY_BEFORE_EXPIRY_S));
    u64::try_from((end.min(latest) - now).as_secs()).unwrap_or(0)
}

/// The labels of a wire name.
fn wire_labels(w: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(&len) = w.get(i) {
        if len == 0 {
            break;
        }
        let start = i + 1;
        let end = start + usize::from(len);
        let Some(l) = w.get(start..end) else { break };
        out.push(l);
        i = end;
    }
    out
}

/// The log text of a wire name (api.md §5 escaping).
pub fn wire_text(w: &[u8]) -> Option<String> {
    WireName::from_labels(wire_labels(w)).ok().map(|n| n.log_text())
}

/// The address a reverse-lookup name names (`in-addr.arpa`, `ip6.arpa`), for the extension's PTR
/// probe (edge.md §12). Labels are most specific first.
pub fn reverse_ip(labels: &[&[u8]]) -> Option<IpAddr> {
    let lower: Vec<Vec<u8>> = labels.iter().map(|l| l.to_ascii_lowercase()).collect();
    let n = lower.len();
    if n == 6 && lower[4] == b"in-addr" && lower[5] == b"arpa" {
        let mut o = [0u8; 4];
        for (i, l) in lower[..4].iter().enumerate() {
            if l.is_empty()
                || l.len() > 3
                || !l.iter().all(u8::is_ascii_digit)
                || (l.len() > 1 && l[0] == b'0')
            {
                return None;
            }
            let v: u16 = std::str::from_utf8(l).ok()?.parse().ok()?;
            o[3 - i] = u8::try_from(v).ok()?;
        }
        return Some(IpAddr::from(o));
    }
    if n == 34 && lower[32] == b"ip6" && lower[33] == b"arpa" {
        let mut v: u128 = 0;
        for l in lower[..32].iter().rev() {
            if l.len() != 1 {
                return None;
            }
            let d = char::from(l[0]).to_digit(16)?;
            v = (v << 4) | u128::from(d);
        }
        return Some(IpAddr::from(std::net::Ipv6Addr::from(v)));
    }
    None
}

/// The device's addresses: every address its MAC holds, plus the source address.
fn device_addrs(edge: &Edge, key: &DeviceKey, src: IpAddr) -> Vec<IpAddr> {
    let mut v = match key {
        DeviceKey::Mac(m) => edge.neighbours.addresses_of(m),
        _ => vec![],
    };
    let s = src.to_canonical();
    if !v.contains(&s) {
        v.push(s);
    }
    v
}

/// The governing profiles of a device's allows (edge.md §12): the profile each of its addresses
/// gets without a profile in the URL (steps 2 and 3 of §5). `None` when no profile admits one.
fn governing(rt: &DnsRuntime, key: &DeviceKey, addrs: &[IpAddr]) -> Option<Vec<Arc<ProfileRt>>> {
    let mac = match key {
        DeviceKey::Mac(m) => Some(*m),
        _ => None,
    };
    let mut out: Vec<Arc<ProfileRt>> = Vec::new();
    for a in addrs {
        let d = rt.device(*a, mac);
        match rt.choose(None, &d) {
            Choice::Profile(p) => {
                let pr = rt.profile(&p)?;
                if !out.iter().any(|x| x.id == pr.id) {
                    out.push(Arc::clone(pr));
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

/// The limits governing profiles allow: the smallest of each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Limits {
    max_duration: u64,
    max_active: u32,
    rate_per_hour: u32,
}

/// Checks the profiles permit a `kind` allow and returns the smallest limits.
fn limits(profiles: &[&ProfileRt], kind: AllowKind) -> Option<Limits> {
    if profiles.is_empty() {
        return None;
    }
    let mut l = Limits {
        max_duration: u64::MAX,
        max_active: u32::MAX,
        rate_per_hour: u32::MAX,
    };
    for p in profiles {
        let b = &p.cfg.bypass;
        if b.mode != BypassMode::SelfService || (kind == AllowKind::Ip && !b.ips) {
            return None;
        }
        l.max_duration = l.max_duration.min(b.max_duration.as_secs());
        l.max_active = l.max_active.min(b.max_active);
        l.rate_per_hour = l.rate_per_hour.min(b.rate_per_hour);
    }
    Some(l)
}

/// `now` plus `secs` (bounded to [`bounds::BYPASS_MAX_DURATION_S`]), never past the end of the
/// timestamp range (9999-12-30T22:00:00.999999999Z).
fn ends_by(now: Timestamp, secs: u64) -> Timestamp {
    let secs = secs.min(bounds::BYPASS_MAX_DURATION_S);
    let d = SignedDuration::from_secs(i64::try_from(secs).unwrap_or(i64::MAX));
    picket_api::time::saturating_add(now, d)
}

/// Whole seconds from `now` to `end`, at least 1 (an allow's firewall timeout).
fn secs_until(end: Timestamp, now: Timestamp) -> u64 {
    u64::try_from((end - now).as_secs()).unwrap_or(0).max(1)
}

/// The firewall keys of a stored IP allow: a pair per device address it lists (its source
/// address among them at creation; an address that moved to another device is dropped from the
/// list, edge-firewall.md §1).
pub fn allow_keys(a: &StoredAllow) -> Vec<FwKey> {
    let Ok(ip) = a.target.parse::<IpAddr>() else {
        return vec![];
    };
    let ip = ip.to_canonical();
    let srcs: Vec<IpAddr> = a.addresses.iter().filter_map(|s| s.parse().ok()).collect();
    srcs.into_iter()
        .map(|s: IpAddr| s.to_canonical())
        .filter(|s| s.is_ipv4() == ip.is_ipv4())
        .map(|s| FwKey {
            set: SetId::pair(ip.is_ipv4()),
            src: Some(s),
            dst: ip,
        })
        .collect()
}

fn new_allow_id() -> String {
    format!("a-{:012x}", rand::random::<u64>() & 0xffff_ffff_ffff)
}

/// One planned change.
enum Plan {
    Create(Box<StoredAllow>),
    Retime {
        old: Box<StoredAllow>,
        new: Box<StoredAllow>,
    },
    Revoke(Box<StoredAllow>),
}

impl Bypass {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ring: Ring::default(),
            rates: Mutex::new(HashMap::new()),
            ops: tokio::sync::Mutex::new(()),
            waiting: Arc::new(Mutex::new(HashMap::new())),
            skipped: AtomicBool::new(false),
        })
    }

    /// A place in the queue for `ops`, or `None` when it is full (in total or for the device).
    fn queue(&self, device: &str) -> Option<Waiting> {
        let mut g = self.waiting.lock().unwrap_or_else(|p| p.into_inner());
        let total: usize = g.values().sum();
        let mine = g.get(device).copied().unwrap_or(0);
        if total >= MAX_WAITING || mine >= MAX_WAITING_PER_DEVICE {
            return None;
        }
        *g.entry(device.to_owned()).or_default() += 1;
        Some(Waiting {
            map: Arc::clone(&self.waiting),
            device: device.to_owned(),
        })
    }

    /// Requests in the last hour by `device`, after pruning older ones.
    fn rate_count(&self, device: &str) -> usize {
        let mut g = self.rates.lock().unwrap_or_else(|p| p.into_inner());
        let Some(q) = g.get_mut(device) else { return 0 };
        while q
            .front()
            .is_some_and(|t| t.elapsed() >= Duration::from_secs(3600))
        {
            q.pop_front();
        }
        q.len()
    }

    fn rate_add(&self, device: &str, n: usize) {
        let mut g = self.rates.lock().unwrap_or_else(|p| p.into_inner());
        if g.len() >= MAX_RATE_DEVICES && !g.contains_key(device) {
            g.retain(|_, q| q.back().is_some_and(|t| t.elapsed() < Duration::from_secs(3600)));
            if g.len() >= MAX_RATE_DEVICES {
                return;
            }
        }
        let q = g.entry(device.to_owned()).or_default();
        let now = Instant::now();
        for _ in 0..n.min(10_000) {
            q.push_back(now);
        }
        while q.len() > 10_000 {
            q.pop_front();
        }
    }

    /// Serves one bypass API request (api.md §6).
    pub async fn handle_http(
        self: &Arc<Self>,
        edge: &Arc<Edge>,
        req: Request<Incoming>,
        peer: SocketAddr,
    ) -> Response<Full<Bytes>> {
        // Browser protection: no CORS, no preflight, the extension header, an extension origin.
        if req.method() == Method::OPTIONS {
            return refusal_response(&Refusal::new(
                StatusCode::FORBIDDEN,
                "forbidden",
                "preflight refused",
                None,
            ));
        }
        let ext = req
            .headers()
            .get(picket_api::bypass::CLIENT_HEADER)
            .is_some_and(|v| {
                v.as_bytes()
                    .eq_ignore_ascii_case(picket_api::bypass::CLIENT_HEADER_VALUE.as_bytes())
            });
        if !ext {
            return refusal_response(&Refusal::new(
                StatusCode::FORBIDDEN,
                "forbidden",
                "X-Picket-Client: extension is required",
                None,
            ));
        }
        if let Some(o) = req.headers().get(header::ORIGIN) {
            let ok = o.to_str().is_ok_and(|s| {
                let s = s.to_ascii_lowercase();
                s.starts_with("chrome-extension://") || s.starts_with("moz-extension://")
            });
            if !ok {
                return refusal_response(&Refusal::new(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    "origin refused",
                    None,
                ));
            }
        }
        // The runtime only: the active state (its bundles) isn't held across the body read and
        // the queue, as a swap waits for the parts it replaces to be freed (bundles.md §6).
        let Some(rt) = edge.active().dns.clone() else {
            return refusal_response(&Refusal::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "no config is active",
                None,
            ));
        };
        let src = peer.ip().to_canonical();
        let device = rt.device(src, edge.neighbours.mac_of(&src));
        let key = rt.clients.key(&device);
        match *req.method() {
            Method::GET => {
                let now = Timestamp::now();
                let text = key.text();
                let list: Vec<AllowView> = edge
                    .allows
                    .list()
                    .iter()
                    .filter(|a| a.device == text && (!edge.clock.synced() || a.expires_at > now))
                    .map(|a| view(a, None))
                    .collect();
                json_response(StatusCode::OK, &list)
            }
            Method::PUT | Method::PATCH => {
                let put = req.method() == Method::PUT;
                // The device's limits before its body is read (edge.md §16), as for DoH bodies.
                let slot = match crate::dns::pipeline::admit_early(edge, peer) {
                    Ok(s) => s,
                    Err(_) => {
                        edge.metrics
                            .rejected
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let mut r = refusal_response(&Refusal::new(
                            StatusCode::TOO_MANY_REQUESTS,
                            "busy",
                            "over this device's limits",
                            None,
                        ));
                        r.headers_mut()
                            .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
                        return r;
                    }
                };
                let charge = edge
                    .dns
                    .listeners
                    .shares
                    .body(crate::dns::listeners::share::source_key(edge, src));
                let (body, charge) = match read_body(req, charge).await {
                    Ok(b) => b,
                    Err(r) => return refusal_response(&r),
                };
                let entries: Vec<AllowEntry> = match parse_entries(&body) {
                    Ok(e) => e,
                    Err(r) => return refusal_response(&r),
                };
                drop(body);
                let Some(place) = self.queue(&key.text()) else {
                    return refusal_response(&Refusal::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "busy",
                        "too many changes waiting",
                        None,
                    ));
                };
                // The change runs to its end whatever happens to this request (edge.md §12: an
                // allow is recorded with its firewall entries, or neither).
                let (me, edge2) = (Arc::clone(self), Arc::clone(edge));
                let job = tokio::spawn(async move {
                    let r = me.change(&edge2, &rt, &key, src, entries, put, "extension").await;
                    drop((place, charge, slot));
                    r
                });
                match job.await {
                    Ok(Ok(v)) => json_response(StatusCode::OK, &v),
                    Ok(Err(r)) => refusal_response(&r),
                    Err(e) => refusal_response(&Refusal::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal",
                        crate::diag::cap(e),
                        None,
                    )),
                }
            }
            _ => {
                let mut r = refusal_response(&Refusal::new(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "GET, PUT or PATCH",
                    None,
                ));
                r.headers_mut()
                    .insert(header::ALLOW, header::HeaderValue::from_static("GET, PUT, PATCH"));
                r
            }
        }
    }

    /// Creates, re-times and revokes `device`'s allows (`PATCH`; `PUT` also revokes every allow
    /// it leaves out). All or nothing. Returns the device's allows after the change.
    #[expect(
        clippy::too_many_arguments,
        reason = "one allow change: the device, its entries and where the change came from"
    )]
    pub async fn change(
        &self,
        edge: &Edge,
        rt: &DnsRuntime,
        key: &DeviceKey,
        src: IpAddr,
        entries: Vec<AllowEntry>,
        put: bool,
        via: &str,
    ) -> Result<Vec<AllowView>, Refusal> {
        let _g = self.ops.lock().await;
        if !edge.clock.synced() {
            // Expiry times are wall-clock times (README §2 Clocks).
            return Err(Refusal::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "clock",
                "the edge's clock isn't synchronised yet",
                None,
            ));
        }
        let now = Timestamp::now();
        let text = key.text();
        let addrs = device_addrs(edge, key, src);
        let mine: Vec<StoredAllow> = edge
            .allows
            .list()
            .into_iter()
            .filter(|a| a.device == text && a.expires_at > now)
            .collect();
        let gov = governing(rt, key, &addrs);
        let device_name = rt.clients.log_name(&rt.device(src, edge.neighbours.mac_of(&src)));
        let mut plans: Vec<Plan> = Vec::new();
        let mut touched: Vec<String> = Vec::new();
        let mut counted = 0usize;
        let mut lim_all: Option<Limits> = None;
        // Entries naming the same allow, by its identity: (past, expires_at, subdomains).
        let mut seen: HashMap<String, (bool, i64, Option<bool>)> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            let past = e.expires_at <= now.as_second();
            // The block a `block_id` names in the device's ring.
            let ring_block: Option<Entry> = e.block_id.as_ref().and_then(|bid| self.ring.find_id(key, bid));
            let block_target = ring_block.as_ref().and_then(|b| wire_text(&b.name));
            // Which allow it names: by id, or by target (api.md §6).
            let existing: Option<&StoredAllow> = if let Some(id) = &e.allow_id {
                let found = mine.iter().find(|a| a.allow_id == *id);
                if found.is_none() && !past {
                    return Err(Refusal::new(
                        StatusCode::CONFLICT,
                        "not_found",
                        "no such allow",
                        Some(i),
                    ));
                }
                found
            } else if let Some(bid) = &e.block_id {
                mine.iter().find(|a| {
                    a.kind == AllowKind::Dns
                        && (a.block_id.as_deref() == Some(bid.as_str())
                            || block_target.as_deref().is_some_and(|t| a.target == t))
                })
            } else if let Some(ip) = &e.ip {
                let ip: IpAddr = ip
                    .parse()
                    .map_err(|_| Refusal::new(StatusCode::BAD_REQUEST, "invalid", "bad ip", Some(i)))?;
                let t = ip.to_canonical().to_string();
                mine.iter().find(|a| a.kind == AllowKind::Ip && a.target == t)
            } else {
                return Err(Refusal::new(
                    StatusCode::BAD_REQUEST,
                    "invalid",
                    "an entry needs block_id, ip or allow_id",
                    Some(i),
                ));
            };
            // The same allow named twice counts once when the entries agree, and is refused
            // when they don't (so no limit counts it twice).
            let ident = match (existing, &e.allow_id, &e.block_id, &e.ip) {
                (Some(x), ..) => format!("id:{}", x.allow_id),
                (None, Some(id), ..) => format!("id:{id}"),
                (None, None, Some(bid), _) => match &block_target {
                    Some(t) => format!("dns:{t}"),
                    None => format!("block:{bid}"),
                },
                (None, None, None, Some(ip)) => match ip.parse::<IpAddr>() {
                    Ok(x) => format!("ip:{}", x.to_canonical()),
                    Err(_) => format!("ip:{ip}"),
                },
                (None, None, None, None) => format!("entry:{i}"),
            };
            let sig = (
                past,
                if past { 0 } else { e.expires_at },
                if past { None } else { e.subdomains },
            );
            match seen.get(&ident) {
                Some(prev) if *prev == sig => continue,
                Some(_) => {
                    return Err(Refusal::new(
                        StatusCode::BAD_REQUEST,
                        "invalid",
                        "two entries name the same allow differently",
                        Some(i),
                    ));
                }
                None => {
                    seen.insert(ident, sig);
                }
            }
            if let Some(x) = existing {
                touched.push(x.allow_id.clone());
            }
            if past {
                // A past expiry revokes; revoking is always allowed.
                if let Some(x) = existing {
                    plans.push(Plan::Revoke(Box::new(x.clone())));
                }
                continue;
            }
            let kind_ = existing.map(|x| x.kind).unwrap_or(if e.ip.is_some() {
                AllowKind::Ip
            } else {
                AllowKind::Dns
            });
            // A new DNS allow's block, from the device's ring.
            let block: Option<Entry> = match (existing, &e.block_id) {
                (None, Some(_)) => Some(ring_block.clone().ok_or_else(|| {
                    Refusal::new(
                        StatusCode::CONFLICT,
                        "no_block",
                        "nothing to lift: no such block for this device",
                        Some(i),
                    )
                })?),
                _ => None,
            };
            let gov = gov.as_ref().ok_or_else(|| {
                Refusal::new(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    "no profile admits this device",
                    Some(i),
                )
            })?;
            let mut profs: Vec<&ProfileRt> = gov.iter().map(|p| &**p).collect();
            let block_profile = block
                .as_ref()
                .map(|b| b.profile.to_string())
                .or_else(|| existing.and_then(|x| x.profile.clone()));
            let stored_prof;
            if kind_ == AllowKind::Dns
                && let Some(bp) = &block_profile
            {
                stored_prof = rt.profile(bp).cloned();
                match &stored_prof {
                    Some(p) => {
                        if !profs.iter().any(|x| x.id == p.id) {
                            profs.push(p);
                        }
                    }
                    None => {
                        return Err(Refusal::new(
                            StatusCode::FORBIDDEN,
                            "forbidden",
                            "the block's profile no longer exists",
                            Some(i),
                        ));
                    }
                }
            }
            let lim = limits(&profs, kind_).ok_or_else(|| {
                Refusal::new(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    "bypass is off in a governing profile",
                    Some(i),
                )
            })?;
            lim_all = Some(match lim_all {
                None => lim,
                Some(l) => Limits {
                    max_duration: l.max_duration.min(lim.max_duration),
                    max_active: l.max_active.min(lim.max_active),
                    rate_per_hour: l.rate_per_hour.min(lim.rate_per_hour),
                },
            });
            let max_end = ends_by(now, lim.max_duration);
            let want = Timestamp::from_second(e.expires_at).unwrap_or(max_end);
            let end = want.min(max_end);
            // A DNS allow must outlast its block's cached answer (#50): one that ends sooner
            // would meet the cached block at reload, behind a countdown that says it will work.
            if kind_ == AllowKind::Dns {
                let (bt, ttl) = match (&block, existing) {
                    (Some(b), _) => (Some(b.wall), Some(b.response.ttl)),
                    (None, Some(x)) => (x.block_time, x.block_ttl),
                    (None, None) => (None, None),
                };
                // Browsers may keep the newest block answer for the name, which can be a later
                // block than the one the request names (another bundle head or rule).
                let newest = match (&block, existing) {
                    (Some(b), _) => self.ring.find_name(key, &b.name),
                    (None, Some(x)) => WireName::from_text(&x.target)
                        .ok()
                        .and_then(|w| self.ring.find_name(key, w.wire())),
                    (None, None) => None,
                };
                let earliest = [(bt, ttl), (newest.as_ref().map(|n| n.wall), newest.as_ref().map(|n| n.response.ttl))]
                    .into_iter()
                    .filter_map(|(bt, ttl)| earliest_end(bt, ttl, now).zip(ttl))
                    .max_by_key(|(e, _)| *e);
                if let Some((earliest, ttl)) = earliest
                    && end < earliest
                {
                    return Err(too_short(earliest, max_end, ttl, now, i));
                }
            }
            counted += 1;
            match existing {
                Some(x) => {
                    let mut n = x.clone();
                    n.expires_at = end;
                    if let Some(s) = e.subdomains
                        && n.kind == AllowKind::Dns
                    {
                        n.subdomains = Some(s);
                    }
                    plans.push(Plan::Retime {
                        old: Box::new(x.clone()),
                        new: Box::new(n),
                    });
                }
                None => {
                    let a = match (kind_, &block, &e.ip) {
                        (AllowKind::Dns, Some(b), _) => {
                            let target = wire_text(&b.name).ok_or_else(|| {
                                Refusal::new(
                                    StatusCode::CONFLICT,
                                    "no_block",
                                    "the block's name can't be read",
                                    Some(i),
                                )
                            })?;
                            StoredAllow {
                                allow_id: new_allow_id(),
                                kind: AllowKind::Dns,
                                device: text.clone(),
                                device_name: device_name.clone(),
                                client: src.to_string(),
                                target,
                                subdomains: Some(e.subdomains.unwrap_or(false)),
                                block_id: Some(b.block_id().to_owned()),
                                profile: Some(b.profile.to_string()),
                                block_time: Some(b.wall),
                                block_ttl: Some(b.response.ttl),
                                addresses: vec![],
                                created_at: now,
                                expires_at: end,
                                extra: Default::default(),
                            }
                        }
                        (AllowKind::Ip, _, Some(ip)) => {
                            let ip: IpAddr = ip
                                .parse::<IpAddr>()
                                .map_err(|_| {
                                    Refusal::new(StatusCode::BAD_REQUEST, "invalid", "bad ip", Some(i))
                                })?
                                .to_canonical();
                            if !allowable_ip(ip, &edge.dns.interfaces) {
                                return Err(Refusal::new(
                                    StatusCode::CONFLICT,
                                    "not_blocked",
                                    "not a unicast address of another host",
                                    Some(i),
                                ));
                            }
                            if !edge.fw.ip_blocked(src, ip) {
                                return Err(Refusal::new(
                                    StatusCode::CONFLICT,
                                    "not_blocked",
                                    "nothing to lift: Picket doesn't block this IP for this device",
                                    Some(i),
                                ));
                            }
                            StoredAllow {
                                allow_id: new_allow_id(),
                                kind: AllowKind::Ip,
                                device: text.clone(),
                                device_name: device_name.clone(),
                                client: src.to_string(),
                                target: ip.to_string(),
                                subdomains: None,
                                block_id: None,
                                profile: None,
                                block_time: None,
                                block_ttl: None,
                                addresses: addrs.iter().map(|a| a.to_string()).collect(),
                                created_at: now,
                                expires_at: end,
                                extra: Default::default(),
                            }
                        }
                        _ => {
                            return Err(Refusal::new(
                                StatusCode::BAD_REQUEST,
                                "invalid",
                                "an entry needs block_id or ip",
                                Some(i),
                            ));
                        }
                    };
                    plans.push(Plan::Create(Box::new(a)));
                }
            }
        }
        if put {
            for a in &mine {
                if !touched.contains(&a.allow_id) {
                    plans.push(Plan::Revoke(Box::new(a.clone())));
                }
            }
        }
        // Limits (edge.md §12): every entry a request creates or re-times counts against
        // `rate_per_hour`; the device's active allows after it against `max_active`.
        if let Some(l) = lim_all {
            if self.rate_count(&text) + counted > l.rate_per_hour as usize {
                return Err(Refusal::new(
                    StatusCode::FORBIDDEN,
                    "rate_limited",
                    "rate_per_hour reached",
                    None,
                ));
            }
            let revoked = plans.iter().filter(|p| matches!(p, Plan::Revoke(_))).count();
            let created = plans.iter().filter(|p| matches!(p, Plan::Create(_))).count();
            if (mine.len() + created).saturating_sub(revoked) > l.max_active as usize {
                let idx = entries.len().checked_sub(1);
                return Err(Refusal::new(
                    StatusCode::FORBIDDEN,
                    "max_active",
                    "max_active reached",
                    idx,
                ));
            }
        }
        // The firewall steps that need the helper's ack come first: new and extended IP allows.
        // If one fails (or the write after them does), each is put back as it was: a new one's
        // entries removed, an extended one's back at its previous expiry (all or nothing).
        // Shortenings and revocations can't fail the request and follow the write.
        let mut granted: Vec<(Vec<FwKey>, Option<StoredAllow>)> = Vec::new();
        for p in &plans {
            let (a, prev): (&StoredAllow, Option<&StoredAllow>) = match p {
                Plan::Create(a) => (a, None),
                Plan::Retime { old, new } => (new, Some(old)),
                Plan::Revoke(_) => continue,
            };
            if a.kind != AllowKind::Ip || prev.is_some_and(|o| a.expires_at < o.expires_at) {
                continue;
            }
            let Ok(ip) = a.target.parse::<IpAddr>() else {
                continue;
            };
            let addrs: Vec<IpAddr> = a.addresses.iter().filter_map(|s| s.parse().ok()).collect();
            match edge
                .fw
                .grant_allow(&text, &addrs, ip, secs_until(a.expires_at, now))
                .await
            {
                Ok(keys) => granted.push((keys, prev.cloned())),
                Err(reason) => {
                    undo_grants(edge, &text, &granted, now);
                    let idx = entries.iter().position(|e| {
                        e.ip.as_deref()
                            .and_then(|x| x.parse::<IpAddr>().ok())
                            .map(|x| x.to_canonical().to_string())
                            == Some(a.target.clone())
                            || e.allow_id.as_deref() == Some(a.allow_id.as_str())
                    });
                    return Err(Refusal::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "firewall",
                        format!("the firewall didn't take the allow: {reason}"),
                        idx,
                    ));
                }
            }
        }
        // An address that moved to another device while the grants were awaited isn't listed
        // again (the firewall took it off the stored allow as it moved, and an extension's copy
        // was made before that), and a key just granted to it goes again, so its new owner
        // doesn't get this device's allow (edge-firewall.md §1). As the re-check does.
        if let Some(m) = crate::neighbours::parse_mac(&text) {
            for p in &mut plans {
                if let Plan::Create(a) | Plan::Retime { new: a, .. } = p
                    && a.kind == AllowKind::Ip
                {
                    a.addresses.retain(|x| owned_by_or_unknown(edge, x, &m));
                }
            }
            let listed: std::collections::HashSet<FwKey> = plans
                .iter()
                .filter_map(|p| match p {
                    Plan::Create(a) | Plan::Retime { new: a, .. } => Some(allow_keys(a)),
                    Plan::Revoke(_) => None,
                })
                .flatten()
                .collect();
            for (keys, _) in &mut granted {
                let (kept, moved): (Vec<FwKey>, Vec<FwKey>) =
                    keys.drain(..).partition(|k| listed.contains(k));
                edge.fw.set_allow(&moved, None);
                *keys = kept;
            }
        }
        // One write for every change, then the records.
        let mut upserts: Vec<(StoredAllow, AllowAction)> = Vec::new();
        let mut ends: Vec<StoredAllow> = Vec::new();
        let mut shortened: Vec<StoredAllow> = Vec::new();
        let mut fresh: Vec<String> = Vec::new();
        for p in plans {
            match p {
                Plan::Create(a) => {
                    fresh.push(a.allow_id.clone());
                    upserts.push((*a, AllowAction::Created));
                }
                Plan::Retime { old, new } => {
                    fresh.push(new.allow_id.clone());
                    if new.kind == AllowKind::Ip && new.expires_at < old.expires_at {
                        shortened.push((*new).clone());
                    }
                    upserts.push((*new, AllowAction::Changed));
                }
                Plan::Revoke(a) => ends.push(*a),
            }
        }
        let allows = Arc::clone(&edge.allows);
        let ids: Vec<String> = ends.iter().map(|a| a.allow_id.clone()).collect();
        let via2 = via.to_owned();
        let ups = upserts.clone();
        let r = tokio::task::spawn_blocking(move || allows.commit(&ups, &ids, AllowAction::Revoked, &via2))
            .await
            .map_err(crate::diag::cap)
            .and_then(|r| r.map_err(|e| crate::diag::cap_chain(&e)));
        if let Err(e) = r {
            undo_grants(edge, &text, &granted, now);
            return Err(Refusal::new(StatusCode::SERVICE_UNAVAILABLE, "storage", e, None));
        }
        drop_moved_after_write(edge, upserts.iter_mut().map(|(a, _)| a));
        drop_moved_after_write(edge, shortened.iter_mut());
        for a in &ends {
            if a.kind == AllowKind::Ip {
                edge.fw.set_allow(&allow_keys(a), None);
            }
        }
        // A shortened allow lowers its entries' expiry (edge-firewall.md §3).
        for a in &shortened {
            edge.fw
                .retime_allow(&a.device, &allow_keys(a), secs_until(a.expires_at, now));
        }
        self.rate_add(&text, counted);
        let now = Timestamp::now();
        Ok(edge
            .allows
            .list()
            .iter()
            .filter(|a| a.device == text && a.expires_at > now)
            .map(|a| view(a, fresh.contains(&a.allow_id).then(|| retry_after(a, now))))
            .collect())
    }

    /// Ends allows (core's revoke list, the CLI): each held one ends with an `allow` record
    /// (`action: revoked`), and IP allows' set entries follow at once, keeping any live DNS
    /// grant. Unknown ids are ignored.
    pub async fn revoke(&self, edge: &Edge, ids: &[String], via: &str) -> anyhow::Result<Vec<StoredAllow>> {
        let _g = self.ops.lock().await;
        let allows = Arc::clone(&edge.allows);
        let ids = ids.to_vec();
        let via = via.to_owned();
        let ended =
            tokio::task::spawn_blocking(move || allows.end(&ids, AllowAction::Revoked, &via)).await??;
        for a in &ended {
            if a.kind == AllowKind::Ip {
                edge.fw.set_allow(&allow_keys(a), None);
            }
        }
        Ok(ended)
    }

    /// Checks every active allow against the active config (edge.md §12 "After each config
    /// activation").
    pub async fn recheck_all(&self, edge: &Edge) {
        self.recheck(edge, Scope::All).await;
    }

    /// Checks one device's allows (it gained an address), and expands its IP allows to it.
    pub async fn recheck_device(&self, edge: &Edge, device: &str) {
        self.recheck(edge, Scope::Device(device)).await;
    }

    async fn recheck(&self, edge: &Edge, scope: Scope<'_>) {
        // README §2 Clocks: expiries are wall-clock times. Remembered, so the task that follows
        // the clock runs a full re-check once it syncs.
        if !edge.clock.synced() {
            self.skipped.store(true, Ordering::SeqCst);
            // Synced in between: the clock task may have looked before the flag was set. Both
            // flags are SeqCst ([`Clock::synced`]), so either this load sees the sync or that
            // task's swap sees `skipped`.
            if !edge.clock.synced() {
                return;
            }
        }
        let Some(rt) = edge.active().dns.clone() else {
            return;
        };
        let only = match scope {
            Scope::Device(d) => Some(d),
            Scope::All | Scope::CatchUp => None,
        };
        let expand = scope != Scope::All;
        let _g = self.ops.lock().await;
        let now = Timestamp::now();
        let mut revoke: Vec<StoredAllow> = Vec::new();
        // Changed allows: shortened (logged `changed`, `via: config`) or expanded to the
        // device's new addresses (no record: `allow` records carry no addresses), or both.
        let mut changes: Vec<(StoredAllow, Option<AllowAction>)> = Vec::new();
        // Keys this re-check granted to new addresses (put back if nothing records them).
        let mut granted: Vec<FwKey> = Vec::new();
        for a in edge.allows.list() {
            if only.is_some_and(|d| d != a.device) || a.expires_at <= now {
                continue;
            }
            let (key, mac) = match crate::neighbours::parse_mac(&a.device) {
                Some(m) => (DeviceKey::Mac(m), Some(m)),
                None => match a.device.parse::<IpAddr>() {
                    Ok(ip) => (DeviceKey::Addr(ip), None),
                    Err(_) => (DeviceKey::Client(a.device.as_str().into()), None),
                },
            };
            let src = a.client.parse::<IpAddr>().ok();
            // The device's addresses now (edge.md §12): for a MAC, those it holds in the
            // neighbour table. The address the allow was made from is never added back: once it
            // moved to another device it is that device's (edge-firewall.md §1), and listing it
            // again would hand that device this one's allow.
            let current: Vec<IpAddr> = match mac {
                Some(m) => edge.neighbours.addresses_of(&m),
                None => src.into_iter().collect(),
            };
            // Governing profiles from those; with none known (aged out of the neighbour table),
            // from the addresses the allow still lists, else its source address.
            let listed: Vec<IpAddr> = a.addresses.iter().filter_map(|x| x.parse().ok()).collect();
            let gov_addrs: Vec<IpAddr> = if !current.is_empty() {
                current.clone()
            } else if !listed.is_empty() {
                listed
            } else {
                src.into_iter().collect()
            };
            let gov = governing(&rt, &key, &gov_addrs);
            let mut profs: Vec<Arc<ProfileRt>> = gov.unwrap_or_default();
            let mut ok = !profs.is_empty();
            if a.kind == AllowKind::Dns
                && let Some(p) = &a.profile
            {
                match rt.profile(p) {
                    Some(pr) => {
                        if !profs.iter().any(|x| x.id == pr.id) {
                            profs.push(Arc::clone(pr));
                        }
                    }
                    None => ok = false,
                }
            }
            let refs: Vec<&ProfileRt> = profs.iter().map(|p| &**p).collect();
            match (ok, limits(&refs, a.kind)) {
                (true, Some(l)) => {
                    let mut n = a.clone();
                    let max_end = ends_by(now, l.max_duration);
                    let shortened = a.expires_at > max_end;
                    if shortened {
                        n.expires_at = max_end;
                    }
                    // In a device or catch-up re-check, an IP allow also covers the device's
                    // current addresses, shortened or not (edge.md §12: both apply at once).
                    // Addresses another device holds now stop being listed (the firewall deletes
                    // their entries as the address moves); only the device's current addresses
                    // are added, each once its entries are granted, with the allow's (possibly
                    // shortened) expiry.
                    if a.kind == AllowKind::Ip
                        && expand
                        && let Some(m) = mac
                    {
                        n.addresses.retain(|x| owned_by_or_unknown(edge, x, &m));
                        if let Ok(ip) = n.target.parse::<IpAddr>().map(|i| i.to_canonical()) {
                            let added: Vec<IpAddr> = current
                                .iter()
                                .filter(|x| {
                                    x.is_ipv4() == ip.is_ipv4() && !n.addresses.contains(&x.to_string())
                                })
                                .copied()
                                .collect();
                            let secs = secs_until(n.expires_at, now);
                            if !added.is_empty() {
                                match edge.fw.grant_allow(&n.device, &added, ip, secs).await {
                                    Ok(keys) => {
                                        granted.extend(keys);
                                        n.addresses.extend(added.iter().map(|x| x.to_string()));
                                    }
                                    Err(e) => tracing::debug!(
                                        "allow {}: not expanded to {added:?}: {e}",
                                        n.allow_id
                                    ),
                                }
                            }
                        }
                    }
                    if shortened {
                        changes.push((n, Some(AllowAction::Changed)));
                    } else if n.addresses != a.addresses {
                        changes.push((n, None));
                    }
                }
                _ => revoke.push(a),
            }
        }
        if revoke.is_empty() && changes.is_empty() {
            return;
        }
        // An address that moved while grants were awaited isn't listed again (the firewall took
        // it off the stored allow as it moved), and a key just granted to it goes again, so its
        // new owner doesn't get this device's allow (edge-firewall.md §1).
        for (n, _) in &mut changes {
            if let Some(m) = crate::neighbours::parse_mac(&n.device)
                && n.kind == AllowKind::Ip
            {
                n.addresses.retain(|x| owned_by_or_unknown(edge, x, &m));
            }
        }
        let listed: std::collections::HashSet<FwKey> =
            changes.iter().flat_map(|(n, _)| allow_keys(n)).collect();
        let (granted, moved): (Vec<FwKey>, Vec<FwKey>) =
            granted.into_iter().partition(|k| listed.contains(k));
        edge.fw.set_allow(&moved, None);
        // Every change takes effect whether or not allows.json takes it, address expansions
        // included (their kernel entries exist already): the memory stays authoritative, so a
        // later revocation removes every address it lists, and the write is retried until it
        // lands (edge.md §12).
        let allows = Arc::clone(&edge.allows);
        let ids: Vec<String> = revoke.iter().map(|a| a.allow_id.clone()).collect();
        let ups = changes.clone();
        let r = tokio::task::spawn_blocking(move || {
            allows.commit_held(&ups, &ids, AllowAction::Revoked, "config")
        })
        .await;
        let failed = match r {
            Ok(Ok((_, true))) => None,
            Ok(Ok((_, false))) => {
                edge.allows.spawn_flush();
                None
            }
            Ok(Err(e)) => Some(crate::diag::cap_chain(&e)),
            Err(e) => Some(crate::diag::cap(e)),
        };
        if let Some(e) = failed {
            tracing::warn!("re-checking temporary allows: {e}");
            // Nothing recorded: the new addresses' entries go again.
            edge.fw.set_allow(&granted, None);
            return;
        }
        drop_moved_after_write(edge, changes.iter_mut().map(|(a, _)| a));
        for a in &revoke {
            if a.kind == AllowKind::Ip {
                edge.fw.set_allow(&allow_keys(a), None);
            }
        }
        for (a, action) in &changes {
            if a.kind == AllowKind::Ip && action.is_some() {
                let secs = secs_until(a.expires_at, now);
                edge.fw.retime_allow(&a.device, &allow_keys(a), secs);
            }
        }
    }

    /// The re-checks that follow events (edge.md §12): a device's allows when it gains an
    /// address; a full catch-up when neighbour events were missed (the channel overflowed) and
    /// when the clock syncs after a re-check was skipped.
    pub async fn run_rechecks(self: Arc<Self>, edge: Arc<Edge>) -> anyhow::Result<()> {
        use tokio::sync::broadcast::error::RecvError;
        let mut rx = edge.neighbours.subscribe();
        let mut clock = edge.clock.subscribe();
        // A re-check skipped before this task subscribed.
        let mut catch_up = edge.clock.synced() && self.skipped.swap(false, Ordering::SeqCst);
        let mut clock_open = true;
        loop {
            if catch_up {
                self.recheck(&edge, Scope::CatchUp).await;
            }
            catch_up = tokio::select! {
                r = rx.recv() => match r {
                    Ok(crate::neighbours::NeighbourEvent::Gained { mac, .. }) => {
                        let text = crate::neighbours::format_mac(&mac);
                        if edge.allows.list().iter().any(|a| a.device == text) {
                            self.recheck_device(&edge, &text).await;
                        }
                        false
                    }
                    Ok(_) => false,
                    Err(RecvError::Lagged(n)) => {
                        tracing::warn!("{n} neighbour events missed: re-checking every temporary allow");
                        true
                    }
                    Err(RecvError::Closed) => {
                        rx = edge.neighbours.subscribe();
                        false
                    }
                },
                r = clock.changed(), if clock_open => {
                    clock_open = r.is_ok();
                    clock_open
                        && *clock.borrow_and_update()
                        && self.skipped.swap(false, Ordering::SeqCst)
                }
            };
        }
    }
}

/// Whether the address `x` (text) belongs to the device `m` in the neighbour table, or to no
/// device there (aged out): an IP allow keeps listing it. One another device holds is that
/// device's (edge-firewall.md §1).
fn owned_by_or_unknown(edge: &Edge, x: &str, m: &crate::neighbours::Mac) -> bool {
    x.parse::<IpAddr>()
        .ok()
        .and_then(|ip| edge.neighbours.mac_of(&ip))
        .is_none_or(|o| o == *m)
}

/// Takes an address that moved to another device after the ownership filter ran, but before the
/// write landed, off the IP allows just written (`allows`, updated to match): the firewall's move
/// handling may have looked for allows listing it before the write, and the write put back the
/// copy that still listed it. A move after this check finds the written allows itself
/// (edge-firewall.md §1). The address's keys lose the allow, as in the filter.
fn drop_moved_after_write<'a>(edge: &Edge, allows: impl IntoIterator<Item = &'a mut StoredAllow>) {
    for a in allows {
        let Some(m) = crate::neighbours::parse_mac(&a.device) else {
            continue;
        };
        if a.kind != AllowKind::Ip {
            continue;
        }
        let (kept, moved): (Vec<String>, Vec<String>) = a
            .addresses
            .iter()
            .cloned()
            .partition(|x| owned_by_or_unknown(edge, x, &m));
        if moved.is_empty() {
            continue;
        }
        for x in &moved {
            edge.allows.remove_address_held(std::slice::from_ref(&*a), x);
        }
        let gone = StoredAllow {
            addresses: moved,
            ..a.clone()
        };
        edge.fw.set_allow(&allow_keys(&gone), None);
        a.addresses = kept;
    }
}

/// Puts back the IP allows a failed request granted: a new allow's entries lose its expiry
/// (removed unless a DNS grant keeps them), an extended one's go back to its previous expiry
/// (and keys it newly covered lose the allow). A key on an address that moved to another device
/// (`device` is the request's) loses the allow too, rather than getting the previous expiry back
/// under its new owner (edge-firewall.md §1).
fn undo_grants(edge: &Edge, device: &str, granted: &[(Vec<FwKey>, Option<StoredAllow>)], now: Timestamp) {
    let mac = crate::neighbours::parse_mac(device);
    let still_held = |k: &FwKey| {
        mac.is_none_or(|m| {
            k.src
                .is_none_or(|ip| edge.neighbours.mac_of(&ip).is_none_or(|o| o == m))
        })
    };
    for (keys, prev) in granted {
        match prev {
            None => edge.fw.set_allow(keys, None),
            Some(old) => {
                let had = allow_keys(old);
                let (kept, added): (Vec<FwKey>, Vec<FwKey>) =
                    keys.iter().partition(|k| had.contains(k) && still_held(k));
                edge.fw
                    .retime_allow(device, &kept, secs_until(old.expires_at, now));
                edge.fw.set_allow(&added, None);
            }
        }
    }
}

/// True for an IP an allow may name (edge.md §12): unicast, and not the edge itself. The
/// `PATCH` check and the extension's PTR probe share it, so the probe never reports a firewall
/// block the API would refuse to lift.
pub fn allowable_ip(ip: IpAddr, interfaces: &Interfaces) -> bool {
    let ip = ip.to_canonical();
    unicast(ip) && !interfaces.is_local(ip)
}

/// True for a unicast address (not unspecified, loopback, multicast or broadcast).
fn unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => !(v.is_unspecified() || v.is_loopback() || v.is_multicast() || v.is_broadcast()),
        IpAddr::V6(v) => !(v.is_unspecified() || v.is_loopback() || v.is_multicast()),
    }
}

fn over_budget() -> Refusal {
    Refusal::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "busy",
        "too many request bodies in flight",
        None,
    )
}

/// Reads a body (at most [`MAX_BODY`], within [`BODY_TIMEOUT`]), charging it to `charge` (its
/// source's and the total body budget, as DoH bodies are: the declared size at once, else as it
/// arrives). Returns the body and the charge, which the caller holds until the change is done.
async fn read_body(
    req: Request<Incoming>,
    mut charge: crate::dns::listeners::share::BodyCharge,
) -> Result<(Vec<u8>, crate::dns::listeners::share::BodyCharge), Refusal> {
    let too_large = || Refusal::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "body too large", None);
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|n| n > MAX_BODY as u64) {
        return Err(too_large());
    }
    if let Some(n) = declared
        && !charge.add(usize::try_from(n).unwrap_or(usize::MAX))
    {
        return Err(over_budget());
    }
    let mut body = req.into_body();
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + BODY_TIMEOUT;
    loop {
        let f = match tokio::time::timeout_at(deadline, body.frame()).await {
            Err(_) => {
                return Err(Refusal::new(
                    StatusCode::REQUEST_TIMEOUT,
                    "timeout",
                    "body too slow",
                    None,
                ));
            }
            Ok(None) => break,
            Ok(Some(Err(_))) => {
                return Err(Refusal::new(
                    StatusCode::BAD_REQUEST,
                    "invalid",
                    "body unreadable",
                    None,
                ));
            }
            Ok(Some(Ok(f))) => f,
        };
        let Ok(d) = f.into_data() else { continue };
        let len = out.len().saturating_add(d.len());
        if len > MAX_BODY || declared.is_some_and(|n| len as u64 > n) {
            return Err(too_large());
        }
        if declared.is_none() && !charge.add(d.len()) {
            return Err(over_budget());
        }
        out.extend_from_slice(&d);
    }
    Ok((out, charge))
}

/// Parses a `PUT`/`PATCH` body: a JSON array of entries (fuzzed: the extension is untrusted).
pub fn parse_entries(body: &[u8]) -> Result<Vec<AllowEntry>, Refusal> {
    if body.len() > MAX_BODY {
        return Err(Refusal::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "body too large",
            None,
        ));
    }
    let v: Vec<AllowEntry> = serde_json::from_slice(body).map_err(|e| {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "invalid",
            crate::convergence::json_error(&e),
            None,
        )
    })?;
    if v.len() > MAX_ENTRIES {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "invalid",
            "too many entries",
            None,
        ));
    }
    for (i, e) in v.iter().enumerate() {
        let named = [e.block_id.is_some(), e.ip.is_some(), e.allow_id.is_some()]
            .iter()
            .filter(|x| **x)
            .count();
        let ok_len = e.block_id.as_ref().is_none_or(|s| s.len() <= 64)
            && e.ip.as_ref().is_none_or(|s| s.len() <= 64)
            && e.allow_id.as_ref().is_none_or(|s| s.len() <= 64);
        if named != 1 || !ok_len {
            return Err(Refusal::new(
                StatusCode::BAD_REQUEST,
                "invalid",
                "an entry names exactly one of block_id, ip and allow_id",
                Some(i),
            ));
        }
    }
    Ok(v)
}

/// The data path's recent-blocks hook (edge.md §12).
pub struct RingHook {
    pub bypass: Arc<Bypass>,
    pub fw: Arc<FwClient>,
    /// The edge's own addresses: no IP allow names them, so no PTR probe reports them.
    pub interfaces: Arc<Interfaces>,
    pub allows: Arc<AllowsStore>,
    pub clock: Arc<Clock>,
}

impl RingHook {
    fn allowed(&self, device: &DeviceKey, name: NameRef<'_>) -> bool {
        let idx =
            crate::dns::filter::AllowIndex::build(&self.allows.snapshot(), Some(Arc::clone(&self.clock)));
        crate::dns::filter::TempAllows::find(&idx, device, name).is_some()
    }
}

impl RecentBlocks for RingHook {
    fn extension_probe(
        &self,
        device: &DeviceKey,
        client: IpAddr,
        query: &Query,
        _msg: &[u8],
    ) -> Option<Vec<u8>> {
        let to = query.reply_to(Transport::of_proto(Proto::Doh), u16::MAX);
        let qn = query.qname();
        let mut buf = vec![0u8; 4096];
        let hit = self
            .bypass
            .ring
            .find_name(device, qn.wire())
            .filter(|e| e.at.elapsed() < Duration::from_secs(e.hold_s()))
            .filter(|_| !self.allowed(device, qn.as_name()));
        let r = if let Some(e) = hit {
            // A hit answers as that block did: EDE 15 with its EXTRA-TEXT.
            match &e.source {
                Source::Bundle { bundle, head } => {
                    let short = picket_api::ids::short_id(head);
                    let ede = EdeOption::blocked_by_bundle(bundle, short, e.block_id());
                    reply::write_block(&mut buf, &to, &e.response, ede)
                }
                Source::Lookup { provider, verdict } => {
                    let ede = EdeOption::blocked_by_lookup(provider, verdict, e.block_id());
                    reply::write_block(&mut buf, &to, &e.response, ede)
                }
            }
        } else if query.qtype == rtype::PTR
            && let Some(ip) = reverse_ip(&qn.labels().collect::<Vec<_>>())
            && allowable_ip(ip, &self.interfaces)
            && self.fw.ip_blocked(client, ip)
        {
            // Only an IP a `PATCH` would accept (edge.md §12): the extension then never shows a
            // firewall block page for a loopback, multicast or edge address it can't lift.
            reply::write_rcode(&mut buf, &to, rcode::NXDOMAIN, &[EdeOption::firewall()])
        } else {
            // A miss: NOERROR with no records and no EDE; nothing else happens.
            reply::write_rcode(&mut buf, &to, rcode::NOERROR, &[])
        };
        let r = r.ok()?;
        buf.truncate(r.len);
        Some(buf)
    }

    fn record_block(&self, device: &DeviceKey, note: &BlockNote<'_>) {
        self.bypass.ring.record(device, note);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden (F11: the bypass API's `expires_at` in Unix seconds; plan §5 step 1, unchanged
    /// after the move to jiff).
    #[test]
    fn golden_unix_seconds() {
        use picket_api::time::golden::{ROWS, ts_from_nanos};
        for r in ROWS {
            assert_eq!(unix(ts_from_nanos(r.nanos)), r.unix_s, "{}", r.name);
        }
    }

    #[test]
    fn reverse_names() {
        let l = |s: &str| s.split('.').map(|x| x.as_bytes().to_vec()).collect::<Vec<_>>();
        let r = |s: &str| {
            let v = l(s);
            reverse_ip(&v.iter().map(Vec::as_slice).collect::<Vec<_>>())
        };
        assert_eq!(
            r("100.100.100.100.in-addr.arpa"),
            Some("100.100.100.100".parse().unwrap())
        );
        assert_eq!(r("4.3.2.1.IN-ADDR.ARPA"), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(r("256.3.2.1.in-addr.arpa"), None);
        assert_eq!(r("03.3.2.1.in-addr.arpa"), None);
        assert_eq!(r("3.2.1.in-addr.arpa"), None);
        let nibbles: Vec<String> = format!(
            "{:032x}",
            u128::from("2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap())
        )
        .chars()
        .rev()
        .map(|c| c.to_string())
        .collect();
        let v6 = format!("{}.ip6.arpa", nibbles.join("."));
        assert_eq!(r(&v6), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(r("x.0.ip6.arpa"), None);
    }

    #[test]
    fn the_change_queue_is_bounded_in_total_and_per_device() {
        let b = Bypass::new();
        let mine: Vec<Waiting> = (0..MAX_WAITING_PER_DEVICE)
            .map(|_| b.queue("aa:bb:cc:dd:ee:01").unwrap())
            .collect();
        assert!(b.queue("aa:bb:cc:dd:ee:01").is_none(), "per device");
        let mut others = Vec::new();
        for i in 0..2 * MAX_WAITING {
            match b.queue(&format!("10.0.0.{i}")) {
                Some(w) => others.push(w),
                None => break,
            }
        }
        assert_eq!(mine.len() + others.len(), MAX_WAITING, "in total");
        drop(mine);
        assert!(b.queue("aa:bb:cc:dd:ee:01").is_some(), "places come back");
    }

    #[test]
    fn entries_parse_strictly() {
        assert!(parse_entries(br#"[{"block_id":"abcdefgh","expires_at":1}]"#).is_ok());
        assert!(parse_entries(br#"[{"ip":"1.2.3.4","block_id":"x","expires_at":1}]"#).is_err());
        assert!(parse_entries(br#"[{"expires_at":1}]"#).is_err());
        assert!(parse_entries(b"{").is_err());
        let many = format!(
            "[{}]",
            vec![r#"{"ip":"1.2.3.4","expires_at":1}"#; MAX_ENTRIES + 1].join(",")
        );
        assert!(parse_entries(many.as_bytes()).is_err());
    }

    #[test]
    fn retry_after_waits_out_the_hold() {
        let now = Timestamp::now();
        let mut a = crate::allows::tests::allow("a", AllowKind::Dns, 3600);
        a.block_time = Some(now - jiff::SignedDuration::from_secs(10));
        a.block_ttl = Some(10);
        assert_eq!(retry_after(&a, now), 50, "hold = max(60, ttl + 5)");
        a.block_ttl = Some(300);
        assert_eq!(retry_after(&a, now), 295);
        a.block_time = Some(now - jiff::SignedDuration::from_secs(400));
        assert_eq!(retry_after(&a, now), 0);
        // A block TTL about as long as the allow: the reload comes 5 s before the allow ends.
        a.block_time = Some(now - jiff::SignedDuration::from_secs(1));
        a.block_ttl = Some(898);
        a.expires_at = now + jiff::SignedDuration::from_secs(900);
        assert_eq!(retry_after(&a, now), 895, "bounded by expires_at − 5 s");
        a.expires_at = now + jiff::SignedDuration::from_secs(3);
        assert_eq!(retry_after(&a, now), 0, "too late to wait: reload now");
        let ip = crate::allows::tests::allow("b", AllowKind::Ip, 3600);
        assert_eq!(retry_after(&ip, now), 0);
    }

    /// #50: a DNS allow may end no earlier than its block's hold plus the reload margin; an
    /// older block's remaining hold may already fit a short allow, and one whose hold ended
    /// constrains nothing.
    #[test]
    fn earliest_end_is_the_rest_of_the_hold_plus_the_reload_margin() {
        let now = Timestamp::from_second(Timestamp::now().as_second()).unwrap();
        let ago = |s: i64| Some(now - SignedDuration::from_secs(s));
        let at = |s: i64| Some(now + SignedDuration::from_secs(s));
        // A fresh 600 s block: 605 s hold + 5 s, past a 5 min maximum.
        assert_eq!(earliest_end(ago(0), Some(600), now), at(610));
        assert!(earliest_end(ago(0), Some(600), now) > at(300));
        // The same block 400 s later: 210 s left, so a 5 min allow fits.
        assert_eq!(earliest_end(ago(400), Some(600), now), at(210));
        // Short TTLs hold 60 s.
        assert_eq!(earliest_end(ago(10), Some(10), now), at(55));
        // Hold over: no constraint. No recorded block: none either.
        assert_eq!(earliest_end(ago(605), Some(600), now), None);
        assert_eq!(earliest_end(None, Some(600), now), None);
        assert_eq!(earliest_end(ago(0), None, now), None);
        // The longest TTL the edge serves fits the extension's shortest choice (15 min).
        let ttl = crate::dns::runtime::bounds::BLOCK_TTL_S;
        assert_eq!(earliest_end(ago(0), Some(ttl), now), at(900));
        assert_eq!(
            picket_api::edge_config::min_allow_for_block_s(ttl),
            900,
            "core's profile check agrees"
        );
        assert_eq!(picket_api::edge_config::min_allow_for_block_s(10), 65);
        assert_eq!(
            picket_api::edge_config::min_allow_for_block_s(86_400),
            900,
            "capped"
        );
    }

    /// `expires_at` is whole seconds: the advertised minimum, asked later in the block's own
    /// second, fits, and a refusal's advice is a whole number of seconds that a caller adding it
    /// to the current Unix second can use.
    #[test]
    fn whole_second_expiries_meet_the_minimum_and_the_advice() {
        let block = Timestamp::from_second(1_000).unwrap() + SignedDuration::from_millis(250);
        let now = Timestamp::from_second(1_000).unwrap() + SignedDuration::from_millis(500);
        let ttl = crate::dns::runtime::bounds::BLOCK_TTL_S;
        let min = i64::try_from(picket_api::edge_config::min_allow_for_block_s(ttl)).unwrap();
        let asked = Timestamp::from_second(now.as_second() + min).unwrap();
        let earliest = earliest_end(Some(block), Some(ttl), now).unwrap();
        assert!(asked >= earliest, "{asked} < {earliest}");
        let block = Timestamp::from_second(100).unwrap() + SignedDuration::from_millis(500);
        let now = Timestamp::from_second(100).unwrap() + SignedDuration::from_millis(600);
        let earliest = earliest_end(Some(block), Some(600), now).unwrap();
        assert_eq!(earliest.subsec_nanosecond(), 0);
        let r = too_short(earliest, now + SignedDuration::from_secs(3600), 600, now, 0);
        let need: i64 = r.message.rsplit(' ').nth(1).unwrap().parse().unwrap();
        assert!(Timestamp::from_second(now.as_second() + need).unwrap() >= earliest, "{}", r.message);
    }

    #[test]
    fn a_too_short_refusal_says_what_is_short() {
        let now = Timestamp::now();
        let at = |s: i64| now + SignedDuration::from_secs(s);
        let r = too_short(at(610), at(300), 600, now, 0);
        assert_eq!(
            (r.status, r.code, r.index),
            (StatusCode::FORBIDDEN, "too_short", Some(0))
        );
        assert!(r.message.contains("605 s more"), "{}", r.message);
        assert!(r.message.contains("(300 s)"), "{}", r.message);
        assert!(r.message.contains("ask again in 310 s"), "{}", r.message);
        let r = too_short(at(610), at(3600), 600, now, 1);
        assert!(r.message.ends_with("ask for at least 610 s"), "{}", r.message);
    }

    /// The edge's longest block TTL fits a 15 min allow made right after the block: the hold
    /// ends before the reload deadline, so the reload finds the cached block answer expired.
    #[test]
    fn longest_block_ttl_fits_a_15_min_allow() {
        let ttl = crate::dns::runtime::bounds::BLOCK_TTL_S;
        let hold = i64::try_from(ring::hold_s(ttl)).unwrap();
        assert!(hold + RETRY_BEFORE_EXPIRY_S <= 15 * 60, "hold {hold}");
        let now = Timestamp::now();
        let mut a = crate::allows::tests::allow("a", AllowKind::Dns, 900);
        a.block_time = Some(now);
        a.block_ttl = Some(ttl);
        a.expires_at = now + SignedDuration::from_secs(900);
        assert_eq!(
            retry_after(&a, now),
            ring::hold_s(ttl),
            "not cut short by expires_at"
        );
    }

    /// An allow's end and a block's hold stop at the end of the timestamp range
    /// (9999-12-30T22:00:00.999999999Z), where `+` would panic.
    #[test]
    fn times_saturate_at_the_range_end() {
        let near_end = Timestamp::MAX - SignedDuration::from_secs(10);
        assert_eq!(ends_by(near_end, 3600), Timestamp::MAX);
        let now = Timestamp::now();
        assert_eq!(ends_by(now, 60), now + SignedDuration::from_secs(60));
        let mut a = crate::allows::tests::allow("a", AllowKind::Dns, 3600);
        a.block_time = Some(near_end);
        a.block_ttl = Some(300);
        a.expires_at = Timestamp::MAX;
        // The hold saturates at the range end; the allow's end, 5 s earlier, bounds it.
        assert_eq!(retry_after(&a, near_end), 5);
    }
}
