//! TLS handshakes on the DoT and DoH listeners, the bypass API's included (edge.md §5; api.md:
//! every interface speaks TLS 1.3).
//!
//! - **TLS 1.3 only** ([`crate::dns::certs::CertSlot::server_config`]): a client whose
//!   ClientHello offers no TLS 1.3 (no `supported_versions` extension listing 0x0304) is refused
//!   with a `protocol_version` alert.
//! - **Refusals are reported** as `tls_version_refused` events (api.md §5), so the admin sees
//!   which device can't connect. [`accept`] reads the ClientHello first (rustls's `Acceptor`,
//!   through `LazyConfigAcceptor`) for its SNI, then continues the handshake with the listener's
//!   config; both halves share one deadline. rustls decides every refusal: a version refusal
//!   ([`offered_without_tls13`]), or a hello without `signature_algorithms`, which rustls refuses
//!   before it looks at versions and which every TLS 1.0 and 1.1 client sends (RFC 5246
//!   §7.4.1.4.1); that one is reported only when the hello offers no TLS 1.3. What the hello
//!   offered comes from its bytes ([`super::client_hello`]): the handshake keeps the first
//!   [`MAX_HELLO_BYTES`] it reads ([`Recorder`]) until it ends.
//! - **Rate limit** (README §2 Bounded): at most one event per listener and device (a device as
//!   the pipeline keys it, edge.md §5: its MAC, the client of a routed address, else the address)
//!   every [`REFUSAL_EVERY`]. Refusals in between are counted (`refused` in the next event); a
//!   sweep every [`SWEEP_EVERY`] reports the count of a device that stopped trying once its hour
//!   is over, and forgets devices with nothing to report. At most [`MAX_REFUSERS`] (listener,
//!   device) pairs are tracked, of which the addresses of one IPv6 /64 without a MAC or client
//!   hold at most [`MAX_PER_PREFIX`]; a refusal that finds no room is counted, and the next event
//!   carries the count (`unlogged`). So refusals cost at most about 2 × [`MAX_REFUSERS`] records
//!   an hour, whatever clients send.
//! - **Restarts:** a clean stop logs every pending count first ([`TlsRefusals::drain`], before
//!   the log buffer goes to the spool). A crash loses the counts not yet in an event (at most an
//!   hour's per pair) and the `unlogged` count; after any restart the table starts empty, so a
//!   device still being refused gets its next event at once.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use picket_api::logs::{event_kind, tls_offered};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::LazyConfigAcceptor;
use tokio_rustls::server::TlsStream;

use super::client_hello;
use crate::dns::profiles::DeviceKey;
use crate::edge::Edge;
use crate::logs::fields;

/// At most one `tls_version_refused` event per listener and device this often.
pub const REFUSAL_EVERY: Duration = Duration::from_secs(3600);
/// How often pending counts whose hour is over are reported.
pub const SWEEP_EVERY: Duration = Duration::from_secs(60);
/// (listener, device) pairs tracked for the rate limit.
pub const MAX_REFUSERS: usize = 1024;
/// Pairs the addresses of one IPv6 /64 hold when they have no MAC and no client (each is a
/// device of its own, edge.md §5): one host rotating addresses there can't fill the table.
pub const MAX_PER_PREFIX: usize = 16;
/// Bytes of a handshake kept to describe a refused ClientHello. Hellos without
/// `signature_algorithms` come from old TLS stacks and take a few hundred bytes; a modern one
/// that doesn't fit is described from rustls's refusal alone.
pub const MAX_HELLO_BYTES: usize = 4096;

/// A TLS listener's transport, as `tls_version_refused` names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Dot,
    Doh,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Dot => "dot",
            Transport::Doh => "doh",
        }
    }
}

/// What a ClientHello that offers no TLS 1.3 offered instead (one of
/// [`picket_api::logs::tls_offered`]), read from rustls's version refusal of it; `None` for any
/// other handshake failure. rustls checks the versions before it resolves a certificate, so a
/// listener still waiting for its certificate reports these refusals too. The hello's bytes say
/// more where they were kept ([`HelloOffer::offered`](client_hello::HelloOffer::offered)).
pub fn offered_without_tls13(e: &io::Error) -> Option<&'static str> {
    use rustls::PeerIncompatible as P;
    match rustls_error(e)? {
        // No supported_versions and a legacy version of TLS 1.2.
        rustls::Error::PeerIncompatible(P::SupportedVersionsExtensionRequired) => Some(tls_offered::TLS12),
        // No supported_versions and a legacy version below TLS 1.2.
        rustls::Error::PeerIncompatible(P::Tls12NotOffered) => Some(tls_offered::TLS11_OR_OLDER),
        // supported_versions without TLS 1.3 (rustls doesn't say what else it listed).
        rustls::Error::PeerIncompatible(P::Tls12NotOfferedOrEnabled) => Some(tls_offered::NO_TLS13),
        _ => None,
    }
}

/// True when rustls refused a hello for lacking `signature_algorithms`, which it checks before
/// versions.
pub fn missing_signature_algorithms(e: &io::Error) -> bool {
    matches!(
        rustls_error(e),
        Some(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::SignatureAlgorithmsExtensionRequired
        ))
    )
}

fn rustls_error(e: &io::Error) -> Option<&rustls::Error> {
    e.get_ref()?.downcast_ref::<rustls::Error>()
}

/// A listener connection's transport that keeps the first [`MAX_HELLO_BYTES`] the handshake
/// reads, so a refused ClientHello can be described; [`accept`] stops it once the ClientHello is
/// in and drops the copy once the handshake succeeded.
pub struct Recorder<IO> {
    io: IO,
    seen: Vec<u8>,
    on: bool,
}

impl<IO> Recorder<IO> {
    fn new(io: IO) -> Self {
        Self {
            io,
            seen: Vec::new(),
            on: true,
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Recorder<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.io).poll_read(cx, buf);
        if self.on && matches!(r, Poll::Ready(Ok(()))) {
            let room = MAX_HELLO_BYTES.saturating_sub(self.seen.len());
            let new = &buf.filled()[before..];
            let take = new.len().min(room);
            self.seen.extend_from_slice(&new[..take]);
        }
        r
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Recorder<IO> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}

/// The TLS side of one accepted connection on `listener`: the handshake under `config` within
/// `within` (the ClientHello and the rest share the deadline). `None` when it failed or timed
/// out; a client refused for offering no TLS 1.3 is reported (module docs).
pub async fn accept<IO>(
    edge: &Edge,
    config: &Arc<rustls::ServerConfig>,
    io: IO,
    peer: SocketAddr,
    listener: &Arc<str>,
    transport: Transport,
    within: Duration,
) -> Option<TlsStream<Recorder<IO>>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let deadline = tokio::time::Instant::now() + within;
    let mut hello = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), Recorder::new(io));
    let mut start = match tokio::time::timeout_at(deadline, &mut hello).await {
        Ok(Ok(start)) => start,
        Ok(Err(e)) => {
            // Refused at the ClientHello: report it when rustls refused it for lacking
            // signature_algorithms and it offers no TLS 1.3 (an old client).
            if missing_signature_algorithms(&e)
                && let Some(rec) = hello.take_io()
                && let Some(h) = client_hello::read(&rec.seen)
                && let Some(offered) = h.offered()
            {
                let r = Refusal {
                    transport,
                    client: peer.ip(),
                    sni: h.sni,
                    offered,
                };
                edge.dns.listeners.tls_refusals.report(edge, listener, r);
            }
            return None;
        }
        Err(_) => return None,
    };
    start.io.on = false; // the whole ClientHello is in
    let sni = start
        .client_hello()
        .server_name()
        .and_then(client_hello::sni_text);
    let handshake = start.into_stream(Arc::clone(config)).into_fallible();
    match tokio::time::timeout_at(deadline, handshake).await {
        Ok(Ok(mut tls)) => {
            tls.get_mut().0.seen = Vec::new();
            Some(tls)
        }
        Ok(Err((e, rec))) => {
            if let Some(refused) = offered_without_tls13(&e) {
                // The hello's bytes say what it offered; rustls's refusal when they can't.
                let offered = client_hello::read(&rec.seen)
                    .and_then(|h| h.offered())
                    .unwrap_or(refused);
                let r = Refusal {
                    transport,
                    client: peer.ip(),
                    sni,
                    offered,
                };
                edge.dns.listeners.tls_refusals.report(edge, listener, r);
            }
            None
        }
        Err(_) => None,
    }
}

/// One refused handshake, as its event reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub transport: Transport,
    pub client: IpAddr,
    pub sni: Option<String>,
    pub offered: &'static str,
}

/// An event to log: the latest refusal of a (listener, device) pair, standing for `refused`
/// refusals, and carrying `unlogged` refusals no pair could take since the previous event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Due {
    pub listener: Arc<str>,
    pub refusal: Refusal,
    pub refused: u64,
    pub unlogged: u64,
}

/// One tracked (listener, device) pair.
struct Entry {
    /// When its last event was logged.
    logged: Instant,
    /// Refusals since then, not yet in an event.
    pending: u64,
    /// The latest of them, for the event that reports them.
    last: Refusal,
}

#[derive(Default)]
struct Table {
    seen: HashMap<(Arc<str>, DeviceKey), Entry>,
    /// Refusals no pair could take, not yet in an event.
    unlogged: u64,
}

impl Table {
    fn due(&mut self, listener: &Arc<str>, refusal: Refusal, refused: u64) -> Due {
        Due {
            listener: Arc::clone(listener),
            refusal,
            refused,
            unlogged: std::mem::take(&mut self.unlogged),
        }
    }

    /// Reports the pending counts of pairs whose hour is over (each starts a new hour) and
    /// forgets those with nothing pending.
    fn sweep(&mut self, now: Instant, out: &mut Vec<Due>) {
        let unlogged = &mut self.unlogged;
        self.seen.retain(|(listener, _), e| {
            if now.saturating_duration_since(e.logged) < REFUSAL_EVERY {
                return true;
            }
            if e.pending == 0 {
                return false;
            }
            out.push(Due {
                listener: Arc::clone(listener),
                refusal: e.last.clone(),
                refused: std::mem::take(&mut e.pending),
                unlogged: std::mem::take(unlogged),
            });
            e.logged = now;
            true
        });
    }

    /// True when `device` is an address without MAC or client in an IPv6 /64 whose addresses
    /// hold [`MAX_PER_PREFIX`] pairs already.
    fn prefix_full(&self, device: &DeviceKey) -> bool {
        let DeviceKey::Addr(IpAddr::V6(a)) = device else {
            return false;
        };
        let mine = &a.segments()[..4];
        self.seen
            .keys()
            .filter(|(_, d)| matches!(d, DeviceKey::Addr(IpAddr::V6(b)) if b.segments()[..4] == *mine))
            .count()
            >= MAX_PER_PREFIX
    }
}

/// The rate limit of `tls_version_refused` events (module docs).
#[derive(Default)]
pub struct TlsRefusals {
    table: Mutex<Table>,
}

impl TlsRefusals {
    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Notes one refusal of `device` on `listener` at `now`; returns the events due.
    pub fn note(&self, listener: &Arc<str>, device: DeviceKey, r: Refusal, now: Instant) -> Vec<Due> {
        let mut t = self.table();
        let mut out = Vec::new();
        let key = (Arc::clone(listener), device);
        if let Some(e) = t.seen.get_mut(&key) {
            if now.saturating_duration_since(e.logged) < REFUSAL_EVERY {
                e.pending = e.pending.saturating_add(1);
                e.last = r;
                return out;
            }
            let refused = std::mem::take(&mut e.pending).saturating_add(1);
            e.logged = now;
            e.last = r.clone();
            out.push(t.due(listener, r, refused));
            return out;
        }
        if t.seen.len() >= MAX_REFUSERS {
            t.sweep(now, &mut out);
        }
        if t.seen.len() >= MAX_REFUSERS || t.prefix_full(&key.1) {
            t.unlogged = t.unlogged.saturating_add(1);
            return out;
        }
        t.seen.insert(
            key,
            Entry {
                logged: now,
                pending: 0,
                last: r.clone(),
            },
        );
        out.push(t.due(listener, r, 1));
        out
    }

    /// The pending counts of pairs whose hour is over at `now` (module docs).
    pub fn sweep(&self, now: Instant) -> Vec<Due> {
        let mut out = Vec::new();
        self.table().sweep(now, &mut out);
        out
    }

    /// Every pending count, whatever its hour (a clean stop).
    pub fn drain(&self) -> Vec<Due> {
        let mut t = self.table();
        let mut out = Vec::new();
        let mut unlogged = std::mem::take(&mut t.unlogged);
        for ((listener, _), e) in t.seen.iter_mut().filter(|(_, e)| e.pending > 0) {
            out.push(Due {
                listener: Arc::clone(listener),
                refusal: e.last.clone(),
                refused: std::mem::take(&mut e.pending),
                unlogged: std::mem::take(&mut unlogged),
            });
        }
        t.unlogged = unlogged;
        out
    }

    /// Notes a refusal of the device behind its client address and logs the events due.
    pub fn report(&self, edge: &Edge, listener: &Arc<str>, r: Refusal) {
        let device = super::share::source_key(edge, r.client);
        log(edge, self.note(listener, device, r, Instant::now()));
    }

    /// [`Self::sweep`] now, logging what it found.
    pub fn sweep_and_log(&self, edge: &Edge) {
        log(edge, self.sweep(Instant::now()));
    }

    /// [`Self::drain`], logging what it found.
    pub fn drain_and_log(&self, edge: &Edge) {
        log(edge, self.drain());
    }
}

/// Logs each due event: the listener, transport, client address, device (its name from
/// `clients`, else its MAC, else null, as on `q` records) and MAC as the edge knows them now,
/// the SNI when the client sent one, what it offered, and the counts.
fn log(edge: &Edge, dues: Vec<Due>) {
    if dues.is_empty() {
        return;
    }
    let active = edge.active();
    for d in dues {
        let ip = d.refusal.client.to_canonical();
        let mac = edge.neighbours.mac_of(&ip);
        let device = active
            .dns
            .as_ref()
            .and_then(|rt| rt.clients.log_name(&rt.device(ip, mac)));
        let mut f = fields(&[
            ("listener", d.listener.to_string().into()),
            ("transport", d.refusal.transport.as_str().into()),
            ("client", picket_wire::log::ip_text(ip).into()),
            ("device", device.into()),
            ("offered", d.refusal.offered.into()),
            ("refused", d.refused.into()),
        ]);
        if let Some(m) = mac {
            f.insert("mac".into(), crate::neighbours::format_mac(&m).into());
        }
        if let Some(s) = d.refusal.sni {
            f.insert("sni".into(), s.into());
        }
        if d.unlogged > 0 {
            f.insert("unlogged".into(), d.unlogged.into());
        }
        edge.logs.event(event_kind::TLS_VERSION_REFUSED, f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn refusal(client: &str) -> Refusal {
        Refusal {
            transport: Transport::Dot,
            client: ip(client),
            sni: None,
            offered: tls_offered::TLS12,
        }
    }

    fn addr(s: &str) -> DeviceKey {
        DeviceKey::Addr(ip(s))
    }

    /// The (refused, unlogged) counts of `dues`.
    fn counts(dues: &[Due]) -> Vec<(u64, u64)> {
        dues.iter().map(|d| (d.refused, d.unlogged)).collect()
    }

    #[test]
    fn one_event_per_listener_and_device_an_hour_counting_the_refusals_between() {
        let r = TlsRefusals::default();
        let (dot, doh): (Arc<str>, Arc<str>) = ("lan-dot".into(), "lan-doh".into());
        let t0 = Instant::now();
        let tablet = DeviceKey::Mac([2, 0, 0, 0, 0, 9]);
        let at = |s| t0 + Duration::from_secs(s);
        assert_eq!(
            counts(&r.note(&dot, tablet.clone(), refusal("192.168.1.9"), t0)),
            [(1, 0)]
        );
        // The same device from another address (an IPv6 privacy address) is the same pair.
        assert!(r.note(&dot, tablet.clone(), refusal("fd00::9"), at(5)).is_empty());
        assert!(
            r.note(&dot, tablet.clone(), refusal("192.168.1.9"), at(6))
                .is_empty()
        );
        // Another listener or another device has its own hour.
        assert_eq!(
            counts(&r.note(&doh, tablet.clone(), refusal("192.168.1.9"), t0)),
            [(1, 0)]
        );
        assert_eq!(
            counts(&r.note(&dot, addr("192.168.1.10"), refusal("192.168.1.10"), t0)),
            [(1, 0)]
        );
        // After the hour: one event for the two counted and this one, naming the latest address.
        let late = r.note(&dot, tablet.clone(), refusal("fd00::9"), t0 + REFUSAL_EVERY);
        assert_eq!(counts(&late), [(3, 0)]);
        assert_eq!(late[0].refusal.client, ip("fd00::9"));
        assert!(
            r.note(
                &dot,
                tablet,
                refusal("fd00::9"),
                t0 + REFUSAL_EVERY + Duration::from_secs(1)
            )
            .is_empty()
        );
    }

    #[test]
    fn the_sweep_reports_a_device_that_stopped_and_forgets_idle_ones() {
        let r = TlsRefusals::default();
        let l: Arc<str> = "lan-dot".into();
        let t0 = Instant::now();
        let dev = addr("192.168.1.9");
        assert_eq!(r.note(&l, dev.clone(), refusal("192.168.1.9"), t0).len(), 1);
        for s in 1..=49 {
            assert!(
                r.note(
                    &l,
                    dev.clone(),
                    refusal("192.168.1.9"),
                    t0 + Duration::from_secs(s)
                )
                .is_empty()
            );
        }
        assert!(
            r.sweep(t0 + Duration::from_secs(1800)).is_empty(),
            "inside its hour"
        );
        let swept = r.sweep(t0 + REFUSAL_EVERY);
        assert_eq!(counts(&swept), [(49, 0)], "the 49 retries after the first event");
        // Its new hour passes with nothing pending: forgotten.
        assert!(r.sweep(t0 + 2 * REFUSAL_EVERY).is_empty());
        assert!(r.table().seen.is_empty());
    }

    #[test]
    fn a_full_table_loses_no_count() {
        // Every refusal ends up in an event's `refused` or `unlogged`, or is still held.
        let r = TlsRefusals::default();
        let l: Arc<str> = "lan-dot".into();
        let t0 = Instant::now();
        let mut dues = Vec::new();
        let mut noted = 0u64;
        let mut note = |dev: DeviceKey, at: Instant, dues: &mut Vec<Due>| {
            noted += 1;
            dues.extend(r.note(&l, dev, refusal("10.0.0.1"), at));
        };
        for i in 0..MAX_REFUSERS {
            let dev = DeviceKey::Addr(IpAddr::from([10, 0, (i >> 8) as u8, i as u8]));
            note(dev.clone(), t0, &mut dues);
            note(dev, t0, &mut dues); // one pending each
        }
        note(addr("10.9.9.9"), t0, &mut dues); // no room: unlogged
        note(addr("10.9.9.8"), t0, &mut dues);
        assert_eq!(dues.len(), MAX_REFUSERS);
        // An hour on, a new device: the sweep reports every pending count first, carrying the two
        // unlogged; the table stays full (each reported pair starts a new hour), so it waits.
        note(addr("10.9.9.7"), t0 + REFUSAL_EVERY, &mut dues);
        assert_eq!(dues.len(), 2 * MAX_REFUSERS);
        assert_eq!(dues[MAX_REFUSERS].unlogged, 2);
        // Another hour with nothing pending frees the table.
        note(addr("10.9.9.6"), t0 + 2 * REFUSAL_EVERY, &mut dues);
        assert_eq!(counts(&dues[2 * MAX_REFUSERS..]), [(1, 1)]);
        let drained: u64 = r.drain().iter().map(|d| d.refused + d.unlogged).sum();
        let held = drained + r.table().unlogged;
        let reported: u64 = dues.iter().map(|d| d.refused + d.unlogged).sum();
        assert_eq!(reported + held, noted);
        assert!(r.table().seen.len() <= MAX_REFUSERS);
    }

    #[test]
    fn one_ipv6_prefix_takes_a_capped_share() {
        let r = TlsRefusals::default();
        let l: Arc<str> = "lan-dot".into();
        let t0 = Instant::now();
        let mut logged = 0;
        for i in 0..100u16 {
            let a = std::net::Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, i >> 8, i & 0xff);
            logged += r
                .note(&l, DeviceKey::Addr(IpAddr::V6(a)), refusal("2001:db8:1:2::1"), t0)
                .len();
        }
        assert_eq!(logged, MAX_PER_PREFIX);
        assert_eq!(r.table().unlogged, 100 - MAX_PER_PREFIX as u64);
        // Other devices still get their events, the first carrying the count.
        let other = r.note(&l, DeviceKey::Mac([2, 0, 0, 0, 0, 1]), refusal("192.168.1.5"), t0);
        assert_eq!(counts(&other), [(1, 100 - MAX_PER_PREFIX as u64)]);
        let next_prefix = std::net::Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1);
        assert_eq!(
            r.note(
                &l,
                DeviceKey::Addr(IpAddr::V6(next_prefix)),
                refusal("2001:db8:1:3::1"),
                t0
            )
            .len(),
            1
        );
    }

    #[test]
    fn a_clean_stop_drains_every_pending_count() {
        let r = TlsRefusals::default();
        let l: Arc<str> = "lan-dot".into();
        let t0 = Instant::now();
        r.note(&l, addr("192.168.1.9"), refusal("192.168.1.9"), t0);
        r.note(&l, addr("192.168.1.9"), refusal("192.168.1.9"), t0);
        r.note(&l, addr("192.168.1.8"), refusal("192.168.1.8"), t0);
        assert_eq!(counts(&r.drain()), [(1, 0)]);
        assert!(r.drain().is_empty());
    }

    #[test]
    fn only_version_refusals_are_classified() {
        use rustls::PeerIncompatible as P;
        let wrap = |e: rustls::Error| io::Error::new(io::ErrorKind::InvalidData, e);
        assert_eq!(
            offered_without_tls13(&wrap(P::SupportedVersionsExtensionRequired.into())),
            Some(tls_offered::TLS12)
        );
        assert_eq!(
            offered_without_tls13(&wrap(P::Tls12NotOffered.into())),
            Some(tls_offered::TLS11_OR_OLDER)
        );
        assert_eq!(
            offered_without_tls13(&wrap(P::Tls12NotOfferedOrEnabled.into())),
            Some(tls_offered::NO_TLS13)
        );
        assert_eq!(
            offered_without_tls13(&wrap(P::NoCipherSuitesInCommon.into())),
            None
        );
        assert_eq!(
            offered_without_tls13(&io::Error::from(io::ErrorKind::UnexpectedEof)),
            None
        );
        assert!(missing_signature_algorithms(&wrap(
            P::SignatureAlgorithmsExtensionRequired.into()
        )));
        assert!(!missing_signature_algorithms(&wrap(
            P::NoCipherSuitesInCommon.into()
        )));
    }
}
