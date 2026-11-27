//! UDP listeners (edge.md §5): one `SO_REUSEPORT` socket per worker, with `IP_PKTINFO` /
//! `IPV6_RECVPKTINFO` (quinn-udp) so each datagram's arrival interface and destination are known:
//! datagrams from interfaces the listener doesn't list are dropped (edge.md §16 "Not an open
//! resolver"), and replies leave from the address the query was sent to. A wildcard IPv6 bind is
//! dual-stack. The watchdog's test query (a loopback datagram from the edge itself, edge.md §16)
//! is recognised before anything else, let through whatever `interfaces` lists and served as
//! internal, in a lane of its own ([`SELF_TEST_INFLIGHT`]): it never takes a client's in-flight
//! slot and never counts as a client query, so client saturation can't fail the watchdog.

use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

use anyhow::{Context, Result};
use quinn_udp::{RecvMeta, Transmit, UdpSocketState};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::{Semaphore, watch};

use picket_api::logs::Proto;

use super::{Live, SharedSpec};
use crate::dns::pipeline::{self, Inbound};
use crate::edge::Edge;

/// Most queries in flight per UDP socket; past it, datagrams are dropped and counted.
pub const MAX_INFLIGHT: usize = 4096;
/// Most watchdog test queries in flight per UDP socket: the watchdog sends one at a time, so
/// this only bounds datagrams from the test's source; past it they drop uncounted.
pub const SELF_TEST_INFLIGHT: usize = 2;
/// The receive buffer: room for a GRO batch (quinn-udp enables UDP_GRO; 64 KiB at most).
const RECV_BUF: usize = 65_536;
/// Spare query and reply buffers kept per socket (4 KiB each, so at most 2 MiB).
const POOL: usize = 512;
const SOCKET_BUFFER: usize = 1 << 20;

fn socket(addr: SocketAddr) -> std::io::Result<Socket> {
    let s = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        s.set_only_v6(false)?;
    }
    s.set_reuse_address(true)?;
    s.set_reuse_port(true)?;
    let _ = s.set_recv_buffer_size(SOCKET_BUFFER);
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    Ok(s)
}

/// Binds `n` sockets to `addr` (the first one's port when `addr` asks for port 0), returning
/// them and the address they share.
pub fn bind(addr: SocketAddr, n: usize) -> Result<(Vec<std::net::UdpSocket>, SocketAddr)> {
    let first = socket(addr).with_context(|| format!("UDP {addr}"))?;
    let at = first.local_addr()?.as_socket().context("local address")?;
    let mut v = vec![std::net::UdpSocket::from(first)];
    for _ in 1..n {
        v.push(std::net::UdpSocket::from(
            socket(at).with_context(|| format!("UDP {at}"))?,
        ));
    }
    Ok((v, at))
}

/// Starts one socket's receive loop.
pub fn spawn(
    edge: Arc<Edge>,
    sock: std::net::UdpSocket,
    spec: SharedSpec,
    shutdown: watch::Receiver<bool>,
    live: Arc<Live>,
) -> Result<tokio::task::JoinHandle<()>> {
    let sock = Arc::new(UdpSocket::from_std(sock)?);
    let state = Arc::new(UdpSocketState::new((&*sock).into())?);
    Ok(tokio::spawn(recv_loop(edge, sock, state, spec, shutdown, live)))
}

async fn recv_loop(
    edge: Arc<Edge>,
    sock: Arc<UdpSocket>,
    state: Arc<UdpSocketState>,
    spec: SharedSpec,
    mut shutdown: watch::Receiver<bool>,
    live: Arc<Live>,
) {
    let sem = Arc::new(Semaphore::new(edge.dns.tuning.udp_inflight.max(1)));
    let self_test_sem = Arc::new(Semaphore::new(SELF_TEST_INFLIGHT));
    let pool = Arc::new(super::BufPool::new(POOL));
    let mut buf = vec![0u8; RECV_BUF];
    // The watchdog's liveness mark (edge.md §16): the first tick is at once.
    let mut tick = live.interval();
    loop {
        live.park_if_stalled().await;
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tick.tick() => {
                live.stamp();
                continue;
            }
            r = sock.readable() => if r.is_err() { return },
        }
        let mut meta = [RecvMeta::default()];
        let res = sock.try_io(Interest::READABLE, || {
            let mut bufs = [IoSliceMut::new(&mut buf)];
            state.recv((&*sock).into(), &mut bufs, &mut meta)
        });
        let n = match res {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                tracing::debug!("UDP receive: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                continue;
            }
        };
        if n == 0 {
            continue;
        }
        let m = meta[0];
        let len = m.len.min(buf.len());
        let stride = if m.stride == 0 { len } else { m.stride };
        if stride == 0 {
            continue;
        }
        let sp = spec.load_full();
        let internal = edge.dns.listeners.is_self_test(m.addr);
        // edge.md §5, §16: `interfaces` is exact for UDP; other interfaces' datagrams drop.
        if !internal && !sp.interfaces.is_empty() {
            let ok = m
                .interface_index
                .and_then(|i| edge.dns.interfaces.name_of(i))
                .is_some_and(|name| sp.interfaces.iter().any(|x| x.as_str() == &*name));
            if !ok {
                let segs = len.div_ceil(stride) as u64;
                edge.metrics.rejected.fetch_add(segs, Relaxed);
                continue;
            }
        }
        // The test query's own lane (edge.md §16): never a client's slot, never `rejected`.
        let lane = if internal { &self_test_sem } else { &sem };
        for seg in buf[..len].chunks(stride) {
            let Ok(permit) = Arc::clone(lane).try_acquire_owned() else {
                if !internal {
                    edge.metrics.rejected.fetch_add(1, Relaxed);
                }
                continue;
            };
            let mut data = pool.take();
            data.extend_from_slice(seg);
            let edge = Arc::clone(&edge);
            let sock = Arc::clone(&sock);
            let state = Arc::clone(&state);
            let sp = Arc::clone(&sp);
            let pool = Arc::clone(&pool);
            tokio::spawn(async move {
                let _permit = permit;
                let out = pipeline::serve_with(
                    &edge,
                    Inbound {
                        msg: &data,
                        client: m.addr,
                        listener: &sp.id,
                        udp_payload: sp.limits.udp_payload,
                        proto: Proto::Udp,
                        named_profile: None,
                        extension: false,
                        internal,
                        admitted: Default::default(),
                    },
                    pool.take(),
                )
                .await;
                pool.put(data);
                if let Some(reply) = out.reply {
                    let t = Transmit {
                        destination: m.addr,
                        ecn: None,
                        contents: &reply,
                        segment_size: None,
                        src_ip: m.dst_ip,
                    };
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        sock.async_io(Interest::WRITABLE, || state.try_send((&*sock).into(), &t)),
                    )
                    .await;
                    pool.put(reply);
                }
            });
        }
    }
}
