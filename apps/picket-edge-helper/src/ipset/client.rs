//! A minimal blocking ipset client on a `NETLINK_NETFILTER` socket (netlink-sys), speaking the
//! messages in [`super::proto`]. Each instance owns one socket; the helper keeps one for the fast
//! path (`ensure`/`delete` and the watchdog probe) and one for everything else, so an `ensure`
//! never queues behind a dump (edge-firewall.md §4).

use std::collections::HashMap;
use std::io;
use std::time::Duration;

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use rustix::net::sockopt::{Timeout, set_socket_timeout};

use super::IpsetError;
use super::proto::{self, CreateSpec, Elem, Member, Reply, Request, SetFamily, SetHeader, SetType};

/// `MSG_TRUNC` (linux/socket.h): `recv` returns the datagram's real length, so a truncated read
/// is detected instead of silently losing messages.
const MSG_TRUNC: i32 = 0x20;
/// Receive buffer per datagram. The kernel's netlink dump skbs are at most 32 KiB (or one
/// page with large pages); 256 KiB leaves headroom.
const RECV_BUF: usize = 256 * 1024;
/// Per-`recv` timeout: a stalled kernel reply fails the call instead of hanging the worker.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Requests per datagram for batched adds and deletes.
const BATCH: usize = 64;

pub struct NetlinkIpset {
    sock: Socket,
    seq: u32,
    protocol: u8,
    buf: Vec<u8>,
    revisions: HashMap<(SetType, SetFamily), u8>,
}

fn io_err(e: io::Error) -> IpsetError {
    if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) {
        IpsetError::Timeout
    } else {
        IpsetError::Io(e.to_string())
    }
}

impl NetlinkIpset {
    /// Opens a socket and negotiates the protocol version (`IPSET_CMD_PROTOCOL`), as libipset
    /// does: the lower of ours and the kernel's, refused below `IPSET_PROTOCOL_MIN`.
    pub fn open() -> Result<Self, IpsetError> {
        let mut sock = Socket::new(NETLINK_NETFILTER).map_err(io_err)?;
        sock.bind_auto().map_err(io_err)?;
        sock.connect(&SocketAddr::new(0, 0)).map_err(io_err)?;
        set_socket_timeout(&sock, Timeout::Recv, Some(IO_TIMEOUT)).map_err(|e| io_err(e.into()))?;
        set_socket_timeout(&sock, Timeout::Send, Some(IO_TIMEOUT)).map_err(|e| io_err(e.into()))?;
        // Larger receive buffer for dumps; failure only costs throughput.
        let _ = sock.set_rx_buf_sz(1 << 20);
        // Error acks without the echoed request payload.
        let _ = sock.set_cap_ack(true);
        let mut me = Self {
            sock,
            seq: 0,
            protocol: proto::IPSET_PROTOCOL,
            buf: Vec::with_capacity(RECV_BUF),
            revisions: HashMap::new(),
        };
        let attrs = me.query(&proto::req_protocol())?;
        let (kernel, kernel_min) = proto::decode_protocol(&attrs)?;
        let p = kernel.min(proto::IPSET_PROTOCOL);
        if p < proto::IPSET_PROTOCOL_MIN || kernel_min.is_some_and(|m| m > proto::IPSET_PROTOCOL) {
            return Err(IpsetError::Protocol(kernel));
        }
        me.protocol = p;
        Ok(me)
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            self.seq = 1;
        }
        self.seq
    }

    fn send(&self, bytes: &[u8]) -> Result<(), IpsetError> {
        let n = self.sock.send(bytes, 0).map_err(io_err)?;
        if n != bytes.len() {
            return Err(IpsetError::Io("short netlink send".into()));
        }
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<Reply>, IpsetError> {
        self.buf.clear();
        self.buf.reserve(RECV_BUF);
        let n = self.sock.recv(&mut self.buf, MSG_TRUNC).map_err(io_err)?;
        if n > self.buf.len() {
            return Err(IpsetError::Io(format!("netlink datagram of {n} bytes truncated")));
        }
        Ok(proto::decode_datagram(&self.buf)?)
    }

    /// A request answered by one ipset message (`PROTOCOL`, `TYPE`).
    fn query(&mut self, req: &Request) -> Result<Vec<u8>, IpsetError> {
        let seq = self.next_seq();
        self.send(&req.encode(seq))?;
        loop {
            for r in self.recv()? {
                if r.seq() != seq {
                    continue; // a late reply to an earlier, timed-out request
                }
                match r {
                    Reply::Ipset { attrs, .. } => return Ok(attrs),
                    Reply::Error { errno, .. } => return Err(IpsetError::Kernel(errno)),
                    Reply::Ack { .. } | Reply::Done { .. } | Reply::Other { .. } => {}
                }
            }
        }
    }

    /// Requests answered by an ack each, batched into datagrams of up to [`BATCH`].
    fn acked(&mut self, reqs: &[Request]) -> Vec<Result<(), IpsetError>> {
        let mut out = Vec::with_capacity(reqs.len());
        for chunk in reqs.chunks(BATCH) {
            let first = self.seq.wrapping_add(1);
            let mut dgram = Vec::with_capacity(chunk.len() * 96);
            let mut seqs = Vec::with_capacity(chunk.len());
            for r in chunk {
                let s = self.next_seq();
                seqs.push(s);
                dgram.extend_from_slice(&r.encode(s));
            }
            let mut results: Vec<Option<Result<(), IpsetError>>> = vec![None; chunk.len()];
            let mut pending = chunk.len();
            if let Err(e) = self.send(&dgram) {
                out.extend(std::iter::repeat_n(Err(e), chunk.len()));
                continue;
            }
            while pending > 0 {
                match self.recv() {
                    Ok(replies) => {
                        for r in replies {
                            let idx = r.seq().wrapping_sub(first) as usize;
                            if idx >= chunk.len() || seqs[idx] != r.seq() || results[idx].is_some() {
                                continue;
                            }
                            let res = match r {
                                Reply::Ack { .. } => Ok(()),
                                Reply::Error { errno, .. } => Err(IpsetError::Kernel(errno)),
                                _ => continue,
                            };
                            results[idx] = Some(res);
                            pending -= 1;
                        }
                    }
                    Err(e) => {
                        for r in results.iter_mut().filter(|r| r.is_none()) {
                            *r = Some(Err(e.clone()));
                        }
                        pending = 0;
                    }
                }
            }
            out.extend(results.into_iter().map(|r| r.unwrap_or(Err(IpsetError::Timeout))));
        }
        out
    }

    /// A dump; `on_msg` gets each ipset message's attributes.
    fn dump(
        &mut self,
        req: &Request,
        on_msg: &mut dyn FnMut(&[u8]) -> Result<(), IpsetError>,
    ) -> Result<(), IpsetError> {
        let seq = self.next_seq();
        self.send(&req.encode(seq))?;
        loop {
            for r in self.recv()? {
                if r.seq() != seq {
                    continue;
                }
                match r {
                    Reply::Ipset { attrs, .. } => on_msg(&attrs)?,
                    Reply::Done { errno: 0, .. } => return Ok(()),
                    Reply::Done { errno, .. } | Reply::Error { errno, .. } => {
                        return Err(IpsetError::Kernel(errno));
                    }
                    Reply::Ack { .. } | Reply::Other { .. } => {}
                }
            }
        }
    }

    /// `IPSET_CMD_PROTOCOL` round trip: the watchdog probe of the fast path.
    pub fn probe(&mut self) -> Result<(), IpsetError> {
        self.query(&proto::req_protocol()).map(|_| ())
    }

    /// The set's header, or `None` if no set has that name.
    pub fn header(&mut self, name: &str) -> Result<Option<SetHeader>, IpsetError> {
        let mut h = SetHeader::default();
        let req = proto::req_list(self.protocol, name, true);
        match self.dump(&req, &mut |a| {
            proto::decode_list(a, &mut h, &mut |_| {})?;
            Ok(())
        }) {
            Ok(()) => Ok(Some(h)),
            Err(e) if e.is_no_set() => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn revision(&mut self, t: SetType, f: SetFamily) -> Result<u8, IpsetError> {
        if let Some(r) = self.revisions.get(&(t, f)) {
            return Ok(*r);
        }
        let attrs = self.query(&proto::req_type(self.protocol, t, f))?;
        let (max, _min) = proto::decode_type(&attrs)?;
        self.revisions.insert((t, f), max);
        Ok(max)
    }

    /// Creates a set at the highest revision the kernel offers for its type (as `ipset` does);
    /// the caller's `spec.revision` is ignored.
    pub fn create(&mut self, spec: &CreateSpec) -> Result<(), IpsetError> {
        let mut spec = spec.clone();
        spec.revision = self.revision(spec.set_type, spec.family)?;
        let req = proto::req_create(self.protocol, &spec);
        self.acked(std::slice::from_ref(&req))
            .pop()
            .unwrap_or(Err(IpsetError::Timeout))
    }

    pub fn destroy(&mut self, name: &str) -> Result<(), IpsetError> {
        let req = proto::req_destroy(self.protocol, name);
        self.acked(std::slice::from_ref(&req))
            .pop()
            .unwrap_or(Err(IpsetError::Timeout))
    }

    pub fn flush(&mut self, name: &str) -> Result<(), IpsetError> {
        let req = proto::req_flush(self.protocol, name);
        self.acked(std::slice::from_ref(&req))
            .pop()
            .unwrap_or(Err(IpsetError::Timeout))
    }

    pub fn add(&mut self, ops: &[(&str, Elem, Option<u32>)]) -> Vec<Result<(), IpsetError>> {
        let reqs: Vec<Request> = ops
            .iter()
            .map(|(s, e, t)| proto::req_add(self.protocol, s, e, *t))
            .collect();
        self.acked(&reqs)
    }

    pub fn del(&mut self, ops: &[(&str, Elem)]) -> Vec<Result<(), IpsetError>> {
        let reqs: Vec<Request> = ops
            .iter()
            .map(|(s, e)| proto::req_del(self.protocol, s, e))
            .collect();
        self.acked(&reqs)
    }

    /// Lists a set's members with their remaining timeouts, streaming each to `sink`.
    pub fn list(&mut self, name: &str, sink: &mut dyn FnMut(Member)) -> Result<SetHeader, IpsetError> {
        let mut h = SetHeader::default();
        let req = proto::req_list(self.protocol, name, false);
        self.dump(&req, &mut |a| {
            proto::decode_list(a, &mut h, sink)?;
            Ok(())
        })?;
        Ok(h)
    }
}
