//! Stream transports to one server (edge.md §6 "Connection model"; RFC 7766, RFC 7858, RFC 9210):
//! plain TCP and DoT.
//!
//! - One long-lived connection per server (TLS 1.3 with session resumption for DoT,
//!   `TCP_NODELAY`), with pipelining and out-of-order answers: a 16-bit ID space per connection,
//!   at most 128 queries in flight, answers matched on ID plus question.
//! - The edge closes a connection that has been quiet for [`IDLE_CLOSE`] (servers close after
//!   about 10 s), and a query on a connection idle longer than [`SUSPECT_IDLE`] that gets no
//!   answer within `min(3 × p99 RTT, 300 ms)` marks the connection suspect and is retried on a
//!   fresh one. "Idle" counts from the last byte **received**: writes succeed into the socket
//!   buffer even on a dead connection, so under steady traffic only reply progress shows it is
//!   alive.
//! - A connection with queries outstanding that has received nothing for [`STALL_AFTER`] is closed
//!   as dead (its queries fail over, counting against the upstream's health) and the next query
//!   opens a fresh one, so a dead connection is noticed under steady traffic well before the
//!   socket buffer fills.
//! - Connects back off with jitter (100 ms → 10 s) while they fail.
//! - Every write is bounded ([`WRITE_TIMEOUT`]), and so is handing a query to the connection
//!   (the query's deadline): a server that stops reading can't wedge the connection.
//! - Each query's ID is replaced by one unique on the connection and restored in the answer, so
//!   callers keep their own IDs (upstream queries and lookup servers alike).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc, oneshot};

use super::transport::{TxError, question_matches};

/// Most queries in flight per connection (edge.md §6).
pub const MAX_INFLIGHT: usize = 128;
/// A quiet connection is closed by the edge after this.
pub const IDLE_CLOSE: Duration = Duration::from_millis(9_500);
/// A query on a connection idle longer than this may find it dead (edge.md §6).
pub const SUSPECT_IDLE: Duration = Duration::from_secs(8);
/// The longest wait for a suspect connection's first answer.
pub const SUSPECT_MAX: Duration = Duration::from_millis(300);
/// No reply at all for this long while queries are outstanding: the connection is dead. Longer
/// than one attempt's timeout, so a merely slow answer doesn't close it.
pub const STALL_AFTER: Duration = Duration::from_secs(3);
/// TCP connect plus TLS handshake.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Writing one query frame (README §2 "every external call has a timeout"). A write blocks only
/// when the server stops reading; past this the connection is closed as failed, its queries fail
/// over to another upstream (counting against this one's health), and the next query opens a
/// fresh connection.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
/// A query nobody answered is forgotten after this, freeing its ID.
const PENDING_MAX_AGE: Duration = Duration::from_secs(15);
const BACKOFF_MIN: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(10);

/// TLS for a DoT server.
#[derive(Clone)]
pub struct TlsTarget {
    pub config: Arc<ClientConfig>,
    pub name: ServerName<'static>,
}

struct Pending {
    orig_id: [u8; 2],
    question: Box<[u8]>,
    since: Instant,
    reply: oneshot::Sender<Result<Vec<u8>, TxError>>,
}

struct Cmd {
    msg: Vec<u8>,
    reply: oneshot::Sender<Result<Vec<u8>, TxError>>,
}

struct Conn {
    tx: mpsc::Sender<Cmd>,
    base: Instant,
    /// Milliseconds since `base` of the last byte sent or received (the idle close).
    last_activity: AtomicU64,
    /// Milliseconds since `base` of the last byte received, or of the connection's start (the
    /// suspect check: reply progress, not writes).
    last_rx: AtomicU64,
    closed: AtomicBool,
}

impl Conn {
    fn new(tx: mpsc::Sender<Cmd>) -> Self {
        Self {
            tx,
            base: Instant::now(),
            last_activity: AtomicU64::new(0),
            last_rx: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        }
    }
    fn touch(&self) {
        self.last_activity
            .store(picket_api::duration::as_millis_u64(self.base.elapsed()), Relaxed);
    }
    fn touch_rx(&self) {
        let now = picket_api::duration::as_millis_u64(self.base.elapsed());
        self.last_activity.store(now, Relaxed);
        self.last_rx.store(now, Relaxed);
    }
    fn idle_for(&self) -> Duration {
        let now = picket_api::duration::as_millis_u64(self.base.elapsed());
        Duration::from_millis(now.saturating_sub(self.last_activity.load(Relaxed)))
    }
    /// Time since the last reply byte (or the connection's start).
    fn rx_idle_for(&self) -> Duration {
        let now = picket_api::duration::as_millis_u64(self.base.elapsed());
        Duration::from_millis(now.saturating_sub(self.last_rx.load(Relaxed)))
    }
}

struct Backoff {
    next_allowed: Option<Instant>,
    delay: Duration,
}

/// A TCP or DoT server.
pub struct StreamTransport {
    addr: SocketAddr,
    tls: Option<TlsTarget>,
    conn: Mutex<Option<Arc<Conn>>>,
    connect_lock: tokio::sync::Mutex<()>,
    backoff: Mutex<Backoff>,
    slots: Semaphore,
}

impl StreamTransport {
    pub fn new(addr: SocketAddr, tls: Option<TlsTarget>) -> Self {
        Self {
            addr,
            tls,
            conn: Mutex::new(None),
            connect_lock: tokio::sync::Mutex::new(()),
            backoff: Mutex::new(Backoff {
                next_allowed: None,
                delay: BACKOFF_MIN,
            }),
            slots: Semaphore::new(MAX_INFLIGHT),
        }
    }

    fn current(&self) -> Option<Arc<Conn>> {
        let g = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        g.as_ref().filter(|c| !c.closed.load(Relaxed)).cloned()
    }

    fn drop_conn(&self, c: &Arc<Conn>) {
        c.closed.store(true, Relaxed);
        let mut g = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if g.as_ref().is_some_and(|x| Arc::ptr_eq(x, c)) {
            *g = None;
        }
    }

    async fn connection(&self, deadline: Instant) -> Result<Arc<Conn>, TxError> {
        if let Some(c) = self.current() {
            return Ok(c);
        }
        let _g = tokio::time::timeout_at(deadline.into(), self.connect_lock.lock())
            .await
            .map_err(|_| TxError::Timeout)?;
        if let Some(c) = self.current() {
            return Ok(c);
        }
        {
            let b = self.backoff.lock().unwrap_or_else(|p| p.into_inner());
            if b.next_allowed.is_some_and(|t| Instant::now() < t) {
                return Err(TxError::Connect("reconnect backing off".into()));
            }
        }
        let limit = deadline.min(Instant::now() + CONNECT_TIMEOUT);
        match tokio::time::timeout_at(limit.into(), self.open()).await {
            Ok(Ok(c)) => {
                let mut b = self.backoff.lock().unwrap_or_else(|p| p.into_inner());
                b.next_allowed = None;
                b.delay = BACKOFF_MIN;
                drop(b);
                *self.conn.lock().unwrap_or_else(|p| p.into_inner()) = Some(Arc::clone(&c));
                Ok(c)
            }
            Ok(Err(e)) => {
                self.failed_connect();
                Err(e)
            }
            Err(_) => {
                self.failed_connect();
                Err(TxError::Connect("connect timed out".into()))
            }
        }
    }

    fn failed_connect(&self) {
        let mut b = self.backoff.lock().unwrap_or_else(|p| p.into_inner());
        let jitter = 0.8 + rand::random::<f64>() * 0.4;
        b.next_allowed = Some(Instant::now() + b.delay.mul_f64(jitter));
        b.delay = (b.delay * 2).min(BACKOFF_MAX);
    }

    async fn open(&self) -> Result<Arc<Conn>, TxError> {
        let tcp = TcpStream::connect(self.addr)
            .await
            .map_err(|e| TxError::Connect(crate::diag::cap(e)))?;
        let _ = tcp.set_nodelay(true);
        let (tx, rx) = mpsc::channel(MAX_INFLIGHT);
        let conn = Arc::new(Conn::new(tx));
        conn.touch();
        match &self.tls {
            None => {
                tokio::spawn(run_conn(tcp, rx, Arc::clone(&conn)));
            }
            Some(t) => {
                let tls = tokio_rustls::TlsConnector::from(Arc::clone(&t.config))
                    .connect(t.name.clone(), tcp)
                    .await
                    .map_err(|e| TxError::Connect(format!("TLS: {}", crate::diag::cap(e))))?;
                tokio::spawn(run_conn(tls, rx, Arc::clone(&conn)));
            }
        }
        Ok(conn)
    }

    /// Sends `msg` and returns the answer with `msg`'s ID. `p99` is the server's p99 RTT, for
    /// the idle-suspect check.
    pub async fn query(
        &self,
        msg: &[u8],
        timeout: Duration,
        p99: Option<Duration>,
    ) -> Result<Vec<u8>, TxError> {
        if msg.len() < 12 || msg.len() > picket_wire::MAX_MESSAGE {
            return Err(TxError::Transport("query size".into()));
        }
        let deadline = Instant::now() + timeout;
        let _slot = tokio::time::timeout_at(deadline.into(), self.slots.acquire())
            .await
            .map_err(|_| TxError::Timeout)?
            .map_err(|_| TxError::Transport("closed".into()))?;
        let mut retried = false;
        loop {
            let conn = self.connection(deadline).await?;
            // Reply progress, not writes, shows the connection is alive.
            let idle = conn.rx_idle_for();
            let (rtx, rrx) = oneshot::channel();
            let sent = tokio::time::timeout_at(
                deadline.into(),
                conn.tx.send(Cmd {
                    msg: msg.to_vec(),
                    reply: rtx,
                }),
            )
            .await;
            let Ok(sent) = sent else {
                // The connection took no query until the deadline: it is wedged.
                self.drop_conn(&conn);
                return Err(TxError::Timeout);
            };
            if sent.is_err() {
                self.drop_conn(&conn);
                if retried {
                    return Err(TxError::Transport("connection closed".into()));
                }
                retried = true;
                continue;
            }
            let suspect = (!retried && idle > SUSPECT_IDLE).then(|| {
                p99.map_or(SUSPECT_MAX, |p| (p * 3).min(SUSPECT_MAX))
                    .max(Duration::from_millis(20))
            });
            let mut rrx = rrx;
            if let Some(s) = suspect {
                let first = Instant::now() + s;
                if first < deadline {
                    match tokio::time::timeout_at(first.into(), &mut rrx).await {
                        Ok(r) => {
                            return r.unwrap_or_else(|_| Err(TxError::Transport("connection closed".into())));
                        }
                        Err(_) => {
                            // Suspect: retry on a fresh connection (edge.md §6).
                            self.drop_conn(&conn);
                            retried = true;
                            continue;
                        }
                    }
                }
            }
            return match tokio::time::timeout_at(deadline.into(), rrx).await {
                Ok(Ok(r)) => r,
                Ok(Err(_)) => Err(TxError::Transport("connection closed".into())),
                Err(_) => Err(TxError::Timeout),
            };
        }
    }

    /// Closes the connection (a config change dropped the server).
    pub fn close(&self) {
        if let Some(c) = self.current() {
            self.drop_conn(&c);
        }
    }
}

impl Drop for StreamTransport {
    fn drop(&mut self) {
        self.close();
    }
}

async fn run_conn<S>(stream: S, mut rx: mpsc::Receiver<Cmd>, conn: Arc<Conn>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut pending: HashMap<u16, Pending> = HashMap::new();
    let mut buf = BytesMut::with_capacity(4096);
    let mut sweep = tokio::time::interval(Duration::from_millis(500));
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Since when queries have been outstanding with nothing received (reply progress resets it).
    let mut unanswered_since: Option<Instant> = None;
    let close_reason: &str = loop {
        if conn.closed.load(Relaxed) {
            break "closed";
        }
        let idle_at = tokio::time::Instant::now() + IDLE_CLOSE.saturating_sub(conn.idle_for());
        tokio::select! {
            cmd = rx.recv(), if pending.len() < MAX_INFLIGHT => {
                let Some(Cmd { mut msg, reply }) = cmd else { break "dropped" };
                let mut id: u16 = rand::random();
                let mut tries = 0;
                while pending.contains_key(&id) && tries < 64 {
                    id = rand::random();
                    tries += 1;
                }
                if pending.contains_key(&id) {
                    let _ = reply.send(Err(TxError::Transport("no free ID".into())));
                    continue;
                }
                let orig_id = [msg[0], msg[1]];
                msg[..2].copy_from_slice(&id.to_be_bytes());
                let qlen = super::transport::question_len(&msg);
                let question: Box<[u8]> = msg.get(12..12 + qlen).unwrap_or(&[]).into();
                let Ok(len) = u16::try_from(msg.len()) else {
                    let _ = reply.send(Err(TxError::Transport("a query over 64 KiB".into())));
                    continue;
                };
                let mut frame = Vec::with_capacity(msg.len() + 2);
                frame.extend_from_slice(&len.to_be_bytes());
                frame.extend_from_slice(&msg);
                let wrote = tokio::time::timeout(WRITE_TIMEOUT, async {
                    wr.write_all(&frame).await?;
                    wr.flush().await
                })
                .await;
                match wrote {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        let _ = reply.send(Err(TxError::Transport(crate::diag::cap(e))));
                        break "write failed";
                    }
                    Err(_) => {
                        let _ = reply.send(Err(TxError::Timeout));
                        break "write timed out";
                    }
                }
                conn.touch();
                if unanswered_since.is_none() {
                    unanswered_since = Some(Instant::now());
                }
                pending.insert(id, Pending { orig_id, question, since: Instant::now(), reply });
            }
            r = rd.read_buf(&mut buf) => {
                match r {
                    Ok(0) => break "closed by server",
                    Ok(_) => {
                        conn.touch_rx();
                        while let Some(mut frame) = crate::dns::listeners::stream::take_frame(&mut buf) {
                            if frame.len() < 12 {
                                continue;
                            }
                            let id = u16::from_be_bytes([frame[0], frame[1]]);
                            if let Some(p) = pending.remove(&id) {
                                if !question_matches(&frame, &p.question) {
                                    let _ = p.reply.send(Err(TxError::Mismatch));
                                    continue;
                                }
                                frame[..2].copy_from_slice(&p.orig_id);
                                let _ = p.reply.send(Ok(frame));
                            }
                        }
                        unanswered_since = (!pending.is_empty()).then(Instant::now);
                    }
                    Err(_) => break "read failed",
                }
            }
            _ = sweep.tick() => {
                // Queries outstanding and nothing received for STALL_AFTER: dead (the caller's
                // timeouts may already have dropped them; the silence still counts).
                if unanswered_since.is_some_and(|t| t.elapsed() >= STALL_AFTER) {
                    break "no reply";
                }
                pending.retain(|_, p| p.since.elapsed() < PENDING_MAX_AGE && !p.reply.is_closed());
            }
            _ = tokio::time::sleep_until(idle_at), if pending.is_empty() => {
                if conn.idle_for() >= IDLE_CLOSE {
                    break "idle";
                }
            }
        }
    };
    conn.closed.store(true, Relaxed);
    let _ = close_reason;
    for (_, p) in pending.drain() {
        let _ = p.reply.send(Err(TxError::Transport("connection closed".into())));
    }
    rx.close();
    while let Ok(c) = rx.try_recv() {
        let _ = c.reply.send(Err(TxError::Transport("connection closed".into())));
    }
    // Bounded too: a TLS close_notify to a server that stopped reading would block.
    let _ = tokio::time::timeout(WRITE_TIMEOUT, wr.shutdown()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D13: a server that stops reading can't wedge the connection: the write times out, the
    /// query fails and the connection is marked closed (so the next query opens a fresh one).
    #[tokio::test]
    async fn a_write_the_server_never_reads_times_out_and_closes_the_connection() {
        let (client, _server) = tokio::io::duplex(16);
        let (tx, rx) = mpsc::channel(MAX_INFLIGHT);
        let conn = Arc::new(Conn::new(tx));
        let task = tokio::spawn(run_conn(client, rx, Arc::clone(&conn)));
        let (rtx, rrx) = oneshot::channel();
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        conn.tx.send(Cmd { msg, reply: rtx }).await.unwrap();
        let r = tokio::time::timeout(WRITE_TIMEOUT * 3, rrx)
            .await
            .expect("answered within the write timeout")
            .expect("a reply");
        assert_eq!(r, Err(TxError::Timeout));
        assert!(conn.closed.load(Relaxed), "marked closed");
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the connection task ends")
            .unwrap();
    }

    fn query_msg() -> Vec<u8> {
        let mut msg = vec![0u8; 12];
        msg[5] = 1;
        msg.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        msg
    }

    /// Wave 3 follow-up (a): a dead connection under steady traffic. The server reads every query
    /// (so writes keep succeeding) but never answers: the connection is closed as dead once
    /// nothing has been received for STALL_AFTER with queries outstanding, long before any socket
    /// buffer fills, and successful writes don't count as liveness.
    #[tokio::test]
    async fn a_connection_that_reads_but_never_answers_is_closed_under_steady_traffic() {
        let (client, mut server) = tokio::io::duplex(1 << 20);
        // The server drains whatever it is sent.
        tokio::spawn(async move {
            let mut b = vec![0u8; 4096];
            while let Ok(n) = server.read(&mut b).await {
                if n == 0 {
                    break;
                }
            }
        });
        let (tx, rx) = mpsc::channel(MAX_INFLIGHT);
        let conn = Arc::new(Conn::new(tx));
        let task = tokio::spawn(run_conn(client, rx, Arc::clone(&conn)));
        let started = Instant::now();
        let mut writes = 0;
        while !conn.closed.load(Relaxed) && started.elapsed() < STALL_AFTER * 4 {
            let (rtx, rrx) = oneshot::channel();
            if conn
                .tx
                .send(Cmd {
                    msg: query_msg(),
                    reply: rtx,
                })
                .await
                .is_err()
            {
                break;
            }
            writes += 1;
            // Callers give up on their own (an attempt's timeout); the connection must still
            // notice that nothing ever came back.
            drop(rrx);
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                conn.idle_for() < Duration::from_secs(1),
                "writes keep the idle clock fresh"
            );
        }
        assert!(conn.closed.load(Relaxed), "closed as dead after {writes} writes");
        let took = started.elapsed();
        assert!(took >= STALL_AFTER, "not before STALL_AFTER: {took:?}");
        assert!(took < STALL_AFTER * 3, "noticed promptly: {took:?}");
        assert!(
            conn.rx_idle_for() >= STALL_AFTER,
            "suspicion is based on replies, not writes"
        );
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the connection task ends")
            .unwrap();
    }

    /// Reply progress keeps a busy connection alive, however long it runs.
    #[tokio::test]
    async fn a_connection_that_answers_stays_open() {
        let (client, server) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(server);
            let mut buf = BytesMut::new();
            loop {
                match rd.read_buf(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                while let Some(f) = crate::dns::listeners::stream::take_frame(&mut buf) {
                    let mut out = (f.len() as u16).to_be_bytes().to_vec();
                    let mut a = f.to_vec();
                    a[2] |= 0x80;
                    out.extend_from_slice(&a);
                    if wr.write_all(&out).await.is_err() {
                        return;
                    }
                }
            }
        });
        let (tx, rx) = mpsc::channel(MAX_INFLIGHT);
        let conn = Arc::new(Conn::new(tx));
        tokio::spawn(run_conn(client, rx, Arc::clone(&conn)));
        let started = Instant::now();
        while started.elapsed() < STALL_AFTER + Duration::from_secs(1) {
            let (rtx, rrx) = oneshot::channel();
            conn.tx
                .send(Cmd {
                    msg: query_msg(),
                    reply: rtx,
                })
                .await
                .unwrap();
            let r = tokio::time::timeout(Duration::from_secs(2), rrx)
                .await
                .unwrap()
                .unwrap();
            assert!(r.is_ok(), "{r:?}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!conn.closed.load(Relaxed));
        assert!(conn.rx_idle_for() < Duration::from_secs(1));
    }
}
