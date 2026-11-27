//! The fast path (edge-firewall.md §3–§4): `ensure` and `delete` from any connection, and the
//! watchdog probe, on one dedicated thread with its own netlink socket. Nothing slow runs here —
//! no exec, no dump, no file I/O — so an `ensure` never waits behind a `dump` page, an `apply` or
//! an `iptables-restore` waiting for the xtables lock, and a hang here (a stalled netlink call)
//! stops the watchdog pings.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

use picket_api::helper::{EnsureResponse, EntryFailure, MAX_TIMEOUT_S, SetEntry, sets};
use tokio::sync::oneshot;

use crate::backend::{Backend, SetOp};
use crate::engine::Cmd;
use crate::ipset::{Elem, IpsetError};
use crate::shared::Shared;

/// Most entries in one `ensure` or `delete` (the edge coalesces ≤ 64; a re-send after a
/// recreated set may be larger). A frame of this many entries stays far below 1 MiB.
pub const MAX_ENTRIES: usize = 4096;
/// Jobs queued for the worker; with one request in flight per connection and a handful of
/// connections, this never fills unless the worker is stuck.
const QUEUE: usize = 32;
/// At most one `set_full` event per set this often from failed adds.
const SET_FULL_EVERY: Duration = Duration::from_secs(10);
/// At most one re-assert trigger this often from adds that found no set.
const NO_SET_EVERY: Duration = Duration::from_secs(1);

pub enum Job {
    Ensure(Vec<SetEntry>, oneshot::Sender<EnsureResponse>),
    Delete(Vec<SetEntry>, oneshot::Sender<EnsureResponse>),
    /// Round trip through the fast netlink socket; the answer is whether the kernel replied.
    Probe(oneshot::Sender<Result<(), IpsetError>>),
}

#[derive(Clone)]
pub struct FastHandle {
    tx: SyncSender<Job>,
}

impl FastHandle {
    /// Queues a job; `Err` if the worker is gone or its queue is full.
    pub fn submit(&self, job: Job) -> Result<(), &'static str> {
        match self.tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err("busy"),
            Err(TrySendError::Disconnected(_)) => Err("fast worker stopped"),
        }
    }
}

/// Checks one entry against the rules the helper enforces (edge-firewall.md §4): only the four
/// timed sets, the set's family, a source for `per_client_ip` sets and none for `global` ones,
/// and `timeout_s` clamped to whole seconds in 1–2,147,483 (0 would make an entry permanent).
pub fn to_op(e: &SetEntry, with_timeout: bool) -> Result<SetOp, &'static str> {
    let (set, pair, v4) = match e.set.as_str() {
        sets::PICKET4 => (sets::PICKET4, true, true),
        sets::PICKET6 => (sets::PICKET6, true, false),
        sets::PICKET_G4 => (sets::PICKET_G4, false, true),
        sets::PICKET_G6 => (sets::PICKET_G6, false, false),
        _ => return Err("invalid_set"),
    };
    let fam_ok = |ip: &IpAddr| ip.is_ipv4() == v4;
    if !fam_ok(&e.dst) {
        return Err("invalid_family");
    }
    let elem = match (pair, e.src) {
        (true, Some(src)) if fam_ok(&src) => Elem::host_pair(src, e.dst),
        (true, Some(_)) => return Err("invalid_family"),
        (true, None) => return Err("missing_src"),
        (false, None) => Elem::ip(e.dst),
        (false, Some(_)) => return Err("unexpected_src"),
    };
    let timeout = with_timeout.then(|| e.timeout_s.clamp(1, MAX_TIMEOUT_S));
    Ok(SetOp { set, elem, timeout })
}

struct Worker<B: Backend> {
    b: Arc<B>,
    shared: Arc<Shared>,
    engine: SyncSender<Cmd>,
    last_full: HashMap<&'static str, Instant>,
    last_trigger: Option<Instant>,
}

impl<B: Backend> Worker<B> {
    fn run_ops(&mut self, entries: &[SetEntry], add: bool) -> EnsureResponse {
        let mut failed = Vec::new();
        let mut ops = Vec::with_capacity(entries.len());
        let mut idx = Vec::with_capacity(entries.len());
        for (i, e) in entries.iter().enumerate() {
            match to_op(e, add) {
                Ok(op) => {
                    ops.push(op);
                    idx.push(i);
                }
                Err(reason) => failed.push(EntryFailure {
                    index: i,
                    reason: reason.into(),
                }),
            }
        }
        let results = if ops.is_empty() {
            Vec::new()
        } else if add {
            self.b.ipset_add(&ops)
        } else {
            self.b.ipset_del(&ops)
        };
        let mut no_set = false;
        for ((i, op), r) in idx.iter().zip(&ops).zip(results) {
            let Err(e) = r else { continue };
            if e.is_set_full() {
                let due = self
                    .last_full
                    .get(op.set)
                    .is_none_or(|t| t.elapsed() >= SET_FULL_EVERY);
                if due {
                    self.last_full.insert(op.set, Instant::now());
                    self.shared.publish_set_full(op.set);
                }
            }
            no_set |= e.is_no_set();
            failed.push(EntryFailure {
                index: *i,
                reason: e.reason(),
            });
        }
        if no_set && self.last_trigger.is_none_or(|t| t.elapsed() >= NO_SET_EVERY) {
            // A set vanished: let the engine recreate it now rather than in ≤ 2 s.
            self.last_trigger = Some(Instant::now());
            let _ = self.engine.try_send(Cmd::Trigger);
        }
        failed.sort_by_key(|f| f.index);
        EnsureResponse {
            ok: failed.is_empty(),
            failed,
        }
    }
}

/// Starts the worker thread. The worker is mandatory (it serves `ensure`, `delete` and the
/// watchdog's probe): an OS that refuses the thread fails start-up, before `READY=1`.
pub fn spawn<B: Backend>(
    b: Arc<B>,
    shared: Arc<Shared>,
    engine: SyncSender<Cmd>,
) -> std::io::Result<FastHandle> {
    let (tx, rx) = sync_channel::<Job>(QUEUE);
    let mut w = Worker {
        b,
        shared,
        engine,
        last_full: HashMap::new(),
        last_trigger: None,
    };
    std::thread::Builder::new().name("fast".into()).spawn(move || {
        for job in rx {
            match job {
                Job::Ensure(entries, reply) => {
                    let _ = reply.send(w.run_ops(&entries, true));
                }
                Job::Delete(entries, reply) => {
                    let _ = reply.send(w.run_ops(&entries, false));
                }
                Job::Probe(reply) => {
                    let _ = reply.send(w.b.ipset_probe());
                }
            }
        }
    })?;
    Ok(FastHandle { tx })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(set: &str, src: Option<&str>, dst: &str, t: u32) -> SetEntry {
        SetEntry {
            set: set.into(),
            src: src.map(|s| s.parse().unwrap()),
            dst: dst.parse().unwrap(),
            timeout_s: t,
        }
    }

    #[test]
    fn rules_the_helper_enforces() {
        assert_eq!(
            to_op(&entry("picket4", Some("10.0.0.1"), "1.1.1.1", 0), true)
                .unwrap()
                .timeout,
            Some(1)
        );
        assert_eq!(
            to_op(&entry("picket4", Some("10.0.0.1"), "1.1.1.1", u32::MAX), true)
                .unwrap()
                .timeout,
            Some(MAX_TIMEOUT_S)
        );
        assert_eq!(
            to_op(&entry("picket-static4", None, "1.1.1.1", 5), true),
            Err("invalid_set")
        );
        assert_eq!(
            to_op(&entry("UBIOS_x", None, "1.1.1.1", 5), true),
            Err("invalid_set")
        );
        assert_eq!(
            to_op(&entry("picket4", None, "1.1.1.1", 5), true),
            Err("missing_src")
        );
        assert_eq!(
            to_op(&entry("picket4", Some("fd00::1"), "1.1.1.1", 5), true),
            Err("invalid_family")
        );
        assert_eq!(
            to_op(&entry("picket6", Some("fd00::1"), "1.1.1.1", 5), true),
            Err("invalid_family")
        );
        assert_eq!(
            to_op(&entry("picket-g4", Some("10.0.0.1"), "1.1.1.1", 5), true),
            Err("unexpected_src")
        );
        let g6 = to_op(&entry("picket-g6", None, "2001:db8::1", 5), false).unwrap();
        assert_eq!(g6.timeout, None);
        assert_eq!(g6.elem, Elem::ip("2001:db8::1".parse().unwrap()));
    }
}
