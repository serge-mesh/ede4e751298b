//! The task supervisor (edge.md §16): named background tasks restarted on panic or error with
//! backoff; a critical task's failure exits the process (systemd restarts it in about a second).
//! Every panic counts in `metrics.panics` and becomes a `panic` event (api.md §5).
//!
//! Fatal reports travel on an unbounded channel whose receiver exists from the start, so a
//! critical task failing during startup is never lost (unlike a `watch` value sent before anyone
//! subscribed).

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};

use crate::logs::{LogProducer, fields};
use crate::metrics::Metrics;

/// How a task's failure is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Restarted with backoff after a panic or an error.
    Background,
    /// A panic or an error exits the process.
    Critical,
}

/// A critical task's failure.
#[derive(Clone, Debug)]
pub struct Fatal {
    pub task: String,
    pub reason: String,
}

/// Restart backoff bounds.
#[derive(Clone, Copy, Debug)]
pub struct Backoff {
    pub min: Duration,
    pub max: Duration,
    /// A run at least this long resets the backoff.
    pub healthy: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            min: Duration::from_secs(1),
            max: Duration::from_secs(60),
            healthy: Duration::from_secs(60),
        }
    }
}

pub struct Supervisor {
    logs: LogProducer,
    metrics: Arc<Metrics>,
    fatal: mpsc::UnboundedSender<Fatal>,
    shutdown: watch::Receiver<bool>,
    backoff: Backoff,
}

impl Supervisor {
    pub fn new(
        logs: LogProducer,
        metrics: Arc<Metrics>,
        shutdown: watch::Receiver<bool>,
        backoff: Backoff,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<Fatal>) {
        // Unbounded on purpose: a fatal report must never block a dying task or be dropped. A
        // critical task sends at most one, as it ends, and start-up code a few, so the tasks bound
        // it.
        let (fatal, rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                logs,
                metrics,
                fatal,
                shutdown,
                backoff,
            }),
            rx,
        )
    }

    /// Reports a fatal failure from outside a supervised task (startup code).
    pub fn report_fatal(&self, task: &str, reason: String) {
        let _ = self.fatal.send(Fatal {
            task: task.to_owned(),
            reason,
        });
    }

    /// Spawns `factory()` as task `name`, supervised per `kind`. The factory is called again
    /// for each restart. A task that returns `Ok` is done and isn't restarted.
    pub fn spawn<F, Fut>(
        self: &Arc<Self>,
        name: &'static str,
        kind: Kind,
        factory: F,
    ) -> tokio::task::JoinHandle<()>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut shutdown = me.shutdown.clone();
            let mut backoff = me.backoff.min;
            loop {
                if *shutdown.borrow() {
                    return;
                }
                let started = Instant::now();
                let mut handle = tokio::spawn(factory());
                let res = tokio::select! {
                    r = &mut handle => r,
                    _ = shutdown.changed() => {
                        handle.abort();
                        return;
                    }
                };
                let reason = match res {
                    Ok(Ok(())) => return,
                    Ok(Err(e)) => {
                        let r = crate::diag::cap_chain(&e);
                        tracing::warn!("task {name} failed: {r}");
                        r
                    }
                    Err(j) if j.is_panic() => {
                        let msg = panic_message(j.into_panic());
                        tracing::error!("task {name} panicked: {msg}");
                        me.metrics.panics.fetch_add(1, Relaxed);
                        me.logs.event(
                            picket_api::logs::event_kind::PANIC,
                            fields(&[("task", name.into()), ("message", msg.clone().into())]),
                        );
                        format!("panicked: {msg}")
                    }
                    Err(_) => return, // cancelled
                };
                if kind == Kind::Critical {
                    let _ = me.fatal.send(Fatal {
                        task: name.to_owned(),
                        reason,
                    });
                    return;
                }
                if started.elapsed() >= me.backoff.healthy {
                    backoff = me.backoff.min;
                }
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown.changed() => return,
                }
                backoff = (backoff * 2).min(me.backoff.max);
            }
        })
    }
}

/// A panic payload as text, capped.
pub fn panic_message(p: Box<dyn std::any::Any + Send>) -> String {
    let s = if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "(non-string panic payload)".to_owned()
    };
    crate::diag::cap(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn quick() -> Backoff {
        Backoff {
            min: Duration::from_millis(5),
            max: Duration::from_millis(20),
            healthy: Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn background_panic_restarts_and_logs_a_panic_event() {
        let (p, mut rx) = LogProducer::new("b".into(), Arc::default());
        let metrics = Metrics::new();
        let (_tx, shut) = watch::channel(false);
        let (sup, _fatal) = Supervisor::new(p, Arc::clone(&metrics), shut, quick());
        let runs = Arc::new(AtomicU32::new(0));
        let r = Arc::clone(&runs);
        sup.spawn("flaky", Kind::Background, move || {
            let r = Arc::clone(&r);
            async move {
                if r.fetch_add(1, Ordering::SeqCst) < 2 {
                    panic!("boom");
                }
                Ok(())
            }
        })
        .await
        .unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 3);
        assert_eq!(metrics.panics.load(Relaxed), 2);
        let e = rx.rx.try_recv().unwrap();
        let v: serde_json::Value = serde_json::from_str(&e.line).unwrap();
        assert_eq!(v["kind"], "panic");
        assert_eq!(v["task"], "flaky");
        assert_eq!(v["message"], "boom");
    }

    #[tokio::test]
    async fn critical_failure_reaches_main_even_before_it_listens() {
        let (p, _rx) = LogProducer::new("b".into(), Arc::default());
        let (_tx, shut) = watch::channel(false);
        let (sup, mut fatal) = Supervisor::new(p, Metrics::new(), shut, quick());
        sup.spawn("core-session", Kind::Critical, || async {
            anyhow::bail!("no way")
        })
        .await
        .unwrap();
        // Nobody was waiting when it failed; the report is still there.
        let f = fatal.recv().await.unwrap();
        assert_eq!(f.task, "core-session");
        assert!(f.reason.contains("no way"));
    }

    #[tokio::test]
    async fn shutdown_stops_tasks() {
        let (p, _rx) = LogProducer::new("b".into(), Arc::default());
        let (tx, shut) = watch::channel(false);
        let (sup, _fatal) = Supervisor::new(p, Metrics::new(), shut, quick());
        let h = sup.spawn("forever", Kind::Background, || async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok(())
        });
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), h)
            .await
            .unwrap()
            .unwrap();
    }
}
