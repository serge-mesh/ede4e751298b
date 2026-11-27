//! The core session (edge.md §13, api.md §3): one WebSocket over pinned mTLS carrying `hello`,
//! `welcome`, `changed` and heartbeats; WebSocket ping every 20 s; reconnect forever with
//! exponential backoff and jitter (1 s → 60 s). Every write has a timeout.
//!
//! - `hello` carries everything api.md §3 lists, `starts` included; after `welcome`, `starts`
//!   resets in `state.json` and the config object is fetched (every (re)connect).
//! - `changed` triggers a fetch; a heartbeat goes every 30 s with running totals.
//! - Core presenting another key than the pinned one refuses the connection and is logged.

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use rand::RngExt as _;
use tokio_tungstenite::tungstenite::Message;

use picket_api::session::{SessionMessage, Welcome};
use picket_api::time::Timestamp;

use crate::core_client::{ClientError, CoreClient, WsStream};
use crate::edge::{CoreState, Edge, SessionStatus};
use crate::report::{self, HelperCpu};

/// Session timing; tests shorten it.
#[derive(Clone, Copy, Debug)]
pub struct Timings {
    pub heartbeat: Duration,
    pub ping: Duration,
    pub welcome: Duration,
    pub write: Duration,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// A session that lasted this long resets the backoff.
    pub healthy: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            heartbeat: Duration::from_secs(30),
            ping: Duration::from_secs(20),
            welcome: Duration::from_secs(30),
            write: Duration::from_secs(10),
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            healthy: Duration::from_secs(60),
        }
    }
}

/// Exponential backoff with jitter: each delay is drawn from [d/2, d], d doubling up to the max.
pub struct Backoff {
    min: Duration,
    max: Duration,
    cur: Duration,
}

impl Backoff {
    pub fn new(min: Duration, max: Duration) -> Self {
        Self { min, max, cur: min }
    }
    pub fn reset(&mut self) {
        self.cur = self.min;
    }
    pub fn next_delay(&mut self) -> Duration {
        let d = self.cur;
        self.cur = (self.cur * 2).min(self.max);
        let ms = picket_api::duration::as_millis_u64(d);
        Duration::from_millis(rand::rng().random_range(ms / 2..=ms.max(1)))
    }
}

fn set_status(edge: &Edge, f: impl FnOnce(&mut SessionStatus)) {
    let mut s = SessionStatus::clone(&edge.session.load());
    let before = s.state;
    f(&mut s);
    if s.state != before {
        s.since = Timestamp::now();
    }
    edge.session.store(Arc::new(s));
}

/// Runs the session forever.
pub async fn run(edge: Arc<Edge>, client: Arc<CoreClient>, timings: Timings) -> anyhow::Result<()> {
    let mut backoff = Backoff::new(timings.backoff_min, timings.backoff_max);
    let mut helper_cpu = HelperCpu::default();
    let mut mismatch_logged: Option<(String, Instant)> = None;
    loop {
        set_status(&edge, |s| {
            if s.state != CoreState::KeyMismatch && s.state != CoreState::NotApproved {
                s.state = CoreState::Connecting;
            }
        });
        let started = Instant::now();
        match client.connect_session().await {
            Ok(ws) => {
                let r = session(&edge, ws, &timings, &mut helper_cpu).await;
                let msg = match &r {
                    Ok(m) => m.clone(),
                    Err(e) => crate::diag::cap_chain(e),
                };
                tracing::warn!("core session ended: {msg}");
                set_status(&edge, |s| {
                    s.state = CoreState::Connecting;
                    s.last_error = Some(msg);
                });
            }
            Err(ClientError::KeyMismatch { presented }) => {
                let pinned = edge.local.core_key.clone().unwrap_or_default();
                let log_now = mismatch_logged
                    .as_ref()
                    .is_none_or(|(k, t)| *k != presented || t.elapsed() >= Duration::from_secs(600));
                if log_now {
                    tracing::warn!(
                        "core presented key {presented}, but edge.json pins {pinned}: refusing the connection \
                         (if core's key changed on purpose, re-run picket-edge setup)"
                    );
                    mismatch_logged = Some((presented.clone(), Instant::now()));
                }
                set_status(&edge, |s| {
                    s.state = CoreState::KeyMismatch;
                    s.last_error = Some(format!("core presented {presented}, pinned {pinned}"));
                });
            }
            Err(ClientError::Forbidden) => {
                set_status(&edge, |s| {
                    s.state = CoreState::NotApproved;
                    s.last_error = Some(format!(
                        "core refused this edge; approve {} under Edges → Pending",
                        edge.identity.fingerprint
                    ));
                });
            }
            Err(e) => {
                set_status(&edge, |s| {
                    s.state = CoreState::Connecting;
                    s.last_error = Some(e.to_string());
                });
            }
        }
        if started.elapsed() >= timings.healthy {
            backoff.reset();
        }
        tokio::time::sleep(backoff.next_delay()).await;
    }
}

async fn send<S>(sink: &mut S, msg: &SessionMessage, timeout: Duration) -> anyhow::Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let text = serde_json::to_string(msg)?;
    tokio::time::timeout(timeout, sink.send(Message::Text(text.into())))
        .await
        .map_err(|_| anyhow::anyhow!("write timed out"))??;
    Ok(())
}

/// One session, from `hello` until it ends. Returns why it ended.
async fn session(
    edge: &Arc<Edge>,
    ws: WsStream,
    t: &Timings,
    helper_cpu: &mut HelperCpu,
) -> anyhow::Result<String> {
    let (mut sink, mut stream) = ws.split();
    send(
        &mut sink,
        &SessionMessage::Hello(Box::new(report::hello(edge))),
        t.write,
    )
    .await?;

    let welcome: Welcome = tokio::time::timeout(t.welcome, async {
        loop {
            match stream.next().await {
                Some(Ok(Message::Text(text))) => {
                    if let Ok(SessionMessage::Welcome(w)) = serde_json::from_str::<SessionMessage>(&text) {
                        return Ok(w);
                    }
                }
                Some(Ok(Message::Ping(_))) => {
                    tokio::time::timeout(t.write, sink.flush())
                        .await
                        .map_err(|_| anyhow::anyhow!("write timed out"))??;
                }
                Some(Ok(Message::Close(_))) | None => anyhow::bail!("closed before welcome"),
                Some(Err(e)) => anyhow::bail!("before welcome: {}", crate::diag::cap(e)),
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("no welcome in time"))??;

    set_status(edge, |s| {
        s.state = CoreState::Connected;
        s.core_version = Some(crate::diag::truncate(&welcome.core_version, 64));
        s.edge_id = Some(crate::diag::truncate(&welcome.edge_id, 128));
        s.edge_name = Some(crate::diag::truncate(&welcome.edge_name, 128));
        s.last_error = None;
    });
    if edge.state.get().starts != 0
        && let Err(e) = edge.state.update_async(|s| s.starts = 0).await
    {
        tracing::warn!("resetting starts: {}", crate::diag::cap_chain(&e));
    }
    // After every (re)connect: fetch the config object, and drain the spool now.
    edge.fetch_now.notify_one();
    edge.log_control.core_reachable();

    let mut hb = tokio::time::interval_at(tokio::time::Instant::now() + t.heartbeat, t.heartbeat);
    hb.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + t.ping, t.ping);
    let mut last_rx = Instant::now();
    loop {
        tokio::select! {
            msg = stream.next() => {
                last_rx = Instant::now();
                match msg {
                    Some(Ok(Message::Text(text))) => match serde_json::from_str::<SessionMessage>(&text) {
                        Ok(SessionMessage::Changed(_)) => edge.fetch_now.notify_one(),
                        Ok(_) => {}
                        Err(e) => tracing::debug!("ignoring a bad session message: {}", crate::diag::cap(e)),
                    },
                    Some(Ok(Message::Ping(_))) => {
                        // tungstenite queued the pong; flush it out now.
                        tokio::time::timeout(t.write, sink.flush())
                            .await
                            .map_err(|_| anyhow::anyhow!("write timed out"))??;
                    }
                    Some(Ok(Message::Close(_))) | None => return Ok("closed by core".into()),
                    Some(Err(e)) => anyhow::bail!("{}", crate::diag::cap(e)),
                    Some(Ok(_)) => {}
                }
            }
            _ = hb.tick() => {
                let h = report::heartbeat(edge, helper_cpu).await;
                send(&mut sink, &SessionMessage::Heartbeat(Box::new(h)), t.write).await?;
            }
            _ = edge.heartbeat_now.notified() => {
                let h = report::heartbeat(edge, helper_cpu).await;
                send(&mut sink, &SessionMessage::Heartbeat(Box::new(h)), t.write).await?;
            }
            _ = ping.tick() => {
                if last_rx.elapsed() > t.ping * 3 {
                    anyhow::bail!("nothing from core for {:?}", last_rx.elapsed());
                }
                tokio::time::timeout(t.write, sink.send(Message::Ping(Default::default())))
                    .await
                    .map_err(|_| anyhow::anyhow!("write timed out"))??;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_with_jitter_up_to_the_max() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
        let mut prev_cap = Duration::from_secs(1);
        for _ in 0..10 {
            let d = b.next_delay();
            assert!(d <= prev_cap && d >= prev_cap / 2, "{d:?} vs {prev_cap:?}");
            prev_cap = (prev_cap * 2).min(Duration::from_secs(60));
        }
        assert!(b.next_delay() <= Duration::from_secs(60));
        b.reset();
        assert!(b.next_delay() <= Duration::from_secs(1));
    }
}
