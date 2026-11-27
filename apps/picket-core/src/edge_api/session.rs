//! `GET /v1/session` (api.md §3, edge.md §13): the WebSocket control session.
//!
//! - The edge's first message is `hello` (within [`HELLO_WAIT`]); core stores it, registers the
//!   session (a newer session of the same edge replaces the older, which closes) and answers
//!   `welcome {core_version, edge_id, edge_name, server_time}`.
//! - `changed {etag}` goes out whenever the edge's config object changes; a session holds at
//!   most one pending `changed` (the newest ETag), never a queue.
//! - A hello is admitted only while the registry still pins the connection's key to its edge
//!   (api.md §1 Key change), and then at a capped rate per edge: a replaced key's hellos spend
//!   none of the edge's rate.
//! - Heartbeats are stored at most once per [`crate::edges::hub::HEARTBEAT_STORE_EVERY`],
//!   counted from the arrival of the last stored one; one arriving sooner only updates the live
//!   copy (`edges::status`).
//! - WebSocket ping every 20 s; a session that sends nothing for [`SILENCE`] is down. Every write
//!   has a deadline ([`WRITE_TIMEOUT`]); a write that misses it ends the session.

use std::time::Duration;

use axum::Extension;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use picket_api::session::{Changed, Hello, SessionMessage, Welcome};

use super::EdgePeer;
use crate::edges::hub::{Refused, Registered};
use crate::edges::messages::{self, Incoming};
use crate::state::SharedState;

/// How long core waits for `hello`.
pub const HELLO_WAIT: Duration = Duration::from_secs(30);
/// Deadline of every write.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// WebSocket ping interval (api.md §3).
pub const PING_EVERY: Duration = Duration::from_secs(20);
/// Nothing from the edge for this long: the session is down (the edge pings every 20 s and
/// sends a heartbeat every 30 s).
pub const SILENCE: Duration = Duration::from_secs(70);

/// The upgrade handler.
pub async fn upgrade(
    State(state): State<SharedState>,
    Extension(peer): Extension<EdgePeer>,
    share: Option<Extension<super::ConnShare>>,
    ws: Result<WebSocketUpgrade, axum::extract::ws::rejection::WebSocketUpgradeRejection>,
) -> Response {
    let ws = match ws {
        Ok(ws) => ws,
        Err(e) => {
            return super::api::error(
                axum::http::StatusCode::BAD_REQUEST,
                "bad_request",
                format!("the session is a WebSocket upgrade: {e}"),
            );
        }
    };
    ws.max_message_size(messages::MAX_MESSAGE)
        .max_frame_size(messages::MAX_MESSAGE)
        .on_upgrade(move |socket| async move {
            // The upgraded socket keeps its connection's share of the port while the session
            // lives (README §2, Bounded): hyper ends the connection task at the upgrade.
            let _share = share;
            if let Err(e) = run(state, peer.clone(), socket).await {
                tracing::info!(edge = %peer.edge_id, "edge session ended: {e}");
            }
        })
}

type Sink = futures_util::stream::SplitSink<WebSocket, Message>;

async fn send(sink: &mut Sink, msg: Message) -> anyhow::Result<()> {
    tokio::time::timeout(WRITE_TIMEOUT, sink.send(msg))
        .await
        .map_err(|_| anyhow::anyhow!("write timed out"))??;
    Ok(())
}

async fn send_json(sink: &mut Sink, msg: &SessionMessage) -> anyhow::Result<()> {
    let text = serde_json::to_string(msg)?;
    send(sink, Message::Text(text.into())).await
}

async fn close(sink: &mut Sink, code: u16, reason: &'static str) {
    let _ = send(
        sink,
        Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })),
    )
    .await;
}

/// Waits for the edge's `hello`, answering pings meanwhile.
async fn wait_hello(
    sink: &mut Sink,
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
) -> anyhow::Result<Hello> {
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(t))) => match messages::decode(t.as_str()) {
                Ok(Incoming::Hello(h)) => return Ok(*h),
                Ok(_) => continue,
                Err(e) => anyhow::bail!("bad hello: {e}"),
            },
            Some(Ok(Message::Ping(_))) => {
                tokio::time::timeout(WRITE_TIMEOUT, sink.flush())
                    .await
                    .map_err(|_| anyhow::anyhow!("write timed out"))??;
            }
            Some(Ok(Message::Close(_))) | None => anyhow::bail!("closed before hello"),
            Some(Err(e)) => anyhow::bail!("before hello: {e}"),
            Some(Ok(_)) => {}
        }
    }
}

async fn run(state: SharedState, peer: EdgePeer, socket: WebSocket) -> anyhow::Result<()> {
    let (mut sink, mut stream) = socket.split();
    let hello = match tokio::time::timeout(HELLO_WAIT, wait_hello(&mut sink, &mut stream)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            close(&mut sink, 1008, "hello expected").await;
            return Err(e);
        }
        Err(_) => {
            close(&mut sink, 1008, "no hello in time").await;
            anyhow::bail!("no hello in time");
        }
    };
    let reg = Registered {
        id: peer.edge_id.clone(),
        name: peer.edge_name.clone(),
        fingerprint: peer.fingerprint.clone(),
    };
    let hub = &state.edges.hub;
    if hub.registered(&reg.fingerprint).is_none() {
        // A key registered a moment ago may not be in the registry yet: ask the database.
        let generation = hub.registry_generation();
        if let Ok(Some((id, name))) = crate::edges::by_key(&state.db, &reg.fingerprint).await
            && id == reg.id
        {
            hub.note_registered(
                &Registered {
                    id,
                    name,
                    fingerprint: reg.fingerprint.clone(),
                },
                generation,
            );
        }
    }
    let boot = hello.boot.clone();
    // api.md §1 Key change: a key replaced, or an edge deleted, while this session waited for
    // its hello gets no session (and so can't replace the edge's real one). README §2, Bounded:
    // each hello starts a session (a boot, a transaction); the edge's registered key gets a
    // capped rate of them (taken only once the key is checked), and retries with its backoff.
    let mut handle = match hub.register(&reg.id, &reg.fingerprint, peer.addr, &boot) {
        Ok(h) => h,
        Err(Refused::NotRegistered) => {
            close(&mut sink, 1008, "this key is no longer registered").await;
            anyhow::bail!("the edge's key changed or the edge was deleted before its hello");
        }
        Err(Refused::TooManyHellos) => {
            close(&mut sink, 1013, "too many sessions; retry later").await;
            anyhow::bail!("hello over the edge's rate");
        }
    };
    let result = session(
        &state,
        &peer,
        &reg,
        &boot,
        hello,
        &mut handle,
        &mut sink,
        &mut stream,
    )
    .await;
    state.edges.hub.unregister(&reg.id, handle.id);
    crate::edges::status::edge_status_event(&state, &reg.id, "session_ended");
    result
}

#[expect(
    clippy::too_many_arguments,
    reason = "the session's registration and the socket halves the caller split"
)]
async fn session(
    state: &SharedState,
    peer: &EdgePeer,
    reg: &Registered,
    boot: &str,
    hello: Hello,
    handle: &mut crate::edges::hub::SessionHandle,
    sink: &mut Sink,
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
) -> anyhow::Result<()> {
    match crate::edges::status::on_hello(state, reg, handle.id, peer.addr, hello).await {
        Ok(true) => {}
        Ok(false) => {
            close(sink, 1000, "no longer the edge's session").await;
            return Ok(());
        }
        Err(e) => {
            close(sink, 1011, "core could not store the hello").await;
            anyhow::bail!("storing the hello: {e}");
        }
    }
    let welcome = SessionMessage::Welcome(Welcome {
        core_version: crate::VERSION.to_string(),
        edge_id: reg.id.clone(),
        edge_name: reg.name.clone(),
        server_time: jiff::Timestamp::now(),
    });
    send_json(sink, &welcome).await?;
    tracing::info!(edge = %reg.id, addr = %peer.addr, "edge session up");

    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + PING_EVERY, PING_EVERY);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_rx = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = handle.close.cancelled() => {
                close(sink, 1000, "replaced by a newer session").await;
                return Ok(());
            }
            _ = state.shutdown.cancelled() => {
                close(sink, 1001, "core is stopping").await;
                return Ok(());
            }
            r = handle.changed.changed() => {
                if r.is_err() {
                    return Ok(());
                }
                let etag = handle.changed.borrow_and_update().clone();
                if let Some(etag) = etag {
                    send_json(sink, &SessionMessage::Changed(Changed { etag })).await?;
                }
            }
            _ = ping.tick() => {
                if last_rx.elapsed() > SILENCE {
                    anyhow::bail!("nothing from the edge for {:?}", last_rx.elapsed());
                }
                send(sink, Message::Ping(Default::default())).await?;
            }
            m = stream.next() => {
                last_rx = tokio::time::Instant::now();
                match m {
                    Some(Ok(Message::Text(t))) => match messages::decode(t.as_str()) {
                        Ok(Incoming::Heartbeat(hb)) => {
                            match crate::edges::status::on_heartbeat(state, reg, handle.id, boot, *hb).await {
                                Ok(true) => {}
                                Ok(false) => {
                                    close(sink, 1000, "no longer the edge's session").await;
                                    return Ok(());
                                }
                                Err(e) => tracing::warn!(edge = %reg.id, error = %e, "cannot store a heartbeat"),
                            }
                        }
                        // One hello per session; other types change nothing.
                        Ok(Incoming::Hello(_)) | Ok(Incoming::Other) => {}
                        Err(e) => tracing::debug!(edge = %reg.id, "ignoring a bad session message: {e}"),
                    },
                    Some(Ok(Message::Ping(_))) => {
                        tokio::time::timeout(WRITE_TIMEOUT, sink.flush())
                            .await
                            .map_err(|_| anyhow::anyhow!("write timed out"))??;
                    }
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Err(e)) => anyhow::bail!("{e}"),
                    Some(Ok(_)) => {}
                }
            }
        }
    }
}
