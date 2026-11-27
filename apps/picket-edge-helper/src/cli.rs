//! `picket-edge-helper disable | enable` (edge.md §15): connect to the socket as root, send the
//! request, print the result.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::{Bytes, BytesMut};
use picket_api::helper::{ApplyResponse, HelperError, kind};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;
use tokio_util::codec::{Decoder, Encoder};

use crate::server::codec;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// An `apply`-like request may wait on the xtables lock for both families.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(150);

#[derive(Deserialize)]
struct Head {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    id: Option<u64>,
}

#[derive(Deserialize)]
struct Body<T> {
    data: T,
}

const CLOSED: &str = "the helper closed the connection (only root and the edge user may connect)";

fn closed(e: std::io::Error) -> anyhow::Error {
    match e.kind() {
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => anyhow::anyhow!(CLOSED),
        _ => e.into(),
    }
}

/// Sends `disable` or `enable` and returns the helper's answer.
pub async fn control(socket: &Path, what: &str) -> anyhow::Result<ApplyResponse> {
    let mut stream = timeout(CONNECT_TIMEOUT, UnixStream::connect(socket))
        .await
        .context("timed out connecting to the helper")?
        .with_context(|| format!("cannot connect to {}", socket.display()))?;
    let req = serde_json::to_vec(&serde_json::json!({"type": what, "id": 1, "data": {}}))?;
    let mut codec = codec();
    let mut out = BytesMut::new();
    codec.encode(Bytes::from(req), &mut out)?;
    stream.write_all(&out).await.map_err(closed)?;
    let mut buf = BytesMut::with_capacity(4096);
    let read = async {
        loop {
            if let Some(f) = codec.decode(&mut buf)? {
                let head: Head = serde_json::from_slice(&f).context("malformed answer")?;
                if head.id != Some(1) {
                    continue; // an event
                }
                if head.kind == kind::ERROR {
                    let e: Body<HelperError> = serde_json::from_slice(&f)?;
                    bail!("{}: {}", e.data.code, e.data.message);
                }
                let r: Body<ApplyResponse> = serde_json::from_slice(&f).context("malformed answer")?;
                return Ok(r.data);
            }
            if stream.read_buf(&mut buf).await.map_err(closed)? == 0 {
                bail!(CLOSED);
            }
        }
    };
    timeout(ANSWER_TIMEOUT, read)
        .await
        .context("the helper did not answer")?
}
