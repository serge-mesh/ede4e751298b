//! One connection to picket-edge-helper (edge-firewall.md §4 "Socket"): length-delimited JSON
//! frames (`LengthDelimitedCodec`, 1 MiB maximum both ways), each `{type, id?, data}`; a response
//! repeats its request's `id`, events have none. One request in flight at a time.
//!
//! The helper is untrusted as seen by the edge (README §2): frames are bounded, decoded into typed
//! data, and a response that doesn't decode is an error, never a panic.

use std::path::Path;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use picket_api::helper::{Frame, HelperError, MAX_FRAME, kind};

/// Why a request failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnError {
    /// The socket failed or closed, or no response came in time: reconnect.
    Io(String),
    /// The helper answered with an error.
    Helper { code: String, message: String },
    /// The response doesn't decode.
    Invalid(String),
}

impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnError::Io(m) => write!(f, "helper connection: {m}"),
            ConnError::Helper { code, message } => write!(f, "helper refused ({code}): {message}"),
            ConnError::Invalid(m) => write!(f, "helper response: {m}"),
        }
    }
}

/// A framed connection.
pub struct Conn {
    io: Framed<UnixStream, LengthDelimitedCodec>,
    next_id: u64,
    /// The helper's pid (`SO_PEERCRED`), for its CPU time and RSS (api.md §3).
    pub pid: Option<u32>,
}

/// Parses one frame (fuzzed: the helper is untrusted).
pub fn parse_frame(b: &[u8]) -> Result<Frame, String> {
    if b.len() > MAX_FRAME {
        return Err("frame too large".into());
    }
    serde_json::from_slice::<Frame>(b).map_err(crate::diag::cap)
}

impl Conn {
    /// Connects within `timeout`.
    pub async fn connect(path: &Path, timeout: Duration) -> Result<Conn, ConnError> {
        let s = tokio::time::timeout(timeout, UnixStream::connect(path))
            .await
            .map_err(|_| ConnError::Io("connect timed out".into()))?
            .map_err(|e| ConnError::Io(crate::diag::cap(e)))?;
        let pid = s
            .peer_cred()
            .ok()
            .and_then(|c| c.pid())
            .and_then(|p| u32::try_from(p).ok());
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(MAX_FRAME)
            .new_codec();
        Ok(Conn {
            io: Framed::new(s, codec),
            next_id: 1,
            pid,
        })
    }

    /// Sends a request and waits for its response, handing every event met meanwhile to
    /// `on_event`. `timeout` bounds the whole exchange.
    pub async fn request<Req: Serialize, Resp: DeserializeOwned>(
        &mut self,
        kind_: &str,
        data: &Req,
        timeout: Duration,
        on_event: &mut (dyn FnMut(Frame) + Send),
    ) -> Result<Resp, ConnError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let frame = Frame::request(kind_, id, data);
        let bytes = serde_json::to_vec(&frame).map_err(|e| ConnError::Invalid(crate::diag::cap(e)))?;
        if bytes.len() > MAX_FRAME {
            return Err(ConnError::Invalid("request over the frame limit".into()));
        }
        let fut = async {
            self.io
                .send(Bytes::from(bytes))
                .await
                .map_err(|e| ConnError::Io(crate::diag::cap(e)))?;
            loop {
                let f = self.read_frame().await?;
                match f.id {
                    None => on_event(f),
                    Some(x) if x == id => return Ok(f),
                    // A response to something else (an earlier request that timed out): skip.
                    Some(_) => {}
                }
            }
        };
        let f = tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ConnError::Io(format!("no response to {kind_} in time")))??;
        if f.kind == kind::ERROR {
            let e: HelperError = f.parse_data().unwrap_or_default();
            return Err(ConnError::Helper {
                code: crate::diag::truncate(&e.code, 64),
                message: crate::diag::truncate(&e.message, 256),
            });
        }
        f.parse_data::<Resp>()
            .map_err(|e| ConnError::Invalid(crate::diag::cap(e)))
    }

    /// Reads the next frame.
    pub async fn read_frame(&mut self) -> Result<Frame, ConnError> {
        match self.io.next().await {
            Some(Ok(b)) => parse_frame(&b).map_err(ConnError::Invalid),
            Some(Err(e)) => Err(ConnError::Io(crate::diag::cap(e))),
            None => Err(ConnError::Io("closed by the helper".into())),
        }
    }
}
