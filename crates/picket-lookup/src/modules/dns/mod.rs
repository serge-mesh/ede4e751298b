//! `dns` (providers.md §5): asks a filtering resolver, such as Quad9 or NextDNS, whether it
//! blocks a name, and takes only the verdict from its answer. The answer never reaches a client
//! and never enters the DNS cache (edge.md §4).
//!
//! - **Transport:** one per provider (`dot` default, `doh`, `udp`, `tcp`), so an encrypted
//!   provider never falls back to plain DNS. 1–8 servers by IP, tried in order: a connect
//!   failure, an invalid answer or no answer within the per-server timeout ([`server_budget`]:
//!   [`SERVER_TIMEOUT`], or less to fit the time the call has left) moves on to the next until
//!   the caller drops the call, and a server that failed (one being asked when the call is
//!   dropped included) is skipped for 30 s while another works. A truncated UDP answer is
//!   retried over TCP within the same server's timeout; a truncated answer over a stream is
//!   invalid.
//! - **Query:** picket-wire's upstream query writer: the name with `qtype` (`A` or `AAAA`), RD, a
//!   random ID, an OPT with DO and CD clear, no ECS, padding to 128 bytes on `dot` and `doh`.
//! - **Answer:** checked like an upstream answer (ID, question, structure; edge.md §7) and read
//!   with picket-wire's lookup facts; its TTLs are ignored.
//! - **Rules, detail, self-test, presets:** [`config`], [`rules`], [`detail`], [`presets`].

pub mod config;
pub mod detail;
pub mod presets;
pub mod rules;

use std::sync::Mutex;
use std::time::Duration;

use anyhow::anyhow;
use picket_api::edge_config::UpstreamProtocol;
use picket_wire::answer::{Invalid, SentQuery, is_truncated_response};
use picket_wire::facts::{LookupFacts, lookup_answer_facts};
use picket_wire::name::QName;
use picket_wire::types::class;
use picket_wire::upstream::{QueryParams, random_query_id, write_query};
use serde_json::Value;
use tokio::time::Instant;

use crate::ctx::{DnsClientError, DnsServer, LookupCtx};
use crate::module::{Answer, LookupError, LookupModule, Preset, SelfTest};

pub use config::{Config, PLAIN_DNS_WARNING, RawConfig};

/// The module id.
pub const ID: &str = "dns";
/// How long one server gets before the next is tried, when the call has the time.
pub const SERVER_TIMEOUT: Duration = Duration::from_millis(1500);
/// The least a server gets while the call has at least that long left.
pub const MIN_SERVER_TIMEOUT: Duration = Duration::from_millis(100);
/// How long a server that failed is skipped while another works.
pub const SKIP_FAILED: Duration = Duration::from_secs(30);
/// Room for the largest query: a 255-byte name, padded to a multiple of 128.
const QUERY_BUF: usize = 512;

#[derive(Default)]
pub struct Module;

/// Per-provider record of servers that failed recently (kept in the provider's `LookupCtx`).
#[derive(Debug, Default)]
pub struct ServerHealth(Mutex<Vec<Option<Instant>>>);

impl ServerHealth {
    /// Server indexes in the order to try: those not skipped, in config order, then the skipped
    /// ones, in config order (tried only when every other one failed).
    pub fn order(&self, n: usize, now: Instant) -> Vec<usize> {
        let mut g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        g.resize(n, None);
        let skipped = |i: usize| g.get(i).copied().flatten().is_some_and(|until| now < until);
        let mut out: Vec<usize> = (0..n).filter(|&i| !skipped(i)).collect();
        out.extend((0..n).filter(|&i| skipped(i)));
        out
    }

    pub fn failed(&self, i: usize, now: Instant) {
        let mut g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(slot) = g.get_mut(i) {
            *slot = Some(now + SKIP_FAILED);
        }
    }

    pub fn ok(&self, i: usize) {
        let mut g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(slot) = g.get_mut(i) {
            *slot = None;
        }
    }
}

/// Why one server gave no valid answer.
#[derive(Debug, thiserror::Error)]
pub enum AskError {
    #[error("{0}")]
    Client(#[from] DnsClientError),
    /// No answer within the per-server timeout (ms).
    #[error("no answer within {0} ms")]
    Timeout(u128),
    #[error("invalid answer: {0}")]
    Invalid(#[from] Invalid),
    /// TC set over a stream (TCP, DoT, DoH, or the TCP retry of a truncated UDP answer): not a
    /// whole answer, so not a valid one (providers.md §5 "Transport").
    #[error("invalid answer: truncated over {0}")]
    Truncated(&'static str),
    #[error("couldn't write the query")]
    Query,
}

/// How long the next server gets (providers.md §5 "Transport": "no answer within a per-server
/// timeout moves on to the next until the caller drops the call"): [`SERVER_TIMEOUT`], cut to
/// fit the call's [`LookupCtx::deadline`]. While other servers remain, half the time left (at
/// least [`MIN_SERVER_TIMEOUT`] when that much is left), so the first, preferred, server gets
/// the most and a silent one still leaves time for the next; the last server gets all of it.
/// Zero once the deadline has passed.
pub fn server_budget(now: Instant, deadline: Option<Instant>, last: bool) -> Duration {
    let Some(deadline) = deadline else {
        return SERVER_TIMEOUT;
    };
    let left = deadline.saturating_duration_since(now);
    let share = if last {
        left
    } else {
        (left / 2).max(MIN_SERVER_TIMEOUT.min(left))
    };
    share.min(SERVER_TIMEOUT)
}

/// Asks one server within `budget` (UDP's TCP retry included) and checks its answer.
pub async fn ask(
    ctx: &LookupCtx,
    cfg: &Config,
    server: &DnsServer,
    qname: &QName,
    budget: Duration,
) -> Result<LookupFacts, AskError> {
    let until = Instant::now() + budget;
    let id = random_query_id();
    let params = QueryParams {
        id,
        cd: false,
        do_bit: false,
        pad: cfg.transport.is_encrypted(),
    };
    let mut buf = [0u8; QUERY_BUF];
    let n =
        write_query(&mut buf, qname.as_name(), cfg.qtype, class::IN, &params).map_err(|_| AskError::Query)?;
    let query = buf.get(..n).ok_or(AskError::Query)?;
    let mut answer = send(ctx, server, query, until, budget).await?;
    let mut transport = cfg.transport;
    // RFC 7766 §5: a truncated UDP answer is retried over TCP before it is checked.
    if transport == UpstreamProtocol::Udp && is_truncated_response(&answer, id) {
        let tcp = DnsServer {
            transport: UpstreamProtocol::Tcp,
            ..server.clone()
        };
        transport = UpstreamProtocol::Tcp;
        answer = send(ctx, &tcp, query, until, budget).await?;
    }
    // Over a stream TC has no use: a server that sets it didn't send the whole answer. Taking
    // it as valid would read a cut answer (often an empty NOERROR) as Clean.
    if is_truncated_response(&answer, id) {
        return Err(AskError::Truncated(detail::transport_text(transport)));
    }
    let sent = SentQuery {
        id,
        qname: qname.as_name(),
        qtype: cfg.qtype,
        qclass: class::IN,
    };
    Ok(lookup_answer_facts(&answer, &sent)?)
}

/// Sends one query, answered by `until` (the server's timeout, `budget` long).
async fn send(
    ctx: &LookupCtx,
    server: &DnsServer,
    query: &[u8],
    until: Instant,
    budget: Duration,
) -> Result<Vec<u8>, AskError> {
    let left = until.saturating_duration_since(Instant::now());
    let timed_out = AskError::Timeout(budget.as_millis());
    if left.is_zero() {
        return Err(timed_out);
    }
    match tokio::time::timeout(left, ctx.dns().query(server, query, left)).await {
        Ok(r) => Ok(r?),
        Err(_) => Err(timed_out),
    }
}

/// Marks the server being asked failed if the call is dropped meanwhile (the caller ran out of
/// `async_timeout_ms`, or the provider was dropped), so the next call skips it.
struct Asking<'a> {
    health: &'a ServerHealth,
    index: usize,
    done: bool,
}

impl Drop for Asking<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.health.failed(self.index, Instant::now());
        }
    }
}

#[async_trait::async_trait]
impl LookupModule for Module {
    fn id(&self) -> &'static str {
        ID
    }

    fn config_schema(&self) -> schemars::Schema {
        schemars::schema_for!(RawConfig)
    }

    async fn lookup(&self, ctx: &LookupCtx, cfg: &Value, name: &str) -> Result<Answer, LookupError> {
        let cfg = ctx
            .parsed::<Config>(cfg)
            .map_err(|e| LookupError::Other(anyhow!("invalid dns config: {e}")))?;
        let qname =
            QName::from_text(name).map_err(|_| LookupError::Other(anyhow!("the name can't be queried")))?;
        let health = ctx.state::<ServerHealth>();
        let mut last = String::new();
        let order = health.order(cfg.servers.len(), Instant::now());
        let count = order.len();
        for (k, i) in order.into_iter().enumerate() {
            let Some(server) = cfg.servers.get(i) else {
                continue;
            };
            let budget = server_budget(Instant::now(), ctx.deadline(), k + 1 == count);
            if budget.is_zero() {
                // The caller is about to drop the call: no server is asked for no time.
                if last.is_empty() {
                    last = "out of time".into();
                }
                break;
            }
            let mut asking = Asking {
                health: &health,
                index: i,
                done: false,
            };
            let asked = ask(ctx, &cfg, &server.dns, &qname, budget).await;
            asking.done = true;
            match asked {
                Ok(facts) => {
                    health.ok(i);
                    let (verdict, rule) = rules::decide(&cfg, &facts);
                    let detail = detail::build(server, cfg.transport, &facts, rule);
                    return Ok(Answer {
                        verdict,
                        detail: Some(detail),
                    });
                }
                Err(e) => {
                    health.failed(i, Instant::now());
                    last = format!("{}: {e}", server.label);
                }
            }
        }
        // No valid answer: an error, for the breaker and retries.
        Err(LookupError::Failed(anyhow!(
            "no valid answer from any server (last: {last})"
        )))
    }

    fn self_test(&self, cfg: &Value) -> Option<SelfTest> {
        serde_json::from_value::<Config>(cfg.clone())
            .ok()
            .and_then(|c| c.self_test)
    }

    fn presets(&self) -> Vec<Preset> {
        presets::presets()
    }
}

#[cfg(test)]
mod tests;
