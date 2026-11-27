//! The validator's network path (core.md §8 "Resolver path"): every query the adapter can't
//! answer from the logged wire goes over DoH to an edge DoH listener — `dnssec.listener`, or by
//! default the first DoH listener on a connected edge — by IP with the listener's TLS name,
//! trusting the LAN CA, at `/dns-query/dnssec-validator`. That path names the system profile
//! `dnssec-validator`, which admits only `dnssec.source_ips` and sees unfiltered data.
//!
//! The DoH client is core's `DnsServerClient` (`lookups::clients::CoreDns`), the one `dns` lookup
//! providers use. A connect or TLS failure means the listener isn't reachable (the item waits);
//! anything after the connection (HTTP 403, timeout, a bad answer) is a failed request (retried
//! with backoff). After a connect failure the resolver says "unreachable" at once for
//! [`DOWN_FOR`], so a waiting queue doesn't knock on a dead listener for every item.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_net::proto::rr::{Name, RecordType};
use picket_api::edge_config::UpstreamProtocol;
use picket_lookup::{DnsClientError, DnsServer, DnsServerClient};

use super::validator::{ChainResolver, ResolveError, chain_query};
use crate::config::model::{ListenerDef, Model};
use crate::state::AppState;
use picket_api::edge_config::ListenerProto;

/// The DoH path that names the `dnssec-validator` profile (core.md §8).
pub const VALIDATOR_PATH: &str = "/dns-query/dnssec-validator";
/// One request's timeout.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long "unreachable" is remembered after every listener failed to connect.
pub const DOWN_FOR: Duration = Duration::from_secs(10);

/// The DoH targets for the validator, in order: the configured listener, or every DoH listener
/// with a managed TLS name, each on the edges it is assigned to (connected edges first).
pub fn targets(model: &Model, state: &AppState) -> Vec<DnsServer> {
    // The LAN CA's roots: edge listeners' certificates come from the current one, or from a
    // previous one until the edge has re-issued them after a rotation (core.md §8, §11).
    let lanca = state.lanca.load().trust_pem();
    let settings = &model.settings;
    let listeners: Vec<&ListenerDef> = match &settings.dnssec.listener {
        Some(id) => model.listeners.get(id).into_iter().collect(),
        None => model
            .listeners
            .values()
            .filter(|l| l.proto == ListenerProto::Doh)
            .collect(),
    };
    let mut connected = Vec::new();
    let mut others = Vec::new();
    for l in listeners {
        if l.proto != ListenerProto::Doh {
            continue;
        }
        let Some(name) = l.tls.as_ref().and_then(|t| t.managed.clone()) else {
            continue;
        };
        let Ok(bind) = l.bind.parse::<SocketAddr>() else {
            continue;
        };
        for edge in &l.edges {
            let session = state.edges.hub.session(edge);
            let ip: Option<IpAddr> = l
                .ips
                .first()
                .copied()
                .or_else(|| (!bind.ip().is_unspecified()).then(|| bind.ip()))
                .or_else(|| {
                    session
                        .as_ref()
                        .and_then(|s| s.addr.parse::<SocketAddr>().ok())
                        .map(|a| a.ip().to_canonical())
                });
            let Some(ip) = ip else { continue };
            let t = DnsServer {
                transport: UpstreamProtocol::Doh,
                ip,
                port: bind.port(),
                tls_host: Some(name.clone()),
                trust_store: Some(lanca.clone()),
                path: Some(VALIDATOR_PATH.into()),
            };
            if session.is_some() {
                connected.push(t);
            } else if settings.dnssec.listener.is_some() {
                // A listener named by hand is tried even on an edge without a session.
                others.push(t);
            }
        }
    }
    connected.dedup();
    connected.extend(others);
    connected
}

/// The production resolver: DoH to an edge listener.
pub struct EdgeDoh {
    state: Weak<AppState>,
    client: crate::lookups::clients::CoreDns,
    down_until: Mutex<Option<Instant>>,
    /// The target that answered last: tried first.
    last: Mutex<Option<DnsServer>>,
}

impl EdgeDoh {
    pub fn new(state: Weak<AppState>, opts: &crate::modules::download::client::HttpOptions) -> Self {
        Self {
            state,
            client: crate::lookups::clients::CoreDns::new(opts),
            down_until: Mutex::new(None),
            last: Mutex::new(None),
        }
    }
}

#[async_trait]
impl ChainResolver for EdgeDoh {
    async fn query(&self, qname: &Name, qtype: RecordType) -> Result<Vec<u8>, ResolveError> {
        if let Ok(g) = self.down_until.lock()
            && g.is_some_and(|t| Instant::now() < t)
        {
            return Err(ResolveError::Unreachable(
                "no edge DoH listener answered recently".into(),
            ));
        }
        let Some(state) = self.state.upgrade() else {
            return Err(ResolveError::Unreachable("core is stopping".into()));
        };
        let model = state
            .analysis
            .model(&state)
            .await
            .map_err(|e| ResolveError::Unreachable(format!("cannot read the configuration: {e}")))?;
        let mut targets = targets(&model, &state);
        if let Some(last) = self.last.lock().ok().and_then(|g| g.clone())
            && let Some(i) = targets.iter().position(|t| *t == last)
        {
            let t = targets.remove(i);
            targets.insert(0, t);
        }
        if targets.is_empty() {
            return Err(ResolveError::Unreachable(
                "no DoH listener with a managed TLS name on a connected edge".into(),
            ));
        }
        let query = chain_query(qname, qtype).map_err(ResolveError::Failed)?;
        let mut last_err = String::new();
        for t in targets.iter().take(4) {
            match self.client.query(t, &query, REQUEST_TIMEOUT).await {
                Ok(answer) => {
                    if let Ok(mut g) = self.last.lock() {
                        *g = Some(t.clone());
                    }
                    // The answer must be the reply to this query (same id, a response).
                    if answer.len() < 12 || answer.get(..2) != query.get(..2) || answer[2] & 0x80 == 0 {
                        return Err(ResolveError::Failed(
                            "an answer that isn't the reply to the query".into(),
                        ));
                    }
                    return Ok(answer);
                }
                Err(DnsClientError::Connect(e)) => {
                    last_err = format!("{}:{}: {e}", t.ip, t.port);
                    continue;
                }
                Err(DnsClientError::Timeout) => {
                    return Err(ResolveError::Failed(format!("{}:{} timed out", t.ip, t.port)));
                }
                Err(e) => return Err(ResolveError::Failed(format!("{}:{}: {e}", t.ip, t.port))),
            }
        }
        if let Ok(mut g) = self.down_until.lock() {
            *g = Some(Instant::now() + DOWN_FOR);
        }
        Err(ResolveError::Unreachable(last_err))
    }
}
