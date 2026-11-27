//! Test doubles (feature `testkit`): mock HTTP and DNS server clients that record what they were
//! sent, a manual wall clock, and a scripted module whose behaviour a closure decides.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use picket_api::time::Timestamp;
use serde_json::Value;

use crate::ctx::{
    Clock, Connections, DnsClientError, DnsServer, DnsServerClient, HttpClient, HttpError, HttpRequest,
    HttpResponse,
};
use crate::module::{Answer, LookupError, LookupModule, SelfTest};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

type HttpFn = dyn Fn(&HttpRequest) -> Result<HttpResponse, HttpError> + Send + Sync;

/// An HTTP client answering from a closure, after an optional delay.
pub struct MockHttp {
    respond: Box<HttpFn>,
    delay: Duration,
    pub requests: Mutex<Vec<HttpRequest>>,
}

impl MockHttp {
    pub fn new(
        respond: impl Fn(&HttpRequest) -> Result<HttpResponse, HttpError> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            respond: Box::new(respond),
            delay: Duration::ZERO,
            requests: Mutex::new(Vec::new()),
        })
    }

    pub fn with_delay(
        delay: Duration,
        respond: impl Fn(&HttpRequest) -> Result<HttpResponse, HttpError> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            respond: Box::new(respond),
            delay,
            requests: Mutex::new(Vec::new()),
        })
    }

    /// A response with this status, headers and body.
    pub fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> HttpResponse {
        let mut map = http::HeaderMap::new();
        for (k, v) in headers {
            if let (Ok(k), Ok(v)) = (
                http::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(v),
            ) {
                map.append(k, v);
            }
        }
        HttpResponse {
            status,
            headers: map,
            body: body.to_vec(),
        }
    }

    pub fn sent(&self) -> Vec<HttpRequest> {
        lock(&self.requests).clone()
    }
}

#[async_trait::async_trait]
impl HttpClient for MockHttp {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        lock(&self.requests).push(req.clone());
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let resp = (self.respond)(&req)?;
        if resp.body.len() > req.max_body {
            return Err(HttpError::BodyTooLarge { limit: req.max_body });
        }
        Ok(resp)
    }
}

type DnsFn = dyn Fn(&DnsServer, &[u8]) -> Result<Vec<u8>, DnsClientError> + Send + Sync;

/// A DNS server client answering from a closure; `delays` holds per-IP delays.
pub struct MockDns {
    respond: Box<DnsFn>,
    pub delays: Mutex<Vec<(std::net::IpAddr, Duration)>>,
    pub queries: Mutex<Vec<(DnsServer, Vec<u8>)>>,
}

impl MockDns {
    pub fn new(
        respond: impl Fn(&DnsServer, &[u8]) -> Result<Vec<u8>, DnsClientError> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            respond: Box::new(respond),
            delays: Mutex::new(Vec::new()),
            queries: Mutex::new(Vec::new()),
        })
    }

    pub fn delay(&self, ip: std::net::IpAddr, d: Duration) {
        lock(&self.delays).push((ip, d));
    }

    pub fn sent(&self) -> Vec<(DnsServer, Vec<u8>)> {
        lock(&self.queries).clone()
    }
}

#[async_trait::async_trait]
impl DnsServerClient for MockDns {
    async fn query(
        &self,
        server: &DnsServer,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsClientError> {
        lock(&self.queries).push((server.clone(), query.to_vec()));
        let delay = lock(&self.delays)
            .iter()
            .find(|(ip, _)| *ip == server.ip)
            .map(|(_, d)| *d);
        if let Some(d) = delay {
            if d >= timeout {
                tokio::time::sleep(timeout).await;
                return Err(DnsClientError::Timeout);
            }
            tokio::time::sleep(d).await;
        }
        (self.respond)(server, query)
    }
}

/// Connections from mock clients.
pub fn connections(http: Arc<dyn HttpClient>, dns: Arc<dyn DnsServerClient>) -> Connections {
    Connections { http, dns }
}

/// A wall clock tests set by hand, synchronised unless a test says otherwise.
#[derive(Debug)]
pub struct ManualClock(Mutex<Timestamp>, std::sync::atomic::AtomicBool);

impl ManualClock {
    pub fn new(t: Timestamp) -> Arc<Self> {
        Arc::new(Self(Mutex::new(t), std::sync::atomic::AtomicBool::new(true)))
    }

    /// Sets what [`Clock::synced`] answers.
    pub fn set_synced(&self, synced: bool) {
        self.1.store(synced, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn set(&self, t: Timestamp) {
        *lock(&self.0) = t;
    }

    pub fn advance(&self, d: Duration) {
        let mut g = lock(&self.0);
        *g = g.checked_add(d).unwrap_or(Timestamp::MAX);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        *lock(&self.0)
    }

    fn synced(&self) -> bool {
        self.1.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The future a [`ScriptedModule`]'s closure returns.
pub type ScriptFuture = Pin<Box<dyn Future<Output = Result<Answer, LookupError>> + Send>>;
type ScriptFn = dyn Fn(Value, String, u64) -> ScriptFuture + Send + Sync;

/// A module whose `lookup` is a closure of (resolved config, name, call number from 0).
pub struct ScriptedModule {
    id: &'static str,
    script: Box<ScriptFn>,
    self_test: Option<SelfTest>,
    pub calls: AtomicU64,
    pub names: Mutex<Vec<String>>,
}

impl ScriptedModule {
    pub fn new(
        id: &'static str,
        script: impl Fn(Value, String, u64) -> ScriptFuture + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            script: Box::new(script),
            self_test: None,
            calls: AtomicU64::new(0),
            names: Mutex::new(Vec::new()),
        })
    }

    pub fn with_self_test(
        id: &'static str,
        test: SelfTest,
        script: impl Fn(Value, String, u64) -> ScriptFuture + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            script: Box::new(script),
            self_test: Some(test),
            calls: AtomicU64::new(0),
            names: Mutex::new(Vec::new()),
        })
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl LookupModule for ScriptedModule {
    fn id(&self) -> &'static str {
        self.id
    }

    fn config_schema(&self) -> schemars::Schema {
        schemars::json_schema!({"type": "object"})
    }

    async fn lookup(
        &self,
        _ctx: &crate::ctx::LookupCtx,
        cfg: &Value,
        name: &str,
    ) -> Result<Answer, LookupError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.names).push(name.to_owned());
        (self.script)(cfg.clone(), name.to_owned(), n).await
    }

    fn self_test(&self, _cfg: &Value) -> Option<SelfTest> {
        self.self_test.clone()
    }
}
