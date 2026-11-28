//! Convergence on the config object (edge.md §13, api.md §2, §4).
//!
//! - The edge fetches `configs/<fp>.json` with `If-None-Match` on each `changed`, after every
//!   (re)connect and every 60 s. An object is verified before use: its id is the BLAKE3 of its
//!   bytes, which must equal the `ETag` when core sends one. Core is untrusted (README §2): an
//!   object is bounded in bytes, values and depth before it is parsed, its logging settings are
//!   range-checked, and parse errors never quote its values (a malformed secret stays out of
//!   the journal and `activation_failed`).
//! - Each request is read on its own, so one malformed entry costs only itself.
//! - Requests (`flush`, `revoked_allows`, `release.install_now`) are applied as soon as an object
//!   carrying them is fetched, without waiting for the rest to activate; ids are compared only for
//!   equality with the last applied one (never by order), recorded in `state.json`, reported as
//!   `applied`. A request that failed is retried on every later round, a 304 included; after a
//!   restart nothing is cached, so the first fetch carries no `If-None-Match` and the object (with
//!   any outstanding request) comes back whole.
//! - The rest goes through the [`Activator`] until the edge runs what the object names, retried
//!   with backoff. `config/<hash>.json` (the last 3) and `state.json` are written only when the
//!   config changes outside `bundles`, `verdict_sets`, `release`, `flush` and `revoked_allows`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use async_trait::async_trait;

use picket_api::edge_api::keys;
use picket_api::edge_config::{EdgeConfig, Flush, ReleaseOffer, RevokedAllows};
use picket_api::logs::{Versions, event_kind};
use picket_api::session::Applied;
use picket_api::time::Timestamp;

use crate::core_client::{ClientError, CoreClient, ObjectReply};
use crate::edge::{ActiveState, ConvergenceStatus, Edge};
use crate::fsutil::{self, WriteOpts};
use crate::hooks::{Activation, ActivationTarget, Activator, RequestHandler};
use crate::logs::fields;
use crate::paths::DataLayout;
use crate::state::{KEEP_CONFIGS, State, StoredConfig};
use crate::update::{InstallDecision, decide_install};

/// Largest config object accepted (README §2 Bounded). A home network's object is far
/// smaller; the shape limits below bound what one this size can cost in RAM.
pub const MAX_CONFIG: u64 = 4 << 20;
/// Most JSON values (scalars, arrays and objects, at any depth) in a config object. Bytes alone
/// don't bound memory: parsed, an empty profile costs ~500 B of `EdgeConfig` and a `0` 32 B of
/// JSON tree, so a 4 MiB object of them would take hundreds of MiB (edge-unifi.md §6:
/// `MemoryMax=768M`). This keeps one parse to a few tens of MiB, with ample room for a real
/// network's clients, profiles and upstreams.
pub const MAX_CONFIG_VALUES: usize = 65_536;
/// Deepest nesting of arrays and objects in a config object (an `EdgeConfig` needs under 10).
pub const MAX_CONFIG_DEPTH: usize = 32;
/// Most `flush.lookups` requests acted on per object, and most ids kept in
/// `applied.flush_lookups` (README §2 Bounded).
pub const MAX_FLUSH_LOOKUPS: usize = 256;
/// Longest lookup provider id a flush request may name.
const MAX_PROVIDER_ID: usize = 128;
/// The top-level fields whose changes aren't a config change (edge.md §2).
pub const RUNTIME_FIELDS: [&str; 5] = ["bundles", "verdict_sets", "release", "flush", "revoked_allows"];

/// The config object without the runtime fields, canonically serialised, and its BLAKE3: the
/// bytes and name of `config/<hash>.json`. Computed on the JSON value, so fields this release
/// doesn't know still count and are kept for a newer release reading the file. Serialised
/// straight from `value`, without a sorted copy of the tree; the bytes equal
/// [`picket_api::ids::canonical_json`] of the stripped value.
pub fn stripped(value: &serde_json::Value) -> (String, Vec<u8>) {
    let bytes = serde_json::to_vec(&Canonical {
        v: value,
        strip: true,
    })
    .unwrap_or_default();
    (picket_api::ids::object_id(&bytes), bytes)
}

/// Serialises a JSON value with object keys sorted, borrowing it (no copy); `strip` leaves out
/// [`RUNTIME_FIELDS`] at the top level.
struct Canonical<'a> {
    v: &'a serde_json::Value,
    strip: bool,
}

impl serde::Serialize for Canonical<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        match self.v {
            serde_json::Value::Object(m) => {
                let mut keys: Vec<&String> = m
                    .keys()
                    .filter(|k| !(self.strip && RUNTIME_FIELDS.contains(&k.as_str())))
                    .collect();
                keys.sort();
                let mut map = s.serialize_map(Some(keys.len()))?;
                for k in keys {
                    if let Some(v) = m.get(k) {
                        map.serialize_entry(k, &Canonical { v, strip: false })?;
                    }
                }
                map.end()
            }
            serde_json::Value::Array(a) => {
                let mut seq = s.serialize_seq(Some(a.len()))?;
                for v in a {
                    seq.serialize_element(&Canonical { v, strip: false })?;
                }
                seq.end()
            }
            other => other.serialize(s),
        }
    }
}

/// Checks a config object's shape before anything is parsed from it: at most
/// [`MAX_CONFIG_VALUES`] values and [`MAX_CONFIG_DEPTH`] levels of nesting (README §2 Bounded:
/// what a parse may cost in RAM). One pass over the bytes; strings are skipped. On malformed
/// JSON the count is still an upper bound, and the parse rejects it anyway.
pub fn check_shape(bytes: &[u8]) -> std::result::Result<(), String> {
    // Values = the root + one per object member (its ':') + one per array element (each ','
    // in an array, plus the first element of a non-empty one).
    let mut values = 1usize;
    let mut stack: Vec<u8> = Vec::new();
    let mut array_opened = false;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        if b.is_ascii_whitespace() {
            continue;
        }
        if std::mem::take(&mut array_opened) && b != b']' {
            values += 1;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                if stack.len() >= MAX_CONFIG_DEPTH {
                    return Err(format!("nested deeper than {MAX_CONFIG_DEPTH} levels"));
                }
                stack.push(b);
                array_opened = b == b'[';
            }
            b'}' | b']' => {
                stack.pop();
            }
            b':' => values += 1,
            b',' if stack.last() == Some(&b'[') => values += 1,
            _ => {}
        }
        if values > MAX_CONFIG_VALUES {
            return Err(format!("more than {MAX_CONFIG_VALUES} values"));
        }
    }
    Ok(())
}

/// A serde_json error as text that never quotes the input (README §2 Secrets: a malformed
/// secret, or any config value, must not reach the journal or an `activation_failed` reason).
/// serde's messages embed the offending value (`invalid type: string "…", expected a map`), and
/// custom ones may too; this keeps the kind, the position and only what comes from the schema.
pub fn json_error(e: &serde_json::Error) -> String {
    use serde_json::error::Category;
    let kind = match e.classify() {
        Category::Io => "unreadable",
        Category::Syntax => "malformed JSON",
        Category::Eof => "truncated JSON",
        Category::Data => "a value of the wrong type or out of range",
    };
    let mut out = format!("{kind} at line {} column {}", e.line(), e.column());
    if e.classify() == Category::Data {
        // Rendered bounded; a message cut short is trusted for nothing.
        let text = crate::diag::cap_to(e, 1024);
        let suffix = format!(" at line {} column {}", e.line(), e.column());
        if let Some(msg) = text.strip_suffix(suffix.as_str()) {
            if msg.starts_with("missing field `") || msg.starts_with("duplicate field `") {
                // Field names come from the schema.
                out.push_str(&format!(" ({msg})"));
            } else if [
                "invalid type: ",
                "invalid value: ",
                "invalid length ",
                "unknown variant ",
            ]
            .iter()
            .any(|p| msg.starts_with(p))
                && let Some((_, expected)) = msg.rsplit_once(", expected ")
            {
                // The schema's part follows the value, so the last ", expected " is the
                // schema's.
                out.push_str(&format!(" (expected {expected})"));
            }
        }
    }
    out
}

/// A verified config object.
#[derive(Clone, Debug)]
pub struct Fetched {
    pub id: String,
    /// The requests it carries, read field by field (edge.md §13: applied even when the rest
    /// doesn't parse).
    pub requests: Arc<Requests>,
    pub config: Result<Arc<EdgeConfig>, String>,
    pub hash: String,
    pub canonical: Arc<Vec<u8>>,
}

impl Fetched {
    /// Verifies and parses an object's bytes. `etag` is core's `ETag`, if any. The shape is
    /// checked first, the JSON tree is built once (for the requests and the stripped hash) and
    /// dropped, and the typed config is parsed straight from the bytes: nothing is copied whole.
    pub fn from_bytes(bytes: &[u8], etag: Option<&str>) -> Result<Self> {
        if bytes.len() as u64 > MAX_CONFIG {
            return Err(anyhow!("config object is over {MAX_CONFIG} bytes"));
        }
        let id = picket_api::ids::object_id(bytes);
        if let Some(e) = etag
            && e != id
        {
            return Err(anyhow!(
                "config object's ETag {:?} isn't its BLAKE3 {id}",
                crate::diag::truncate(e, 80)
            ));
        }
        check_shape(bytes).map_err(|e| anyhow!("config object refused: {e}"))?;
        let (requests, hash, canonical) = {
            let value: serde_json::Value = serde_json::from_slice(bytes)
                .map_err(|e| anyhow!("config object isn't JSON: {}", json_error(&e)))?;
            if !value.is_object() {
                return Err(anyhow!("config object isn't a JSON object"));
            }
            let (hash, canonical) = stripped(&value);
            (requests_of(&value), hash, canonical)
        };
        let config = serde_json::from_slice::<EdgeConfig>(bytes)
            .map_err(|e| json_error(&e))
            .and_then(|c| validate(&c).map(|()| effective(c)));
        Ok(Self {
            id,
            requests: Arc::new(requests),
            config,
            hash,
            canonical: Arc::new(canonical),
        })
    }
}

/// The config the edge runs: without lookup providers and verdict sets no profile attaches
/// `sync` ([`crate::dns::runtime::keep_required_providers`], #44).
fn effective(mut c: EdgeConfig) -> Arc<EdgeConfig> {
    let dropped = crate::dns::runtime::keep_required_providers(&mut c);
    if !dropped.is_empty() {
        tracing::debug!(
            "lookup providers no profile attaches sync, not run: {}",
            crate::diag::truncate(&dropped.join(", "), 256)
        );
    }
    Arc::new(c)
}

/// Checks what the edge will use in paths and comparisons (README §2 Untrusted input: core is
/// untrusted as seen by the edge). Deeper checks of listeners, profiles and upstreams belong to
/// the modules that build them ([`crate::dns::runtime`], [`crate::dns::upstream`]).
pub fn validate(c: &EdgeConfig) -> std::result::Result<(), String> {
    let name_ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 128
            && s != "."
            && s != ".."
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    for (b, head) in &c.bundles {
        if !name_ok(b) || !picket_api::ids::is_object_id(head) {
            return Err(format!(
                "bad bundle head {:?} → {:?}",
                crate::diag::truncate(b, 64),
                crate::diag::truncate(head, 80)
            ));
        }
    }
    for (p, head) in &c.verdict_sets {
        if !name_ok(p) || !picket_api::ids::is_object_id(head) {
            return Err(format!("bad verdict-set head {:?}", crate::diag::truncate(p, 64)));
        }
    }
    for p in c.lookup_providers.keys() {
        if !name_ok(p) {
            return Err(format!(
                "bad lookup provider id {:?}",
                crate::diag::truncate(p, 64)
            ));
        }
    }
    for l in &c.listeners {
        if !name_ok(&l.id) {
            return Err(format!("bad listener id {:?}", crate::diag::truncate(&l.id, 64)));
        }
    }
    if let Some(problem) = crate::logs::logging_problem(&c.logging) {
        return Err(problem);
    }
    Ok(())
}

/// The requests an object carries, read field by field from the JSON, so an object whose config
/// part doesn't parse still delivers its requests (edge.md §13: applied without waiting for the
/// rest of the object).
#[derive(Clone, Debug, Default)]
pub struct Requests {
    pub flush: Flush,
    pub revoked_allows: Option<RevokedAllows>,
    pub release: Option<ReleaseOffer>,
    pub lookup_providers: Vec<String>,
}

pub fn requests_of(v: &serde_json::Value) -> Requests {
    use serde::Deserialize;
    let flush = v.get("flush");
    // Each request on its own (api.md §4): one malformed entry costs only itself.
    let dns = flush
        .and_then(|f| f.get("dns"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let lookups = flush
        .and_then(|f| f.get("lookups"))
        .and_then(serde_json::Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(p, id)| Some((p.clone(), id.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default();
    let revoked_allows = v
        .get("revoked_allows")
        .and_then(serde_json::Value::as_object)
        .map(|r| RevokedAllows {
            id: r
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            allows: r
                .get("allows")
                .and_then(serde_json::Value::as_array)
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
                .unwrap_or_default(),
        });
    Requests {
        flush: Flush { dns, lookups },
        revoked_allows,
        // An install is acted on only when its offer parses whole.
        release: v
            .get("release")
            .and_then(|r| Option::<ReleaseOffer>::deserialize(r).ok().flatten()),
        lookup_providers: v
            .get("lookup_providers")
            .and_then(|m| m.as_object())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default(),
    }
}

/// Keeps `applied.flush_lookups` bounded: providers the object no longer names (requested or
/// attached) lose their entry, and at most [`MAX_FLUSH_LOOKUPS`] stay.
pub fn prune_flush_lookups(applied: &mut std::collections::BTreeMap<String, String>, req: &Requests) {
    applied.retain(|p, _| req.flush.lookups.contains_key(p) || req.lookup_providers.contains(p));
    while applied.len() > MAX_FLUSH_LOOKUPS {
        let Some(k) = applied.keys().next_back().cloned() else {
            break;
        };
        applied.remove(&k);
    }
}

/// Writes `config/<hash>.json` (0600: it holds lookup-provider secrets) if it isn't there.
pub fn store_config_file(layout: &DataLayout, hash: &str, canonical: &[u8]) -> Result<()> {
    let dir = layout.config_dir();
    fsutil::create_dir_all_mode(&dir, 0o700)?;
    let path = dir.join(format!("{hash}.json"));
    if let Ok(b) = fsutil::read_nofollow_bounded(&path, MAX_CONFIG)
        && picket_api::ids::object_id(&b) == hash
    {
        return Ok(());
    }
    fsutil::atomic_write(&path, canonical, WriteOpts::mode(0o600))?;
    Ok(())
}

/// Deletes `config/*.json` files `state.json` no longer lists (edge.md §2).
pub fn delete_unreferenced_configs(layout: &DataLayout, state: &State) {
    let Ok(rd) = std::fs::read_dir(layout.config_dir()) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(hash) = name.to_str().and_then(|n| n.strip_suffix(".json")) else {
            continue;
        };
        if !state.configs.iter().any(|c| c.hash == hash) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// The stored configs that can never run: missing, failing their BLAKE3 hash, or not parsing.
/// A file that can't be read for another reason (permissions, an I/O error) isn't counted: that
/// may pass. Startup drops these from `state.json` and deletes their files, so `have` lists only
/// configs the edge holds (api.md §3).
pub fn unusable_stored(layout: &DataLayout, state: &State) -> Vec<String> {
    let mut out = vec![];
    for sc in &state.configs {
        let path = layout.config_dir().join(format!("{}.json", sc.hash));
        let bad = match fsutil::read_nofollow_bounded(&path, MAX_CONFIG) {
            Ok(b) => {
                picket_api::ids::object_id(&b) != sc.hash
                    || check_shape(&b).is_err()
                    || serde_json::from_slice::<EdgeConfig>(&b).is_err()
            }
            Err(e) => matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidData
            ),
        };
        if bad {
            out.push(sc.hash.clone());
        }
    }
    out
}

/// The stored configs that verify (BLAKE3 of the file = its hash) and parse, newest first
/// (edge.md §3 step 1). A failing one is reported and skipped.
pub fn load_stored(layout: &DataLayout, state: &State) -> Vec<(StoredConfig, Arc<EdgeConfig>, Arc<Vec<u8>>)> {
    let mut out = vec![];
    for sc in &state.configs {
        let path = layout.config_dir().join(format!("{}.json", sc.hash));
        let bytes = match fsutil::read_nofollow_bounded(&path, MAX_CONFIG) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("stored config {}: {}", path.display(), crate::diag::cap(e));
                continue;
            }
        };
        if picket_api::ids::object_id(&bytes) != sc.hash {
            tracing::warn!(
                "stored config {} fails its BLAKE3 check; skipping it",
                path.display()
            );
            continue;
        }
        if let Err(e) = check_shape(&bytes) {
            tracing::warn!("stored config {} refused: {e}", path.display());
            continue;
        }
        match serde_json::from_slice::<EdgeConfig>(&bytes) {
            Ok(c) => out.push((sc.clone(), effective(c), Arc::new(bytes))),
            Err(e) => tracing::warn!(
                "stored config {} doesn't parse: {}",
                path.display(),
                json_error(&e)
            ),
        }
    }
    out
}

/// Records `hash` (stored from `object`) as the newest config, keeping the last 3.
fn push_config(s: &mut State, hash: &str, object: &str) {
    s.configs.retain(|c| c.hash != hash);
    s.configs.insert(
        0,
        StoredConfig {
            hash: hash.to_owned(),
            object: object.to_owned(),
        },
    );
    s.configs.truncate(KEEP_CONFIGS);
}

/// The foundation's minimal activator (`service::start` installs `bundles::EdgeActivator`
/// instead): config-only objects go live at once with a new `versions` block; the logging
/// settings reach the shipper.
pub struct ConfigActivator;

#[async_trait]
impl Activator for ConfigActivator {
    async fn activate(&self, edge: &Edge, t: &ActivationTarget) -> Activation {
        if !t.config.bundles.is_empty() || !t.config.verdict_sets.is_empty() {
            // A config goes live only once every bundle and verdict set it names is active.
            return Activation::Retry {
                stage: "load".into(),
                reason: "this activator doesn't activate bundles or verdict sets".into(),
            };
        }
        let versions = Versions {
            config: picket_api::ids::short_id(&t.config_version).to_owned(),
            ..Default::default()
        };
        let prev = edge.active();
        edge.active.store(Arc::new(ActiveState {
            object_id: Some(t.object_id.clone()),
            config_version: Some(t.config_version.clone()),
            config_hash: Some(t.config_hash.clone()),
            config: Some(Arc::clone(&t.config)),
            versions: Some(Arc::new(versions)),
            bundles: Arc::clone(&prev.bundles),
            dns: prev.dns.clone(),
        }));
        edge.log_control.set_config(t.config.logging);
        Activation::Active
    }
}

/// The foundation's request handler, for edges started without the DNS data path's hooks:
/// flushes succeed at once (nothing is cached); revocations end the allows `allows.json` holds
/// (and their firewall entries).
pub struct DefaultRequests;

#[async_trait]
impl RequestHandler for DefaultRequests {
    async fn flush_dns(&self, _edge: &Edge) -> Result<()> {
        // Nothing to flush without the DNS data path: `dns::activation::DnsRequests` (installed
        // by `service::start`) flushes the cache.
        Ok(())
    }
    async fn flush_lookups(&self, _edge: &Edge, _provider: &str) -> Result<()> {
        Ok(())
    }
    async fn flush_all_lookups(&self, _edge: &Edge) -> Result<()> {
        Ok(())
    }
    async fn revoke_allows(&self, edge: &Edge, list: &RevokedAllows) -> Result<()> {
        // IP allows' set entries follow at once (edge.md §12).
        let b = Arc::clone(&edge.bypass);
        b.revoke(edge, &list.allows, "core").await.map(|_| ())
    }
}

/// Timing of the convergence loop; tests shorten it.
#[derive(Clone, Copy, Debug)]
pub struct Timings {
    pub every: Duration,
    pub retry_min: Duration,
    pub retry_max: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            every: Duration::from_secs(60),
            retry_min: Duration::from_secs(1),
            retry_max: Duration::from_secs(300),
        }
    }
}

/// Runs the newest stored config the activator accepts, at start (edge.md §3 step 5). Returns
/// the hash it runs.
pub async fn start_from_disk(edge: &Edge) -> Option<String> {
    let layout = edge.layout.clone();
    let state = edge.state.get();
    let stored = tokio::task::spawn_blocking(move || load_stored(&layout, &state))
        .await
        .ok()?;
    let newest = stored.first().map(|(sc, _, _)| sc.hash.clone());
    for (sc, cfg, _) in stored {
        let target = ActivationTarget {
            object_id: sc.object.clone(),
            config_version: sc.object.clone(),
            config_hash: sc.hash.clone(),
            config: cfg,
            config_changed: true,
            from_disk: true,
        };
        match edge.hooks.activator().activate(edge, &target).await {
            Activation::Active => {
                if newest.as_deref() != Some(sc.hash.as_str()) {
                    tracing::warn!(
                        "running an older stored config ({}): the newest can't run",
                        picket_api::ids::short_id(&sc.object)
                    );
                }
                return Some(sc.hash);
            }
            Activation::Retry { reason, .. } | Activation::Failed { reason, .. } => {
                tracing::warn!(
                    "stored config {} can't run: {reason}",
                    picket_api::ids::short_id(&sc.object)
                );
            }
        }
    }
    None
}

/// The convergence loop.
pub struct Convergence {
    edge: Arc<Edge>,
    client: Arc<CoreClient>,
    timings: Timings,
    latest: Option<Fetched>,
    /// The object whose contents fully run.
    converged: Option<String>,
    /// An object that can't be built: not retried until core sends another.
    failed: Option<String>,
    last_failure: Option<(String, String, String)>,
    retry_at: Option<Instant>,
    backoff: Duration,
    fetch_backoff: Duration,
    next_fetch: Instant,
    forbidden_logged: bool,
}

impl Convergence {
    pub fn new(edge: Arc<Edge>, client: Arc<CoreClient>, timings: Timings) -> Self {
        Self {
            edge,
            client,
            timings,
            latest: None,
            converged: None,
            failed: None,
            last_failure: None,
            retry_at: None,
            backoff: timings.retry_min,
            fetch_backoff: timings.retry_min,
            next_fetch: Instant::now(),
            forbidden_logged: false,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            let wake = self.retry_at.map_or(self.next_fetch, |r| r.min(self.next_fetch));
            tokio::select! {
                _ = self.edge.fetch_now.notified() => { self.next_fetch = Instant::now(); }
                _ = tokio::time::sleep_until(wake.into()) => {}
            }
            self.round().await;
        }
    }

    /// One round: fetch if due, then apply requests and converge on the latest object.
    pub async fn round(&mut self) {
        if Instant::now() >= self.next_fetch {
            match self.fetch().await {
                Ok(()) => {
                    self.fetch_backoff = self.timings.retry_min;
                    self.next_fetch = Instant::now() + self.timings.every;
                }
                Err(e) => {
                    self.set_error(Some(e.to_string()));
                    self.next_fetch = Instant::now() + self.fetch_backoff;
                    self.fetch_backoff = (self.fetch_backoff * 2).min(self.timings.every);
                }
            }
        }
        let Some(f) = self.latest.clone() else { return };
        if let Err(e) = self.apply_requests(&f).await {
            tracing::warn!("applying requests: {}", crate::diag::cap_chain(&e));
        }
        if self.retry_at.is_none_or(|t| Instant::now() >= t) {
            self.converge(&f).await;
        }
    }

    fn set_error(&self, e: Option<String>) {
        let mut st = ConvergenceStatus::clone(&self.edge.convergence.load());
        st.last_error = e.map(crate::diag::cap);
        self.edge.convergence.store(Arc::new(st));
    }

    async fn fetch(&mut self) -> std::result::Result<(), ClientError> {
        let key = keys::config(&self.edge.identity.fp_path());
        let inm = self.latest.as_ref().map(|f| f.id.clone());
        let reply = match self.client.get_object(&key, inm.as_deref(), MAX_CONFIG).await {
            Ok(r) => r,
            Err(ClientError::Forbidden) => {
                if !self.forbidden_logged {
                    tracing::warn!(
                        "core refuses this edge's config (403): approve key {} on core (Edges → Pending)",
                        self.edge.identity.fingerprint
                    );
                    self.forbidden_logged = true;
                }
                return Err(ClientError::Forbidden);
            }
            Err(e) => return Err(e),
        };
        self.forbidden_logged = false;
        let mut st = ConvergenceStatus::clone(&self.edge.convergence.load());
        st.last_fetch = Some(Timestamp::now());
        st.last_error = None;
        match reply {
            ObjectReply::NotModified => {}
            ObjectReply::Body { bytes, etag } => match Fetched::from_bytes(&bytes, etag.as_deref()) {
                Ok(f) => {
                    st.fetched = Some(f.id.clone());
                    if self.latest.as_ref().is_none_or(|l| l.id != f.id) {
                        // A new object: converge on it now, not after an older retry's backoff.
                        self.retry_at = None;
                        self.backoff = self.timings.retry_min;
                    }
                    self.latest = Some(f);
                }
                Err(e) => {
                    self.edge.convergence.store(Arc::new(st));
                    return Err(ClientError::Invalid(crate::diag::cap_chain(&e)));
                }
            },
        }
        self.edge.convergence.store(Arc::new(st));
        Ok(())
    }

    /// Applies every request whose id differs from the last applied one (edge.md §13).
    pub async fn apply_requests(&mut self, f: &Fetched) -> Result<()> {
        let edge = &self.edge;
        let req = Arc::clone(&f.requests);
        let state = edge.state.get();
        let mut applied: Applied = state.applied.clone();
        let handler = edge.hooks.requests();
        let id_ok = |id: &str| picket_api::ids::is_id64(id);

        if let Some(id) = req.flush.dns.as_deref().filter(|i| id_ok(i))
            && applied.flush_dns.as_deref() != Some(id)
        {
            match handler.flush_dns(edge).await {
                Ok(()) => applied.flush_dns = Some(id.to_owned()),
                Err(e) => tracing::warn!("flush.dns {id}: {}", crate::diag::cap_chain(&e)),
            }
        }
        for (provider, id) in req.flush.lookups.iter().take(MAX_FLUSH_LOOKUPS) {
            if !id_ok(id) || provider.is_empty() || provider.len() > MAX_PROVIDER_ID {
                continue;
            }
            if applied.flush_lookups.get(provider) == Some(id) {
                continue;
            }
            match handler.flush_lookups(edge, provider).await {
                Ok(()) => {
                    applied.flush_lookups.insert(provider.clone(), id.clone());
                }
                Err(e) => tracing::warn!("flush.lookups.{provider} {id}: {}", crate::diag::cap_chain(&e)),
            }
        }
        prune_flush_lookups(&mut applied.flush_lookups, &req);
        if let Some(list) = req.revoked_allows.as_ref().filter(|l| id_ok(&l.id))
            && applied.revoked_allows.as_deref() != Some(list.id.as_str())
        {
            match handler.revoke_allows(edge, list).await {
                Ok(()) => applied.revoked_allows = Some(list.id.clone()),
                Err(e) => tracing::warn!("revoked_allows {}: {}", list.id, crate::diag::cap_chain(&e)),
            }
        }
        match decide_install(
            req.release.as_ref(),
            applied.install_now.as_deref(),
            edge.local.updates_enabled,
            state.rollback_from.as_deref(),
            picket_api::VERSION,
        ) {
            InstallDecision::Ignore => {}
            InstallDecision::AppliedNothing(id) => applied.install_now = Some(id),
            InstallDecision::HandOff(r) => {
                if let Some(offer) = req.release.as_ref() {
                    match edge.hooks.handoff().hand_off(edge, &r, offer).await {
                        Ok(true) => applied.install_now = Some(r.id.clone()),
                        Ok(false) => {}
                        Err(e) => tracing::warn!("install_now {}: {}", r.id, crate::diag::cap_chain(&e)),
                    }
                }
            }
        }
        // `auto_update` (edge.md §14 When): the offered release, with no request id, when the
        // rules allow it and no handoff is pending.
        if let Some(offer) = req.release.as_ref()
            && crate::release::auto_due(edge, offer, state.rollback_from.as_deref())
            && !edge.layout.releases_dir().join("pending.json").exists()
            && let Err(e) = edge.hooks.handoff().auto_update(edge, offer).await
        {
            tracing::warn!("auto-update to {}: {}", offer.version, crate::diag::cap_chain(&e));
        }
        // "Until core offers a different one" (edge.md §14): a new offer lifts the block.
        let clear_rollback = state
            .rollback_from
            .as_ref()
            .is_some_and(|v| req.release.as_ref().is_some_and(|o| &o.version != v));
        if applied != state.applied || clear_rollback {
            edge.state
                .update_async(move |s| {
                    s.applied = applied;
                    if clear_rollback {
                        s.rollback_from = None;
                    }
                })
                .await?;
        }
        Ok(())
    }

    async fn converge(&mut self, f: &Fetched) {
        if self.converged.as_deref() == Some(f.id.as_str()) || self.failed.as_deref() == Some(f.id.as_str()) {
            self.ensure_persisted().await;
            return;
        }
        let edge = Arc::clone(&self.edge);
        let config = match &f.config {
            Ok(c) => Arc::clone(c),
            Err(reason) => {
                self.fail(f, "parse", reason, true);
                return;
            }
        };
        // Read and let go: a snapshot held across the activation would keep every part it
        // replaces alive (bundles.md §6: the next swap waits until the replaced part is freed).
        let (config_changed, config_version) = {
            let active = edge.active();
            let changed = active.config_hash.as_deref() != Some(f.hash.as_str());
            let version = if changed {
                f.id.clone()
            } else {
                active.config_version.clone().unwrap_or_else(|| f.id.clone())
            };
            (changed, version)
        };
        if config_changed {
            let mut st = ConvergenceStatus::clone(&edge.convergence.load());
            st.in_progress = Some(f.id.clone());
            edge.convergence.store(Arc::new(st));
        }
        let target = ActivationTarget {
            object_id: f.id.clone(),
            config_version: config_version.clone(),
            config_hash: f.hash.clone(),
            config,
            config_changed,
            from_disk: false,
        };
        match edge.hooks.activator().activate(&edge, &target).await {
            Activation::Active => {
                if config_changed {
                    if let Err(e) = self.persist(f, &config_version).await {
                        tracing::warn!(
                            "persisting config {}: {}",
                            picket_api::ids::short_id(&f.id),
                            crate::diag::cap_chain(&e)
                        );
                    }
                    edge.logs.event(
                        event_kind::ACTIVATED,
                        fields(&[("config", picket_api::ids::short_id(&config_version).into())]),
                    );
                }
                self.converged = Some(f.id.clone());
                self.failed = None;
                self.last_failure = None;
                self.retry_at = None;
                self.backoff = self.timings.retry_min;
                let mut st = ConvergenceStatus::clone(&edge.convergence.load());
                st.in_progress = None;
                edge.convergence.store(Arc::new(st));
            }
            Activation::Retry { stage, reason } => self.fail(f, &stage, &reason, false),
            Activation::Failed { stage, reason } => self.fail(f, &stage, &reason, true),
        }
    }

    /// Logs `activation_failed` once per (object, stage, reason) and schedules the retry (or
    /// none, for an object that can't be built).
    fn fail(&mut self, f: &Fetched, stage: &str, reason: &str, permanent: bool) {
        let key = (f.id.clone(), stage.to_owned(), reason.to_owned());
        if self.last_failure.as_ref() != Some(&key) {
            tracing::warn!(
                "config {} can't go live ({stage}): {reason}",
                picket_api::ids::short_id(&f.id)
            );
            self.edge.logs.event(
                event_kind::ACTIVATION_FAILED,
                fields(&[
                    ("config", picket_api::ids::short_id(&f.id).into()),
                    ("stage", stage.into()),
                    ("reason", crate::diag::cap(reason).into()),
                ]),
            );
            self.last_failure = Some(key);
        }
        if permanent {
            self.failed = Some(f.id.clone());
            self.retry_at = None;
            let mut st = ConvergenceStatus::clone(&self.edge.convergence.load());
            st.in_progress = None;
            self.edge.convergence.store(Arc::new(st));
        } else {
            self.retry_at = Some(Instant::now() + self.backoff);
            self.backoff = (self.backoff * 2).min(self.timings.retry_max);
        }
    }

    async fn persist(&self, f: &Fetched, config_version: &str) -> Result<()> {
        let layout = self.edge.layout.clone();
        let hash = f.hash.clone();
        let canonical = Arc::clone(&f.canonical);
        tokio::task::spawn_blocking(move || store_config_file(&layout, &hash, &canonical)).await??;
        let hash = f.hash.clone();
        let object = config_version.to_owned();
        self.edge
            .state
            .update_async(move |s| push_config(s, &hash, &object))
            .await?;
        let layout = self.edge.layout.clone();
        let state = self.edge.state.get();
        tokio::task::spawn_blocking(move || delete_unreferenced_configs(&layout, &state)).await?;
        Ok(())
    }

    /// Retries persisting the active config if an earlier write failed.
    async fn ensure_persisted(&self) {
        let active = self.edge.active();
        let (Some(hash), Some(version)) = (active.config_hash.clone(), active.config_version.clone()) else {
            return;
        };
        if self.edge.state.get().configs.first().map(|c| c.hash.as_str()) == Some(hash.as_str()) {
            return;
        }
        if let Some(f) = self.latest.as_ref().filter(|f| f.hash == hash)
            && let Err(e) = self.persist(f, &version).await
        {
            tracing::warn!("persisting config: {}", crate::diag::cap_chain(&e));
        }
    }
}

/// `have.config`: the active config's id first, then the other stored ones, newest first.
pub fn have_configs(active: &ActiveState, state: &State) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    if let Some(v) = &active.config_version {
        out.push(v.clone());
    }
    for c in &state.configs {
        if !out.contains(&c.object) {
            out.push(c.object.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stripped_hash_ignores_runtime_fields_and_keeps_unknown_ones() {
        let a: serde_json::Value =
            serde_json::json!({"listeners": [], "bundles": {"b": "1"}, "flush": {"dns": "x"}, "future": 1});
        let b: serde_json::Value = serde_json::json!({"future": 1, "listeners": [], "bundles": {"b": "2"}, "release": {"version": "1.0.0"}});
        let c: serde_json::Value = serde_json::json!({"future": 2, "listeners": []});
        assert_eq!(stripped(&a).0, stripped(&b).0);
        assert_ne!(stripped(&a).0, stripped(&c).0);
        let (h, bytes) = stripped(&a);
        assert_eq!(picket_api::ids::object_id(&bytes), h);
        assert!(String::from_utf8(bytes).unwrap().contains("future"));
    }

    #[test]
    fn fetched_verifies_etag_and_keeps_requests_of_unparseable_configs() {
        let body = br#"{"listeners": "not a list", "flush": {"dns": "0123456789abcdef"}}"#;
        let id = picket_api::ids::object_id(body);
        assert!(Fetched::from_bytes(body, Some("deadbeef")).is_err());
        let f = Fetched::from_bytes(body, Some(&id)).unwrap();
        assert!(f.config.is_err());
        assert_eq!(f.requests.flush.dns.as_deref(), Some("0123456789abcdef"));
        assert!(Fetched::from_bytes(b"[1]", None).is_err());
    }

    #[test]
    fn a_malformed_lookup_flush_keeps_the_other_requests() {
        // api.md §4: each request stands on its own; one bad entry doesn't discard the others.
        let v = serde_json::json!({
            "flush": {"dns": "0123456789abcdef", "lookups": {"bad": 5, "q9": "fedcba9876543210"}},
            "revoked_allows": {"id": "00112233445566ff", "allows": ["a-1", 7, "a-2"]}
        });
        let r = requests_of(&v);
        assert_eq!(r.flush.dns.as_deref(), Some("0123456789abcdef"));
        assert_eq!(
            r.flush.lookups.get("q9").map(String::as_str),
            Some("fedcba9876543210")
        );
        assert!(!r.flush.lookups.contains_key("bad"));
        let ra = r.revoked_allows.unwrap();
        assert_eq!(ra.id, "00112233445566ff");
        assert_eq!(ra.allows, vec!["a-1".to_owned(), "a-2".to_owned()]);
    }

    #[test]
    fn parse_errors_never_quote_config_values() {
        // README §2 Secrets: a malformed secret (or any value) never reaches the journal or the
        // `activation_failed` reason.
        for body in [
            &br#"{"secrets": "MY_PRIVATE_API_TOKEN"}"#[..],
            br#"{"secrets": {"k": ["MY_PRIVATE_API_TOKEN"]}}"#,
            br#"{"listeners": [{"id": "x", "proto": "MY_PRIVATE_API_TOKEN"}]}"#,
            br#"{"logging": {"retention_h": "MY_PRIVATE_API_TOKEN"}}"#,
        ] {
            let f = Fetched::from_bytes(body, None).unwrap();
            let reason = f.config.unwrap_err();
            assert!(!reason.contains("MY_PRIVATE"), "{reason}");
            assert!(reason.contains("line 1"), "{reason}");
        }
        let e = Fetched::from_bytes(br#"{"a": "MY_PRIVATE_API_TOKEN"#, None).unwrap_err();
        assert!(!format!("{e:#}").contains("MY_PRIVATE"), "{e:#}");
    }

    #[test]
    fn logging_values_out_of_range_are_rejected() {
        // README §2 range checks: core's logging settings drive arithmetic and disk use.
        use picket_api::edge_config::LoggingConfig;
        let with = |l: LoggingConfig| EdgeConfig {
            logging: l,
            ..Default::default()
        };
        assert!(validate(&with(LoggingConfig::default())).is_ok());
        // spool_after_s: core's 1–3600 (edge.md §11).
        for ok in [1, 3600] {
            let l = LoggingConfig {
                spool_after_s: ok,
                ..Default::default()
            };
            assert!(validate(&with(l)).is_ok(), "{ok}");
        }
        for bad in [
            LoggingConfig {
                spool_after_s: 0,
                ..Default::default()
            },
            LoggingConfig {
                spool_after_s: 3601,
                ..Default::default()
            },
            LoggingConfig {
                retention_h: 0,
                ..Default::default()
            },
            LoggingConfig {
                retention_h: u32::MAX,
                ..Default::default()
            },
            LoggingConfig {
                spool_max_mib: 0,
                ..Default::default()
            },
            LoggingConfig {
                spool_max_mib: 1_000_000_000_000,
                ..Default::default()
            },
            LoggingConfig {
                ssd_spool_max_mib: Some(u64::MAX),
                ..Default::default()
            },
            LoggingConfig {
                spool_after_s: u32::MAX,
                ..Default::default()
            },
            LoggingConfig {
                batch_max: 0,
                ..Default::default()
            },
        ] {
            assert!(validate(&with(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn config_objects_too_big_to_hold_are_refused_before_parsing() {
        // README §2 Bounded, edge-unifi.md §6: an object within the byte cap can still expand
        // to hundreds of MiB as a JSON tree and typed config (empty profiles: ~500 B each).
        let mut body = String::from("{\"profiles\":{");
        let mut i = 0u64;
        while body.len() < (1 << 20) {
            body.push_str(&format!("\"{i:x}\":{{}},"));
            i += 1;
        }
        body.push_str("\"z\":{}}}");
        assert!(Fetched::from_bytes(body.as_bytes(), None).is_err());
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        assert!(Fetched::from_bytes(deep.as_bytes(), None).is_err());
        let huge = format!(
            "{{\"edge\":{{\"name\":\"{}\"}}}}",
            "x".repeat(MAX_CONFIG as usize)
        );
        assert!(Fetched::from_bytes(huge.as_bytes(), None).is_err());
    }

    #[test]
    fn stripped_bytes_are_the_canonical_json_of_the_stripped_value() {
        // The serialiser borrows the tree instead of sorting a copy; the bytes must not change.
        let v = serde_json::json!({
            "z": {"b": [3, {"y": null, "x": "é\"\\n"}], "a": 1.5},
            "flush": {"dns": "x"}, "bundles": {}, "release": null, "verdict_sets": {},
            "revoked_allows": {"id": "1"}, "a": [true, false, -7, 1e300, "\u{1}"],
            "nested": {"flush": "kept below the top level"}
        });
        let mut copy = v.clone();
        for f in RUNTIME_FIELDS {
            copy.as_object_mut().unwrap().remove(f);
        }
        assert_eq!(stripped(&v).1, picket_api::ids::canonical_json(&copy));
    }

    #[test]
    fn shape_check_counts_values_not_bytes_in_strings() {
        let at = |n: usize| {
            let items = vec!["0"; n].join(",");
            format!("[{items}]")
        };
        // The root array plus n elements.
        assert!(check_shape(at(MAX_CONFIG_VALUES - 1).as_bytes()).is_ok());
        assert!(check_shape(at(MAX_CONFIG_VALUES).as_bytes()).is_err());
        // Brackets, commas, colons and escaped quotes inside strings aren't structure.
        let s = format!("{{\"k\":\"{}\\\"[,:{{\"}}", "[,:{".repeat(MAX_CONFIG_VALUES));
        assert!(check_shape(s.as_bytes()).is_ok(), "one member");
        let members: Vec<String> = (0..MAX_CONFIG_VALUES).map(|i| format!("\"{i}\":{{}}")).collect();
        assert!(check_shape(format!("{{{}}}", members.join(",")).as_bytes()).is_err());
        assert!(check_shape(b"[[],[],{}]").is_ok());
        assert!(
            check_shape(
                format!("{}{}", "[".repeat(MAX_CONFIG_DEPTH), "]".repeat(MAX_CONFIG_DEPTH)).as_bytes()
            )
            .is_ok()
        );
    }

    #[test]
    fn parse_errors_keep_what_the_schema_says() {
        let reason = |body: &[u8]| Fetched::from_bytes(body, None).unwrap().config.unwrap_err();
        let r = reason(br#"{"secrets": "tok"}"#);
        assert!(r.contains("expected a map"), "{r}");
        let r = reason(br#"{"listeners": [{"proto": "tok"}]}"#);
        assert!(r.contains("expected one of") && !r.contains("tok"), "{r}");
        let r = reason(br#"{"logging": {"retention_h": -1}}"#);
        assert!(r.contains("line 1") && !r.contains("-1"), "{r}");
    }

    /// The peak RSS a worst-case object within the limits adds while it is verified and parsed
    /// (edge-unifi.md §6: `MemoryMax=768M`, ≈ 130 MB in use). Measured in a child process
    /// running only [`memory_probe`], so other tests' allocations don't count.
    #[test]
    fn worst_case_config_objects_parse_in_bounded_memory() {
        let exe = std::env::current_exe().unwrap();
        for shape in ["profiles", "listeners", "zeros", "string"] {
            let out = std::process::Command::new(&exe)
                .args([
                    "--exact",
                    "convergence::tests::memory_probe",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("PICKET_MEM_PROBE", shape)
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            let mib: u64 = text
                .split("peak_mib=")
                .nth(1)
                .and_then(|r| r.split_whitespace().next())
                .unwrap_or_else(|| panic!("no probe output for {shape}: {text}"))
                .parse()
                .unwrap();
            println!("{shape}: {mib} MiB");
            assert!(mib < 96, "{shape}: a parse added {mib} MiB");
        }
    }

    #[test]
    #[ignore = "run by worst_case_config_objects_parse_in_bounded_memory in a child process"]
    fn memory_probe() {
        let Ok(shape) = std::env::var("PICKET_MEM_PROBE") else {
            return;
        };
        let hwm = || {
            let s = std::fs::read_to_string("/proc/self/status").unwrap();
            let kib: u64 = s
                .lines()
                .find_map(|l| l.strip_prefix("VmHWM:"))
                .unwrap()
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .unwrap();
            kib >> 10
        };
        // As many values as the shape check lets through, then padded with a string to the byte
        // cap: the most an object within the limits can cost.
        let n = MAX_CONFIG_VALUES - 16;
        let (open, item, close): (&str, &dyn Fn(usize) -> String, &str) = match shape.as_str() {
            "profiles" => ("{\"profiles\":{", &|i| format!("\"{i:x}\":{{}}"), "}"),
            "listeners" => ("{\"listeners\":[", &|_| "{}".to_owned(), "]"),
            "zeros" => ("{\"x\":[", &|_| "0".to_owned(), "]"),
            _ => ("{\"x\":[", &|_| String::new(), "]"),
        };
        let items: Vec<String> = if shape == "string" {
            vec![]
        } else {
            (0..n).map(item).collect()
        };
        let mut body = format!("{open}{}{close},\"pad\":\"", items.join(","));
        drop(items);
        let room = (MAX_CONFIG as usize).saturating_sub(body.len() + 2);
        body.push_str(&"p".repeat(room));
        body.push_str("\"}");
        assert!(body.len() as u64 <= MAX_CONFIG);
        let before = hwm();
        let f = Fetched::from_bytes(body.as_bytes(), None);
        assert!(f.is_ok(), "{shape}: {:?}", f.err());
        println!("peak_mib={}", hwm().saturating_sub(before));
    }

    #[test]
    fn applied_lookup_flushes_stay_bounded_to_named_providers() {
        let mut applied: std::collections::BTreeMap<String, String> = (0..MAX_FLUSH_LOOKUPS + 50)
            .map(|i| (format!("p{i:04}"), "0123456789abcdef".to_owned()))
            .collect();
        applied.insert("gone".into(), "0123456789abcdef".into());
        let req = Requests {
            lookup_providers: applied.keys().filter(|k| *k != "gone").cloned().collect(),
            ..Default::default()
        };
        prune_flush_lookups(&mut applied, &req);
        assert_eq!(applied.len(), MAX_FLUSH_LOOKUPS);
        assert!(!applied.contains_key("gone"));
    }

    #[test]
    fn validation_rejects_path_tricks() {
        let mut c = EdgeConfig::default();
        c.bundles.insert("../x".into(), "a".repeat(64));
        assert!(validate(&c).is_err());
        let mut c = EdgeConfig::default();
        c.bundles.insert("block-common".into(), "short".into());
        assert!(validate(&c).is_err());
        let mut c = EdgeConfig::default();
        c.bundles.insert("block-common".into(), "a".repeat(64));
        assert!(validate(&c).is_ok());
    }

    #[test]
    fn stored_configs_keep_three_and_verify() {
        let d = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(d.path());
        let mut state = State::default();
        let mut hashes = vec![];
        for i in 0..4 {
            let v = serde_json::json!({"cache": {"size_mib": i + 1}});
            let (h, bytes) = stripped(&v);
            store_config_file(&layout, &h, &bytes).unwrap();
            push_config(&mut state, &h, &format!("{i:064x}"));
            hashes.push(h);
        }
        assert_eq!(state.configs.len(), 3);
        assert_eq!(state.configs[0].hash, hashes[3]);
        delete_unreferenced_configs(&layout, &state);
        assert!(!layout.config_dir().join(format!("{}.json", hashes[0])).exists());
        let m = std::fs::metadata(layout.config_dir().join(format!("{}.json", hashes[3]))).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        // Corrupt the newest: it is skipped.
        std::fs::write(
            layout.config_dir().join(format!("{}.json", hashes[3])),
            b"{\"tampered\":1}",
        )
        .unwrap();
        let loaded = load_stored(&layout, &state);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].0.hash, hashes[2]);
        // The tampered one and a missing one can never run; an unreadable one might.
        std::fs::remove_file(layout.config_dir().join(format!("{}.json", hashes[1]))).unwrap();
        assert_eq!(
            unusable_stored(&layout, &state),
            vec![hashes[3].clone(), hashes[1].clone()]
        );
    }
}
