//! Publishing each edge's config object (core.md §4, api.md §2, §4; edge.md §13; storage.md §4).
//!
//! - **Rendering:** [`Publisher::render`] renders every edge's `EdgeConfig` from the model, the
//!   settings, the release offer, the bundle and verdict-set heads core names, the edge's
//!   requests and core's addresses ([`crate::edges::render()`]). It runs, debounced, after every
//!   trigger ([`Publisher::trigger`]: a configuration commit, a request, a release registration,
//!   a hello that changes the release offer, a new head) and every minute as a safety net (core's
//!   addresses, heads published by other modules). Renders are serialised.
//! - **Publishing:** a config whose id (the BLAKE3 of its canonical bytes) changed is stored in
//!   `edge_configs` without secret values, with the versions it names in `edge_named` (when core
//!   first named each there, for `convergence_lag_s`), all in one writer transaction; right after
//!   that commit, inside the writer, the in-memory copy the edge port serves is swapped and the
//!   edge's session is told `changed {etag}`. So what is served, what is stored and what is
//!   announced follow one another in commit order.
//! - **Pins:** when the edge port serves an edge its config object, core pins the config and the
//!   heads and verdict sets it names for that edge, before the bytes go out
//!   ([`Publisher::pin_served`]). A pin ends when a `have` report whose `fetched` was served at or
//!   after it no longer lists it ([`end_pins`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use picket_api::EdgeConfig;
use picket_api::session::Have;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use tokio::sync::Notify;

use crate::edges::render::{EdgeRunning, EdgeState, Rendered, render};
use crate::error::{CoreError, CoreResult};
use crate::state::{AppState, SharedState};

/// How long renders wait for more triggers before they run.
pub const DEBOUNCE: Duration = Duration::from_millis(300);
/// Every edge is re-rendered at least this often.
pub const RENDER_EVERY: Duration = Duration::from_secs(60);
/// Edges named in the dirty set before it becomes "all" (README §2, Bounded).
const MAX_DIRTY: usize = 4096;
/// Pins are kept for the objects of this many most recent serves per edge (README §2,
/// Bounded: an edge that fetches but never reports `have` can't grow the table for ever).
pub const MAX_PINNED_SERVES: i64 = 64;

/// A published config object.
#[derive(Clone, Debug)]
pub struct Published {
    pub edge: String,
    /// BLAKE3 of `bytes`: the config's version and ETag.
    pub id: String,
    /// The canonical bytes served as `configs/<fp>.json` (secrets included).
    pub bytes: Bytes,
    /// When core first published it (`edge_configs.published_at`).
    pub published_at: String,
    pub config: Arc<EdgeConfig>,
    pub missing_heads: Vec<String>,
    pub missing_verdict_sets: Vec<String>,
    pub missing_secrets: Vec<String>,
}

impl Published {
    /// What it names, as `(kind, target, id)`: the config, each bundle head and each verdict
    /// set (the pins and `edge_named` rows).
    pub fn named(&self) -> Vec<(&'static str, String, String)> {
        let mut v = vec![("config", String::new(), self.id.clone())];
        v.extend(
            self.config
                .bundles
                .iter()
                .map(|(b, h)| ("bundle", b.clone(), h.clone())),
        );
        v.extend(
            self.config
                .verdict_sets
                .iter()
                .map(|(p, h)| ("verdict_set", p.clone(), h.clone())),
        );
        v
    }
}

#[derive(Debug, Default)]
enum Dirty {
    #[default]
    None,
    Some(BTreeSet<String>),
    All,
}

/// Renders, stores and announces config objects.
pub struct Publisher {
    current: Arc<Mutex<HashMap<String, Arc<Published>>>>,
    dirty: Mutex<Dirty>,
    wake: Notify,
    render_lock: tokio::sync::Mutex<()>,
    served_seq: AtomicI64,
    last_pinned: Mutex<HashMap<String, String>>,
    debounce: Duration,
}

impl Default for Publisher {
    fn default() -> Self {
        Self::new(DEBOUNCE)
    }
}

impl Publisher {
    pub fn new(debounce: Duration) -> Self {
        Self {
            current: Default::default(),
            dirty: Mutex::new(Dirty::None),
            wake: Notify::new(),
            render_lock: tokio::sync::Mutex::new(()),
            served_seq: AtomicI64::new(0),
            last_pinned: Default::default(),
            debounce,
        }
    }

    /// Asks for `edge`'s config (or every edge's, with `None`) to be re-rendered soon.
    pub fn trigger(&self, edge: Option<&str>) {
        self.mark(edge);
        self.wake.notify_one();
    }

    /// Marks `edge` (every edge with `None`) for the next render without waking the loop: for
    /// the loop itself, which renders next anyway. Waking itself would leave a stored permit, so
    /// its next wait would return at once for an empty turn (README §2 Bounded).
    fn mark(&self, edge: Option<&str>) {
        if let Ok(mut d) = self.dirty.lock() {
            *d = match (std::mem::take(&mut *d), edge) {
                (Dirty::All, _) | (_, None) => Dirty::All,
                (Dirty::None, Some(e)) => Dirty::Some(BTreeSet::from([e.to_string()])),
                (Dirty::Some(mut s), Some(e)) => {
                    s.insert(e.to_string());
                    if s.len() > MAX_DIRTY {
                        Dirty::All
                    } else {
                        Dirty::Some(s)
                    }
                }
            };
        }
    }

    /// The config object core serves `edge` now.
    pub fn current(&self, edge: &str) -> Option<Arc<Published>> {
        self.current.lock().ok()?.get(edge).cloned()
    }

    /// Loads the config object each edge was last given from durable storage (README §2
    /// Restarts; bundles.md §2 Budget; core.md §4): the one `edge_named` names for it, rebuilt
    /// from its stored body (`edge_configs`) with the secrets' current values. Call at start
    /// before the first render, so the budgets resolve against what each edge runs: an edge kept
    /// on a bundle's older head stays on it, and a held config stays held. A body whose rebuilt
    /// bytes don't give its id (a secret changed while the config was held, or an older release
    /// stored a credential it masked) is published again as it stands with today's secret values,
    /// so the edge keeps its bundles. Returns how many edges were restored.
    pub async fn restore(&self, state: &SharedState) -> CoreResult<usize> {
        let model = state.config.model().await?;
        let edges: Vec<String> = model.edges.keys().cloned().collect();
        let stored: Vec<(String, String, String, String)> = state
            .db
            .read(move |c| {
                let mut st = c.prepare(
                    "SELECT n.id, c.body_json, c.published_at FROM edge_named n
                     JOIN edge_configs c ON c.config_id = n.id
                     WHERE n.edge_id = ?1 AND n.kind = 'config' AND n.target = ''",
                )?;
                let mut out = Vec::new();
                for e in &edges {
                    let row: Option<(String, String, String)> = st
                        .query_row([e], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                        .optional()?;
                    if let Some((id, body, at)) = row {
                        out.push((e.clone(), id, body, at));
                    }
                }
                Ok::<_, CoreError>(out)
            })
            .await?;
        let mut exact: Vec<Published> = Vec::new();
        let mut again: Vec<(String, Rendered)> = Vec::new();
        for (edge, id, body, published_at) in stored {
            let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&body) else {
                tracing::warn!(edge = %edge, "a stored edge config doesn't parse; the edge gets a new one");
                continue;
            };
            let names: Vec<String> = value
                .get("secrets")
                .and_then(|v| v.as_object())
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            let values = state.config.secret_values(names).await?;
            if let Some(serde_json::Value::Object(m)) = value.get_mut("secrets") {
                m.retain(|k, _| values.contains_key(k));
                for (k, v) in m.iter_mut() {
                    *v = serde_json::Value::String(values.get(k).cloned().unwrap_or_default());
                }
            }
            let Ok(config) = serde_json::from_value::<EdgeConfig>(value.clone()) else {
                tracing::warn!(edge = %edge, "a stored edge config doesn't parse; the edge gets a new one");
                continue;
            };
            let bytes = picket_api::ids::canonical_json(&value);
            let rid = picket_api::ids::object_id(&bytes);
            if rid == id {
                exact.push(Published {
                    edge,
                    id,
                    bytes: Bytes::from(bytes),
                    published_at,
                    config: Arc::new(config),
                    missing_heads: Vec::new(),
                    missing_verdict_sets: Vec::new(),
                    missing_secrets: Vec::new(),
                });
            } else {
                again.push((
                    edge,
                    Rendered {
                        config,
                        bytes,
                        id: rid,
                        stored_body: body,
                        missing_heads: Vec::new(),
                        missing_verdict_sets: Vec::new(),
                        missing_secrets: Vec::new(),
                    },
                ));
            }
        }
        let n = exact.len() + again.len();
        if let Ok(mut cur) = self.current.lock() {
            for p in exact {
                cur.insert(p.edge.clone(), Arc::new(p));
            }
        }
        if !again.is_empty() {
            self.publish(state, again).await?;
        }
        Ok(n)
    }

    /// Reads where `served_seq` continues from (at start).
    pub fn load_served_seq(&self, c: &Connection) -> rusqlite::Result<()> {
        let n: i64 = c.query_row(
            "SELECT max(coalesce((SELECT max(served_seq) FROM edge_configs), 0),
                        coalesce((SELECT max(served_seq) FROM edge_pins), 0))",
            [],
            |r| r.get(0),
        )?;
        self.served_seq.store(n, Ordering::SeqCst);
        Ok(())
    }

    /// The debounced render loop, until shutdown.
    pub async fn run(self: Arc<Self>, state: SharedState) {
        let mut every = tokio::time::interval(RENDER_EVERY);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        every.tick().await;
        loop {
            if !self.wait(&state.shutdown, &mut every).await {
                return;
            }
            tokio::select! {
                _ = state.shutdown.cancelled() => return,
                _ = tokio::time::sleep(self.debounce) => {}
            }
            let dirty = self
                .dirty
                .lock()
                .map(|mut d| std::mem::take(&mut *d))
                .unwrap_or_default();
            let only = match dirty {
                Dirty::None => continue,
                Dirty::All => None,
                Dirty::Some(s) => Some(s),
            };
            if let Err(e) = self.render(&state, only.clone()).await {
                tracing::warn!(error = %e, "rendering edge configs failed; retrying");
                // Marked and woken: the loop retries after the pause below.
                match only {
                    None => self.trigger(None),
                    Some(s) => s.iter().for_each(|e| self.trigger(Some(e))),
                }
                tokio::select! {
                    _ = state.shutdown.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
            }
        }
    }

    /// Waits for a trigger, or for the periodic render, which marks every edge. False at
    /// shutdown.
    async fn wait(
        &self,
        shutdown: &tokio_util::sync::CancellationToken,
        every: &mut tokio::time::Interval,
    ) -> bool {
        tokio::select! {
            _ = shutdown.cancelled() => false,
            _ = self.wake.notified() => true,
            _ = every.tick() => {
                self.mark(None);
                true
            }
        }
    }

    /// The per-edge render inputs besides the model, for `edge` (also the UI's preview).
    pub async fn edge_state(
        &self,
        state: &AppState,
        edge: &str,
        shared: &SharedInputs,
    ) -> CoreResult<EdgeState> {
        let live = state.edges.hub.live(edge);
        let mut bundle_heads = shared.bundle_heads.clone();
        shared.with_holds(edge, &mut bundle_heads);
        Ok(EdgeState {
            bundle_heads,
            verdict_set_heads: shared.verdict_sets.clone(),
            release: shared.release.clone(),
            running: EdgeRunning {
                version: live.hello.as_ref().map(|h| h.edge_version.clone()),
                arch: live.hello.as_ref().map(|h| h.arch.clone()),
            },
            requests: crate::edges::requests(&state.db, edge).await?,
            secrets: shared.secrets.clone(),
            core_ips: shared.core_ips.clone(),
            lanca_root: Some(shared.lanca_root.clone()),
        })
    }

    /// Renders `only` these edges (every edge with `None`) and publishes those whose config
    /// changed.
    pub async fn render(&self, state: &SharedState, only: Option<BTreeSet<String>>) -> CoreResult<()> {
        let _serial = self.render_lock.lock().await;
        let model = state.config.model().await?;
        let shared = SharedInputs::load(state, &model).await?;
        let mut changed: Vec<(String, Rendered)> = Vec::new();
        let mut budgets: Vec<(String, crate::compiler::budget::Resolved)> = Vec::new();
        // Compaction builds the overlay budgets ask for: bundle → (parts, edge names).
        let mut compact: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
        // Verdict sets whose new base the overlay budgets ask for (bundles.md §5).
        let mut rebase_sets: BTreeSet<String> = BTreeSet::new();
        for (edge, def) in &model.edges {
            if only.as_ref().is_some_and(|o| !o.contains(edge)) {
                continue;
            }
            let mut es = self.edge_state(state, edge, &shared).await?;
            // Bundle heads within the edge's budget (bundles.md §2 Budget).
            let current = self.current(edge);
            let named = current.as_ref().map(|p| &p.config.bundles);
            // Both budgets, against what the edge would run (bundles.md §2 Budget, §5).
            let resolved = crate::compiler::budget::resolve(
                &crate::compiler::budget::Budgets {
                    sets: shared.verdict_overlays.clone(),
                    ..crate::compiler::budget::Budgets::of_mib(
                        def.settings.bundle_budget_mib,
                        def.settings.overlay_budget(def.platform),
                    )
                },
                &shared.needed,
                &shared.bundle_heads,
                named,
                &shared.head_sizes,
                &shared.overlay_parts,
            );
            for (b, parts) in &resolved.compact {
                compact
                    .entry(b.clone())
                    .or_insert_with(|| (BTreeSet::new(), BTreeSet::new()))
                    .0
                    .extend(parts.iter().cloned());
                if let Some(e) = compact.get_mut(b) {
                    e.1.insert(def.name.clone());
                }
            }
            rebase_sets.extend(resolved.rebase_sets.iter().cloned());
            es.bundle_heads = resolved.heads.clone();
            shared.with_holds(edge, &mut es.bundle_heads);
            let hold = resolved.hold.is_some() && current.is_some();
            budgets.push((edge.clone(), resolved));
            if hold {
                // A bundle new to the edge doesn't fit: its whole current config stays.
                continue;
            }
            let r = render(&model, edge, &es).map_err(|e| CoreError::Other(anyhow::anyhow!("{e}")))?;
            if let Some(p) = current.filter(|p| p.id == r.id) {
                // The same object; what it lacks may be known better now (a restored config).
                if (&p.missing_heads, &p.missing_verdict_sets, &p.missing_secrets)
                    != (&r.missing_heads, &r.missing_verdict_sets, &r.missing_secrets)
                    && let Ok(mut cur) = self.current.lock()
                {
                    let mut q = (*p).clone();
                    q.missing_heads = r.missing_heads;
                    q.missing_verdict_sets = r.missing_verdict_sets;
                    q.missing_secrets = r.missing_secrets;
                    cur.insert(edge.clone(), Arc::new(q));
                }
                continue;
            }
            changed.push((edge.clone(), r));
        }
        over_budget_alerts(state, budgets).await?;
        for p in &rebase_sets {
            crate::lookups::verdict_sets::request_base(state, p);
        }
        // The largest overlays first, as their bundles' compaction builds (bundles.md §5; core.md
        // §3 P2); a request for a bundle already waiting merges into it.
        for (bundle, (parts, edges)) in compact {
            state.compiler.request(
                state,
                &bundle,
                crate::compiler::Request {
                    reasons: edges
                        .iter()
                        .take(8)
                        .map(|e| format!("overlay budget of edge {e}"))
                        .collect(),
                    compact: parts,
                    ..crate::compiler::Request::default()
                },
                crate::scheduler::Priority::P2,
            );
        }
        if only.is_none()
            && let Ok(mut cur) = self.current.lock()
        {
            cur.retain(|e, _| model.edges.contains_key(e));
        }
        if changed.is_empty() {
            return Ok(());
        }
        self.publish(state, changed).await
    }

    /// Stores, swaps in and announces changed config objects, in one writer transaction (module
    /// docs).
    async fn publish(&self, state: &SharedState, changed: Vec<(String, Rendered)>) -> CoreResult<()> {
        let current = self.current.clone();
        let hub = state.edges.hub.clone();
        let published = state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                let now = crate::util::now_ts();
                let mut out = Vec::new();
                for (edge, r) in changed {
                    tx.execute(
                        "INSERT INTO edge_configs(config_id, edge_id, published_at, body_json) VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(config_id) DO NOTHING",
                        params![r.id, edge, now, r.stored_body],
                    )?;
                    let published_at: String = tx.query_row(
                        "SELECT published_at FROM edge_configs WHERE config_id = ?1",
                        [&r.id],
                        |row| row.get(0),
                    )?;
                    let p = Published {
                        edge: edge.clone(),
                        id: r.id,
                        bytes: Bytes::from(r.bytes),
                        published_at,
                        config: Arc::new(r.config),
                        missing_heads: r.missing_heads,
                        missing_verdict_sets: r.missing_verdict_sets,
                        missing_secrets: r.missing_secrets,
                    };
                    name_versions(&tx, &p, &now)?;
                    out.push(p);
                }
                tx.commit()?;
                // Right after the commit, in commit order (module docs).
                let mut names = Vec::new();
                if let Ok(mut cur) = current.lock() {
                    for p in out {
                        hub.notify_changed(&p.edge, &p.id);
                        names.push((p.edge.clone(), p.id.clone()));
                        cur.insert(p.edge.clone(), Arc::new(p));
                    }
                }
                Ok::<_, CoreError>(names)
            })
            .await?;
        for (edge, id) in published {
            tracing::info!(edge = %edge, config = %picket_api::ids::short_id(&id), "edge config published");
        }
        Ok(())
    }

    /// `edge`'s config object, rendering it first if core holds none yet.
    pub async fn current_or_render(&self, state: &SharedState, edge: &str) -> CoreResult<Arc<Published>> {
        if let Some(p) = self.current(edge) {
            return Ok(p);
        }
        self.render(state, Some(BTreeSet::from([edge.to_string()])))
            .await?;
        self.current(edge)
            .ok_or_else(|| CoreError::NotFound(format!("no config for edge {edge:?}")))
    }

    /// Pins what `p` names for its edge before it is served (storage.md §4 Pins).
    pub async fn pin_served(&self, state: &AppState, p: &Arc<Published>) -> CoreResult<()> {
        if self
            .last_pinned
            .lock()
            .ok()
            .and_then(|m| m.get(&p.edge).cloned())
            .as_deref()
            == Some(p.id.as_str())
        {
            return Ok(());
        }
        let seq = self.served_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let (edge, id, named) = (p.edge.clone(), p.id.clone(), p.named());
        state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                let now = crate::util::now_ts();
                tx.execute(
                    "UPDATE edge_configs SET served_seq = ?1 WHERE config_id = ?2",
                    params![seq, id],
                )?;
                for (kind, target, nid) in &named {
                    tx.execute(
                        "INSERT INTO edge_pins(edge_id, kind, target, id, served_seq, pinned_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                         ON CONFLICT(edge_id, kind, target, id) DO UPDATE SET served_seq = excluded.served_seq",
                        params![edge, kind, target, nid, seq, now],
                    )?;
                }
                tx.execute(
                    "DELETE FROM edge_pins WHERE edge_id = ?1 AND served_seq < (
                       SELECT min(s) FROM (SELECT DISTINCT served_seq AS s FROM edge_pins WHERE edge_id = ?1
                                           ORDER BY served_seq DESC LIMIT ?2))",
                    params![edge, MAX_PINNED_SERVES],
                )?;
                tx.commit()?;
                Ok::<_, CoreError>(())
            })
            .await?;
        if let Ok(mut m) = self.last_pinned.lock() {
            m.insert(p.edge.clone(), p.id.clone());
        }
        Ok(())
    }
}

/// Render inputs shared by every edge.
pub struct SharedInputs {
    pub secrets: BTreeMap<String, String>,
    /// Each bundle's current head (before per-edge budgets).
    pub bundle_heads: BTreeMap<String, String>,
    /// The in-memory sizes of the current heads and of the heads the edges' configs name now
    /// (bundles.md §2 Budget).
    pub head_sizes: BTreeMap<String, crate::compiler::store::HeadSize>,
    /// The bundles every edge needs ([`crate::edges::render::edge_bundles`]).
    pub needed: BTreeSet<String>,
    /// The current heads' parts with an overlay: bundle → (part id, bytes), for compaction
    /// (bundles.md §5).
    pub overlay_parts: BTreeMap<String, Vec<(String, u64)>>,
    pub verdict_sets: BTreeMap<String, String>,
    /// The overlay bytes each named verdict set costs each edge (every edge names every `sync`
    /// provider's set; edge.md §17), by provider.
    pub verdict_overlays: BTreeMap<String, u64>,
    pub release: Option<crate::edges::render::ReleaseInput>,
    pub core_ips: Vec<std::net::IpAddr>,
    /// The LAN CA's current root (`EdgeConfig.lanca_root`, core.md §11).
    pub lanca_root: String,
    /// After a config restore: edge → bundle → the head that edge ran, named until the bundle's
    /// downloaded feeds have their first runs (core.md §2; [`crate::config::export::holds`]).
    pub held: BTreeMap<String, BTreeMap<String, String>>,
}

impl SharedInputs {
    /// `heads` with the restore's held heads for `edge` in place of the current ones.
    pub fn with_holds(&self, edge: &str, heads: &mut BTreeMap<String, String>) {
        if let Some(h) = self.held.get(edge) {
            for (b, head) in h {
                if self.needed.contains(b) {
                    heads.insert(b.clone(), head.clone());
                }
            }
        }
    }

    pub async fn load(state: &AppState, model: &crate::config::Model) -> CoreResult<Self> {
        let names: Vec<String> = model
            .lookup_providers
            .values()
            .flat_map(|p| p.secret_refs())
            .collect();
        let secrets = state.config.secret_values(names).await?;
        // Heads the edges' current configs name: the budget keeps an edge on them.
        let mut named: Vec<(String, String)> = Vec::new();
        for e in model.edges.keys() {
            if let Some(p) = state.edges.publisher.current(e) {
                named.extend(p.config.bundles.iter().map(|(b, h)| (b.clone(), h.clone())));
            }
        }
        let needed = crate::edges::render::edge_bundles(model);
        let needed2 = needed.clone();
        let m2 = model.clone();
        let (held, rows) = state
            .db
            .read(move |c| {
                let held = crate::config::export::holds(c, &m2)?;
                let rows: i64 = c.query_row("SELECT count(*) FROM restore_holds", [], |r| r.get(0))?;
                Ok::<_, CoreError>((held, rows))
            })
            .await?;
        let live: usize = held.values().map(BTreeMap::len).sum();
        if usize::try_from(rows).unwrap_or(0) > live {
            // Holds whose bundles' downloaded feeds have their first runs now end.
            let h2 = held.clone();
            state
                .db
                .write(move |c| Ok::<_, CoreError>(crate::config::export::prune_holds(c, &h2)?))
                .await?;
        }
        let held_named: Vec<(String, String)> = held
            .values()
            .flat_map(|m| m.iter().map(|(b, h)| (b.clone(), h.clone())))
            .collect();
        let (bundle_heads, verdict_sets, head_sizes, overlay_parts, verdict_overlays) = state
            .db
            .read(move |c| {
                let heads = current_bundle_heads(c)?;
                let mut all = named;
                all.extend(held_named);
                all.extend(heads.iter().map(|(b, h)| (b.clone(), h.clone())));
                let sizes = crate::compiler::store::head_sizes(c, &all)?;
                let parts = crate::compiler::store::overlay_parts(c, needed2.iter())?;
                let sets = current_verdict_sets(c)?;
                let overlay: BTreeMap<String, u64> = crate::lookups::verdict_sets::overlay_bytes(c)?
                    .into_iter()
                    .filter(|(p, _)| sets.contains_key(p))
                    .collect();
                Ok::<_, CoreError>((heads, sets, sizes, parts, overlay))
            })
            .await?;
        Ok(Self {
            secrets,
            needed,
            overlay_parts,
            head_sizes,
            bundle_heads,
            verdict_sets,
            verdict_overlays,
            release: state.edges.releases.offer(),
            core_ips: state.core_ips().as_ref().clone(),
            lanca_root: state.lanca.load().fingerprint(),
            held,
        })
    }
}

/// The bundle heads core names before per-edge budgets: each bundle's current head (the version
/// its last build published, `bundle_builds.head_id`). Per edge, [`crate::compiler::budget`] keeps
/// an edge on its head where a newer one would pass its `bundle_budget_mib`, and after a config
/// restore [`SharedInputs::with_holds`] keeps the heads each edge ran until the bundle's
/// downloaded feeds have their first runs (core.md §2).
pub fn current_bundle_heads(c: &Connection) -> rusqlite::Result<BTreeMap<String, String>> {
    crate::compiler::store::current_heads(c)
}

/// The verdict-set heads core names: each provider's current head under its current
/// `cache_generation` (core.md §7; published by [`crate::lookups::verdict_sets`]).
pub fn current_verdict_sets(c: &Connection) -> rusqlite::Result<BTreeMap<String, String>> {
    crate::lookups::verdict_sets::current_heads(c)
}

/// Records what `p` names in `edge_named`: a version keeps the time core first named it there;
/// a target no longer named is dropped.
fn name_versions(tx: &Transaction<'_>, p: &Published, now: &str) -> rusqlite::Result<()> {
    let named = p.named();
    let keep: BTreeSet<(String, String)> = named.iter().map(|(k, t, _)| (k.to_string(), t.clone())).collect();
    let existing: Vec<(String, String)> = {
        let mut st = tx.prepare("SELECT kind, target FROM edge_named WHERE edge_id = ?1")?;
        st.query_map([&p.edge], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    for (k, t) in existing {
        if !keep.contains(&(k.clone(), t.clone())) {
            tx.execute(
                "DELETE FROM edge_named WHERE edge_id = ?1 AND kind = ?2 AND target = ?3",
                params![p.edge, k, t],
            )?;
        }
    }
    for (kind, target, id) in named {
        let at = if kind == "config" {
            p.published_at.as_str()
        } else {
            now
        };
        tx.execute(
            "INSERT INTO edge_named(edge_id, kind, target, id, named_at) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(edge_id, kind, target) DO UPDATE SET id = excluded.id, named_at = excluded.named_at,
                active_at = NULL WHERE edge_named.id <> excluded.id",
            params![p.edge, kind, target, id, at],
        )?;
    }
    Ok(())
}

/// True when `have` lists `(kind, target, id)` among its active, previous or in-progress
/// versions.
pub fn have_lists(have: &Have, kind: &str, target: &str, id: &str) -> bool {
    let has = |m: &BTreeMap<String, Vec<String>>| m.get(target).is_some_and(|v| v.iter().any(|x| x == id));
    match kind {
        "config" => have.config.iter().any(|x| x == id) || have.in_progress.config.as_deref() == Some(id),
        "bundle" => has(&have.bundles) || has(&have.in_progress.bundles),
        "verdict_set" => has(&have.verdict_sets) || has(&have.in_progress.verdict_sets),
        _ => true,
    }
}

/// Ends the pins a `have` report releases (storage.md §4): those served at or before the object
/// its `fetched` names that it no longer lists. Configs whose pin ended, and those it lists as
/// active or previous, get `last_used_at` now. Call inside the status transaction.
pub fn end_pins(tx: &Transaction<'_>, edge: &str, have: &Have, now: &str) -> rusqlite::Result<usize> {
    for id in &have.config {
        tx.execute(
            "UPDATE edge_configs SET last_used_at = ?2 WHERE config_id = ?1 AND edge_id = ?3",
            params![id, now, edge],
        )?;
    }
    let Some(fetched) = have.fetched.as_deref() else {
        return Ok(0);
    };
    let seq: Option<i64> = tx
        .query_row(
            "SELECT served_seq FROM edge_configs WHERE config_id = ?1 AND edge_id = ?2",
            params![fetched, edge],
            |r| r.get(0),
        )
        .ok()
        .flatten();
    let Some(seq) = seq else { return Ok(0) };
    let rows: Vec<(String, String, String)> = {
        let mut st =
            tx.prepare("SELECT kind, target, id FROM edge_pins WHERE edge_id = ?1 AND served_seq <= ?2")?;
        st.query_map(params![edge, seq], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut ended = 0;
    for (kind, target, id) in rows {
        if have_lists(have, &kind, &target, &id) {
            continue;
        }
        tx.execute(
            "DELETE FROM edge_pins WHERE edge_id = ?1 AND kind = ?2 AND target = ?3 AND id = ?4",
            params![edge, kind, target, id],
        )?;
        if kind == "config" {
            tx.execute(
                "UPDATE edge_configs SET last_used_at = ?2 WHERE config_id = ?1",
                params![id, now],
            )?;
        }
        ended += 1;
    }
    Ok(ended)
}

/// Raises `bundle_over_budget` for each bundle an edge stays behind on, that holds its config or
/// that a new edge runs without, and resolves the edge's others (bundles.md §2 Budget; core.md
/// §9): an alert stays open while the edge can't take the bundle's current head.
async fn over_budget_alerts(
    state: &SharedState,
    budgets: Vec<(String, crate::compiler::budget::Resolved)>,
) -> CoreResult<()> {
    if budgets.is_empty() {
        return Ok(());
    }
    if budgets.iter().all(|(_, r)| r.kept.is_empty()) {
        // Nothing over budget: write only when an over-budget alert of these edges is open.
        let edges: Vec<String> = budgets.iter().map(|(e, _)| e.clone()).collect();
        let open: i64 = state
            .db
            .read(move |c| {
                let mut n = 0i64;
                for e in &edges {
                    n += c.query_row(
                        "SELECT count(*) FROM alerts WHERE state = 'open' AND kind = 'bundle_over_budget' AND edge_id = ?1",
                        [e],
                        |r| r.get::<_, i64>(0),
                    )?;
                }
                Ok::<_, CoreError>(n)
            })
            .await?;
        if open == 0 {
            return Ok(());
        }
    }
    let alerts = state.alerts.clone();
    let ch = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let mut ch = crate::alerts::Changes::default();
            for (edge, r) in &budgets {
                let prefix = format!("bundle_over_budget:{edge}:");
                let mut keep: BTreeSet<String> = BTreeSet::new();
                for (bundle, kept, wanted) in &r.kept {
                    let key = format!("{prefix}{bundle}");
                    keep.insert(key.clone());
                    if crate::alerts::Alerts::is_open_in(&tx, &key)? {
                        continue;
                    }
                    let waiting = r.hold.is_some();
                    let which = match (r.total > r.budget, r.overlay > r.overlay_budget) {
                        (true, true) => "bundle and overlay budgets",
                        (false, true) => "overlay budget",
                        _ => "bundle budget",
                    };
                    let title = if waiting {
                        format!("Bundle {bundle} doesn't fit edge {edge}'s {which}; config changes for the edge are waiting")
                    } else if kept.is_empty() {
                        format!("Bundle {bundle} doesn't fit edge {edge}'s {which}; the edge runs without it for now")
                    } else {
                        format!("Bundle {bundle}'s new version doesn't fit edge {edge}'s {which}; the edge stays on its version")
                    };
                    let spec = crate::alerts::RaiseSpec::new(
                        "bundle_over_budget",
                        crate::alerts::Severity::Warning,
                        key,
                        title,
                        serde_json::json!({
                            "edge": edge, "bundle": bundle, "kept_head": kept, "wanted_head": wanted,
                            "budget_bytes": r.budget, "named_bytes": r.total, "changes_waiting": waiting,
                            "overlay_budget_bytes": r.overlay_budget, "overlay_bytes": r.overlay,
                            "compaction_requested": r.compact.contains_key(bundle),
                        }),
                    )
                    .edge(edge.clone())
                    .bundle(bundle.clone());
                    alerts.raise_in(&tx, &spec, &mut ch)?;
                }
                let open: Vec<String> = {
                    let mut st = tx.prepare(
                        "SELECT dedupe_key FROM alerts WHERE state = 'open' AND kind = 'bundle_over_budget' AND edge_id = ?1",
                    )?;
                    st.query_map([edge], |row| row.get(0))?
                        .collect::<rusqlite::Result<_>>()?
                };
                for k in open {
                    if !keep.contains(&k) {
                        alerts.resolve_in(&tx, &k, Some(&serde_json::json!({"fits": true})), &mut ch)?;
                    }
                }
            }
            tx.commit()?;
            alerts.committed(&ch);
            Ok::<_, CoreError>(ch)
        })
        .await?;
    state.alerts.announce(ch);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// README §2 Bounded: the periodic render marks every edge without waking the loop. It used
    /// to trigger itself, which left a stored permit, so the wait after each periodic render
    /// returned at once for an empty turn. On the paused clock: each wait takes a full period.
    #[tokio::test(start_paused = true)]
    async fn an_idle_render_loop_waits_a_period_between_renders() {
        let p = Publisher::new(DEBOUNCE);
        let stop = tokio_util::sync::CancellationToken::new();
        let mut every = tokio::time::interval(RENDER_EVERY);
        every.tick().await;
        let t0 = tokio::time::Instant::now();
        for turn in 1..=3u32 {
            assert!(p.wait(&stop, &mut every).await);
            assert_eq!(t0.elapsed(), RENDER_EVERY * turn, "turn {turn}");
            let dirty = p.dirty.lock().map(|mut d| std::mem::take(&mut *d)).unwrap();
            assert!(
                matches!(dirty, Dirty::All),
                "turn {turn}: the periodic render marks every edge"
            );
        }
        // A trigger still wakes it at once.
        p.trigger(Some("e1"));
        assert!(p.wait(&stop, &mut every).await);
        assert_eq!(t0.elapsed(), RENDER_EVERY * 3);
        stop.cancel();
        assert!(!p.wait(&stop, &mut every).await);
    }
}
