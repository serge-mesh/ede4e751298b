//! The live side of edges (core.md §4, api.md §3): one session per edge, the registry of pinned
//! keys the edge port checks on every request, and each edge's last reported state.
//!
//! - **One session per edge:** a newer session replaces the older, which is told to close; a
//!   message from a replaced session changes nothing ([`Hub::is_current`]).
//! - **`changed`:** each session has a `watch` slot holding the newest ETag to announce, so a
//!   slow session holds one pending message, never a queue (README §2, Bounded).
//! - **Live state** ([`EdgeLive`]) is what the edge last reported: the hello, the last
//!   heartbeat, its conditions, `have`, `applied`, `versions`. It is written by the database
//!   writer right after the commit that stored it, so it follows `edge_status` in commit order,
//!   and it is loaded from `edge_status` at start, so a restart forgets nothing the edge said.
//! - **Key changes** (api.md §1): a session registers only while the registry pins its key to
//!   its edge (checked under the sessions lock, so a refresh that follows closes it), and a
//!   registry refresh closes every session whose key went away. An admission's early registry
//!   entry is skipped when a refresh ran since its database read ([`Hub::note_registered`]), so a
//!   replaced key never returns to the registry.
//! - **Session message rates** (README §2, Bounded; api.md §3: a heartbeat every 30 s): an
//!   edge's heartbeat is stored at most once per [`HEARTBEAT_STORE_EVERY`], counted from the
//!   arrival of the last stored one; one arriving sooner only updates the live copy, and the next
//!   one after the interval is stored (running totals lose nothing). Hellos are admitted per edge
//!   by a token bucket ([`HELLO_BURST`], [`HELLO_REFILL`]), so a reconnect loop can't add boots
//!   or tie up the writer; a hello takes a token only once its key is checked
//!   ([`Hub::register`]), so a replaced key can't spend the edge's share.
//! - Every map here holds at most one entry per registered edge.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use jiff::Timestamp;
use picket_api::logs::Versions;
use picket_api::session::{Applied, Condition, Have, Heartbeat, Hello};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// An edge's heartbeats are stored at most this often (README §2, Bounded). The edge sends one
/// every 30 s (api.md §3); a little less leaves room for jitter. Policy choice: the spec gives
/// no number.
pub const HEARTBEAT_STORE_EVERY: std::time::Duration = std::time::Duration::from_secs(20);
/// Hellos an edge may send in a burst (each is a session start: a boot row, a transaction) …
pub const HELLO_BURST: f64 = 10.0;
/// … and how often it earns one more. The edge reconnects with backoff from 1 s to 60 s, so a
/// healthy edge never meets the limit. Policy choice: the spec gives no number.
pub const HELLO_REFILL: std::time::Duration = std::time::Duration::from_secs(30);

/// Why [`Hub::register`] gave a hello no session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The registry no longer pins the connection's key to the edge (api.md §1 Key change).
    NotRegistered,
    /// The edge has no hello token left (README §2, Bounded); it retries with its backoff.
    TooManyHellos,
}

/// What core keeps of an edge's hello (`edge_status.hello_json`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct HelloInfo {
    pub edge_version: String,
    pub arch: String,
    pub os: String,
    pub kernel: String,
    pub platform: String,
    pub firmware: Option<String>,
    /// When `firmware` last changed (core.md §4: shown with the firmware).
    pub firmware_changed_at: Option<String>,
    pub mem_total: Option<u64>,
    pub allowed_binds: Vec<String>,
    pub updates_enabled: bool,
    pub boot: String,
    pub starts: u32,
    /// When core received the hello.
    pub at: String,
    /// The session's peer address.
    pub addr: Option<String>,
}

impl HelloInfo {
    pub fn from_hello(h: &Hello, previous: Option<&HelloInfo>, now: &str, addr: Option<String>) -> Self {
        let firmware_changed_at = match previous {
            Some(p) if p.firmware == h.firmware => p.firmware_changed_at.clone(),
            _ => Some(now.to_string()),
        };
        Self {
            edge_version: h.edge_version.clone(),
            arch: h.arch.clone(),
            os: h.os.clone(),
            kernel: h.kernel.clone(),
            platform: h.platform.clone(),
            firmware: h.firmware.clone(),
            firmware_changed_at,
            mem_total: h.mem_total,
            allowed_binds: h.allowed_binds.clone(),
            updates_enabled: h.updates_enabled,
            boot: h.boot.clone(),
            starts: h.starts,
            at: now.to_string(),
            addr,
        }
    }

    /// True when the edge's `allowed_binds` lets a listener bind `bind` (edge.md §2: exact
    /// `ip:port` strings, `*` for everything).
    pub fn bind_allowed(&self, bind: &str) -> bool {
        self.allowed_binds.iter().any(|b| b == "*" || b == bind)
    }
}

/// The latest terminal update outcome core holds for an edge (`edge_status.update_result_json`,
/// core.md §9), replaced only by a later `at`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct UpdateRecord {
    pub result_id: String,
    /// `ok` or `failed`.
    pub outcome: String,
    pub version: String,
    pub at: String,
    /// The failed stage, when an `update_failed` event named it.
    pub stage: Option<String>,
}

/// What an edge last reported.
#[derive(Clone, Debug, Default)]
pub struct EdgeLive {
    pub hello: Option<HelloInfo>,
    pub heartbeat: Option<Arc<Heartbeat>>,
    /// When core received the last heartbeat.
    pub heartbeat_at: Option<Timestamp>,
    /// The last hello or heartbeat (wall clock, for display and after a restart).
    pub last_seen: Option<Timestamp>,
    /// The last heartbeat on the monotonic clock (README §2 Clocks); `None` after a restart
    /// until one arrives.
    pub last_seen_mono: Option<tokio::time::Instant>,
    pub conditions: Vec<Condition>,
    pub applied: Applied,
    pub have: Have,
    pub versions: Option<Versions>,
    pub update: Option<UpdateRecord>,
}

struct Slot {
    id: u64,
    /// The key the session's connection presented.
    fingerprint: String,
    addr: SocketAddr,
    since: Timestamp,
    boot: String,
    changed: watch::Sender<Option<String>>,
    close: CancellationToken,
}

/// A session's link to the hub.
pub struct SessionHandle {
    pub id: u64,
    /// The newest ETag to announce with `changed`.
    pub changed: watch::Receiver<Option<String>>,
    /// Cancelled when a newer session replaces this one, or the edge's key goes away.
    pub close: CancellationToken,
}

/// A connected session, for display.
#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct SessionInfo {
    pub addr: String,
    pub since: String,
    pub boot: String,
}

/// A registered edge as the edge port pins it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registered {
    pub id: String,
    pub name: String,
    pub fingerprint: String,
}

/// Sessions, live state and the key registry.
pub struct Hub {
    sessions: Mutex<HashMap<String, Slot>>,
    live: Mutex<HashMap<String, EdgeLive>>,
    next: AtomicU64,
    /// Fingerprint → edge, refreshed from `edges` after every configuration commit.
    registry: ArcSwap<HashMap<String, Registered>>,
    /// Counts registry refreshes; held while the registry is replaced, so an admission's early
    /// entry and a refresh never interleave.
    registry_gen: Mutex<u64>,
    sessions_replaced: AtomicU64,
    /// When each edge's last heartbeat was stored (monotonic).
    stored_heartbeat: Mutex<HashMap<String, tokio::time::Instant>>,
    heartbeat_every_ms: AtomicU64,
    /// Each edge's hello tokens and when they were last topped up.
    hellos: Mutex<HashMap<String, (tokio::time::Instant, f64)>>,
    hellos_refused: AtomicU64,
}

impl Default for Hub {
    fn default() -> Self {
        Self {
            sessions: Default::default(),
            live: Default::default(),
            next: AtomicU64::new(0),
            registry: Default::default(),
            registry_gen: Mutex::new(0),
            sessions_replaced: AtomicU64::new(0),
            stored_heartbeat: Default::default(),
            heartbeat_every_ms: AtomicU64::new(picket_api::duration::as_millis_u64(HEARTBEAT_STORE_EVERY)),
            hellos: Default::default(),
            hellos_refused: AtomicU64::new(0),
        }
    }
}

impl Hub {
    pub fn new() -> Self {
        Self::default()
    }

    // -- registry ----------------------------------------------------------------------------

    /// Re-reads the registered keys; closes the sessions of edges whose key went away or
    /// changed (api.md §1 Key change: the old key is refused from now on).
    pub fn refresh_registry(&self, c: &Connection) -> rusqlite::Result<()> {
        let mut st = c.prepare("SELECT id, name, key_sha256 FROM edges")?;
        let map: HashMap<String, Registered> = st
            .query_map([], |r| {
                Ok(Registered {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    fingerprint: r.get(2)?,
                })
            })?
            .filter_map(Result::ok)
            .map(|e| (e.fingerprint.clone(), e))
            .collect();
        let by_id: HashMap<String, String> = map
            .values()
            .map(|e| (e.id.clone(), e.fingerprint.clone()))
            .collect();
        // The new registry first, then the sessions: a session registering meanwhile either sees
        // the new registry (and is refused) or is closed below (it checks under the same lock).
        {
            let mut g = self.registry_gen.lock().unwrap_or_else(|p| p.into_inner());
            self.registry.store(Arc::new(map));
            *g += 1;
        }
        if let Ok(mut s) = self.sessions.lock() {
            s.retain(|edge, slot| {
                let keep = by_id.get(edge).is_some_and(|fp| *fp == slot.fingerprint);
                if !keep {
                    slot.close.cancel();
                }
                keep
            });
        }
        if let Ok(mut l) = self.live.lock() {
            l.retain(|edge, _| by_id.contains_key(edge));
        }
        if let Ok(mut m) = self.stored_heartbeat.lock() {
            m.retain(|edge, _| by_id.contains_key(edge));
        }
        if let Ok(mut m) = self.hellos.lock() {
            m.retain(|edge, _| by_id.contains_key(edge));
        }
        Ok(())
    }

    /// The registry's refresh count: read it before the database read that
    /// [`Hub::note_registered`] reports.
    pub fn registry_generation(&self) -> u64 {
        *self.registry_gen.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Adds an edge the database says is registered (the edge port's admission) to the registry
    /// before the next refresh would. `generation` is [`Hub::registry_generation`] from before
    /// that database read: when a refresh ran since, the read may predate a key change the
    /// refresh already applied, so nothing is added (the refresh's registry is newer).
    pub fn note_registered(&self, e: &Registered, generation: u64) {
        let g = self.registry_gen.lock().unwrap_or_else(|p| p.into_inner());
        if *g != generation || self.registry.load().get(&e.fingerprint) == Some(e) {
            return;
        }
        let mut m = HashMap::clone(&self.registry.load());
        m.retain(|_, v| v.id != e.id);
        m.insert(e.fingerprint.clone(), e.clone());
        self.registry.store(Arc::new(m));
        drop(g);
    }

    /// True while the registry pins `fingerprint` to `edge`.
    pub fn pins(&self, edge: &str, fingerprint: &str) -> bool {
        self.registry
            .load()
            .get(fingerprint)
            .is_some_and(|r| r.id == edge)
    }

    /// The edge holding `fingerprint` now, if any.
    pub fn registered(&self, fingerprint: &str) -> Option<Registered> {
        self.registry.load().get(fingerprint).cloned()
    }

    /// A registered edge's name.
    pub fn name_of(&self, edge: &str) -> Option<String> {
        self.registry
            .load()
            .values()
            .find(|e| e.id == edge)
            .map(|e| e.name.clone())
    }

    /// Every registered edge id.
    pub fn edge_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.registry.load().values().map(|e| e.id.clone()).collect();
        v.sort();
        v
    }

    // -- sessions ----------------------------------------------------------------------------

    /// Registers a new session for `edge` on a connection that presented `fingerprint`,
    /// replacing (and closing) an older one. Refused when the registry no longer pins that key
    /// to the edge (replaced or deleted while the session waited for its hello; api.md §1): the
    /// check runs under the sessions lock, after which a registry refresh closes the session.
    /// Only then does the hello take one of the edge's tokens ([`Hub::admit_hello`]), so hellos
    /// of a replaced key never spend the edge's share (README §2, Bounded), and a refused hello
    /// replaces nothing.
    pub fn register(
        &self,
        edge: &str,
        fingerprint: &str,
        addr: SocketAddr,
        boot: &str,
    ) -> Result<SessionHandle, Refused> {
        let mut sessions = self.sessions.lock().map_err(|_| Refused::NotRegistered)?;
        if !self.pins(edge, fingerprint) {
            return Err(Refused::NotRegistered);
        }
        if !self.admit_hello(edge) {
            return Err(Refused::TooManyHellos);
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = watch::channel(None);
        let close = CancellationToken::new();
        let slot = Slot {
            id,
            fingerprint: fingerprint.to_string(),
            addr,
            since: Timestamp::now(),
            boot: boot.to_string(),
            changed: tx,
            close: close.clone(),
        };
        if let Some(old) = sessions.insert(edge.to_string(), slot) {
            old.close.cancel();
            self.sessions_replaced.fetch_add(1, Ordering::Relaxed);
        }
        Ok(SessionHandle {
            id,
            changed: rx,
            close,
        })
    }

    // -- session message rates (README §2, Bounded) -----------------------------------------

    /// True when `edge`'s next heartbeat should be stored: none stored yet, or the last stored
    /// one arrived at least the interval ago.
    pub fn heartbeat_due(&self, edge: &str) -> bool {
        let every = self.heartbeat_interval();
        self.stored_heartbeat
            .lock()
            .map(|m| m.get(edge).is_none_or(|t| t.elapsed() >= every))
            .unwrap_or(true)
    }

    /// Records that a heartbeat of `edge` that arrived at `arrived` was stored. The interval
    /// runs from its arrival, not from its commit, so a writer running behind doesn't make the
    /// next heartbeat early (api.md §3: one every 30 s).
    pub fn heartbeat_stored(&self, edge: &str, arrived: tokio::time::Instant) {
        if let Ok(mut m) = self.stored_heartbeat.lock() {
            let t = m.entry(edge.to_string()).or_insert(arrived);
            *t = (*t).max(arrived);
        }
    }

    /// How often an edge's heartbeats are stored ([`HEARTBEAT_STORE_EVERY`] unless a test set
    /// another): also the window for its `cert_roots` (`lanca::rotation::record_served`).
    pub fn heartbeat_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.heartbeat_every_ms.load(Ordering::Relaxed))
    }

    /// Sets how often heartbeats are stored (tests send several in a row).
    pub fn set_heartbeat_interval(&self, every: std::time::Duration) {
        self.heartbeat_every_ms
            .store(picket_api::duration::as_millis_u64(every), Ordering::Relaxed);
    }

    /// Takes one of `edge`'s hello tokens; false when it has none left (the session is refused
    /// and the edge retries with its backoff).
    pub fn admit_hello(&self, edge: &str) -> bool {
        let now = tokio::time::Instant::now();
        let ok = match self.hellos.lock() {
            Ok(mut m) => {
                let (at, tokens) = m.entry(edge.to_string()).or_insert((now, HELLO_BURST));
                let earned = now.duration_since(*at).as_secs_f64() / HELLO_REFILL.as_secs_f64();
                *tokens = (*tokens + earned).min(HELLO_BURST);
                *at = now;
                if *tokens >= 1.0 {
                    *tokens -= 1.0;
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        };
        if !ok {
            self.hellos_refused.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    /// Hellos refused for their edge's rate since start.
    pub fn hellos_refused(&self) -> u64 {
        self.hellos_refused.load(Ordering::Relaxed)
    }

    /// Removes the session `id` of `edge` if it is still the current one; returns whether it was.
    pub fn unregister(&self, edge: &str, id: u64) -> bool {
        match self.sessions.lock() {
            Ok(mut s) => {
                if s.get(edge).is_some_and(|slot| slot.id == id) {
                    s.remove(edge);
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    /// True while session `id` is `edge`'s current session.
    pub fn is_current(&self, edge: &str, id: u64) -> bool {
        self.sessions
            .lock()
            .map(|s| s.get(edge).is_some_and(|slot| slot.id == id))
            .unwrap_or(false)
    }

    /// Announces a new ETag to `edge`'s session, if it has one.
    pub fn notify_changed(&self, edge: &str, etag: &str) {
        if let Ok(s) = self.sessions.lock()
            && let Some(slot) = s.get(edge)
        {
            slot.changed.send_replace(Some(etag.to_string()));
        }
    }

    /// `edge`'s connected session, if any.
    pub fn session(&self, edge: &str) -> Option<SessionInfo> {
        self.sessions.lock().ok()?.get(edge).map(|s| SessionInfo {
            addr: s.addr.to_string(),
            since: crate::util::ts(&s.since),
            boot: s.boot.clone(),
        })
    }

    /// Sessions replaced by a newer one of the same edge since start.
    pub fn sessions_replaced(&self) -> u64 {
        self.sessions_replaced.load(Ordering::Relaxed)
    }

    /// Closes every session (shutdown).
    pub fn close_all(&self) {
        if let Ok(s) = self.sessions.lock() {
            for slot in s.values() {
                slot.close.cancel();
            }
        }
    }

    // -- live state --------------------------------------------------------------------------

    /// A copy of `edge`'s live state.
    pub fn live(&self, edge: &str) -> EdgeLive {
        self.live
            .lock()
            .ok()
            .and_then(|l| l.get(edge).cloned())
            .unwrap_or_default()
    }

    /// Every edge's live state.
    pub fn all_live(&self) -> Vec<(String, EdgeLive)> {
        let mut v: Vec<(String, EdgeLive)> = self
            .live
            .lock()
            .map(|l| l.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Changes `edge`'s live state. Call on the database writer, right after the commit that
    /// stored the change, so the copy follows the database in commit order.
    pub fn update_live(&self, edge: &str, f: impl FnOnce(&mut EdgeLive)) {
        if let Ok(mut l) = self.live.lock() {
            // A deleted edge's entry is dropped at the next registry refresh.
            f(l.entry(edge.to_string()).or_default());
        }
    }

    /// Loads every edge's stored status (at start).
    pub fn load_live(&self, c: &Connection) -> rusqlite::Result<()> {
        let mut st = c.prepare(
            "SELECT s.edge_id, s.last_seen, s.versions_json, s.conditions_json, s.heartbeat_json,
                    s.update_result_json, s.hello_json
             FROM edge_status s JOIN edges e ON e.id = s.edge_id",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<String>>(6)?,
            ))
        })?;
        let mut map = HashMap::new();
        for row in rows.filter_map(Result::ok) {
            let (edge, last_seen, versions, conditions, heartbeat, update, hello) = row;
            fn parse<T: for<'de> Deserialize<'de>>(s: Option<String>) -> Option<T> {
                s.and_then(|s| serde_json::from_str(&s).ok())
            }
            let heartbeat: Option<Heartbeat> = parse(heartbeat);
            let live = EdgeLive {
                hello: parse(hello),
                applied: heartbeat.as_ref().map(|h| h.applied.clone()).unwrap_or_default(),
                have: heartbeat.as_ref().map(|h| h.have.clone()).unwrap_or_default(),
                heartbeat: heartbeat.map(Arc::new),
                heartbeat_at: None,
                last_seen: last_seen.as_deref().and_then(crate::util::parse_ts),
                last_seen_mono: None,
                conditions: parse(conditions).unwrap_or_default(),
                versions: parse(versions),
                update: parse(update),
            };
            map.insert(edge, live);
        }
        if let Ok(mut l) = self.live.lock() {
            *l = map;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edges(rows: &[(&str, &str)]) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE edges (id TEXT, name TEXT, key_sha256 TEXT)")
            .unwrap();
        for (id, fp) in rows {
            c.execute("INSERT INTO edges VALUES (?1, ?1, ?2)", rusqlite::params![id, fp])
                .unwrap();
        }
        c
    }

    fn addr() -> SocketAddr {
        "127.0.0.1:1".parse().unwrap()
    }

    #[test]
    fn an_admission_read_before_a_key_change_never_restores_the_old_key() {
        // api.md §1 Key change (review A1b): the edge port reads the key's edge from the database,
        // then notes it in the registry; a key change committed and refreshed in between must win.
        let hub = Hub::new();
        hub.refresh_registry(&edges(&[("e1", "SHA256:old")])).unwrap();
        let old = Registered {
            id: "e1".into(),
            name: "e1".into(),
            fingerprint: "SHA256:old".into(),
        };
        let seen = hub.registry_generation();
        hub.refresh_registry(&edges(&[("e1", "SHA256:new")])).unwrap();
        hub.note_registered(&old, seen);
        assert!(hub.registered("SHA256:old").is_none());
        assert!(hub.pins("e1", "SHA256:new"));
        // Without a refresh in between, the note is kept.
        let seen = hub.registry_generation();
        let other = Registered {
            id: "e2".into(),
            name: "e2".into(),
            fingerprint: "SHA256:e2".into(),
        };
        hub.note_registered(&other, seen);
        assert!(hub.pins("e2", "SHA256:e2"));
    }

    #[test]
    fn a_session_registers_only_while_its_key_is_pinned() {
        // api.md §1 Key change (review A1a): a session that waited for its hello across a key
        // change or a deletion doesn't register; one registered just before is closed.
        let hub = Hub::new();
        hub.refresh_registry(&edges(&[("e1", "SHA256:old"), ("e2", "SHA256:e2")]))
            .unwrap();
        let before = hub.register("e1", "SHA256:old", addr(), "b1").unwrap();
        hub.refresh_registry(&edges(&[("e1", "SHA256:new")])).unwrap();
        assert!(before.close.is_cancelled());
        assert_eq!(
            hub.register("e1", "SHA256:old", addr(), "b1").err(),
            Some(Refused::NotRegistered)
        );
        assert_eq!(
            hub.register("e2", "SHA256:e2", addr(), "b1").err(),
            Some(Refused::NotRegistered),
            "deleted"
        );
        assert!(hub.register("e1", "SHA256:new", addr(), "b2").is_ok());
    }

    #[test]
    fn heartbeats_are_stored_once_per_interval_and_hellos_are_rationed() {
        let hub = Hub::new();
        assert!(hub.heartbeat_due("e1"));
        hub.heartbeat_stored("e1", tokio::time::Instant::now());
        assert!(!hub.heartbeat_due("e1"));
        assert!(hub.heartbeat_due("e2"));
        hub.set_heartbeat_interval(std::time::Duration::ZERO);
        assert!(hub.heartbeat_due("e1"));
        let admitted = (0..50).filter(|_| hub.admit_hello("e1")).count();
        assert_eq!(admitted, HELLO_BURST as usize);
        assert!(hub.admit_hello("e2"), "each edge has its own share");
        assert_eq!(hub.hellos_refused(), 50 - HELLO_BURST as u64);
    }
}
