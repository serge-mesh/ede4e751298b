//! Requests to an edge (core.md §4, api.md §4): **Update** (`release.install_now`), a flush of
//! the DNS cache or of one lookup provider's RAM tier, and a revoke of a temporary allow. Each
//! is a field of the edge's config object, so an offline edge applies it when it reconnects.
//!
//! - `edge_requests` holds the latest request of each kind per edge (several requests made while
//!   the edge is offline collapse into one), with a new random 64-bit id each time and the time
//!   it was made, for display.
//! - A request is pending until the edge's `applied` (hello and heartbeats) carries its id; the
//!   edge compares ids only for equality.
//! - The revoke list (`revoked_allows`) holds every allow the UI revoked that hasn't ended and
//!   that no acknowledged list covered yet. It gets a new id whenever it changes. Core removes an
//!   allow from it only once the edge acknowledges a list id that covered it, or the edge's log
//!   shows that allow ended; its `expires_at` never removes it (storage.md §3 `temp_allows`).

use rusqlite::{OptionalExtension, Transaction, params};
use serde::Serialize;

use crate::error::{CoreError, CoreResult};
use crate::state::AppState;

/// Request kinds as stored in `edge_requests.kind`.
pub mod kind {
    pub const FLUSH_DNS: &str = "flush_dns";
    pub const FLUSH_LOOKUPS: &str = "flush_lookups";
    pub const INSTALL_NOW: &str = "install_now";
    pub const REVOKED_ALLOWS: &str = "revoked_allows";
}

/// One request, for display.
#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct RequestView {
    pub kind: String,
    /// The lookup provider of a `flush_lookups` request.
    pub provider: Option<String>,
    pub request_id: String,
    pub requested_at: String,
    /// The release an `install_now` request is for.
    pub version: Option<String>,
    /// True until the edge's `applied` carries this id.
    pub pending: bool,
}

fn upsert(
    tx: &Transaction<'_>,
    edge: &str,
    kind: &str,
    provider: &str,
    version: Option<&str>,
    blake3: Option<&str>,
) -> rusqlite::Result<String> {
    let id = picket_api::ids::new_id64();
    tx.execute(
        "INSERT INTO edge_requests(edge_id, kind, provider, request_id, version, blake3, requested_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(edge_id, kind, provider) DO UPDATE SET request_id = excluded.request_id,
            version = excluded.version, blake3 = excluded.blake3, requested_at = excluded.requested_at",
        params![edge, kind, provider, id, version, blake3, crate::util::now_ts()],
    )?;
    Ok(id)
}

fn edge_exists(tx: &Transaction<'_>, edge: &str) -> rusqlite::Result<bool> {
    Ok(tx
        .query_row("SELECT 1 FROM edges WHERE id = ?1", [edge], |_| Ok(()))
        .optional()?
        .is_some())
}

/// Requests a flush of `edge`'s DNS cache (`provider: None`) or of one lookup provider's RAM
/// tier. Returns the request id.
pub async fn flush(state: &AppState, edge: &str, provider: Option<String>) -> CoreResult<String> {
    if let Some(p) = &provider {
        let m = state
            .config
            .model_of(crate::config::EntityKind::LookupProvider)
            .await?;
        if !m.lookup_providers.contains_key(p) {
            return Err(CoreError::NotFound(format!("no lookup provider {p:?}")));
        }
    }
    let edge_s = edge.to_string();
    let id = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            if !edge_exists(&tx, &edge_s)? {
                return Err(CoreError::NotFound(format!("no edge {edge_s:?}")));
            }
            let id = match provider.as_deref() {
                None => upsert(&tx, &edge_s, kind::FLUSH_DNS, "", None, None)?,
                Some(p) => upsert(&tx, &edge_s, kind::FLUSH_LOOKUPS, p, None, None)?,
            };
            tx.commit()?;
            Ok::<_, CoreError>(id)
        })
        .await?;
    state.edges.publisher.trigger(Some(edge));
    Ok(id)
}

/// **Update** (core.md §5): sets `release.install_now` to a new id with the offered release's
/// version and BLAKE3 for the edge's architecture. Refused while core offers no release, or the
/// edge's architecture isn't known yet (it reports it in `hello`).
pub async fn install_now(state: &AppState, edge: &str) -> CoreResult<String> {
    let offer = state
        .edges
        .releases
        .offer()
        .ok_or_else(|| CoreError::Conflict("core offers no edge release (see release_invalid)".into()))?;
    let live = state.edges.hub.live(edge);
    let arch = live.hello.as_ref().map(|h| h.arch.clone()).ok_or_else(|| {
        CoreError::Conflict("the edge hasn't connected yet, so its architecture is unknown".into())
    })?;
    let blake3 = offer
        .tarballs
        .get(&arch)
        .cloned()
        .ok_or_else(|| CoreError::Conflict(format!("core has no {arch} release to offer")))?;
    let edge_s = edge.to_string();
    let version = offer.version.clone();
    let id = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            if !edge_exists(&tx, &edge_s)? {
                return Err(CoreError::NotFound(format!("no edge {edge_s:?}")));
            }
            let id = upsert(&tx, &edge_s, kind::INSTALL_NOW, "", Some(&version), Some(&blake3))?;
            tx.commit()?;
            Ok::<_, CoreError>(id)
        })
        .await?;
    state.edges.publisher.trigger(Some(edge));
    Ok(id)
}

/// Gives the revoke list a new id when the allows it holds changed (api.md §4: a new id
/// whenever it changes). Call inside the transaction that changed `temp_allows`.
pub fn refresh_revoke_list(tx: &Transaction<'_>, edge: &str) -> rusqlite::Result<bool> {
    let listed: Vec<String> = {
        let mut st = tx.prepare(
            "SELECT allow_id FROM temp_allows WHERE edge_id = ?1 AND revoke_requested_at IS NOT NULL
               AND ended_at IS NULL AND revoke_acked_at IS NULL ORDER BY allow_id",
        )?;
        st.query_map([edge], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    let fingerprint = picket_api::ids::object_id(listed.join("\n").as_bytes());
    // `blake3` of the row keeps the list's content hash, so an unchanged list keeps its id.
    let current: Option<Option<String>> = tx
        .query_row(
            "SELECT blake3 FROM edge_requests WHERE edge_id = ?1 AND kind = ?2 AND provider = ''",
            params![edge, kind::REVOKED_ALLOWS],
            |r| r.get(0),
        )
        .optional()?;
    match current {
        Some(Some(h)) if h == fingerprint => Ok(false),
        None if listed.is_empty() => Ok(false),
        _ => {
            upsert(tx, edge, kind::REVOKED_ALLOWS, "", None, Some(&fingerprint))?;
            Ok(true)
        }
    }
}

/// Revokes a temporary allow on `edge` (Temporary allows → revoke): it joins the edge's revoke
/// list, which gets a new id. An allow core hasn't heard of yet is recorded too, so the edge
/// still ends it (it ignores unknown ones).
pub async fn revoke_allow(state: &AppState, edge: &str, allow_id: &str) -> CoreResult<String> {
    if allow_id.is_empty() || allow_id.len() > 64 {
        return Err(CoreError::Invalid("an allow id is 1–64 characters".into()));
    }
    let (edge_s, allow) = (edge.to_string(), allow_id.to_string());
    let coalesced = state.events.coalesced().clone();
    let id = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            if !edge_exists(&tx, &edge_s)? {
                return Err(CoreError::NotFound(format!("no edge {edge_s:?}")));
            }
            let ended: Option<Option<String>> = tx
                .query_row(
                    "SELECT ended_at FROM temp_allows WHERE edge_id = ?1 AND allow_id = ?2",
                    params![edge_s, allow],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(Some(_)) = ended {
                return Err(CoreError::Conflict("that allow has already ended".into()));
            }
            let now = crate::util::now_ts();
            tx.execute(
                "INSERT INTO temp_allows(edge_id, allow_id, revoke_requested_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(edge_id, allow_id) DO UPDATE SET revoke_requested_at = excluded.revoke_requested_at,
                    revoke_acked_at = NULL",
                params![edge_s, allow, now],
            )?;
            refresh_revoke_list(&tx, &edge_s)?;
            let id: String = tx.query_row(
                "SELECT request_id FROM edge_requests WHERE edge_id = ?1 AND kind = ?2 AND provider = ''",
                params![edge_s, kind::REVOKED_ALLOWS],
                |r| r.get(0),
            )?;
            tx.commit()?;
            // On the writer, right after the commit (`web::events` module docs).
            coalesced.temp_allow(&edge_s, crate::web::events::AllowChange::RevokeRequested);
            Ok::<_, CoreError>(id)
        })
        .await?;
    state.edges.publisher.trigger(Some(edge));
    Ok(id)
}

/// What an acknowledgement did ([`ack_revoke_list`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Acked {
    /// The revoke list changed (the config must be re-rendered).
    pub changed: bool,
    /// Allows whose revoke was acknowledged (their state is now `revoked`).
    pub allows: usize,
}

/// Acknowledgements in a hello or heartbeat (`applied.revoked_allows`): when the edge applied
/// the current revoke list's id, every allow on it is acknowledged and leaves the list, which
/// then gets a new id.
pub fn ack_revoke_list(tx: &Transaction<'_>, edge: &str, applied: Option<&str>) -> rusqlite::Result<Acked> {
    let Some(applied) = applied else {
        return Ok(Acked::default());
    };
    let current: Option<String> = tx
        .query_row(
            "SELECT request_id FROM edge_requests WHERE edge_id = ?1 AND kind = ?2 AND provider = ''",
            params![edge, kind::REVOKED_ALLOWS],
            |r| r.get(0),
        )
        .optional()?;
    // Ids compare only for equality (api.md §4): an older id acknowledges nothing.
    if current.as_deref() != Some(applied) {
        return Ok(Acked::default());
    }
    let n = tx.execute(
        "UPDATE temp_allows SET revoke_acked_at = ?2 WHERE edge_id = ?1 AND revoke_requested_at IS NOT NULL
           AND ended_at IS NULL AND revoke_acked_at IS NULL",
        params![edge, crate::util::now_ts()],
    )?;
    if n == 0 {
        return Ok(Acked::default());
    }
    Ok(Acked {
        changed: refresh_revoke_list(tx, edge)?,
        allows: n,
    })
}

/// `edge`'s requests with their pending state against `applied`.
pub fn views(
    c: &rusqlite::Connection,
    edge: &str,
    applied: &picket_api::session::Applied,
) -> rusqlite::Result<Vec<RequestView>> {
    let mut st = c.prepare(
        "SELECT kind, provider, request_id, requested_at, version, blake3 FROM edge_requests WHERE edge_id = ?1
         ORDER BY kind, provider",
    )?;
    let rows = st.query_map([edge], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, Option<String>>(5)?,
        ))
    })?;
    let empty_list = picket_api::ids::object_id(b"");
    let mut out = Vec::new();
    for row in rows {
        let (kind, provider, request_id, requested_at, version, blake3) = row?;
        // An emptied revoke list isn't rendered (api.md §4: null when there are none), so there
        // is nothing for the edge to apply.
        if kind == kind::REVOKED_ALLOWS && blake3.as_deref() == Some(empty_list.as_str()) {
            continue;
        }
        let applied_id = match kind.as_str() {
            kind::FLUSH_DNS => applied.flush_dns.as_deref(),
            kind::FLUSH_LOOKUPS => applied.flush_lookups.get(&provider).map(String::as_str),
            kind::INSTALL_NOW => applied.install_now.as_deref(),
            kind::REVOKED_ALLOWS => applied.revoked_allows.as_deref(),
            _ => None,
        };
        out.push(RequestView {
            pending: applied_id != Some(request_id.as_str()),
            provider: (!provider.is_empty()).then_some(provider),
            kind,
            request_id,
            requested_at,
            version,
        });
    }
    Ok(out)
}
