//! Self-update bookkeeping on the edge side (edge.md §14). The download, signature check and
//! `pending.json` handoff are [`crate::release`]'s ([`crate::hooks::UpdateHandoff`]); this module
//! decides whether an `install_now` request installs anything, keeps `applied.install_now`
//! across restarts, and imports the updater's result as an `update_ok` / `update_failed` event.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use picket_api::edge_config::{InstallNow, ReleaseOffer};
use picket_api::logs::event_kind;
use picket_api::session::{Outcome, UpdateOutcome};
use picket_api::time::Timestamp;
use picket_api::update::{Pending, UpdateResult, compare_versions, is_release_version, stage};

use crate::edge::Edge;
use crate::fsutil;
use crate::logs::{Delivery, DropReason, event_record, fields};
use crate::state::StateStore;

const MAX_RESULT: u64 = 64 << 10;

/// What to do about the config object's `release.install_now`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallDecision {
    /// No request, the id was applied already, or it doesn't match the offer: nothing to do.
    Ignore,
    /// The edge installs nothing (already on that release, a rule forbids it, or updates are
    /// disabled): the id counts as applied at once.
    AppliedNothing(String),
    /// Hand the release to the updater; the id counts as applied once that succeeded.
    HandOff(InstallNow),
}

/// Decides an `install_now` request (edge.md §14 When): acted on only when its id differs from
/// the last applied one and its version and blake3 match the offered release; never a downgrade
/// unless `release.rollback`; never the version last rolled back from while core still offers
/// it; nothing with `updates_enabled: false`.
pub fn decide_install(
    offer: Option<&ReleaseOffer>,
    applied: Option<&str>,
    updates_enabled: bool,
    rollback_from: Option<&str>,
    running: &str,
) -> InstallDecision {
    let Some(offer) = offer else {
        return InstallDecision::Ignore;
    };
    let Some(req) = offer.install_now.as_ref() else {
        return InstallDecision::Ignore;
    };
    if !picket_api::ids::is_id64(&req.id) || applied == Some(req.id.as_str()) {
        return InstallDecision::Ignore;
    }
    if req.version != offer.version || req.blake3 != offer.blake3 {
        return InstallDecision::Ignore;
    }
    let installs_nothing = !updates_enabled
        || !is_release_version(&req.version)
        || req.version == running
        || rollback_from == Some(req.version.as_str())
        || (!offer.rollback && compare_versions(&req.version, running) == Some(std::cmp::Ordering::Less));
    if installs_nothing {
        InstallDecision::AppliedNothing(req.id.clone())
    } else {
        InstallDecision::HandOff(req.clone())
    }
}

/// Reads `bin/update-result.json` leniently: a valid result with a malformed or empty version is
/// still accepted (its version reported as best we can), its `at` clamped to our clock. Returns
/// `None` when there is no file or it carries no usable `result_id` / `outcome`.
pub fn read_result(path: &Path) -> Result<Option<UpdateResult>> {
    let (bytes, mtime) = match std::fs::metadata(path) {
        Ok(m) => (fsutil::read_bounded(path, MAX_RESULT)?, m.modified().ok()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let v: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("{} isn't valid JSON: {}", path.display(), crate::diag::cap(e));
            return Ok(None);
        }
    };
    Ok(parse_result(&v, mtime.and_then(|t| Timestamp::try_from(t).ok())))
}

fn clean(s: &str, max: usize) -> String {
    let t: String = s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').collect();
    crate::diag::truncate(t.trim(), max)
}

pub fn parse_result(v: &serde_json::Value, mtime: Option<Timestamp>) -> Option<UpdateResult> {
    let result_id = v
        .get("result_id")?
        .as_str()
        .map(|s| clean(s, 64))
        .filter(|s| !s.is_empty())?;
    let outcome = match v.get("outcome")?.as_str()? {
        "ok" => Outcome::Ok,
        "failed" => Outcome::Failed,
        _ => return None,
    };
    let version = v
        .get("version")
        .and_then(|x| x.as_str())
        .map(|s| clean(s, 64))
        .unwrap_or_default();
    let stage = v
        .get("stage")
        .and_then(|x| x.as_str())
        .map(|s| clean(s, 64))
        .filter(|s| !s.is_empty());
    let request_id = v
        .get("request_id")
        .and_then(|x| x.as_str())
        .filter(|s| picket_api::ids::is_id64(s))
        .map(str::to_owned);
    let now = Timestamp::now();
    let at = v
        .get("at")
        .and_then(|x| x.as_str())
        .and_then(|s| picket_api::time::parse(s).ok())
        .or(mtime)
        .unwrap_or(now);
    Some(UpdateResult {
        result_id,
        request_id,
        outcome,
        stage,
        version,
        at: picket_api::time::clamp_to_now(at, now),
    })
}

/// Whether a failed result means the edge must not install that version again until core offers
/// a different one (edge.md §14): after a rollback (stage `readiness`, `units` or `rollback`),
/// and for a release whose signed trusted comment doesn't name the pending version and this
/// architecture (`verify`: it "fails its signature check" every time). Not for `unpack` (no space
/// on the drive, say), `locked`, `superseded` or `pending`, which may succeed on a later try;
/// convergence retries those with backoff (§13).
fn blocks_reinstall(r: &UpdateResult) -> bool {
    r.outcome == Outcome::Failed
        && matches!(
            r.stage.as_deref(),
            Some(stage::READINESS | stage::UNITS | stage::ROLLBACK | stage::VERIFY)
        )
        && is_release_version(&r.version)
}

/// At start, before any handoff (edge.md §14): record as applied the request id in
/// `pending.json`, else that of an updater result not imported yet, so a stop between the
/// handoff and saving the id doesn't install twice.
pub fn record_startup_install_id(
    state: &StateStore,
    releases_dir: &Path,
    result_path: Option<&Path>,
) -> Result<()> {
    let pending_id = fsutil::read_bounded(&releases_dir.join("pending.json"), MAX_RESULT)
        .ok()
        .and_then(|b| serde_json::from_slice::<Pending>(&b).ok())
        .and_then(|p| p.request_id)
        .filter(|id| picket_api::ids::is_id64(id));
    let id = match pending_id {
        Some(id) => Some(id),
        None => {
            let cur = state.get();
            result_path
                .and_then(|p| read_result(p).ok().flatten())
                .filter(|r| cur.update.as_ref().is_none_or(|u| u.result_id != r.result_id))
                .and_then(|r| r.request_id)
        }
    };
    if let Some(id) = id {
        state.update(|s| s.applied.install_now = Some(id))?;
    }
    Ok(())
}

/// Imports updater results: at start and every few seconds (the updater writes its result once
/// the new edge is up, so it appears shortly after start), a result whose `result_id` isn't the
/// latest outcome's is logged as `update_ok` / `update_failed` with `ts` = its `at` (so a
/// re-import past the retention window is dropped as too old). Once the event is acked or fsynced
/// into the spool, the outcome is saved in `state.json`; a stop in between imports it again
/// under a new `(boot, seq)` and core drops the repeat by its `result_id`.
pub async fn import_loop(edge: Arc<Edge>, result_path: PathBuf, every: Duration) -> Result<()> {
    loop {
        if let Err(e) = import_once(&edge, &result_path).await {
            tracing::warn!("update result import: {}", crate::diag::cap_chain(&e));
        }
        tokio::time::sleep(every).await;
    }
}

/// One import attempt. Returns the delivery when it logged an event.
pub async fn import_once(edge: &Arc<Edge>, result_path: &Path) -> Result<Option<Delivery>> {
    let p = result_path.to_path_buf();
    let Some(r) = tokio::task::spawn_blocking(move || read_result(&p)).await?? else {
        return Ok(None);
    };
    let cur = edge.state.get();
    if cur.update.as_ref().is_some_and(|u| u.result_id == r.result_id) {
        return Ok(None);
    }
    let kind = match r.outcome {
        Outcome::Ok => event_kind::UPDATE_OK,
        Outcome::Failed => event_kind::UPDATE_FAILED,
    };
    let mut f = fields(&[
        ("result_id", r.result_id.clone().into()),
        ("version", r.version.clone().into()),
    ]);
    if let Some(s) = &r.stage {
        f.insert("stage".into(), s.clone().into());
    }
    let receipt = edge.logs.emit_at_with_receipt(event_record(kind, f), r.at);
    // Bounded: if the record can't leave the buffer (the spool can't be written), try again in
    // a later round; core drops a repeat by its result_id.
    let delivery = tokio::time::timeout(Duration::from_secs(300), receipt)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(Delivery::Dropped(DropReason::BufferFull));
    let final_ = match delivery {
        Delivery::Acked | Delivery::Spooled => true,
        // Core refused it, or it is past retention: importing again can't help. Save it, so
        // `hello`/heartbeats carry the outcome and the import doesn't loop.
        Delivery::Dropped(DropReason::Rejected | DropReason::TooOld) => true,
        // Not delivered (buffer full, shutdown): try again next round.
        Delivery::Dropped(_) => false,
    };
    if final_ {
        let outcome = UpdateOutcome {
            result_id: r.result_id.clone(),
            outcome: r.outcome,
            version: r.version.clone(),
            at: r.at,
        };
        let block = blocks_reinstall(&r).then(|| r.version.clone());
        edge.state
            .update_async(move |s| {
                s.update = Some(outcome);
                if let Some(v) = block {
                    s.rollback_from = Some(v);
                }
            })
            .await?;
    }
    Ok(Some(delivery))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(version: &str, id: Option<&str>) -> ReleaseOffer {
        ReleaseOffer {
            auto_update: false,
            version: version.into(),
            blake3: "b3".into(),
            rollback: false,
            install_now: id.map(|i| InstallNow {
                id: i.into(),
                version: version.into(),
                blake3: "b3".into(),
            }),
        }
    }

    const ID: &str = "0123456789abcdef";

    #[test]
    fn install_rules() {
        use InstallDecision::*;
        assert_eq!(decide_install(None, None, true, None, "1.0.0"), Ignore);
        assert_eq!(
            decide_install(Some(&offer("1.1.0", None)), None, true, None, "1.0.0"),
            Ignore
        );
        assert!(matches!(
            decide_install(Some(&offer("1.1.0", Some(ID))), None, true, None, "1.0.0"),
            HandOff(_)
        ));
        // Compared by equality only: an older-looking id is still new.
        assert!(matches!(
            decide_install(
                Some(&offer("1.1.0", Some(ID))),
                Some("ffffffffffffffff"),
                true,
                None,
                "1.0.0"
            ),
            HandOff(_)
        ));
        assert_eq!(
            decide_install(Some(&offer("1.1.0", Some(ID))), Some(ID), true, None, "1.0.0"),
            Ignore
        );
        assert_eq!(
            decide_install(Some(&offer("1.1.0", Some(ID))), None, false, None, "1.0.0"),
            AppliedNothing(ID.into()),
            "updates disabled"
        );
        assert_eq!(
            decide_install(Some(&offer("1.0.0", Some(ID))), None, true, None, "1.0.0"),
            AppliedNothing(ID.into())
        );
        assert_eq!(
            decide_install(Some(&offer("0.9.0", Some(ID))), None, true, None, "1.0.0"),
            AppliedNothing(ID.into())
        );
        let mut rb = offer("0.9.0", Some(ID));
        rb.rollback = true;
        assert!(matches!(
            decide_install(Some(&rb), None, true, None, "1.0.0"),
            HandOff(_)
        ));
        assert_eq!(
            decide_install(
                Some(&offer("1.1.0", Some(ID))),
                None,
                true,
                Some("1.1.0"),
                "1.0.0"
            ),
            AppliedNothing(ID.into())
        );
        let mut mismatch = offer("1.1.0", Some(ID));
        mismatch.install_now.as_mut().unwrap().blake3 = "other".into();
        assert_eq!(decide_install(Some(&mismatch), None, true, None, "1.0.0"), Ignore);
    }

    #[test]
    fn lenient_result_parsing() {
        let v = serde_json::json!({"result_id": "a1b2c3d4e5f60718", "request_id": ID, "outcome": "failed",
            "stage": "readiness", "version": "", "at": "2026-11-20T10:00:00.000000Z"});
        let r = parse_result(&v, None).unwrap();
        assert_eq!(r.version, "");
        assert_eq!(r.outcome, Outcome::Failed);
        assert_eq!(r.request_id.as_deref(), Some(ID));
        let v = serde_json::json!({"result_id": "x", "outcome": "failed", "version": "../../etc\n1.2", "at": "garbage"});
        let r = parse_result(&v, None).unwrap();
        assert!(!r.version.contains('\n'));
        assert!(r.at <= Timestamp::now());
        let v = serde_json::json!({"result_id": "x", "outcome": "ok", "version": 7, "at": "2999-01-01T00:00:00Z"});
        let r = parse_result(&v, None).unwrap();
        assert_eq!(r.version, "");
        assert!(r.at <= Timestamp::now(), "clamped to our clock");
        assert!(parse_result(&serde_json::json!({"outcome": "ok"}), None).is_none());
        assert!(parse_result(&serde_json::json!({"result_id": "x", "outcome": "maybe"}), None).is_none());
        assert!(!blocks_reinstall(&parse_result(&serde_json::json!({"result_id": "x", "outcome": "failed", "stage": "locked", "version": "1.2.3"}), None).unwrap()));
        assert!(blocks_reinstall(&parse_result(&serde_json::json!({"result_id": "x", "outcome": "failed", "stage": "readiness", "version": "1.2.3"}), None).unwrap()));
        let failed_at = |stage: &str| {
            parse_result(
                &serde_json::json!({"result_id": "x", "outcome": "failed", "stage": stage, "version": "1.2.3"}),
                None,
            )
            .unwrap()
        };
        // A rollback (edge.md §14 step 4) and a release that fails verification block it.
        for st in ["readiness", "units", "rollback", "verify"] {
            assert!(blocks_reinstall(&failed_at(st)), "{st}");
        }
        // Anything else (no space to unpack, the lock busy, superseded) may succeed next time.
        for st in ["unpack", "locked", "superseded", "pending"] {
            assert!(!blocks_reinstall(&failed_at(st)), "{st}");
        }
    }

    #[test]
    fn startup_records_pending_or_unimported_request_id() {
        let d = tempfile::tempdir().unwrap();
        let state = StateStore::load(&d.path().join("state.json")).unwrap();
        let releases = d.path().join("releases");
        std::fs::create_dir_all(&releases).unwrap();
        let result = d.path().join("update-result.json");
        std::fs::write(
            &result,
            serde_json::json!({"result_id": "r1", "request_id": "1111111111111111", "outcome": "ok", "version": "1.1.0",
                "at": "2026-11-20T10:00:00Z"})
            .to_string(),
        )
        .unwrap();
        record_startup_install_id(&state, &releases, Some(&result)).unwrap();
        assert_eq!(
            state.get().applied.install_now.as_deref(),
            Some("1111111111111111")
        );
        std::fs::write(
            releases.join("pending.json"),
            r#"{"version":"1.2.0","request_id":"2222222222222222"}"#,
        )
        .unwrap();
        record_startup_install_id(&state, &releases, Some(&result)).unwrap();
        assert_eq!(
            state.get().applied.install_now.as_deref(),
            Some("2222222222222222")
        );
    }
}
