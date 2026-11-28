//! The configuration model (core.md §2): entities, validation, system objects, secrets at rest
//! and the change journal. [`ConfigStore`] is the async handle the rest of core uses.

pub mod credentials;
pub mod export;
pub mod journal;
pub mod model;
pub mod secrets;
pub mod store;
pub mod system;
pub mod validate;

use std::sync::Arc;

use arc_swap::ArcSwap;
use serde_json::Value;
use tokio::sync::watch;

use crate::db::Db;
use crate::error::{CoreError, CoreResult};
use crate::settings::Settings;
pub use model::{EntityKind, Model};
pub use secrets::SecretsKey;
pub use store::{Actor, Op, Outcome, SaveOpts};
pub use validate::Issue;

/// Async access to the configuration. Every write goes through the writer task as one
/// transaction. The settings snapshot and the generation are published by the writer itself,
/// right after the commit: in commit order, and even when the caller has gone away (a client
/// that disconnects after its save was queued), so the running copy never lags core.db (README
/// §2 "Settings reach their user"; core.md §2, §11).
#[derive(Clone)]
pub struct ConfigStore {
    db: Db,
    secrets_key: Option<Arc<SecretsKey>>,
    settings: Arc<ArcSwap<Settings>>,
    generation: Arc<watch::Sender<u64>>,
}

impl ConfigStore {
    pub fn new(db: Db, secrets_key: Option<Arc<SecretsKey>>, settings: Settings) -> Self {
        let (tx, _) = watch::channel(0);
        Self {
            db,
            secrets_key,
            settings: Arc::new(ArcSwap::from_pointee(settings)),
            generation: Arc::new(tx),
        }
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    /// The current settings snapshot (cheap).
    pub fn settings(&self) -> Arc<Settings> {
        self.settings.load_full()
    }

    /// A receiver that changes after every committed configuration change (edges re-render
    /// configs, the compiler rebuilds, …).
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    /// What the writer publishes after a commit (it outlives the caller's future).
    fn publisher(&self) -> Publisher {
        Publisher {
            settings: self.settings.clone(),
            generation: self.generation.clone(),
        }
    }

    /// Loads the whole model.
    pub async fn model(&self) -> CoreResult<Model> {
        self.db
            .read(|c| store::load_model(c).map_err(CoreError::Other))
            .await
    }

    /// The settings and one kind's entities (listing, reading one entity).
    pub async fn model_of(&self, kind: EntityKind) -> CoreResult<Model> {
        self.db
            .read(move |c| store::load_kind(c, kind).map_err(CoreError::Other))
            .await
    }

    /// Current configuration problems (errors and warnings).
    pub async fn issues(&self) -> CoreResult<Vec<Issue>> {
        let m = self.model().await?;
        let mut issues = validate::validate(&m);
        // Binds the edges' last hellos don't allow (core.md §4).
        let reported = self
            .db
            .read(|c| {
                let mut st =
                    c.prepare("SELECT edge_id, hello_json FROM edge_status WHERE hello_json IS NOT NULL")?;
                let rows = st
                    .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                let mut out = std::collections::BTreeMap::new();
                for (edge, hello) in rows {
                    if let Some(b) = serde_json::from_str::<Value>(&hello)
                        .ok()
                        .and_then(|h| h.get("allowed_binds").cloned())
                        .and_then(|b| serde_json::from_value::<Vec<String>>(b).ok())
                    {
                        out.insert(edge, b);
                    }
                }
                Ok::<_, CoreError>(out)
            })
            .await?;
        issues.extend(validate::allowed_binds(&m, &reported));
        Ok(issues)
    }

    /// Creates, replaces or deletes one entity.
    pub async fn apply(
        &self,
        kind: EntityKind,
        op: Op,
        actor: Actor,
        clear_cached_verdicts: Option<bool>,
    ) -> CoreResult<Outcome> {
        self.apply_with(
            kind,
            op,
            actor,
            store::SaveOpts {
                clear_cached_verdicts,
                ..Default::default()
            },
        )
        .await
    }

    /// [`Self::apply`] with every save option.
    pub async fn apply_with(
        &self,
        kind: EntityKind,
        op: Op,
        actor: Actor,
        opts: store::SaveOpts,
    ) -> CoreResult<Outcome> {
        let p = self.publisher();
        self.db
            .write(move |c| {
                let tx = c.transaction()?;
                let out = store::apply_with(&tx, kind, op, &actor, opts)?;
                tx.commit()?;
                p.publish(None);
                Ok::<_, CoreError>(out)
            })
            .await
    }

    /// Runs `f` in a config transaction and publishes the change (feeds core adds or removes
    /// itself: a listing's new provider feeds, a restore). `f` journals what it changes.
    pub async fn change<T: Send + 'static>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> CoreResult<T> + Send + 'static,
    ) -> CoreResult<T> {
        let p = self.publisher();
        self.db
            .write(move |c| {
                let tx = c.transaction()?;
                let out = f(&tx)?;
                tx.commit()?;
                p.publish(None);
                Ok::<_, CoreError>(out)
            })
            .await
    }

    /// Replaces the whole configuration in one transaction (the config restore, core.md §2):
    /// `f` gets the secrets key to seal the values the document carries; `after` runs on the
    /// writer right after the commit, before the new settings and generation are published.
    pub async fn replace_all<T: Send + 'static>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction<'_>, Option<&SecretsKey>) -> CoreResult<T> + Send + 'static,
        after: impl FnOnce(&T) + Send + 'static,
    ) -> CoreResult<T> {
        let key = self.secrets_key.clone();
        let p = self.publisher();
        self.db
            .write(move |c| {
                let tx = c.transaction()?;
                let out = f(&tx, key.as_deref())?;
                tx.commit()?;
                after(&out);
                let settings = crate::settings::load(c).map_err(CoreError::Other)?;
                p.publish(Some(settings));
                Ok::<_, CoreError>(out)
            })
            .await
    }

    /// Runs `f` in one config transaction that may change settings; `after` runs on the writer
    /// right after the commit, before the new settings and generation are published, and
    /// returns false to publish nothing (a test stopping there as a crash would). The LAN CA
    /// rotation puts its new root in place in `after`, so nothing sees the new `lanca.zones`
    /// with the old root (core.md §11, [`crate::lanca::rotation`]).
    pub async fn change_settings<T: Send + 'static>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> CoreResult<T> + Send + 'static,
        after: impl FnOnce(&T) -> bool + Send + 'static,
    ) -> CoreResult<(T, bool)> {
        let p = self.publisher();
        self.db
            .write(move |c| {
                let tx = c.transaction()?;
                let out = f(&tx)?;
                tx.commit()?;
                if !after(&out) {
                    return Ok::<_, CoreError>((out, false));
                }
                let settings = crate::settings::load(c).map_err(CoreError::Other)?;
                p.publish(Some(settings));
                Ok((out, true))
            })
            .await
    }

    /// Applies a settings patch.
    pub async fn patch_settings(&self, patch: Value, actor: Actor) -> CoreResult<Settings> {
        let p = self.publisher();
        self.db
            .write(move |c| {
                let tx = c.transaction()?;
                let s = store::apply_settings(&tx, &patch, &actor, false)?;
                tx.commit()?;
                p.publish(Some(s.clone()));
                Ok::<_, CoreError>(s)
            })
            .await
    }

    pub async fn reorder_clients(&self, names: Vec<String>, actor: Actor) -> CoreResult<()> {
        let p = self.publisher();
        self.db
            .write(move |c| {
                let tx = c.transaction()?;
                store::reorder_clients(&tx, &names, &actor)?;
                tx.commit()?;
                p.publish(None);
                Ok::<_, CoreError>(())
            })
            .await
    }

    pub async fn set_secret(&self, name: String, value: String, actor: Actor) -> CoreResult<()> {
        let key = self.secrets_key.clone();
        let p = self.publisher();
        self.db
            .write(move |c| {
                let tx = c.transaction()?;
                store::set_secret(&tx, key.as_deref(), &name, &value, &actor)?;
                tx.commit()?;
                p.publish(None);
                Ok::<_, CoreError>(())
            })
            .await
    }

    pub async fn delete_secret(&self, name: String, actor: Actor) -> CoreResult<()> {
        let p = self.publisher();
        self.db
            .write(move |c| {
                let tx = c.transaction()?;
                store::delete_secret(&tx, &name, &actor)?;
                tx.commit()?;
                p.publish(None);
                Ok::<_, CoreError>(())
            })
            .await
    }

    /// Decrypted secret values for rendering edge configs (never for the UI).
    pub async fn secret_values(
        &self,
        names: Vec<String>,
    ) -> CoreResult<std::collections::BTreeMap<String, String>> {
        let key = self.secrets_key.clone();
        self.db
            .read(move |c| store::read_secret_values(c, key.as_deref(), &names).map_err(CoreError::Other))
            .await
    }
}

/// Publishes a commit to the running process: the new settings snapshot (when settings changed)
/// and a generation bump. Called on the writer thread, right after the commit.
struct Publisher {
    settings: Arc<ArcSwap<Settings>>,
    generation: Arc<watch::Sender<u64>>,
}

impl Publisher {
    fn publish(&self, settings: Option<Settings>) {
        if let Some(s) = settings {
            self.settings.store(Arc::new(s));
        }
        self.generation.send_modify(|g| *g = g.wrapping_add(1));
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll};

    use super::*;

    fn store() -> (tempfile::TempDir, ConfigStore) {
        let d = tempfile::tempdir().unwrap();
        let opts = crate::db::DbOptions::core(d.path());
        crate::db::migrate::create_fresh(&opts, &crate::db::migrate::CORE).unwrap();
        let db = Db::open(opts).unwrap();
        (d, ConfigStore::new(db, None, Settings::default()))
    }

    /// Polls `f` once (queueing its write), then drops it: a client that disconnects.
    fn poll_once_then_drop<F: Future>(f: F) {
        let mut f = pin!(f);
        let waker = futures_util::task::noop_waker();
        assert!(f.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    }

    async fn stored(c: &ConfigStore) -> Settings {
        c.db().read(crate::settings::load).await.unwrap()
    }

    #[tokio::test]
    async fn a_save_whose_caller_went_away_still_reaches_the_running_copy() {
        // README §2 "Settings reach their user": the write was queued, so it commits; the
        // running copy (the web guard's allowlist) must follow it.
        let (_d, c) = store();
        let gen_rx = c.subscribe();
        poll_once_then_drop(c.patch_settings(
            serde_json::json!({"web": {"allow_cidrs": ["10.0.0.0/8"]}}),
            Actor::cli(),
        ));
        assert!(c.db().ping(std::time::Duration::from_secs(5)).await);
        assert_eq!(stored(&c).await.web.allow_cidrs, vec!["10.0.0.0/8"]);
        assert_eq!(c.settings().web.allow_cidrs, vec!["10.0.0.0/8"]);
        assert!(gen_rx.has_changed().unwrap(), "subscribers are told");
    }

    #[tokio::test]
    async fn concurrent_saves_publish_in_commit_order() {
        // An older snapshot never overwrites a newer one, whatever order the callers resume in.
        let (_d, c) = store();
        let waker = futures_util::task::noop_waker();
        let mut first = pin!(c.patch_settings(
            serde_json::json!({"web": {"allow_cidrs": ["0.0.0.0/0"]}}),
            Actor::cli()
        ));
        assert!(first.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        // The second save commits after the first and restricts access.
        c.patch_settings(
            serde_json::json!({"web": {"allow_cidrs": ["127.0.0.1/32"]}}),
            Actor::cli(),
        )
        .await
        .unwrap();
        // The first caller resumes last.
        let r = std::future::poll_fn(|cx| match first.as_mut().poll(cx) {
            Poll::Ready(r) => Poll::Ready(r),
            Poll::Pending => Poll::Pending,
        })
        .await;
        r.unwrap();
        assert_eq!(stored(&c).await.web.allow_cidrs, vec!["127.0.0.1/32"]);
        assert_eq!(c.settings().web.allow_cidrs, vec!["127.0.0.1/32"]);
    }
}
