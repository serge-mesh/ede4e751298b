//! Basic auth for the UI (core.md §12): one account, `admin`, its password stored only as an
//! argon2id hash in `ui_account`. Checked on the UI's assets, `/api/ui/v1` and the UI WebSocket
//! upgrade.
//!
//! **Failed logins:** from one IP, after 5 failures in 1 min, core answers `429` for 1 min; 10
//! failures from one IP within 10 min raise `ui_auth_failures`. A request without credentials
//! gets `401` and isn't a failure (browsers ask first). "One IP" is an IPv4 address or an IPv6
//! /64 ([`crate::net::share_key`]): a host picks privacy addresses from its /64 at will, so
//! per-address counts would give it a fresh limit, and a fresh waiter share, per address.
//!
//! **argon2 is bounded** (README §2): [`ARGON2_SLOTS`] verifications at once, each IP with at
//! most [`MAX_CHECKS_PER_IP`] checks waiting or running (`429` beyond) and [`MAX_CHECKS`] in all
//! (`503` beyond, or after [`SLOT_WAIT`]). The block is checked again once a check gets its slot,
//! and the slot, the IP's share and the failure count stay with the verification itself, so a
//! cancelled request neither frees a slot early nor escapes the count.
//!
//! Browsers resend the password with every request, and argon2id is deliberately slow, so a
//! verified password is remembered as a keyed BLAKE3 tag bound to the stored hash: a later
//! request with the same password and hash skips argon2. The stored hash is re-read every few
//! seconds, so an offline `picket-core passwd` takes effect without a restart.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use base64::Engine as _;
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::db::Db;
use crate::error::CoreError;
use crate::instance::ADMIN;

/// Password length bounds for changes.
pub const MIN_PASSWORD: usize = 12;
pub const MAX_PASSWORD: usize = 1024;

/// Hashes a password with argon2id (the `argon2` crate's defaults: m = 19 MiB, t = 2, p = 1).
pub fn hash_password(pw: &str) -> Result<String> {
    Argon2::default()
        .hash_password(pw.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| anyhow!("argon2: {e}"))
}

/// Verifies a password against a stored argon2id hash.
pub fn verify_password(pw: &str, hash: &str) -> bool {
    Argon2::default().verify_password(pw.as_bytes(), hash).is_ok()
}

/// Checks a new password's length.
pub fn check_new_password(pw: &str) -> Result<(), String> {
    let n = pw.chars().count();
    if n < MIN_PASSWORD {
        return Err(format!("the password needs at least {MIN_PASSWORD} characters"));
    }
    if pw.len() > MAX_PASSWORD {
        return Err(format!("the password is longer than {MAX_PASSWORD} bytes"));
    }
    if pw.chars().any(char::is_control) {
        return Err("the password can't hold control characters".into());
    }
    Ok(())
}

/// Parses `Authorization: Basic …` into (user, password).
pub fn parse_basic(header: &str) -> Option<(String, String)> {
    let (scheme, rest) = header.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") || rest.len() > 4096 {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(rest.trim())
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (u, p) = text.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

/// Limiter thresholds (core.md §12).
pub const BLOCK_FAILURES: usize = 5;
pub const BLOCK_WINDOW: Duration = Duration::from_secs(60);
pub const BLOCK_FOR: Duration = Duration::from_secs(60);
pub const ALERT_FAILURES: usize = 10;
pub const ALERT_WINDOW: Duration = Duration::from_secs(600);
/// IPs tracked at once; beyond it the stalest are forgotten.
const MAX_TRACKED: usize = 10_000;

#[derive(Default)]
struct IpRecord {
    failures: VecDeque<Instant>,
    blocked_until: Option<Instant>,
    alerted_at: Option<Instant>,
}

/// What a failure led to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FailOutcome {
    /// The IP is now blocked (answer 429).
    pub blocked: bool,
    /// Raise `ui_auth_failures` for this IP.
    pub alert: bool,
}

/// Failed-login tracking per IP.
#[derive(Default)]
pub struct Limiter {
    ips: HashMap<IpAddr, IpRecord>,
}

impl Limiter {
    /// `Some(retry_after)` while `ip` is blocked.
    pub fn blocked(&mut self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let rec = self.ips.get_mut(&ip)?;
        match rec.blocked_until {
            Some(t) if t > now => Some(t - now),
            Some(_) => {
                rec.blocked_until = None;
                None
            }
            None => None,
        }
    }

    pub fn fail(&mut self, ip: IpAddr, now: Instant) -> FailOutcome {
        if self.ips.len() >= MAX_TRACKED && !self.ips.contains_key(&ip) {
            self.evict(now);
        }
        let rec = self.ips.entry(ip).or_default();
        rec.failures.push_back(now);
        while rec
            .failures
            .front()
            .is_some_and(|t| now.duration_since(*t) > ALERT_WINDOW)
        {
            rec.failures.pop_front();
        }
        while rec.failures.len() > ALERT_FAILURES * 4 {
            rec.failures.pop_front();
        }
        let recent = rec
            .failures
            .iter()
            .filter(|t| now.duration_since(**t) <= BLOCK_WINDOW)
            .count();
        let mut out = FailOutcome::default();
        if recent >= BLOCK_FAILURES {
            rec.blocked_until = Some(now + BLOCK_FOR);
            out.blocked = true;
        }
        if rec.failures.len() >= ALERT_FAILURES
            && rec
                .alerted_at
                .is_none_or(|t| now.duration_since(t) > ALERT_WINDOW)
        {
            rec.alerted_at = Some(now);
            out.alert = true;
        }
        out
    }

    fn evict(&mut self, now: Instant) {
        self.ips.retain(|_, r| {
            r.blocked_until.is_some_and(|t| t > now)
                || r.failures
                    .back()
                    .is_some_and(|t| now.duration_since(*t) <= ALERT_WINDOW)
        });
        if self.ips.len() >= MAX_TRACKED {
            // Still full: forget the stalest half.
            let mut by_age: Vec<(IpAddr, Instant)> = self
                .ips
                .iter()
                .map(|(ip, r)| (*ip, r.failures.back().copied().unwrap_or(now)))
                .collect();
            by_age.sort_by_key(|(_, t)| *t);
            for (ip, _) in by_age.into_iter().take(MAX_TRACKED / 2) {
                self.ips.remove(&ip);
            }
        }
    }
}

/// The result of checking a request's credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthResult {
    Ok,
    /// No credentials: ask for them (401, not a failure).
    Missing,
    /// Wrong credentials (401), counted.
    Failed,
    /// Too many failures (429).
    Blocked(Duration),
    /// This IP already has its share of password checks waiting or running (429).
    Throttled,
    /// Every password-check slot is taken, or the stored hash can't be read (503).
    Busy,
}

/// argon2 verifications running at once: each needs ~19 MiB and tens of ms.
pub const ARGON2_SLOTS: usize = 2;
/// Password checks (waiting for a slot or running) per IP; beyond it `429` (README §2, Bounded:
/// each client gets a capped share). A browser sends a few requests at once before its first
/// verification is remembered, so the share leaves room for that.
pub const MAX_CHECKS_PER_IP: usize = 4;
/// Password checks waiting or running in all; beyond it `503`.
pub const MAX_CHECKS: usize = 32;
/// The longest a check waits for an argon2 slot before `503`.
pub const SLOT_WAIT: Duration = Duration::from_secs(10);

/// Password checks waiting or running, in all and per IP.
#[derive(Default)]
struct Waiting {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// One admitted password check; dropping it frees its place (also when the request is
/// cancelled, or when argon2 ends after the request went away).
struct Ticket {
    inner: Arc<Inner>,
    ip: IpAddr,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let Ok(mut w) = self.inner.waiting.lock() {
            w.total = w.total.saturating_sub(1);
            if let Some(n) = w.per_ip.get_mut(&self.ip) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    w.per_ip.remove(&self.ip);
                }
            }
        }
    }
}

struct Inner {
    db: Db,
    /// Shared with the writer closure of [`AuthState::set_password`], which updates them after
    /// its commit.
    hash: Arc<Mutex<Option<(String, Instant)>>>,
    verified: Arc<Mutex<Option<blake3::Hash>>>,
    key: [u8; 32],
    limiter: Mutex<Limiter>,
    permits: Arc<Semaphore>,
    waiting: Mutex<Waiting>,
    /// Raises `ui_auth_failures` (None in tests that don't need it).
    alerts: Option<crate::alerts::Alerts>,
}

/// Shared auth state.
pub struct AuthState {
    inner: Arc<Inner>,
}

/// How long a loaded hash is trusted before re-reading `ui_account`.
const HASH_TTL: Duration = Duration::from_secs(5);

impl Inner {
    fn blocked(&self, ip: IpAddr) -> Option<Duration> {
        let ip = crate::net::share_key(ip);
        self.limiter
            .lock()
            .ok()
            .and_then(|mut l| l.blocked(ip, Instant::now()))
    }

    fn remembered(&self, tag: blake3::Hash) -> bool {
        // blake3::Hash compares in constant time.
        self.verified.lock().ok().and_then(|g| *g) == Some(tag)
    }

    /// Counts a failure and raises `ui_auth_failures` when it is due (core.md §9, §12). Runs
    /// wherever the failure is decided, so a cancelled request is still counted.
    fn fail(&self, ip: IpAddr, handle: Option<&tokio::runtime::Handle>) -> FailOutcome {
        let out = self
            .limiter
            .lock()
            .map(|mut l| l.fail(ip, Instant::now()))
            .unwrap_or_default();
        if out.alert
            && let (Some(alerts), Some(h)) = (self.alerts.clone(), handle)
        {
            let ip = crate::net::share_label(ip);
            h.spawn(async move {
                let spec = crate::alerts::RaiseSpec::new(
                    "ui_auth_failures",
                    crate::alerts::Severity::Warning,
                    format!("ui_auth_failures:{ip}"),
                    format!("Repeated failed UI logins from {ip}"),
                    serde_json::json!({"ip": ip, "failures": ALERT_FAILURES, "window": "10m"}),
                );
                if let Err(e) = alerts.raise(spec).await {
                    tracing::warn!(error = %e, "cannot raise ui_auth_failures");
                }
            });
        }
        out
    }

    /// Admits one password check for `ip`, within its share and the total.
    fn admit(self: &Arc<Self>, ip: IpAddr) -> Result<Ticket, AuthResult> {
        let mut w = self.waiting.lock().map_err(|_| AuthResult::Busy)?;
        let mine = w.per_ip.get(&ip).copied().unwrap_or(0);
        if mine >= MAX_CHECKS_PER_IP {
            return Err(AuthResult::Throttled);
        }
        if w.total >= MAX_CHECKS {
            return Err(AuthResult::Busy);
        }
        w.total += 1;
        w.per_ip.insert(ip, mine + 1);
        Ok(Ticket {
            inner: self.clone(),
            ip,
        })
    }
}

impl AuthState {
    pub fn new(db: Db, alerts: Option<crate::alerts::Alerts>) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                hash: Arc::new(Mutex::new(None)),
                verified: Arc::new(Mutex::new(None)),
                key: crate::util::random_bytes::<32>(),
                limiter: Mutex::new(Limiter::default()),
                permits: Arc::new(Semaphore::new(ARGON2_SLOTS)),
                waiting: Mutex::new(Waiting::default()),
                alerts,
            }),
        }
    }

    async fn current_hash(&self) -> Result<String, CoreError> {
        if let Ok(g) = self.inner.hash.lock()
            && let Some((h, at)) = g.as_ref()
            && at.elapsed() < HASH_TTL
        {
            return Ok(h.clone());
        }
        let h: String = self
            .inner
            .db
            .read(|c| {
                Ok::<_, CoreError>(c.query_row(
                    "SELECT password_argon2id FROM ui_account WHERE name = ?1",
                    [ADMIN],
                    |r| r.get(0),
                )?)
            })
            .await?;
        if let Ok(mut g) = self.inner.hash.lock() {
            *g = Some((h.clone(), Instant::now()));
        }
        Ok(h)
    }

    fn tag(&self, hash: &str, pw: &str) -> blake3::Hash {
        let mut h = blake3::Hasher::new_keyed(&self.inner.key);
        h.update(hash.as_bytes());
        h.update(&[0]);
        h.update(pw.as_bytes());
        h.finalize()
    }

    /// Checks `user`/`pw` from `ip` through the limiter (core.md §12): a blocked IP gets
    /// `Blocked` without a verification, before and again after waiting for an argon2 slot (a
    /// burst queued before the block starts is stopped by it); a wrong password is counted. The
    /// argon2 slot and the IP's share are held until the verification itself ends, and the
    /// failure is counted there, so cancelling the request (an HTTP/2 stream reset) neither
    /// frees a slot early nor skips the count.
    pub async fn check_credentials(&self, ip: IpAddr, user: &str, pw: &str) -> (AuthResult, FailOutcome) {
        let ip = crate::net::share_key(ip);
        if let Some(d) = self.inner.blocked(ip) {
            return (AuthResult::Blocked(d), FailOutcome::default());
        }
        let handle = tokio::runtime::Handle::try_current().ok();
        if user != ADMIN || pw.len() > MAX_PASSWORD {
            return self.failed(ip, handle.as_ref());
        }
        let Ok(hash) = self.current_hash().await else {
            return (AuthResult::Busy, FailOutcome::default());
        };
        let tag = self.tag(&hash, pw);
        if self.inner.remembered(tag) {
            return (AuthResult::Ok, FailOutcome::default());
        }
        let ticket = match self.inner.admit(ip) {
            Ok(t) => t,
            Err(r) => return (r, FailOutcome::default()),
        };
        let permit = match tokio::time::timeout(SLOT_WAIT, self.inner.permits.clone().acquire_owned()).await {
            Ok(Ok(p)) => p,
            _ => return (AuthResult::Busy, FailOutcome::default()),
        };
        // The block may have started while this check waited.
        if let Some(d) = self.inner.blocked(ip) {
            return (AuthResult::Blocked(d), FailOutcome::default());
        }
        if self.inner.remembered(tag) {
            return (AuthResult::Ok, FailOutcome::default());
        }
        let inner = self.inner.clone();
        let pw = pw.to_string();
        let joined = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _ticket = ticket;
            if verify_password(&pw, &hash) {
                if let Ok(mut g) = inner.verified.lock() {
                    *g = Some(tag);
                }
                (true, FailOutcome::default())
            } else {
                (false, inner.fail(ip, handle.as_ref()))
            }
        })
        .await;
        match joined {
            Ok((true, _)) => (AuthResult::Ok, FailOutcome::default()),
            Ok((false, out)) if out.blocked => (AuthResult::Blocked(BLOCK_FOR), out),
            Ok((false, out)) => (AuthResult::Failed, out),
            Err(_) => (AuthResult::Busy, FailOutcome::default()),
        }
    }

    fn failed(&self, ip: IpAddr, handle: Option<&tokio::runtime::Handle>) -> (AuthResult, FailOutcome) {
        let out = self.inner.fail(ip, handle);
        if out.blocked {
            (AuthResult::Blocked(BLOCK_FOR), out)
        } else {
            (AuthResult::Failed, out)
        }
    }

    /// Checks a request's `Authorization` header for `ip`.
    pub async fn check(&self, ip: IpAddr, header: Option<&str>) -> (AuthResult, FailOutcome) {
        let ip = crate::net::share_key(ip);
        if let Some(d) = self.inner.blocked(ip) {
            return (AuthResult::Blocked(d), FailOutcome::default());
        }
        let Some(header) = header else {
            return (AuthResult::Missing, FailOutcome::default());
        };
        match parse_basic(header) {
            Some((u, p)) => self.check_credentials(ip, &u, &p).await,
            None => self.failed(ip, tokio::runtime::Handle::try_current().ok().as_ref()),
        }
    }

    /// Counts a failed login at a given time (tests replay spread-out failures with it).
    #[doc(hidden)]
    pub fn record_failure_at(&self, ip: IpAddr, at: Instant) -> FailOutcome {
        self.inner
            .limiter
            .lock()
            .map(|mut l| l.fail(crate::net::share_key(ip), at))
            .unwrap_or_default()
    }

    /// Changes the password (current one required by the caller), deletes `initial-password`
    /// (core.md §12) and forgets the remembered verification. The file and the in-memory hash
    /// follow the commit on the writer itself, so a request dropped after its write was queued
    /// still completes the change.
    pub async fn set_password(&self, data_dir: &std::path::Path, new: &str) -> Result<(), CoreError> {
        check_new_password(new).map_err(CoreError::Invalid)?;
        let new = new.to_string();
        let hash = tokio::task::spawn_blocking(move || hash_password(&new))
            .await
            .map_err(|e| CoreError::Other(anyhow!("{e}")))??;
        let (hash_cache, verified) = (self.inner.hash.clone(), self.inner.verified.clone());
        let data_dir = data_dir.to_path_buf();
        self.inner
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                tx.execute(
                    "INSERT INTO ui_account(name, password_argon2id, changed_at) VALUES (?1, ?2, ?3)
                     ON CONFLICT(name) DO UPDATE SET password_argon2id = excluded.password_argon2id, changed_at = excluded.changed_at",
                    rusqlite::params![ADMIN, hash, crate::util::now_ts()],
                )?;
                tx.execute(
                    "INSERT INTO config_changes(at, source_ip, entity, entity_id, diff_json) VALUES (?1, NULL, 'account', ?2, ?3)",
                    rusqlite::params![crate::util::now_ts(), ADMIN, r#"{"op":"update","password":"<redacted>"}"#],
                )?;
                tx.commit()?;
                if let Ok(mut g) = hash_cache.lock() {
                    *g = Some((hash, Instant::now()));
                }
                if let Ok(mut g) = verified.lock() {
                    *g = None;
                }
                remove_initial_password(&data_dir);
                Ok::<_, CoreError>(())
            })
            .await
    }
}

/// Deletes `<data_dir>/initial-password` once the password has changed.
pub fn remove_initial_password(data_dir: &std::path::Path) {
    let p = data_dir.join(crate::instance::INITIAL_PASSWORD);
    match std::fs::remove_file(&p) {
        Ok(()) => {
            let _ = crate::util::fsync_dir(data_dir);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(error = %e, "cannot delete initial-password"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashing() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong", &h));
    }

    #[test]
    fn basic_header() {
        let v = base64::engine::general_purpose::STANDARD.encode("admin:pa:ss");
        assert_eq!(
            parse_basic(&format!("Basic {v}")).unwrap(),
            ("admin".into(), "pa:ss".into())
        );
        assert!(parse_basic("Bearer x").is_none());
        assert!(parse_basic("Basic !!!").is_none());
    }

    #[test]
    fn limiter_blocks_and_alerts() {
        let mut l = Limiter::default();
        let ip: IpAddr = "192.168.1.5".parse().unwrap();
        let t0 = Instant::now();
        for i in 0..4 {
            let o = l.fail(ip, t0 + Duration::from_secs(i));
            assert!(!o.blocked);
        }
        assert!(l.blocked(ip, t0 + Duration::from_secs(4)).is_none());
        let o = l.fail(ip, t0 + Duration::from_secs(5));
        assert!(o.blocked && !o.alert);
        assert!(l.blocked(ip, t0 + Duration::from_secs(30)).is_some());
        assert!(
            l.blocked(ip, t0 + Duration::from_secs(70)).is_none(),
            "blocked for 1 min"
        );
        // Spread failures: 10 within 10 min alert once, without a block.
        let ip2: IpAddr = "10.0.0.9".parse().unwrap();
        let mut alerts = 0;
        for i in 0..12u64 {
            let o = l.fail(ip2, t0 + Duration::from_secs(i * 50));
            assert!(!o.blocked);
            alerts += o.alert as u32;
        }
        assert_eq!(alerts, 1);
        // Another IP is unaffected.
        assert!(l.blocked("10.0.0.10".parse().unwrap(), t0).is_none());
    }

    async fn auth_state(pw: &str) -> (tempfile::TempDir, AuthState) {
        let d = tempfile::tempdir().unwrap();
        let opts = crate::db::DbOptions::core(d.path());
        crate::db::migrate::create_fresh(&opts, &crate::db::migrate::CORE).unwrap();
        let db = Db::open(opts).unwrap();
        let hash = hash_password(pw).unwrap();
        db.write(move |c| {
            c.execute(
                "INSERT INTO ui_account(name, password_argon2id, changed_at) VALUES ('admin', ?1, '')",
                [hash],
            )?;
            Ok::<_, CoreError>(())
        })
        .await
        .unwrap();
        (d, AuthState::new(db, None))
    }

    impl AuthState {
        fn failures(&self, ip: IpAddr) -> usize {
            let l = self.inner.limiter.lock().unwrap();
            l.ips.get(&ip).map_or(0, |r| r.failures.len())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_cancelled_check_keeps_its_slot_until_argon2_ends_and_is_counted() {
        // core.md §12, README §2 Bounded: an HTTP/2 stream reset must neither free an argon2
        // slot while the verification still runs nor skip the failure count.
        let (_d, auth) = auth_state("the right password").await;
        let auth = Arc::new(auth);
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let a = auth.clone();
        let task = tokio::spawn(async move { a.check_credentials(ip, ADMIN, "a wrong guess").await });
        while auth.inner.permits.available_permits() == ARGON2_SLOTS {
            tokio::task::yield_now().await;
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            auth.inner.permits.available_permits(),
            ARGON2_SLOTS - 1,
            "the verification still holds its slot"
        );
        for _ in 0..1000 {
            if auth.inner.permits.available_permits() == ARGON2_SLOTS {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(auth.inner.permits.available_permits(), ARGON2_SLOTS);
        assert_eq!(auth.failures(ip), 1, "the cancelled guess was counted");
        assert_eq!(auth.inner.waiting.lock().unwrap().total, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn checks_queued_before_the_block_are_stopped_by_it() {
        // core.md §12: checks waiting for an argon2 slot when the IP gets blocked are answered
        // 429 without a verification, the right password included.
        let (_d, auth) = auth_state("the right password").await;
        let auth = Arc::new(auth);
        let ip: IpAddr = "192.0.2.3".parse().unwrap();
        let held = auth
            .inner
            .permits
            .clone()
            .acquire_many_owned(ARGON2_SLOTS as u32)
            .await
            .unwrap();
        let mut queued = Vec::new();
        for pw in ["wrong 1", "wrong 2", "wrong 3", "the right password"] {
            let a = auth.clone();
            queued.push(tokio::spawn(
                async move { a.check_credentials(ip, ADMIN, pw).await.0 },
            ));
        }
        while auth.inner.waiting.lock().unwrap().total < 4 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        // Failures elsewhere (other requests from the IP) block it meanwhile.
        let now = Instant::now();
        for _ in 0..BLOCK_FAILURES {
            auth.record_failure_at(ip, now);
        }
        drop(held);
        for t in queued {
            assert!(matches!(t.await.unwrap(), AuthResult::Blocked(_)));
        }
        assert_eq!(auth.failures(ip), BLOCK_FAILURES, "nothing more was verified");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ipv6_privacy_addresses_share_one_limit() {
        // README §2 Bounded (CC10), core.md §12: failures and waiting checks from one /64 count
        // together, so rotating SLAAC privacy addresses neither escapes the block nor takes
        // more than one share of the argon2 waiters.
        let (_d, auth) = auth_state("the right password").await;
        let auth = Arc::new(auth);
        let addr = |i: u16| IpAddr::from([0x2001, 0xdb8, 7, 7, i, 1, 2, 3]);
        let now = Instant::now();
        for i in 0..BLOCK_FAILURES as u16 {
            auth.record_failure_at(addr(i), now);
        }
        assert!(matches!(
            auth.check_credentials(addr(99), ADMIN, "the right password")
                .await
                .0,
            AuthResult::Blocked(_)
        ));
        assert!(auth.inner.blocked("2001:db8:7:8::1".parse().unwrap()).is_none());
        let held = auth
            .inner
            .permits
            .clone()
            .acquire_many_owned(ARGON2_SLOTS as u32)
            .await
            .unwrap();
        let mut waiting = Vec::new();
        for i in 0..MAX_CHECKS_PER_IP as u16 {
            let a = auth.clone();
            let ip = IpAddr::from([0x2001, 0xdb8, 9, 9, i, 0, 0, 1]);
            waiting.push(tokio::spawn(async move {
                a.check_credentials(ip, ADMIN, "guess").await.0
            }));
        }
        while auth.inner.waiting.lock().unwrap().total < MAX_CHECKS_PER_IP {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let r = auth
            .check_credentials("2001:db8:9:9:ffff::1".parse().unwrap(), ADMIN, "guess")
            .await
            .0;
        assert_eq!(r, AuthResult::Throttled);
        drop(held);
        for t in waiting {
            t.await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn password_checks_are_capped_per_ip_and_in_total() {
        let (_d, auth) = auth_state("the right password").await;
        let auth = Arc::new(auth);
        // Both argon2 slots busy: every check waits.
        let held = auth
            .inner
            .permits
            .clone()
            .acquire_many_owned(ARGON2_SLOTS as u32)
            .await
            .unwrap();
        let spawn = |ip: IpAddr| {
            let a = auth.clone();
            tokio::spawn(async move { a.check_credentials(ip, ADMIN, "a wrong guess").await.0 })
        };
        let wait_total = |n: usize| {
            let a = auth.clone();
            async move {
                for _ in 0..1000 {
                    if a.inner.waiting.lock().unwrap().total == n {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                panic!("never {n} waiting");
            }
        };
        let one: IpAddr = "192.0.2.1".parse().unwrap();
        let mut waiting = Vec::new();
        for _ in 0..MAX_CHECKS_PER_IP {
            waiting.push(spawn(one));
        }
        wait_total(MAX_CHECKS_PER_IP).await;
        // One host has its share: 429 at once, without waiting or a count.
        assert_eq!(spawn(one).await.unwrap(), AuthResult::Throttled);
        assert_eq!(auth.failures(one), 0);
        // Other hosts fill the rest; then 503.
        for i in 0..(MAX_CHECKS - MAX_CHECKS_PER_IP) {
            waiting.push(spawn(IpAddr::from([10, 0, (i / 200) as u8, (i % 200) as u8])));
        }
        wait_total(MAX_CHECKS).await;
        assert_eq!(
            spawn("192.0.2.99".parse().unwrap()).await.unwrap(),
            AuthResult::Busy
        );
        drop(held);
        for t in waiting {
            let r = t.await.unwrap();
            assert!(matches!(r, AuthResult::Failed | AuthResult::Blocked(_)), "{r:?}");
        }
        assert_eq!(auth.inner.waiting.lock().unwrap().total, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_password_change_dropped_after_its_write_was_queued_still_completes() {
        // core.md §12: initial-password goes when the password is first changed; the running
        // copy of the hash follows the commit even when the request went away.
        let (d, auth) = auth_state("the first password").await;
        let auth = Arc::new(auth);
        let file = d.path().join(crate::instance::INITIAL_PASSWORD);
        std::fs::write(&file, "the first password\n").unwrap();
        // Hold the writer so the change waits in its queue.
        let (release, hold) = std::sync::mpsc::channel::<()>();
        let (started_tx, started) = std::sync::mpsc::channel::<()>();
        let db = auth.inner.db.clone();
        let blocker = tokio::spawn(async move {
            db.write(move |_| {
                let _ = started_tx.send(());
                let _ = hold.recv();
                Ok::<_, CoreError>(())
            })
            .await
        });
        while started.try_recv().is_err() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let (a, dir) = (auth.clone(), d.path().to_path_buf());
        let task = tokio::spawn(async move { a.set_password(&dir, "a brand new password").await });
        for _ in 0..2000 {
            if auth.inner.db.pending_writes() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(auth.inner.db.pending_writes(), 1, "the change is queued");
        task.abort();
        let _ = task.await;
        release.send(()).unwrap();
        blocker.await.unwrap().unwrap();
        assert!(auth.inner.db.ping(Duration::from_secs(5)).await);
        assert!(!file.exists(), "initial-password deleted");
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        assert_eq!(
            auth.check_credentials(ip, ADMIN, "a brand new password").await.0,
            AuthResult::Ok
        );
        assert_eq!(
            auth.check_credentials(ip, ADMIN, "the first password").await.0,
            AuthResult::Failed
        );
    }

    #[test]
    fn password_rules() {
        assert!(check_new_password("short").is_err());
        assert!(check_new_password("long enough password").is_ok());
        assert!(check_new_password("with\ncontrol chars").is_err());
    }
}
