//! Helpers for the compiler's tests: manual feeds and bundles through the UI API, builds, and
//! loading a published head from core's blob store with picket-bundle's reader.

use std::path::PathBuf;
use std::time::Duration;

use picket_bundle::page::MemPages;
use picket_bundle::{Bundle, Head};
use picket_core::compiler::source::View;
use picket_core::compiler::spec::{self, Spec};
use picket_rules::matcher::{BundleMatcher, Outcome};
use picket_rules::{QueryCtx, Rule};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use super::{Core, client};

pub fn ui(c: &Core, method: Method, path: &str) -> reqwest::RequestBuilder {
    client()
        .request(method, format!("{}/api/ui/v1{path}", c.base("http")))
        .basic_auth("admin", Some(&c.init.password))
        .header("X-Picket-UI", "1")
}

pub async fn get(c: &Core, path: &str) -> (StatusCode, Value) {
    let r = ui(c, Method::GET, path).send().await.unwrap();
    let st = r.status();
    (st, r.json().await.unwrap_or(Value::Null))
}

/// Creates (or replaces) an entity through the UI API.
pub async fn put_entity(c: &Core, kind: &str, id: &str, body: Value) {
    let r = ui(c, Method::POST, &format!("/{kind}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    if r.status() == StatusCode::CONFLICT {
        let r = ui(c, Method::PUT, &format!("/{kind}/{id}"))
            .json(&body)
            .send()
            .await
            .unwrap();
        let st = r.status();
        assert!(st.is_success(), "{kind}/{id}: {st} {}", r.text().await.unwrap());
        return;
    }
    let st = r.status();
    assert!(st.is_success(), "{kind}/{id}: {st} {}", r.text().await.unwrap());
}

/// A manual feed in adblock format.
pub async fn manual_feed(c: &Core, id: &str, extra: Value) {
    let mut body = json!({"id": id, "name": id, "format": "adblock"});
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        b.extend(e.clone());
    }
    put_entity(c, "feeds", id, body).await;
}

/// The number of runs a feed has.
pub async fn runs(c: &Core, feed: &str) -> i64 {
    let f = feed.to_string();
    c.state
        .db
        .read(move |db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT count(*) FROM feed_runs WHERE feed_id = ?1",
                [f],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .await
        .unwrap()
}

/// Saves a manual feed's file and waits for its run to be stored.
pub async fn save(c: &Core, feed: &str, content: &str) {
    let (_, file) = get(c, &format!("/feeds/{feed}/file")).await;
    let base = file["version"].as_str().map(str::to_string);
    let before = runs(c, feed).await;
    let r = ui(c, Method::PUT, &format!("/feeds/{feed}/file"))
        .json(&json!({"content": content, "base_version": base}))
        .send()
        .await
        .unwrap();
    let st = r.status();
    let v: Value = r.json().await.unwrap();
    assert_eq!(st, StatusCode::OK, "{v}");
    if v["changed"] == false {
        return;
    }
    wait("the save's run", || async {
        runs(c, feed).await > before && !c.state.feeds.is_busy(feed)
    })
    .await;
}

/// Waits (generously: CI is slow, and tests may run as root on a shared machine) until `f` holds.
pub async fn wait<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    // A deadline, not a number of polls: a slow check (a large bundle's tables) must not shorten
    // it, and a 75,000-key build plus its re-rank can take minutes on a loaded CI machine.
    let end = tokio::time::Instant::now() + Duration::from_secs(600);
    while tokio::time::Instant::now() < end {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if f().await {
        return;
    }
    panic!("timed out waiting for {what}");
}

/// The bundle's build row: (status, head, feed runs).
pub async fn build_row(c: &Core, bundle: &str) -> Option<(String, Option<String>, spec::Runs)> {
    let b = bundle.to_string();
    c.state
        .db
        .read(move |db| Ok::<_, anyhow::Error>(picket_core::compiler::store::build_row(db, &b)?))
        .await
        .unwrap()
        .map(|r| (r.status, r.head_id, r.feed_runs))
}

/// Requests a build of `bundle` and waits until it reflects its feeds' newest runs. Returns its
/// head.
pub async fn build(c: &Core, bundle: &str) -> Option<String> {
    c.state.compiler.request(
        &c.state,
        bundle,
        picket_core::compiler::Request {
            reasons: ["test".to_string()].into(),
            ..Default::default()
        },
        picket_core::scheduler::Priority::P0,
    );
    settle(c, bundle).await
}

/// Waits until `bundle` is built at its feeds' newest runs and no build of it waits.
pub async fn settle(c: &Core, bundle: &str) -> Option<String> {
    let model = c.state.config.model().await.unwrap();
    let def = model.bundles.get(bundle).unwrap().clone();
    let spec = Spec::of(&def, &model);
    wait(&format!("bundle {bundle}'s build"), || {
        let spec = spec.clone();
        async move {
            if c.state.compiler.busy(bundle) {
                return false;
            }
            let snap = c
                .state
                .db
                .read({
                    let spec = spec.clone();
                    move |db| Ok::<_, anyhow::Error>(spec::snapshot(db, &spec)?)
                })
                .await
                .unwrap();
            // At its definition's hash too: a proposed split waits for its tiering dry run
            // (bundles.md §2 Tiering), then builds.
            let b = bundle.to_string();
            let row = c
                .state
                .db
                .read(move |db| Ok::<_, anyhow::Error>(picket_core::compiler::store::build_row(db, &b)?))
                .await
                .unwrap();
            match row {
                Some(r) => r.status == "ok" && r.feed_runs == snap && r.definition_hash == spec.def_hash,
                None => false,
            }
        }
    })
    .await;
    build_row(c, bundle).await.and_then(|r| r.1)
}

/// Blobs from core's blob store.
pub struct DirBlobs(pub PathBuf);

impl picket_bundle::compile::BlobSource for DirBlobs {
    fn blob(&self, id: &str) -> Option<Vec<u8>> {
        std::fs::read(picket_core::blobs::path(&self.0, id).ok()?).ok()
    }
}

/// Loads a published head with picket-bundle's reader, cold page files from the blob store.
pub fn load(c: &Core, head_id: &str) -> (Bundle, MemPages, Head) {
    let blobs = DirBlobs(c.dir.path().to_path_buf());
    use picket_bundle::compile::BlobSource;
    let bytes = blobs.blob(head_id).expect("head blob");
    let head = Head::from_bytes(&bytes).unwrap();
    let mut pages = MemPages::default();
    for s in &head.cold_shards {
        let m = picket_bundle::head::Manifest::from_bytes(&blobs.blob(&s.base).unwrap()).unwrap();
        let id = m.file(picket_bundle::head::COLD_PAGES).unwrap().blake3.clone();
        pages.files.insert(id.clone(), blobs.blob(&id).unwrap());
    }
    let b = picket_bundle::compile::load_bundle(
        &bytes,
        &blobs,
        Some(&pages),
        picket_bundle::patterns::DEFAULT_BUDGET,
    )
    .expect("load the published head");
    (b, pages, head)
}

/// picket-rules' reference matcher over the bundle's rules as its feeds stand now, in bundle
/// order.
pub async fn reference(c: &Core, bundle: &str) -> BundleMatcher {
    let model = c.state.config.model().await.unwrap();
    let def = model.bundles.get(bundle).unwrap().clone();
    let spec = Spec::of(&def, &model);
    let rules: Vec<Rule> = c
        .state
        .db
        .read(move |db| {
            let runs = spec::snapshot(db, &spec)?;
            let view = View::new(&spec, &runs);
            let mut out = Vec::new();
            let mut bad = 0u64;
            view.for_each_in_order(db, &mut bad, |r| out.push(r.rule.clone()))?;
            Ok::<_, anyhow::Error>(out)
        })
        .await
        .unwrap();
    BundleMatcher::new(Spec::of(&def, &model).rules_action(), rules)
        .with_public_suffix_list(picket_core::psl::rules_list())
}

/// A query.
#[derive(Clone, Debug)]
pub struct Q {
    pub name: Option<String>,
    pub ip: Option<std::net::IpAddr>,
    pub qtype: u16,
    pub client_ip: Option<std::net::IpAddr>,
    pub client: Option<String>,
    pub tags: Vec<String>,
}

impl Q {
    pub fn name(n: &str) -> Q {
        Q {
            name: Some(n.to_string()),
            ip: None,
            qtype: 1,
            client_ip: None,
            client: None,
            tags: vec![],
        }
    }
    pub fn ip(ip: &str) -> Q {
        Q {
            ip: Some(ip.parse().unwrap()),
            ..Q::name("")
        }
    }
}

fn with_ctx<R>(q: &Q, f: impl FnOnce(&QueryCtx<'_>) -> R) -> R {
    let names: Vec<&str> = q.client.iter().map(String::as_str).collect();
    let tags: Vec<&str> = q.tags.iter().map(String::as_str).collect();
    f(&QueryCtx {
        qtype: q.qtype,
        client_ip: q.client_ip,
        client_names: &names,
        client_tags: &tags,
    })
}

fn labels(n: &str) -> Vec<&[u8]> {
    if n.is_empty() {
        return vec![];
    }
    n.split('.').map(str::as_bytes).collect()
}

/// The published bundle's decision (cold stage included), as text.
pub fn decide(b: &Bundle, pages: &MemPages, q: &Q) -> String {
    let d = with_ctx(q, |ctx| match (&q.name, q.ip) {
        (_, Some(ip)) => {
            let d = b.lookup_ip(ip, ctx);
            if d.cold == picket_bundle::ColdCheck::Needed {
                let c = b.lookup_ip_cold(ip, pages);
                d.with_cold(c)
            } else {
                d
            }
        }
        (Some(n), None) => b.lookup_labels_full(&labels(n), ctx, pages),
        _ => unreachable!(),
    });
    outcome(&d.outcome)
}

/// The reference matcher's decision, as text.
pub fn decide_ref(m: &BundleMatcher, q: &Q) -> String {
    let o = with_ctx(q, |ctx| match (&q.name, q.ip) {
        (_, Some(ip)) => m.match_ip(ip, ctx).outcome,
        (Some(n), None) => m.match_name(&labels(n), ctx).outcome,
        _ => unreachable!(),
    });
    outcome(&o)
}

/// The decision in the parity tables' syntax (records sorted: their order isn't a decision).
pub fn outcome(o: &Outcome) -> String {
    use picket_rules::ip::netip_string;
    use picket_rules::rewrite::RewriteAnswer;
    match o {
        Outcome::None => "none".into(),
        Outcome::Allow => "allowed".into(),
        Outcome::InScope => "in-scope".into(),
        Outcome::Exception => "allow".into(),
        Outcome::Block => "block".into(),
        Outcome::HostMapping(ips) => {
            let mut v: Vec<String> = ips.iter().map(|ip| netip_string(*ip)).collect();
            v.sort();
            format!("hosts {}", v.join(","))
        }
        Outcome::Rewrite(RewriteAnswer::Cname(c)) => format!("rewrite cname {c}"),
        Outcome::Rewrite(RewriteAnswer::Rcode(r)) => format!("rewrite rcode {r}"),
        Outcome::Rewrite(RewriteAnswer::Records(recs)) => {
            let mut v: Vec<String> = recs
                .iter()
                .map(|(t, val)| format!("{t}={}", val.to_text()))
                .collect();
            v.sort();
            v.dedup();
            format!("rewrite records {}", v.join("|")).trim().to_string()
        }
    }
}
