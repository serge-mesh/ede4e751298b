//! The bundle compiler end to end (build-and-test.md §5 rows "AdGuard parity", "Bundles", "Hot and
//! cold parts", "Compile alerts", "Warn bundles"; bundles.md §1–§7): manual feeds through the real
//! ingest, builds in the heavy lane, versions in core's blob store loaded with picket-bundle's
//! reader, and decisions compared with picket-rules' reference matcher.

use crate::common;

use std::collections::BTreeMap;

use common::bundles::*;
use common::{Core, start_core};
use reqwest::Method;
use serde_json::{Value, json};

async fn core() -> Core {
    start_core(Some(json!({"web": {"tls": "off"}}))).await
}

/// One group of the parity corpus (fixtures/rules/parity-corpus.txt).
struct Group {
    title: String,
    rules: Vec<String>,
    queries: Vec<Q>,
}

fn tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn query(target: &str, is_ip: bool, opts: &[String]) -> Q {
    let mut q = if is_ip { Q::ip(target) } else { Q::name(target) };
    for o in opts {
        let Some((k, v)) = o.split_once('=') else { continue };
        match k {
            "qtype" => q.qtype = picket_rules::rrtype::parse_rr_type(v).unwrap(),
            "ip" => q.client_ip = Some(v.parse().unwrap()),
            "client" => q.client = Some(v.to_string()),
            "tags" => q.tags = v.split(',').map(String::from).collect(),
            _ => {}
        }
    }
    q
}

fn corpus() -> Vec<Group> {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rules/parity-corpus.txt"
    ))
    .unwrap();
    let mut out: Vec<Group> = Vec::new();
    for raw in text.lines() {
        if raw.trim().is_empty() || raw.starts_with('#') {
            continue;
        }
        if let Some(t) = raw.strip_prefix("= ") {
            out.push(Group {
                title: t.to_string(),
                rules: vec![],
                queries: vec![],
            });
            continue;
        }
        if let Some(m) = raw.strip_prefix("m ") {
            let parts: Vec<&str> = m.split(" ~~").collect();
            let mut g = Group {
                title: format!("matrix {}", parts[0].trim()),
                rules: vec![parts[0].trim().to_string()],
                queries: vec![],
            };
            for names in &parts[1..] {
                for t in names.split_whitespace() {
                    g.queries
                        .push(query(t, t.parse::<std::net::IpAddr>().is_ok(), &[]));
                }
            }
            out.push(g);
            continue;
        }
        let g = out.last_mut().unwrap();
        if let Some(r) = raw.strip_prefix("r ") {
            g.rules.push(r.to_string());
            continue;
        }
        let (is_ip, rest) = match (raw.strip_prefix("e "), raw.strip_prefix("i ")) {
            (Some(r), _) => (false, r),
            (_, Some(r)) => (true, r),
            _ => panic!("unknown corpus line {raw:?}"),
        };
        let t = tokens(rest);
        g.queries.push(query(&t[0], is_ip, &t[2..]));
    }
    out
}

/// Each name with its parent, a child and the other address type.
fn widen(qs: &[Q]) -> Vec<Q> {
    let mut out = qs.to_vec();
    for q in qs {
        if let Some(n) = &q.name {
            if let Some((_, p)) = n.split_once('.') {
                let mut x = q.clone();
                x.name = Some(p.to_string());
                out.push(x);
            }
            let mut x = q.clone();
            x.name = Some(format!("zz.{n}"));
            out.push(x);
            let mut x = q.clone();
            x.qtype = if q.qtype == 28 { 1 } else { 28 };
            out.push(x);
        }
    }
    out
}

/// AdGuard parity end to end (build-and-test.md §5): every group of the parity corpus goes in a
/// manual feed, through ingest and a build, into a published version; that version, loaded with
/// picket-bundle's reader, decides every query (and its neighbours) as picket-rules' reference
/// matcher does over the same stored rules. Each group builds twice: all hot in one shard, and
/// as a cold-tier bundle in shards of two keys (cold stage, sharding, pruning across parts).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parity_corpus_end_to_end() {
    let c = core().await;
    let groups = corpus();
    assert!(groups.len() > 50, "the corpus is there");
    for (i, g) in groups.iter().enumerate() {
        let f = format!("p{i}");
        manual_feed(&c, &f, json!({})).await;
        put_entity(
            &c,
            "bundles",
            &f,
            json!({"id": f, "name": f, "feeds": [{"feed": f}], "max_shard_keys": 0}),
        )
        .await;
        let cold = format!("pc{i}");
        put_entity(
            &c,
            "bundles",
            &cold,
            json!({"id": cold, "name": cold, "feeds": [{"feed": f, "tier": "cold"}], "max_shard_keys": 2}),
        )
        .await;
        save(&c, &f, &format!("{}\n", g.rules.join("\n"))).await;
    }
    let mut failures = Vec::new();
    let (mut checked, mut cold_parts, mut decided) = (0usize, 0usize, 0usize);
    for (i, g) in groups.iter().enumerate() {
        for b in [format!("p{i}"), format!("pc{i}")] {
            let head = build(&c, &b).await.expect("a published head");
            let (bundle, pages, h) = load(&c, &head);
            cold_parts += usize::from(!h.cold_shards.is_empty());
            let reference = reference(&c, &b).await;
            for q in widen(&g.queries) {
                let got = decide(&bundle, &pages, &q);
                let want = decide_ref(&reference, &q);
                checked += 1;
                decided += usize::from(got != "none");
                if got != want {
                    failures.push(format!(
                        "[{}] {b} rules={:?} {q:?}: published={got} reference={want}",
                        g.title, g.rules
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        checked > 500 && decided > 100,
        "{checked} checked, {decided} decided"
    );
    assert!(cold_parts > 10, "cold parts exercised: {cold_parts}");
}

fn probes() -> Vec<Q> {
    let mut v = Vec::new();
    for n in [
        "d.example",
        "sub.d.example",
        "a.sub.d.example",
        "e.example",
        "sub.e.example",
        "keep.example",
        "gone.example",
        "moved.example",
        "back.example",
        "cold.example",
        "x.cold.example",
        "rw.example",
        "tracker.example",
        "ads1.example",
        "new.example",
        "n1.example",
        "n2.example",
        "n3.example",
        "n4.example",
        "n5.example",
        "n6.example",
        "n7.example",
        "x.n7.example",
        "1.2.3.4",
    ] {
        let mut q = Q::name(n);
        v.push(q.clone());
        q.qtype = 28;
        v.push(q);
    }
    for ip in [
        "1.2.3.4",
        "1.2.3.5",
        "10.0.0.1",
        "10.1.0.1",
        "10.2.0.9",
        "45.12.3.4",
        "2001:db8::1",
        "2001:db8::5",
    ] {
        v.push(Q::ip(ip));
    }
    v
}

/// Decisions of a published head over the probe set.
fn decisions(c: &Core, head: &str) -> BTreeMap<String, String> {
    let (b, pages, _) = load(c, head);
    probes()
        .iter()
        .map(|q| (format!("{q:?}"), decide(&b, &pages, q)))
        .collect()
}

/// Incremental builds equal builds from scratch (build-and-test.md §5 "Bundles", "Hot and cold
/// parts"; bundles.md §2): across additions, removals, tier moves, IP runs that split and merge,
/// shards that split, a pruned parent/child pair, and a chain of three versions, an incremental
/// head (deltas on its bases) decides every probe as a fresh build over the same entries.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn incremental_builds_equal_builds_from_scratch() {
    let c = core().await;
    manual_feed(&c, "hotf", json!({})).await;
    manual_feed(&c, "coldf", json!({})).await;
    manual_feed(&c, "ipf", json!({"format": "plain"})).await;
    let def = |id: &str| {
        json!({"id": id, "name": id, "max_shard_keys": 3,
               "feeds": [{"feed": "hotf"}, {"feed": "coldf", "tier": "cold"}, {"feed": "ipf"}]})
    };
    put_entity(&c, "bundles", "inc", def("inc")).await;
    let v1_hot = "||d.example^\n||sub.d.example^\n||keep.example^\n||gone.example^\n||rw.example^$dnsrewrite=1.2.3.4\n\
                  ||tracker.example^$dnstype=AAAA\n||1.2.3.4^\n@@||10.0.0.1^\n||ads*.example^\n\
                  ||e.example^\n@@|e.example^\n||sub.e.example^\n@@|sub.e.example^\n";
    let v1_cold = "||cold.example^\n||back.example^\n||moved.example^\n";
    save(&c, "hotf", v1_hot).await;
    save(&c, "coldf", v1_cold).await;
    save(&c, "ipf", "10.0.0.0/8\n").await;
    let h1 = build(&c, "inc").await.unwrap();
    // v2: removes ||d^ (sub.d still blocks: its pruned key comes back), drops `gone`, moves
    // `back` hot (now in the hot feed too) and `moved` cold (left only in the cold feed), changes
    // a rewrite and the IP rules (a run splits), adds names that split shards.
    let v2_hot = "||sub.d.example^\n||keep.example^\n||back.example^\n||rw.example^$dnsrewrite=1.2.3.5\n\
                  ||tracker.example^$dnstype=AAAA\n@@||1.2.3.4^\n@@||10.1.0.1^\n||45.12.3.4^\n||2001:db8::1^\n\
                  ||ads*.example^\n/^x\\./\n||new.example^\n||n1.example^\n||n2.example^\n||n3.example^\n||n4.example^\n\
                  ||e.example^\n@@|e.example^\n||sub.e.example^\n@@|sub.e.example^\n";
    save(&c, "hotf", v2_hot).await;
    save(&c, "ipf", "10.0.0.0/8\n2001:db8::/32\n").await;
    let h2 = build(&c, "inc").await.unwrap();
    assert_ne!(h1, h2);
    let (_, _, head2) = load(&c, &h2);
    assert!(
        head2
            .shards
            .iter()
            .chain(head2.cold_shards.iter())
            .any(|s| !s.deltas.is_empty())
            || head2.ip_shards.iter().any(|s| !s.deltas.is_empty()),
        "an incremental head carries deltas"
    );
    // A fresh bundle over the same entries.
    put_entity(&c, "bundles", "inc-fresh", def("inc-fresh")).await;
    let f2 = build(&c, "inc-fresh").await.unwrap();
    let (a, b) = (decisions(&c, &h2), decisions(&c, &f2));
    assert_eq!(a, b, "v2: incremental == fresh");
    // The bundles.md rows.
    assert_eq!(
        a[&format!("{:?}", Q::name("sub.d.example"))],
        "block",
        "a run removing ||d^ still blocks sub.d"
    );
    assert_eq!(a[&format!("{:?}", Q::name("d.example"))], "none");
    assert_eq!(
        a[&format!("{:?}", Q::name("sub.e.example"))],
        "allow",
        "||d^ + @@|d^ + ||sub.d^ + @@|sub.d^ allows sub.d"
    );
    assert_eq!(a[&format!("{:?}", Q::ip("10.1.0.1"))], "allow");
    // Moves: `back` is hot now, `moved` cold.
    let (bb, pages, _) = load(&c, &h2);
    let detail = |n: &str| {
        let labels: Vec<&[u8]> = n.split('.').map(str::as_bytes).collect();
        bb.lookup_labels_full(
            &labels,
            &picket_rules::QueryCtx {
                qtype: 1,
                ..Default::default()
            },
            &pages,
        )
    };
    assert!(!detail("back.example").reason.unwrap().cold, "moved hot");
    assert!(detail("moved.example").reason.unwrap().cold, "stays cold");
    // v3 on top: a chain of two deltas, removals across shards, the cold feed emptied.
    save(
        &c,
        "hotf",
        "||keep.example^\n||n5.example^\n||n6.example^\n||n7.example^\n||1.2.3.5^\n",
    )
    .await;
    save(&c, "coldf", "||cold.example^\n").await;
    save(&c, "ipf", "10.2.0.0/16\n").await;
    let h3 = build(&c, "inc").await.unwrap();
    let f3 = build(&c, "inc-fresh").await.unwrap();
    assert_eq!(decisions(&c, &h3), decisions(&c, &f3), "v3: incremental == fresh");
    // Every build that changed something is a version (the configuration watch may add one for
    // the new bundle before its feeds had runs).
    let (_, v) = get(&c, "/bundles/inc/versions").await;
    assert!(v["items"].as_array().unwrap().len() >= 3, "{v}");
    assert_eq!(v["items"][0]["head"], h3);
    assert_eq!(v["items"][0]["current"], true);
    // The materialised state equals the fresh bundle's (keys, parts and flags).
    assert_eq!(materialised(&c, "inc").await, materialised(&c, "inc-fresh").await);
}

/// A bundle's `bundle_keys` as (part, key, flags).
async fn materialised(c: &Core, b: &'static str) -> Vec<(String, String, i64)> {
    c.state
        .db
        .read(move |db| {
            let mut st =
                db.prepare("SELECT part, key, value FROM bundle_keys WHERE bundle_id = ?1 ORDER BY key")?;
            let v = st
                .query_map([b], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)? & 0xffff,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await
        .unwrap()
}

/// Determinism (bundles.md §2): the same entries give byte-identical outputs. A bundle built,
/// retired and built again from scratch with the same stamp names the same head (whose id is the
/// BLAKE3 of its bytes, naming every base, delta and segment by theirs).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_inputs_give_byte_identical_outputs() {
    let c = core().await;
    c.state
        .compiler
        .set_fixed_time(Some("2026-11-21T00:00:00.000000Z".into()));
    manual_feed(&c, "df", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "det",
        json!({"id": "det", "name": "det", "feeds": [{"feed": "df"}], "max_shard_keys": 2}),
    )
    .await;
    let mut text = String::new();
    for i in 0..40 {
        text.push_str(&format!("||n{i}.example^\n"));
    }
    text.push_str("||rw.example^$dnsrewrite=1.2.3.4\n/^ads[0-9]+\\./\n10.0.0.0/8\n");
    save(&c, "df", &text).await;
    build(&c, "det").await.unwrap();
    // Two builds from scratch over the same entries.
    picket_core::compiler::retire(&c.state, "det").await.unwrap();
    let h1 = build(&c, "det").await.unwrap();
    picket_core::compiler::retire(&c.state, "det").await.unwrap();
    let h2 = build(&c, "det").await.unwrap();
    assert_eq!(h1, h2, "byte-identical heads");
    let (_, _, head) = load(&c, &h1);
    assert!(head.shards.len() > 1, "split into shards of two keys");
}

/// Restarts (README §2 Restarts; build-and-test.md §5): a build stopped part-way (its job dropped
/// between steps, as a stop does) leaves only scratch rows; start-time recovery empties them and
/// builds the bundle again, to the same result as an uninterrupted build.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_build_stopped_part_way_is_rebuilt_at_start() {
    use picket_core::scheduler::HeavyJob;
    let c = core().await;
    c.state
        .compiler
        .set_fixed_time(Some("2026-11-21T00:00:00.000000Z".into()));
    manual_feed(&c, "rf", json!({})).await;
    let mut text = String::new();
    for i in 0..25_000 {
        text.push_str(&format!("||r{i}.example^\n"));
    }
    save(&c, "rf", &text).await;
    put_entity(
        &c,
        "bundles",
        "rb",
        json!({"id": "rb", "name": "rb", "feeds": [{"feed": "rf"}]}),
    )
    .await;
    // The configuration watch may queue a build of the new bundle: let it finish, then undo it
    // so the bundle is new again.
    settle(&c, "rb").await;
    let reference_head = build_row(&c, "rb").await.unwrap().1.unwrap();
    picket_core::compiler::retire(&c.state, "rb").await.unwrap();
    // Drive a build by hand into its key pass and stop it there.
    let mut job = picket_core::compiler::build::BuildJob::new(c.state.clone(), "rb");
    for _ in 0..8 {
        job.step().await.unwrap();
    }
    drop(job);
    let scratch: i64 = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT (SELECT count(*) FROM bundle_build_keys WHERE bundle_id = 'rb') +
                        (SELECT count(*) FROM bundle_keys WHERE bundle_id = 'rb')",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(scratch > 0, "the stopped build left work rows");
    assert!(
        build_row(&c, "rb").await.is_none_or(|r| r.1.is_none()),
        "nothing was published"
    );
    // Start-time recovery.
    let n = picket_core::compiler::recover(&c.state).await.unwrap();
    assert!(n >= 1);
    let head = settle(&c, "rb").await.unwrap();
    assert_eq!(
        head, reference_head,
        "the same version as the uninterrupted build"
    );
    let left: i64 = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row("SELECT count(*) FROM bundle_build_keys", [], |r| r.get(0))?)
        })
        .await
        .unwrap();
    assert_eq!(left, 0, "no scratch rows left");
}

async fn alert(c: &Core, key: &str) -> Option<(String, Value)> {
    c.state.alerts.get_by_key(key).await.unwrap().map(|a| {
        (
            serde_json::to_value(a.state)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string(),
            a.details,
        )
    })
}

async fn open_alerts(c: &Core, kind: &str, bundle: &str) -> Vec<picket_core::alerts::Alert> {
    c.state
        .alerts
        .list(
            picket_core::alerts::AlertFilter {
                kind: Some(kind.into()),
                bundle: Some(bundle.into()),
                state: Some(picket_core::alerts::AlertState::Open),
                ..Default::default()
            },
            None,
            100,
        )
        .await
        .unwrap()
}

/// Compile alerts (build-and-test.md §5 "Compile alerts"; bundles.md §2): `broad_block` once per
/// rule (resolved when it leaves), the public-suffix guardrail, a cross-feed cancellation (one
/// warning per canceller), and a recorded FireHOL level 1 file raising none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guardrails_raise_once_and_resolve() {
    let c = core().await;
    manual_feed(&c, "ga", json!({})).await;
    manual_feed(&c, "gb", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "gb1",
        json!({"id": "gb1", "name": "gb1", "feeds": [{"feed": "ga"}, {"feed": "gb"}]}),
    )
    .await;
    save(
        &c,
        "ga",
        "||com^\n||duckdns.org^\n||ads.example^\n||tracker.example^\n",
    )
    .await;
    save(&c, "gb", "@@||ads.example^\n").await;
    build(&c, "gb1").await.unwrap();
    let broad = open_alerts(&c, "broad_block", "gb1").await;
    assert_eq!(broad.len(), 1, "{broad:?}");
    assert_eq!(broad[0].details["rule"], "||com^");
    assert_eq!(broad[0].details["feed"], "ga");
    let warnings = open_alerts(&c, "bundle_warning", "gb1").await;
    let kinds: Vec<&str> = warnings
        .iter()
        .filter_map(|a| a.details["warning"].as_str())
        .collect();
    assert!(kinds.contains(&"public_suffix"), "{warnings:?}");
    let cancel: Vec<_> = warnings
        .iter()
        .filter(|a| a.details["warning"] == "cross_feed_cancellation")
        .collect();
    assert_eq!(cancel.len(), 1, "one warning per canceller");
    assert_eq!(cancel[0].details["proven"], true);
    assert_eq!(cancel[0].details["rule"], "@@||ads.example^");
    // A rebuild with the rules still there raises nothing new (count stays 1).
    save(
        &c,
        "ga",
        "||com^\n||duckdns.org^\n||ads.example^\n||tracker.example^\n||more.example^\n",
    )
    .await;
    build(&c, "gb1").await.unwrap();
    assert_eq!(open_alerts(&c, "broad_block", "gb1").await[0].count, 1);
    // The rule leaves: resolved.
    save(&c, "ga", "||duckdns.org^\n||ads.example^\n").await;
    save(&c, "gb", "").await;
    build(&c, "gb1").await.unwrap();
    assert!(open_alerts(&c, "broad_block", "gb1").await.is_empty());
    assert!(
        open_alerts(&c, "bundle_warning", "gb1")
            .await
            .iter()
            .all(|a| a.details["warning"] != "cross_feed_cancellation"),
        "the canceller left"
    );
    // FireHOL level 1 raises none (private, reserved and multicast space isn't broad).
    manual_feed(&c, "fh", json!({"format": "plain"})).await;
    put_entity(
        &c,
        "bundles",
        "fhb",
        json!({"id": "fhb", "name": "fhb", "feeds": [{"feed": "fh"}]}),
    )
    .await;
    let firehol = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rules/firehol-level1-sample.netset"
    ))
    .unwrap();
    save(&c, "fh", &firehol).await;
    build(&c, "fhb").await.unwrap();
    assert!(open_alerts(&c, "broad_block", "fhb").await.is_empty());
}

/// The raw rules of a bundle's open `broad_block` alerts, sorted.
async fn broad_rules(c: &Core, bundle: &str) -> Vec<String> {
    let mut r: Vec<String> = open_alerts(c, "broad_block", bundle)
        .await
        .iter()
        .filter_map(|a| a.details["rule"].as_str().map(str::to_string))
        .collect();
    r.sort();
    r
}

/// A restricted rule with no pattern text (`$dnstype=A`, stored with an empty key) matches every
/// name for what it restricts, so it raises `broad_block` (bundles.md §2) in a fresh build, in a
/// full one (a feed added to a built bundle) and in an incremental one, like `*$client=…`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn empty_pattern_rules_raise_broad_alerts_in_every_build() {
    let c = core().await;
    // Fresh.
    manual_feed(&c, "ea", json!({})).await;
    save(&c, "ea", "||ads.example^\n$dnstype=A\n*$client=192.168.1.9\n").await;
    put_entity(
        &c,
        "bundles",
        "eb",
        json!({"id": "eb", "name": "eb", "feeds": [{"feed": "ea"}]}),
    )
    .await;
    build(&c, "eb").await.unwrap();
    assert_eq!(
        broad_rules(&c, "eb").await,
        ["$dnstype=A", "*$client=192.168.1.9"]
    );
    // Full: a feed holding one joins the built bundle (a changed definition).
    manual_feed(&c, "ec", json!({})).await;
    save(&c, "ec", "||tracker.example^\n$client=192.168.1.5\n").await;
    put_entity(
        &c,
        "bundles",
        "eb",
        json!({"id": "eb", "name": "eb", "feeds": [{"feed": "ea"}, {"feed": "ec"}]}),
    )
    .await;
    build(&c, "eb").await.unwrap();
    assert_eq!(
        broad_rules(&c, "eb").await,
        ["$client=192.168.1.5", "$dnstype=A", "*$client=192.168.1.9"]
    );
    // Incremental: a new one in a member feed.
    save(&c, "ec", "||tracker.example^\n$client=192.168.1.5\n$ctag=kids\n").await;
    build(&c, "eb").await.unwrap();
    assert_eq!(
        broad_rules(&c, "eb").await,
        [
            "$client=192.168.1.5",
            "$ctag=kids",
            "$dnstype=A",
            "*$client=192.168.1.9"
        ]
    );
}

/// Each open `broad_block` of a bundle: its raw rule → (severity, count).
async fn broad_severities(c: &Core, bundle: &str) -> BTreeMap<String, (String, u64)> {
    open_alerts(c, "broad_block", bundle)
        .await
        .into_iter()
        .map(|a| {
            (
                a.details["rule"].as_str().unwrap().to_string(),
                (
                    serde_json::to_value(a.severity).unwrap().as_str().unwrap().to_string(),
                    a.count as u64,
                ),
            )
        })
        .collect()
}

/// #67: a manual feed's broad block restricted to a selected audience (a positive `$client` or
/// `$ctag`, no broad source range) is a warning, the same for every equivalent form and in
/// fresh, full and incremental builds; exclusion-only selectors, broad source ranges, `$dnstype`
/// or `$denyallow` alone and unscoped rules stay critical. An open critical finding the policy
/// now puts at warning (an older release's) is reclassified in place: one alert, count and
/// history kept. Unchanged rebuilds count nothing; a rule that leaves resolves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scoped_manual_broad_blocks_are_warnings() {
    let c = core().await;
    let warning = [
        "$client=kids-tablet",
        "*$client=kids-tablet",
        "||*^$client=kids-tablet",
        "/./$client=kids-tablet",
        "||com^$client=kids-tablet",
        "$ctag=kids",
        "$client=kids-tablet,dnstype=A",
        "$client=kids-tablet,denyallow=school.example",
        "$client=~admin,ctag=kids",
        "$client=192.168.1.9",
    ];
    let critical = [
        "$client=~kids-tablet",
        "$ctag=~kids",
        "$client=0.0.0.0/0",
        "$client=192.168.1.0/24",
        "$client=kids-tablet|192.168.0.0/16",
        "$dnstype=A",
        "*$denyallow=school.example",
        "||com^",
    ];
    let expected = |rules: &[&str]| -> BTreeMap<String, String> {
        rules
            .iter()
            .map(|r| {
                let sev = if warning.contains(r) { "warning" } else { "critical" };
                (r.to_string(), sev.to_string())
            })
            .collect()
    };
    let severities = |m: BTreeMap<String, (String, u64)>| -> BTreeMap<String, String> {
        m.into_iter().map(|(k, (s, _))| (k, s)).collect()
    };
    // Fresh: half of each list.
    manual_feed(&c, "sa", json!({})).await;
    let first: Vec<&str> = warning[..5].iter().chain(&critical[..4]).copied().collect();
    save(&c, "sa", &format!("||ads.example^\n{}\n", first.join("\n"))).await;
    put_entity(
        &c,
        "bundles",
        "sb",
        json!({"id": "sb", "name": "sb", "feeds": [{"feed": "sa"}]}),
    )
    .await;
    build(&c, "sb").await.unwrap();
    assert_eq!(severities(broad_severities(&c, "sb").await), expected(&first));
    // Incremental: the rest of the first list joins the feed.
    let mut all_a: Vec<&str> = first.clone();
    all_a.extend(&warning[5..8]);
    all_a.extend(&critical[4..6]);
    save(&c, "sa", &format!("||ads.example^\n{}\n", all_a.join("\n"))).await;
    build(&c, "sb").await.unwrap();
    assert_eq!(severities(broad_severities(&c, "sb").await), expected(&all_a));
    // Full: a second manual feed with the rest joins the built bundle.
    manual_feed(&c, "sc", json!({})).await;
    let rest: Vec<&str> = warning[8..].iter().chain(&critical[6..]).copied().collect();
    save(&c, "sc", &format!("{}\n", rest.join("\n"))).await;
    put_entity(
        &c,
        "bundles",
        "sb",
        json!({"id": "sb", "name": "sb", "feeds": [{"feed": "sa"}, {"feed": "sc"}]}),
    )
    .await;
    build(&c, "sb").await.unwrap();
    let mut every: Vec<&str> = all_a.clone();
    every.extend(&rest);
    assert_eq!(severities(broad_severities(&c, "sb").await), expected(&every));
    let scoped = open_alerts(&c, "broad_block", "sb")
        .await
        .into_iter()
        .find(|a| a.details["rule"] == "$ctag=kids")
        .unwrap();
    assert_eq!(
        (
            scoped.details["feed"].as_str(),
            scoped.details["scope"].as_str(),
            scoped.details["line"].is_number()
        ),
        (Some("sa"), Some("selected_audience"), true),
        "{}",
        scoped.details
    );
    assert!(scoped.title.contains("selected audience"), "{}", scoped.title);
    // An older release's critical finding of a scoped rule: reclassified at the next commit, in
    // place, without a new occurrence or a second open alert.
    let key = open_alerts(&c, "broad_block", "sb")
        .await
        .into_iter()
        .find(|a| a.details["rule"] == "$client=kids-tablet")
        .unwrap()
        .dedupe_key;
    let k2 = key.clone();
    c.state
        .db
        .write(move |db| {
            db.execute(
                "UPDATE alerts SET severity = 'critical', title = 'A broad block' WHERE dedupe_key = ?1",
                [&k2],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    save(&c, "sc", &format!("{}\n||more.example^\n", rest.join("\n"))).await;
    build(&c, "sb").await.unwrap();
    let now = broad_severities(&c, "sb").await;
    assert_eq!(severities(now.clone()), expected(&every));
    assert!(now.values().all(|(_, n)| *n == 1), "unchanged rules count nothing: {now:?}");
    let (a, history) = {
        let a = c.state.alerts.get_by_key(&key).await.unwrap().unwrap();
        c.state.alerts.get(a.id).await.unwrap()
    };
    assert_eq!(a.count, 1);
    assert!(a.title.contains("selected audience"), "{}", a.title);
    assert!(
        history.iter().any(|h| h.change == "reclassified"),
        "{history:?}"
    );
    assert_eq!(
        open_alerts(&c, "broad_block", "sb")
            .await
            .iter()
            .filter(|a| a.details["rule"] == "$client=kids-tablet")
            .count(),
        1
    );
    // The scoped rule leaves its feed: its finding resolves; the rest stand.
    let left: Vec<&str> = all_a.iter().copied().filter(|r| *r != "$client=kids-tablet").collect();
    save(&c, "sa", &format!("||ads.example^\n{}\n", left.join("\n"))).await;
    build(&c, "sb").await.unwrap();
    assert_eq!(
        c.state.alerts.get_by_key(&key).await.unwrap().unwrap().state,
        picket_core::alerts::AlertState::Resolved
    );
    let mut remaining = left.clone();
    remaining.extend(&rest);
    assert_eq!(severities(broad_severities(&c, "sb").await), expected(&remaining));
}

/// Warn bundles (build-and-test.md §5 "Warn bundles"; bundles.md §3, feeds.md §7): a block entry
/// a warn bundle named in its feed's `warn_on` matches records a warning and raises
/// `warninglist_hit`; the key keeps blocking; the warning resolves when the entry leaves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn warn_bundles_record_warnings() {
    let c = core().await;
    save(&c, "manual-warn", "||mycompany.example^\n").await;
    build(&c, "warn-common").await;
    manual_feed(&c, "wf", json!({"warn_on": ["warn-common"]})).await;
    put_entity(
        &c,
        "bundles",
        "wb",
        json!({"id": "wb", "name": "wb", "feeds": [{"feed": "wf"}]}),
    )
    .await;
    save(&c, "wf", "||ads.mycompany.example^\n||ads.example^\n").await;
    let head = build(&c, "wb").await.unwrap();
    let (_, w) = get(&c, "/bundles/wb/warnings").await;
    let items = w["warnings"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{w}");
    assert_eq!(items[0]["value"], "ads.mycompany.example");
    assert_eq!(items[0]["by_bundle"], "warn-common");
    assert_eq!(items[0]["kind"], "warn");
    assert_eq!(
        alert(&c, "warninglist_hit:warn-common:wf").await.unwrap().0,
        "open"
    );
    // It keeps blocking.
    let (b, pages, _) = load(&c, &head);
    assert_eq!(decide(&b, &pages, &Q::name("ads.mycompany.example")), "block");
    // The entry leaves its feed: the warning and the alert resolve.
    save(&c, "wf", "||ads.example^\n").await;
    build(&c, "wb").await;
    let (_, w) = get(&c, "/bundles/wb/warnings").await;
    assert!(w["warnings"]["items"].as_array().unwrap().is_empty(), "{w}");
    assert_eq!(
        alert(&c, "warninglist_hit:warn-common:wf").await.unwrap().0,
        "resolved"
    );
}

/// A failed build keeps the previous version and raises `bundle_build_failed`; the next good
/// build resolves it (core.md §9).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_build_keeps_the_previous_version() {
    let c = core().await;
    manual_feed(&c, "ff", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "fb",
        json!({"id": "fb", "name": "fb", "feeds": [{"feed": "ff"}]}),
    )
    .await;
    save(&c, "ff", "||a.example^\n").await;
    let h1 = build(&c, "fb").await.unwrap();
    // Damage the published rich.json: the next incremental build can't continue from it.
    let (_, _, head) = load(&c, &h1);
    let rich = head.segment(picket_bundle::head::RICH).unwrap().to_string();
    let path = picket_core::blobs::path(c.dir.path(), &rich).unwrap();
    let good = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"{broken").unwrap();
    save(&c, "ff", "||a.example^\n||b.example^\n").await;
    c.state.compiler.request(
        &c.state,
        "fb",
        picket_core::compiler::Request::default(),
        picket_core::scheduler::Priority::P0,
    );
    wait("the failure", || async {
        build_row(&c, "fb").await.is_some_and(|r| r.0 == "failed")
    })
    .await;
    assert_eq!(
        build_row(&c, "fb").await.unwrap().1.as_deref(),
        Some(h1.as_str()),
        "the previous version stays"
    );
    assert_eq!(alert(&c, "bundle_build_failed:fb").await.unwrap().0, "open");
    let (_, st) = get(&c, "/bundles/fb/status").await;
    assert_eq!(st["status"], "failed");
    std::fs::write(&path, good).unwrap();
    let h2 = build(&c, "fb").await.unwrap();
    assert_ne!(h1, h2);
    assert_eq!(alert(&c, "bundle_build_failed:fb").await.unwrap().0, "resolved");
}

/// Publishing (bundles.md §7; core.md §4): a new version changes the head an edge's config object
/// names; a head past the edge's `bundle_budget_mib` isn't named (the edge keeps its version) and
/// `bundle_over_budget` names the edge and the bundle; serving the config pins what it names.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn versions_reach_edge_configs_within_budgets() {
    let c = core().await;
    let edge = common::edge::FakeEdge::registered(&c, "e1").await;
    save(&c, "manual-block", "||blocked.example^\n").await;
    let h1 = build(&c, "block-common").await.unwrap();
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    let named = |c: &Core| {
        c.state
            .edges
            .publisher
            .current(&edge.id)
            .unwrap()
            .config
            .bundles
            .get("block-common")
            .cloned()
    };
    assert_eq!(named(&c).as_deref(), Some(h1.as_str()));
    // A new version is named.
    save(&c, "manual-block", "||blocked.example^\n||also.example^\n").await;
    let h2 = build(&c, "block-common").await.unwrap();
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    assert_eq!(named(&c).as_deref(), Some(h2.as_str()));
    // A version too large for the edge's budget (its stats say 1 GiB): the edge keeps h2.
    // Inflated in its commit's own transaction, so the publisher's own render (debounced after
    // the commit) never sees it small.
    let sql = format!(
        "CREATE TRIGGER inflate_h3 AFTER INSERT ON bundle_versions
         WHEN NEW.bundle_id = 'block-common' AND NEW.head_id NOT IN ('{h1}', '{h2}')
         BEGIN UPDATE bundle_versions SET stats_json = json_set(stats_json, '$.edge_mem_bytes', 1073741824)
           WHERE bundle_id = NEW.bundle_id AND head_id = NEW.head_id; END"
    );
    c.state
        .db
        .write(move |db| {
            db.execute(&sql, [])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    save(
        &c,
        "manual-block",
        "||blocked.example^\n||also.example^\n||third.example^\n",
    )
    .await;
    let h3 = build(&c, "block-common").await.unwrap();
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    assert_eq!(
        named(&c).as_deref(),
        Some(h2.as_str()),
        "the edge stays on its version"
    );
    let a = alert(&c, &format!("bundle_over_budget:{}:block-common", edge.id))
        .await
        .unwrap();
    assert_eq!(a.0, "open");
    assert_eq!(a.1["wanted_head"], h3);
    // Serving the config pins the head it names.
    let r = edge
        .http
        .get(format!(
            "https://127.0.0.1:{}/objects/configs/{}.json",
            edge.port, edge.fp_path
        ))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let pinned: i64 = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT count(*) FROM edge_pins WHERE kind = 'bundle' AND target = 'block-common'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(pinned >= 1);
    // The head and its blobs are served to the pinned edge.
    let r = edge
        .http
        .get(format!(
            "https://127.0.0.1:{}/objects/bundles/block-common/heads/{h2}.json",
            edge.port
        ))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let head: picket_bundle::Head = serde_json::from_slice(&r.bytes().await.unwrap()).unwrap();
    let base = &head.shards[0].base;
    let r = edge
        .http
        .get(format!("https://127.0.0.1:{}/objects/blobs/{base}", edge.port))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
}

/// The UI API (core.md §12 Bundles): status, versions, build now, explain with the reference
/// matcher.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bundle_routes() {
    let c = core().await;
    manual_feed(&c, "uf", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "ub",
        json!({"id": "ub", "name": "ub", "feeds": [{"feed": "uf"}]}),
    )
    .await;
    save(&c, "uf", "||ads.example^\n@@||ok.ads.example^\n").await;
    let head = build(&c, "ub").await.unwrap();
    let (st, all) = get(&c, "/bundle-status").await;
    assert!(st.is_success());
    assert!(
        all.as_array()
            .unwrap()
            .iter()
            .any(|b| b["bundle"] == "ub" && b["head"] == head)
    );
    let (_, s) = get(&c, "/bundles/ub/status").await;
    assert_eq!(s["status"], "ok");
    assert!(!s["shards"].as_array().unwrap().is_empty());
    let (_, e) = get(&c, "/bundles/ub/explain?name=x.ads.example").await;
    assert_eq!(e["outcome"], "block");
    assert_eq!(e["matches"][0]["rule"], "||ads.example^");
    let (_, e) = get(&c, "/bundles/ub/explain?name=ok.ads.example").await;
    assert_eq!(e["outcome"], "exception");
    let r = ui(&c, Method::POST, "/bundles/ub/build")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::ACCEPTED);
    settle(&c, "ub").await;
    let (st, _) = get(&c, "/bundles/nope/status").await;
    assert_eq!(st, reqwest::StatusCode::NOT_FOUND);
}

/// Hot and cold parts (build-and-test.md §5; bundles.md §1 Tiers, §2 Tiering): an
/// intelligent-tiering feed's keys all start hot; the build that pushes the hot part past
/// `hot_max_mib` re-ranks, and the keys ranking within it stay hot while the rest move cold (both
/// sides of each move in one head); a second re-rank of the same inputs moves nothing (ranking
/// determinism); a cold key still blocks, answered from the cold part.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intelligent_tiering_ranks_and_moves_keys() {
    let c = core().await;
    manual_feed(&c, "itf", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "tier",
        json!({"id": "tier", "name": "tier", "hot_max_mib": 1, "max_shard_keys": 0,
               "feeds": [{"feed": "itf", "tier": "intelligent-tiering"}]}),
    )
    .await;
    let n = 75_000usize;
    let mut text = String::with_capacity(n * 20);
    for i in 0..n {
        text.push_str(&format!("||t{i}.example^\n"));
    }
    save(&c, "itf", &text).await;
    build(&c, "tier").await.unwrap();
    // The re-rank the build asked for (P2) runs; wait for it.
    settle(&c, "tier").await;
    let parts = || async {
        c.state
            .db
            .read(|db| {
                let hot: i64 = db.query_row(
                    "SELECT count(*) FROM bundle_keys WHERE bundle_id = 'tier' AND part = 'hot'",
                    [],
                    |r| r.get(0),
                )?;
                let cold: i64 = db.query_row(
                    "SELECT count(*) FROM bundle_keys WHERE bundle_id = 'tier' AND part = 'cold'",
                    [],
                    |r| r.get(0),
                )?;
                Ok::<_, anyhow::Error>((hot, cold))
            })
            .await
            .unwrap()
    };
    let per = picket_core::compiler::tier::HOT_BYTES_PER_KEY as i64;
    let within = (1024 * 1024) / per;
    wait("the re-rank's moves", || async { parts().await.0 == within }).await;
    let (hot, cold) = parts().await;
    assert_eq!((hot, cold), (within, n as i64 - within));
    let head = build_row(&c, "tier").await.unwrap().1.unwrap();
    let (b, pages, h) = load(&c, &head);
    assert!(!h.cold_shards.is_empty());
    // A cold key blocks, from the cold part.
    let cold_key: String = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT key FROM bundle_keys WHERE bundle_id = 'tier' AND part = 'cold' LIMIT 1",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    let name = picket_rules::name::reverse_dotted(&cold_key);
    let labels: Vec<&[u8]> = name.split('.').map(str::as_bytes).collect();
    let d = b.lookup_labels_full(
        &labels,
        &picket_rules::QueryCtx {
            qtype: 1,
            ..Default::default()
        },
        &pages,
    );
    assert_eq!(outcome(&d.outcome), "block");
    assert!(d.reason.unwrap().cold, "answered from the cold part");
    // Ranking determinism: re-ranking the same inputs moves nothing and publishes nothing new.
    c.state.compiler.request(
        &c.state,
        "tier",
        picket_core::compiler::Request {
            rerank: true,
            ..Default::default()
        },
        picket_core::scheduler::Priority::P0,
    );
    settle(&c, "tier").await;
    assert_eq!(parts().await, (hot, cold));
    assert_eq!(
        build_row(&c, "tier").await.unwrap().1.unwrap(),
        head,
        "the same head"
    );
}

/// The grouped public-suffix warning's dedupe key (#49).
fn psl_key(bundle: &str, feed: &str) -> String {
    format!("bundle_warning:{bundle}:public_suffix:{feed}")
}

/// The alert under `key`.
async fn alert_of(c: &Core, key: &str) -> picket_core::alerts::Alert {
    c.state.alerts.get_by_key(key).await.unwrap().unwrap_or_else(|| panic!("no alert {key}"))
}

fn is_open(a: &picket_core::alerts::Alert) -> bool {
    a.state == picket_core::alerts::AlertState::Open
}

/// Resolves the alert under `key` by hand, through the UI API.
async fn resolve_by_hand(c: &Core, key: &str) {
    let id = alert_of(c, key).await.id;
    let r = ui(c, Method::POST, &format!("/alerts/{id}/resolve"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
}

/// Twenty public suffixes below the top level, sorted.
const SUFFIXES: [&str; 20] = [
    "ac.uk", "co.jp", "co.nz", "co.uk", "com.au", "com.br", "edu.au", "gov.uk", "ltd.uk", "me.uk",
    "ne.jp", "net.au", "net.br", "net.nz", "or.jp", "org.au", "org.nz", "org.uk", "plc.uk", "police.uk",
];

fn psl_rules(suffixes: &[&str], extra: &str) -> String {
    let mut s: String = suffixes.iter().map(|x| format!("||{x}^\n")).collect();
    s.push_str(extra);
    s
}

/// Public-suffix guardrail (#49): one warning per (bundle, feed) pair with the exact counts and
/// a preview, the full list behind it paginated; its summary follows the set without new
/// occurrences while open; a hand resolve holds until a suffix it hasn't shown enters, which
/// reopens it (also when the count stays the same); a feed leaving the bundle and the bundle's
/// deletion resolve theirs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_suffix_warnings_are_grouped_per_bundle_and_feed() {
    let c = core().await;
    manual_feed(&c, "pa", json!({})).await;
    manual_feed(&c, "pb", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "p1",
        json!({"id": "p1", "name": "p1", "feeds": [{"feed": "pa"}, {"feed": "pb"}]}),
    )
    .await;
    put_entity(&c, "bundles", "p2", json!({"id": "p2", "name": "p2", "feeds": [{"feed": "pa"}]})).await;
    // co.uk twice: two rules, one suffix.
    save(&c, "pa", &psl_rules(&SUFFIXES, "||co.uk^$important\n||fine.example^\n")).await;
    save(&c, "pb", "||com.au^\n").await;
    build(&c, "p1").await.unwrap();
    build(&c, "p2").await.unwrap();

    let a = alert_of(&c, &psl_key("p1", "pa")).await;
    assert!(is_open(&a));
    assert_eq!(a.details["warning"], "public_suffix");
    assert_eq!(a.details["suffixes"], 20);
    assert_eq!(a.details["rules"], 21);
    assert_eq!(a.details["preview"], json!(SUFFIXES[..10]));
    assert_eq!(a.details["more"], 10);
    assert_eq!(a.title, "Bundle p1 blocks 20 public suffixes (feed pa)");
    let count = a.count;
    let b = alert_of(&c, &psl_key("p1", "pb")).await;
    assert!(is_open(&b));
    assert_eq!(b.details["suffixes"], 1);
    assert_eq!(b.title, "Bundle p1 blocks 1 public suffix (feed pb)");
    assert_eq!(alert_of(&c, &psl_key("p2", "pa")).await.details["suffixes"], 20);
    // One warning per pair, none per rule.
    let open: Vec<String> = open_alerts(&c, "bundle_warning", "p1")
        .await
        .iter()
        .filter(|a| a.details["warning"] == "public_suffix")
        .map(|a| a.dedupe_key.clone())
        .collect();
    assert_eq!(open.len(), 2, "{open:?}");

    // The full list, paginated past the preview.
    let (st, page) = get(&c, "/bundles/p1/public-suffixes?feed=pa&limit=15").await;
    assert_eq!(st, 200, "{page}");
    assert_eq!(page["total"], 20);
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 15);
    let co = items.iter().find(|i| i["suffix"] == "co.uk").unwrap();
    let mut rules: Vec<&str> = co["rules"].as_array().unwrap().iter().map(|r| r["rule"].as_str().unwrap()).collect();
    rules.sort_unstable();
    assert_eq!(rules, ["||co.uk^", "||co.uk^$important"]);
    assert!(co["rules"][0]["line"].as_i64().unwrap() > 0);
    let cursor = page["next_cursor"].as_str().unwrap();
    let (_, page2) = get(&c, &format!("/bundles/p1/public-suffixes?feed=pa&limit=15&cursor={cursor}")).await;
    assert_eq!(page2["items"].as_array().unwrap().len(), 5);
    assert!(page2["next_cursor"].is_null());
    let (_, all) = get(&c, "/bundles/p1/public-suffixes").await;
    assert_eq!(all["total"], 21, "both feeds");
    assert_eq!(get(&c, "/bundles/nope/public-suffixes").await.0, 404);

    // A suffix leaves: the summary follows, no new occurrence.
    let fewer: Vec<&str> = SUFFIXES.iter().copied().filter(|s| *s != "police.uk").collect();
    save(&c, "pa", &psl_rules(&fewer, "||co.uk^$important\n||fine.example^\n")).await;
    build(&c, "p1").await.unwrap();
    let a = alert_of(&c, &psl_key("p1", "pa")).await;
    assert!(is_open(&a));
    assert_eq!(a.details["suffixes"], 19);
    assert_eq!(a.count, count, "a summary update isn't an occurrence");

    // Resolved by hand: a rebuild with the same suffixes leaves it resolved.
    resolve_by_hand(&c, &psl_key("p1", "pa")).await;
    save(&c, "pa", &psl_rules(&fewer, "||co.uk^$important\n||fine.example^\n||other.example^\n")).await;
    build(&c, "p1").await.unwrap();
    assert!(!is_open(&alert_of(&c, &psl_key("p1", "pa")).await), "nothing new: stays resolved");

    // The same count with one suffix replaced reopens it, naming the new one.
    let replaced: Vec<&str> = fewer.iter().map(|s| if *s == "me.uk" { "com.mx" } else { s }).collect();
    save(&c, "pa", &psl_rules(&replaced, "||co.uk^$important\n||fine.example^\n")).await;
    build(&c, "p1").await.unwrap();
    let a = alert_of(&c, &psl_key("p1", "pa")).await;
    assert!(is_open(&a), "a suffix it hadn't shown reopens it");
    assert_eq!(a.details["suffixes"], 19);
    assert_eq!(a.details["added"], json!(["com.mx"]));

    // Feed pb leaves p1: its warning resolves. p2 is deleted: its warning resolves.
    put_entity(&c, "bundles", "p1", json!({"id": "p1", "name": "p1", "feeds": [{"feed": "pa"}]})).await;
    build(&c, "p1").await.unwrap();
    assert!(!is_open(&alert_of(&c, &psl_key("p1", "pb")).await));
    assert!(is_open(&alert_of(&c, &psl_key("p1", "pa")).await));
    let r = ui(&c, Method::DELETE, "/bundles/p2")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    wait("p2's warning to resolve", || async {
        !is_open(&alert_of(&c, &psl_key("p2", "pa")).await)
    })
    .await;
}

/// A hand-resolved public-suffix warning stays resolved across a restart and a rebuild with
/// the same suffixes (#49).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_resolved_public_suffix_warning_survives_a_restart() {
    let c = core().await;
    manual_feed(&c, "pr", json!({})).await;
    put_entity(&c, "bundles", "pr1", json!({"id": "pr1", "name": "pr1", "feeds": [{"feed": "pr"}]})).await;
    save(&c, "pr", "||co.uk^\n||org.uk^\n").await;
    build(&c, "pr1").await.unwrap();
    resolve_by_hand(&c, &psl_key("pr1", "pr")).await;
    let c = restarted(c).await;
    assert!(!is_open(&alert_of(&c, &psl_key("pr1", "pr")).await));
    save(&c, "pr", "||co.uk^\n||org.uk^\n||fine.example^\n").await;
    build(&c, "pr1").await.unwrap();
    assert!(!is_open(&alert_of(&c, &psl_key("pr1", "pr")).await), "same suffixes: stays resolved");
    save(&c, "pr", "||co.uk^\n||org.uk^\n||me.uk^\n").await;
    build(&c, "pr1").await.unwrap();
    let a = alert_of(&c, &psl_key("pr1", "pr")).await;
    assert!(is_open(&a));
    assert_eq!(a.details["added"], json!(["me.uk"]));
}

/// Stops `c` and starts a core on a copy of its data directory.
async fn restarted(c: Core) -> Core {
    c.stop.cancel();
    let dir = tempfile::tempdir().unwrap();
    common::snapshot_dir(c.dir.path(), dir.path());
    let init = c.init.clone();
    drop(c);
    let stop = tokio_util::sync::CancellationToken::new();
    let opts = picket_core::run::StartOptions {
        release_dir: std::path::PathBuf::from("/nonexistent/picket-core/edge"),
        any_port: true,
        clock_synced: Some(true),
        disk_watch: false,
        ..Default::default()
    };
    let (state, info) = picket_core::run::start_with(dir.path(), stop.clone(), opts).await.unwrap();
    Core {
        dir,
        init,
        state,
        info,
        stop,
    }
}
