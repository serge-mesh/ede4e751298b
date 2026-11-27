//! Golden files (build-and-test.md §4 "Golden bundle files, cold page files and verdict sets
//! included: written on x86_64, read on aarch64, identical lookups"; bundles.md §4).
//!
//! `fixtures/bundles/` holds a small block bundle at its second version (hot, cold and IP shard
//! bases, a hot, a cold and an IP delta, both segments) and a verdict set (base and delta), each
//! blob under `blobs/<blake3>`, the heads as `head.json`, and `expectations.tsv`: queries and the
//! decisions recorded when the files were written (checked against picket-rules' reference
//! matcher then). The read test loads the files from disk, reading cold and verdict pages with
//! `pread` as the edge does, and requires the same decisions; nothing in the formats depends on
//! the host's endianness or pointer width, so the files read identically on aarch64 (the QEMU run
//! is deferred infrastructure). A second test rebuilds every file in memory and
//! requires byte-identical output (bundles.md §2 "Determinism").
//!
//! Regenerate with `PICKET_WRITE_GOLDEN_BUNDLES=1 cargo test -p picket-bundle --test golden`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use common::*;
use picket_bundle::FORMAT;
use picket_bundle::compile::{
    BuildOptions, BuiltBundle, CompileOptions, Compiled, build, compile_rules, load_bundle,
};
use picket_bundle::hash::verdict_hash_seed;
use picket_bundle::head::DeltaRef;
use picket_bundle::page::{PAGE_SIZE, PageReader};
use picket_bundle::patterns::DEFAULT_BUDGET;
use picket_bundle::verdict::{
    VerdictChange, VerdictHead, VerdictKind, VerdictRecord, load_verdict_set, name_hash, write_base,
    write_delta,
};
use picket_rules::Flags;
use picket_rules::compile::Part;
use picket_rules::formats::{DomainsAs, Format, ParseConfig, parse_lines};
use picket_rules::matcher::BundleAction;

fn dir() -> PathBuf {
    Path::new(FIXTURES).join("bundles")
}

const V1: &[&str] = &[
    "||ads.example^",
    "|exact.example^",
    "@@||ok.ads.example^",
    "||imp.example^$important",
    "@@||imp.example^",
    "*.subs.example^",
    "0.0.0.0 hosts.example",
    "192.0.2.10 mapped.example",
    "||rw.example^$dnsrewrite=203.0.113.7",
    "||nx.example^$dnsrewrite=NXDOMAIN;;",
    "||aaaa.example^$dnstype=AAAA",
    "||kid.example^$client=kid",
    "||deny.example^$denyallow=fine.deny.example",
    "||ads*.track.example^",
    "/^banner[0-9]+\\./",
    "||1.2.3.4^",
    "@@||1.2.3.5^",
    "||10.0.0^",
    "||2001:db8::1^",
    "||cold1.example^",
    "||cold2.example^",
    "||cold3.example^",
];

const V2_CHANGES: &[&str] = &["||new.example^", "||cold4.example^", "@@||198.51.100.7^"];
const V2_REMOVED: &[&str] = &["||cold2.example^", "|exact.example^"];

fn rules(lines: &[&str], plain: &[&str]) -> Vec<picket_rules::Rule> {
    let mut out = parse_rules(&lines.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let cfg = ParseConfig::new(
        Format::Plain,
        DomainsAs::Exact,
        picket_api::time::Timestamp::now(),
    );
    parse_lines(plain.join("\n").as_bytes(), &cfg, |e| out.push(e.rule)).unwrap();
    out
}

fn v1_rules() -> Vec<picket_rules::Rule> {
    rules(V1, &["198.51.100.0/24", "2001:db8:1::/48"])
}

fn v2_rules() -> Vec<picket_rules::Rule> {
    let lines: Vec<&str> = V1
        .iter()
        .copied()
        .filter(|l| !V2_REMOVED.contains(l))
        .chain(V2_CHANGES.iter().copied())
        .collect();
    rules(&lines, &["198.51.100.0/24", "2001:db8:1::/48", "203.0.113.0/28"])
}

fn tier(k: &str, _f: Flags) -> Part {
    if k.starts_with("example.cold") {
        Part::Cold
    } else {
        Part::Hot
    }
}

fn compiled(r: &[picket_rules::Rule]) -> Compiled {
    compile_rules(r, &CompileOptions::new(BundleAction::Block, Some(psl())))
}

/// Every golden file, built in memory.
struct Golden {
    head: Vec<u8>,
    verdict_head: Vec<u8>,
    blobs: Store,
    /// The second version's rules (for the reference check).
    rules: Vec<picket_rules::Rule>,
}

fn generate() -> Golden {
    let mut o = BuildOptions::new("golden", BundleAction::Block);
    o.part_of = Some(&tier);
    o.max_shard_keys = 8;
    o.feed_runs = [("manual-block".to_string(), 3)].into_iter().collect();
    let v1: BuiltBundle = build(&compiled(&v1_rules()), &o).unwrap();
    assert!(!v1.head.cold_shards.is_empty() && v1.head.shards.len() > 1 && v1.head.ip_shards.len() >= 3);
    let r2 = v2_rules();
    let (mut h2, mut store, _, _) = incremental(&v1, &compiled(&r2), Some(&tier), 1);
    h2.issued_at = "2026-11-21T01:00:00Z".into();
    assert!(h2.shards.iter().any(|s| !s.deltas.is_empty()));
    assert!(h2.cold_shards.iter().any(|s| !s.deltas.is_empty()));
    assert!(h2.ip_shards.iter().any(|s| !s.deltas.is_empty()));
    // Keep only the blobs the head names.
    let mut named: Vec<String> = Vec::new();
    for s in h2.shards.iter().chain(&h2.cold_shards) {
        named.push(s.base.clone());
        let m = picket_bundle::head::Manifest::from_bytes(&store[&s.base]).unwrap();
        named.extend(m.files.values().map(|f| f.blake3.clone()));
        named.extend(s.deltas.iter().map(|d| d.blake3.clone()));
    }
    for s in &h2.ip_shards {
        named.push(s.base.clone());
        named.extend(s.deltas.iter().map(|d| d.blake3.clone()));
    }
    named.extend(h2.segments.values().cloned());
    store.retain(|k, _| named.contains(k));
    // The verdict set.
    let (provider, generation) = ("q9", "b71e4d09a2c63f58");
    let seed = verdict_hash_seed(provider, generation);
    let at = picket_api::time::Timestamp::from_microsecond(1_763_686_921_123_456).unwrap();
    let rec = |v, s: Option<f32>, r: Option<&str>| VerdictRecord {
        verdict: v,
        obtained_at: at,
        score: s,
        reason: r.map(String::from),
    };
    let base_recs = vec![
        (
            name_hash(seed, "bad.example.org"),
            rec(VerdictKind::Block, Some(9.5), Some("malware")),
        ),
        (
            name_hash(seed, "good.example.org"),
            rec(VerdictKind::Clean, None, None),
        ),
        (
            name_hash(seed, "gone.example.org"),
            rec(VerdictKind::Block, None, Some("phishing")),
        ),
    ];
    let base = write_base(provider, generation, &base_recs).unwrap();
    let (delta, dh) = write_delta(
        provider,
        generation,
        &base.blob.id,
        1,
        base.checksum,
        &[
            VerdictChange {
                hash: name_hash(seed, "gone.example.org"),
                old: Some(base_recs[2].1.clone()),
                new: None,
            },
            VerdictChange {
                hash: name_hash(seed, "new.example.org"),
                old: None,
                new: Some(rec(VerdictKind::Unknown, None, None)),
            },
        ],
        "2026-11-21T01:00:00Z",
    )
    .unwrap();
    store.insert(base.blob.id.clone(), base.blob.bytes.clone());
    store.insert(delta.id.clone(), delta.bytes.clone());
    let vh = VerdictHead {
        provider: provider.into(),
        format: FORMAT,
        generation: generation.into(),
        hash_seed: seed,
        base: base.blob.id.clone(),
        deltas: vec![DeltaRef {
            seq: 1,
            blake3: delta.id.clone(),
            size: delta.size(),
        }],
        seq: 1,
        checksum: dh.new_checksum,
        issued_at: "2026-11-21T01:00:00Z".into(),
    };
    Golden {
        head: h2.to_bytes(),
        verdict_head: vh.to_blob().bytes,
        blobs: store,
        rules: r2,
    }
}

/// The edge's page reader: open, `pread` one page, close.
struct FsPages(PathBuf);

impl PageReader for FsPages {
    fn read_page(&self, file: &str, file_page: u64, buf: &mut [u8; PAGE_SIZE]) -> std::io::Result<()> {
        if !picket_bundle::bytes::is_object_id(file) {
            return Err(std::io::Error::other("bad file id"));
        }
        let f = fs::File::open(self.0.join(file))?;
        f.read_exact_at(buf, file_page * PAGE_SIZE as u64)
    }
}

fn queries() -> Vec<Query> {
    let mut out = Vec::new();
    for n in [
        "ads.example",
        "x.ads.example",
        "ok.ads.example",
        "a.ok.ads.example",
        "exact.example",
        "sub.exact.example",
        "imp.example",
        "x.imp.example",
        "subs.example",
        "a.subs.example",
        "hosts.example",
        "mapped.example",
        "rw.example",
        "nx.example",
        "aaaa.example",
        "kid.example",
        "deny.example",
        "fine.deny.example",
        "x.fine.deny.example",
        "ads1.track.example",
        "banner12.example.net",
        "cold1.example",
        "x.cold2.example",
        "cold3.example",
        "cold4.example",
        "new.example",
        "1.2.3.4",
        "other.example",
        "1.10.0.0",
    ] {
        for (qtype, client) in [(1u16, None), (28, Some("kid"))] {
            let mut q = Query::name(n);
            q.qtype = qtype;
            q.client_name = client.map(String::from);
            out.push(q);
        }
    }
    for ip in [
        "1.2.3.4",
        "1.2.3.5",
        "1.2.3.6",
        "10.0.0.9",
        "1.10.0.0",
        "198.51.100.7",
        "198.51.100.8",
        "203.0.113.5",
        "203.0.113.99",
        "2001:db8::1",
        "2001:db8:1::9",
        "2001:db8:2::1",
        "::ffff:1.2.3.4",
    ] {
        out.push(Query::ip(ip.parse().unwrap()));
    }
    out
}

fn query_key(q: &Query) -> String {
    let t = match &q.target {
        Target::Name(l) => format!(
            "name:{}",
            picket_api::names::encode_labels(l.iter().map(Vec::as_slice))
        ),
        Target::Ip(ip) => format!("ip:{ip}"),
    };
    format!("{t}\t{}\t{}", q.qtype, q.client_name.as_deref().unwrap_or("-"))
}

#[test]
fn golden_files_read_identically() {
    let d = dir();
    if std::env::var_os("PICKET_WRITE_GOLDEN_BUNDLES").is_some() {
        write_golden(&d);
    }
    let blobs_dir = d.join("blobs");
    let mut store: Store = BTreeMap::new();
    for e in fs::read_dir(&blobs_dir)
        .expect("fixtures/bundles/blobs (regenerate with PICKET_WRITE_GOLDEN_BUNDLES=1)")
    {
        let e = e.unwrap();
        store.insert(
            e.file_name().to_string_lossy().into_owned(),
            fs::read(e.path()).unwrap(),
        );
    }
    let pages = FsPages(blobs_dir.clone());
    let head = fs::read(d.join("block-head.json")).unwrap();
    let bundle = load_bundle(&head, &store, Some(&pages), DEFAULT_BUDGET).expect("golden bundle loads");
    let want: BTreeMap<String, String> = fs::read_to_string(d.join("expectations.tsv"))
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let (k, v) = l.rsplit_once('\t').unwrap();
            (k.to_string(), v.to_string())
        })
        .collect();
    let mut checked = 0;
    for q in queries() {
        let k = query_key(&q);
        let Some(w) = want.get(&k) else { continue };
        let d = common_decision(&bundle, &pages, &q);
        assert_eq!(&format_decision(&d), w, "{k}");
        checked += 1;
    }
    assert!(checked > 60, "{checked}");
    // The verdict set.
    let vhead = fs::read(d.join("verdict-head.json")).unwrap();
    let set = load_verdict_set(&vhead, &|id| store.get(id).cloned(), &pages).unwrap();
    assert_eq!(
        set.lookup("bad.example.org", &pages).unwrap().unwrap().verdict,
        VerdictKind::Block
    );
    assert_eq!(
        set.lookup("good.example.org", &pages).unwrap().unwrap().verdict,
        VerdictKind::Clean
    );
    assert_eq!(set.lookup("gone.example.org", &pages).unwrap(), None);
    assert_eq!(
        set.lookup("new.example.org", &pages).unwrap().unwrap().verdict,
        VerdictKind::Unknown
    );
    let bad = set.lookup("bad.example.org", &pages).unwrap().unwrap();
    assert_eq!(bad.score, Some(9.5));
    assert_eq!(bad.reason.as_deref(), Some("malware"));
    assert_eq!(bad.obtained_at.as_microsecond(), 1_763_686_921_123_456);
}

fn common_decision(b: &picket_bundle::Bundle, pages: &dyn PageReader, q: &Query) -> picket_bundle::Decision {
    let names: Vec<&str> = q.client_name.iter().map(String::as_str).collect();
    let ctx = picket_rules::QueryCtx {
        qtype: q.qtype,
        client_ip: q.client_ip,
        client_names: &names,
        client_tags: &[],
    };
    match &q.target {
        Target::Name(n) => {
            let labels: Vec<&[u8]> = n.iter().map(Vec::as_slice).collect();
            b.lookup_labels_full(&labels, &ctx, pages)
        }
        Target::Ip(ip) => {
            let d = b.lookup_ip(*ip, &ctx);
            if d.cold == picket_bundle::ColdCheck::Needed {
                d.with_cold(b.lookup_ip_cold(*ip, pages))
            } else {
                d
            }
        }
    }
}

fn format_decision(d: &picket_bundle::Decision) -> String {
    let r = d
        .reason
        .as_ref()
        .map(|r| format!("{:?}/{:?}/{}", r.kind, r.key, if r.cold { "cold" } else { "hot" }))
        .unwrap_or_else(|| "-".into());
    format!("{} {r}", decision(&d.outcome))
}

#[test]
fn golden_files_are_byte_identical_when_rebuilt() {
    let d = dir();
    if !d.join("block-head.json").exists() {
        return;
    }
    let Golden {
        head,
        verdict_head: vhead,
        blobs: store,
        ..
    } = generate();
    assert_eq!(
        fs::read(d.join("block-head.json")).unwrap(),
        head,
        "head.json changed: regenerate"
    );
    assert_eq!(fs::read(d.join("verdict-head.json")).unwrap(), vhead);
    for (id, bytes) in &store {
        let on_disk =
            fs::read(d.join("blobs").join(id)).unwrap_or_else(|_| panic!("blob {id} missing: regenerate"));
        assert_eq!(&on_disk, bytes, "blob {id}");
    }
}

fn write_golden(d: &Path) {
    let Golden {
        head,
        verdict_head: vhead,
        blobs: store,
        rules: r2,
    } = generate();
    let _ = fs::remove_dir_all(d);
    fs::create_dir_all(d.join("blobs")).unwrap();
    for (id, bytes) in &store {
        fs::write(d.join("blobs").join(id), bytes).unwrap();
    }
    fs::write(d.join("block-head.json"), &head).unwrap();
    fs::write(d.join("verdict-head.json"), &vhead).unwrap();
    // Expectations, from the in-memory bundle, each checked against the reference matcher.
    let mem = picket_bundle::page::MemPages {
        files: store.clone().into_iter().collect(),
    };
    let bundle = load_bundle(&head, &store, Some(&mem), DEFAULT_BUDGET).unwrap();
    let reference = reference(BundleAction::Block, r2);
    let mut out = String::from(
        "# query\tqtype\tclient name\tdecision reason (written by tests/golden.rs; PICKET_WRITE_GOLDEN_BUNDLES=1)\n",
    );
    for q in queries() {
        let dd = common_decision(&bundle, &mem, &q);
        assert_eq!(
            decision(&dd.outcome),
            decision(&reference_outcome(&reference, &q)),
            "{q:?}"
        );
        out.push_str(&format!("{}\t{}\n", query_key(&q), format_decision(&dd)));
    }
    fs::write(d.join("expectations.tsv"), out).unwrap();
    fs::write(
        d.join("README.md"),
        "# Golden bundle files\n\nWritten by `crates/picket-bundle/tests/golden.rs` (regenerate with \
         `PICKET_WRITE_GOLDEN_BUNDLES=1 cargo test -p picket-bundle --test golden`): a block bundle at its \
         second version (`block-head.json`: hot, cold and IP shard bases with a hot, a cold and an IP delta, \
         and both segments) and a verdict set (`verdict-head.json`: base and delta). Every blob is under \
         `blobs/<blake3>`. `expectations.tsv` holds the decisions recorded when the files were written; the \
         test reads the files back (cold and verdict pages with `pread`) and requires the same decisions \
         (build-and-test.md §4).\n",
    )
    .unwrap();
}
