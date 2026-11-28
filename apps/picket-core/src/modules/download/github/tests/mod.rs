//! `github` against a local fake of github.com, api.github.com and raw.githubusercontent.com
//! (build-and-test.md §5 "Download modules"): recorded `ls-refs` replies, the trees, commits and
//! contents APIs, blob checks, rate-limit replies, a jsDelivr `@latest` URL, several feeds of one
//! provider, a head move changing one of them, a feed left out of a check catching up after the
//! head moved on, a truncated tree walked within its budget and one that can't finish, and a
//! file deleted from the repository.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use serde_json::json;

use super::*;
use crate::modules::download::LastRun;
use crate::modules::download::client::{Http, HttpOptions};
use crate::modules::download::testkit::{Reply, Seen, TestServer};

/// A recorded `ls-refs` answer (protocol v2) from github.com for `ref-prefix HEAD` with
/// `symrefs`, as captured; the object id is substituted.
const LS_REFS_HEAD: &str = include_str!("ls-refs-head.txt");

#[derive(Default)]
struct Repo {
    head: String,
    /// commit → (path → body).
    trees: HashMap<String, BTreeMap<String, String>>,
    /// Commits API items, newest first.
    commits: Vec<serde_json::Value>,
    /// Serve another body than the blob hash says.
    corrupt: bool,
    /// The recursive tree answer is truncated.
    truncated: bool,
    rate_limit: Option<Reply>,
}

fn blob_sha(body: &str) -> String {
    let mut h = sha1::Sha1::new();
    h.update(format!("blob {}\0", body.len()).as_bytes());
    h.update(body.as_bytes());
    hex::encode(h.finalize())
}

/// A tree id for a directory of a commit (`<commit>:<dir>` hashed).
fn tree_sha(commit: &str, dir: &str) -> String {
    let mut h = sha1::Sha1::new();
    h.update(format!("{commit}:{dir}").as_bytes());
    hex::encode(h.finalize())
}

fn pkt(line: &str) -> String {
    format!("{:04x}{line}", line.len() + 4)
}

/// The entries of one directory of a commit's tree: its files and its subdirectories.
fn dir_entries(files: &BTreeMap<String, String>, commit: &str, dir: &str) -> Vec<serde_json::Value> {
    let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
    let mut out = Vec::new();
    let mut subdirs = std::collections::BTreeSet::new();
    for (path, body) in files {
        let Some(rest) = path.strip_prefix(&prefix) else { continue };
        match rest.split_once('/') {
            None => out.push(json!({"path": rest, "type": "blob", "mode": "100644", "sha": blob_sha(body)})),
            Some((d, _)) => {
                subdirs.insert(d.to_string());
            }
        }
    }
    for d in subdirs {
        let full = if dir.is_empty() { d.clone() } else { format!("{dir}/{d}") };
        out.push(json!({"path": d, "type": "tree", "mode": "040000", "sha": tree_sha(commit, &full)}));
    }
    out
}

fn handler(repo: Arc<Mutex<Repo>>) -> impl Fn(&Seen) -> Reply + Send + Sync + 'static {
    move |s: &Seen| {
        let r = repo.lock().unwrap();
        if let Some(rl) = &r.rate_limit {
            return rl.clone();
        }
        match s.host.as_str() {
            "github.com" => {
                assert_eq!(s.path, "/hagezi/dns-blocklists.git/git-upload-pack");
                assert_eq!(s.header("git-protocol"), Some("version=2"));
                let body = String::from_utf8_lossy(&s.body).into_owned();
                let answer = if body.contains("ref-prefix HEAD") {
                    LS_REFS_HEAD.replace("{OID}", &r.head)
                } else if body.contains("ref-prefix refs/heads/main") {
                    format!(
                        "{}{}0000",
                        pkt(&format!("{}000000 refs/heads/main-old\n", &r.head[..34])),
                        pkt(&format!("{} refs/heads/main\n", r.head))
                    )
                } else {
                    "0000".into()
                };
                Reply::ok(answer).header("content-type", "application/x-git-upload-pack-result")
            }
            "api.github.com" => {
                let rest = s.path.trim_start_matches("/repos/hagezi/dns-blocklists/");
                if rest == "commits" {
                    return Reply::ok(serde_json::to_string(&r.commits).unwrap())
                        .header("content-type", "application/json");
                }
                if let Some(sha) = rest.strip_prefix("git/trees/") {
                    let recursive = s.query.as_deref().is_some_and(|q| q.contains("recursive=1"));
                    // Find the commit and directory this sha names.
                    for (commit, files) in &r.trees {
                        if sha == commit {
                            if recursive {
                                let all: Vec<serde_json::Value> = if r.truncated {
                                    dir_entries(files, commit, "")
                                } else {
                                    files
                                        .iter()
                                        .map(|(p, b)| json!({"path": p, "type": "blob", "mode": "100644", "sha": blob_sha(b)}))
                                        .collect()
                                };
                                return Reply::ok(json!({"sha": sha, "tree": all, "truncated": r.truncated}).to_string())
                                    .header("content-type", "application/json");
                            }
                            return Reply::ok(json!({"sha": sha, "tree": dir_entries(files, commit, ""), "truncated": false}).to_string())
                                .header("content-type", "application/json");
                        }
                        let dirs: std::collections::BTreeSet<String> = files
                            .keys()
                            .flat_map(|p| {
                                let segs: Vec<&str> = p.split('/').collect();
                                (1..segs.len()).map(move |i| segs[..i].join("/")).collect::<Vec<_>>()
                            })
                            .collect();
                        for d in dirs {
                            if tree_sha(commit, &d) == sha {
                                return Reply::ok(json!({"sha": sha, "tree": dir_entries(files, commit, &d), "truncated": false}).to_string())
                                    .header("content-type", "application/json");
                            }
                        }
                    }
                    return Reply::status(404);
                }
                let path = rest.trim_start_matches("contents/").to_string();
                let q = s.query.clone().unwrap_or_default();
                let commit = q.trim_start_matches("ref=").to_string();
                match r.trees.get(&commit).and_then(|t| t.get(&path)) {
                    Some(b) => Reply::ok(json!({"type": "file", "sha": blob_sha(b), "size": b.len(), "content": ""}).to_string())
                        .header("content-type", "application/json"),
                    None => Reply::status(404),
                }
            }
            "raw.githubusercontent.com" => {
                let rest = s.path.trim_start_matches("/hagezi/dns-blocklists/");
                let (commit, path) = rest.split_once('/').unwrap();
                match r.trees.get(commit).and_then(|t| t.get(path)) {
                    Some(b) if r.corrupt => Reply::ok(format!("{b}tampered\n")),
                    Some(b) => Reply::ok(b.clone()),
                    None => Reply::status(404),
                }
            }
            _ => Reply::status(404),
        }
    }
}

async fn fake() -> (TestServer, Arc<Mutex<Repo>>) {
    let repo = Arc::new(Mutex::new(Repo::default()));
    let srv = TestServer::start(
        &["github.com", "api.github.com", "raw.githubusercontent.com"],
        handler(repo.clone()),
    )
    .await;
    (srv, repo)
}

fn commit(sha: &str, date: &str, root: bool) -> serde_json::Value {
    let parents = if root { json!([]) } else { json!([{"sha": "p"}]) };
    json!({"sha": sha, "commit": {"committer": {"date": date}, "author": {"date": date}}, "parents": parents})
}

fn ctx(opts: &HttpOptions, dir: &std::path::Path, last_ok: Option<Timestamp>) -> Ctx {
    Ctx::new(Http::new(opts.clone()).unwrap(), "hagezi", dir, 1 << 20, Default::default()).with_now(Timestamp::now(), last_ok)
}

/// Sets the head to `head` with these files.
fn set(repo: &Arc<Mutex<Repo>>, head: &str, files: &[(&str, &str)]) {
    let mut r = repo.lock().unwrap();
    r.head = head.into();
    r.trees.insert(
        head.into(),
        files.iter().map(|(p, b)| (p.to_string(), b.to_string())).collect(),
    );
}

const H1: &str = "1111111111111111111111111111111111111111";
const H2: &str = "2222222222222222222222222222222222222222";
const H3: &str = "3333333333333333333333333333333333333333";

fn cfg() -> serde_json::Value {
    json!({"owner": "hagezi", "repo": "dns-blocklists", "token": "ghp_testtoken123"})
}

fn fc(file: &str, last: Option<&LastRun>) -> FileCheck {
    FileCheck {
        file: file.into(),
        last: last.cloned(),
    }
}

fn last_of(o: &Result<CheckOutcome, CheckError>, prev: Option<&LastRun>) -> LastRun {
    match o {
        Ok(CheckOutcome::Changed {
            updated_at,
            version,
            state,
            ..
        }) => LastRun {
            updated_at: *updated_at,
            version: version.clone(),
            state: state.clone(),
        },
        Ok(CheckOutcome::Unchanged { state: Some(s), .. }) => LastRun {
            state: s.clone(),
            ..prev.unwrap().clone()
        },
        Ok(CheckOutcome::Unchanged { state: None, .. }) => prev.unwrap().clone(),
        Err(e) => panic!("{e}"),
    }
}

fn kind(o: &Result<CheckOutcome, CheckError>) -> &'static str {
    match o {
        Ok(CheckOutcome::Changed { .. }) => "changed",
        Ok(CheckOutcome::Unchanged { method, .. }) => method,
        Err(CheckError::Missing) => "missing",
        Err(CheckError::RateLimited { .. }) => "rate_limited",
        Err(CheckError::Failed(_)) => "failed",
    }
}

/// Several feeds of one provider: one `ls-refs`, one tree (with the listing), then commits and a
/// download per changed file; a head move that changes one file downloads only that one; the
/// same head is one `ls-refs` and nothing else.
#[tokio::test]
async fn several_feeds_one_ls_refs_and_a_head_move_changing_one() {
    let (srv, repo) = fake().await;
    let d = tempfile::tempdir().unwrap();
    let opts = srv.http_options();
    let m = Module;
    set(
        &repo,
        H1,
        &[
            ("adblock/tif.txt", "||a.example^\n"),
            ("adblock/ultimate.txt", "||u.example^\n"),
            ("hosts/tif.txt", "0.0.0.0 a.example\n"),
        ],
    );
    repo.lock().unwrap().commits = vec![commit(H1, "2026-11-20T10:00:00Z", false)];
    let pc = m
        .check(&ctx(&opts, d.path(), None), &cfg(), None, &[fc("adblock/tif.txt", None), fc("adblock/ultimate.txt", None)], &["adblock/*.txt".into()])
        .await
        .unwrap();
    assert_eq!(pc.files.iter().map(|(_, r)| kind(r)).collect::<Vec<_>>(), vec!["changed", "changed"]);
    let listing = pc.listing.clone().unwrap();
    assert!(listing.whole);
    assert_eq!(listing.files.len(), 3, "every blob, whatever select says");
    assert_eq!(pc.state["listed_head"], H1);
    let seen = srv.seen();
    assert_eq!(seen.iter().filter(|s| s.host == "github.com").count(), 1, "one ls-refs");
    assert_eq!(seen.iter().filter(|s| s.path.contains("/git/trees/")).count(), 1, "one tree");
    let raw: Vec<&Seen> = seen.iter().filter(|s| s.host == "raw.githubusercontent.com").collect();
    assert_eq!(raw.len(), 2);
    assert!(raw.iter().all(|s| s.path.contains(H1)), "by commit, never by branch");
    for s in &seen {
        assert!(s.header("authorization").is_some(), "the token goes to {}", s.host);
    }
    let la = last_of(&pc.files[0].1, None);
    let lu = last_of(&pc.files[1].1, None);
    assert_eq!(la.state["head"], H1);
    assert_eq!(la.version, blob_sha("||a.example^\n"));
    let pstate = pc.state.clone();
    drop(pc);

    // The same head: one ls-refs, Unchanged for both, no listing.
    srv.clear();
    let pc = m
        .check(&ctx(&opts, d.path(), Some(Timestamp::now())), &cfg(), Some(&pstate), &[fc("adblock/tif.txt", Some(&la)), fc("adblock/ultimate.txt", Some(&lu))], &[])
        .await
        .unwrap();
    assert_eq!(pc.files.iter().map(|(_, r)| kind(r)).collect::<Vec<_>>(), vec!["ls-refs", "ls-refs"]);
    assert!(pc.listing.is_none());
    assert_eq!(srv.seen().len(), 1);

    // The head moves and changes only ultimate.txt: tif is Unchanged with the new head in its
    // state; ultimate is Changed with its exact commit times.
    srv.clear();
    let lo = Timestamp::now() - jiff::SignedDuration::from_hours(1);
    set(
        &repo,
        H2,
        &[
            ("adblock/tif.txt", "||a.example^\n"),
            ("adblock/ultimate.txt", "||u.example^\n||v.example^\n"),
            ("hosts/tif.txt", "0.0.0.0 a.example\n"),
        ],
    );
    let t_new = picket_api::time::format_secs(&(Timestamp::now() - jiff::SignedDuration::from_mins(5)));
    repo.lock().unwrap().commits = vec![commit(H2, &t_new, false), commit(H1, "2026-11-20T10:00:00Z", false)];
    let pc = m
        .check(&ctx(&opts, d.path(), Some(lo)), &cfg(), Some(&pstate), &[fc("adblock/tif.txt", Some(&la)), fc("adblock/ultimate.txt", Some(&lu))], &[])
        .await
        .unwrap();
    assert_eq!(pc.files.iter().map(|(_, r)| kind(r)).collect::<Vec<_>>(), vec!["tree", "changed"]);
    match &pc.files[1].1 {
        Ok(CheckOutcome::Changed { change_times, .. }) => {
            assert_eq!(change_times, &vec![ChangeTime::Exact(t_new.parse().unwrap())]);
        }
        o => panic!("{o:?}"),
    }
    let la2 = last_of(&pc.files[0].1, Some(&la));
    assert_eq!(la2.state["head"], H2);
    assert!(pc.listing.is_some(), "a head move lists again");
    let seen = srv.seen();
    assert_eq!(seen.iter().filter(|s| s.host == "raw.githubusercontent.com").count(), 1, "only the changed file");
    let q = seen.iter().find(|s| s.path.ends_with("/commits")).unwrap().query.clone().unwrap();
    assert!(q.contains(&format!("sha={H2}")) && q.contains("since=") && q.contains("path=adblock%2Fultimate.txt"), "{q}");
}

/// A feed left out of checks (staged, disabled or failing) still sees every change since its own
/// last run: judged against its own head, never the provider's (the #56 bug).
#[tokio::test]
async fn a_feed_left_out_catches_up_after_the_head_moved_on() {
    let (srv, repo) = fake().await;
    let d = tempfile::tempdir().unwrap();
    let opts = srv.http_options();
    let m = Module;
    set(&repo, H1, &[("a.txt", "a1\n"), ("b.txt", "b1\n")]);
    repo.lock().unwrap().commits = vec![commit(H1, "2026-11-20T10:00:00Z", false)];
    let pc = m
        .check(&ctx(&opts, d.path(), None), &cfg(), None, &[fc("a.txt", None), fc("b.txt", None)], &[])
        .await
        .unwrap();
    let (la, lb) = (last_of(&pc.files[0].1, None), last_of(&pc.files[1].1, None));
    let ps = pc.state.clone();
    drop(pc);
    // b changes at H2; a check covering only a (b was busy) sees the head move.
    set(&repo, H2, &[("a.txt", "a1\n"), ("b.txt", "b2\n")]);
    let pc = m
        .check(&ctx(&opts, d.path(), Some(Timestamp::now())), &cfg(), Some(&ps), &[fc("a.txt", Some(&la))], &[])
        .await
        .unwrap();
    let la2 = last_of(&pc.files[0].1, Some(&la));
    let ps2 = pc.state.clone();
    drop(pc);
    // H3 changes nothing for b; b is back in the check with its old (H1) state: Changed.
    set(&repo, H3, &[("a.txt", "a1\n"), ("b.txt", "b2\n"), ("c.txt", "c\n")]);
    let pc = m
        .check(&ctx(&opts, d.path(), Some(Timestamp::now())), &cfg(), Some(&ps2), &[fc("a.txt", Some(&la2)), fc("b.txt", Some(&lb))], &[])
        .await
        .unwrap();
    assert_eq!(pc.files.iter().map(|(_, r)| kind(r)).collect::<Vec<_>>(), vec!["tree", "changed"]);
    match &pc.files[1].1 {
        Ok(CheckOutcome::Changed { file, .. }) => assert_eq!(std::fs::read_to_string(file.path()).unwrap(), "b2\n"),
        o => panic!("{o:?}"),
    }
}

/// The commits query's `since` is a stored `updated_at` minus a day: it saturates, so a time at
/// the start of the timestamp range still checks. (Such a time can't be read back from storage
/// any more, since the strict RFC 3339 reader takes years 0000 to 9999 only; this guards the sum.
/// The range's end can't overflow here: the sum subtracts.)
#[tokio::test]
async fn a_last_run_at_the_range_start_still_checks() {
    let (srv, repo) = fake().await;
    let d = tempfile::tempdir().unwrap();
    let opts = srv.http_options();
    let m = Module;
    set(&repo, H1, &[("a.txt", "a1\n")]);
    repo.lock().unwrap().commits = vec![commit(H1, "2026-11-20T10:00:00Z", false)];
    let pc = m.check(&ctx(&opts, d.path(), None), &cfg(), None, &[fc("a.txt", None)], &[]).await.unwrap();
    let la = last_of(&pc.files[0].1, None);
    let ps = pc.state.clone();
    drop(pc);
    set(&repo, H2, &[("a.txt", "a2\n")]);
    repo.lock().unwrap().commits = vec![commit(H2, "2026-11-21T10:00:00Z", false)];
    let last = LastRun { updated_at: Timestamp::MIN, ..la };
    let pc = m.check(&ctx(&opts, d.path(), None), &cfg(), Some(&ps), &[fc("a.txt", Some(&last))], &[]).await.unwrap();
    assert_eq!(kind(&pc.files[0].1), "changed");
}

/// A truncated tree is walked without `recursive`, only into directories a `select` pattern or
/// a feed's path reaches, within the budget: a listing limited to what `select` reaches.
#[tokio::test]
async fn a_truncated_tree_walked_within_its_budget() {
    let (srv, repo) = fake().await;
    let d = tempfile::tempdir().unwrap();
    let opts = srv.http_options();
    let mut files: Vec<(String, String)> = vec![
        ("adblock/tif.txt".into(), "||a.example^\n".into()),
        ("adblock/pro.txt".into(), "||p.example^\n".into()),
        ("lists/x/list.json".into(), "{}".into()),
    ];
    // Many directories `select` doesn't reach: never walked.
    for i in 0..200 {
        files.push((format!("other{i}/f.txt"), "x\n".into()));
    }
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    set(&repo, H1, &refs);
    repo.lock().unwrap().truncated = true;
    repo.lock().unwrap().commits = vec![commit(H1, "2026-11-20T10:00:00Z", false)];
    let pc = Module
        .check(&ctx(&opts, d.path(), None), &cfg(), None, &[fc("lists/x/list.json", None)], &["adblock/*.txt".into()])
        .await
        .unwrap();
    assert_eq!(kind(&pc.files[0].1), "changed", "the feed's path is reached");
    let l = pc.listing.clone().expect("a listing limited to what select reaches");
    assert!(!l.whole);
    assert!(l.files.contains(&"adblock/tif.txt".to_string()) && l.files.contains(&"adblock/pro.txt".to_string()));
    assert!(!l.files.iter().any(|f| f.starts_with("other")), "unreachable directories aren't walked");
    let trees = srv.seen().iter().filter(|s| s.path.contains("/git/trees/")).count();
    assert!(trees <= 1 + WALK_BUDGET, "{trees}");
    assert!(srv.seen().iter().all(|s| !s.path.contains("/contents/")), "no contents call needed");
}

/// A walk that can't finish within the budget gives no listing and reports it; the feeds'
/// files are resolved with the contents API instead (and a partial listing never makes a file
/// `Missing`: a 404 does).
#[tokio::test]
async fn a_truncated_tree_that_cant_be_walked() {
    let (srv, repo) = fake().await;
    let d = tempfile::tempdir().unwrap();
    let opts = srv.http_options();
    let mut files: Vec<(String, String)> = vec![("lists/keep/list.json".into(), "{\"k\": 1}".into())];
    for i in 0..80 {
        files.push((format!("lists/l{i}/list.json"), "{}".into()));
    }
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    set(&repo, H1, &refs);
    repo.lock().unwrap().truncated = true;
    let c = ctx(&opts, d.path(), None);
    let pc = Module
        .check(&c, &cfg(), None, &[fc("lists/keep/list.json", None), fc("lists/gone/list.json", None)], &["lists/*/list.json".into()])
        .await
        .unwrap();
    assert!(pc.listing.is_none(), "a walk that can't finish gives no listing");
    assert!(c.take_listing_incomplete().is_some(), "and says so");
    assert_eq!(pc.state.get("listed_head"), None, "the next check lists again");
    assert_eq!(pc.files.iter().map(|(_, r)| kind(r)).collect::<Vec<_>>(), vec!["changed", "missing"]);
    assert!(srv.seen().iter().any(|s| s.path.contains("/contents/")));
}

/// Q2 (README §2 Bounded; providers.md §3): a walk keeps each file's full path, so it charges
/// every path it keeps to its byte budget: a directory with a long path holding many files that
/// fit every per-answer limit gives no listing once the paths pass the budget, instead of
/// building them all in RAM.
#[tokio::test]
async fn a_walk_charges_the_paths_it_keeps() {
    let (srv, repo) = fake().await;
    let d = tempfile::tempdir().unwrap();
    let opts = srv.http_options();
    let dir = "d".repeat(1000);
    let n = (MAX_WALK_BYTES as usize) / 1000 + 2000;
    let mut files: Vec<(String, String)> = vec![("lists/a.txt".into(), "a.example\n".into())];
    for i in 0..n {
        files.push((format!("{dir}/f{i:06}.txt"), "x\n".into()));
    }
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    set(&repo, H1, &refs);
    repo.lock().unwrap().truncated = true;
    let c = ctx(&opts, d.path(), None);
    let pc = Module
        .check(&c, &cfg(), None, &[], &["**/*.txt".into()])
        .await
        .unwrap();
    let trees = srv.seen().iter().filter(|s| s.path.contains("/git/trees/")).count();
    assert!(trees <= 4, "the answers fit every limit: {trees} requests");
    assert!(
        pc.listing.is_none(),
        "{} paths kept past the walk's byte budget",
        pc.listing.as_ref().map_or(0, |l| l.files.len())
    );
    assert!(c.take_listing_incomplete().is_some());
}

/// Q2: a path longer than a repository path may be ([`check_path`], which a feed's `file` must
/// pass) is never kept, and the walk doesn't descend where every path would be longer: nested
/// directories with long names don't make it build paths of many KiB.
#[tokio::test]
async fn a_walk_keeps_no_path_longer_than_a_file_path() {
    let (srv, repo) = fake().await;
    let d = tempfile::tempdir().unwrap();
    let opts = srv.http_options();
    let seg = "s".repeat(250);
    let deep: Vec<String> = (1..=40).map(|k| vec![seg.as_str(); k].join("/")).collect();
    let mut files: Vec<(String, String)> = vec![("lists/a.txt".into(), "a.example\n".into())];
    for p in &deep {
        files.push((format!("{p}/f.txt"), "x\n".into()));
    }
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    set(&repo, H1, &refs);
    repo.lock().unwrap().truncated = true;
    let pc = Module
        .check(&ctx(&opts, d.path(), None), &cfg(), None, &[], &["**/*.txt".into()])
        .await
        .unwrap();
    let l = pc.listing.expect("the walk of what a file path can reach finishes");
    assert!(l.files.contains(&"lists/a.txt".to_string()));
    let longest = l.files.iter().map(String::len).max().unwrap_or(0);
    assert!(longest <= 1024, "a kept path of {longest} bytes");
    assert!(l.files.iter().all(|f| check_path(f).is_ok()));
    let trees = srv.seen().iter().filter(|s| s.path.contains("/git/trees/")).count();
    // The recursive answer, the root, `lists` and the four levels a file path can reach.
    assert!(trees <= 3 + 4, "{trees} tree requests: no descent past a file path's length");
}

/// A file deleted from the repository is `Missing` (absent from a complete tree).
#[tokio::test]
async fn a_deleted_file_is_missing() {
    let (srv, repo) = fake().await;
    let d = tempfile::tempdir().unwrap();
    let opts = srv.http_options();
    set(&repo, H1, &[("a.txt", "a\n"), ("b.txt", "b\n")]);
    repo.lock().unwrap().commits = vec![commit(H1, "2026-11-20T10:00:00Z", false)];
    let pc = Module
        .check(&ctx(&opts, d.path(), None), &cfg(), None, &[fc("a.txt", None), fc("b.txt", None)], &[])
        .await
        .unwrap();
    let (la, lb) = (last_of(&pc.files[0].1, None), last_of(&pc.files[1].1, None));
    let ps = pc.state.clone();
    drop(pc);
    set(&repo, H2, &[("a.txt", "a\n")]);
    let pc = Module
        .check(&ctx(&opts, d.path(), Some(Timestamp::now())), &cfg(), Some(&ps), &[fc("a.txt", Some(&la)), fc("b.txt", Some(&lb))], &[])
        .await
        .unwrap();
    assert_eq!(pc.files.iter().map(|(_, r)| kind(r)).collect::<Vec<_>>(), vec!["tree", "missing"]);
    assert_eq!(pc.listing.unwrap().files, vec!["a.txt".to_string()]);
}

#[tokio::test]
async fn blob_mismatch_and_rate_limits() {
    let (srv, repo) = fake().await;
    let d = tempfile::tempdir().unwrap();
    let opts = srv.http_options();
    set(&repo, H1, &[("adblock/tif.txt", "||a.example^\n")]);
    repo.lock().unwrap().corrupt = true;
    let pc = Module
        .check(&ctx(&opts, d.path(), None), &cfg(), None, &[fc("adblock/tif.txt", None)], &[])
        .await
        .unwrap();
    let e = pc.files[0].1.as_ref().unwrap_err();
    assert!(e.to_string().contains("blob hash"), "{e}");
    drop(pc);
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);

    repo.lock().unwrap().rate_limit = Some(Reply::status(429).header("retry-after", "120"));
    match Module
        .check(&ctx(&opts, d.path(), None), &cfg(), None, &[fc("adblock/tif.txt", None)], &[])
        .await
    {
        Err(CheckError::RateLimited { until }) => {
            let secs = (until - Timestamp::now()).as_secs();
            assert!((100..=121).contains(&secs), "{secs}");
        }
        o => panic!("{o:?}"),
    }
    let reset = (Timestamp::now() + jiff::SignedDuration::from_hours(5)).as_second();
    repo.lock().unwrap().rate_limit = Some(
        Reply::status(403)
            .header("x-ratelimit-remaining", "0")
            .header("x-ratelimit-reset", &reset.to_string()),
    );
    match Module.check(&ctx(&opts, d.path(), None), &cfg(), None, &[], &[]).await {
        Err(CheckError::RateLimited { until }) => {
            // A valid deadline past an hour is kept whole (issue #65), not cut to an hour.
            let want = Timestamp::from_second(reset).unwrap();
            assert_eq!(until, want, "the reset time, 5 h away");
        }
        o => panic!("{o:?}"),
    }
    // A reset beyond the longest cooldown honoured is held to it.
    let far = (Timestamp::now() + jiff::SignedDuration::from_hours(24 * 30)).as_second();
    repo.lock().unwrap().rate_limit = Some(
        Reply::status(403)
            .header("x-ratelimit-remaining", "0")
            .header("x-ratelimit-reset", &far.to_string()),
    );
    match Module.check(&ctx(&opts, d.path(), None), &cfg(), None, &[], &[]).await {
        Err(CheckError::RateLimited { until }) => {
            let max = Timestamp::now() + crate::modules::download::dates::MAX_COOLDOWN;
            assert!(until <= max && until > max - jiff::SignedDuration::from_mins(1), "{until}");
        }
        o => panic!("{o:?}"),
    }
    repo.lock().unwrap().rate_limit = Some(Reply::status(403));
    assert!(matches!(
        Module.check(&ctx(&opts, d.path(), None), &cfg(), None, &[], &[]).await,
        Err(CheckError::Failed(_))
    ));
}

#[tokio::test]
async fn history_skips_root_commits() {
    let (srv, repo) = fake().await;
    let d = tempfile::tempdir().unwrap();
    let now = Timestamp::now();
    let t = |h: i64| picket_api::time::format_secs(&(now - jiff::SignedDuration::from_hours(h)));
    repo.lock().unwrap().commits = vec![commit("a", &t(1), false), commit("b", &t(7), false), commit("c", &t(30), true)];
    let h = Module
        .history(&ctx(&srv.http_options(), d.path(), None), &cfg(), "adblock/tif.txt")
        .await
        .unwrap();
    assert_eq!(h.len(), 2, "{h:?}");
    let q = srv.seen()[0].query.clone().unwrap();
    assert!(q.contains("path=adblock%2Ftif.txt"), "{q}");
}

#[tokio::test]
async fn the_default_branch_is_resolved_with_ls_refs() {
    let (srv, repo) = fake().await;
    set(&repo, H1, &[]);
    let http = Http::new(srv.http_options()).unwrap();
    assert_eq!(default_branch(&http, "hagezi", "dns-blocklists", None).await.unwrap(), "main");
}

#[test]
fn url_forms() {
    let u = parse_url("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt").unwrap();
    assert_eq!(
        (u.owner.as_str(), u.repo.as_str(), u.branch.as_deref(), u.path.as_str()),
        ("hagezi", "dns-blocklists", Some("main"), "adblock/tif.txt")
    );
    assert!(u.notice.is_none());
    let u = parse_url("https://raw.githubusercontent.com/o/r/refs/heads/dev/a/b.txt").unwrap();
    assert_eq!((u.branch.as_deref(), u.path.as_str()), (Some("dev"), "a/b.txt"));
    let u = parse_url("https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt").unwrap();
    assert_eq!((u.branch, u.path.as_str()), (None, "adblock/tif.txt"));
    assert!(u.notice.unwrap().contains("12 hours"));
    assert!(parse_url("https://cdn.jsdelivr.net/gh/o/r@1.2.3/a.txt").unwrap_err().contains("tags"));
    assert!(parse_url("https://o.github.io/list.txt").unwrap_err().contains("http module"));
    let u = parse_url("https://github.com/o/r/blob/main/lists/a.txt").unwrap();
    assert_eq!((u.branch.as_deref(), u.path.as_str()), (Some("main"), "lists/a.txt"));
    assert!(parse_url("https://github.com/o/r").is_err());
    assert!(parse_url("http://raw.githubusercontent.com/o/r/main/a").is_err());
    assert!(parse_url("https://raw.githubusercontent.com/o/r/1111111111111111111111111111111111111111/a").is_err());
}

#[test]
fn config_checks() {
    let m = Module;
    assert!(m.normalize_config(&json!({"owner": "o", "repo": "r"})).is_ok());
    assert!(m.normalize_config(&json!({"owner": "o", "repo": "r", "branch": "gh-pages", "token": "${secret:gh}"})).is_ok());
    assert!(m.normalize_config(&json!({"owner": "o"})).is_err());
    assert!(m.normalize_config(&json!({"owner": "o", "repo": "r", "branch": "a..b"})).is_err());
    assert!(m.normalize_config(&json!({"owner": "o", "repo": "r", "token": "ghp_literal"})).is_err());
    assert!(m.normalize_config(&json!({"owner": "o", "repo": "r", "path": "x"})).is_err(), "files name paths, not the config");
    assert_eq!(m.location(&json!({"owner": "HaGeZi", "repo": "DNS-Blocklists"})), "https://github.com/hagezi/dns-blocklists/");
    assert_ne!(
        m.epoch_key(&json!({"owner": "o", "repo": "r"})),
        m.epoch_key(&json!({"owner": "o", "repo": "r", "branch": "dev"})),
        "another branch points elsewhere"
    );
    assert!(m.lists_files());
    assert!(m.check_file(&json!({}), "adblock/*.txt", true).is_ok());
    assert!(m.check_file(&json!({}), "../x", false).is_err());
}

#[test]
fn api_answers() {
    assert!(parse_blob_sha(br#"[{"type": "file"}]"#).unwrap_err().contains("directory"));
    assert_eq!(
        parse_blob_sha(br#"{"type": "file", "sha": "ABCDEF0123456789ABCDEF0123456789ABCDEF01"}"#).unwrap(),
        "abcdef0123456789abcdef0123456789abcdef01"
    );
    assert!(parse_blob_sha(b"nope").is_err());
    assert!(parse_commits(b"{}").is_err());
    let c = parse_commits(br#"[{"commit": {"committer": {"date": "2026-01-01T00:00:00Z"}}, "parents": []}, {"commit": {}}]"#).unwrap();
    assert_eq!(c.len(), 1);
    assert!(c[0].root);
    let sha = "1111111111111111111111111111111111111111";
    let t = parse_tree(
        format!(
            r#"{{"sha": "x", "truncated": true, "tree": [
                {{"path": "a.txt", "type": "blob", "mode": "100644", "sha": "{sha}"}},
                {{"path": "link", "type": "blob", "mode": "120000", "sha": "{sha}"}},
                {{"path": "sub", "type": "commit", "mode": "160000", "sha": "{sha}"}},
                {{"path": "dir", "type": "tree", "mode": "040000", "sha": "{sha}"}},
                {{"path": "../evil", "type": "blob", "mode": "100644", "sha": "{sha}"}},
                {{"path": "bad", "type": "blob", "mode": "100644", "sha": "zz"}}]}}"#
        )
        .as_bytes(),
    )
    .unwrap();
    assert!(t.truncated);
    let names: Vec<(&str, bool)> = t.entries.iter().map(|e| (e.path.as_str(), e.dir)).collect();
    assert_eq!(names, vec![("a.txt", false), ("dir", true)], "symlinks, submodules and bad entries left out");
    assert!(parse_tree(b"{}").is_err());
}

/// Z2 (feeds.md §3, providers.md §3): a selection edit ends the wait after a walk that couldn't
/// finish, unless the whole listing kept is for the head the walk failed at.
#[test]
fn a_selection_edit_ends_a_failed_walks_wait_unless_the_listing_is_for_that_head() {
    let m = Module;
    let at = Timestamp::now();
    let state = |listed: Option<&str>, failed: Option<&str>| {
        serde_json::to_value(ProviderState {
            listed_head: listed.map(str::to_string),
            walk_failed: failed.map(|h| WalkFailed { head: h.into(), at }),
        })
        .unwrap()
    };
    let cleared = m
        .state_for_selection_edit(&state(Some("a"), Some("b")))
        .expect("the wait ends");
    let s: ProviderState = serde_json::from_value(cleared).unwrap();
    assert_eq!(s.listed_head.as_deref(), Some("a"), "the listing's head is kept");
    assert!(s.walk_failed.is_none());
    assert!(m.state_for_selection_edit(&state(Some("b"), Some("b"))).is_none());
    assert!(m.state_for_selection_edit(&state(Some("a"), None)).is_none());
    assert!(m.state_for_selection_edit(&state(None, Some("b"))).is_some());
}
