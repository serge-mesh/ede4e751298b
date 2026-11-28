//! A fake of github.com (`ls-refs`), api.github.com (trees, contents, commits) and
//! raw.githubusercontent.com for one repository, `o/r`, whose head and files tests change. Any
//! other owner and repository answer the same (a preset's repository, say).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use picket_core::modules::download::testkit::{Reply, Seen, TestServer};
use serde_json::json;
use sha1::Digest as _;

pub const HOSTS: &[&str] = &["github.com", "api.github.com", "raw.githubusercontent.com"];

#[derive(Default)]
pub struct Repo {
    pub head: String,
    /// commit → (path → body).
    pub trees: BTreeMap<String, BTreeMap<String, String>>,
    /// Commits API items, newest first (any path).
    pub commits: Vec<serde_json::Value>,
    /// The recursive tree is truncated (and the walk's directories go past the budget).
    pub truncated: bool,
    /// With `truncated`: the walk can finish (each directory's own entries answer by its tree
    /// id, [`dir_tree_id`]).
    pub walkable: bool,
    /// Tree answers wait this long (a check in flight).
    pub slow_trees: Option<std::time::Duration>,
    /// Every answer is a 503 (GitHub down).
    pub down: bool,
}

pub fn blob_sha(body: &str) -> String {
    let mut h = sha1::Sha1::new();
    h.update(format!("blob {}\0", body.len()).as_bytes());
    h.update(body.as_bytes());
    hex::encode(h.finalize())
}

/// A commit id for the n-th head.
pub fn head(n: u32) -> String {
    format!("{n:040x}")
}

pub fn commit(date: &str, root: bool) -> serde_json::Value {
    let parents = if root { json!([]) } else { json!([{"sha": "p"}]) };
    json!({"sha": "c", "commit": {"committer": {"date": date}, "author": {"date": date}}, "parents": parents})
}

fn pkt(line: &str) -> String {
    format!("{:04x}{line}", line.len() + 4)
}

impl Repo {
    /// Moves the head to `n` with these files.
    pub fn set(&mut self, n: u32, files: &[(&str, &str)]) {
        self.head = head(n);
        self.trees.insert(
            self.head.clone(),
            files
                .iter()
                .map(|(p, b)| (p.to_string(), b.to_string()))
                .collect(),
        );
    }
}

/// `path` past its first `n` segments (`/repos/o/r/x/y`, 3: `x/y`).
fn past(path: &str, n: usize) -> &str {
    path.trim_start_matches('/')
        .splitn(n + 1, '/')
        .nth(n)
        .unwrap_or("")
}

fn handle(r: &Repo, s: &Seen) -> Reply {
    if r.down {
        return Reply::status(503);
    }
    match s.host.as_str() {
        "github.com" => {
            // `main` and `gh-pages` (a preset's branch) at the head.
            let answer = format!(
                "{}{}{}0000",
                pkt(&format!("{} HEAD symref-target:refs/heads/main\n", r.head)),
                pkt(&format!("{} refs/heads/gh-pages\n", r.head)),
                pkt(&format!("{} refs/heads/main\n", r.head))
            );
            Reply::ok(answer).header("content-type", "application/x-git-upload-pack-result")
        }
        "api.github.com" => {
            let rest = past(&s.path, 3);
            if rest == "commits" {
                return Reply::ok(serde_json::to_string(&r.commits).unwrap())
                    .header("content-type", "application/json");
            }
            if let Some(sha) = rest.strip_prefix("git/trees/") {
                if r.truncated && r.walkable {
                    let reply = walk_tree(r, sha, s.query.as_deref().unwrap_or("").contains("recursive=1"));
                    return match r.slow_trees {
                        Some(delay) => Reply {
                            status: reply.status,
                            headers: reply.headers.clone(),
                            body: picket_core::modules::download::testkit::ReplyBody::Slow {
                                chunk: match reply.body {
                                    picket_core::modules::download::testkit::ReplyBody::Bytes(b) => b,
                                    _ => bytes::Bytes::new(),
                                },
                                count: 1,
                                delay,
                            },
                        },
                        None => reply,
                    };
                }
                let Some(files) = r.trees.get(sha) else {
                    return if r.truncated {
                        // A subdirectory of a truncated tree: an empty directory with one more level,
                        // so the walk never finishes within its budget.
                        let sub: Vec<serde_json::Value> = (0..60)
                            .map(|i| json!({"path": format!("d{i}"), "type": "tree", "mode": "040000", "sha": format!("{:040x}", 0xdead0000u64 + i)}))
                            .collect();
                        Reply::ok(json!({"sha": sha, "tree": sub, "truncated": false}).to_string())
                            .header("content-type", "application/json")
                    } else {
                        Reply::status(404)
                    };
                };
                if r.truncated {
                    let root: Vec<serde_json::Value> = (0..60)
                        .map(|i| json!({"path": format!("d{i}"), "type": "tree", "mode": "040000", "sha": format!("{:040x}", 0xbeef0000u64 + i)}))
                        .collect();
                    return Reply::ok(json!({"sha": sha, "tree": root, "truncated": true}).to_string())
                        .header("content-type", "application/json");
                }
                let tree: Vec<serde_json::Value> = files
                    .iter()
                    .map(|(p, b)| json!({"path": p, "type": "blob", "mode": "100644", "sha": blob_sha(b)}))
                    .collect();
                return Reply::ok(json!({"sha": sha, "tree": tree, "truncated": false}).to_string())
                    .header("content-type", "application/json");
            }
            let path = rest.trim_start_matches("contents/").to_string();
            let q = s.query.clone().unwrap_or_default();
            let commit = q.trim_start_matches("ref=").to_string();
            match r.trees.get(&commit).and_then(|t| t.get(&path)) {
                Some(b) => Reply::ok(json!({"type": "file", "sha": blob_sha(b), "content": ""}).to_string())
                    .header("content-type", "application/json"),
                None => Reply::status(404),
            }
        }
        "raw.githubusercontent.com" => {
            let rest = past(&s.path, 2);
            let (commit, path) = rest.split_once('/').unwrap_or_default();
            match r.trees.get(commit).and_then(|t| t.get(path)) {
                Some(b) => Reply::ok(b.clone()),
                None => Reply::status(404),
            }
        }
        _ => Reply::status(404),
    }
}

/// The tree id the fake gives a directory of a commit.
pub fn dir_tree_id(commit: &str, dir: &str) -> String {
    let mut h = sha1::Sha1::new();
    h.update(format!("{commit}:{dir}").as_bytes());
    hex::encode(h.finalize())
}

/// One directory of a walkable truncated tree: the commit's id is its root, [`dir_tree_id`] a
/// directory; the root's recursive answer is truncated, every other answer complete.
fn walk_tree(r: &Repo, sha: &str, recursive: bool) -> Reply {
    let found = if r.trees.contains_key(sha) {
        Some((sha.to_string(), String::new()))
    } else {
        r.trees.iter().find_map(|(commit, files)| {
            files.keys().find_map(|p| {
                let segs: Vec<&str> = p.split('/').collect();
                (1..segs.len())
                    .map(|n| segs[..n].join("/"))
                    .find(|d| dir_tree_id(commit, d) == sha)
                    .map(|d| (commit.clone(), d))
            })
        })
    };
    let Some((commit, dir)) = found else {
        return Reply::status(404);
    };
    let files = &r.trees[&commit];
    let prefix = if dir.is_empty() {
        String::new()
    } else {
        format!("{dir}/")
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut tree = Vec::new();
    for (p, b) in files {
        let Some(rest) = p.strip_prefix(&prefix) else {
            continue;
        };
        match rest.split_once('/') {
            Some((sub, _)) => {
                if seen.insert(sub.to_string()) {
                    let full = format!("{prefix}{sub}");
                    tree.push(json!({"path": sub, "type": "tree", "mode": "040000",
                                     "sha": dir_tree_id(&commit, &full)}));
                }
            }
            None => tree.push(json!({"path": rest, "type": "blob", "mode": "100644", "sha": blob_sha(b)})),
        }
    }
    let truncated = recursive && dir.is_empty();
    Reply::ok(json!({"sha": sha, "tree": tree, "truncated": truncated}).to_string())
        .header("content-type", "application/json")
}

/// Starts the fake.
pub async fn fake() -> (TestServer, Arc<Mutex<Repo>>) {
    let repo = Arc::new(Mutex::new(Repo::default()));
    let r = repo.clone();
    let srv = TestServer::start(HOSTS, move |s: &Seen| handle(&r.lock().unwrap(), s)).await;
    (srv, repo)
}
