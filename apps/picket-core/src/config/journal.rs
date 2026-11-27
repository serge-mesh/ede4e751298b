//! The `config_changes` journal (storage.md §3): one row per change, with a redacted diff.
//! Secrets never appear (README §2): secret values aren't part of entities, and any config field
//! whose name looks like a credential is masked unless it only references a secret by name.

use anyhow::Result;
use rusqlite::Transaction;
use serde_json::{Map, Value};

use super::model::EntityKind;

const REDACTED: &str = "<redacted>";

/// Writes one journal row.
pub fn record(
    tx: &Transaction<'_>,
    source_ip: Option<&str>,
    source: &str,
    kind: EntityKind,
    id: &str,
    diff: &Value,
) -> Result<()> {
    let mut diff = redact(diff);
    if matches!(kind, EntityKind::Feed | EntityKind::LookupProvider) {
        // Provider configs get the strict rules (header maps, `*key` names: config::credentials).
        diff = super::credentials::mask(&diff);
    }
    if let Value::Object(m) = &mut diff {
        m.insert("source".into(), Value::String(source.into()));
    }
    tx.execute(
        "INSERT INTO config_changes(at, source_ip, entity, entity_id, diff_json) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            crate::util::now_ts(),
            source_ip,
            kind.as_str(),
            id,
            serde_json::to_string(&diff)?
        ],
    )?;
    Ok(())
}

/// The diff between two versions of an entity: `create`, `delete`, or `update` with the
/// changed top-level fields.
pub fn diff(before: Option<&Value>, after: Option<&Value>) -> Value {
    match (before, after) {
        (None, Some(a)) => serde_json::json!({"op": "create", "after": a}),
        (Some(b), None) => serde_json::json!({"op": "delete", "before": b}),
        (Some(b), Some(a)) => {
            let mut changes = Map::new();
            let empty = Map::new();
            let bm = b.as_object().unwrap_or(&empty);
            let am = a.as_object().unwrap_or(&empty);
            let mut keys: Vec<&String> = bm.keys().chain(am.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let (x, y) = (bm.get(k), am.get(k));
                if x != y {
                    changes.insert(
                        k.clone(),
                        serde_json::json!({"before": x.cloned().unwrap_or(Value::Null), "after": y.cloned().unwrap_or(Value::Null)}),
                    );
                }
            }
            serde_json::json!({"op": "update", "changes": changes})
        }
        (None, None) => serde_json::json!({"op": "none"}),
    }
}

/// True when a JSON key names a credential.
pub(crate) fn sensitive_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "api-key",
        "authorization",
        "bearer",
        "private_key",
        "credential",
        "cookie",
    ]
    .iter()
    .any(|s| k.contains(s))
}

/// True when `s` holds `${secret:name}` references and, besides them and an optional auth
/// scheme word (`Bearer`, `Basic`, `Token`), nothing that could be a credential.
pub(crate) fn only_secret_refs(s: &str) -> bool {
    if !s.contains("${secret:") {
        return false;
    }
    let mut rest = String::new();
    let mut cur = s;
    while let Some(i) = cur.find("${secret:") {
        rest.push_str(&cur[..i]);
        match cur[i..].find('}') {
            Some(j) => cur = &cur[i + j + 1..],
            None => return false,
        }
    }
    rest.push_str(cur);
    let rest = rest.trim();
    let rest = ["Bearer", "Basic", "Token"]
        .iter()
        .find_map(|w| rest.strip_prefix(w))
        .unwrap_or(rest);
    !rest.chars().any(char::is_alphanumeric)
}

/// Masks credential-looking fields, keeping `${secret:name}` references (names aren't secret).
/// Under a credential-looking key every value is masked, however deeply nested (a
/// `credentials` object or a `tokens` list hides all it holds), except pure references.
pub fn redact(v: &Value) -> Value {
    // Also credentials in values and URLs (`Bearer …`, `?apikey=…`), whatever the field's name.
    super::credentials::mask_generic(&walk(v, false))
}

fn walk(v: &Value, sensitive: bool) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, val)| {
                    let s = sensitive || (sensitive_key(k) && k != "secret_refs");
                    (k.clone(), walk(val, s))
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(|x| walk(x, sensitive)).collect()),
        Value::String(s) if sensitive && !only_secret_refs(s) => Value::String(REDACTED.into()),
        Value::Number(_) if sensitive => Value::String(REDACTED.into()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diffs() {
        let a = serde_json::json!({"x": 1, "y": 2});
        let b = serde_json::json!({"x": 1, "y": 3, "z": true});
        let d = diff(Some(&a), Some(&b));
        assert_eq!(d["op"], "update");
        assert!(d["changes"].get("x").is_none());
        assert_eq!(d["changes"]["y"]["after"], 3);
        assert_eq!(diff(None, Some(&a))["op"], "create");
    }

    #[test]
    fn redaction() {
        let v = serde_json::json!({
            "config": {"headers": {"Authorization": "Bearer abc123", "X-Api-Key": "${secret:am_rt}"}, "url": "https://x"},
            "token": "t0k3n",
            "password": null
        });
        let r = redact(&v);
        assert_eq!(r["config"]["headers"]["Authorization"], REDACTED);
        assert_eq!(r["config"]["headers"]["X-Api-Key"], "${secret:am_rt}");
        assert_eq!(r["config"]["url"], "https://x");
        assert_eq!(r["token"], REDACTED);
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("abc123") && !s.contains("t0k3n"));
    }

    #[test]
    fn redaction_covers_everything_under_a_credential_key() {
        let v = serde_json::json!({
            "credentials": {"user": "u1", "pass": "hunter2", "ref": "${secret:x}"},
            "tokens": ["abc", "def"],
            "cookie": "session=1",
            "headers": {"Cookie": "sid=2", "Accept": "application/json"},
            "api_key": 12345
        });
        let r = redact(&v);
        let s = serde_json::to_string(&r).unwrap();
        for leak in ["hunter2", "u1", "abc", "def", "session=1", "sid=2", "12345"] {
            assert!(!s.contains(leak), "{leak} leaked: {s}");
        }
        assert_eq!(r["credentials"]["ref"], "${secret:x}");
        assert_eq!(r["headers"]["Accept"], "application/json");
    }
}
