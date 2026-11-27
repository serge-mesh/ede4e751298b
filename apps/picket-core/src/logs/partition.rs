//! Hourly query-log partitions `logs/YYYY-MM-DDTHH.db` (storage.md §2, §3, §5).
//!
//! Partitions are never migrated: each keeps the log schema it was created with, and a new one
//! gets the running release's ([`LOG_SCHEMA`]). Log schema changes only add tables and nullable
//! or defaulted columns, so any release reads and writes any partition by the columns both know:
//! a table or column the partition lacks reads as empty or its default, and writes leave it out
//! ([`Partition::insert`], [`Partition::select_list`]). A newer partition is never a reason to
//! exit.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use jiff::tz::Offset;
use jiff::{Timestamp, civil};
use rusqlite::{Connection, ToSql};

pub const LOGS_DIR: &str = "logs";

/// The log schema version of partitions this release creates (`PRAGMA user_version`).
pub const LOG_SCHEMA_VERSION: u32 = 3;

/// The log schema, version 3: version 1, plus `events.reason_json` and `events.edns_json` (v2:
/// the whole `reason`, with the deciding value and `cold`, and the client's OPT; api.md §5), plus
/// `events.cold_check` (v3: the result of core's check of the record's unchecked cold lookups,
/// core.md §6) and the index on `bundle` the tiering dry run reads a bundle's blocks by
/// (bundles.md §2; a partition without it is scanned). Core's progress through a partition (the
/// analysis, retro-match) is kept in core.db, never here, so it works on partitions of every
/// version. Later versions only add tables and nullable or defaulted columns.
pub const LOG_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    edge_id TEXT NOT NULL,
    boot TEXT NOT NULL,
    seq INTEGER NOT NULL,
    ts TEXT NOT NULL,
    version_set INTEGER,
    listener TEXT,
    proto TEXT,
    client_ip TEXT,
    device TEXT,
    profile TEXT,
    qname TEXT,
    qtype TEXT,
    rcode TEXT,
    decision TEXT,
    step INTEGER,
    bundle TEXT,
    rule_key TEXT,
    match_kind TEXT,
    stage TEXT,
    block_id TEXT,
    answers_json TEXT,
    targets_json TEXT,
    truncated INTEGER NOT NULL DEFAULT 0,
    response BLOB,
    tc INTEGER NOT NULL DEFAULT 0,
    answer_id TEXT,
    received_at TEXT,
    age_s INTEGER,
    answer_missing INTEGER NOT NULL DEFAULT 0,
    wire_check TEXT,
    trial_check TEXT,
    client_do INTEGER,
    cname_json TEXT,
    lookups_json TEXT,
    cold_unchecked_json TEXT,
    upstream_json TEXT,
    fw_json TEXT,
    timings_json TEXT,
    reason_json TEXT,
    edns_json TEXT,
    cold_check TEXT,
    PRIMARY KEY (edge_id, boot, seq)
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_qname ON events(qname);
CREATE INDEX IF NOT EXISTS events_client_ip ON events(client_ip);
CREATE INDEX IF NOT EXISTS events_device ON events(device);
CREATE INDEX IF NOT EXISTS events_decision ON events(decision);
CREATE INDEX IF NOT EXISTS events_bundle ON events(bundle) WHERE bundle IS NOT NULL;

CREATE TABLE IF NOT EXISTS answers (
    id TEXT PRIMARY KEY,
    wire BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS answered_names (
    qname TEXT NOT NULL,
    profile TEXT NOT NULL,
    PRIMARY KEY (qname, profile)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS answered_ips (
    ip TEXT NOT NULL,
    profile TEXT NOT NULL,
    PRIMARY KEY (ip, profile)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS attribution (
    edge_id TEXT NOT NULL,
    boot TEXT NOT NULL,
    seq INTEGER NOT NULL,
    matches_json TEXT,
    status TEXT NOT NULL,
    PRIMARY KEY (edge_id, boot, seq)
);

CREATE TABLE IF NOT EXISTS would_blocks (
    edge_id TEXT NOT NULL,
    boot TEXT NOT NULL,
    seq INTEGER NOT NULL,
    bundle_id TEXT NOT NULL,
    head_id TEXT NOT NULL,
    key TEXT,
    stage TEXT,
    matches_json TEXT,
    status TEXT,
    PRIMARY KEY (edge_id, boot, seq, bundle_id)
);
CREATE INDEX IF NOT EXISTS would_blocks_bundle ON would_blocks(bundle_id);

CREATE TABLE IF NOT EXISTS version_sets (
    id INTEGER PRIMARY KEY,
    blake3 TEXT NOT NULL UNIQUE,
    versions_json TEXT NOT NULL
);
"#;

/// The file name of the partition holding `t`'s hour (UTC).
pub fn partition_file_name(t: &Timestamp) -> String {
    format!("{}.db", t.strftime("%Y-%m-%dT%H"))
}

/// The key of `t`'s hour in core.db's per-partition tables (`log_progress.hour`): the
/// partition's file stem, `YYYY-MM-DDTHH` (UTC).
pub fn hour_key(t: &Timestamp) -> String {
    t.strftime("%Y-%m-%dT%H").to_string()
}

/// The hour a `log_progress.hour` key stands for.
pub fn parse_hour_key(key: &str) -> Option<Timestamp> {
    parse_partition_name(&format!("{key}.db"))
}

/// The hour a partition file name stands for, if it is one.
pub fn parse_partition_name(name: &str) -> Option<Timestamp> {
    let stem = name.strip_suffix(".db")?;
    if stem.len() != 13 {
        return None;
    }
    let dt = civil::DateTime::strptime("%Y-%m-%dT%H:%M:%S", format!("{stem}:00:00")).ok()?;
    Offset::UTC.to_timestamp(dt).ok()
}

/// The start of `t`'s hour.
pub fn hour_start(t: &Timestamp) -> Timestamp {
    // Truncated in whole seconds: `Timestamp::round` would round half up (11:42 → 12:00).
    let s = t.as_second();
    Timestamp::from_second(s - s.rem_euclid(3600)).unwrap_or(*t)
}

/// The directory of partitions.
#[derive(Clone, Debug)]
pub struct LogStore {
    dir: PathBuf,
}

impl LogStore {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            dir: data_dir.join(LOGS_DIR),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path_for(&self, hour: &Timestamp) -> PathBuf {
        self.dir.join(partition_file_name(hour))
    }

    /// Opens the partition for `hour`, creating it with this release's schema when `create` is
    /// set and it doesn't exist. `None` when it doesn't exist and `create` is off.
    pub fn open(&self, hour: &Timestamp, create: bool) -> Result<Option<Partition>> {
        let path = self.path_for(hour);
        if !path.exists() && !create {
            return Ok(None);
        }
        crate::util::ensure_dir(&self.dir)?;
        Partition::open(&path).map(Some)
    }

    /// Every partition file, oldest first.
    pub fn list(&self) -> Result<Vec<(Timestamp, PathBuf)>> {
        let mut out = Vec::new();
        let rd = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for ent in rd {
            let ent = ent?;
            let name = ent.file_name().to_string_lossy().into_owned();
            if let Some(h) = parse_partition_name(&name) {
                out.push((h, ent.path()));
            }
        }
        out.sort();
        Ok(out)
    }

    /// Deletes a whole partition with its WAL and SHM (retention, storage.md §4).
    pub fn delete(&self, hour: &Timestamp) -> Result<()> {
        let path = self.path_for(hour);
        for p in [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            match std::fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("remove {}", p.display())),
            }
        }
        Ok(())
    }
}

/// One open partition with its column map.
pub struct Partition {
    pub conn: Connection,
    /// The partition's log schema version (any; newer is fine).
    pub schema_version: u32,
    columns: HashMap<String, BTreeSet<String>>,
}

impl Partition {
    /// Opens (or creates) a partition file: WAL, `synchronous=FULL` (a batch is durable before
    /// it is acked, storage.md §2). A new file gets [`LOG_SCHEMA`].
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            bail!("{} refused WAL mode", path.display());
        }
        conn.execute_batch("PRAGMA synchronous = FULL; PRAGMA cache_size = -4096;")?;
        let tables: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
            [],
            |r| r.get(0),
        )?;
        if tables == 0 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(LOG_SCHEMA)?;
            tx.pragma_update(None, "user_version", LOG_SCHEMA_VERSION)?;
            tx.commit()?;
        }
        let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let mut p = Self {
            conn,
            schema_version: u32::try_from(v).unwrap_or(0),
            columns: HashMap::new(),
        };
        p.refresh_columns()?;
        Ok(p)
    }

    /// Re-reads the partition's tables and columns.
    pub fn refresh_columns(&mut self) -> Result<()> {
        self.columns.clear();
        let tables: Vec<String> = {
            let mut st = self
                .conn
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?;
            st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
        };
        for t in tables {
            let cols = table_columns(&self.conn, &t)?;
            self.columns.insert(t, cols);
        }
        Ok(())
    }

    pub fn has_table(&self, table: &str) -> bool {
        self.columns.contains_key(table)
    }

    pub fn has_column(&self, table: &str, column: &str) -> bool {
        self.columns.get(table).is_some_and(|c| c.contains(column))
    }

    /// The columns of `table` this partition holds.
    pub fn columns(&self, table: &str) -> Option<&BTreeSet<String>> {
        self.columns.get(table)
    }

    /// Inserts a row, writing only the columns the partition knows; the others are left out
    /// (storage.md §5). Returns `Ok(false)` when the partition lacks the table.
    pub fn insert(
        &self,
        table: &str,
        values: &[(&str, &dyn ToSql)],
        or_ignore: bool,
    ) -> rusqlite::Result<bool> {
        let Some(cols) = self.columns.get(table) else {
            return Ok(false);
        };
        let known: Vec<&(&str, &dyn ToSql)> = values.iter().filter(|(c, _)| cols.contains(*c)).collect();
        if known.is_empty() {
            return Ok(false);
        }
        let names: Vec<String> = known.iter().map(|(c, _)| quote_ident(c)).collect();
        let marks: Vec<String> = (1..=known.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "INSERT {}INTO {} ({}) VALUES ({})",
            if or_ignore { "OR IGNORE " } else { "" },
            quote_ident(table),
            names.join(", "),
            marks.join(", ")
        );
        let params: Vec<&dyn ToSql> = known.iter().map(|(_, v)| *v).collect();
        self.conn.prepare_cached(&sql)?.execute(params.as_slice())?;
        Ok(true)
    }

    /// A SELECT list for `wanted` columns of `table`: each column the partition lacks is
    /// replaced by its default (`NULL` unless given) under its own name, so callers read every
    /// partition alike.
    pub fn select_list(&self, table: &str, wanted: &[(&str, &str)]) -> String {
        wanted
            .iter()
            .map(|(col, default)| {
                if self.has_column(table, col) {
                    quote_ident(col)
                } else {
                    format!("{} AS {}", default, quote_ident(col))
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The column names of `table` (`PRAGMA table_info`).
pub fn table_columns(conn: &Connection, table: &str) -> Result<BTreeSet<String>> {
    let mut st = conn.prepare(&format!("PRAGMA table_info({})", quote_ident(table)))?;
    let cols = st
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(cols)
}

fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        let t = "2026-11-13T10:22:01Z".parse::<Timestamp>().unwrap();
        assert_eq!(partition_file_name(&t), "2026-11-13T10.db");
        assert_eq!(parse_partition_name("2026-11-13T10.db").unwrap(), hour_start(&t));
        assert!(parse_partition_name("2026-11-13T10.db-wal").is_none());
        assert!(parse_partition_name("core.db").is_none());
    }

    /// Golden (F5: partition file names and `log_progress.hour` keys; plan §5 step 1, unchanged
    /// after the move to jiff).
    #[test]
    fn golden_partition_names() {
        use picket_api::time::golden::{ROWS, ts_from_nanos};
        let f1 = picket_api::time::format_micros;
        for r in ROWS {
            let t = ts_from_nanos(r.nanos);
            let name = format!("{}.db", r.hour);
            assert_eq!(partition_file_name(&t), name, "{}", r.name);
            assert_eq!(hour_key(&t), r.hour, "{}", r.name);
            assert_eq!(f1(&hour_start(&t)), r.hour_start, "{}", r.name);
            assert_eq!(
                parse_partition_name(&name).as_ref().map(f1).as_deref(),
                Some(r.hour_start),
                "{}",
                r.name
            );
            assert_eq!(
                parse_hour_key(r.hour).as_ref().map(f1).as_deref(),
                Some(r.hour_start),
                "{}",
                r.name
            );
        }
        for name in [
            "2026-11-13T10",
            "2026-11-13T10.DB",
            "2026-11-13T10.db.db",
            "2026-11-13T1.db",
            "2026-11-13T100.db",
            "2026-11-13T24.db",
            "2026-02-30T00.db",
            "2026-11-13 10.db",
            "2026-11-13t10.db",
            "2026-11-13T+1.db",
            "2026_11_13T10.db",
            "x026-11-13T10.db",
            "20261-1-13T10.db",
        ] {
            assert_eq!(parse_partition_name(name), None, "{name}");
        }
    }

    #[test]
    fn create_insert_and_tolerate_other_schemas() {
        let d = tempfile::tempdir().unwrap();
        let store = LogStore::new(d.path());
        let hour = hour_start(&Timestamp::now());
        let p = store.open(&hour, true).unwrap().unwrap();
        assert_eq!(p.schema_version, LOG_SCHEMA_VERSION);
        assert!(p.has_column("events", "trial_check"));
        // A column a future release added is left out on write.
        let wrote = p
            .insert(
                "events",
                &[
                    ("edge_id", &"e-01"),
                    ("boot", &"b1"),
                    ("seq", &1i64),
                    ("ts", &"2026-11-13T10:22:01.000000Z"),
                    ("future_column", &"x"),
                ],
                false,
            )
            .unwrap();
        assert!(wrote);
        assert!(!p.insert("future_table", &[("a", &1i64)], false).unwrap());

        // An older partition without `trial_check` reads it as its default.
        let old = d.path().join("old.db");
        {
            let c = Connection::open(&old).unwrap();
            c.execute_batch(
                "CREATE TABLE events (edge_id TEXT, boot TEXT, seq INTEGER, ts TEXT); PRAGMA user_version = 0;",
            )
            .unwrap();
            c.execute("INSERT INTO events VALUES ('e', 'b', 1, 't')", [])
                .unwrap();
        }
        let op = Partition::open(&old).unwrap();
        assert!(!op.has_column("events", "trial_check"));
        let list = op.select_list("events", &[("seq", "0"), ("trial_check", "NULL")]);
        let (seq, tc): (i64, Option<String>) = op
            .conn
            .query_row(&format!("SELECT {list} FROM events"), [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(seq, 1);
        assert!(tc.is_none());
        // A newer partition is fine too.
        op.conn.execute_batch("PRAGMA user_version = 99").unwrap();
        assert_eq!(Partition::open(&old).unwrap().schema_version, 99);

        assert_eq!(store.list().unwrap().len(), 1);
        store.delete(&hour).unwrap();
        assert!(store.list().unwrap().is_empty());
    }
}
