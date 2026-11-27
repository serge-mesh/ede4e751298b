//! Export and import of a feed's entries (feeds.md §4 "Export and import", api.md §7).
//!
//! - **Export** (`GET feeds/{id}/export`): `<feed id>.json` with the feed's settings (for a
//!   `misp-warninglist` feed, its list's `type` as `misp_type`), then each open entry as stored
//!   (`raw`, rule type, match kind, `first_seen_at`, `last_seen_at`), `entries` last, in order of
//!   `first_seen_at` and then `line_no`. **Export as file** (`?as=file`): the entries as a file
//!   in the feed's format: a line format with comment lines naming the feed and its settings,
//!   a `picket-first-seen` directive before each run of entries that share a date and
//!   `picket-first-seen: none` at the end; a `misp-warninglist` feed as a MISP list with a
//!   `picket_first_seen` map and a `picket_feed` object. Both are streamed from a dedicated
//!   read connection, never held in RAM.
//! - **Import** takes either export, or a plain list file, into a new manual feed, an existing
//!   manual feed (replacing or merging its file), or a provider feed (merging: an import run,
//!   [`super::ingest::Work::Import`]). Whatever comes in is written as one file in the target's
//!   format: a manual feed saves it like any save; a provider feed's import run keeps it as its
//!   blob. The body is spooled first (like a manual save) and parsed as it is read; the file it
//!   makes must fit the download size cap, the body 32 times the cap after decompression
//!   (`413`). Another format, `format_options` or MISP list `type`, or `replace` on a provider
//!   feed, is `422`; a taken id `409`; a stale `base_version` `409`. A new feed's settings come
//!   from the export; the query's `format`, `domains_as`, `category`, `warn_on` and `rule_policy`
//!   switches are the admin's picks for a plain list file or a bare MISP list, and one that
//!   differs from what an export declares is `422` naming the field ([`QuerySettings`]). A
//!   manual target's reply carries the file's `saved_at`. A provider feed holds at most
//!   [`MAX_WAITING_IMPORTS_PER_FEED`] accepted import waiting for its run, and waiting imports
//!   at most [`MAX_WAITING_IMPORT_CAPS`] download caps of blobs in all (README §2 Bounded): an
//!   import past either is `503`. Nothing changes on a refusal.

use std::io::{BufRead, Read};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use bytes::Bytes;
use rusqlite::OptionalExtension;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::body::{self, BodyError, ExportEntry, ImportBody};
use super::manual::{self, SaveError};
use crate::config::model::{
    Category, DomainsAs, FeedDef, FeedFormat, FormatOptions, Mode, ModeSpec, Modes, PolicyOption, RulePolicy,
};
use crate::config::{Actor, EntityKind, Op};
use crate::modules::download::ctx::{SyncStageWriter, stage_sync_in};
use crate::state::SharedState;

/// An import body may be this many times the download size cap after decompression (api.md §7).
pub const BODY_FACTOR: u64 = 32;
/// The longest `raw` line an import reads.
pub const MAX_LINE: usize = 64 * 1024;

/// The settings an export carries (feeds.md §4).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ExportSettings {
    pub id: String,
    pub name: String,
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub format: FeedFormat,
    pub format_options: FormatOptions,
    pub rule_policy: RulePolicy,
    pub category: Category,
    pub warn_on: Option<Vec<String>>,
    /// A `misp-warninglist` feed's list `type`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub misp_type: Option<String>,
}

impl ExportSettings {
    fn of(def: &FeedDef, misp_type: Option<String>) -> Self {
        Self {
            id: def.id.clone(),
            name: def.name.clone(),
            provider: def.provider.clone(),
            file: def.file.clone(),
            format: def.format,
            format_options: def.format_options.clone(),
            rule_policy: def.rule_policy.resolved(def.is_manual()),
            category: def.category,
            warn_on: def.warn_on.clone(),
            misp_type,
        }
    }
}

fn enum_str<T: Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(Value::String(s)) => s,
        _ => String::new(),
    }
}

/// The comment marker of a line format's directives and header (`#` for hosts).
pub fn comment(format: FeedFormat) -> &'static str {
    match format {
        FeedFormat::Hosts => "#",
        _ => "!",
    }
}

/// The list `type` of the run behind the feed's applied entries (its latest applied run; never a
/// held, rejected or expiry run), or of its newest run with a blob.
pub async fn misp_type_of(state: &SharedState, feed: &str) -> Option<String> {
    let f = feed.to_string();
    state
        .db
        .read(move |c| Ok::<_, anyhow::Error>(misp_type_in(c, &f)))
        .await
        .ok()
        .flatten()
}

/// [`misp_type_of`] on a connection (inside the caller's read transaction).
fn misp_type_in(c: &rusqlite::Connection, feed: &str) -> Option<String> {
    c.query_row(
        &format!(
            "SELECT {} FROM feed_runs WHERE feed_id = ?1 AND status = 'applied' ORDER BY id DESC LIMIT 1",
            super::store::RUN_COLUMNS
        ),
        [feed],
        super::store::row_to_run,
    )
    .ok()
    .and_then(|r| r.parse.and_then(|p| p.misp_type))
}

/// What an export sends: its content type, file name and body.
pub struct Export {
    pub content_type: &'static str,
    pub filename: String,
    pub body: axum::body::Body,
}

/// Opens a read-only connection of its own (an export may take as long as its client).
fn export_conn(state: &SharedState) -> anyhow::Result<rusqlite::Connection> {
    let c = rusqlite::Connection::open_with_flags(
        state.db.path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    c.busy_timeout(std::time::Duration::from_secs(30))?;
    Ok(c)
}

const ENTRY_SQL: &str = "SELECT raw, rule_type, kind, first_seen_at, last_seen_at FROM feed_entries
     WHERE feed_id = ?1 AND removed_run IS NULL ORDER BY first_seen_at, coalesce(line_no, 0), id";

/// Streams chunks a blocking writer produces.
struct Chunks {
    tx: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
    buf: Vec<u8>,
}

impl Chunks {
    fn put(&mut self, b: &[u8]) -> Result<(), ()> {
        self.buf.extend_from_slice(b);
        if self.buf.len() >= 64 * 1024 {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), ()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let b = Bytes::from(std::mem::take(&mut self.buf));
        self.tx.blocking_send(Ok(b)).map_err(|_| ())
    }
}

/// `GET feeds/{id}/export` (`as_file`: `?as=file`).
pub fn export(
    state: &SharedState,
    def: &FeedDef,
    as_file: bool,
    slot: tokio::sync::OwnedSemaphorePermit,
) -> anyhow::Result<Export> {
    let def = def.clone();
    let conn = export_conn(state)?;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(8);
    let feed = def.id.clone();
    let now = crate::util::now_ts();
    let format = def.format;
    let (content_type, filename) = match (as_file, format) {
        (false, _) => ("application/json", format!("{feed}.json")),
        (true, FeedFormat::MispWarninglist) => ("application/json", format!("{feed}.json")),
        (true, _) => ("text/plain; charset=utf-8", format!("{feed}.txt")),
    };
    tokio::task::spawn_blocking(move || {
        let _slot = slot;
        let mut out = Chunks { tx, buf: Vec::new() };
        let r = (|| -> Result<(), ()> {
            // One read transaction: the list type, the values and their dates come from one
            // snapshot, so an ingest meanwhile can't mix two versions (feeds.md §4: an export is
            // always one list).
            let snapshot = conn.unchecked_transaction().map_err(|_| ())?;
            let misp = (format == FeedFormat::MispWarninglist)
                .then(|| misp_type_in(&snapshot, &feed))
                .flatten();
            let settings = ExportSettings::of(&def, misp);
            let mut st = snapshot.prepare(ENTRY_SQL).map_err(|_| ())?;
            if !as_file {
                // `picket_feed_export` first and `entries` last (api.md §7), in this order.
                let h = format!(
                    "{{\"picket_feed_export\":1,\"exported_at\":{},\"feed\":{},\"entries\":[",
                    super::misp::quote(&now),
                    serde_json::to_string(&settings).map_err(|_| ())?
                );
                out.put(h.as_bytes())?;
                let mut rows = st.query([&feed]).map_err(|_| ())?;
                let mut first = true;
                while let Some(r) = rows.next().map_err(|_| ())? {
                    let e = json!({
                        "raw": r.get::<_, String>(0).unwrap_or_default(),
                        "rule_type": r.get::<_, String>(1).unwrap_or_default(),
                        "kind": r.get::<_, String>(2).unwrap_or_default(),
                        "first_seen_at": r.get::<_, String>(3).unwrap_or_default(),
                        "last_seen_at": r.get::<_, String>(4).unwrap_or_default(),
                    });
                    if !first {
                        out.put(b",")?;
                    }
                    first = false;
                    out.put(e.to_string().as_bytes())?;
                }
                out.put(b"]}")?;
            } else if format == FeedFormat::MispWarninglist {
                let picket_feed = serde_json::to_string(&settings).map_err(|_| ())?;
                let head = format!(
                    "{{\"name\":{},\"type\":{},\"picket_feed\":{picket_feed},\"list\":[",
                    super::misp::quote(&settings.name),
                    super::misp::quote(settings.misp_type.as_deref().unwrap_or("hostname"))
                );
                out.put(head.as_bytes())?;
                let mut first = true;
                {
                    let mut rows = st.query([&feed]).map_err(|_| ())?;
                    while let Some(r) = rows.next().map_err(|_| ())? {
                        let raw: String = r.get(0).unwrap_or_default();
                        if !first {
                            out.put(b",")?;
                        }
                        first = false;
                        out.put(super::misp::quote(&raw).as_bytes())?;
                    }
                }
                out.put(b"],\"picket_first_seen\":{")?;
                first = true;
                let mut rows = st.query([&feed]).map_err(|_| ())?;
                while let Some(r) = rows.next().map_err(|_| ())? {
                    let raw: String = r.get(0).unwrap_or_default();
                    let fs: String = r.get(3).unwrap_or_default();
                    if !first {
                        out.put(b",")?;
                    }
                    first = false;
                    out.put(format!("{}:{}", super::misp::quote(&raw), super::misp::quote(&fs)).as_bytes())?;
                }
                out.put(b"}}")?;
            } else {
                let c = comment(format);
                let header = header_lines(c, &settings, &now);
                out.put(header.as_bytes())?;
                let mut rows = st.query([&feed]).map_err(|_| ())?;
                let mut current: Option<String> = None;
                while let Some(r) = rows.next().map_err(|_| ())? {
                    let raw: String = r.get(0).unwrap_or_default();
                    let fs: String = r.get(3).unwrap_or_default();
                    if current.as_deref() != Some(fs.as_str()) {
                        out.put(format!("{c} picket-first-seen: {fs}\n").as_bytes())?;
                        current = Some(fs);
                    }
                    out.put(raw.as_bytes())?;
                    out.put(b"\n")?;
                }
                out.put(format!("{c} picket-first-seen: none\n").as_bytes())?;
            }
            out.flush()
        })();
        if r.is_err() {
            let _ = out
                .tx
                .blocking_send(Err(std::io::Error::other("the export stopped")));
        }
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|x| (x, rx)) });
    Ok(Export {
        content_type,
        filename,
        body: axum::body::Body::from_stream(stream),
    })
}

/// The comment lines at the top of a line-format file export.
fn header_lines(c: &str, s: &ExportSettings, now: &str) -> String {
    let clean = |v: &str| crate::util::sanitize_for_message(v, 512);
    let j = |v: &dyn erased::Ser| v.json();
    let mut h = String::new();
    h.push_str(&format!("{c} picket-feed-export: 1\n"));
    h.push_str(&format!("{c} feed: {}\n", clean(&s.id)));
    h.push_str(&format!("{c} name: {}\n", clean(&s.name)));
    h.push_str(&format!(
        "{c} provider: {}\n",
        clean(s.provider.as_deref().unwrap_or(""))
    ));
    h.push_str(&format!("{c} exported_at: {now}\n"));
    h.push_str(&format!("{c} format: {}\n", enum_str(&s.format)));
    h.push_str(&format!("{c} format_options: {}\n", j(&s.format_options)));
    h.push_str(&format!("{c} rule_policy: {}\n", j(&s.rule_policy)));
    h.push_str(&format!("{c} category: {}\n", s.category.as_str()));
    h.push_str(&format!("{c} warn_on: {}\n", j(&s.warn_on)));
    h
}

mod erased {
    pub trait Ser {
        fn json(&self) -> String;
    }
    impl<T: serde::Serialize> Ser for T {
        fn json(&self) -> String {
            serde_json::to_string(self).unwrap_or_else(|_| "null".into())
        }
    }
}

/// Reads a line-format file export's header (the comment lines at its top): the settings it
/// names, if it is one.
pub fn read_header<R: BufRead>(r: R) -> Option<Value> {
    let mut m = serde_json::Map::new();
    let mut is_export = false;
    for line in r.lines().take(64) {
        let Ok(line) = line else { break };
        let t = line.trim();
        let Some(rest) = t.strip_prefix('!').or_else(|| t.strip_prefix('#')) else {
            break;
        };
        let rest = rest.trim();
        let Some((k, v)) = rest.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "picket-feed-export" => is_export = true,
            "picket-first-seen" => break,
            "feed" => {
                m.insert("id".into(), Value::String(v.into()));
            }
            "name" | "provider" | "format" | "category" | "exported_at" => {
                m.insert(k.into(), Value::String(v.into()));
            }
            "format_options" | "rule_policy" | "warn_on" => {
                if let Ok(x) = serde_json::from_str::<Value>(v) {
                    m.insert(k.into(), x);
                }
            }
            _ => {}
        }
    }
    is_export.then_some(Value::Object(m))
}

/// The feed settings an import's query names (api.md §7). Into a new manual feed
/// (`POST feeds/import`) they are the admin's picks for a plain list file or a bare MISP list;
/// an export declares its own (feeds.md §4: a new feed's settings come from the export), so a
/// query setting that differs from what the export declares is refused (`422` naming the field),
/// one equal to it is fine, and one the export leaves out fills it. Into an existing feed each
/// must be the feed's own (replacing and merging need the same format and `format_options`; the
/// feed keeps its settings).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct QuerySettings {
    pub format: Option<FeedFormat>,
    pub domains_as: Option<DomainsAs>,
    pub category: Option<Category>,
    pub warn_on: Option<Vec<String>>,
    pub redirects: Option<PolicyOption>,
    pub client_rules: Option<PolicyOption>,
    pub browser_changes: Option<PolicyOption>,
}

/// Where an import goes (api.md §7).
#[derive(Clone, Debug)]
pub enum Target {
    /// A new manual feed (`POST feeds/import`): `id` and `name` from the query, else from the
    /// export; the other settings as [`QuerySettings`] says.
    NewManual {
        id: Option<String>,
        name: Option<String>,
        settings: QuerySettings,
    },
    /// An existing feed (`POST feeds/{id}/import?mode=…`).
    Existing {
        feed: String,
        replace: bool,
        base_version: Option<String>,
        settings: QuerySettings,
    },
}

/// What an import did.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct Imported {
    pub feed: String,
    /// A new manual feed was created.
    pub created: bool,
    /// A manual feed's file version afterwards.
    pub version: Option<String>,
    /// When a manual feed's file was saved (the `saved_at` of `GET feeds/{id}/file`, and the
    /// `updated_at` of the run that reads it): this import's save, or the unchanged file's.
    pub saved_at: Option<String>,
    /// False when a manual feed's file didn't change (no run).
    pub changed: bool,
    /// A provider feed's import run went to the heavy lane.
    pub run_queued: bool,
    /// Entries in a JSON export.
    pub entries: Option<u64>,
}

fn invalid(m: impl Into<String>) -> SaveError {
    SaveError::Invalid(m.into())
}

/// The settings an import found (a JSON export's `feed`, a file header, a MISP `picket_feed`).
fn settings_of(v: &Value) -> Result<ExportSettings, SaveError> {
    serde_json::from_value(v.clone())
        .map_err(|e| invalid(format!("the export's feed settings are invalid: {e}")))
}

/// The file an import made, with what it knew about where it came from.
struct Made {
    file: crate::modules::download::StagedFile,
    settings: Option<ExportSettings>,
    /// An export's settings as it declares them (a JSON export's `feed`, a file export's header,
    /// a MISP export's `picket_feed` with its format): which keys it names. `None` for a plain
    /// list file or a bare MISP list.
    declared: Option<serde_json::Map<String, Value>>,
    entries: Option<u64>,
}

/// What [`make_file`] keeps while the body streams.
struct Making {
    w: SyncStageWriter,
    map: SyncStageWriter,
    settings: Option<ExportSettings>,
    declared: Option<serde_json::Map<String, Value>>,
    fmt: Option<FeedFormat>,
    current: Option<Option<String>>,
    first_value: bool,
    first_date: bool,
    started: bool,
}

impl Making {
    fn misp_start(&mut self) -> std::io::Result<()> {
        if !self.started {
            let ty = self
                .settings
                .as_ref()
                .and_then(|s| s.misp_type.clone())
                .unwrap_or_else(|| "hostname".into());
            self.w
                .write(format!("{{\"type\":{},\"list\":[", super::misp::quote(&ty)).as_bytes())?;
            self.started = true;
        }
        Ok(())
    }

    fn entry(&mut self, e: ExportEntry<'_>) -> std::io::Result<()> {
        let format = self.fmt.unwrap_or(FeedFormat::Adblock);
        if format == FeedFormat::MispWarninglist {
            self.misp_start()?;
            if !self.first_value {
                self.w.write(b",")?;
            }
            self.first_value = false;
            self.w.write(super::misp::quote(e.raw).as_bytes())?;
            if let Some(d) = e.first_seen_at {
                if !self.first_date {
                    self.map.write(b",")?;
                }
                self.first_date = false;
                self.map
                    .write(format!("{}:{}", super::misp::quote(e.raw), super::misp::quote(d)).as_bytes())?;
            }
            return Ok(());
        }
        let c = comment(format);
        let want = e.first_seen_at.map(str::to_string);
        if self.current.as_ref() != Some(&want) {
            match &want {
                Some(d) => self.w.write(format!("{c} picket-first-seen: {d}\n").as_bytes())?,
                None => self
                    .w
                    .write(format!("{c} picket-first-seen: none\n").as_bytes())?,
            }
            self.current = Some(want);
        }
        self.w.write(e.raw.as_bytes())?;
        self.w.write(b"\n")
    }
}

/// Writes an import body as one file in `format` (feeds.md §4 "As a file"), on a blocking thread.
fn make_file(
    reader: Box<dyn Read + Send>,
    format: Option<FeedFormat>,
    staging: &std::path::Path,
    feed: &str,
    max: u64,
) -> Result<Made, SaveError> {
    let st = std::cell::RefCell::new(Making {
        w: stage_sync_in(staging, feed, max).map_err(anyhow::Error::from)?,
        map: stage_sync_in(staging, feed, max).map_err(anyhow::Error::from)?,
        settings: None,
        declared: None,
        fmt: format,
        current: None,
        first_value: true,
        first_date: true,
        started: false,
    });
    let werr = |e: std::io::Error| manual::body_err(BodyError::from(e), max);
    let body = body::parse_import(
        reader,
        MAX_LINE,
        &mut |f| {
            let s = settings_of(f).map_err(|e| BodyError::Invalid(e.to_string()))?;
            let mut m = st.borrow_mut();
            if m.fmt.is_none() {
                m.fmt = Some(s.format);
            }
            m.settings = Some(s);
            m.declared = f.as_object().cloned();
            Ok(())
        },
        &mut |e: ExportEntry<'_>| st.borrow_mut().entry(e).map_err(BodyError::from),
        &mut |b| st.borrow_mut().w.write(b).map_err(BodyError::from),
    )
    .map_err(|e| manual::body_err(e, max))?;
    let mut m = st.into_inner();
    let entries = match &body {
        ImportBody::Export { feed, entries } => {
            if m.settings.is_none() {
                m.settings = Some(settings_of(feed)?);
                m.declared = feed.as_object().cloned();
            }
            let format = m.fmt.unwrap_or(FeedFormat::Adblock);
            if format == FeedFormat::MispWarninglist {
                m.misp_start().map_err(werr)?;
                m.w.write(b"],\"picket_first_seen\":{").map_err(werr)?;
                let map = m.map.finish().map_err(anyhow::Error::from)?;
                copy(map.path(), &mut m.w, max)?;
                m.w.write(b"}}").map_err(werr)?;
            } else {
                // Lines appended later keep the default date.
                m.w.write(format!("{} picket-first-seen: none\n", comment(format)).as_bytes())
                    .map_err(werr)?;
            }
            Some(*entries)
        }
        ImportBody::File => None,
    };
    let mut settings = m.settings.take();
    let mut declared = m.declared.take();
    let file = m.w.finish().map_err(anyhow::Error::from)?;
    if entries.is_none() {
        // A file (feeds.md §4): what it declares wins over the format expected, so a conflict
        // with it is refused (api.md §7: another format → 422) rather than the file read as
        // something it isn't. A MISP export (one with `picket_feed`) is one whatever was
        // expected. A file that is neither a MISP export nor a readable MISP list is read for a
        // line-format export's header even where a MISP list was expected: a `.txt` export sent
        // to a MISP feed, or with `format=misp-warninglist`, is that export, never a MISP list
        // it can't be read as. Else a MISP list (expected, or nothing was and it reads as one)
        // or a plain list file.
        let picket_feed = misp_picket_feed(file.path());
        let list_type = super::misp::open(file.path()).and_then(super::misp::list_type);
        let header = if picket_feed.is_none() && list_type.is_err() {
            std::fs::File::open(file.path())
                .ok()
                .and_then(|f| read_header(std::io::BufReader::new(f)))
        } else {
            None
        };
        let misp = header.is_none()
            && (format == Some(FeedFormat::MispWarninglist)
                || picket_feed.is_some()
                || (format.is_none() && list_type.is_ok()));
        settings = if let Some(h) = header {
            declared = h.as_object().cloned();
            Some(settings_of(&h)?)
        } else if misp {
            let ty = list_type.ok().flatten();
            let mut s = match &picket_feed {
                Some(h) => settings_of(h)?,
                None => ExportSettings::default(),
            };
            s.format = FeedFormat::MispWarninglist;
            s.misp_type = ty;
            declared = picket_feed.and_then(|h| h.as_object().cloned()).map(|mut d| {
                d.insert(
                    "format".into(),
                    Value::String(enum_str(&FeedFormat::MispWarninglist)),
                );
                d
            });
            Some(s)
        } else {
            None
        };
    }
    Ok(Made {
        file,
        settings,
        declared,
        entries,
    })
}

/// A MISP export's `picket_feed` object, if the file is one.
fn misp_picket_feed(path: &std::path::Path) -> Option<Value> {
    let f = super::misp::open(path).ok()?;
    super::misp::picket_feed(f).ok().flatten()
}

fn copy(path: &std::path::Path, out: &mut SyncStageWriter, max: u64) -> Result<(), SaveError> {
    let mut r = std::fs::File::open(path).map_err(anyhow::Error::from)?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf).map_err(anyhow::Error::from)?;
        if n == 0 {
            return Ok(());
        }
        out.write(&buf[..n])
            .map_err(|e| manual::body_err(BodyError::from(e), max))?;
    }
}

/// Merges an imported file into a manual feed's current one (feeds.md §4): line formats add the
/// imported lines between `picket-first-seen: none` lines, so neither side's dates reach the
/// other's lines; MISP lists join their lists and `picket_first_seen` maps (the earlier date
/// wins).
fn merge_files(
    current: Option<&std::path::Path>,
    imported: &std::path::Path,
    format: FeedFormat,
    staging: &std::path::Path,
    feed: &str,
    max: u64,
) -> Result<crate::modules::download::StagedFile, SaveError> {
    let mut out = stage_sync_in(staging, feed, max).map_err(anyhow::Error::from)?;
    let werr = |e: std::io::Error| manual::body_err(BodyError::from(e), max);
    if format == FeedFormat::MispWarninglist {
        merge_misp(current, imported, staging, feed, max, &mut out)?;
        return Ok(out.finish().map_err(anyhow::Error::from)?);
    }
    let c = comment(format);
    if let Some(cur) = current {
        let mut r = std::fs::File::open(cur).map_err(anyhow::Error::from)?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut last = None;
        loop {
            let n = r.read(&mut buf).map_err(anyhow::Error::from)?;
            if n == 0 {
                break;
            }
            last = buf.get(n - 1).copied();
            out.write(&buf[..n]).map_err(werr)?;
        }
        if last.is_some_and(|b| b != b'\n') {
            out.write(b"\n").map_err(werr)?;
        }
    }
    out.write(format!("{c} picket-first-seen: none\n").as_bytes())
        .map_err(werr)?;
    copy(imported, &mut out, max)?;
    let mut tail = [0u8; 1];
    let ends_nl = std::fs::File::open(imported)
        .ok()
        .and_then(|mut f| {
            use std::io::Seek;
            let len = f.metadata().ok()?.len();
            if len == 0 {
                return Some(true);
            }
            f.seek(std::io::SeekFrom::Start(len - 1)).ok()?;
            f.read_exact(&mut tail).ok()?;
            Some(tail[0] == b'\n')
        })
        .unwrap_or(true);
    if !ends_nl {
        out.write(b"\n").map_err(werr)?;
    }
    out.write(format!("{c} picket-first-seen: none\n").as_bytes())
        .map_err(werr)?;
    Ok(out.finish().map_err(anyhow::Error::from)?)
}

/// Pages of a MISP merge's scratch database kept in memory (8 MiB: README §2 Bounded).
const MERGE_CACHE_KIB: i64 = 8 * 1024;

/// A MISP merge's scratch database in `staging/`, deleted when dropped (and at start).
struct Scratch {
    conn: Option<rusqlite::Connection>,
    path: std::path::PathBuf,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(self.conn.take());
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let mut p = self.path.clone().into_os_string();
            p.push(suffix);
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Joins two MISP lists (feeds.md §4): their `list` values in order, duplicates collapsing, and
/// their `picket_first_seen` maps, the earlier date winning (a date that parses over one that
/// doesn't). Streamed through a scratch SQLite file whose page cache is bounded, so a list near
/// the download cap never sits in RAM (core.md §1 peak RAM; README §2 Bounded).
fn merge_misp(
    current: Option<&std::path::Path>,
    imported: &std::path::Path,
    staging: &std::path::Path,
    feed: &str,
    max: u64,
    out: &mut SyncStageWriter,
) -> Result<(), SaveError> {
    let werr = |e: std::io::Error| manual::body_err(BodyError::from(e), max);
    let path = staging.join(format!(
        "merge-{}-{}.sqlite",
        feed.chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .take(64)
            .collect::<String>(),
        crate::util::random_hex(8)
    ));
    let mut scratch = Scratch {
        conn: Some(rusqlite::Connection::open(&path).map_err(anyhow::Error::from)?),
        path,
    };
    let c = scratch
        .conn
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("no scratch database"))?;
    c.execute_batch(&format!(
        "PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF; PRAGMA temp_store = FILE;
         PRAGMA cache_size = -{MERGE_CACHE_KIB};
         CREATE TABLE v (seq INTEGER PRIMARY KEY, value TEXT NOT NULL UNIQUE);
         CREATE TABLE d (k TEXT PRIMARY KEY, d TEXT NOT NULL);"
    ))
    .map_err(anyhow::Error::from)?;
    let mut ty: Option<String> = None;
    let mut budget = max;
    let io = |e: rusqlite::Error| std::io::Error::other(e.to_string());
    for p in current.into_iter().chain(std::iter::once(imported)) {
        let tx = c.transaction().map_err(anyhow::Error::from)?;
        {
            let mut ins = tx
                .prepare("INSERT OR IGNORE INTO v(value) VALUES (?1)")
                .map_err(anyhow::Error::from)?;
            let t = super::misp::open(p)
                .and_then(|f| {
                    super::misp::values(f, |v| {
                        budget = budget.saturating_sub(v.len() as u64 + 4);
                        if budget == 0 {
                            return Err(std::io::Error::new(std::io::ErrorKind::FileTooLarge, "too large"));
                        }
                        ins.execute([&v]).map_err(io)?;
                        Ok(())
                    })
                })
                .map_err(|e| manual::body_err(BodyError::from(e), max))?;
            if ty.is_none() {
                ty = t;
            }
            let mut get = tx
                .prepare("SELECT d FROM d WHERE k = ?1")
                .map_err(anyhow::Error::from)?;
            let mut put = tx
                .prepare("INSERT INTO d(k, d) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET d = excluded.d")
                .map_err(anyhow::Error::from)?;
            super::misp::open(p)
                .and_then(|f| {
                    super::misp::first_seen(f, |k, d| {
                        budget = budget.saturating_sub((k.len() + d.len()) as u64 + 6);
                        if budget == 0 {
                            return Err(std::io::Error::new(std::io::ErrorKind::FileTooLarge, "too large"));
                        }
                        let old: Option<String> = get.query_row([&k], |r| r.get(0)).optional().map_err(io)?;
                        let parsed = picket_rules::formats::parse_rfc3339(d.trim());
                        let keep_old = match &old {
                            Some(o) => {
                                picket_rules::formats::parse_rfc3339(o)
                                    .zip(parsed)
                                    .is_some_and(|(o, n)| o <= n)
                                    || parsed.is_none()
                            }
                            None => false,
                        };
                        if !keep_old {
                            put.execute([&k, &d]).map_err(io)?;
                        }
                        Ok(())
                    })
                })
                .map_err(|e| manual::body_err(BodyError::from(e), max))?;
        }
        tx.commit().map_err(anyhow::Error::from)?;
    }
    out.write(
        format!(
            "{{\"type\":{},\"list\":[",
            super::misp::quote(ty.as_deref().unwrap_or("hostname"))
        )
        .as_bytes(),
    )
    .map_err(werr)?;
    {
        let mut st = c
            .prepare("SELECT value FROM v ORDER BY seq")
            .map_err(anyhow::Error::from)?;
        let mut rows = st.query([]).map_err(anyhow::Error::from)?;
        let mut first = true;
        while let Some(r) = rows.next().map_err(anyhow::Error::from)? {
            let v: String = r.get(0).map_err(anyhow::Error::from)?;
            if !first {
                out.write(b",").map_err(werr)?;
            }
            first = false;
            out.write(super::misp::quote(&v).as_bytes()).map_err(werr)?;
        }
    }
    out.write(b"],\"picket_first_seen\":{").map_err(werr)?;
    {
        let mut st = c
            .prepare("SELECT k, d FROM d ORDER BY k")
            .map_err(anyhow::Error::from)?;
        let mut rows = st.query([]).map_err(anyhow::Error::from)?;
        let mut first = true;
        while let Some(r) = rows.next().map_err(anyhow::Error::from)? {
            let (k, d): (String, String) = (
                r.get(0).map_err(anyhow::Error::from)?,
                r.get(1).map_err(anyhow::Error::from)?,
            );
            if !first {
                out.write(b",").map_err(werr)?;
            }
            first = false;
            out.write(format!("{}:{}", super::misp::quote(&k), super::misp::quote(&d)).as_bytes())
                .map_err(werr)?;
        }
    }
    out.write(b"}}").map_err(werr)?;
    Ok(())
}

/// Refuses an import whose format, `format_options` or MISP list `type` differ from the target
/// feed's (feeds.md §4: `422`).
fn same_format(def: &FeedDef, s: &ExportSettings, target_type: Option<&str>) -> Result<(), SaveError> {
    if s.format != def.format {
        return Err(invalid(format!(
            "the import is {} and the feed {}: replacing and merging need the same format",
            enum_str(&s.format),
            enum_str(&def.format)
        )));
    }
    if s.format_options != def.format_options {
        return Err(invalid("the import's format_options differ from the feed's"));
    }
    if def.format == FeedFormat::MispWarninglist
        && let (Some(a), Some(b)) = (s.misp_type.as_deref(), target_type)
        && a != b
    {
        return Err(invalid(format!(
            "the import is a MISP list of type {a:?} and the feed's {b:?}: they need the same type"
        )));
    }
    Ok(())
}

/// Two `warn_on` lists name the same warn bundles (feeds.md §1: the bundles a feed is checked
/// against, a set): order and repeats don't make another setting.
fn same_bundles(a: &[String], b: &[String]) -> bool {
    fn set(v: &[String]) -> std::collections::BTreeSet<&str> {
        v.iter().map(String::as_str).collect()
    }
    set(a) == set(b)
}

/// A query setting the import refuses: a `422` naming the field (feeds.md §4, api.md §7).
fn conflict(feed: &str, field: &str, message: String) -> SaveError {
    SaveError::Issues(vec![crate::config::validate::Issue {
        severity: crate::config::validate::Severity::Error,
        entity: "feed".into(),
        id: feed.into(),
        field: Some(field.into()),
        code: "import_setting_conflict".into(),
        message,
    }])
}

/// An import into an existing feed takes no settings of its own: each setting in the query must
/// be the feed's (replacing and merging need the same format and `format_options`, feeds.md §4;
/// the feed keeps its other settings), else `422` naming the field.
fn existing_query(def: &FeedDef, q: &QuerySettings) -> Result<(), SaveError> {
    let refuse = |field: &str, feed: String, query: String| {
        conflict(
            &def.id,
            field,
            format!(
                "{field}: the feed's is {feed} and the query says {query}; an import keeps the feed's settings (edit the feed to change them)"
            ),
        )
    };
    if let Some(f) = q.format.filter(|f| *f != def.format) {
        return Err(refuse("format", enum_str(&def.format), enum_str(&f)));
    }
    let domains_as = def.format_options.domains_as.unwrap_or(DomainsAs::Exact);
    if let Some(d) = q.domains_as.filter(|d| *d != domains_as) {
        return Err(refuse(
            "format_options",
            format!("domains_as {}", enum_str(&domains_as)),
            format!("domains_as {}", enum_str(&d)),
        ));
    }
    if let Some(c) = q.category.filter(|c| *c != def.category) {
        return Err(refuse("category", enum_str(&def.category), enum_str(&c)));
    }
    if let Some(w) = q
        .warn_on
        .as_ref()
        .filter(|w| !same_bundles(w, &def.effective_warn_on()))
    {
        return Err(refuse(
            "warn_on",
            format!("{:?}", def.effective_warn_on()),
            format!("{w:?}"),
        ));
    }
    let policy = def.rule_policy.resolved(def.is_manual());
    for (field, query, current) in [
        ("redirects", q.redirects, policy.redirects),
        ("client_rules", q.client_rules, policy.client_rules),
        ("browser_changes", q.browser_changes, policy.browser_changes),
    ] {
        if let Some(v) = query.filter(|v| Some(*v) != current) {
            return Err(refuse(
                "rule_policy",
                format!("{field} {}", current.map(|c| enum_str(&c)).unwrap_or_default()),
                format!("{field} {}", enum_str(&v)),
            ));
        }
    }
    Ok(())
}

/// A new manual feed's definition from an import (feeds.md §4): `name`, `format`,
/// `format_options`, `rule_policy`, `category` and `warn_on` from the export where it declares
/// them, else from the query (the admin's picks for a plain list), else the manual-feed
/// defaults. A query setting that differs from one the export declares is refused, naming it;
/// one equal to it is fine. Every rule type is `replace` (`browser` included) and the feed has
/// no provider.
fn new_manual_def(
    id: &str,
    name: Option<String>,
    s: &ExportSettings,
    declared: Option<&serde_json::Map<String, Value>>,
    has_settings: bool,
    q: &QuerySettings,
) -> Result<FeedDef, SaveError> {
    let has = |k: &str| declared.is_some_and(|d| d.contains_key(k));
    let refuse = |field: &str, declared: String, query: String| {
        conflict(
            id,
            field,
            format!(
                "{field}: the export declares {declared} and the query says {query}; a new feed's settings come from its export"
            ),
        )
    };
    // format: an export's; else the query's, a bare MISP list's, adblock.
    let format = if has("format") {
        if let Some(f) = q.format.filter(|f| *f != s.format) {
            return Err(refuse("format", enum_str(&s.format), enum_str(&f)));
        }
        s.format
    } else {
        q.format
            .or(has_settings.then_some(s.format))
            .unwrap_or(FeedFormat::Adblock)
    };
    let mut format_options = if has("format_options") {
        s.format_options.clone()
    } else {
        FormatOptions::default()
    };
    if let Some(d) = q.domains_as {
        let current = format_options.domains_as.unwrap_or(DomainsAs::Exact);
        if has("format_options") && current != d {
            return Err(refuse(
                "format_options",
                format!("domains_as {}", enum_str(&current)),
                format!("domains_as {}", enum_str(&d)),
            ));
        }
        if !has("format_options") {
            format_options.domains_as = Some(d);
        }
    }
    let category = match q.category {
        Some(c) if has("category") && c != s.category => {
            return Err(refuse("category", enum_str(&s.category), enum_str(&c)));
        }
        Some(c) => c,
        None => s.category,
    };
    // warn_on: compared as it applies (null follows the category, feeds.md §1), as a set.
    let effective = |w: &Option<Vec<String>>| match w {
        Some(w) => w.clone(),
        None if category == Category::Security => vec!["warn-common".to_string()],
        None => vec![],
    };
    let warn_on = match &q.warn_on {
        Some(w) if has("warn_on") && !same_bundles(&effective(&s.warn_on), w) => {
            return Err(refuse(
                "warn_on",
                format!("{:?}", effective(&s.warn_on)),
                format!("{w:?}"),
            ));
        }
        Some(_) if has("warn_on") => s.warn_on.clone(),
        Some(w) => Some(w.clone()),
        None => s.warn_on.clone(),
    };
    // rule_policy: each switch as it applies to a manual feed (left out: keep, feeds.md §8).
    let base = if has("rule_policy") {
        s.rule_policy.resolved(true)
    } else {
        RulePolicy::default().resolved(true)
    };
    let mut rule_policy = base.clone();
    for (field, query, current, slot) in [
        (
            "redirects",
            q.redirects,
            base.redirects,
            &mut rule_policy.redirects,
        ),
        (
            "client_rules",
            q.client_rules,
            base.client_rules,
            &mut rule_policy.client_rules,
        ),
        (
            "browser_changes",
            q.browser_changes,
            base.browser_changes,
            &mut rule_policy.browser_changes,
        ),
    ] {
        let Some(v) = query else { continue };
        if has("rule_policy") && Some(v) != current {
            return Err(refuse(
                "rule_policy",
                format!("{field} {}", current.map(|c| enum_str(&c)).unwrap_or_default()),
                format!("{field} {}", enum_str(&v)),
            ));
        }
        *slot = Some(v);
    }
    let replace = ModeSpec {
        mode: Mode::Replace,
        expire_after: None,
    };
    Ok(FeedDef {
        id: id.to_string(),
        name: name
            .or_else(|| (!s.name.is_empty()).then(|| s.name.clone()))
            .unwrap_or_else(|| id.to_string()),
        category,
        warn_on,
        enabled: true,
        provider: None,
        file: None,
        format,
        format_options,
        rule_policy,
        modes: Modes {
            dns: replace.clone(),
            ip: replace.clone(),
            browser: replace,
        },
        sanity: Default::default(),
        system: false,
    })
}

/// `POST feeds/import` and `POST feeds/{id}/import`.
pub async fn import(
    state: &SharedState,
    target: Target,
    body: axum::body::Body,
    encoding: Option<&str>,
    actor: Actor,
) -> Result<Imported, SaveError> {
    let (max, _) = manual::caps(state);
    let body_max = max.saturating_mul(BODY_FACTOR);
    let gzip = manual::gzip_of(encoding)?;
    // The target, checked before the body is read, with the source generation it has now: a
    // provider-feed merge is accepted only if the feed is still that one (feeds.md §4).
    let mut source_gen: Option<i64> = None;
    let existing: Option<FeedDef> = match &target {
        Target::Existing { feed, replace, .. } => {
            let def = state
                .feeds
                .def_or_reload(state, feed)
                .await
                .ok_or_else(|| SaveError::NotFound(feed.clone()))?;
            if !def.is_manual() && *replace {
                return Err(invalid(
                    "replacing a provider feed's entries is refused: its next download would undo it; merge instead",
                ));
            }
            if let Target::Existing { settings, .. } = &target {
                existing_query(&def, settings)?;
            }
            let f = feed.clone();
            source_gen = state
                .db
                .read(move |c| Ok::<_, anyhow::Error>(super::store::source_gen(c, &f)?))
                .await?;
            Some(def)
        }
        Target::NewManual { id: Some(id), .. } => {
            if state.feeds.def_or_reload(state, id).await.is_some() {
                return Err(SaveError::Conflict {
                    current: format!("feed {id:?} already exists"),
                });
            }
            None
        }
        Target::NewManual { .. } => None,
    };
    let mut upload = manual::admit(state, body_max)?;
    let tag = match &target {
        Target::Existing { feed, .. } => feed.clone(),
        Target::NewManual { id, .. } => id.clone().unwrap_or_else(|| "import".into()),
    };
    let spool = manual::spool_body(state, &tag, body, body_max, max, &mut upload.budget).await?;
    let staging = state.data_dir.join("staging");
    let dropped = Arc::new(AtomicBool::new(false));
    let _cancel = manual::CancelOnDrop(dropped.clone());
    let shutdown = state.shutdown.clone();
    let format = match (&existing, &target) {
        (Some(d), _) => Some(d.format),
        (None, Target::NewManual { settings, .. }) => settings.format,
        _ => None,
    };
    let (st2, tag2) = (staging.clone(), tag.clone());
    let made = tokio::task::spawn_blocking(move || -> Result<Made, SaveError> {
        let reader = manual::spool_reader(spool.path(), gzip, body_max, dropped, shutdown)
            .map_err(anyhow::Error::from)?;
        make_file(reader, format, &st2, &tag2, max)
    })
    .await
    .map_err(|e| anyhow::anyhow!("the import failed: {e}"))??;
    match (target, existing) {
        (
            Target::NewManual {
                id,
                name,
                settings: q,
            },
            _,
        ) => {
            let s = made.settings.clone().unwrap_or_default();
            let id = id
                .or_else(|| (!s.id.is_empty()).then(|| s.id.clone()))
                .ok_or_else(|| invalid("a new manual feed needs an id (?id=)"))?;
            let def = new_manual_def(&id, name, &s, made.declared.as_ref(), made.settings.is_some(), &q)?;
            let body = serde_json::to_value(&def).map_err(anyhow::Error::from)?;
            state
                .config
                .apply(EntityKind::Feed, Op::Create(body), actor.clone(), None)
                .await
                .map_err(|e| match e {
                    crate::error::CoreError::Conflict(m) => SaveError::Conflict { current: m },
                    // As an entity save's: each problem with its field (F2: the query's
                    // rule_policy and warn_on are validated as the feed's own fields).
                    crate::error::CoreError::Validation(v) => SaveError::Issues(v),
                    e => SaveError::Other(anyhow::anyhow!("{e}")),
                })?;
            state.feeds.reload(state).await;
            let lock = state.feeds.save_lock(&id);
            let _g = lock.lock().await;
            let r = manual::store_and_check(state, &id, made.file, None, actor).await?;
            Ok(Imported {
                feed: id,
                created: true,
                version: Some(r.version),
                saved_at: r.saved_at,
                changed: r.changed,
                run_queued: false,
                entries: made.entries,
            })
        }
        (
            Target::Existing {
                feed,
                replace,
                base_version,
                ..
            },
            Some(def),
        ) => {
            let target_type = if def.format == FeedFormat::MispWarninglist {
                misp_type_of(state, &feed).await
            } else {
                None
            };
            if let Some(s) = &made.settings {
                same_format(&def, s, target_type.as_deref())?;
            }
            if !def.is_manual() {
                let binding = super::store::ImportBinding {
                    format: def.format,
                    format_options: def.format_options.clone(),
                    misp_type: target_type,
                };
                return merge_provider(state, &def, source_gen, binding, made).await;
            }
            let lock = state.feeds.save_lock(&feed);
            let _g = lock.lock().await;
            let current = manual::file_info(state, &feed).await?;
            match (&current, &base_version) {
                (None, None) => {}
                (Some(c), Some(b)) if &c.version == b => {}
                (Some(c), _) => {
                    return Err(SaveError::Conflict {
                        current: c.version.clone(),
                    });
                }
                (None, Some(_)) => {
                    return Err(SaveError::Conflict {
                        current: String::new(),
                    });
                }
            }
            let file = if replace {
                made.file
            } else {
                let cur_path = current.as_ref().map(|c| c.path.clone());
                let (st3, f3) = (staging.clone(), feed.clone());
                let imported = made.file;
                tokio::task::spawn_blocking(move || {
                    let r = merge_files(cur_path.as_deref(), imported.path(), def.format, &st3, &f3, max);
                    drop(imported);
                    r
                })
                .await
                .map_err(|e| anyhow::anyhow!("the merge failed: {e}"))??
            };
            let r = manual::store_and_check(state, &feed, file, current, actor).await?;
            Ok(Imported {
                feed,
                created: false,
                version: Some(r.version),
                saved_at: r.saved_at,
                changed: r.changed,
                run_queued: false,
                entries: made.entries,
            })
        }
        (Target::Existing { feed, .. }, None) => Err(SaveError::NotFound(feed)),
    }
}

/// How long a provider-feed merge waits for the feed's run in progress.
const IMPORT_WAIT: std::time::Duration = std::time::Duration::from_secs(10 * 60);
/// Accepted imports a provider feed may hold waiting for their runs (README §2 Bounded; policy
/// choice): one, so imports and their blobs can't pile up while its run waits for a retry.
pub const MAX_WAITING_IMPORTS_PER_FEED: i64 = 1;
/// The blob bytes accepted imports waiting for their runs may hold in all, in download size caps
/// (`feeds.max_download_mib`; policy choice): four imports at the cap.
pub const MAX_WAITING_IMPORT_CAPS: u64 = 4;

/// Why an import wasn't accepted.
enum Refused {
    /// The feed was deleted, created again or edited while the import was read.
    Changed,
    /// The feed already holds [`MAX_WAITING_IMPORTS_PER_FEED`] waiting imports.
    FeedFull,
    /// Waiting imports hold [`MAX_WAITING_IMPORT_CAPS`] download caps of blobs.
    BytesFull,
}

/// A merge into a provider feed (feeds.md §4): it waits for the feed's run in progress, then, in
/// one transaction, checks that the feed is still the one the import was checked against (no
/// deletion, re-creation or source edit: its source generation; the same format,
/// `format_options` and MISP list type) and that the import fits the waiting imports' bounds
/// (README §2 Bounded: [`MAX_WAITING_IMPORTS_PER_FEED`], [`MAX_WAITING_IMPORT_CAPS`]; else `503`,
/// nothing stored), stores its file as a blob and records it as a pending import
/// (`feed_imports`) — so an accepted import survives a full heavy lane and a restart — and queues
/// its run. Its run deletes the record when stored; deleting the feed deletes it too.
async fn merge_provider(
    state: &SharedState,
    def: &FeedDef,
    source_gen: Option<i64>,
    binding: super::store::ImportBinding,
    made: Made,
) -> Result<Imported, SaveError> {
    let deadline = tokio::time::Instant::now() + IMPORT_WAIT;
    loop {
        if state.feeds.acquire_for_import(&def.id) {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(SaveError::Busy("the feed's runs keep it busy"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    // Held: freed if anything below fails, or handed to the run.
    let mut hold = ImportHold {
        state: Some(state.clone()),
        feed: def.id.clone(),
    };
    let mut file = made.file;
    let data_dir = state.data_dir.clone();
    let feed = def.id.clone();
    let b2 = binding.clone();
    let (cap, _) = manual::caps(state);
    let max_bytes = cap.saturating_mul(MAX_WAITING_IMPORT_CAPS);
    let accepted = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let fmt: Option<(String, String)> = tx
                .query_row(
                    "SELECT format, format_options_json FROM feeds WHERE id = ?1",
                    [&feed],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let same_feed = super::store::source_current(&tx, &feed, source_gen)?;
            let same_format = fmt.is_some_and(|(f, o)| {
                serde_json::from_value::<FeedFormat>(Value::String(f)).ok() == Some(b2.format)
                    && serde_json::from_str::<FormatOptions>(&o).ok().as_ref() == Some(&b2.format_options)
            });
            let same_type =
                b2.format != FeedFormat::MispWarninglist || misp_type_in(&tx, &feed) == b2.misp_type;
            if !(same_feed && same_format && same_type) {
                return Ok::<_, anyhow::Error>(Err(Refused::Changed));
            }
            // Imports a source edit left behind can never run (their run drops them): they hold
            // no place.
            tx.execute(
                "DELETE FROM feed_imports WHERE feed_id = ?1 AND source_gen IS NOT ?2",
                rusqlite::params![feed, source_gen],
            )?;
            let waiting: i64 = tx.query_row(
                "SELECT count(*) FROM feed_imports WHERE feed_id = ?1",
                [&feed],
                |r| r.get(0),
            )?;
            if waiting >= MAX_WAITING_IMPORTS_PER_FEED {
                return Ok(Err(Refused::FeedFull));
            }
            let held: i64 = tx.query_row(
                "SELECT coalesce(sum(b.size), 0) FROM feed_imports i JOIN blobs b ON b.blake3 = i.blob",
                [],
                |r| r.get(0),
            )?;
            if crate::util::nonneg(held).saturating_add(file.size()) > max_bytes {
                return Ok(Err(Refused::BytesFull));
            }
            let blob = super::check::adopt(&tx, &data_dir, &mut file, crate::blobs::kind::DOWNLOAD)?;
            let id = super::store::add_import(&tx, &feed, &blob, source_gen, &b2)?;
            tx.commit()?;
            Ok(Ok(id))
        })
        .await?;
    let import = match accepted {
        Ok(id) => id,
        Err(Refused::Changed) => {
            return Err(SaveError::Conflict {
                current:
                    "the feed was deleted, created again or edited while the import was read; import it again"
                        .into(),
            });
        }
        Err(Refused::FeedFull) => {
            return Err(SaveError::Busy(
                "an earlier import into this feed is still waiting for its run",
            ));
        }
        Err(Refused::BytesFull) => {
            return Err(SaveError::Busy(
                "imports waiting for their runs already hold the disk space they may use",
            ));
        }
    };
    hold.state = None;
    state.feeds.import_accepted(&def.id, import);
    state
        .feeds
        .submit(state, &def.id, super::ingest::Work::Import { import, source_gen });
    Ok(Imported {
        feed: def.id.clone(),
        created: false,
        version: None,
        saved_at: None,
        changed: true,
        run_queued: true,
        entries: made.entries,
    })
}

/// Frees a feed an import took busy, unless its run took it over.
struct ImportHold {
    state: Option<SharedState>,
    feed: String,
}

impl Drop for ImportHold {
    fn drop(&mut self) {
        if let Some(s) = self.state.take() {
            s.feeds.release(&s, &self.feed);
        }
    }
}

/// The size of a feed's export and of the file it would make (the UI's warning, feeds.md §4).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ExportSize {
    pub entries: u64,
    /// Bytes of the JSON export, estimated.
    pub json_bytes: u64,
    /// Bytes of the file an import of it would make, estimated.
    pub file_bytes: u64,
    /// The download size cap the file must fit.
    pub file_cap: u64,
    /// The import body bound the JSON export must fit.
    pub body_cap: u64,
}

pub async fn export_size(state: &SharedState, feed: &str) -> anyhow::Result<ExportSize> {
    let f = feed.to_string();
    let (n, raw): (i64, i64) = state
        .db
        .read(move |c| {
            Ok::<_, anyhow::Error>(c.query_row(
                "SELECT count(*), coalesce(sum(length(raw)), 0) FROM feed_entries WHERE feed_id = ?1 AND removed_run IS NULL",
                [&f],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .await?;
    let (max, _) = manual::caps(state);
    let n = crate::util::nonneg(n);
    let raw = crate::util::nonneg(raw);
    Ok(ExportSize {
        entries: n,
        json_bytes: raw + n * 150,
        file_bytes: raw + n + n / 4 * 40,
        file_cap: max,
        body_cap: max.saturating_mul(BODY_FACTOR),
    })
}

/// The file name a feed exports under (for `Content-Disposition`).
pub fn disposition(filename: &str) -> String {
    let safe: String = filename
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    format!("attachment; filename=\"{safe}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FP4 (feeds.md §4): a MISP merge joins the lists in order (duplicates collapse) and the
    /// maps (the earlier date wins, a date that parses over one that doesn't), streamed through a
    /// scratch database that is gone afterwards.
    #[test]
    fn misp_merges_stream_through_a_scratch_file_that_goes() {
        let d = tempfile::tempdir().unwrap();
        let cur = d.path().join("cur.json");
        std::fs::write(
            &cur,
            r#"{"type": "string", "list": ["a", "b"], "picket_first_seen": {"a": "2020-01-02", "b": "nope"}}"#,
        )
        .unwrap();
        let imp = d.path().join("imp.json");
        std::fs::write(
            &imp,
            r#"{"type": "string", "list": ["c", "a"], "picket_first_seen": {"a": "2019-05-05", "b": "2021-01-01", "c": "bad"}}"#,
        )
        .unwrap();
        let mut out = stage_sync_in(d.path(), "f", 1 << 20).unwrap();
        merge_misp(Some(&cur), &imp, d.path(), "f", 1 << 20, &mut out).unwrap();
        let f = out.finish().unwrap();
        let v: Value = serde_json::from_slice(&std::fs::read(f.path()).unwrap()).unwrap();
        assert_eq!(v["type"], "string");
        assert_eq!(v["list"], json!(["a", "b", "c"]));
        assert_eq!(
            v["picket_first_seen"],
            json!({"a": "2019-05-05", "b": "2021-01-01", "c": "bad"})
        );
        let left: Vec<String> = std::fs::read_dir(d.path())
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.starts_with("merge-"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
        // Past the cap: refused, and the scratch file goes too.
        let mut out = stage_sync_in(d.path(), "f", 16).unwrap();
        assert!(merge_misp(Some(&cur), &imp, d.path(), "f", 16, &mut out).is_err());
        assert!(
            !std::fs::read_dir(d.path())
                .unwrap()
                .filter_map(|e| e.ok()?.file_name().into_string().ok())
                .any(|n| n.starts_with("merge-"))
        );
    }

    #[test]
    fn headers_round_trip() {
        let s = ExportSettings {
            id: "f".into(),
            name: "My feed".into(),
            provider: Some("p".into()),
            format: FeedFormat::Plain,
            format_options: FormatOptions {
                domains_as: Some(DomainsAs::Subdomains),
            },
            category: Category::Security,
            warn_on: Some(vec!["warn-common".into()]),
            ..Default::default()
        };
        let h = header_lines("!", &s, "2026-11-23T04:00:00Z");
        let back =
            read_header(format!("{h}! picket-first-seen: 2021-01-01\na.example\n").as_bytes()).unwrap();
        let b = settings_of(&back).unwrap();
        assert_eq!(b.name, "My feed");
        assert_eq!(b.format, FeedFormat::Plain);
        assert_eq!(b.format_options.domains_as, Some(DomainsAs::Subdomains));
        assert_eq!(b.category, Category::Security);
        assert_eq!(b.warn_on, Some(vec!["warn-common".to_string()]));
        assert!(
            read_header("a.example\n".as_bytes()).is_none(),
            "a plain list has no header"
        );
        assert_eq!(disposition("a b\"c.json"), "attachment; filename=\"abc.json\"");
    }
}
