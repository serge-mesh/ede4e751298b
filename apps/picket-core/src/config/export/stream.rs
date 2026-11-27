//! Reading the config export document as a stream (core.md §2 "Export and restore"; core.md §3
//! "Bounded memory per job"; README §2 Bounded, Untrusted input).
//!
//! A document may be as large as [`super::MAX_DOCUMENT_BYTES`]: manual feeds' files and alert
//! evidence make up most of it. A restore spills the body to a file and reads it twice, never
//! holding the large parts in memory:
//!
//! 1. [`prescan`] walks the bytes once: no string longer than [`MAX_STRING_BYTES`] (so the JSON
//!    parser never buffers more than that for one value), no nesting deeper than [`MAX_DEPTH`],
//!    and each part the parser keeps in memory, and each element of a streamed list, within its
//!    size cap ([`CAPS`]). Object keys are read as the parser reads them (escapes decoded), so
//!    the caps hold however a key is written (README §2 Untrusted input). The export writes
//!    through the same checks ([`Prescan`]): it never writes a document the restore refuses.
//!    The previous format's single-string manual file (README §2 Compatibility) is the one
//!    string past [`MAX_STRING_BYTES`]: [`Normalize`] cuts it into chunks as it is read.
//! 2. [`parse`] reads the document with a [`Sink`]: the small parts (format, configuration, the
//!    feeds' and providers' state) come back as a [`Head`]; manual feeds' files (base64, in
//!    chunks) are decoded as they are read; alerts with their rows, feed check history and
//!    `config_changes` go to the sink one row at a time. The restore's first pass checks them
//!    (and decodes the files into `staging/`); its second pass, inside the restore's
//!    transaction, writes them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use serde::Deserialize;
use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use super::Configuration;
use crate::feeds::restore::{CheckPart, FeedPart, ProviderPart};

/// The longest JSON string a document may hold (raw bytes between the quotes): files travel in
/// base64 chunks ([`super::CHUNK_BYTES`] decoded, a third more encoded).
pub const MAX_STRING_BYTES: u64 = 4 * 1024 * 1024;
/// The deepest nesting a document may hold.
pub const MAX_DEPTH: usize = 64;
/// The largest a file decodes to: the most `feeds.max_download_mib` allows. The restored
/// settings' own cap is checked after the first pass.
pub const MAX_FILE_BYTES: u64 = 4096 * 1024 * 1024;

/// The configuration part's cap: the save validation keeps every configuration well within it
/// ([`crate::config::validate::MAX_CONFIG_BYTES`]).
pub const CONFIGURATION_CAP: u64 = 16 * 1024 * 1024;

/// Size caps, by path (`.`-joined object keys, `[]` for a list element): the parts the parser
/// keeps in memory whole, and each element of the lists it streams. The export applies the same
/// caps as it writes ([`Prescan`]).
pub const CAPS: &[(&str, u64)] = &[
    ("configuration", CONFIGURATION_CAP),
    ("feed_state.feeds", 16 * 1024 * 1024),
    ("feed_state.providers", 32 * 1024 * 1024),
    ("feed_state.checks.[]", 4 * 1024 * 1024),
    ("config_changes.[]", 4 * 1024 * 1024),
    ("alerts.[].alert", 4 * 1024 * 1024),
    ("alerts.[].evidence_rule", 4 * 1024 * 1024),
    ("alerts.[].history.[]", 4 * 1024 * 1024),
    ("alerts.[].evidence.[]", 4 * 1024 * 1024),
    ("alerts.[].evidence_counts.[]", 4 * 1024 * 1024),
    ("alerts.[].evidence_answers.[]", 4 * 1024 * 1024),
    ("alerts.[].wire_examples.[]", 4 * 1024 * 1024),
];

/// Checks the document's bytes against the bounds above before anything parses it (module
/// docs). A malformed document passes here and fails in [`parse`].
pub fn prescan(r: impl Read) -> Result<(), String> {
    let mut r = BufReader::with_capacity(64 * 1024, r);
    let mut scan = Prescan::default();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r
            .read(&mut buf)
            .map_err(|e| format!("cannot read the document: {e}"))?;
        if n == 0 {
            return Ok(());
        }
        scan.feed(&buf[..n])?;
    }
}

/// The longest object key a path names; a longer key matches none.
const MAX_LABEL: usize = 64;

/// One open container.
struct Frame {
    obj: bool,
    /// An object's current key, `[]` for a list.
    label: Label,
    start: u64,
    expect_key: bool,
}

/// A path element: an object key as the parser reads it (escapes decoded), or a list.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Label {
    List,
    Key(Vec<u8>),
    /// A key longer than [`MAX_LABEL`]: no path names it.
    Long,
}

impl Label {
    fn is(&self, s: &str) -> bool {
        match self {
            Label::List => s == "[]",
            Label::Key(k) => k.as_slice() == s.as_bytes(),
            Label::Long => false,
        }
    }
}

/// A string's escape state.
#[derive(Clone, Copy, Debug, Default)]
enum Esc {
    #[default]
    None,
    /// After a backslash.
    Backslash,
    /// Inside a `u` escape: hex digits left, the code unit so far.
    Hex(u8, u32),
}

/// What one byte was ([`Tracker::step`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    Other,
    /// A container opened.
    Open,
    /// A container closed, `size` bytes long (its frame is gone from the stack).
    Close(u64),
    /// A closing bracket with nothing open.
    Unbalanced,
    /// A string opened: a value at a path of the previous format's single-string manual file
    /// (`legacy`), or not.
    StrOpen {
        legacy: bool,
    },
    /// A byte inside a string, its quotes excluded.
    StrByte,
    /// A string closed, `len` raw bytes between its quotes.
    StrClose {
        len: u64,
        legacy: bool,
    },
}

/// Follows a JSON document byte by byte: the path of each byte (object keys decoded as the
/// parser decodes them, README §2 Untrusted input: the bounds hold however a key is written),
/// and where strings and containers start and end. A malformed document isn't detected here; the
/// parser refuses it.
#[derive(Default)]
struct Tracker {
    stack: Vec<Frame>,
    pos: u64,
    in_str: bool,
    is_key: bool,
    legacy: bool,
    str_start: u64,
    esc: Esc,
    /// The key being read, decoded (at most [`MAX_LABEL`] bytes).
    key: Vec<u8>,
    key_long: bool,
    /// A `u` escape's high surrogate waiting for its low half.
    high: Option<u32>,
}

impl Tracker {
    /// True at the value of `manual_files[].file` or `manual_files[].applied.file`.
    fn at_legacy_file(&self) -> bool {
        let st = &self.stack;
        let is = |i: usize, s: &str| st[i].label.is(s);
        st.last().is_some_and(|f| f.obj)
            && match st.len() {
                3 => is(0, "manual_files") && is(1, "[]") && is(2, "file"),
                4 => is(0, "manual_files") && is(1, "[]") && is(2, "applied") && is(3, "file"),
                _ => false,
            }
    }

    fn push_key_byte(&mut self, b: u8) {
        if self.key.len() < MAX_LABEL {
            self.key.push(b);
        } else {
            self.key_long = true;
        }
    }

    fn push_key_char(&mut self, c: u32) {
        let c = char::from_u32(c).unwrap_or(char::REPLACEMENT_CHARACTER);
        let mut b = [0u8; 4];
        for x in c.encode_utf8(&mut b).as_bytes() {
            self.push_key_byte(*x);
        }
    }

    /// One UTF-16 code unit of a `u` escape in a key.
    fn push_key_unit(&mut self, v: u32) {
        if (0xD800..0xDC00).contains(&v) {
            if self.high.replace(v).is_some() {
                self.push_key_char(0xFFFD);
            }
            return;
        }
        let c = if (0xDC00..0xE000).contains(&v) {
            match self.high.take() {
                Some(h) => 0x10000 + ((h - 0xD800) << 10) + (v - 0xDC00),
                None => 0xFFFD,
            }
        } else {
            if self.high.take().is_some() {
                self.push_key_char(0xFFFD);
            }
            v
        };
        self.push_key_char(c);
    }

    fn step(&mut self, b: u8) -> Ev {
        let at = self.pos;
        self.pos += 1;
        if self.in_str {
            match self.esc {
                Esc::Backslash => {
                    self.esc = Esc::None;
                    if b == b'u' {
                        self.esc = Esc::Hex(4, 0);
                    } else if self.is_key {
                        // Any other escape is malformed: the parser refuses it.
                        self.push_key_char(json_escape(b).unwrap_or(u32::from(b)));
                    }
                    return Ev::StrByte;
                }
                Esc::Hex(left, v) => {
                    // A digit that isn't hex is malformed: the parser refuses it.
                    let v = (v << 4) | char::from(b).to_digit(16).unwrap_or(0);
                    if left > 1 {
                        self.esc = Esc::Hex(left - 1, v);
                    } else {
                        self.esc = Esc::None;
                        if self.is_key {
                            self.push_key_unit(v);
                        }
                    }
                    return Ev::StrByte;
                }
                Esc::None => {}
            }
            return match b {
                b'\\' => {
                    self.esc = Esc::Backslash;
                    Ev::StrByte
                }
                b'"' => {
                    self.in_str = false;
                    if self.is_key {
                        if self.high.take().is_some() {
                            self.push_key_char(0xFFFD);
                        }
                        let label = if self.key_long {
                            Label::Long
                        } else {
                            Label::Key(std::mem::take(&mut self.key))
                        };
                        if let Some(f) = self.stack.last_mut() {
                            f.label = label;
                            f.expect_key = false;
                        }
                    }
                    Ev::StrClose {
                        len: at - self.str_start - 1,
                        legacy: self.legacy,
                    }
                }
                _ => {
                    if self.is_key {
                        if self.high.take().is_some() {
                            self.push_key_char(0xFFFD);
                        }
                        self.push_key_byte(b);
                    }
                    Ev::StrByte
                }
            };
        }
        match b {
            b'"' => {
                self.in_str = true;
                self.str_start = at;
                self.esc = Esc::None;
                self.is_key = self.stack.last().is_some_and(|f| f.obj && f.expect_key);
                self.key.clear();
                self.key_long = false;
                self.high = None;
                self.legacy = !self.is_key && self.at_legacy_file();
                Ev::StrOpen { legacy: self.legacy }
            }
            b'{' | b'[' => {
                self.stack.push(Frame {
                    obj: b == b'{',
                    label: if b == b'[' {
                        Label::List
                    } else {
                        Label::Key(Vec::new())
                    },
                    start: at,
                    expect_key: b == b'{',
                });
                Ev::Open
            }
            b'}' | b']' => match self.stack.pop() {
                Some(f) => Ev::Close(at + 1 - f.start),
                None => Ev::Unbalanced,
            },
            b',' => {
                if let Some(f) = self.stack.last_mut()
                    && f.obj
                {
                    f.expect_key = true;
                }
                Ev::Other
            }
            _ => Ev::Other,
        }
    }

    /// The cap of the container that just closed (its parents are the stack), with its path.
    fn cap(&self) -> Option<(&'static str, u64)> {
        static SPLIT: std::sync::LazyLock<Vec<(Vec<&'static str>, &'static str, u64)>> =
            std::sync::LazyLock::new(|| {
                CAPS.iter()
                    .map(|(p, c)| (p.split('.').collect(), *p, *c))
                    .collect()
            });
        SPLIT
            .iter()
            .find(|(parts, _, _)| {
                parts.len() == self.stack.len() && parts.iter().zip(&self.stack).all(|(p, f)| f.label.is(p))
            })
            .map(|(_, path, cap)| (*path, *cap))
    }
}

/// The pre-scan ([`prescan`]) fed bytes as they come: the restore feeds it the document it
/// received, the export the document it writes, so both apply exactly the same bounds (README §2
/// Bounded: an export a restore would refuse is refused as it is written, naming the part).
#[derive(Default)]
pub struct Prescan {
    t: Tracker,
}

impl Prescan {
    /// Checks the next bytes of the document.
    pub fn feed(&mut self, buf: &[u8]) -> Result<(), String> {
        for &b in buf {
            match self.t.step(b) {
                Ev::Open if self.t.stack.len() > MAX_DEPTH => {
                    return Err(format!("the document nests deeper than {MAX_DEPTH} levels"));
                }
                Ev::Unbalanced => {
                    return Err(format!("an unbalanced bracket at byte {}", self.t.pos - 1));
                }
                // The previous format's single-string manual file streams ([`Normalize`]): only
                // the document's bound and the decoded size's apply to it.
                Ev::StrClose { len, legacy: false } if len > MAX_STRING_BYTES => {
                    return Err(format!(
                        "a string at byte {} is longer than {} MiB (files travel in base64 chunks)",
                        self.t.str_start,
                        MAX_STRING_BYTES / (1024 * 1024)
                    ));
                }
                Ev::Close(size) => {
                    if let Some((path, cap)) = self.t.cap()
                        && size > cap
                    {
                        return Err(format!("{path} is larger than {} MiB", cap / (1024 * 1024)));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// The character the JSON escape `\<b>` stands for (RFC 8259 §7), the `u` escape aside; `None`
/// for a byte no JSON escape takes.
fn json_escape(b: u8) -> Option<u32> {
    Some(match b {
        b'"' | b'\\' | b'/' => u32::from(b),
        b'b' => 0x08,
        b'f' => 0x0c,
        b'n' => 0x0a,
        b'r' => 0x0d,
        b't' => 0x09,
        _ => return None,
    })
}

/// Base64 characters per chunk a previous-format single-string file is cut into (a multiple of
/// 4, so each chunk decodes on its own; [`super::CHUNK_BYTES`] decoded).
const LEGACY_CHUNK_CHARS: usize = super::CHUNK_BYTES / 3 * 4;

/// Reads a document with each previous-format single-string manual file (README §2
/// Compatibility: release N reads N−1's exports) turned into this format's chunk list as the
/// bytes go by, so the parser never holds such a file whole (core.md §3). Inside such a string,
/// JSON's escapes are decoded; a character outside base64's alphabet, or data after padding,
/// becomes `!`, which the decoder refuses as it would the whole string; and what JSON doesn't
/// allow in a string (an escape it doesn't have, a control character) is passed on as written,
/// so the parser refuses the document as malformed: a document JSON refuses is never one that
/// parses here.
pub struct Normalize<R> {
    inner: R,
    t: Tracker,
    /// Bytes ready for the reader.
    out: std::collections::VecDeque<u8>,
    buf: Box<[u8]>,
    /// Inside a legacy string: its escape state, characters in the current chunk, padding seen.
    esc: Esc,
    in_chunk: usize,
    padded: bool,
}

impl<R: Read> Normalize<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            t: Tracker::default(),
            out: std::collections::VecDeque::new(),
            buf: vec![0u8; 64 * 1024].into_boxed_slice(),
            esc: Esc::None,
            in_chunk: 0,
            padded: false,
        }
    }

    /// One decoded character of a legacy string.
    fn legacy_char(&mut self, c: u32) {
        let ok = matches!(
            char::from_u32(c),
            Some('A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' | '=')
        );
        let c = match char::from_u32(c) {
            Some('=') if ok => {
                self.padded = true;
                b'='
            }
            Some(ch) if ok && !self.padded => ch as u8,
            _ => b'!',
        };
        if self.in_chunk == LEGACY_CHUNK_CHARS {
            self.out.extend(b"\",\"");
            self.in_chunk = 0;
        }
        self.out.push_back(c);
        self.in_chunk += 1;
    }

    fn byte(&mut self, b: u8) {
        let legacy = self.t.legacy;
        match self.t.step(b) {
            Ev::StrOpen { legacy: true } => {
                self.esc = Esc::None;
                self.in_chunk = 0;
                self.padded = false;
                self.out.extend(b"[\"");
            }
            Ev::StrClose { legacy: true, .. } => self.out.extend(b"\"]"),
            Ev::StrByte if legacy => match self.esc {
                Esc::None if b == b'\\' => self.esc = Esc::Backslash,
                // A control character can't stand in a JSON string: passed on as written, the
                // parser refuses the document as malformed.
                Esc::None if b < 0x20 => self.out.push_back(b),
                Esc::None => self.legacy_char(u32::from(b)),
                Esc::Backslash if b == b'u' => self.esc = Esc::Hex(4, 0),
                Esc::Backslash => {
                    self.esc = Esc::None;
                    match json_escape(b) {
                        Some(c) => self.legacy_char(c),
                        // Not a JSON escape (README §2 Untrusted input): it goes to the parser as
                        // written, which refuses the document as malformed (api.md §7: `422`), as
                        // it would the string unnormalised.
                        None => self.out.extend([b'\\', b]),
                    }
                }
                Esc::Hex(left, v) => match char::from(b).to_digit(16) {
                    Some(d) if left > 1 => self.esc = Esc::Hex(left - 1, (v << 4) | d),
                    Some(d) => {
                        self.esc = Esc::None;
                        self.legacy_char((v << 4) | d);
                    }
                    // A `u` escape with a digit that isn't hex: as above, the parser refuses it.
                    None => {
                        self.esc = Esc::None;
                        self.out.extend([b'\\', b'u', b]);
                    }
                },
            },
            _ => self.out.push_back(b),
        }
    }
}

impl<R: Read> Read for Normalize<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.out.is_empty() {
            let n = self.inner.read(&mut self.buf)?;
            if n == 0 {
                return Ok(0);
            }
            let buf = std::mem::take(&mut self.buf);
            for &b in &buf[..n] {
                self.byte(b);
            }
            self.buf = buf;
        }
        let n = out.len().min(self.out.len());
        for (o, b) in out.iter_mut().zip(self.out.drain(..n)) {
            *o = b;
        }
        Ok(n)
    }
}

/// The parts of a document held in memory.
#[derive(Clone, Debug, Default)]
pub struct Head {
    pub format_version: u32,
    pub exported_at: Option<String>,
    pub core_version: Option<String>,
    pub configuration: Configuration,
    pub feed_feeds: Vec<FeedPart>,
    pub feed_providers: Vec<ProviderPart>,
}

/// A decoded file: its BLAKE3, size and, when decoded into `staging/`, its file there (deleted
/// when this is dropped).
#[derive(Debug, Default)]
pub struct Decoded {
    pub b3: String,
    pub size: u64,
    pub path: Option<PathBuf>,
}

impl Drop for Decoded {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// One manual feed's file as read (pass 1).
#[derive(Debug, Default)]
pub struct ManualMeta {
    pub feed: String,
    pub version: Option<String>,
    pub saved_at: Option<String>,
    pub file: Decoded,
    /// The latest applied run's blob, with its version and `updated_at`.
    pub applied: Option<(Decoded, Option<String>, Option<String>)>,
}

/// An alert's child tables, as the document names them.
pub const ALERT_CHILDREN: &[(&str, &str)] = &[
    ("history", "alert_history"),
    ("evidence", "alert_evidence"),
    ("evidence_counts", "alert_evidence_counts"),
    ("evidence_answers", "alert_evidence_answers"),
    ("wire_examples", "wire_examples"),
];

/// Where [`parse`] hands the streamed parts.
pub trait Sink {
    /// Where to decode manual files (pass 1): `Some(dir)` into files there, `None` only hashing
    /// them. Pass 2 skips them (`decode` false).
    fn decode(&self) -> bool;
    fn staging(&self) -> Option<&Path>;
    fn manual_file(&mut self, m: ManualMeta) -> anyhow::Result<()>;
    /// An alert's `alerts` row.
    fn alert(&mut self, row: Map<String, Value>) -> anyhow::Result<()>;
    /// A row of one of the alert's child tables (`alert_history`, …, `alert_evidence_rules`).
    fn alert_row(&mut self, table: &'static str, row: Map<String, Value>) -> anyhow::Result<()>;
    /// The end of one alert.
    fn alert_end(&mut self) -> anyhow::Result<()>;
    fn check(&mut self, c: CheckPart) -> anyhow::Result<()>;
    fn change(&mut self, row: Map<String, Value>) -> anyhow::Result<()>;
}

/// Reads the document at `path` (checked by [`prescan`]) into `sink`.
pub fn parse(path: &Path, sink: &mut dyn Sink) -> Result<Head, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("cannot read the document: {e}"))?;
    parse_reader(BufReader::with_capacity(256 * 1024, f), sink)
}

/// [`parse`] from any reader (tests and the fuzz target).
pub fn parse_reader(r: impl Read, sink: &mut dyn Sink) -> Result<Head, String> {
    let mut de = serde_json::Deserializer::from_reader(Normalize::new(r));
    let head = DocSeed { sink }
        .deserialize(&mut de)
        .map_err(|e| format!("not a config export: {e}"))?;
    de.end().map_err(|e| format!("not a config export: {e}"))?;
    Ok(head)
}

fn custom<E: de::Error>(e: anyhow::Error) -> E {
    E::custom(format!("{e:#}"))
}

struct DocSeed<'a> {
    sink: &'a mut dyn Sink,
}

impl<'de> DeserializeSeed<'de> for DocSeed<'_> {
    type Value = Head;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Head, D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for DocSeed<'_> {
    type Value = Head;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a config export document (a JSON object)")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Head, A::Error> {
        let mut head = Head::default();
        let mut seen_version = false;
        while let Some(k) = m.next_key::<String>()? {
            match k.as_str() {
                "format_version" => {
                    head.format_version = m.next_value()?;
                    seen_version = true;
                }
                "exported_at" => head.exported_at = m.next_value()?,
                "core_version" => head.core_version = m.next_value()?,
                "configuration" => head.configuration = m.next_value()?,
                "manual_files" => m.next_value_seed(ManualFiles {
                    sink: &mut *self.sink,
                })?,
                "alerts" => m.next_value_seed(Alerts {
                    sink: &mut *self.sink,
                })?,
                "feed_state" => m.next_value_seed(FeedState {
                    sink: &mut *self.sink,
                    head: &mut head,
                })?,
                "config_changes" => m.next_value_seed(Rows {
                    sink: &mut *self.sink,
                    what: Rowed::Change,
                })?,
                // Another release's part (README §2 Compatibility): skipped without buffering.
                _ => {
                    m.next_value::<IgnoredAny>()?;
                }
            }
        }
        if !seen_version {
            return Err(de::Error::missing_field("format_version"));
        }
        Ok(head)
    }
}

/// Where a streamed row goes.
#[derive(Clone, Copy)]
enum Rowed {
    Change,
    AlertChild(&'static str),
}

/// A list of rows, each handed to the sink as it is read.
struct Rows<'a> {
    sink: &'a mut dyn Sink,
    what: Rowed,
}

impl<'de> DeserializeSeed<'de> for Rows<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for Rows<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of rows")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<(), A::Error> {
        while let Some(row) = s.next_element::<Map<String, Value>>()? {
            match self.what {
                Rowed::Change => self.sink.change(row),
                Rowed::AlertChild(t) => self.sink.alert_row(t, row),
            }
            .map_err(custom)?;
        }
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
}

struct Alerts<'a> {
    sink: &'a mut dyn Sink,
}

impl<'de> DeserializeSeed<'de> for Alerts<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for Alerts<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of alerts")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<(), A::Error> {
        while s
            .next_element_seed(OneAlert {
                sink: &mut *self.sink,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
}

struct OneAlert<'a> {
    sink: &'a mut dyn Sink,
}

impl<'de> DeserializeSeed<'de> for OneAlert<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for OneAlert<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an alert with its rows")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<(), A::Error> {
        while let Some(k) = m.next_key::<String>()? {
            if k == "alert" {
                let row: Map<String, Value> = m.next_value()?;
                self.sink.alert(row).map_err(custom)?;
            } else if k == "evidence_rule" {
                if let Some(row) = m.next_value::<Option<Map<String, Value>>>()? {
                    self.sink.alert_row("alert_evidence_rules", row).map_err(custom)?;
                }
            } else if let Some((_, table)) = ALERT_CHILDREN.iter().find(|(n, _)| *n == k) {
                m.next_value_seed(Rows {
                    sink: &mut *self.sink,
                    what: Rowed::AlertChild(table),
                })?;
            } else {
                m.next_value::<IgnoredAny>()?;
            }
        }
        self.sink.alert_end().map_err(custom)
    }
}

struct FeedState<'a> {
    sink: &'a mut dyn Sink,
    head: &'a mut Head,
}

impl<'de> DeserializeSeed<'de> for FeedState<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for FeedState<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the feeds' state and check history")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<(), A::Error> {
        while let Some(k) = m.next_key::<String>()? {
            match k.as_str() {
                "feeds" => self.head.feed_feeds = m.next_value()?,
                "providers" => self.head.feed_providers = m.next_value()?,
                "checks" => m.next_value_seed(Checks {
                    sink: &mut *self.sink,
                })?,
                _ => {
                    m.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
}

struct Checks<'a> {
    sink: &'a mut dyn Sink,
}

impl<'de> DeserializeSeed<'de> for Checks<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for Checks<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of feed checks")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<(), A::Error> {
        while let Some(c) = s.next_element::<CheckPart>()? {
            self.sink.check(c).map_err(custom)?;
        }
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
}

struct ManualFiles<'a> {
    sink: &'a mut dyn Sink,
}

impl<'de> DeserializeSeed<'de> for ManualFiles<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        if self.sink.decode() {
            d.deserialize_seq(self)
        } else {
            IgnoredAny::deserialize(d).map(|_| ())
        }
    }
}

impl<'de> Visitor<'de> for ManualFiles<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of manual files")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<(), A::Error> {
        loop {
            let staging = self.sink.staging().map(Path::to_path_buf);
            let Some(m) = s.next_element_seed(OneManual { staging })? else {
                break;
            };
            self.sink.manual_file(m).map_err(custom)?;
        }
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
}

struct OneManual {
    staging: Option<PathBuf>,
}

impl<'de> DeserializeSeed<'de> for OneManual {
    type Value = ManualMeta;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<ManualMeta, D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for OneManual {
    type Value = ManualMeta;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a manual feed's file")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<ManualMeta, A::Error> {
        let mut out = ManualMeta::default();
        let mut file: Option<Decoded> = None;
        while let Some(k) = m.next_key::<String>()? {
            match k.as_str() {
                "feed" => out.feed = m.next_value()?,
                "version" => out.version = m.next_value()?,
                "saved_at" => out.saved_at = m.next_value()?,
                "file" => {
                    file = Some(m.next_value_seed(FileSeed {
                        staging: self.staging.as_deref(),
                    })?)
                }
                "applied" => {
                    out.applied = m.next_value_seed(AppliedSeed {
                        staging: self.staging.as_deref(),
                    })?
                }
                _ => {
                    m.next_value::<IgnoredAny>()?;
                }
            }
        }
        out.file = file.ok_or_else(|| de::Error::missing_field("file"))?;
        Ok(out)
    }
}

struct AppliedSeed<'a> {
    staging: Option<&'a Path>,
}

impl<'de> DeserializeSeed<'de> for AppliedSeed<'_> {
    type Value = Option<(Decoded, Option<String>, Option<String>)>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_option(self)
    }
}

impl<'de> Visitor<'de> for AppliedSeed<'_> {
    type Value = Option<(Decoded, Option<String>, Option<String>)>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an applied blob or null")
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_map(self)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
        let (mut file, mut version, mut updated_at) = (None, None, None);
        while let Some(k) = m.next_key::<String>()? {
            match k.as_str() {
                "file" => {
                    file = Some(m.next_value_seed(FileSeed {
                        staging: self.staging,
                    })?)
                }
                "version" => version = m.next_value()?,
                "updated_at" => updated_at = m.next_value()?,
                _ => {
                    m.next_value::<IgnoredAny>()?;
                }
            }
        }
        let file = file.ok_or_else(|| de::Error::missing_field("file"))?;
        Ok(Some((file, version, updated_at)))
    }
}

/// A file in base64: one string, or a list of chunks each decoding on its own (module docs).
/// Decoded as it is read: hashed, size-checked and, with a staging directory, written there.
struct FileSeed<'a> {
    staging: Option<&'a Path>,
}

/// Decodes chunks into a hasher and an optional file.
struct FileWriter {
    hasher: blake3::Hasher,
    size: u64,
    out: Option<(PathBuf, std::io::BufWriter<std::fs::File>)>,
}

impl FileWriter {
    fn new(staging: Option<&Path>) -> anyhow::Result<Self> {
        let out = match staging {
            Some(dir) => {
                crate::util::ensure_dir(dir)?;
                let p = dir.join(format!("restore-file-{}.tmp", crate::util::random_hex(8)));
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&p)?;
                Some((p, std::io::BufWriter::new(f)))
            }
            None => None,
        };
        Ok(Self {
            hasher: blake3::Hasher::new(),
            size: 0,
            out,
        })
    }

    fn chunk(&mut self, b64: &str) -> anyhow::Result<()> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| anyhow::anyhow!("a manual file isn't base64"))?;
        self.size += bytes.len() as u64;
        if self.size > MAX_FILE_BYTES {
            anyhow::bail!(
                "a manual file is larger than {} MiB",
                MAX_FILE_BYTES / (1024 * 1024)
            );
        }
        self.hasher.update(&bytes);
        if let Some((_, w)) = self.out.as_mut() {
            w.write_all(&bytes)?;
        }
        Ok(())
    }

    fn finish(mut self) -> anyhow::Result<Decoded> {
        let path = match self.out.take() {
            Some((p, w)) => {
                let f = w.into_inner().map_err(|e| e.into_error())?;
                f.sync_all()?;
                Some(p)
            }
            None => None,
        };
        Ok(Decoded {
            b3: self.hasher.finalize().to_hex().to_string(),
            size: self.size,
            path,
        })
    }
}

impl Drop for FileWriter {
    fn drop(&mut self) {
        if let Some((p, _)) = self.out.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl<'de> DeserializeSeed<'de> for FileSeed<'_> {
    type Value = Decoded;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Decoded, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for FileSeed<'_> {
    type Value = Decoded;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a file in base64: a string or a list of chunks")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Decoded, E> {
        let mut w = FileWriter::new(self.staging).map_err(custom)?;
        w.chunk(v).map_err(custom)?;
        w.finish().map_err(custom)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Decoded, A::Error> {
        let mut w = FileWriter::new(self.staging).map_err(custom)?;
        while let Some(chunk) = s.next_element::<std::borrow::Cow<'de, str>>()? {
            w.chunk(&chunk).map_err(custom)?;
        }
        w.finish().map_err(custom)
    }
}

/// What the first pass gathers and checks while it reads (the restore's step 1, core.md §2:
/// "one bad reference rejects the whole document").
#[derive(Debug, Default)]
pub struct Checker {
    /// Where manual files are decoded; `None` only hashes them (the fuzz target).
    pub staging: Option<PathBuf>,
    pub manual: Vec<ManualMeta>,
    pub alerts: usize,
    pub changes: usize,
    pub checks: usize,
    alert_ids: BTreeSet<i64>,
    /// The current alert's id and the `alert_id`s its rows name.
    current: Option<i64>,
    row_ids: BTreeSet<i64>,
    rows: BTreeMap<&'static str, usize>,
    /// Feed providers and feeds the check history names.
    pub check_providers: BTreeSet<String>,
    pub check_feeds: BTreeSet<String>,
}

/// Bounds the first pass checks (README §2 Bounded).
pub mod limits {
    /// Alerts one document may hold.
    pub const MAX_ALERTS: usize = 100_000;
    /// Rows one alert's child table may hold: past `alerts.evidence_per_alert`'s largest value
    /// with room for the answers and counts beside the copies.
    pub const MAX_ALERT_ROWS: usize = 250_000;
    /// `config_changes` rows a document may hold.
    pub const MAX_CHANGES: usize = 1_000_000;
    /// Check-history entries a document may hold.
    pub const MAX_CHECKS: usize = 5_000_000;
    /// Distinct feeds or providers the check history may name.
    pub const MAX_NAMED: usize = 100_000;
    /// Manual files a document may hold.
    pub const MAX_MANUAL: usize = 10_000;
}

impl Checker {
    /// A first pass that decodes manual files into `staging` (`None`: hashes them only).
    pub fn new(staging: Option<PathBuf>) -> Self {
        Self {
            staging,
            ..Self::default()
        }
    }
}

impl Sink for Checker {
    fn decode(&self) -> bool {
        true
    }

    fn staging(&self) -> Option<&Path> {
        self.staging.as_deref()
    }

    fn manual_file(&mut self, m: ManualMeta) -> anyhow::Result<()> {
        if self.manual.len() >= limits::MAX_MANUAL {
            anyhow::bail!("the export holds too many manual files");
        }
        self.manual.push(m);
        Ok(())
    }

    fn alert(&mut self, row: Map<String, Value>) -> anyhow::Result<()> {
        let id = row.get("id").and_then(Value::as_i64);
        let key = row.get("dedupe_key").and_then(Value::as_str);
        let (Some(id), Some(_), Some(_)) = (id, key, row.get("kind").and_then(Value::as_str)) else {
            anyhow::bail!("an alert without its id, kind or dedupe key");
        };
        if self.current.is_some() {
            anyhow::bail!("an alert holds two alert rows");
        }
        if !self.alert_ids.insert(id) {
            anyhow::bail!("the export holds alert {id} twice");
        }
        self.current = Some(id);
        Ok(())
    }

    fn alert_row(&mut self, table: &'static str, row: Map<String, Value>) -> anyhow::Result<()> {
        let n = self.rows.entry(table).or_default();
        *n += 1;
        if *n > limits::MAX_ALERT_ROWS {
            anyhow::bail!("an alert holds too many {table} rows");
        }
        let Some(id) = row.get("alert_id").and_then(Value::as_i64) else {
            anyhow::bail!("a {table} row without its alert_id");
        };
        if self.row_ids.len() < 4 {
            self.row_ids.insert(id);
        } else if !self.row_ids.contains(&id) {
            anyhow::bail!("an alert's {table} row names another alert");
        }
        Ok(())
    }

    fn alert_end(&mut self) -> anyhow::Result<()> {
        let Some(id) = self.current.take() else {
            anyhow::bail!("an alert without its alert row");
        };
        if self.row_ids.iter().any(|x| *x != id) {
            anyhow::bail!("alert {id}'s rows name another alert");
        }
        self.row_ids.clear();
        self.rows.clear();
        self.alerts += 1;
        if self.alerts > limits::MAX_ALERTS {
            anyhow::bail!("the export holds too many alerts");
        }
        Ok(())
    }

    fn check(&mut self, c: CheckPart) -> anyhow::Result<()> {
        self.checks += 1;
        if self.checks > limits::MAX_CHECKS {
            anyhow::bail!("the export holds too much feed check history");
        }
        if let Some(p) = c.provider {
            self.check_providers.insert(p);
        }
        for f in c.feeds {
            self.check_feeds.insert(f.feed);
        }
        if self.check_providers.len() > limits::MAX_NAMED || self.check_feeds.len() > limits::MAX_NAMED {
            anyhow::bail!("the export's check history names too many feeds or providers");
        }
        Ok(())
    }

    fn change(&mut self, _row: Map<String, Value>) -> anyhow::Result<()> {
        self.changes += 1;
        if self.changes > limits::MAX_CHANGES {
            anyhow::bail!("the export holds too many changes");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prescan_bounds_strings_depth_and_parts() {
        assert!(prescan(&br#"{"format_version": 1, "a": "x"}"#[..]).is_ok());
        let long = format!(r#"{{"x": "{}"}}"#, "a".repeat(MAX_STRING_BYTES as usize + 1));
        assert!(prescan(long.as_bytes()).unwrap_err().contains("longer than"));
        let deep = "[".repeat(MAX_DEPTH + 1);
        assert!(prescan(deep.as_bytes()).unwrap_err().contains("deeper"));
        // An escaped quote doesn't end a string; a part past its cap is refused.
        let row = format!(r#"{{"k": "{}"}}"#, "\\\"".repeat(1024));
        let changes = format!(r#"{{"config_changes": [{row}, {row}]}}"#);
        assert!(prescan(changes.as_bytes()).is_ok());
        let big = format!(
            r#"{{"configuration": {{"x": [{}]}}}}"#,
            vec![format!("\"{}\"", "a".repeat(1 << 20)); 17].join(",")
        );
        assert!(prescan(big.as_bytes()).unwrap_err().contains("configuration"));
    }

    #[test]
    fn files_decode_from_a_string_or_chunks() {
        let doc = br#"{"format_version": 1, "manual_files": [
            {"feed": "a", "file": "aGVsbG8K"},
            {"feed": "b", "file": ["aGVs", "bG8K"], "applied": {"file": ["aGk="], "version": "v"}},
            {"feed": "c", "file": ["!!"]}
        ]}"#;
        let mut c = Checker::default();
        let e = parse_reader(&doc[..], &mut c).unwrap_err();
        assert!(e.contains("base64"), "{e}");
        let doc = br#"{"format_version": 1, "manual_files": [
            {"feed": "a", "file": "aGVsbG8K"},
            {"feed": "b", "file": ["aGVs", "bG8K"], "applied": {"file": ["aGk="], "version": "v"}}
        ], "later": {"ignored": [1, 2]}}"#;
        let mut c = Checker::default();
        parse_reader(&doc[..], &mut c).unwrap();
        assert_eq!(c.manual.len(), 2);
        assert_eq!(c.manual[0].file.b3, c.manual[1].file.b3, "the same bytes");
        assert_eq!(c.manual[0].file.size, 6);
        assert_eq!(c.manual[1].applied.as_ref().unwrap().0.size, 2);
    }

    /// README §2 Compatibility (review round 2, R5): a previous-format single-string file (here
    /// with escaped solidi) reaches the parser as chunks no longer than one, and decodes to the
    /// same bytes; data after padding or outside base64 is refused as in one string.
    #[test]
    fn previous_format_single_string_files_stream_in_chunks() {
        let file: Vec<u8> = (0..(LEGACY_CHUNK_CHARS / 4 * 3 * 2 + 5))
            .map(|i| (i * 7) as u8)
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&file);
        let escaped = b64.replace('/', "\\/");
        assert!(escaped.len() > b64.len(), "the file has solidi to escape");
        let doc = format!(
            r#"{{"format_version": 1, "manual_files": [{{"feed": "a", "file": "{escaped}", "applied": {{"file": "{b64}"}}}}]}}"#
        );
        assert!(prescan(doc.as_bytes()).is_ok());
        let mut c = Checker::default();
        parse_reader(doc.as_bytes(), &mut c).unwrap();
        let want = blake3::hash(&file).to_hex().to_string();
        assert_eq!(c.manual[0].file.size, file.len() as u64);
        assert_eq!(c.manual[0].file.b3, want);
        assert_eq!(c.manual[0].applied.as_ref().unwrap().0.b3, want);
        let mut out = String::new();
        Normalize::new(doc.as_bytes()).read_to_string(&mut out).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let chunks = v["manual_files"][0]["file"].as_array().unwrap();
        assert_eq!(chunks.len(), 3);
        assert!(
            chunks
                .iter()
                .all(|c| c.as_str().unwrap().len() <= LEGACY_CHUNK_CHARS)
        );
        for bad in ["AA==AAAA", "AA!A"] {
            let doc =
                format!(r#"{{"format_version": 1, "manual_files": [{{"feed": "a", "file": "{bad}"}}]}}"#);
            let e = parse_reader(doc.as_bytes(), &mut Checker::default()).unwrap_err();
            assert!(e.contains("base64"), "{bad}: {e}");
        }
        // What JSON doesn't allow in a string stays malformed (final check, round 3), whatever
        // base64 the string would make without it.
        for bad in [r"\QUFB", r"AA\u00G1AA", r#"AA\u0"AA"#, "AA\u{1}AA"] {
            let doc =
                format!(r#"{{"format_version": 1, "manual_files": [{{"feed": "a", "file": "{bad}"}}]}}"#);
            assert!(serde_json::from_str::<Value>(&doc).is_err(), "{bad}");
            let e = parse_reader(doc.as_bytes(), &mut Checker::default()).unwrap_err();
            assert!(
                e.contains("escape") || e.contains("control character"),
                "{bad}: {e}"
            );
        }
    }

    #[test]
    fn alerts_stream_with_their_rows_checked() {
        let ok = br#"{"format_version": 1, "alerts": [
            {"history": [{"alert_id": 7, "at": "t"}], "alert": {"id": 7, "kind": "k", "dedupe_key": "d"}},
            {"alert": {"id": 8, "kind": "k", "dedupe_key": "e"}, "evidence_rule": null}
        ]}"#;
        let mut c = Checker::default();
        parse_reader(&ok[..], &mut c).unwrap();
        assert_eq!(c.alerts, 2);
        for bad in [
            &br#"{"format_version": 1, "alerts": [{"alert": {"id": 7, "kind": "k"}}]}"#[..],
            &br#"{"format_version": 1, "alerts": [{"alert": {"id": 7, "kind": "k", "dedupe_key": "d"}, "evidence": [{"alert_id": 9}]}]}"#[..],
            &br#"{"format_version": 1, "alerts": [{"alert": {"id": 7, "kind": "k", "dedupe_key": "d"}}, {"alert": {"id": 7, "kind": "k", "dedupe_key": "x"}}]}"#[..],
            &br#"{"alerts": []}"#[..],
        ] {
            let mut c = Checker::default();
            assert!(parse_reader(bad, &mut c).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }
}
