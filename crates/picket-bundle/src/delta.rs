//! Delta files (bundles.md §5): gzip JSON lines, one header line, then ops.
//!
//! ```text
//! domain: {"bundle":"b","shard":3,"base":"<id>","seq":42,"prev_checksum":"…","new_checksum":"…","created_at":"…"}
//!         {"op":"upsert","key":"com.example.ads","value":3}
//!         {"op":"delete","key":"net.example.old"}
//! cold:   as domain, with "cold_shard" for "shard" and "mid_checksum" (after the upserts)
//! IP:     {"bundle":"b","ip_shard":"v4/45",…}
//!         {"op":"upsert","range":["45.12.0.0","45.12.3.255"],"value":1}
//!         {"op":"delete","range":["45.12.4.0","45.12.7.255"]}
//! verdict set (providers.md §4): {"provider":"p","generation":"…","base":"<id>","seq":…,…}
//!         {"op":"upsert","key":"<32 hex hash>","value":{"verdict":"block","obtained_at":"…","score":7.5,"reason":"…"}}
//! ```
//!
//! The writer emits upserts then deletes, each sorted by key (or first address), so a delta is
//! byte-identical for the same changes. The reader bounds the decompressed size, the line length
//! and the op count before allocating (README §2 "Untrusted input").

use std::io::{BufRead, BufReader, Read, Write};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::checksum::SetChecksum;
use crate::ips::IpShardId;
use crate::value::Value;

/// Largest decompressed delta the reader accepts: room for [`MAX_OPS`] ops of ~100 bytes
/// (README §2 "Bounded"; review round 1, B8).
pub const MAX_DELTA_BYTES: u64 = 64 * 1024 * 1024;
/// Longest line.
pub const MAX_LINE: usize = 64 * 1024;
/// Most ops in one delta: 512 Ki, the entries of a 16 MiB overlay at ~30 B each (the largest
/// default `overlay_budget_mib`, edge.md §17). Core compacts before a delta would push an edge's
/// overlays past its budget (bundles.md §5), so a longer delta is never needed; parsed, it costs at
/// most ~40 MB while the overlay is rebuilt. Policy bound (owner to confirm).
pub const MAX_OPS: usize = 512 * 1024;

/// Why a delta is refused.
#[derive(Debug, thiserror::Error)]
pub enum DeltaError {
    #[error("delta gzip/io: {0}")]
    Io(#[from] std::io::Error),
    #[error("delta is larger than {MAX_DELTA_BYTES} bytes decompressed")]
    TooLarge,
    #[error("delta line {0} is too long")]
    LineTooLong(usize),
    #[error("delta line {line}: {source}")]
    Json { line: usize, source: serde_json::Error },
    #[error("delta has no header")]
    NoHeader,
    #[error("delta line {0}: bad op: {1}")]
    Op(usize, &'static str),
    #[error("delta has more than {MAX_OPS} ops")]
    TooManyOps,
    #[error("delta header doesn't fit this part: {0}")]
    Header(&'static str),
}

/// A delta's header line (domain, cold and IP deltas).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaHeader {
    pub bundle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cold_shard: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_shard: Option<IpShardId>,
    pub base: String,
    pub seq: u64,
    pub prev_checksum: SetChecksum,
    /// Cold deltas: the set checksum after the upserts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mid_checksum: Option<SetChecksum>,
    pub new_checksum: SetChecksum,
    pub created_at: String,
}

/// A domain or cold delta op.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeyOp {
    Upsert { key: Vec<u8>, value: Value },
    Delete { key: Vec<u8> },
}

impl KeyOp {
    pub fn key(&self) -> &[u8] {
        match self {
            KeyOp::Upsert { key, .. } | KeyOp::Delete { key } => key,
        }
    }
}

/// An IP delta op on a run (IPv4 in the low 32 bits).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RangeOp {
    Upsert { first: u128, last: u128, value: Value },
    Delete { first: u128, last: u128 },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum KeyOpLine {
    Upsert { key: String, value: u64 },
    Delete { key: String },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum RangeOpLine {
    Upsert { range: [String; 2], value: u64 },
    Delete { range: [String; 2] },
}

/// A parsed domain or cold delta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyDelta {
    pub header: DeltaHeader,
    pub ops: Vec<KeyOp>,
}

/// A parsed IP delta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeDelta {
    pub header: DeltaHeader,
    pub ops: Vec<RangeOp>,
}

/// Checks a key: a reversed name of 1–253 printable ASCII bytes.
pub fn valid_key(k: &[u8]) -> bool {
    !k.is_empty() && k.len() <= 253 && k.iter().all(|&b| (0x21..=0x7e).contains(&b))
}

pub(crate) fn gzip(lines: &[Vec<u8>]) -> Vec<u8> {
    let mut enc = flate2::GzBuilder::new().write(Vec::new(), flate2::Compression::default());
    for l in lines {
        let _ = enc.write_all(l);
        let _ = enc.write_all(b"\n");
    }
    enc.finish().unwrap_or_default()
}

/// Reads the lines of a gzip JSON-lines file within the limits, calling `f(line_no, line)` (1-based)
/// for each non-empty line.
pub(crate) fn read_lines(
    data: &[u8],
    mut f: impl FnMut(usize, &[u8]) -> Result<(), DeltaError>,
) -> Result<(), DeltaError> {
    let dec = flate2::read::GzDecoder::new(data);
    let mut r = BufReader::new(dec.take(MAX_DELTA_BYTES.saturating_add(1)));
    let mut total = 0u64;
    let mut line = Vec::new();
    let mut n = 0usize;
    loop {
        line.clear();
        let got = (&mut r)
            .take(u64::try_from(MAX_LINE).unwrap_or(u64::MAX).saturating_add(1))
            .read_until(b'\n', &mut line)?;
        if got == 0 {
            break;
        }
        n = n.saturating_add(1);
        total = total.saturating_add(got as u64);
        if total > MAX_DELTA_BYTES {
            return Err(DeltaError::TooLarge);
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        } else if got > MAX_LINE {
            return Err(DeltaError::LineTooLong(n));
        }
        if line.len() > MAX_LINE {
            return Err(DeltaError::LineTooLong(n));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        f(n, &line)?;
    }
    Ok(())
}

fn json<'a, T: Deserialize<'a>>(line: usize, b: &'a [u8]) -> Result<T, DeltaError> {
    serde_json::from_slice(b).map_err(|source| DeltaError::Json { line, source })
}

/// Writes a domain or cold delta: upserts then deletes, each sorted by key.
pub fn write_key_delta(header: &DeltaHeader, ops: &[KeyOp]) -> Vec<u8> {
    let mut ups: Vec<&KeyOp> = ops.iter().filter(|o| matches!(o, KeyOp::Upsert { .. })).collect();
    let mut dels: Vec<&KeyOp> = ops.iter().filter(|o| matches!(o, KeyOp::Delete { .. })).collect();
    ups.sort_by(|a, b| a.key().cmp(b.key()));
    dels.sort_by(|a, b| a.key().cmp(b.key()));
    let mut lines = vec![serde_json::to_vec(header).unwrap_or_default()];
    for op in ups.into_iter().chain(dels) {
        let line = match op {
            KeyOp::Upsert { key, value } => KeyOpLine::Upsert {
                key: String::from_utf8_lossy(key).into_owned(),
                value: value.0,
            },
            KeyOp::Delete { key } => KeyOpLine::Delete {
                key: String::from_utf8_lossy(key).into_owned(),
            },
        };
        lines.push(serde_json::to_vec(&line).unwrap_or_default());
    }
    gzip(&lines)
}

/// Parses a domain or cold delta.
pub fn read_key_delta(data: &[u8]) -> Result<KeyDelta, DeltaError> {
    let mut header: Option<DeltaHeader> = None;
    let mut ops = Vec::new();
    read_lines(data, |n, line| {
        if header.is_none() {
            header = Some(json(n, line)?);
            return Ok(());
        }
        if ops.len() >= MAX_OPS {
            return Err(DeltaError::TooManyOps);
        }
        let op = match json::<KeyOpLine>(n, line)? {
            KeyOpLine::Upsert { key, value } => KeyOp::Upsert {
                key: key.into_bytes(),
                value: Value::from_stored(value),
            },
            KeyOpLine::Delete { key } => KeyOp::Delete {
                key: key.into_bytes(),
            },
        };
        if !valid_key(op.key()) {
            return Err(DeltaError::Op(n, "key"));
        }
        ops.push(op);
        Ok(())
    })?;
    let header = header.ok_or(DeltaError::NoHeader)?;
    Ok(KeyDelta { header, ops })
}

fn addr_text(v4: bool, a: u128) -> String {
    picket_rules::ip::go_ip_string(addr_ip(v4, a))
}

/// An address (IPv4 in the low 32 bits) as an `IpAddr`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "an IPv4 address is the low 32 bits"
)]
pub fn addr_ip(v4: bool, a: u128) -> IpAddr {
    if v4 {
        IpAddr::V4(std::net::Ipv4Addr::from(a as u32))
    } else {
        IpAddr::V6(std::net::Ipv6Addr::from(a))
    }
}

fn parse_addr(v4: bool, s: &str) -> Option<u128> {
    match s.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) if v4 => Some(u128::from(u32::from(a))),
        IpAddr::V6(a) if !v4 && a.to_ipv4_mapped().is_none() => Some(u128::from(a)),
        _ => None,
    }
}

/// Writes an IP delta: upserts then deletes, each sorted by first address.
pub fn write_range_delta(header: &DeltaHeader, ops: &[RangeOp]) -> Vec<u8> {
    let v4 = header.ip_shard.is_some_and(IpShardId::is_v4);
    let first = |o: &RangeOp| match o {
        RangeOp::Upsert { first, .. } | RangeOp::Delete { first, .. } => *first,
    };
    let mut ups: Vec<&RangeOp> = ops
        .iter()
        .filter(|o| matches!(o, RangeOp::Upsert { .. }))
        .collect();
    let mut dels: Vec<&RangeOp> = ops
        .iter()
        .filter(|o| matches!(o, RangeOp::Delete { .. }))
        .collect();
    ups.sort_by_key(|o| first(o));
    dels.sort_by_key(|o| first(o));
    let mut lines = vec![serde_json::to_vec(header).unwrap_or_default()];
    for op in ups.into_iter().chain(dels) {
        let line = match *op {
            RangeOp::Upsert { first, last, value } => RangeOpLine::Upsert {
                range: [addr_text(v4, first), addr_text(v4, last)],
                value: value.0,
            },
            RangeOp::Delete { first, last } => RangeOpLine::Delete {
                range: [addr_text(v4, first), addr_text(v4, last)],
            },
        };
        lines.push(serde_json::to_vec(&line).unwrap_or_default());
    }
    gzip(&lines)
}

/// Parses an IP delta; every range must be inside the header's shard.
pub fn read_range_delta(data: &[u8]) -> Result<RangeDelta, DeltaError> {
    let mut header: Option<DeltaHeader> = None;
    let mut ops = Vec::new();
    read_lines(data, |n, line| {
        let Some(h) = &header else {
            let h: DeltaHeader = json(n, line)?;
            if h.ip_shard.is_none() {
                return Err(DeltaError::Header("no ip_shard"));
            }
            header = Some(h);
            return Ok(());
        };
        if ops.len() >= MAX_OPS {
            return Err(DeltaError::TooManyOps);
        }
        let shard = h.ip_shard.unwrap_or(IpShardId::V6);
        let v4 = shard.is_v4();
        let (lo, hi) = shard.bounds();
        let range = |r: &[String; 2]| -> Result<(u128, u128), DeltaError> {
            let a = parse_addr(v4, &r[0]).ok_or(DeltaError::Op(n, "address"))?;
            let b = parse_addr(v4, &r[1]).ok_or(DeltaError::Op(n, "address"))?;
            if a > b || a < lo || b > hi {
                return Err(DeltaError::Op(n, "range"));
            }
            Ok((a, b))
        };
        let op = match json::<RangeOpLine>(n, line)? {
            RangeOpLine::Upsert { range: r, value } => {
                let (first, last) = range(&r)?;
                RangeOp::Upsert {
                    first,
                    last,
                    value: Value::from_stored(value),
                }
            }
            RangeOpLine::Delete { range: r } => {
                let (first, last) = range(&r)?;
                RangeOp::Delete { first, last }
            }
        };
        ops.push(op);
        Ok(())
    })?;
    let header = header.ok_or(DeltaError::NoHeader)?;
    Ok(RangeDelta { header, ops })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> DeltaHeader {
        DeltaHeader {
            bundle: "b".into(),
            shard: Some(3),
            cold_shard: None,
            ip_shard: None,
            base: "x".repeat(64),
            seq: 42,
            prev_checksum: SetChecksum(1),
            mid_checksum: None,
            new_checksum: SetChecksum(2),
            created_at: "2026-11-21T00:00:00Z".into(),
        }
    }

    #[test]
    fn key_delta_roundtrip_and_determinism() {
        let ops = vec![
            KeyOp::Delete {
                key: b"net.example.old".to_vec(),
            },
            KeyOp::Upsert {
                key: b"com.example.ads".to_vec(),
                value: Value(3),
            },
            KeyOp::Upsert {
                key: b"com.a".to_vec(),
                value: Value(1),
            },
        ];
        let a = write_key_delta(&header(), &ops);
        let mut rev = ops.clone();
        rev.reverse();
        assert_eq!(a, write_key_delta(&header(), &rev), "byte-identical");
        let d = read_key_delta(&a).unwrap();
        assert_eq!(d.header, header());
        assert_eq!(d.ops[0].key(), b"com.a");
        assert_eq!(d.ops.len(), 3);
        let text = {
            let mut s = String::new();
            flate2::read::GzDecoder::new(a.as_slice())
                .read_to_string(&mut s)
                .unwrap();
            s
        };
        assert!(text.starts_with(r#"{"bundle":"b","shard":3,"base":""#), "{text}");
        assert!(text.contains(r#"{"op":"upsert","key":"com.example.ads","value":3}"#));
        assert!(text.contains(r#"{"op":"delete","key":"net.example.old"}"#));
    }

    #[test]
    fn range_delta_roundtrip() {
        let mut h = header();
        h.shard = None;
        h.ip_shard = Some(IpShardId::V4(45));
        let a = |s: &str| u128::from(u32::from(s.parse::<std::net::Ipv4Addr>().unwrap()));
        let ops = vec![
            RangeOp::Upsert {
                first: a("45.12.0.0"),
                last: a("45.12.3.255"),
                value: Value(1),
            },
            RangeOp::Delete {
                first: a("45.12.4.0"),
                last: a("45.12.7.255"),
            },
        ];
        let bytes = write_range_delta(&h, &ops);
        let d = read_range_delta(&bytes).unwrap();
        assert_eq!(d.ops, ops);
        let mut text = String::new();
        flate2::read::GzDecoder::new(bytes.as_slice())
            .read_to_string(&mut text)
            .unwrap();
        assert!(text.contains(r#"{"op":"upsert","range":["45.12.0.0","45.12.3.255"],"value":1}"#));
        // A range outside the shard is refused.
        let bad = write_range_delta(
            &h,
            &[RangeOp::Delete {
                first: a("46.0.0.0"),
                last: a("46.0.0.1"),
            }],
        );
        assert!(matches!(read_range_delta(&bad), Err(DeltaError::Op(2, "range"))));
    }

    /// Review round 1, B8 (c): a delta past [`MAX_OPS`] is refused while it is read.
    #[test]
    fn op_cap() {
        let mut lines = vec![serde_json::to_vec(&header()).unwrap()];
        for i in 0..=MAX_OPS {
            lines.push(format!(r#"{{"op":"delete","key":"com.k{i}"}}"#).into_bytes());
        }
        assert!(matches!(
            read_key_delta(&gzip(&lines)),
            Err(DeltaError::TooManyOps)
        ));
        lines.pop();
        assert_eq!(read_key_delta(&gzip(&lines)).unwrap().ops.len(), MAX_OPS);
    }

    #[test]
    fn refusals() {
        assert!(read_key_delta(b"not gzip").is_err());
        assert!(matches!(read_key_delta(&gzip(&[])), Err(DeltaError::NoHeader)));
        let long = vec![b'x'; MAX_LINE + 10];
        assert!(matches!(
            read_key_delta(&gzip(&[long])),
            Err(DeltaError::LineTooLong(1))
        ));
        let bad_key = gzip(&[
            serde_json::to_vec(&header()).unwrap(),
            br#"{"op":"delete","key":""}"#.to_vec(),
        ]);
        assert!(matches!(read_key_delta(&bad_key), Err(DeltaError::Op(2, "key"))));
    }
}
