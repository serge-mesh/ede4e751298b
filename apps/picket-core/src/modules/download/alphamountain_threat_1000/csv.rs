//! A streaming RFC 4180 reader for alphaMountain's CSV (providers.md §3): one record at a time,
//! each field bounded, quoted fields with `""` escapes. The CSV is untrusted input: a field past
//! [`MAX_FIELD`] or a record past [`MAX_FIELDS`] fields is skipped and counted, never held.

use std::io::{self, BufRead};

/// The longest field kept.
pub const MAX_FIELD: usize = 4096;
/// The most fields in one record.
pub const MAX_FIELDS: usize = 64;

/// What a conversion found.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CsvStats {
    /// Data records (after the header).
    pub rows: u64,
    /// Rows written (risk_score at or above the minimum).
    pub kept: u64,
    /// Rows below the minimum.
    pub below: u64,
    /// Rows without a readable hostname or risk_score, or with too many or too long fields.
    pub bad_rows: u64,
    /// Cells holding CR or LF (providers.md §3: rejected and counted).
    pub rejected_cells: u64,
}

/// One record's fields; `None` for a field that was too long.
type Record = Vec<Option<String>>;

/// Reads the next record. `Ok(None)` at the end.
fn next_record<R: BufRead>(r: &mut R, too_many: &mut bool) -> io::Result<Option<Record>> {
    let mut rec: Record = Vec::new();
    let mut field = Vec::<u8>::new();
    let mut field_long = false;
    let mut in_quotes = false;
    let mut at_field_start = true;
    let mut quote_pending = false; // saw `"` inside quotes; next byte decides
    let mut any = false;
    *too_many = false;
    let push = |rec: &mut Record, field: &mut Vec<u8>, field_long: &mut bool, too_many: &mut bool| {
        if rec.len() >= MAX_FIELDS {
            *too_many = true;
        } else if *field_long {
            rec.push(None);
        } else {
            rec.push(Some(String::from_utf8_lossy(field).into_owned()));
        }
        field.clear();
        *field_long = false;
    };
    loop {
        let (consumed, done) = {
            let buf = match r.fill_buf() {
                Ok(b) => b,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if buf.is_empty() {
                if !any {
                    return Ok(None);
                }
                push(&mut rec, &mut field, &mut field_long, too_many);
                return Ok(Some(rec));
            }
            any = true;
            let mut i = 0;
            let mut done = false;
            while i < buf.len() {
                let b = buf[i];
                i += 1;
                if quote_pending {
                    quote_pending = false;
                    if b == b'"' {
                        if field.len() < MAX_FIELD {
                            field.push(b'"');
                        } else {
                            field_long = true;
                        }
                        continue;
                    }
                    in_quotes = false;
                }
                if in_quotes {
                    if b == b'"' {
                        quote_pending = true;
                    } else if field.len() < MAX_FIELD {
                        field.push(b);
                    } else {
                        field_long = true;
                    }
                    continue;
                }
                match b {
                    b'"' if at_field_start => {
                        in_quotes = true;
                        at_field_start = false;
                    }
                    b',' => {
                        push(&mut rec, &mut field, &mut field_long, too_many);
                        at_field_start = true;
                    }
                    b'\n' => {
                        if field.last() == Some(&b'\r') {
                            field.pop();
                        }
                        push(&mut rec, &mut field, &mut field_long, too_many);
                        done = true;
                        break;
                    }
                    _ => {
                        at_field_start = false;
                        if field.len() < MAX_FIELD {
                            field.push(b);
                        } else {
                            field_long = true;
                        }
                    }
                }
            }
            (i, done)
        };
        r.consume(consumed);
        if done {
            return Ok(Some(rec));
        }
    }
}

/// Converts the CSV into `plain` lines: the hostname of each row whose `risk_score` is at least
/// `min_score`, through `out`. The header names the columns (`hostname,risk_score,more_info`);
/// without `hostname` and `risk_score` the file can't be read.
pub fn convert<R: BufRead>(
    mut r: R,
    min_score: f64,
    mut out: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<CsvStats> {
    let mut stats = CsvStats::default();
    let mut too_many = false;
    let header = loop {
        match next_record(&mut r, &mut too_many)? {
            None => return Err(io::Error::other("the CSV is empty")),
            Some(h) if h.iter().all(|f| f.as_deref().is_none_or(|s| s.trim().is_empty())) => continue,
            Some(h) => break h,
        }
    };
    let col = |name: &str| {
        header.iter().position(|f| {
            f.as_deref()
                .is_some_and(|s| s.trim().trim_start_matches('\u{feff}').eq_ignore_ascii_case(name))
        })
    };
    let (Some(host_col), Some(score_col)) = (col("hostname"), col("risk_score")) else {
        return Err(io::Error::other("the CSV has no hostname,risk_score header"));
    };
    while let Some(rec) = next_record(&mut r, &mut too_many)? {
        if rec.iter().all(|f| f.as_deref().is_some_and(|s| s.trim().is_empty())) && !too_many {
            continue; // a blank line
        }
        stats.rows += 1;
        let crlf = rec
            .iter()
            .filter(|f| f.as_deref().is_some_and(|s| s.contains(['\r', '\n'])))
            .count() as u64;
        stats.rejected_cells += crlf;
        let host = rec.get(host_col).cloned().flatten();
        let score = rec
            .get(score_col)
            .cloned()
            .flatten()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|s| s.is_finite());
        let (Some(host), Some(score)) = (host, score) else {
            stats.bad_rows += 1;
            continue;
        };
        if too_many || host.contains(['\r', '\n']) {
            stats.bad_rows += 1;
            continue;
        }
        let host = host.trim();
        if host.is_empty() {
            stats.bad_rows += 1;
            continue;
        }
        if score < min_score {
            stats.below += 1;
            continue;
        }
        out(host)?;
        stats.kept += 1;
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str, min: f64) -> (Vec<String>, CsvStats) {
        let mut v = Vec::new();
        let s = convert(text.as_bytes(), min, |h| {
            v.push(h.to_string());
            Ok(())
        })
        .unwrap();
        (v, s)
    }

    #[test]
    fn keeps_rows_at_or_above_the_minimum() {
        let text = "hostname,risk_score,more_info\r\nbad.example,9.5,https://x/1\r\nmeh.example,6.9,\r\n\"q.example\",7.0,\"a, \"\"quoted\"\" note\"\r\n";
        let (v, s) = run(text, 7.0);
        assert_eq!(v, vec!["bad.example", "q.example"]);
        assert_eq!(s.rows, 3);
        assert_eq!(s.kept, 2);
        assert_eq!(s.below, 1);
    }

    #[test]
    fn rejects_cells_with_line_breaks() {
        let text = "hostname,risk_score,more_info\n\"evil.example\nnext.example\",9,x\nok.example,9,\"line\nbreak\"\n";
        let (v, s) = run(text, 7.0);
        assert_eq!(v, vec!["ok.example"], "a hostname cell with a line break never becomes two lines");
        assert_eq!(s.rejected_cells, 2);
        assert_eq!(s.bad_rows, 1);
    }

    #[test]
    fn bad_input() {
        assert!(convert(&b""[..], 7.0, |_| Ok(())).is_err());
        assert!(convert(&b"a,b\n1,2\n"[..], 7.0, |_| Ok(())).is_err());
        let (v, s) = run("risk_score,hostname\nNaN,x.example\nnope,y.example\n9,z.example", 7.0);
        assert_eq!(v, vec!["z.example"], "columns by name; a last line without LF counts");
        assert_eq!(s.bad_rows, 2);
        let long = format!("hostname,risk_score\n{},9\nok.example,9\n", "a".repeat(MAX_FIELD + 10));
        let (v, s) = run(&long, 7.0);
        assert_eq!(v, vec!["ok.example"]);
        assert_eq!(s.bad_rows, 1);
        let wide = format!("hostname,risk_score\nw.example,9{}\nok.example,9\n", ",x".repeat(MAX_FIELDS + 5));
        let (v, _) = run(&wide, 7.0);
        assert_eq!(v, vec!["ok.example"]);
        // An unterminated quote runs to the end without panicking.
        let (v, _) = run("hostname,risk_score\n\"open,9\n", 7.0);
        assert!(v.is_empty());
    }
}
