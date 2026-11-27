//! Git pkt-line framing (git protocol v2, `gitprotocol-common`): each line is four hex digits
//! giving its length (the four included), then the payload; `0000` is a flush, `0001` a
//! delimiter, `0002` the end of a response. Used to write the `ls-refs` request and to read its
//! answer, which is untrusted input: bounded, never panicking.

/// The largest pkt-line git allows (65520 bytes, header included).
pub const MAX_PKT: usize = 65520;

/// One frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pkt<'a> {
    Data(&'a [u8]),
    Flush,
    Delim,
    End,
}

/// Why an answer can't be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PktError {
    #[error("a pkt-line is cut short")]
    Truncated,
    #[error("a pkt-line has a bad length header")]
    BadLength,
}

/// Appends one data line.
pub fn write_line(out: &mut Vec<u8>, line: &str) {
    let len = line.len() + 4;
    out.extend_from_slice(format!("{len:04x}").as_bytes());
    out.extend_from_slice(line.as_bytes());
}

/// Splits a buffer into frames.
pub fn parse(mut buf: &[u8]) -> Result<Vec<Pkt<'_>>, PktError> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let head = buf.get(..4).ok_or(PktError::Truncated)?;
        let hex = std::str::from_utf8(head).map_err(|_| PktError::BadLength)?;
        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(PktError::BadLength);
        }
        let len = usize::from_str_radix(hex, 16).map_err(|_| PktError::BadLength)?;
        match len {
            0 => {
                out.push(Pkt::Flush);
                buf = &buf[4..];
            }
            1 => {
                out.push(Pkt::Delim);
                buf = &buf[4..];
            }
            2 => {
                out.push(Pkt::End);
                buf = &buf[4..];
            }
            3 => return Err(PktError::BadLength),
            n if n > MAX_PKT => return Err(PktError::BadLength),
            n => {
                let data = buf.get(4..n).ok_or(PktError::Truncated)?;
                out.push(Pkt::Data(data));
                buf = &buf[n..];
            }
        }
    }
    Ok(out)
}

/// The `ls-refs` request (protocol v2) for one ref: `refs/heads/<branch>`, or `HEAD` for the
/// default branch.
pub fn ls_refs_request(branch: Option<&str>, agent: &str) -> Vec<u8> {
    let mut out = Vec::new();
    write_line(&mut out, "command=ls-refs\n");
    write_line(&mut out, &format!("agent={agent}\n"));
    out.extend_from_slice(b"0001");
    write_line(&mut out, "symrefs\n");
    match branch {
        Some(b) => write_line(&mut out, &format!("ref-prefix refs/heads/{b}\n")),
        None => write_line(&mut out, "ref-prefix HEAD\n"),
    }
    out.extend_from_slice(b"0000");
    out
}

/// Finds the object id of exactly `refname` in an `ls-refs` answer (`<oid> <refname>[ attr…]`).
/// An `ERR` line is returned as the error text.
pub fn find_ref(answer: &[u8], refname: &str) -> Result<Option<String>, String> {
    let pkts = parse(answer).map_err(|e| e.to_string())?;
    for p in pkts {
        let Pkt::Data(d) = p else { continue };
        let line = String::from_utf8_lossy(d);
        let line = line.trim_end_matches('\n');
        if let Some(err) = line.strip_prefix("ERR ") {
            return Err(crate::util::sanitize_for_message(err, 200));
        }
        let mut parts = line.split(' ');
        let (Some(oid), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        let oid_ok = (oid.len() == 40 || oid.len() == 64) && oid.bytes().all(|b| b.is_ascii_hexdigit());
        if oid_ok && name == refname {
            return Ok(Some(oid.to_ascii_lowercase()));
        }
    }
    Ok(None)
}

/// The branch a symbolic ref points at in an `ls-refs` answer with `symrefs`
/// (`<oid> HEAD symref-target:refs/heads/<branch>`): the default branch's name.
pub fn find_symref_branch(answer: &[u8], refname: &str) -> Result<Option<String>, String> {
    let pkts = parse(answer).map_err(|e| e.to_string())?;
    for p in pkts {
        let Pkt::Data(d) = p else { continue };
        let line = String::from_utf8_lossy(d);
        let line = line.trim_end_matches('\n');
        if let Some(err) = line.strip_prefix("ERR ") {
            return Err(crate::util::sanitize_for_message(err, 200));
        }
        let mut parts = line.split(' ');
        let (Some(_oid), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        if name != refname {
            continue;
        }
        for attr in parts {
            if let Some(target) = attr.strip_prefix("symref-target:refs/heads/")
                && !target.is_empty()
                && target.len() <= 255
            {
                return Ok(Some(target.to_string()));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_framing() {
        let r = ls_refs_request(Some("main"), "picket/1");
        let text = String::from_utf8(r.clone()).unwrap();
        assert!(text.starts_with("0014command=ls-refs\n"), "{text}");
        assert!(text.contains("0001"));
        assert!(text.contains("001fref-prefix refs/heads/main\n"), "{text}");
        assert!(text.ends_with("0000"));
        let pkts = parse(&r).unwrap();
        assert_eq!(pkts.last(), Some(&Pkt::Flush));
        assert!(
            String::from_utf8(ls_refs_request(None, "a"))
                .unwrap()
                .contains("ref-prefix HEAD\n")
        );
    }

    #[test]
    fn answers() {
        let mut a = Vec::new();
        write_line(
            &mut a,
            "1111111111111111111111111111111111111111 refs/heads/main-old\n",
        );
        write_line(
            &mut a,
            "2222222222222222222222222222222222222222 refs/heads/main\n",
        );
        write_line(
            &mut a,
            "3333333333333333333333333333333333333333 HEAD symref-target:refs/heads/main\n",
        );
        a.extend_from_slice(b"0000");
        assert_eq!(
            find_ref(&a, "refs/heads/main").unwrap().as_deref(),
            Some("2222222222222222222222222222222222222222"),
            "an exact ref name, not a prefix match"
        );
        assert_eq!(
            find_ref(&a, "HEAD").unwrap().as_deref(),
            Some("3333333333333333333333333333333333333333")
        );
        assert_eq!(find_ref(&a, "refs/heads/dev").unwrap(), None);
        assert_eq!(find_symref_branch(&a, "HEAD").unwrap().as_deref(), Some("main"));
        assert_eq!(find_symref_branch(&a, "refs/heads/main").unwrap(), None);
        let mut e = Vec::new();
        write_line(&mut e, "ERR upload-pack: not our ref\n");
        assert!(find_ref(&e, "HEAD").unwrap_err().contains("not our ref"));
        assert!(parse(b"00").is_err());
        assert!(parse(b"zzzz").is_err());
        assert!(parse(b"0003").is_err());
        assert!(parse(b"0010abc").is_err(), "cut short");
        assert!(parse(b"ffffxxxx").is_err(), "over the git maximum");
    }
}
