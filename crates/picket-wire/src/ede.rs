//! Extended DNS Errors in replies (RFC 8914; edge.md §4 "Extended DNS Errors").
//!
//! - EXTRA-TEXT is ASCII `key=value` tokens separated by spaces; values percent-encode every byte
//!   outside `A-Za-z0-9-._~`.
//! - At most 128 bytes, and within the client's UDP size. Over either, tokens are dropped from the
//!   left (so `block`, written last, goes last), then the EDE options, before any record is
//!   dropped or TC set.
//! - Sent only when the query has an OPT (RFC 6891 §7).
//!
//! Options borrow their values, so building and writing them never allocates.

use crate::types::{ede_code, edns_code};
use crate::wire::{Out, WriteError};

/// The EXTRA-TEXT cap (edge.md §4).
pub const EXTRA_TEXT_MAX: usize = 128;

/// The most EDE options one reply carries; options past this are not written.
pub const MAX_EDE_PER_REPLY: usize = 4;

const MAX_TOKENS: usize = 3;

/// One `key=value` token. `value2`, when present, follows `value` after a literal `@`
/// (`bundle=<id>@<head>`); both parts are percent-encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdeToken<'a> {
    pub key: &'static str,
    pub value: &'a str,
    pub value2: Option<&'a str>,
}

impl EdeToken<'_> {
    fn len(&self) -> usize {
        let v2 = self.value2.map_or(0, |v| enc_len(v.as_bytes()).saturating_add(1));
        self.key
            .len()
            .saturating_add(1)
            .saturating_add(enc_len(self.value.as_bytes()))
            .saturating_add(v2)
    }

    fn write(&self, o: &mut Out<'_>) -> Result<(), WriteError> {
        o.put(self.key.as_bytes())?;
        o.u8(b'=')?;
        write_enc(o, self.value.as_bytes())?;
        if let Some(v2) = self.value2 {
            o.u8(b'@')?;
            write_enc(o, v2.as_bytes())?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Text<'a> {
    Tokens([Option<EdeToken<'a>>; MAX_TOKENS]),
    /// A fixed sentence (EDE 18), dropped whole.
    Fixed(&'static str),
}

/// One EDE option for a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdeOption<'a> {
    pub code: u16,
    text: Text<'a>,
}

impl<'a> EdeOption<'a> {
    /// An option with `key=value` tokens, written in order (at most 3; extra tokens are ignored).
    pub fn with_tokens(code: u16, tokens: &[EdeToken<'a>]) -> Self {
        let mut t = [None; MAX_TOKENS];
        for (slot, tok) in t.iter_mut().zip(tokens) {
            *slot = Some(*tok);
        }
        Self {
            code,
            text: Text::Tokens(t),
        }
    }

    /// An option without EXTRA-TEXT.
    pub fn bare(code: u16) -> Self {
        Self::with_tokens(code, &[])
    }

    /// EDE 15 for a block by a bundle rule: `bundle=<id>@<head> block=<block_id>`; `head` is the
    /// short head id as in logs.
    pub fn blocked_by_bundle(bundle: &'a str, head: &'a str, block_id: &'a str) -> Self {
        Self::with_tokens(
            ede_code::BLOCKED,
            &[
                EdeToken {
                    key: "bundle",
                    value: bundle,
                    value2: Some(head),
                },
                EdeToken {
                    key: "block",
                    value: block_id,
                    value2: None,
                },
            ],
        )
    }

    /// EDE 15 for a block by a sync lookup: `lookup=<provider> verdict=<verdict> block=<id>`.
    pub fn blocked_by_lookup(provider: &'a str, verdict: &'a str, block_id: &'a str) -> Self {
        Self::with_tokens(
            ede_code::BLOCKED,
            &[
                EdeToken {
                    key: "lookup",
                    value: provider,
                    value2: None,
                },
                EdeToken {
                    key: "verdict",
                    value: verdict,
                    value2: None,
                },
                EdeToken {
                    key: "block",
                    value: block_id,
                    value2: None,
                },
            ],
        )
    }

    /// EDE 4 *Forged Answer*, without text, added to sinkhole answers that carry records.
    pub fn forged() -> Self {
        Self::bare(ede_code::FORGED_ANSWER)
    }

    /// EDE 15 `cause=firewall`: the extension's PTR probe for a blocked IP.
    pub fn firewall() -> Self {
        Self::cause(ede_code::BLOCKED, "firewall")
    }

    /// EDE 18 for a client no profile admits.
    pub fn not_permitted() -> Self {
        Self {
            code: ede_code::PROHIBITED,
            text: Text::Fixed("not permitted from this address"),
        }
    }

    /// EDE 18 for a profile named in the DoH path or DoT name that refuses the client.
    pub fn profile_not_permitted() -> Self {
        Self {
            code: ede_code::PROHIBITED,
            text: Text::Fixed("profile not permitted from this address"),
        }
    }

    /// EDE 3 *Stale Answer* with `cause=<cause>`.
    pub fn stale(cause: &'a str) -> Self {
        Self::cause(ede_code::STALE_ANSWER, cause)
    }

    /// EDE 23 *Network Error* with `cause=<cause>`: no upstream answered.
    pub fn no_upstream(cause: &'a str) -> Self {
        Self::cause(ede_code::NETWORK_ERROR, cause)
    }

    fn cause(code: u16, cause: &'a str) -> Self {
        Self::with_tokens(
            code,
            &[EdeToken {
                key: "cause",
                value: cause,
                value2: None,
            }],
        )
    }

    fn token_count(&self) -> usize {
        match &self.text {
            Text::Tokens(t) => t.iter().take_while(|t| t.is_some()).count(),
            Text::Fixed(_) => 1,
        }
    }

    /// EXTRA-TEXT length when the first `from` tokens are dropped.
    fn text_len(&self, from: usize) -> usize {
        match &self.text {
            Text::Tokens(t) => {
                let mut len = 0usize;
                for (i, tok) in t.iter().map_while(|t| t.as_ref()).enumerate().skip(from) {
                    if i > from {
                        len = len.saturating_add(1);
                    }
                    len = len.saturating_add(tok.len());
                }
                len
            }
            Text::Fixed(s) if from == 0 => s.len(),
            Text::Fixed(_) => 0,
        }
    }

    /// The option's wire size: OPTION-CODE, OPTION-LENGTH, INFO-CODE, EXTRA-TEXT.
    fn wire_len(&self, from: usize) -> usize {
        self.text_len(from).saturating_add(6)
    }

    fn write(&self, o: &mut Out<'_>, from: usize) -> Result<(), WriteError> {
        let text = self.text_len(from);
        o.u16(edns_code::EDE)?;
        o.u16(u16::try_from(text.saturating_add(2)).map_err(|_| WriteError::TooLong)?)?;
        o.u16(self.code)?;
        match &self.text {
            Text::Tokens(t) => {
                for (i, tok) in t.iter().map_while(|t| t.as_ref()).enumerate().skip(from) {
                    if i > from {
                        o.u8(b' ')?;
                    }
                    tok.write(o)?;
                }
            }
            Text::Fixed(s) => {
                if from == 0 {
                    o.put(s.as_bytes())?;
                }
            }
        }
        Ok(())
    }

    /// The EXTRA-TEXT this option would carry on its own, after the 128-byte rule (for tests and
    /// logs).
    pub fn extra_text(&self) -> String {
        let from = self.first_within_cap();
        let mut buf = [0u8; 512];
        let mut o = Out::new(&mut buf);
        if self.write(&mut o, from).is_err() {
            return String::new();
        }
        let n = o.pos();
        buf.get(6..n)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    }

    /// The first token kept under the 128-byte cap: tokens go from the left.
    fn first_within_cap(&self) -> usize {
        let n = self.token_count();
        (0..=n)
            .find(|&from| self.text_len(from) <= EXTRA_TEXT_MAX)
            .unwrap_or(n)
    }
}

/// Bytes outside `A-Za-z0-9-._~` take three (`%XX`).
fn enc_len(v: &[u8]) -> usize {
    v.iter()
        .map(|&b| if unreserved(b) { 1usize } else { 3 })
        .fold(0usize, usize::saturating_add)
}

fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn write_enc(o: &mut Out<'_>, v: &[u8]) -> Result<(), WriteError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in v {
        if unreserved(b) {
            o.u8(b)?;
        } else {
            let hi = HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
            let lo = HEX.get(usize::from(b & 0x0F)).copied().unwrap_or(b'0');
            o.put(&[b'%', hi, lo])?;
        }
    }
    Ok(())
}

/// Which options and tokens a reply carries after the drop rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EdePlan {
    /// Per option: `Some(first token kept)` or `None` when the option is dropped.
    from: [Option<usize>; MAX_EDE_PER_REPLY],
    n: usize,
}

impl EdePlan {
    /// Every option, with each option's tokens cut to the 128-byte cap.
    pub(crate) fn new(opts: &[EdeOption<'_>]) -> Self {
        let mut from = [None; MAX_EDE_PER_REPLY];
        let mut n = 0usize;
        for (slot, opt) in from.iter_mut().zip(opts) {
            *slot = Some(opt.first_within_cap());
            n = n.saturating_add(1);
        }
        Self { from, n }
    }

    pub(crate) fn none() -> Self {
        Self {
            from: [None; MAX_EDE_PER_REPLY],
            n: 0,
        }
    }

    /// The bytes the kept options take inside the OPT RDATA.
    pub(crate) fn size(&self, opts: &[EdeOption<'_>]) -> usize {
        self.from
            .iter()
            .zip(opts)
            .take(self.n)
            .filter_map(|(f, o)| f.map(|from| o.wire_len(from)))
            .fold(0usize, usize::saturating_add)
    }

    /// Drops tokens from the left, then options from the last, until the kept options fit in
    /// `budget` bytes. Returns false when nothing could be kept within it.
    pub(crate) fn shrink_to(&mut self, opts: &[EdeOption<'_>], budget: usize) -> bool {
        while self.size(opts) > budget {
            // Tokens first: the leftmost token of the first option that still has text.
            let tok = self
                .from
                .iter_mut()
                .zip(opts)
                .take(self.n)
                .find(|(f, o)| f.is_some_and(|from| from < o.token_count()));
            if let Some((f, _)) = tok {
                *f = f.map(|from| from.saturating_add(1));
                continue;
            }
            // Then whole options, the last first.
            match self.from.iter_mut().take(self.n).rev().find(|f| f.is_some()) {
                Some(f) => *f = None,
                None => return false,
            }
        }
        true
    }

    pub(crate) fn write(&self, o: &mut Out<'_>, opts: &[EdeOption<'_>]) -> Result<(), WriteError> {
        for (f, opt) in self.from.iter().zip(opts).take(self.n) {
            if let Some(from) = f {
                opt.write(o, *from)?;
            }
        }
        Ok(())
    }

    /// How many options are kept.
    pub(crate) fn kept(&self) -> usize {
        self.from.iter().take(self.n).filter(|f| f.is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_text() {
        let e = EdeOption::blocked_by_bundle("block-common", "c02f7a9e1b4d6e83", "k3j9q2");
        assert_eq!(
            e.extra_text(),
            "bundle=block-common@c02f7a9e1b4d6e83 block=k3j9q2"
        );
        let l = EdeOption::blocked_by_lookup("q9", "block", "k3j9q2");
        assert_eq!(l.extra_text(), "lookup=q9 verdict=block block=k3j9q2");
        assert_eq!(EdeOption::stale("optimistic").extra_text(), "cause=optimistic");
        assert_eq!(
            EdeOption::not_permitted().extra_text(),
            "not permitted from this address"
        );
        assert_eq!(EdeOption::forged().extra_text(), "");
    }

    #[test]
    fn percent_encoding() {
        let e = EdeOption::blocked_by_bundle("a b", "x/y", "é~_.-");
        assert_eq!(e.extra_text(), "bundle=a%20b@x%2Fy block=%C3%A9~_.-");
    }

    #[test]
    fn cap_drops_tokens_from_the_left() {
        let long = "x".repeat(120);
        let e = EdeOption::blocked_by_bundle(&long, "c02f7a9e1b4d6e83", "k3j9q2");
        // The bundle token alone is over the cap: dropped, `block` kept.
        assert_eq!(e.extra_text(), "block=k3j9q2");
        let huge = "y".repeat(130);
        let e = EdeOption::blocked_by_bundle("b", "h", &huge);
        assert_eq!(e.extra_text(), "");
        let l = EdeOption::blocked_by_lookup(&long, "block", "k3j9q2");
        assert_eq!(l.extra_text(), "verdict=block block=k3j9q2");
    }

    #[test]
    fn plan_shrinks_tokens_then_options() {
        let opts = [
            EdeOption::blocked_by_lookup("provider", "block", "abc"),
            EdeOption::forged(),
        ];
        let mut p = EdePlan::new(&opts);
        let full = p.size(&opts);
        assert_eq!(full, 6 + "lookup=provider verdict=block block=abc".len() + 6);
        assert!(p.shrink_to(&opts, full - 1));
        assert_eq!(p.size(&opts), 6 + "verdict=block block=abc".len() + 6);
        assert!(p.shrink_to(&opts, 6 + "block=abc".len() + 6));
        assert!(p.shrink_to(&opts, 12));
        assert_eq!(p.kept(), 2);
        assert!(p.shrink_to(&opts, 11));
        assert_eq!(p.kept(), 1); // EDE 4 dropped first, EDE 15 (empty) kept
        assert!(p.shrink_to(&opts, 0));
        assert_eq!(p.kept(), 0);
    }
}
