//! Answer facts for the `dns` lookup module (providers.md §5): the answer is checked like an
//! upstream answer (ID, question and structure, edge.md §7; one with another ID or question is
//! invalid), decoded with hickory and scrubbed, and only the verdict inputs come out. Its TTLs are
//! ignored: the provider's cache TTLs apply. No copy is encoded. [`detail_text`] makes an
//! EXTRA-TEXT safe for the provider's `detail`.

use std::net::IpAddr;

use crate::answer::{AnswerLimits, EdeInfo, Invalid, SentQuery, analyze};
use crate::name::WireName;

/// What a lookup rule can test (providers.md §5 `dns` "Rules").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupFacts {
    /// The full rcode (`rcode` condition).
    pub rcode: u16,
    /// Every EDE option, in order (`ede`, `ede_text` conditions).
    pub ede: Vec<EdeInfo>,
    /// A and AAAA addresses of the question and its chain (`answers_in`); hints aren't included.
    pub addrs: Vec<IpAddr>,
    /// The CNAME chain after the question name (`cname_suffix` tests its last name).
    pub chain: Vec<WireName>,
    /// The authority section holds a negative-caching SOA (`soa`).
    pub soa: bool,
}

/// Checks a lookup answer to `sent` and returns its facts.
pub fn lookup_answer_facts(msg: &[u8], sent: &SentQuery<'_>) -> Result<LookupFacts, Invalid> {
    let a = analyze(msg, sent, &AnswerLimits::default())?;
    let f = a.facts();
    Ok(LookupFacts {
        rcode: f.rcode,
        ede: f.ede.clone(),
        addrs: f
            .addrs
            .iter()
            .filter(|x| !x.source.is_hint())
            .map(|x| x.ip)
            .collect(),
        chain: f.chain.clone(),
        soa: f.soa,
    })
}

/// The most EXTRA-TEXT bytes a `dns` lookup's `detail` keeps (providers.md §5 `dns`).
pub const DETAIL_TEXT_MAX: usize = 64;

impl EdeInfo {
    /// This EXTRA-TEXT as a `dns` lookup's `detail` shows it: [`detail_text`] with
    /// [`DETAIL_TEXT_MAX`].
    pub fn detail_text(&self) -> String {
        detail_text(self.text.as_bytes(), DETAIL_TEXT_MAX)
    }
}

/// EXTRA-TEXT made safe to show (providers.md §5 `dns` "Detail": "EXTRA-TEXT cut to 64 bytes with
/// control characters escaped"): the first `max` bytes, cut back to a character boundary, with
/// control characters, bytes that aren't UTF-8 and `\` written as `\DDD` (decimal, as in log
/// names, api.md §5).
pub fn detail_text(text: &[u8], max: usize) -> String {
    // Don't split a UTF-8 sequence: back off while the first byte left out continues one.
    let mut n = max.min(text.len());
    while n > 0 && text.get(n).is_some_and(|b| b & 0xC0 == 0x80) {
        n = n.saturating_sub(1);
    }
    let cut = text.get(..n).unwrap_or(&[]);
    let mut out = String::with_capacity(cut.len());
    let escape = |out: &mut String, b: u8| {
        out.push('\\');
        for d in [b / 100, (b / 10) % 10, b % 10] {
            out.push(char::from(b'0'.saturating_add(d)));
        }
    };
    for chunk in cut.utf8_chunks() {
        for c in chunk.valid().chars() {
            if c.is_control() || c == '\\' {
                let mut buf = [0u8; 4];
                for &b in c.encode_utf8(&mut buf).as_bytes() {
                    escape(&mut out, b);
                }
            } else {
                out.push(c);
            }
        }
        for &b in chunk.invalid() {
            escape(&mut out, b);
        }
    }
    out
}
