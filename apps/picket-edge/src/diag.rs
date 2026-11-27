//! Diagnostics (edge.md §11): `tracing` to stderr (journald under systemd), `warn` and above by
//! default, `RUST_LOG` overrides. Never per-query lines or client data.
//!
//! Every error text that reaches a journal line, an `event` record or an admin reply goes through
//! [`cap`], so a huge serde or I/O error can't produce an oversized line (a line over 64 KiB is
//! silently skipped downstream) or a bloated record.

use std::fmt::Display;

/// Longest error text in an `event` record (`reason`) or an admin reply.
pub const MAX_REASON: usize = 512;
/// Longest error text in a journal line.
pub const MAX_JOURNAL: usize = 1024;

/// Installs the stderr subscriber. Safe to call more than once (later calls are ignored).
pub fn init_tracing() {
    use std::io::IsTerminal;
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    // Under systemd stderr goes to journald, which stamps its own time: no colours, no time.
    let journald = std::env::var_os("JOURNAL_STREAM").is_some();
    let b = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_target(false);
    let _ = if journald {
        b.without_time().try_init()
    } else {
        b.try_init()
    };
}

/// Truncates `s` to at most `max` bytes on a char boundary, marking a cut with `…`.
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max.saturating_sub('…'.len_utf8());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + 3);
    out.push_str(&s[..end]);
    out.push('…');
    out
}

/// An error (or any displayable value) as text capped at [`MAX_REASON`] bytes, with control
/// characters replaced so it stays one line.
pub fn cap(e: impl Display) -> String {
    cap_to(e, MAX_REASON)
}

/// As [`cap`] with an explicit limit.
pub fn cap_to(e: impl Display, max: usize) -> String {
    // Render at most a bounded prefix: a Display impl can produce megabytes (a serde error
    // quoting its input). `LimitedWriter` stops collecting past the cap.
    let mut w = LimitedWriter {
        buf: String::new(),
        max: max.saturating_add(8),
    };
    let _ = std::fmt::write(&mut w, format_args!("{e}"));
    let one_line: String = w
        .buf
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    truncate(&one_line, max)
}

struct LimitedWriter {
    buf: String,
    max: usize,
}

impl std::fmt::Write for LimitedWriter {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        if self.buf.len() >= self.max {
            // Stop the formatter early; the text is already over the cap.
            return Err(std::fmt::Error);
        }
        let room = self.max - self.buf.len();
        if s.len() <= room {
            self.buf.push_str(s);
        } else {
            let mut end = room;
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            self.buf.push_str(&s[..end]);
            return Err(std::fmt::Error);
        }
        Ok(())
    }
}

/// `anyhow` errors with their causes, capped: `outer: cause: cause`.
pub fn cap_chain(e: &anyhow::Error) -> String {
    cap(format_args!("{e:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_on_char_boundary() {
        assert_eq!(truncate("abc", 5), "abc");
        let t = truncate("ééééé", 5);
        assert!(t.len() <= 5, "{t}");
        assert!(t.ends_with('…'));
    }

    #[test]
    fn caps_huge_errors_and_newlines() {
        let huge = "x".repeat(10 << 20);
        let e = serde_json::from_str::<u8>(&format!("\"{huge}\"")).unwrap_err();
        let s = cap(&e);
        assert!(s.len() <= MAX_REASON);
        let s = cap("line1\nline2\r\0");
        assert!(!s.contains('\n') && !s.contains('\0'));
        let big = anyhow::anyhow!("{}", "y".repeat(100_000)).context("outer");
        assert!(cap_chain(&big).len() <= MAX_REASON);
    }
}
