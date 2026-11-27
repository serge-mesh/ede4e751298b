//! Cron schedules, in UTC and parsed with `croner`: lookup self-tests (providers.md §4
//! "Self-tests") and core's `cron` feed triggers (feed-scheduling.md §1). One parser for both, so
//! the forms, the config check and the schedulers agree.
//!
//! **croner 4's reading** (jiff plan choice D1). croner 5 refuses two pattern shapes croner 4
//! accepted, so a stored schedule using one would stop running after the upgrade. [`parse`]
//! first writes the pattern as croner 4 read it:
//! - weekday and month names become their numbers in every field: croner 4 replaced them
//!   across the whole pattern (`0 0 * * jan` ran on Mondays, `0 0 * mon *` every day of
//!   January, `mon * * * *` at minute 1);
//! - a bare `L` in day-of-week is dropped: croner 4 ignored it (`0 0 * * 1,L` ran on Mondays).
//!   When nothing else is left there, croner 4 ran on day-of-month alone if that restricts the
//!   day (`0 0 1 * L`: the 1st), so the field becomes `*`; otherwise it never found a time
//!   (`0 0 * * L`), and the pattern stays as it is, for croner 5 to refuse.
//!
//! Every other pattern reaches croner 5 as croner 4 would have seen it, and croner 5 finds the
//! same times for those. `fixtures/cron/croner4-next-runs.txt` holds croner 4's times
//! (`selftest`'s golden test). Callers bound the expression's length ([`crate::selftest::MAX_CRON`]).

use std::str::FromStr as _;

use jiff::Timestamp;
use jiff::tz::TimeZone;

pub use croner::Cron;
pub use croner::errors::CronError;

/// croner 4's name replacements, applied in this order to the whole pattern (its default,
/// Sunday = 0 weekdays).
const NAMES: [(&str, &str); 20] = [
    ("-SUN", "-7"),
    ("SUN", "0"),
    ("MON", "1"),
    ("TUE", "2"),
    ("WED", "3"),
    ("THU", "4"),
    ("FRI", "5"),
    ("SAT", "6"),
    ("JAN", "1"),
    ("FEB", "2"),
    ("MAR", "3"),
    ("APR", "4"),
    ("MAY", "5"),
    ("JUN", "6"),
    ("JUL", "7"),
    ("AUG", "8"),
    ("SEP", "9"),
    ("OCT", "10"),
    ("NOV", "11"),
    ("DEC", "12"),
];

/// Parses a schedule as croner 4 read it (module docs).
pub fn parse(expr: &str) -> Result<Cron, CronError> {
    Cron::from_str(&croner4_form(expr))
}

/// The first time after `after` (strictly) on the schedule, if croner finds one.
pub fn next_after(cron: &Cron, after: Timestamp) -> Option<Timestamp> {
    cron.find_next_occurrence(&after.to_zoned_datetime(TimeZone::UTC), false)
        .ok()
        .map(|z| z.timestamp())
}

/// `expr` as croner 4 read it, in a form croner 5 reads the same way (module docs).
fn croner4_form(expr: &str) -> String {
    let mut s = expr.trim().to_uppercase();
    // A nickname (`@daily`) is expanded before names are replaced, by both versions alike; any
    // other pattern with `@` is refused by both.
    if s.contains('@') {
        return s;
    }
    for (name, number) in NAMES {
        s = s.replace(name, number);
    }
    let mut fields: Vec<&str> = s.split_whitespace().collect();
    // Optional seconds first and an optional year last, as croner's default parser takes them.
    let (dom, dow) = match fields.len() {
        5 => (2, 4),
        6 | 7 => (3, 5),
        _ => return s,
    };
    let (plus, list) = match fields[dow].strip_prefix('+') {
        Some(rest) => ("+", rest),
        None => ("", fields[dow]),
    };
    if !list.split(',').any(|p| p == "L") {
        return s;
    }
    let kept = list
        .split(',')
        .filter(|p| *p != "L")
        .collect::<Vec<_>>()
        .join(",");
    let new_dow = if kept.split(',').any(|p| !p.is_empty()) {
        // croner 4 refused `*` inside a list (`*,L`); left alone, croner 5 refuses it too.
        if kept.replace('?', "*") == "*" {
            return s;
        }
        format!("{plus}{kept}")
    } else if plus.is_empty() && fields[dom].replace('?', "*") != "*" {
        // Day-of-week matched nothing and croner 4 ORs it with day-of-month.
        "*".to_string()
    } else {
        // Never ran: an empty day-of-week ANDed (`+`) or alone (day-of-month `*`).
        return s;
    };
    fields[dow] = &new_dow;
    fields.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn croner4_forms() {
        for (expr, want) in [
            // Unchanged, apart from case and surrounding space.
            ("0 * * * *", "0 * * * *"),
            (" 0 0 L * 5L ", "0 0 L * 5L"),
            ("@weekly", "@WEEKLY"),
            ("@monthly", "@MONTHLY"),
            // Names, in any field.
            ("5 4 * * sun", "5 4 * * 0"),
            ("0 0 * JAN-MAR MON-FRI", "0 0 * 1-3 1-5"),
            ("0 0 * * FRI-SUN", "0 0 * * 5-7"),
            ("0 0 * * jan", "0 0 * * 1"),
            ("0 0 * mon *", "0 0 * 1 *"),
            ("0 0 * JAN-SUN *", "0 0 * 1-7 *"),
            ("mon * * * *", "1 * * * *"),
            // A bare `L` in day-of-week.
            ("0 0 * * 1,L", "0 0 * * 1"),
            ("0 0 * * l,5", "0 0 * * 5"),
            ("0 0 * * +1,L", "0 0 * * +1"),
            ("0 0 1 * */2,L", "0 0 1 * */2"),
            ("0 0 1 * L", "0 0 1 * *"),
            ("0 0 1 * ,L", "0 0 1 * *"),
            ("0 0 L * L,L", "0 0 L * *"),
            ("0 0 0 1 * L", "0 0 0 1 * *"),
            ("0 0 0 1 * L 2030", "0 0 0 1 * * 2030"),
            // What croner 4 never ran or refused stays, for croner 5 to refuse.
            ("0 0 * * L", "0 0 * * L"),
            ("0 0 ? * L", "0 0 ? * L"),
            ("0 0 1 * +L", "0 0 1 * +L"),
            ("0 0 1 * *,L", "0 0 1 * *,L"),
            ("0 0 1 * ?,L", "0 0 1 * ?,L"),
            ("* * * *", "* * * *"),
        ] {
            assert_eq!(croner4_form(expr), want, "{expr:?}");
        }
    }

    #[test]
    fn rewritten_shapes_parse_and_the_rest_are_refused() {
        for expr in [
            "0 0 * * jan",
            "0 0 * mon *",
            "mon * * * *",
            "0 0 * * 1,L",
            "0 0 1 * L",
        ] {
            assert!(Cron::from_str(expr).is_err(), "croner 5 alone refuses {expr:?}");
            assert!(parse(expr).is_ok(), "{expr:?}");
        }
        for expr in ["0 0 * * L", "0 0 1 * +L", "0 0 * * dec", "not a cron", ""] {
            assert!(parse(expr).is_err(), "{expr:?}");
        }
    }
}
