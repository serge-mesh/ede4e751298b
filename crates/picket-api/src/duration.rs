//! Durations written as text in config documents: `30s`, `2m`, `24h`, `7d`, `1w` (feeds.md,
//! providers.md, edge.md §12). A plain integer is read as seconds.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A duration stored as whole seconds and written with the largest exact unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DurationStr(pub u64);

impl DurationStr {
    pub const fn secs(s: u64) -> Self {
        Self(s)
    }
    pub const fn minutes(m: u64) -> Self {
        Self(m * 60)
    }
    pub const fn hours(h: u64) -> Self {
        Self(h * 3600)
    }
    pub const fn days(d: u64) -> Self {
        Self(d * 86_400)
    }
    pub fn as_secs(self) -> u64 {
        self.0
    }
    pub fn as_duration(self) -> Duration {
        Duration::from_secs(self.0)
    }

    /// Parses `<n><unit>` where unit is `s`, `m`, `h`, `d` or `w`, sums like `1h30m`, or a bare
    /// number of seconds.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty duration".into());
        }
        if let Ok(n) = s.parse::<u64>() {
            return Ok(Self(n));
        }
        let mut total: u64 = 0;
        let mut num = String::new();
        for c in s.chars() {
            if c.is_ascii_digit() {
                num.push(c);
                continue;
            }
            let n: u64 = num.parse().map_err(|_| format!("bad duration {s:?}"))?;
            num.clear();
            let mult = match c {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86_400,
                'w' => 604_800,
                _ => return Err(format!("bad duration unit {c:?} in {s:?}")),
            };
            total = total
                .checked_add(n.checked_mul(mult).ok_or("duration overflow")?)
                .ok_or("duration overflow")?;
        }
        if !num.is_empty() {
            return Err(format!("duration {s:?} is missing a unit"));
        }
        Ok(Self(total))
    }
}

impl fmt::Display for DurationStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        if s == 0 {
            return write!(f, "0s");
        }
        for (unit, len) in [("w", 604_800), ("d", 86_400), ("h", 3600), ("m", 60)] {
            if s.is_multiple_of(len) {
                return write!(f, "{}{unit}", s / len);
            }
        }
        write!(f, "{s}s")
    }
}

impl Serialize for DurationStr {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DurationStr {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u64),
            Text(String),
        }
        match Raw::deserialize(de)? {
            Raw::Num(n) => Ok(Self(n)),
            Raw::Text(t) => Self::parse(&t).map_err(serde::de::Error::custom),
        }
    }
}

impl schemars::JsonSchema for DurationStr {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Duration".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^([0-9]+[smhdw])+$|^[0-9]+$",
            "description": "A duration such as 30s, 2m, 24h, 7d or 1w"
        })
    }
}

/// `d` in whole milliseconds, saturating at `u64::MAX` (no lossy `as`).
pub fn as_millis_u64(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// `d` in whole microseconds, saturating at `u64::MAX`.
pub fn as_micros_u64(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

/// `d` in whole milliseconds, saturating at `i64::MAX` (SQLite integers, signed times).
pub fn as_millis_i64(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

/// `d` in whole seconds, saturating at `i64::MAX`.
pub fn as_secs_i64(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format() {
        assert_eq!(DurationStr::parse("2m").unwrap().0, 120);
        assert_eq!(DurationStr::parse("1h30m").unwrap().0, 5400);
        assert_eq!(DurationStr::parse("7d").unwrap().to_string(), "1w");
        assert_eq!(DurationStr::parse("90").unwrap().to_string(), "90s");
        assert_eq!(DurationStr(5400).to_string(), "90m");
        assert!(DurationStr::parse("5x").is_err());
        assert!(DurationStr::parse("5").is_ok());
        assert!(DurationStr::parse("1h5").is_err());
        let v: DurationStr = serde_json::from_str("\"24h\"").unwrap();
        assert_eq!(v, DurationStr::hours(24));
        assert_eq!(serde_json::to_string(&v).unwrap(), "\"1d\"");
    }
}
