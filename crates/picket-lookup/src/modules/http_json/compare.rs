//! `block_if` / `clean_if` comparisons (providers.md §5 `http_json`): numeric comparisons
//! (`>= 7.0`, `< 4.0`, …) and string equality (`== "malicious"`). Booleans compare by equality
//! too (`== true`). A value of another type than the operand never matches.

use std::fmt;

use serde_json::Value;

/// The longest comparison text accepted.
pub const MAX_COMPARISON: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::Eq => "==",
            Self::Ne => "!=",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Operand {
    Number(f64),
    String(String),
    Bool(bool),
}

/// One parsed comparison.
#[derive(Clone, Debug, PartialEq)]
pub struct Comparison {
    op: Op,
    rhs: Operand,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CompareError {
    #[error("comparison over {MAX_COMPARISON} bytes")]
    TooLong,
    #[error("expected an operator: <, <=, >, >=, == or !=")]
    NoOperator,
    #[error("expected a number, a JSON string or true/false after the operator")]
    BadOperand,
    #[error("strings and booleans compare only with == and !=")]
    OrderOnNonNumber,
}

impl Comparison {
    pub fn parse(text: &str) -> Result<Self, CompareError> {
        if text.len() > MAX_COMPARISON {
            return Err(CompareError::TooLong);
        }
        let t = text.trim();
        let (op, rest) = [
            (">=", Op::Ge),
            ("<=", Op::Le),
            ("==", Op::Eq),
            ("!=", Op::Ne),
            (">", Op::Gt),
            ("<", Op::Lt),
        ]
        .iter()
        .find_map(|(s, op)| t.strip_prefix(s).map(|r| (*op, r.trim())))
        .ok_or(CompareError::NoOperator)?;
        let rhs = if rest.starts_with('"') {
            Operand::String(serde_json::from_str::<String>(rest).map_err(|_| CompareError::BadOperand)?)
        } else if rest == "true" || rest == "false" {
            Operand::Bool(rest == "true")
        } else {
            Operand::Number(parse_number(rest).ok_or(CompareError::BadOperand)?)
        };
        if !matches!(rhs, Operand::Number(_)) && !matches!(op, Op::Eq | Op::Ne) {
            return Err(CompareError::OrderOnNonNumber);
        }
        Ok(Self { op, rhs })
    }

    /// Whether `v` satisfies the comparison.
    pub fn matches(&self, v: &Value) -> bool {
        match &self.rhs {
            Operand::Number(r) => {
                let Some(l) = v.as_f64().filter(|_| v.is_number()) else {
                    return false;
                };
                match self.op {
                    Op::Lt => l < *r,
                    Op::Le => l <= *r,
                    Op::Gt => l > *r,
                    Op::Ge => l >= *r,
                    Op::Eq => l == *r,
                    Op::Ne => l != *r,
                }
            }
            Operand::String(r) => match v.as_str() {
                Some(l) => (l == r) == (self.op == Op::Eq),
                None => false,
            },
            Operand::Bool(r) => match v.as_bool() {
                Some(l) => (l == *r) == (self.op == Op::Eq),
                None => false,
            },
        }
    }
}

impl fmt::Display for Comparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.op.as_str())?;
        f.write_str(" ")?;
        match &self.rhs {
            Operand::Number(n) => write!(f, "{n}"),
            Operand::String(s) => {
                write!(f, "{}", serde_json::to_string(s).map_err(|_| fmt::Error)?)
            }
            Operand::Bool(b) => write!(f, "{b}"),
        }
    }
}

/// A JSON-style number: optional `-`, digits, optional fraction and exponent. No `inf`, `NaN`,
/// hex or leading `+`.
fn parse_number(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return None;
    }
    let ok = b
        .iter()
        .all(|&c| c.is_ascii_digit() || matches!(c, b'-' | b'.' | b'e' | b'E' | b'+'));
    let digit_first = b.first().is_some_and(|&c| c == b'-' || c.is_ascii_digit());
    if !ok || !digit_first {
        return None;
    }
    s.parse::<f64>().ok().filter(|v| v.is_finite())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn numeric() {
        let ge = Comparison::parse(">= 7.0").unwrap();
        assert!(ge.matches(&json!(7)));
        assert!(ge.matches(&json!(9.5)));
        assert!(!ge.matches(&json!(6.99)));
        assert!(!ge.matches(&json!("8")), "a numeric string isn't a number");
        assert!(!ge.matches(&Value::Null));
        let lt = Comparison::parse("<4.0").unwrap();
        assert!(lt.matches(&json!(3)) && !lt.matches(&json!(4)));
        assert!(Comparison::parse("== -1e3").unwrap().matches(&json!(-1000)));
        assert!(Comparison::parse("!= 0").unwrap().matches(&json!(1)));
        assert_eq!(ge.to_string(), ">= 7");
    }

    #[test]
    fn strings_and_bools() {
        let eq = Comparison::parse(r#"== "malicious""#).unwrap();
        assert!(eq.matches(&json!("malicious")));
        assert!(!eq.matches(&json!("Malicious")));
        assert!(!eq.matches(&json!(1)));
        let ne = Comparison::parse(r#"!= "ok""#).unwrap();
        assert!(ne.matches(&json!("bad")) && !ne.matches(&json!("ok")));
        assert!(Comparison::parse("== true").unwrap().matches(&json!(true)));
        assert!(!Comparison::parse("== true").unwrap().matches(&json!(1)));
        assert_eq!(eq.to_string(), r#"== "malicious""#);
    }

    #[test]
    fn refused() {
        for bad in [
            "",
            "7",
            "=> 7",
            ">= ",
            ">= inf",
            ">= NaN",
            ">= 0x10",
            ">= +1",
            "< \"a\"",
            "== 'x'",
            ">= 7 7",
            "== \"unterminated",
        ] {
            assert!(Comparison::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            Comparison::parse(&format!("== \"{}\"", "a".repeat(300))),
            Err(CompareError::TooLong)
        );
    }
}
