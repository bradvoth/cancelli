//! Byte-exact ports of the two Python serialisations the POC hashes:
//! `json.dumps(obj, sort_keys=True, ensure_ascii=False)` with the default
//! separators `", "` and `": "`.
//!
//! [`J`] is an order-preserving JSON tree. The same value is serialised two
//! ways: [`py_dumps_sorted`] for hashes (keys sorted by code point, which is
//! byte order for UTF-8) and [`compact`] for the wire (document order kept,
//! so the request lists questions and choice labels in rubric order).

use serde_json::Value;

/// An order-preserving JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum J {
    /// `null`.
    Null,
    /// A boolean.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// An unsigned integer beyond `i64`.
    UInt(u64),
    /// A float.
    Float(f64),
    /// A string.
    Str(String),
    /// An array.
    Arr(Vec<J>),
    /// An object in insertion order.
    Obj(Vec<(String, J)>),
}

impl J {
    /// Convenience string constructor.
    pub fn s(v: impl Into<String>) -> J {
        J::Str(v.into())
    }

    /// Convert a `serde_json::Value` (keys come out sorted, which is all the
    /// hash path needs).
    pub fn from_value(v: &Value) -> J {
        match v {
            Value::Null => J::Null,
            Value::Bool(b) => J::Bool(*b),
            Value::Number(n) => match n.as_i64() {
                Some(i) => J::Int(i),
                None => match n.as_u64() {
                    Some(u) => J::UInt(u),
                    None => J::Float(n.as_f64().unwrap_or(f64::NAN)),
                },
            },
            Value::String(s) => J::Str(s.clone()),
            Value::Array(a) => J::Arr(a.iter().map(J::from_value).collect()),
            Value::Object(o) => J::Obj(
                o.iter()
                    .map(|(k, x)| (k.clone(), J::from_value(x)))
                    .collect(),
            ),
        }
    }
}

/// Python `json.dumps(s)` string escaping with `ensure_ascii=False`: only
/// `"`, `\` and C0 controls are escaped (`\b \f \n \r \t`, else `\u00xx`),
/// which is exactly serde_json's string escaping.
fn push_str(out: &mut String, s: &str) {
    out.push_str(&serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into()));
}

/// Python `float.__repr__` as used by `json.dumps`: shortest round-trip
/// digits; fixed notation for decimal exponents in [-4, 16), otherwise
/// `d.ddde+XX`; `NaN`/`Infinity` literals.
pub fn py_float(x: f64) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    if x == 0.0 {
        return if x.is_sign_negative() { "-0.0" } else { "0.0" }.into();
    }
    // `{:e}` gives the shortest round-trip digits, e.g. "1.25e-7", "3e20".
    let e = format!("{x:e}");
    let (mant, exp) = e.split_once('e').unwrap_or((e.as_str(), "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let neg = mant.starts_with('-');
    let digits: String = mant.chars().filter(char::is_ascii_digit).collect();
    let sign = if neg { "-" } else { "" };
    if (-4..16).contains(&exp) {
        let n = digits.len() as i32;
        let s = if exp >= n - 1 {
            // integral: digits followed by zeros, then ".0"
            format!("{digits}{}.0", "0".repeat((exp - (n - 1)) as usize))
        } else if exp >= 0 {
            let (a, b) = digits.split_at((exp + 1) as usize);
            format!("{a}.{b}")
        } else {
            format!("0.{}{digits}", "0".repeat((-exp - 1) as usize))
        };
        format!("{sign}{s}")
    } else {
        let (a, b) = digits.split_at(1);
        let m = if b.is_empty() {
            a.to_string()
        } else {
            format!("{a}.{b}")
        };
        let es = if exp < 0 { '-' } else { '+' };
        format!("{sign}{m}e{es}{:02}", exp.abs())
    }
}

fn write_py(out: &mut String, j: &J) {
    match j {
        J::Null => out.push_str("null"),
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::Int(i) => out.push_str(&i.to_string()),
        J::UInt(u) => out.push_str(&u.to_string()),
        J::Float(f) => out.push_str(&py_float(*f)),
        J::Str(s) => push_str(out, s),
        J::Arr(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_py(out, x);
            }
            out.push(']');
        }
        J::Obj(o) => {
            let mut items: Vec<&(String, J)> = o.iter().collect();
            items.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (i, (k, v)) in items.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                push_str(out, k);
                out.push_str(": ");
                write_py(out, v);
            }
            out.push('}');
        }
    }
}

/// `json.dumps(j, sort_keys=True, ensure_ascii=False)`.
pub fn py_dumps_sorted(j: &J) -> String {
    let mut out = String::new();
    write_py(&mut out, j);
    out
}

fn write_compact(out: &mut String, j: &J) {
    match j {
        J::Obj(o) => {
            out.push('{');
            for (i, (k, v)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_str(out, k);
                out.push(':');
                write_compact(out, v);
            }
            out.push('}');
        }
        J::Arr(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_compact(out, x);
            }
            out.push(']');
        }
        J::Float(f) if !f.is_finite() => out.push_str("null"),
        other => write_py(out, other),
    }
}

/// Compact wire JSON in document order.
pub fn compact(j: &J) -> String {
    let mut out = String::new();
    write_compact(&mut out, j);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_separators_sorting_and_escapes() {
        let j = J::Obj(vec![
            ("b".into(), J::Arr(vec![J::Int(1), J::s("x")])),
            ("a".into(), J::s("é \"q\" \\ \n\t\u{1}\u{7f}—")),
            ("é".into(), J::Bool(true)),
            ("Z".into(), J::Null),
        ]);
        assert_eq!(
            py_dumps_sorted(&j),
            "{\"Z\": null, \"a\": \"é \\\"q\\\" \\\\ \\n\\t\\u0001\u{7f}—\", \"b\": [1, \"x\"], \"é\": true}"
        );
        assert_eq!(
            compact(&j),
            "{\"b\":[1,\"x\"],\"a\":\"é \\\"q\\\" \\\\ \\n\\t\\u0001\u{7f}—\",\"é\":true,\"Z\":null}"
        );
    }

    #[test]
    fn python_float_repr() {
        for (x, want) in [
            (1.0, "1.0"),
            (0.5, "0.5"),
            (100.0, "100.0"),
            (1e16, "1e+16"),
            (1.5e16, "1.5e+16"),
            (123456789012345.6, "123456789012345.6"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.25e-7, "1.25e-07"),
            (-2.5, "-2.5"),
            (0.1 + 0.2, "0.30000000000000004"),
        ] {
            assert_eq!(py_float(x), want, "{x}");
        }
    }

    #[test]
    fn from_value_numbers() {
        let v: Value =
            serde_json::from_str(r#"{"n": 3, "f": 1.0, "big": 18446744073709551615}"#).unwrap();
        assert_eq!(
            py_dumps_sorted(&J::from_value(&v)),
            "{\"big\": 18446744073709551615, \"f\": 1.0, \"n\": 3}"
        );
    }
}
