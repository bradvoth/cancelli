//! Python-`re`-compatible regular expressions and string helpers.
//!
//! The CARE reference is Python 3 and matches `str` patterns, so `\b`, `\w`,
//! `\s` are Unicode-aware. Rust's `regex` crate is Unicode-aware by default,
//! but differs in a few places this module papers over:
//!
//! * Python's `\s` also matches the ASCII separators U+001C..U+001F (they are
//!   `str.isspace()`); Rust's `\s` (Unicode `White_Space`) does not. `\s` is
//!   rewritten to `[\s\x1c-\x1f]` and `\S` to `[^\s\x1c-\x1f]`.
//! * Python's `$` (no MULTILINE) matches at the end of input *or* before a
//!   final `\n`; it is rewritten to `(?:\n?\z)`. Every call site only uses
//!   `$` inside `is_match`/alternations where consuming that newline is
//!   harmless.
//! * `\Z` becomes `\z`.
//! * Lookaround and backreferences are not supported by `regex`; such
//!   patterns are compiled with `fancy-regex` (a backtracking engine that
//!   delegates everything else to `regex`).

/// Characters Python's `str.isspace()` accepts that Rust's
/// `char::is_whitespace` does not.
pub fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python `str.split()` with no arguments.
pub fn py_split(s: &str) -> Vec<&str> {
    s.split(py_isspace).filter(|t| !t.is_empty()).collect()
}

/// Python `str.strip()` with no arguments.
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(py_isspace)
}

/// Python `os.path.basename` for POSIX paths.
pub fn basename(s: &str) -> &str {
    match s.rfind('/') {
        Some(i) => &s[i + 1..],
        None => s,
    }
}

/// Python `repr(float)` for the values that appear in CARE traces (finite,
/// moderate magnitude): shortest round-trip digits, always with a `.`.
pub fn py_float_repr(x: f64) -> String {
    let s = format!("{x}");
    if s.contains('.') || s.contains('e') || s.contains("inf") || s.contains("NaN") {
        s
    } else {
        format!("{s}.0")
    }
}

/// Python `round(x, n)`: correctly rounded on the exact binary value
/// (Rust's `{:.n}` formatting is exact and ties-to-even, matching CPython).
pub fn py_round(x: f64, n: usize) -> f64 {
    format!("{x:.n$}").parse().unwrap_or(x)
}

/// Rewrite a Python pattern into `regex`-crate syntax. Returns the rewritten
/// pattern and whether it needs the backtracking engine.
pub fn translate(pat: &str) -> (String, bool) {
    let mut out = String::with_capacity(pat.len() + 16);
    let mut fancy = false;
    let mut in_class = false;
    let chars: Vec<char> = pat.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            let n = chars[i + 1];
            i += 2;
            match n {
                's' if in_class => out.push_str(r"\s\x1c-\x1f"),
                's' => out.push_str(r"[\s\x1c-\x1f]"),
                'S' if !in_class => out.push_str(r"[^\s\x1c-\x1f]"),
                'Z' => out.push_str(r"\z"),
                '1'..='9' if !in_class => {
                    fancy = true;
                    out.push('\\');
                    out.push(n);
                }
                _ => {
                    out.push('\\');
                    out.push(n);
                }
            }
            continue;
        }
        if in_class {
            if c == ']' {
                in_class = false;
            }
            out.push(c);
            i += 1;
            continue;
        }
        match c {
            '[' if matches!(
                chars.get(i + 1..i + 6),
                Some(['\\', 's', '\\', 'S', ']']) | Some(['\\', 'S', '\\', 's', ']'])
            ) =>
            {
                // `[\s\S]` = any character. `(?s:.)` is the same set but
                // compiles ~20x faster inside bounded repeats like `{0,200}`.
                out.push_str("(?s:.)");
                i += 6;
            }
            '[' => {
                in_class = true;
                out.push('[');
                i += 1;
                // A leading `^` and/or `]` are literal parts of the class.
                if i < chars.len() && chars[i] == '^' {
                    out.push('^');
                    i += 1;
                }
                if i < chars.len() && chars[i] == ']' {
                    out.push_str(r"\]");
                    i += 1;
                }
            }
            '(' if chars.get(i + 1) == Some(&'?') => {
                let rest: String = chars[i + 1..chars.len().min(i + 4)].iter().collect();
                if rest.starts_with("?=")
                    || rest.starts_with("?!")
                    || rest.starts_with("?<=")
                    || rest.starts_with("?<!")
                {
                    fancy = true;
                }
                out.push('(');
                i += 1;
            }
            '$' => {
                out.push_str(r"(?:\n?\z)");
                i += 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    (out, fancy)
}

/// A compiled Python-compatible regex.
#[derive(Debug)]
pub enum PyRegex {
    /// Compiled by the linear-time `regex` crate.
    Std(regex::Regex),
    /// Needs lookaround/backreferences: compiled by `fancy-regex`.
    Fancy(Box<fancy_regex::Regex>),
}

/// Compile error (pattern text plus engine message).
#[derive(Debug, Clone)]
pub struct PyRegexError(pub String);

impl std::fmt::Display for PyRegexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PyRegexError {}

impl PyRegex {
    /// Compile `pat` with Python semantics; `ignore_case` mirrors `re.I`.
    pub fn new(pat: &str, ignore_case: bool) -> Result<Self, PyRegexError> {
        let (t, fancy) = translate(pat);
        let t = if ignore_case { format!("(?i){t}") } else { t };
        if fancy {
            fancy_regex::Regex::new(&t)
                .map(|r| PyRegex::Fancy(Box::new(r)))
                .map_err(|e| PyRegexError(format!("{pat}: {e}")))
        } else {
            regex::Regex::new(&t)
                .map(PyRegex::Std)
                .map_err(|e| PyRegexError(format!("{pat}: {e}")))
        }
    }

    /// Compile a pattern that is a compile-time constant in this crate.
    /// Every such pattern is exercised by unit tests, so failure is a
    /// programming error surfaced at first use.
    pub fn constant(pat: &str) -> Self {
        match Self::new(pat, false) {
            Ok(r) => r,
            Err(e) => panic!("built-in pattern failed to compile: {e}"),
        }
    }

    /// Whether this regex needed the backtracking engine.
    pub fn is_fancy(&self) -> bool {
        matches!(self, PyRegex::Fancy(_))
    }

    /// `re.search(...) is not None`. A backtracking-limit error in the
    /// fancy engine counts as "no match".
    pub fn is_match(&self, s: &str) -> bool {
        match self {
            PyRegex::Std(r) => r.is_match(s),
            PyRegex::Fancy(r) => r.is_match(s).unwrap_or(false),
        }
    }

    /// `re.finditer` returning capture groups (index 0 = whole match).
    /// Only supported for `Std` regexes (all internal patterns are `Std`).
    pub fn captures(&self, s: &str) -> Vec<Vec<Option<String>>> {
        match self {
            PyRegex::Std(r) => r
                .captures_iter(s)
                .map(|c| {
                    c.iter()
                        .map(|m| m.map(|m| m.as_str().to_string()))
                        .collect()
                })
                .collect(),
            PyRegex::Fancy(r) => r
                .captures_iter(s)
                .filter_map(|c| c.ok())
                .map(|c| {
                    c.iter()
                        .map(|m| m.map(|m| m.as_str().to_string()))
                        .collect()
                })
                .collect(),
        }
    }

    /// `re.sub(pat, fn, s)` with a closure receiving the captures.
    pub fn replace_with<F>(&self, s: &str, mut f: F) -> String
    where
        F: FnMut(&[Option<&str>]) -> String,
    {
        match self {
            PyRegex::Std(r) => r
                .replace_all(s, |c: &regex::Captures<'_>| {
                    let groups: Vec<Option<&str>> =
                        c.iter().map(|m| m.map(|m| m.as_str())).collect();
                    f(&groups)
                })
                .into_owned(),
            PyRegex::Fancy(r) => r
                .replace_all(s, |c: &fancy_regex::Captures<'_, str>| {
                    let groups: Vec<Option<&str>> =
                        c.iter().map(|m| m.map(|m| m.as_str())).collect();
                    f(&groups)
                })
                .into_owned(),
        }
    }

    /// `re.sub(pat, repl, s)` where `repl` uses Python `\N` group references.
    pub fn sub(&self, s: &str, repl: &str) -> String {
        self.replace_with(s, |g| expand_py_template(repl, g))
    }
}

fn expand_py_template(repl: &str, groups: &[Option<&str>]) -> String {
    let mut out = String::new();
    let mut it = repl.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\'
            && let Some(d) = it.peek().copied()
            && let Some(n) = d.to_digit(10)
        {
            it.next();
            out.push_str(groups.get(n as usize).copied().flatten().unwrap_or(""));
            continue;
        }
        out.push(c);
    }
    out
}

/// Convenience: lazily compiled internal pattern.
#[macro_export]
macro_rules! py_re {
    ($name:ident, $pat:expr) => {
        fn $name() -> &'static $crate::pyre::PyRegex {
            static R: std::sync::OnceLock<$crate::pyre::PyRegex> = std::sync::OnceLock::new();
            R.get_or_init(|| $crate::pyre::PyRegex::constant($pat))
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_matches_python() {
        let r = PyRegex::new(r"a\sb", false).unwrap();
        assert!(r.is_match("a\u{1f}b"));
        assert!(r.is_match("a b"));
        let r = PyRegex::new(r"a\Sb", false).unwrap();
        assert!(!r.is_match("a\u{1f}b"));
        assert!(r.is_match("axb"));
        let r = PyRegex::new(r"a[\s;]b", false).unwrap();
        assert!(r.is_match("a\u{1c}b"));
        assert_eq!(py_split(" a\u{1f}b  c "), vec!["a", "b", "c"]);
    }

    #[test]
    fn dollar_matches_before_final_newline() {
        let r = PyRegex::new(r"x$", false).unwrap();
        assert!(r.is_match("x\n"));
        assert!(r.is_match("x"));
        assert!(!r.is_match("x\ny"));
    }

    #[test]
    fn lookaround_uses_fancy() {
        let r = PyRegex::new(r"/usr/(?!local/)\S+", true).unwrap();
        assert!(r.is_fancy());
        assert!(r.is_match("rm /usr/bin/x"));
        assert!(!r.is_match("rm /usr/local/x"));
    }

    #[test]
    fn unicode_word_boundary_and_case() {
        let r = PyRegex::new(r"\bRM\b", true).unwrap();
        assert!(r.is_match("é rm x"));
        assert!(!r.is_match("érm x"));
    }

    #[test]
    fn sub_with_groups() {
        let r = PyRegex::new(r"\$IFS([A-Za-z_]\w*)", false).unwrap();
        assert_eq!(r.sub("a$IFSsh", r" \1"), "a sh");
    }

    #[test]
    fn float_repr_and_round() {
        assert_eq!(py_float_repr(0.345), "0.345");
        assert_eq!(py_float_repr(1.0), "1.0");
        assert_eq!(py_round(0.30000000000000004, 4), 0.3);
        assert_eq!(py_round(2.675, 2), 2.67); // CPython: round(2.675, 2) == 2.67
    }
}
