//! Stage 1 — Canonicalization (operator N), producing *views*.
//!
//! Port of `care/canonicalization.py`. The reference rewrites the command in
//! place (IFS, variable splitting, substitution collapse) and then APPENDS
//! decoded payloads as `\x1f<TAG>…</TAG>\x1f` marker text, which downstream
//! layers then parse as shell (FIX-006). cancelli instead returns a list of
//! views: the raw command, the in-place rewrite (when it differs), and one
//! view per decoded/unwrapped payload. Every layer scores `max` over views.
//! Each decoded view is itself canonicalized, bounded by [`MAX_DEPTH`] and
//! [`MAX_VIEWS`].

use serde::Serialize;

use crate::fixes::Tags;
use crate::py_re;
use crate::pyre::py_isspace;

/// Maximum decode/unwrap nesting depth.
pub const MAX_DEPTH: usize = 3;
/// Maximum number of views per command.
pub const MAX_VIEWS: usize = 16;
/// Reference cap on unwrapped `sh -c` bodies (chars).
const SHELL_C_MAX: usize = 4000;

/// How a view was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKind {
    /// The command exactly as the agent submitted it.
    Raw,
    /// IFS / variable-splitting / substitution-collapse rewrite.
    Rewritten,
    /// `base64.b64decode('…')` inside a Python one-liner (`PY_B64`).
    PyB64,
    /// Base64 token in a `base64 -d` context (`B64DEC`).
    B64Dec,
    /// `printf '\xNN…'` (`HEXDEC`).
    HexDec,
    /// `printf '\0NNN…'` (`OCTDEC`).
    OctDec,
    /// Body of `sh -c '…'` / `busybox sh -c '…'` (`SHELL_C`).
    ShellC,
}

/// One verification target.
#[derive(Debug, Clone, Serialize)]
pub struct View {
    /// Derivation.
    pub kind: ViewKind,
    /// Text of the view.
    pub text: String,
    /// Decode depth (raw = 0).
    pub depth: usize,
    /// Index of the view this one was derived from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<usize>,
}

// -------------- IFS --------------

py_re!(re_ifs_brace, r"\$\{IFS(?:[%#][^}]*)?\}");
py_re!(re_ifs_plain, r"\$IFS\b");
py_re!(re_ifs_glued, r"\$IFS([A-Za-z_]\w*)");
py_re!(re_multi_space, r"  +");

/// `expand_ifs` (canonicalization.py:33-43).
pub fn expand_ifs(cmd: &str) -> String {
    let out = re_ifs_brace().sub(cmd, " ");
    let out = re_ifs_plain().sub(&out, " ");
    let out = re_ifs_glued().sub(&out, r" \1");
    re_multi_space().sub(&out, " ")
}

// -------------- Substitution-nesting collapse --------------

py_re!(re_bt_echo, r"`\s*echo\s+([A-Za-z0-9_./@:\-]+)\s*`");
py_re!(
    re_bt_printf,
    r#"`\s*printf\s+['"]([A-Za-z0-9_./@:\-]+)['"]\s*`"#
);
py_re!(re_sub_echo, r"\$\(\s*echo\s+([A-Za-z0-9_./@:\-]+)\s*\)");
py_re!(
    re_sub_printf,
    r#"\$\(\s*printf\s+["']([A-Za-z0-9_./@:\-]+)["']\s*\)"#
);
py_re!(
    re_sub_printf_s,
    r#"\$\(\s*printf\s+["']%s["']\s+([A-Za-z0-9_./@:\-]+)\s*\)"#
);
py_re!(
    re_sub_printf_var,
    r#"\$\(\s*printf\s+["']%s["']\s+(\$\w+)\s*\)"#
);
py_re!(
    re_sub_glued,
    r#"\$\(\s*([A-Za-z0-9_./@:\-]+)(?:""|'')([A-Za-z0-9_./@:\-]+)\s*\)"#
);
py_re!(
    re_glued,
    r#"([A-Za-z0-9_./@:\-]+)(?:""|'')([A-Za-z0-9_./@:\-]+)"#
);
py_re!(re_empty_sub, r"\$\(\s*\)|``");

/// `collapse_substitution` (canonicalization.py:48-79).
pub fn collapse_substitution(cmd: &str) -> String {
    let mut out = cmd.to_string();
    for _ in 0..10 {
        let prev = out.clone();
        out = re_bt_echo().sub(&out, r"\1");
        out = re_bt_printf().sub(&out, r"\1");
        out = re_sub_echo().sub(&out, r"\1");
        out = re_sub_printf().sub(&out, r"\1");
        out = re_sub_printf_s().sub(&out, r"\1");
        out = re_sub_printf_var().sub(&out, r"\1");
        out = re_sub_glued().sub(&out, r"\1\2");
        out = re_glued().sub(&out, r"\1\2");
        out = re_empty_sub().sub(&out, "");
        if out == prev {
            break;
        }
    }
    out
}

// -------------- Variable-splitting expansion --------------

py_re!(
    re_assign,
    r#"(?:^|;|\s|&&|\|\|)\s*([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|'([^']*)'|([^\s;|&]+))"#
);
py_re!(re_var_brace, r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}");
py_re!(re_var_plain, r"\$([A-Za-z_][A-Za-z0-9_]*)");

/// `expand_variables` (canonicalization.py:84-111).
pub fn expand_variables(cmd: &str) -> String {
    let mut assigns: Vec<(String, String)> = Vec::new();
    for caps in re_assign().captures(cmd) {
        let Some(name) = caps.get(1).cloned().flatten() else {
            continue;
        };
        let val = caps
            .get(3)
            .cloned()
            .flatten()
            .or_else(|| caps.get(4).cloned().flatten())
            .or_else(|| caps.get(5).cloned().flatten());
        let Some(val) = val else { continue };
        if val.chars().count() > 40 || val.chars().any(|c| "()[]<>|&;\\".contains(c)) {
            continue;
        }
        if let Some(slot) = assigns.iter_mut().find(|(n, _)| *n == name) {
            slot.1 = val;
        } else {
            assigns.push((name, val));
        }
    }
    if assigns.is_empty() {
        return cmd.to_string();
    }
    let lookup = |g: &[Option<&str>]| -> String {
        let name = g.get(1).copied().flatten().unwrap_or("");
        assigns
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| g[0].unwrap_or("").to_string())
    };
    let mut out = cmd.to_string();
    for _ in 0..2 {
        out = re_var_brace().replace_with(&out, lookup);
        out = re_var_plain().replace_with(&out, lookup);
    }
    out
}

// -------------- Python-compatible decoding helpers --------------

/// `bytes.decode('utf-8', errors='ignore')`.
pub fn utf8_ignore(bytes: &[u8]) -> String {
    let mut s = String::new();
    for chunk in bytes.utf8_chunks() {
        s.push_str(chunk.valid());
    }
    s
}

/// `base64.b64decode(s, validate=True)` (strict mode).
pub fn b64decode_strict(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let b = s.as_bytes();
    let pads = b.iter().rev().take_while(|&&c| c == b'=').count();
    let data = &b[..b.len() - pads];
    if pads > 2 || !b.len().is_multiple_of(4) || data.iter().any(|&c| val(c).is_none()) {
        return None;
    }
    let ok = matches!((data.len() % 4, pads), (0, 0) | (2, 2) | (3, 1));
    if !ok {
        return None;
    }
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    for chunk in data.chunks(4) {
        let mut acc: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= val(c).unwrap_or(0) << (18 - 6 * i);
        }
        let n = chunk.len() - 1;
        for i in 0..n {
            out.push(((acc >> (16 - 8 * i)) & 0xff) as u8);
        }
    }
    Some(out)
}

/// Approximation of Python `str.isprintable()` for one character: ASCII is
/// exact; for non-ASCII, control and whitespace characters are treated as
/// non-printable (Python also rejects format/private-use/unassigned code
/// points, which this approximation accepts — documented limitation).
pub fn py_char_printable(c: char) -> bool {
    if c.is_ascii() {
        return (' '..='~').contains(&c);
    }
    !(c.is_control() || c.is_whitespace())
}

// -------------- Base64 payload inlining --------------

py_re!(re_py_b64, r#"base64\.b64decode\(['"]([A-Za-z0-9+/=]+)['"]"#);
py_re!(re_b64_ctx, r"\bbase64\s+(-d|--decode)\b");
// EXT-006: macOS `base64 -D` (BSD base64 decode flag).
py_re!(re_b64_ctx_macos, r"\bbase64\s+-D\b");
py_re!(re_b64_candidate_ref, r"\b[A-Za-z0-9+/]{12,}={0,2}\b");
py_re!(re_b64_run, r"[A-Za-z0-9+/]{10,}={0,2}");

/// Candidates the reference regex yields (`\b…={0,2}\b`), used both to
/// reproduce reference behaviour and to detect when FIX-007 changed it.
fn b64_candidates_reference(cmd: &str) -> Vec<String> {
    re_b64_candidate_ref()
        .captures(cmd)
        .into_iter()
        .filter_map(|c| c.into_iter().next().flatten())
        .collect()
}

/// FIX-007: maximal base64-alphabet runs plus their `=` padding, at least
/// 12 characters *including* padding. The reference requires 12 alphabet
/// characters before the padding and then a trailing `\b`, which backtracks
/// off the padding when a quote or space follows; either way padded
/// payloads fail its `len % 4 == 0` check and are never decoded. The run regex is greedy over the alphabet and
/// matches are non-overlapping, so every match is already a maximal run.
fn b64_candidates_fixed(cmd: &str) -> Vec<String> {
    re_b64_run()
        .captures(cmd)
        .into_iter()
        .filter_map(|c| c.into_iter().next().flatten())
        .collect()
}

fn b64_decode_payload(s: &str) -> Option<String> {
    if s.chars().count() < 12 || !s.len().is_multiple_of(4) {
        return None;
    }
    let dec = utf8_ignore(&b64decode_strict(s)?);
    if !dec.is_empty()
        && dec
            .chars()
            .all(|c| py_char_printable(c) || "\n\t ".contains(c))
    {
        Some(dec)
    } else {
        None
    }
}

fn inline_base64(cmd: &str, tags: &mut Tags) -> Vec<(ViewKind, String)> {
    let mut out = Vec::new();
    for caps in re_py_b64().captures(cmd) {
        let Some(payload) = caps.get(1).cloned().flatten() else {
            continue;
        };
        if let Some(bytes) = b64decode_strict(&payload) {
            let dec = utf8_ignore(&bytes);
            let printable = dec.chars().all(py_char_printable);
            if printable || dec.contains('\n') || dec.contains('\t') {
                out.push((ViewKind::PyB64, dec));
            }
        }
    }
    let ctx_ref = re_b64_ctx().is_match(cmd);
    let ctx_mac = !ctx_ref && re_b64_ctx_macos().is_match(cmd);
    if ctx_ref || ctx_mac {
        let reference: Vec<String> = b64_candidates_reference(cmd)
            .into_iter()
            .filter_map(|s| b64_decode_payload(&s))
            .collect();
        for s in b64_candidates_fixed(cmd) {
            if let Some(dec) = b64_decode_payload(&s) {
                if ctx_mac {
                    tags.ext("EXT-006");
                } else if !reference.contains(&dec) {
                    tags.fix("FIX-007");
                }
                out.push((ViewKind::B64Dec, dec));
            }
        }
    }
    out
}

// -------------- Hex / octal printf decoding --------------

py_re!(
    re_printf_hex,
    r#"printf\s+['"]((?:\\x[0-9a-fA-F]{2})+)['"]"#
);
py_re!(re_hex_byte, r"\\x([0-9a-fA-F]{2})");
py_re!(re_printf_oct, r#"printf\s+['"]((?:\\0[0-7]{2,3})+)['"]"#);
py_re!(re_oct_byte, r"\\0([0-7]{2,3})");

fn decode_printf(cmd: &str) -> Vec<(ViewKind, String)> {
    let mut out = Vec::new();
    for caps in re_printf_hex().captures(cmd) {
        let Some(seq) = caps.get(1).cloned().flatten() else {
            continue;
        };
        let bytes: Vec<u8> = re_hex_byte()
            .captures(&seq)
            .into_iter()
            .filter_map(|c| c.get(1).cloned().flatten())
            .filter_map(|h| u8::from_str_radix(&h, 16).ok())
            .collect();
        let dec = utf8_ignore(&bytes);
        if !dec.is_empty() {
            out.push((ViewKind::HexDec, dec));
        }
    }
    for caps in re_printf_oct().captures(cmd) {
        let Some(seq) = caps.get(1).cloned().flatten() else {
            continue;
        };
        let vals: Vec<u32> = re_oct_byte()
            .captures(&seq)
            .into_iter()
            .filter_map(|c| c.get(1).cloned().flatten())
            .filter_map(|o| u32::from_str_radix(&o, 8).ok())
            .collect();
        // Python: bytes(int(o, 8) ...) raises ValueError (> 255) -> skip.
        let Ok(bytes) = vals
            .into_iter()
            .map(u8::try_from)
            .collect::<Result<Vec<u8>, _>>()
        else {
            continue;
        };
        let dec = utf8_ignore(&bytes);
        if !dec.is_empty() {
            out.push((ViewKind::OctDec, dec));
        }
    }
    out
}

// -------------- Shell-wrapper unwrap --------------

const SHELL_NAMES: &[&str] = &["sh", "bash", "dash", "zsh", "ash", "ksh"];

/// Python `shlex.split(s, posix=True)` (comments disabled). `None` on
/// `ValueError` (unterminated quote / trailing escape).
pub fn shlex_split(s: &str) -> Option<Vec<String>> {
    #[derive(Clone, Copy, PartialEq)]
    enum St {
        Space,
        Word,
        Quote(char),
        Escape(Esc),
    }
    #[derive(Clone, Copy, PartialEq)]
    enum Esc {
        Word,
        Dq,
    }
    let ws = |c: char| matches!(c, ' ' | '\t' | '\r' | '\n');
    let mut toks = Vec::new();
    let mut tok = String::new();
    let mut quoted = false;
    let mut st = St::Space;
    for c in s.chars() {
        match st {
            St::Space => {
                if ws(c) {
                    continue;
                } else if c == '\\' {
                    st = St::Escape(Esc::Word);
                } else if c == '\'' || c == '"' {
                    st = St::Quote(c);
                } else {
                    tok.push(c);
                    st = St::Word;
                }
            }
            St::Word => {
                if ws(c) {
                    st = St::Space;
                    if !tok.is_empty() || quoted {
                        toks.push(std::mem::take(&mut tok));
                        quoted = false;
                    }
                } else if c == '\'' || c == '"' {
                    st = St::Quote(c);
                } else if c == '\\' {
                    st = St::Escape(Esc::Word);
                } else {
                    tok.push(c);
                }
            }
            St::Quote(q) => {
                quoted = true;
                if c == q {
                    st = St::Word;
                } else if c == '\\' && q == '"' {
                    st = St::Escape(Esc::Dq);
                } else {
                    tok.push(c);
                }
            }
            St::Escape(e) => {
                if e == Esc::Dq && c != '\\' && c != '"' {
                    tok.push('\\');
                }
                tok.push(c);
                st = match e {
                    Esc::Word => St::Word,
                    Esc::Dq => St::Quote('"'),
                };
            }
        }
    }
    match st {
        St::Quote(_) | St::Escape(_) => None,
        St::Word => {
            if !tok.is_empty() || quoted {
                toks.push(tok);
            }
            Some(toks)
        }
        St::Space => Some(toks),
    }
}

fn unwrap_shell_c(cmd: &str) -> Vec<(ViewKind, String)> {
    let Some(toks) = shlex_split(cmd) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let flag_c = |t: &str| t.starts_with('-') && t.contains('c');
    let mut i = 0;
    while i < toks.len() {
        let t = toks[i].as_str();
        if SHELL_NAMES.contains(&t) && i + 2 < toks.len() && flag_c(&toks[i + 1]) {
            let inner = &toks[i + 2];
            let n = inner.chars().count();
            if n > 0 && n < SHELL_C_MAX {
                out.push((ViewKind::ShellC, inner.clone()));
            }
            i += 3;
            continue;
        }
        if t == "busybox" {
            let mut j = i + 1;
            if j < toks.len() && SHELL_NAMES.contains(&toks[j].as_str()) {
                j += 1;
            }
            if j + 1 < toks.len() && flag_c(&toks[j]) {
                let inner = &toks[j + 1];
                let n = inner.chars().count();
                if n > 0 && n < SHELL_C_MAX {
                    out.push((ViewKind::ShellC, inner.clone()));
                }
                i = j + 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

// -------------- Public pipeline --------------

/// In-place rewrite chain of `normalize` (IFS → variables → substitution).
pub fn rewrite(cmd: &str) -> String {
    collapse_substitution(&expand_variables(&expand_ifs(cmd)))
}

/// Decoders of `normalize`, in reference order, applied to one text.
fn decode_all(text: &str, tags: &mut Tags) -> Vec<(ViewKind, String)> {
    let mut out = inline_base64(text, tags);
    out.extend(decode_printf(text));
    out.extend(unwrap_shell_c(text));
    out
}

/// Produce the views of a command.
pub fn views(cmd: &str, tags: &mut Tags) -> Vec<View> {
    let mut views = vec![View {
        kind: ViewKind::Raw,
        text: cmd.to_string(),
        depth: 0,
        parent: None,
    }];
    let mut i = 0;
    while i < views.len() && views.len() < MAX_VIEWS {
        // Rewritten views are terminal for the rewrite step (idempotent
        // enough; the reference applies it once) but still get decoded.
        let (base_idx, depth) = (i, views[i].depth);
        let base_text = if views[i].kind == ViewKind::Rewritten {
            views[i].text.clone()
        } else {
            let rw = rewrite(&views[i].text);
            if rw != views[i].text {
                push_view(&mut views, ViewKind::Rewritten, rw.clone(), depth, base_idx);
                // decode the rewritten form (it is what the reference decodes)
                i += 1;
                continue;
            }
            rw
        };
        if depth < MAX_DEPTH {
            for (kind, text) in decode_all(&base_text, tags) {
                if views.len() >= MAX_VIEWS {
                    break;
                }
                if text.chars().all(py_isspace) {
                    continue;
                }
                push_view(&mut views, kind, text, depth + 1, base_idx);
            }
        }
        i += 1;
    }
    if views.len() > 1 {
        tags.fix("FIX-006");
    }
    views
}

fn push_view(views: &mut Vec<View>, kind: ViewKind, text: String, depth: usize, parent: usize) {
    if views.iter().any(|v| v.text == text) {
        return;
    }
    views.push(View {
        kind,
        text,
        depth,
        parent: Some(parent),
    });
}

/// Reference-equivalent marker string (`normalize` output), for display and
/// the `analyze` debug output only. Never fed to the layers.
pub fn reference_normalized(cmd: &str) -> String {
    let x = rewrite(cmd);
    let mut out = x.clone();
    for (kind, dec) in inline_base64_reference(&x) {
        out.push_str(&format!(
            " \u{1f}<{}>{dec}</{}>\u{1f}",
            tag(kind),
            tag(kind)
        ));
    }
    let with_b64 = out.clone();
    for (kind, dec) in decode_printf(&with_b64) {
        out.push_str(&format!(
            " \u{1f}<{}>{dec}</{}>\u{1f}",
            tag(kind),
            tag(kind)
        ));
    }
    let with_printf = out.clone();
    for (kind, dec) in unwrap_shell_c(&with_printf) {
        out.push_str(&format!(
            " \u{1f}<{}>{dec}</{}>\u{1f}",
            tag(kind),
            tag(kind)
        ));
    }
    out
}

fn inline_base64_reference(cmd: &str) -> Vec<(ViewKind, String)> {
    let mut scratch = Tags::default();
    let mut out: Vec<(ViewKind, String)> = inline_base64(cmd, &mut scratch)
        .into_iter()
        .filter(|(k, _)| *k == ViewKind::PyB64)
        .collect();
    if re_b64_ctx().is_match(cmd) {
        for s in b64_candidates_reference(cmd) {
            if let Some(dec) = b64_decode_payload(&s) {
                out.push((ViewKind::B64Dec, dec));
            }
        }
    }
    out
}

fn tag(kind: ViewKind) -> &'static str {
    match kind {
        ViewKind::Raw | ViewKind::Rewritten => "",
        ViewKind::PyB64 => "PY_B64",
        ViewKind::B64Dec => "B64DEC",
        ViewKind::HexDec => "HEXDEC",
        ViewKind::OctDec => "OCTDEC",
        ViewKind::ShellC => "SHELL_C",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifs_forms() {
        assert_eq!(expand_ifs("rm${IFS}-rf${IFS}/tmp"), "rm -rf /tmp");
        assert_eq!(expand_ifs("cat$IFS/etc/passwd"), "cat /etc/passwd");
        assert_eq!(expand_ifs("x$IFSsh"), "x sh");
    }

    #[test]
    fn variable_splitting() {
        assert_eq!(
            expand_variables(r#"_z0="cur";_z1="l";$_z0$_z1 -fsSL http://e/i"#),
            r#"_z0="cur";_z1="l";curl -fsSL http://e/i"#
        );
    }

    #[test]
    fn substitution_collapse() {
        assert_eq!(collapse_substitution("$(echo curl) -s x"), "curl -s x");
        assert_eq!(
            collapse_substitution(r#"$(c""url) -fsSL x"#),
            "curl -fsSL x"
        );
    }

    #[test]
    fn shlex_matches_python() {
        assert_eq!(
            shlex_split(r#"a 'b c' "d\"e" f\ g"#).unwrap(),
            vec!["a", "b c", "d\"e", "f g"]
        );
        assert_eq!(shlex_split(r#"x "a\b""#).unwrap(), vec!["x", "a\\b"]);
        assert_eq!(shlex_split("''").unwrap(), vec![""]);
        assert_eq!(shlex_split("a\u{1f}b c").unwrap(), vec!["a\u{1f}b", "c"]);
        assert!(shlex_split("a\\").is_none());
        assert!(shlex_split("'x").is_none());
    }

    #[test]
    fn b64_strict() {
        assert_eq!(b64decode_strict("cm0gLXJmIC8=").unwrap(), b"rm -rf /");
        assert!(b64decode_strict("cm0gLXJmIC8").is_none());
        assert!(b64decode_strict("YQ=").is_none());
        assert_eq!(b64decode_strict("YW==").unwrap(), b"a");
    }

    #[test]
    fn padded_base64_is_decoded_fix_007() {
        let mut t = Tags::default();
        let v = views("eval $(echo 'cm0gLXJmIC8=' | base64 -d)", &mut t);
        assert!(
            v.iter()
                .any(|v| v.kind == ViewKind::B64Dec && v.text == "rm -rf /")
        );
        assert!(t.fixes.contains("FIX-007"));
        // The reference never decodes it.
        assert!(
            !reference_normalized("eval $(echo 'cm0gLXJmIC8=' | base64 -d)").contains("B64DEC")
        );
    }

    #[test]
    fn shell_c_view_and_reference_markers() {
        let mut t = Tags::default();
        let v = views("bash -c 'rm -rf /'", &mut t);
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].kind, ViewKind::ShellC);
        assert_eq!(v[1].text, "rm -rf /");
        assert_eq!(
            reference_normalized("bash -c 'rm -rf /'"),
            "bash -c 'rm -rf /' \u{1f}<SHELL_C>rm -rf /</SHELL_C>\u{1f}"
        );
    }

    #[test]
    fn printf_hex_and_octal() {
        let mut t = Tags::default();
        let v = views(r"printf '\x72\x6d\x20\x2d\x72\x66' | sh", &mut t);
        assert!(
            v.iter()
                .any(|v| v.kind == ViewKind::HexDec && v.text == "rm -rf")
        );
        let v = views(r"printf '\0143\0141\0164' | sh", &mut t);
        assert!(
            v.iter()
                .any(|v| v.kind == ViewKind::OctDec && v.text == "cat")
        );
    }

    #[test]
    fn macos_base64_flag_ext_006() {
        let mut t = Tags::default();
        let v = views("echo cm0gLXJmIC90bXAv | base64 -D | sh", &mut t);
        assert!(
            v.iter()
                .any(|v| v.kind == ViewKind::B64Dec && v.text == "rm -rf /tmp/")
        );
        assert!(t.exts.contains("EXT-006"));
    }
}
