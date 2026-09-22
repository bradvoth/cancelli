//! L3 — path-sensitive validation (s_path), port of `care/path.py`, plus
//! macOS extension tiers (`EXT-NNN`).
//!
//! Score, reason and trigger list reproduce the reference exactly (including
//! its early return on the first system-root/critical hit). In addition every
//! path is classified into a [`PathHit`] (tier + access context) so the
//! paper's `p_spath` predicate (FIX-002) can be evaluated.

use serde::Serialize;

use crate::fixes::Tags;
use crate::py_re;
use crate::pyre::{PyRegex, basename, py_split, py_strip};
use crate::tunables::PathScores;

/// Sensitivity tier of a path hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathTier {
    /// System-root sink under a destructive head.
    SystemRoot,
    /// Critical pattern (block devices, shadow, keys, kernel surfaces).
    Critical,
    /// Secret-bearing path.
    Secret,
    /// Sensitive system directory.
    SensitiveSystem,
    /// `../` traversal.
    Traversal,
}

/// Access context of a hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// Write/modify.
    Write,
    /// Read/inspect.
    Read,
    /// Neither head list applies (reference `sensitive_ambiguous`).
    Ambiguous,
}

/// One classified path.
#[derive(Debug, Clone, Serialize)]
pub struct PathHit {
    /// Path as written.
    pub path: String,
    /// Tier.
    pub tier: PathTier,
    /// Access context.
    pub access: Access,
    /// Whether the path bears secrets (credential/key/shadow files).
    pub secret_bearing: bool,
    /// EXT id when the hit comes from a macOS extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<&'static str>,
}

/// L3 result for one view.
#[derive(Debug, Clone, Serialize)]
pub struct PathResult {
    /// View index.
    pub view: usize,
    /// s_path.
    pub score: f64,
    /// Reference reason string.
    pub reason: String,
    /// Reference trigger list.
    pub triggered: Vec<String>,
    /// All classified hits.
    pub hits: Vec<PathHit>,
}

// -------------- catalogs (path.py:20-89) --------------

/// Critical patterns; `(pattern, secret_bearing, ext)`.
fn critical_patterns() -> &'static [(PyRegex, bool, Option<&'static str>)] {
    static P: std::sync::OnceLock<Vec<(PyRegex, bool, Option<&'static str>)>> =
        std::sync::OnceLock::new();
    P.get_or_init(|| {
        vec![
            (
                PyRegex::constant(r"^/dev/(sd|hd|nvme|vd|md|mmcblk|loop)"),
                false,
                None,
            ),
            (
                PyRegex::constant(r"/etc/(shadow|gshadow|sudoers)(\s|$|/)"),
                true,
                None,
            ),
            (PyRegex::constant(r"\.ssh/authorized_keys"), true, None),
            (
                PyRegex::constant(r"\.ssh/id_(rsa|ed25519|ecdsa|dsa)\b"),
                true,
                None,
            ),
            (
                PyRegex::constant(r"/proc/(sysrq-trigger|kallsyms|kcore|kmsg|self/mem|kmem)\b"),
                false,
                None,
            ),
            (
                PyRegex::constant(r"/sys/kernel/(kexec|debug|tracing|security)\b"),
                false,
                None,
            ),
            // EXT-005: macOS whole-disk / raw-disk devices.
            (
                PyRegex::constant(r"^/dev/r?disk[0-9]"),
                false,
                Some("EXT-005"),
            ),
        ]
    })
}

const SECRET_READ_PATHS: &[(&str, Option<&str>)] = &[
    ("~/.ssh/id_", None),
    ("~/.ssh/authorized_keys", None),
    ("~/.aws/credentials", None),
    ("~/.docker/config.json", None),
    ("~/.kube/config", None),
    ("~/.gnupg/", None),
    ("~/.netrc", None),
    ("~/.mysql_history", None),
    ("/etc/shadow", None),
    ("/etc/gshadow", None),
    ("/etc/sudoers", None),
    ("/root/.ssh", None),
    ("~/Library/Keychains/", Some("EXT-001")),
    ("/Library/Keychains/", Some("EXT-001")),
];

const SENSITIVE_WRITE_PATHS: &[(&str, Option<&str>)] = &[
    ("/etc/", None),
    ("/boot/", None),
    ("/sys/", None),
    ("/proc/sys/", None),
    ("/root/", None),
    ("/var/log/", None),
    ("/var/lib/", None),
    ("/dev/", None),
    ("/System/", Some("EXT-003")),
    ("/Library/LaunchAgents/", Some("EXT-003")),
    ("/Library/LaunchDaemons/", Some("EXT-003")),
    ("/Library/StartupItems/", Some("EXT-003")),
    ("~/Library/LaunchAgents/", Some("EXT-003")),
];

const BENIGN_DEVICE_PATHS: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/stdin",
    "/dev/tty",
    "/dev/pts/",
    "/dev/fd/",
];

const SYSTEM_ROOT_TARGETS: &[(&str, Option<&str>)] = &[
    ("/", None),
    ("/*", None),
    ("/home", None),
    ("/etc", None),
    ("/usr", None),
    ("/var", None),
    ("/opt", None),
    ("/srv", None),
    ("/boot", None),
    ("/bin", None),
    ("/sbin", None),
    ("/lib", None),
    ("/lib64", None),
    ("/System", Some("EXT-004")),
    ("/Library", Some("EXT-004")),
    ("/Applications", Some("EXT-004")),
    ("/Users", Some("EXT-004")),
    ("/private", Some("EXT-004")),
    ("/Volumes", Some("EXT-004")),
];

const READ_ONLY_HEADS: &[&str] = &[
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "wc",
    "nl",
    "od",
    "xxd",
    "hexdump",
    "strings",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "ack",
    "find",
    "locate",
    "which",
    "whereis",
    "type",
    "ls",
    "ll",
    "dir",
    "tree",
    "file",
    "stat",
    "readlink",
    "realpath",
    "du",
    "df",
    "awk",
    "sed",
    "cut",
    "sort",
    "uniq",
    "tr",
    "column",
    "paste",
    "diff",
    "cmp",
    "jq",
    "yq",
    "echo",
    "printf",
    "ps",
    "top",
    "htop",
    "free",
    "uptime",
    "date",
    "uname",
    "id",
    "whoami",
    "hostname",
    "env",
    "printenv",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "mount",
    "rsync",
];

const WRITE_HEADS: &[&str] = &[
    "cp",
    "mv",
    "mkdir",
    "touch",
    "ln",
    "rm",
    "rmdir",
    "dd",
    "mkfs",
    "shred",
    "wipefs",
    "fdisk",
    "truncate",
    "fallocate",
    "chmod",
    "chown",
    "chgrp",
    "setcap",
    "tar",
    "zip",
    "unzip",
    "gzip",
    "gunzip",
    "apt",
    "apt-get",
    "yum",
    "dnf",
    "pacman",
    "npm",
    "pip",
    "pip3",
    "make",
    "gcc",
    "g++",
    "cmake",
    "git",
];

const DESTRUCTIVE_HEADS: &[&str] = &[
    "rm", "dd", "mkfs", "shred", "wipefs", "fdisk", "parted", "gdisk", "sgdisk", "cfdisk",
    "truncate",
];

// -------------- helpers --------------

/// `_head` without the reference's `<SHELL_C>` marker lookup (FIX-006:
/// unwrapped bodies are separate views with their own head).
fn head(cmd: &str) -> &str {
    py_split(py_strip(cmd))
        .first()
        .map(|t| basename(t))
        .unwrap_or("")
}

/// FIX-010: `mkfs.<fs>` behaves like `mkfs`.
fn in_heads(h: &str, heads: &[&str], tags: &mut Tags) -> bool {
    if heads.contains(&h) {
        return true;
    }
    if heads.contains(&"mkfs") && h.starts_with("mkfs.") {
        tags.fix("FIX-010");
        return true;
    }
    false
}

py_re!(re_redirect_write, r"(?:^|[^0-9&])>{1,2}\s*\S");
py_re!(re_sed_inplace, r"\bsed\s+[^|;]*-i\b");
py_re!(re_sed_seg, r"\bsed\s+[^|;]+");
py_re!(re_tee_any, r"\btee\b\s+(-a\s+)?\S");
py_re!(re_dev_overwrite, r">\s*/dev/(sd|hd|nvme|vd)");
py_re!(re_redirect_target, r">{1,2}\s*([^\s;&|]+)");
py_re!(re_tee_target, r"\btee\b\s+(?:-a\s+)?([^\s|&;]+)");
py_re!(re_token, r#""[^"]+"|'[^']+'|\S+"#);

fn has_write_context(cmd: &str, tags: &mut Tags) -> bool {
    let h = head(cmd);
    if in_heads(h, WRITE_HEADS, tags) {
        return true;
    }
    if h == "sudo" {
        let toks = py_split(cmd);
        if toks.len() > 1 && in_heads(basename(toks[1]), WRITE_HEADS, tags) {
            return true;
        }
    }
    // Reference: `(?<![0-9&])>{1,2}\s*\S` — equivalent for a boolean search.
    if re_redirect_write().is_match(cmd) {
        return true;
    }
    if h == "sed" && re_sed_inplace().is_match(cmd) {
        return true;
    }
    re_tee_any().is_match(cmd)
}

fn is_destructive_head(cmd: &str, tags: &mut Tags) -> bool {
    let h = head(cmd);
    if in_heads(h, DESTRUCTIVE_HEADS, tags) {
        return true;
    }
    if h == "sudo" {
        let toks = py_split(cmd);
        return toks.len() > 1 && in_heads(basename(toks[1]), DESTRUCTIVE_HEADS, tags);
    }
    re_dev_overwrite().is_match(cmd)
}

/// Python `os.path.expanduser` for `~` and `~/…` (HOME with trailing `/`
/// stripped). `~user` forms are returned unchanged (no passwd lookup).
pub fn expanduser(p: &str, home: &str) -> String {
    if p == "~" || p.starts_with("~/") {
        let h = home.trim_end_matches('/');
        let out = format!("{h}{}", &p[1..]);
        if out.is_empty() { "/".to_string() } else { out }
    } else {
        p.to_string()
    }
}

fn strip_quotes(t: &str) -> &str {
    t.trim_matches(|c| c == '"' || c == '\'')
}

fn starts_any(s: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| s.starts_with(p))
}

/// `_extract_paths` (path.py:248-270), minus the marker stripping (no
/// markers exist with views).
pub fn extract_paths(cmd: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for caps in re_token().captures(cmd) {
        let Some(tok) = caps.into_iter().next().flatten() else {
            continue;
        };
        let t = strip_quotes(&tok);
        if t.is_empty() {
            continue;
        }
        if t.starts_with('-') && !t.starts_with('/') {
            if let Some((_, rhs)) = t.split_once('=')
                && (starts_any(rhs, &["/", "~", "./"]) || rhs.contains("../"))
            {
                paths.push(rhs.to_string());
            }
            continue;
        }
        if starts_any(t, &["/", "~", "./"]) || t.contains("../") {
            paths.push(t.to_string());
        }
    }
    for caps in re_redirect_target().captures(cmd) {
        let Some(tgt) = caps.get(1).cloned().flatten() else {
            continue;
        };
        let tgt = strip_quotes(&tgt);
        if !tgt.is_empty() && (starts_any(tgt, &["/", "~", "./"]) || tgt.contains("../")) {
            paths.push(tgt.to_string());
        }
    }
    paths
}

/// EXT-002: macOS `/private/{etc,var,tmp}` are the real locations of
/// `/etc`, `/var`, `/tmp`.
fn alias_private(p: &str) -> Option<String> {
    for d in ["/private/etc", "/private/var", "/private/tmp"] {
        if let Some(rest) = p.strip_prefix(d)
            && (rest.is_empty() || rest.starts_with('/'))
        {
            return Some(p["/private".len()..].to_string());
        }
    }
    None
}

/// `PathValidator.validate` (path.py:151-245) on one view, built-in scores.
pub fn validate(view: usize, cmd: &str, home: &str, tags: &mut Tags) -> PathResult {
    validate_with(view, cmd, home, tags, &PathScores::default())
}

/// [`validate`] with tunable tier scores (`care.path`). The early return on
/// the first system-root/critical hit is kept whatever its score.
pub fn validate_with(
    view: usize,
    cmd: &str,
    home: &str,
    tags: &mut Tags,
    sc: &PathScores,
) -> PathResult {
    let mut res = PathResult {
        view,
        score: 0.0,
        reason: "paths_ok".into(),
        triggered: Vec::new(),
        hits: Vec::new(),
    };
    let paths = extract_paths(cmd);
    if paths.is_empty() {
        return res;
    }
    let h = head(cmd);
    let is_read = READ_ONLY_HEADS.contains(&h);
    let writing = has_write_context(cmd, tags);
    let destructive = is_destructive_head(cmd, tags);

    let mut write_targets: Vec<String> = Vec::new();
    for caps in re_redirect_target().captures(cmd) {
        if let Some(t) = caps.get(1).cloned().flatten() {
            let t = strip_quotes(&t).to_string();
            write_targets.push(expanduser(&t, home));
            write_targets.push(t);
        }
    }
    if re_sed_inplace().is_match(cmd)
        && let Some(seg) = re_sed_seg().captures(cmd).into_iter().next()
        && let Some(seg) = seg.into_iter().next().flatten()
    {
        for tok in py_split(&seg) {
            let t = strip_quotes(tok);
            if t.starts_with('/') || t.starts_with('~') {
                write_targets.push(t.to_string());
                write_targets.push(expanduser(t, home));
            }
        }
    }
    for caps in re_tee_target().captures(cmd) {
        if let Some(t) = caps.get(1).cloned().flatten() {
            let t = strip_quotes(&t);
            if starts_any(t, &["/", "~", "./"]) {
                write_targets.push(t.to_string());
                write_targets.push(expanduser(t, home));
            }
        }
    }

    // `decided` = the reference has already returned (score frozen at 1.0);
    // hits are still collected for the skip predicates.
    let mut decided = false;
    let mut max_score = 0.0_f64;
    let add_trig = |res: &mut PathResult, p: &str, decided: bool| {
        if !decided && !res.triggered.iter().any(|x| x == p) {
            res.triggered.push(p.to_string());
        }
    };

    for p0 in &paths {
        let expanded0 = expanduser(p0, home);
        let is_write_this = write_targets.iter().any(|w| w == p0 || *w == expanded0);
        let (p, expanded, aliased) = match (alias_private(p0), alias_private(&expanded0)) {
            (Some(a), Some(b)) => (a, b, true),
            (Some(a), None) => (a, expanded0.clone(), true),
            (None, Some(b)) => (p0.clone(), b, true),
            (None, None) => (p0.clone(), expanded0.clone(), false),
        };
        let alias_ext = if aliased { Some("EXT-002") } else { None };
        let access = if is_write_this || (writing && !is_read) {
            Access::Write
        } else if is_read && !writing {
            Access::Read
        } else {
            Access::Ambiguous
        };

        // (a) system-root sink, destructive heads only
        if let Some((_, ext)) = SYSTEM_ROOT_TARGETS
            .iter()
            .find(|(r, _)| *r == p || *r == expanded)
            && destructive
        {
            let ext = ext.or(alias_ext);
            res.hits.push(PathHit {
                path: p0.clone(),
                tier: PathTier::SystemRoot,
                access: Access::Write,
                secret_bearing: false,
                ext,
            });
            if let Some(e) = ext {
                tags.ext(e);
            }
            if !decided {
                add_trig(&mut res, p0, false);
                res.score = sc.system_root;
                res.reason = format!("destructive_on_system_root:{p0}");
                decided = true;
            }
            continue;
        }

        // (b) critical patterns
        if let Some((_, secret, ext)) = critical_patterns()
            .iter()
            .find(|(pat, _, _)| pat.is_match(&expanded) || pat.is_match(&p))
        {
            let ext = ext.or(alias_ext);
            res.hits.push(PathHit {
                path: p0.clone(),
                tier: PathTier::Critical,
                access,
                secret_bearing: *secret,
                ext,
            });
            if let Some(e) = ext {
                tags.ext(e);
            }
            if !decided {
                add_trig(&mut res, p0, false);
                res.score = sc.critical;
                res.reason = format!("critical_path:{p0}");
                decided = true;
            }
            continue;
        }

        // (c) secret-bearing paths
        for (sp, ext) in SECRET_READ_PATHS {
            let tail = sp.trim_start_matches('~');
            if expanded.starts_with(sp) || p.starts_with(sp) || expanded.contains(tail) {
                let ext = ext.or(alias_ext);
                res.hits.push(PathHit {
                    path: p0.clone(),
                    tier: PathTier::Secret,
                    access,
                    secret_bearing: true,
                    ext,
                });
                if let Some(e) = ext {
                    tags.ext(e);
                }
                if !decided && sc.secret > max_score {
                    max_score = sc.secret;
                    res.reason = format!("secret_path:{p0}");
                }
                add_trig(&mut res, p0, decided);
            }
        }

        // (d) sensitive system paths; benign device files short-circuit
        // (including the traversal check, as in the reference)
        if BENIGN_DEVICE_PATHS
            .iter()
            .any(|b| expanded.starts_with(b) || p.starts_with(b))
        {
            continue;
        }
        for (sp, ext) in SENSITIVE_WRITE_PATHS {
            let spx = expanduser(sp, home);
            let matched = expanded.starts_with(sp)
                || p.starts_with(sp)
                || (sp.starts_with('~') && expanded.starts_with(&spx));
            if matched {
                let (score, why) = match access {
                    Access::Write => (sc.sensitive_write, "sensitive_write"),
                    Access::Read => (sc.sensitive_read, "sensitive_read"),
                    Access::Ambiguous => (sc.sensitive_ambiguous, "sensitive_ambiguous"),
                };
                let ext = ext.or(alias_ext);
                res.hits.push(PathHit {
                    path: p0.clone(),
                    tier: PathTier::SensitiveSystem,
                    access,
                    secret_bearing: false,
                    ext,
                });
                if let Some(e) = ext {
                    tags.ext(e);
                }
                if !decided && score > max_score {
                    max_score = score;
                    res.reason = format!("{why}:{p0}");
                }
                add_trig(&mut res, p0, decided);
            }
        }

        // (e) traversal
        if p.contains("../") {
            let score = if is_read {
                sc.traversal_read
            } else {
                sc.traversal
            };
            res.hits.push(PathHit {
                path: p0.clone(),
                tier: PathTier::Traversal,
                access,
                secret_bearing: false,
                ext: None,
            });
            if !decided && score > max_score {
                max_score = score;
                res.reason = format!("path_traversal:{p0}");
            }
            add_trig(&mut res, p0, decided);
        }
    }
    if !decided {
        res.score = max_score;
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "/home/user";

    fn v(c: &str) -> (f64, String) {
        let r = validate(0, c, HOME, &mut Tags::default());
        (r.score, r.reason)
    }

    #[test]
    fn reference_examples() {
        assert_eq!(
            v("cat /etc/os-release"),
            (0.10, "sensitive_read:/etc/os-release".into())
        );
        assert_eq!(
            v("echo x >> /etc/profile"),
            (0.70, "sensitive_write:/etc/profile".into())
        );
        assert_eq!(v("rm -rf /"), (1.0, "destructive_on_system_root:/".into()));
        assert_eq!(v("find / -name x"), (0.0, "paths_ok".into()));
        assert_eq!(v("cat ~/.ssh/id_rsa").0, 1.0);
        assert_eq!(
            v("cat ~/.aws/credentials"),
            (0.85, "secret_path:~/.aws/credentials".into())
        );
        assert_eq!(v("echo hi > /dev/null"), (0.0, "paths_ok".into()));
        assert_eq!(v("cat ../../x"), (0.3, "path_traversal:../../x".into()));
        assert_eq!(
            v("rm -rf /var/log/*"),
            (0.70, "sensitive_write:/var/log/*".into())
        );
        assert_eq!(
            v("curl -o /etc/x http://e"),
            (0.35, "sensitive_ambiguous:/etc/x".into())
        );
    }

    #[test]
    fn mkfs_variants_fix_010() {
        let mut t = Tags::default();
        let r = validate(0, "mkfs.ext4 /dev/xvdf", HOME, &mut t);
        assert_eq!(r.score, 0.70);
        assert!(t.fixes.contains("FIX-010"));
        assert_eq!(v("mkfs /dev/xvdf").0, 0.70);
    }

    #[test]
    fn macos_extensions() {
        let mut t = Tags::default();
        assert_eq!(
            validate(0, "cat ~/Library/Keychains/login.keychain-db", HOME, &mut t).score,
            0.85
        );
        assert!(t.exts.contains("EXT-001"));
        let mut t = Tags::default();
        assert_eq!(
            validate(0, "echo x >> /private/etc/hosts", HOME, &mut t).score,
            0.70
        );
        assert!(t.exts.contains("EXT-002"));
        let mut t = Tags::default();
        assert_eq!(
            validate(
                0,
                "cp evil.plist ~/Library/LaunchAgents/x.plist",
                HOME,
                &mut t
            )
            .score,
            0.70
        );
        assert!(t.exts.contains("EXT-003"));
        let mut t = Tags::default();
        assert_eq!(validate(0, "rm -rf /Applications", HOME, &mut t).score, 1.0);
        assert!(t.exts.contains("EXT-004"));
        let mut t = Tags::default();
        // `of=/dev/disk2` is not extracted as a path (reference behaviour).
        assert_eq!(
            validate(0, "dd if=x of=/dev/disk2", HOME, &mut t).score,
            0.0
        );
        let r = validate(0, "diskutil eraseDisk JHFS+ X /dev/disk2", HOME, &mut t);
        assert_eq!(r.score, 1.0);
        assert!(t.exts.contains("EXT-005"));
    }

    #[test]
    fn hits_record_tier_and_access() {
        let r = validate(0, "cat /etc/hosts", HOME, &mut Tags::default());
        assert_eq!(r.hits.len(), 1);
        assert_eq!(r.hits[0].tier, PathTier::SensitiveSystem);
        assert_eq!(r.hits[0].access, Access::Read);
    }
}
