//! Configuration (D10): `$XDG_CONFIG_HOME/cancelli/config.toml` when
//! `XDG_CONFIG_HOME` is set, else `~/.config/cancelli/config.toml`
//! (deliberately not macOS `~/Library/Application Support`).
//!
//! Precedence: CLI flag > env var > config file > built-in default. A missing
//! file means defaults; an unreadable/invalid file means defaults plus an
//! error diagnostic; unknown keys produce warning diagnostics.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::policy::Mode;

/// Process environment inputs (captured once so tests can inject them).
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// `$HOME`.
    pub home: Option<String>,
    /// `$XDG_CONFIG_HOME`.
    pub xdg_config_home: Option<String>,
    /// `$CANCELLI_LOG_DIR`.
    pub log_dir: Option<String>,
    /// `$CANCELLI_MODE`.
    pub mode: Option<String>,
}

impl Env {
    /// Read from the process environment (empty values count as unset).
    pub fn from_process() -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Env {
            home: get("HOME"),
            xdg_config_home: get("XDG_CONFIG_HOME"),
            log_dir: get("CANCELLI_LOG_DIR"),
            mode: get("CANCELLI_MODE"),
        }
    }
}

/// Where a value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Built-in default.
    Default,
    /// Config file.
    File,
    /// Environment variable.
    Env,
    /// CLI flag.
    Cli,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Default => "default",
            Source::File => "file",
            Source::Env => "env",
            Source::Cli => "cli",
        }
    }
}

/// Effective configuration.
#[derive(Debug, Clone, Serialize)]
pub struct Config {
    /// Operating mode.
    pub mode: Mode,
    /// Never emit a decision.
    pub dry_run: bool,
    /// Log directory (already `~`-expanded).
    pub log_dir: PathBuf,
    /// Non-Bash string truncation threshold (bytes).
    pub max_field_bytes: usize,
    /// Judge backend (`stub` only for now).
    pub judge_backend: String,
    /// Judge base URL (step 2).
    pub judge_base_url: Option<String>,
    /// Judge model (step 2).
    pub judge_model: Option<String>,
    /// Judge timeout in ms (FIX-008).
    pub judge_timeout_ms: u64,
}

/// A diagnostic produced while loading.
#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    /// `error` or `warning`.
    pub level: &'static str,
    /// Message.
    pub message: String,
}

/// Loaded configuration plus provenance.
#[derive(Debug, Clone, Serialize)]
pub struct Loaded {
    /// Effective values.
    pub config: Config,
    /// Source of each key.
    pub sources: BTreeMap<&'static str, Source>,
    /// Config file path consulted.
    pub path: Option<PathBuf>,
    /// Whether the file existed.
    pub file_found: bool,
    /// Load diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// CLI overrides.
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    /// `--mode`.
    pub mode: Option<Mode>,
    /// `--dry-run` (forces true).
    pub dry_run: bool,
}

/// Default log directory (before `~` expansion).
pub const DEFAULT_LOG_DIR: &str = "~/.local/share/cancelli";

/// Commented default file written by `cancelli config --init`.
pub const DEFAULT_FILE: &str = r#"# cancelli configuration
# Precedence: CLI flag > environment variable > this file > built-in default.

mode = "balanced"          # strict | balanced | auto   (env CANCELLI_MODE)
dry_run = true             # the --dry-run flag forces true

[log]
dir = "~/.local/share/cancelli"   # env CANCELLI_LOG_DIR overrides
max_field_bytes = 4096            # non-Bash string truncation threshold

[judge]                    # step 2; ignored while the stub is active
backend = "stub"
# base_url = "http://127.0.0.1:8006/v1"
# model = ""
# timeout_ms = 2000
"#;

/// Config file location per D10.
pub fn config_path(env: &Env) -> Option<PathBuf> {
    if let Some(x) = &env.xdg_config_home {
        return Some(Path::new(x).join("cancelli").join("config.toml"));
    }
    env.home.as_ref().map(|h| {
        Path::new(h)
            .join(".config")
            .join("cancelli")
            .join("config.toml")
    })
}

/// Expand a leading `~`.
pub fn expand_tilde(p: &str, env: &Env) -> PathBuf {
    match (p.strip_prefix('~'), &env.home) {
        (Some(rest), Some(h)) if rest.is_empty() || rest.starts_with('/') => {
            PathBuf::from(format!("{}{}", h.trim_end_matches('/'), rest))
        }
        _ => PathBuf::from(p),
    }
}

const KNOWN: &[(&str, &[&str])] = &[
    ("", &["mode", "dry_run", "log", "judge"]),
    ("log", &["dir", "max_field_bytes"]),
    ("judge", &["backend", "base_url", "model", "timeout_ms"]),
];

/// Load the effective configuration.
pub fn load(env: &Env, cli: &CliOverrides) -> Loaded {
    let mut diags = Vec::new();
    let mut sources: BTreeMap<&'static str, Source> = BTreeMap::new();
    let mut mode = Mode::Balanced;
    let mut dry_run = true;
    let mut log_dir = DEFAULT_LOG_DIR.to_string();
    let mut max_field_bytes: usize = 4096;
    let mut backend = "stub".to_string();
    let mut base_url = None;
    let mut model = None;
    let mut timeout_ms: u64 = 2000;
    for k in [
        "mode",
        "dry_run",
        "log.dir",
        "log.max_field_bytes",
        "judge.backend",
        "judge.base_url",
        "judge.model",
        "judge.timeout_ms",
    ] {
        sources.insert(k, Source::Default);
    }

    let path = config_path(env);
    let mut file_found = false;
    if let Some(p) = &path {
        match std::fs::read_to_string(p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => diags.push(Diagnostic {
                level: "error",
                message: format!("cannot read {}: {e}; using defaults", p.display()),
            }),
            Ok(text) => {
                file_found = true;
                match text.parse::<toml::Table>() {
                    Err(e) => diags.push(Diagnostic {
                        level: "error",
                        message: format!("invalid TOML in {}: {e}; using defaults", p.display()),
                    }),
                    Ok(table) => {
                        let mut f = FileValues::default();
                        match f.read(&table, &mut diags) {
                            Ok(()) => {
                                if let Some(v) = f.mode {
                                    mode = v;
                                    sources.insert("mode", Source::File);
                                }
                                if let Some(v) = f.dry_run {
                                    dry_run = v;
                                    sources.insert("dry_run", Source::File);
                                }
                                if let Some(v) = f.log_dir {
                                    log_dir = v;
                                    sources.insert("log.dir", Source::File);
                                }
                                if let Some(v) = f.max_field_bytes {
                                    max_field_bytes = v;
                                    sources.insert("log.max_field_bytes", Source::File);
                                }
                                if let Some(v) = f.backend {
                                    backend = v;
                                    sources.insert("judge.backend", Source::File);
                                }
                                if let Some(v) = f.base_url {
                                    base_url = Some(v);
                                    sources.insert("judge.base_url", Source::File);
                                }
                                if let Some(v) = f.model {
                                    model = Some(v);
                                    sources.insert("judge.model", Source::File);
                                }
                                if let Some(v) = f.timeout_ms {
                                    timeout_ms = v;
                                    sources.insert("judge.timeout_ms", Source::File);
                                }
                            }
                            Err(msg) => diags.push(Diagnostic {
                                level: "error",
                                message: format!(
                                    "invalid config {}: {msg}; using defaults",
                                    p.display()
                                ),
                            }),
                        }
                    }
                }
            }
        }
    }

    if let Some(m) = &env.mode {
        match Mode::parse(m) {
            Some(v) => {
                mode = v;
                sources.insert("mode", Source::Env);
            }
            None => diags.push(Diagnostic {
                level: "warning",
                message: format!("CANCELLI_MODE={m:?} is not strict|balanced|auto; ignored"),
            }),
        }
    }
    if let Some(d) = &env.log_dir {
        log_dir = d.clone();
        sources.insert("log.dir", Source::Env);
    }
    if let Some(m) = cli.mode {
        mode = m;
        sources.insert("mode", Source::Cli);
    }
    if cli.dry_run {
        dry_run = true;
        sources.insert("dry_run", Source::Cli);
    }
    if backend != "stub" {
        diags.push(Diagnostic {
            level: "warning",
            message: format!("judge.backend {backend:?} is not implemented yet; using the stub"),
        });
    }

    Loaded {
        config: Config {
            mode,
            dry_run,
            log_dir: expand_tilde(&log_dir, env),
            max_field_bytes,
            judge_backend: backend,
            judge_base_url: base_url,
            judge_model: model,
            judge_timeout_ms: timeout_ms,
        },
        sources,
        path,
        file_found,
        diagnostics: diags,
    }
}

#[derive(Default)]
struct FileValues {
    mode: Option<Mode>,
    dry_run: Option<bool>,
    log_dir: Option<String>,
    max_field_bytes: Option<usize>,
    backend: Option<String>,
    base_url: Option<String>,
    model: Option<String>,
    timeout_ms: Option<u64>,
}

impl FileValues {
    /// Type errors make the whole file invalid (defaults are used); unknown
    /// keys are warnings.
    fn read(&mut self, t: &toml::Table, diags: &mut Vec<Diagnostic>) -> Result<(), String> {
        unknown_keys("", t, diags);
        if let Some(v) = t.get("mode") {
            let s = v.as_str().ok_or("mode must be a string")?;
            self.mode = Some(
                Mode::parse(s).ok_or_else(|| format!("mode {s:?} is not strict|balanced|auto"))?,
            );
        }
        if let Some(v) = t.get("dry_run") {
            self.dry_run = Some(v.as_bool().ok_or("dry_run must be a boolean")?);
        }
        if let Some(v) = t.get("log") {
            let log = v.as_table().ok_or("[log] must be a table")?;
            unknown_keys("log", log, diags);
            if let Some(v) = log.get("dir") {
                self.log_dir = Some(v.as_str().ok_or("log.dir must be a string")?.to_string());
            }
            if let Some(v) = log.get("max_field_bytes") {
                let n = v
                    .as_integer()
                    .ok_or("log.max_field_bytes must be an integer")?;
                self.max_field_bytes =
                    Some(usize::try_from(n).map_err(|_| "log.max_field_bytes must be >= 0")?);
            }
        }
        if let Some(v) = t.get("judge") {
            let j = v.as_table().ok_or("[judge] must be a table")?;
            unknown_keys("judge", j, diags);
            if let Some(v) = j.get("backend") {
                self.backend = Some(
                    v.as_str()
                        .ok_or("judge.backend must be a string")?
                        .to_string(),
                );
            }
            if let Some(v) = j.get("base_url") {
                self.base_url = Some(
                    v.as_str()
                        .ok_or("judge.base_url must be a string")?
                        .to_string(),
                );
            }
            if let Some(v) = j.get("model") {
                self.model = Some(
                    v.as_str()
                        .ok_or("judge.model must be a string")?
                        .to_string(),
                );
            }
            if let Some(v) = j.get("timeout_ms") {
                let n = v
                    .as_integer()
                    .ok_or("judge.timeout_ms must be an integer")?;
                self.timeout_ms =
                    Some(u64::try_from(n).map_err(|_| "judge.timeout_ms must be >= 0")?);
            }
        }
        Ok(())
    }
}

fn unknown_keys(section: &str, t: &toml::Table, diags: &mut Vec<Diagnostic>) {
    let known = KNOWN
        .iter()
        .find(|(s, _)| *s == section)
        .map(|(_, k)| *k)
        .unwrap_or(&[]);
    for k in t.keys() {
        if !known.contains(&k.as_str()) {
            let full = if section.is_empty() {
                k.clone()
            } else {
                format!("{section}.{k}")
            };
            diags.push(Diagnostic {
                level: "warning",
                message: format!("unknown config key `{full}` ignored"),
            });
        }
    }
}

/// Human-readable `cancelli config` output.
pub fn render(l: &Loaded) -> String {
    let c = &l.config;
    let src = |k: &str| {
        l.sources
            .get(k)
            .copied()
            .unwrap_or(Source::Default)
            .as_str()
    };
    let opt = |o: &Option<String>| {
        o.as_deref()
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|| "(unset)".into())
    };
    let mut out = String::new();
    let file = match &l.path {
        Some(p) if l.file_found => format!("{} (found)", p.display()),
        Some(p) => format!("{} (not found; defaults)", p.display()),
        None => "(no HOME or XDG_CONFIG_HOME)".into(),
    };
    out.push_str(&format!("# config file: {file}\n"));
    out.push_str(&format!(
        "mode = {:?}  # {}\n",
        c.mode.as_str(),
        src("mode")
    ));
    out.push_str(&format!("dry_run = {}  # {}\n", c.dry_run, src("dry_run")));
    out.push_str(&format!(
        "log.dir = {:?}  # {}\n",
        c.log_dir.display().to_string(),
        src("log.dir")
    ));
    out.push_str(&format!(
        "log.max_field_bytes = {}  # {}\n",
        c.max_field_bytes,
        src("log.max_field_bytes")
    ));
    out.push_str(&format!(
        "judge.backend = {:?}  # {}\n",
        c.judge_backend,
        src("judge.backend")
    ));
    out.push_str(&format!(
        "judge.base_url = {}  # {}\n",
        opt(&c.judge_base_url),
        src("judge.base_url")
    ));
    out.push_str(&format!(
        "judge.model = {}  # {}\n",
        opt(&c.judge_model),
        src("judge.model")
    ));
    out.push_str(&format!(
        "judge.timeout_ms = {}  # {}\n",
        c.judge_timeout_ms,
        src("judge.timeout_ms")
    ));
    for d in &l.diagnostics {
        out.push_str(&format!("# {}: {}\n", d.level, d.message));
    }
    out
}

/// `cancelli config --init`: write the default file; refuse to overwrite.
pub fn init(env: &Env) -> Result<PathBuf, String> {
    let p = config_path(env).ok_or("neither XDG_CONFIG_HOME nor HOME is set")?;
    if p.exists() {
        return Err(format!("{} already exists; not overwriting", p.display()));
    }
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&p)
        .map_err(|e| format!("create {}: {e}", p.display()))?;
    std::io::Write::write_all(&mut f, DEFAULT_FILE.as_bytes())
        .map_err(|e| format!("write {}: {e}", p.display()))?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_in(dir: &Path) -> Env {
        Env {
            home: Some(dir.join("home").display().to_string()),
            xdg_config_home: None,
            log_dir: None,
            mode: None,
        }
    }

    #[test]
    fn path_prefers_xdg() {
        let mut e = Env {
            home: Some("/h".into()),
            ..Env::default()
        };
        assert_eq!(
            config_path(&e).unwrap(),
            PathBuf::from("/h/.config/cancelli/config.toml")
        );
        e.xdg_config_home = Some("/x".into());
        assert_eq!(
            config_path(&e).unwrap(),
            PathBuf::from("/x/cancelli/config.toml")
        );
    }

    #[test]
    fn missing_file_is_defaults() {
        let d = tempfile::tempdir().unwrap();
        let l = load(&env_in(d.path()), &CliOverrides::default());
        assert!(!l.file_found);
        assert!(l.diagnostics.is_empty());
        assert_eq!(l.config.mode, Mode::Balanced);
        assert_eq!(
            l.config.log_dir,
            d.path().join("home/.local/share/cancelli")
        );
    }

    #[test]
    fn precedence_cli_env_file_default() {
        let d = tempfile::tempdir().unwrap();
        let mut env = env_in(d.path());
        let p = config_path(&env).unwrap();
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            "mode = \"strict\"\n[log]\ndir = \"/from/file\"\nbogus = 1\n",
        )
        .unwrap();
        let l = load(&env, &CliOverrides::default());
        assert_eq!(l.config.mode, Mode::Strict);
        assert_eq!(l.sources["mode"], Source::File);
        assert_eq!(l.config.log_dir, PathBuf::from("/from/file"));
        assert_eq!(l.diagnostics.len(), 1);
        assert_eq!(l.diagnostics[0].level, "warning");
        env.mode = Some("auto".into());
        env.log_dir = Some("/from/env".into());
        let l = load(&env, &CliOverrides::default());
        assert_eq!(
            (l.config.mode, l.sources["mode"]),
            (Mode::Auto, Source::Env)
        );
        assert_eq!(l.config.log_dir, PathBuf::from("/from/env"));
        let l = load(
            &env,
            &CliOverrides {
                mode: Some(Mode::Balanced),
                dry_run: true,
            },
        );
        assert_eq!(
            (l.config.mode, l.sources["mode"]),
            (Mode::Balanced, Source::Cli)
        );
    }

    #[test]
    fn invalid_file_is_defaults_plus_error() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let p = config_path(&env).unwrap();
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "mode = [").unwrap();
        let l = load(&env, &CliOverrides::default());
        assert_eq!(l.config.mode, Mode::Balanced);
        assert_eq!(l.diagnostics[0].level, "error");
        std::fs::write(&p, "mode = \"nope\"\n").unwrap();
        let l = load(&env, &CliOverrides::default());
        assert_eq!(l.config.mode, Mode::Balanced);
        assert_eq!(l.diagnostics[0].level, "error");
    }

    #[test]
    fn init_refuses_overwrite_and_default_file_parses() {
        let d = tempfile::tempdir().unwrap();
        let env = env_in(d.path());
        let p = init(&env).unwrap();
        assert!(init(&env).is_err());
        let l = load(&env, &CliOverrides::default());
        assert!(l.file_found);
        assert!(l.diagnostics.is_empty(), "{:?}", l.diagnostics);
        assert_eq!(std::fs::read_to_string(p).unwrap(), DEFAULT_FILE);
    }
}
