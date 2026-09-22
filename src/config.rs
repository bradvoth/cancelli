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

use crate::jev::client::{self, KeySource, PINNED_MODEL, Secret};
use crate::policy::Mode;

/// A snapshot of environment variables whose `Debug` never shows values
/// (it may hold the API key).
#[derive(Clone, Default)]
pub struct EnvVars(pub BTreeMap<String, String>);

impl std::fmt::Debug for EnvVars {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.keys()).finish()
    }
}

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
    /// `$TYPESAFE_BASE_URL`.
    pub base_url: Option<String>,
    /// Every variable (the key env var is named by `judge.api_key_env`).
    pub vars: EnvVars,
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
            base_url: get("TYPESAFE_BASE_URL"),
            // `vars_os`: `std::env::vars()` panics on a non-UTF-8 variable,
            // and this runs before the hook's panic guard.
            vars: EnvVars(
                std::env::vars_os()
                    .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
                    .collect(),
            ),
        }
    }

    /// A variable by name (empty counts as unset).
    pub fn var(&self, name: &str) -> Option<&str> {
        self.vars
            .0
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
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
    /// D13: a Jev `allow` emits `permissionDecision: "allow"`.
    pub decide_all: bool,
    /// Judge backend: `jev` | `stub`.
    pub judge_backend: String,
    /// Jev base URL.
    pub judge_base_url: String,
    /// Requested model (responses must report [`PINNED_MODEL`]).
    pub judge_model: String,
    /// Name of the env var holding the API key.
    pub judge_api_key_env: String,
    /// Key file (0600), used when the env var is unset.
    pub judge_api_key_file: Option<PathBuf>,
    /// Per-request timeout in ms.
    pub judge_timeout_ms: u64,
    /// Total budget in ms (including one retry).
    pub judge_budget_ms: u64,
}

impl Config {
    /// Resolve the API key (env var first, then the file). Never logged.
    pub fn api_key(&self, env: &Env) -> Result<(Secret, KeySource), String> {
        client::resolve_key(
            env.var(&self.judge_api_key_env),
            &self.judge_api_key_env,
            self.judge_api_key_file.as_deref(),
        )
    }
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
    /// `--decide-all` (forces true).
    pub decide_all: bool,
}

/// Default log directory (before `~` expansion).
pub const DEFAULT_LOG_DIR: &str = "~/.local/share/cancelli";

/// Commented default file written by `cancelli config --init`.
pub const DEFAULT_FILE: &str = r#"# cancelli configuration
# Precedence: CLI flag > environment variable > this file > built-in default.

mode = "balanced"          # strict | balanced | auto   (env CANCELLI_MODE)
dry_run = true             # the --dry-run flag forces true
decide_all = false         # D13: a Jev "allow" emits allow (skips the prompt); --decide-all forces true

[log]
dir = "~/.local/share/cancelli"   # env CANCELLI_LOG_DIR overrides
max_field_bytes = 4096            # non-Bash string truncation threshold

[judge]
backend = "jev"            # "jev" | "stub"
base_url = "https://api.typesafe.ai"   # env TYPESAFE_BASE_URL overrides
model = "jev-1.13.0"       # pinned; response.model must match
api_key_env = "TYPESAFE_API_KEY"
# api_key_file = "~/.config/cancelli/jev_api_key"   # 0600; used if the env var is unset (this path is the default when the file exists)
timeout_ms = 3000          # per request
budget_ms = 5000           # total incl. one retry on 408/429/5xx/timeout; keep well under the hook timeout
"#;

/// Default Jev base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.typesafe.ai";

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

/// `jev_api_key` next to config.toml, used when `api_key_file` is unset and
/// the file exists.
fn default_key_file(env: &Env) -> Option<PathBuf> {
    let p = config_path(env)?.with_file_name("jev_api_key");
    p.exists().then_some(p)
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
    ("", &["mode", "dry_run", "decide_all", "log", "judge"]),
    ("log", &["dir", "max_field_bytes"]),
    (
        "judge",
        &[
            "backend",
            "base_url",
            "model",
            "api_key_env",
            "api_key_file",
            "timeout_ms",
            "budget_ms",
        ],
    ),
];

/// Load the effective configuration.
pub fn load(env: &Env, cli: &CliOverrides) -> Loaded {
    let mut diags = Vec::new();
    let mut sources: BTreeMap<&'static str, Source> = BTreeMap::new();
    let mut mode = Mode::Balanced;
    let mut dry_run = true;
    let mut log_dir = DEFAULT_LOG_DIR.to_string();
    let mut max_field_bytes: usize = 4096;
    let mut decide_all = false;
    let mut backend = "jev".to_string();
    let mut base_url = DEFAULT_BASE_URL.to_string();
    let mut model = PINNED_MODEL.to_string();
    let mut api_key_env = "TYPESAFE_API_KEY".to_string();
    let mut api_key_file: Option<String> = None;
    let mut timeout_ms: u64 = 3000;
    let mut budget_ms: u64 = 5000;
    for k in [
        "mode",
        "dry_run",
        "decide_all",
        "log.dir",
        "log.max_field_bytes",
        "judge.backend",
        "judge.base_url",
        "judge.model",
        "judge.api_key_env",
        "judge.api_key_file",
        "judge.timeout_ms",
        "judge.budget_ms",
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
                                if let Some(v) = f.decide_all {
                                    decide_all = v;
                                    sources.insert("decide_all", Source::File);
                                }
                                if let Some(v) = f.backend {
                                    backend = v;
                                    sources.insert("judge.backend", Source::File);
                                }
                                if let Some(v) = f.base_url {
                                    base_url = v;
                                    sources.insert("judge.base_url", Source::File);
                                }
                                if let Some(v) = f.model {
                                    model = v;
                                    sources.insert("judge.model", Source::File);
                                }
                                if let Some(v) = f.api_key_env {
                                    api_key_env = v;
                                    sources.insert("judge.api_key_env", Source::File);
                                }
                                if let Some(v) = f.api_key_file {
                                    api_key_file = Some(v);
                                    sources.insert("judge.api_key_file", Source::File);
                                }
                                if let Some(v) = f.timeout_ms {
                                    timeout_ms = v;
                                    sources.insert("judge.timeout_ms", Source::File);
                                }
                                if let Some(v) = f.budget_ms {
                                    budget_ms = v;
                                    sources.insert("judge.budget_ms", Source::File);
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
    if let Some(u) = &env.base_url {
        base_url = u.clone();
        sources.insert("judge.base_url", Source::Env);
    }
    if let Some(m) = cli.mode {
        mode = m;
        sources.insert("mode", Source::Cli);
    }
    if cli.dry_run {
        dry_run = true;
        sources.insert("dry_run", Source::Cli);
    }
    if cli.decide_all {
        decide_all = true;
        sources.insert("decide_all", Source::Cli);
    }
    if model != PINNED_MODEL {
        diags.push(Diagnostic {
            level: "warning",
            message: format!(
                "judge.model {model:?}: the rubric is calibrated for {PINNED_MODEL:?} and any \
                 other response.model is treated as a failure (ask)"
            ),
        });
    }
    if budget_ms < timeout_ms {
        diags.push(Diagnostic {
            level: "warning",
            message: format!(
                "judge.budget_ms {budget_ms} < judge.timeout_ms {timeout_ms}; requests are capped by the budget"
            ),
        });
    }

    Loaded {
        config: Config {
            mode,
            dry_run,
            log_dir: expand_tilde(&log_dir, env),
            max_field_bytes,
            decide_all,
            judge_backend: backend,
            judge_base_url: base_url,
            judge_model: model,
            judge_api_key_env: api_key_env,
            judge_api_key_file: api_key_file
                .map(|p| expand_tilde(&p, env))
                .or_else(|| default_key_file(env)),
            judge_timeout_ms: timeout_ms,
            judge_budget_ms: budget_ms,
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
    decide_all: Option<bool>,
    backend: Option<String>,
    base_url: Option<String>,
    model: Option<String>,
    api_key_env: Option<String>,
    api_key_file: Option<String>,
    timeout_ms: Option<u64>,
    budget_ms: Option<u64>,
}

fn table_str(t: &toml::Table, section: &str, key: &str) -> Result<Option<String>, String> {
    match t.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| format!("{section}.{key} must be a string")),
    }
}

fn table_ms(t: &toml::Table, section: &str, key: &str) -> Result<Option<u64>, String> {
    match t.get(key) {
        None => Ok(None),
        Some(v) => {
            let n = v
                .as_integer()
                .ok_or_else(|| format!("{section}.{key} must be an integer"))?;
            match u64::try_from(n) {
                Ok(n) if n > 0 => Ok(Some(n)),
                _ => Err(format!("{section}.{key} must be > 0")),
            }
        }
    }
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
        if let Some(v) = t.get("decide_all") {
            self.decide_all = Some(v.as_bool().ok_or("decide_all must be a boolean")?);
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
            self.backend = table_str(j, "judge", "backend")?;
            if let Some(b) = &self.backend
                && b != "jev"
                && b != "stub"
            {
                return Err(format!("judge.backend {b:?} is not jev|stub"));
            }
            self.base_url = table_str(j, "judge", "base_url")?;
            self.model = table_str(j, "judge", "model")?;
            self.api_key_env = table_str(j, "judge", "api_key_env")?;
            self.api_key_file = table_str(j, "judge", "api_key_file")?;
            self.timeout_ms = table_ms(j, "judge", "timeout_ms")?;
            self.budget_ms = table_ms(j, "judge", "budget_ms")?;
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
        if section == "log" && k == "decide_all" {
            diags.push(Diagnostic {
                level: "warning",
                message: "`log.decide_all` ignored: decide_all is a top-level key \
                          (put it above the [log] table)"
                    .into(),
            });
            continue;
        }
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

/// Human-readable `cancelli config` output. The key itself is never shown,
/// only whether and where it was found.
pub fn render(l: &Loaded, env: &Env) -> String {
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
        "decide_all = {}  # {}\n",
        c.decide_all,
        src("decide_all")
    ));
    out.push_str(&format!(
        "judge.backend = {:?}  # {}\n",
        c.judge_backend,
        src("judge.backend")
    ));
    out.push_str(&format!(
        "judge.base_url = {:?}  # {}\n",
        c.judge_base_url,
        src("judge.base_url")
    ));
    out.push_str(&format!(
        "judge.model = {:?}  # {}\n",
        c.judge_model,
        src("judge.model")
    ));
    out.push_str(&format!(
        "judge.api_key_env = {:?}  # {}\n",
        c.judge_api_key_env,
        src("judge.api_key_env")
    ));
    out.push_str(&format!(
        "judge.api_key_file = {}  # {}\n",
        opt(&c
            .judge_api_key_file
            .as_ref()
            .map(|p| p.display().to_string())),
        src("judge.api_key_file")
    ));
    out.push_str(&format!(
        "judge.timeout_ms = {}  # {}\n",
        c.judge_timeout_ms,
        src("judge.timeout_ms")
    ));
    out.push_str(&format!(
        "judge.budget_ms = {}  # {}\n",
        c.judge_budget_ms,
        src("judge.budget_ms")
    ));
    out.push_str(&match c.api_key(env) {
        Ok((_, from)) => format!("# judge api key: found ({from})\n"),
        Err(e) => format!("# judge api key: {e}\n"),
    });
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
            ..Env::default()
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
    fn key_file_defaults_next_to_config_only_if_present() {
        let d = tempfile::tempdir().unwrap();
        let e = env_in(d.path());
        let l = load(&e, &CliOverrides::default());
        assert_eq!(l.config.judge_api_key_file, None);
        let key = d.path().join("home/.config/cancelli/jev_api_key");
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        std::fs::write(&key, "k").unwrap();
        let l = load(&e, &CliOverrides::default());
        assert_eq!(l.config.judge_api_key_file, Some(key));
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
                decide_all: false,
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

    #[test]
    fn jev_keys_defaults_file_env_cli() {
        let d = tempfile::tempdir().unwrap();
        let mut env = env_in(d.path());
        let l = load(&env, &CliOverrides::default());
        let c = &l.config;
        assert!(!c.decide_all);
        assert_eq!(c.judge_backend, "jev");
        assert_eq!(c.judge_base_url, "https://api.typesafe.ai");
        assert_eq!(c.judge_model, "jev-1.13.0");
        assert_eq!(c.judge_api_key_env, "TYPESAFE_API_KEY");
        assert_eq!(c.judge_api_key_file, None);
        assert_eq!((c.judge_timeout_ms, c.judge_budget_ms), (3000, 5000));
        let p = config_path(&env).unwrap();
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            "decide_all = true\n[judge]\nbase_url = \"http://127.0.0.1:9\"\n\
             api_key_env = \"MY_KEY\"\napi_key_file = \"~/k\"\ntimeout_ms = 100\nbudget_ms = 250\n",
        )
        .unwrap();
        let l = load(&env, &CliOverrides::default());
        assert!(l.diagnostics.is_empty(), "{:?}", l.diagnostics);
        assert!(l.config.decide_all);
        assert_eq!(l.sources["decide_all"], Source::File);
        assert_eq!(l.config.judge_base_url, "http://127.0.0.1:9");
        assert_eq!(l.config.judge_api_key_file, Some(d.path().join("home/k")));
        assert_eq!(l.config.judge_budget_ms, 250);
        env.base_url = Some("http://env.example".into());
        let l = load(&env, &CliOverrides::default());
        assert_eq!(
            (
                l.config.judge_base_url.as_str(),
                l.sources["judge.base_url"]
            ),
            ("http://env.example", Source::Env)
        );
        std::fs::write(&p, "[judge]\nbackend = \"gpt\"\n").unwrap();
        let l = load(&env, &CliOverrides::default());
        assert_eq!(l.diagnostics[0].level, "error");
        assert_eq!(l.config.judge_backend, "jev");
        std::fs::write(&p, "[log]\ndecide_all = true\n").unwrap();
        let l = load(
            &env,
            &CliOverrides {
                decide_all: true,
                ..CliOverrides::default()
            },
        );
        assert!(l.diagnostics[0].message.contains("top-level"));
        assert_eq!(
            (l.config.decide_all, l.sources["decide_all"]),
            (true, Source::Cli)
        );
    }

    #[test]
    fn render_shows_key_source_never_key() {
        let d = tempfile::tempdir().unwrap();
        let mut env = env_in(d.path());
        env.vars
            .0
            .insert("TYPESAFE_API_KEY".into(), "tsk_supersecret_123".into());
        let l = load(&env, &CliOverrides::default());
        let out = render(&l, &env);
        assert!(out.contains("# judge api key: found (env $TYPESAFE_API_KEY)"));
        assert!(out.contains("judge.budget_ms = 5000  # default"));
        assert!(!out.contains("tsk_supersecret_123"));
        assert!(!format!("{env:?}").contains("tsk_supersecret_123"));
    }
}
