//! Claude Code `PreToolUse` hook handling: stdin JSON → analysis → one log
//! record → (enforce mode only) a decision on stdout. Fails open: every
//! internal error becomes an `error` record and empty stdout.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::config::{self, CliOverrides, Config, Env, Loaded};
use crate::engine::{self, Analysis, Options};
use crate::jev::client::Transport;
use crate::jev::decide::Verdict as JevVerdict;
use crate::jev::transcript::ContextSource;
use crate::jev::{self, JevAdjudicator};
use crate::logging;
use crate::policy::Mode;
use crate::resolution::{Adjudicator, Final, StubAdjudicator};
use crate::rules;

/// Hook invocation arguments (from the CLI).
#[derive(Debug, Clone, Default)]
pub struct HookArgs {
    /// `--dry-run`.
    pub dry_run: bool,
    /// `--mode`.
    pub mode: Option<Mode>,
    /// `--decide-all`.
    pub decide_all: bool,
}

/// What the hook prints and how it exits (always 0: fail open).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookOutput {
    /// Stdout (empty in dry-run and for ALLOW).
    pub stdout: String,
}

fn base_record(kind: &str, loaded: &Loaded) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("kind".into(), json!(kind));
    m.insert("ts".into(), json!(logging::ts(logging::now())));
    m.insert("version".into(), json!(crate::VERSION));
    m.insert(
        "rules_version".into(),
        json!(rules::bank().map(|b| b.version.clone()).unwrap_or_default()),
    );
    m.insert("mode".into(), json!(loaded.config.mode.as_str()));
    m.insert("dry_run".into(), json!(loaded.config.dry_run));
    m
}

fn write(loaded: &Loaded, rec: Map<String, Value>) {
    // Nowhere to report a logging failure without breaking the hook
    // contract (stdout must stay empty); the record is dropped.
    let _ = logging::append(&loaded.config.log_dir, logging::now(), &Value::Object(rec));
}

/// Log an error record (used for every fail-open path).
pub fn log_error(loaded: &Loaded, stage: &str, error: &str, extra: Map<String, Value>) {
    let mut r = base_record("error", loaded);
    r.insert("stage".into(), json!(stage));
    r.insert("error".into(), json!(error));
    r.extend(extra);
    write(loaded, r);
}

/// Load config for the hook, logging its diagnostics.
pub fn load_config(env: &Env, args: &HookArgs) -> Loaded {
    let loaded = config::load(
        env,
        &CliOverrides {
            mode: args.mode,
            dry_run: args.dry_run,
            decide_all: args.decide_all,
        },
    );
    for d in &loaded.diagnostics {
        let mut r = base_record(d.level, &loaded);
        r.insert("stage".into(), json!("config"));
        r.insert(
            "config_path".into(),
            json!(loaded.path.as_ref().map(|p| p.display().to_string())),
        );
        r.insert(
            if d.level == "error" {
                "error"
            } else {
                "message"
            }
            .into(),
            json!(d.message),
        );
        write(&loaded, r);
    }
    loaded
}

fn str_field(v: &Value, k: &str) -> Value {
    v.get(k).cloned().unwrap_or(Value::Null)
}

/// Jev settings from the config.
pub fn jev_settings(c: &Config) -> jev::Settings {
    jev::Settings {
        transport: Transport {
            base_url: c.judge_base_url.clone(),
            timeout: Duration::from_millis(c.judge_timeout_ms),
            budget: Duration::from_millis(c.judge_budget_ms),
        },
        model: c.judge_model.clone(),
        decide_all: c.decide_all,
    }
}

/// The configured adjudicator and its backstop timeout (FIX-008) for one
/// hook call.
pub fn adjudicator(
    c: &Config,
    env: &Env,
    source: ContextSource,
) -> (Arc<dyn Adjudicator>, Duration) {
    if c.judge_backend == "stub" {
        return (
            Arc::new(StubAdjudicator),
            Duration::from_millis(c.judge_timeout_ms),
        );
    }
    let adj = JevAdjudicator {
        settings: jev_settings(c),
        key: c.api_key(env),
        source,
    };
    (
        Arc::new(adj),
        jev::backstop(Duration::from_millis(c.judge_budget_ms)),
    )
}

fn emit(decision: &str, reason: String) -> Option<Value> {
    Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
}

/// Decision JSON for enforce mode. CARE's static verdicts are unchanged
/// (D12); a Jev verdict names its tier; a Jev `allow` emits only with
/// `decide_all` (D13); Jev failures ask (D15).
pub fn decision_output(a: &Analysis, decide_all: bool) -> Option<Value> {
    let rules: Vec<&str> = a.fired_rules.iter().map(|r| r.id.as_str()).collect();
    let rules = if rules.is_empty() {
        "none".to_string()
    } else {
        rules.join(",")
    };
    if let Some(j) = a.judge.as_ref().and_then(|o| o.jev.as_ref()) {
        let care = format!("CARE WARN score {}, rules {}", a.aggregate, rules);
        let why = match (&j.error, j.tier, j.tier_rule) {
            (Some(e), _, _) => format!("Jev unavailable ({e})"),
            (None, Some(t), Some(rule)) => format!("Jev {t}: {rule}"),
            _ => "Jev".to_string(),
        };
        return match j.verdict {
            JevVerdict::Allow if !decide_all => None,
            v => emit(
                v.as_str(),
                format!("cancelli: {} -> {}; {care}", why, v.as_str()),
            ),
        };
    }
    let (decision, reason) = match a.r#final {
        Final::Allow => return None,
        Final::Ask => (
            "ask",
            format!(
                "cancelli (CARE): WARN, score {}, judge failed; rules {}",
                a.aggregate, rules
            ),
        ),
        Final::Deny => (
            "deny",
            format!(
                "cancelli (CARE): DENY, score {} [{}], skip {}, rules {}",
                a.aggregate,
                a.provisional.get(a.mode).as_str(),
                a.skip_predicate.as_deref().unwrap_or("none"),
                rules
            ),
        ),
        Final::Unadjudicated => (
            "ask",
            format!(
                "cancelli (CARE): WARN, score {}, no judge configured; rules {}",
                a.aggregate, rules
            ),
        ),
    };
    emit(decision, reason)
}

/// Handle one hook invocation.
pub fn run(stdin: &[u8], args: &HookArgs, env: &Env) -> HookOutput {
    let start = Instant::now();
    let loaded = load_config(env, args);
    let empty = HookOutput {
        stdout: String::new(),
    };

    let payload: Value = match serde_json::from_slice(stdin) {
        Ok(v @ Value::Object(_)) => v,
        Ok(_) | Err(_) => {
            let msg = match serde_json::from_slice::<Value>(stdin) {
                Ok(_) => "payload is not a JSON object".to_string(),
                Err(e) => format!("invalid JSON: {e}"),
            };
            let mut extra = Map::new();
            extra.insert("stdin_len".into(), json!(stdin.len()));
            extra.insert("stdin_sha256".into(), json!(logging::sha256_hex(stdin)));
            log_error(&loaded, "parse_input", &msg, extra);
            return empty;
        }
    };

    let mut rec = base_record("event", &loaded);
    for k in [
        "session_id",
        "tool_use_id",
        "cwd",
        "permission_mode",
        "hook_event_name",
        "transcript_path",
        "tool_name",
    ] {
        rec.insert(k.into(), str_field(&payload, k));
    }
    let keys: Vec<&String> = payload
        .as_object()
        .map(|o| o.keys().collect())
        .unwrap_or_default();
    rec.insert("payload_keys".into(), json!(keys));

    let tool = payload
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let tool_input = payload.get("tool_input").cloned().unwrap_or(Value::Null);
    let mut stdout = String::new();

    if tool == "Bash" {
        let Some(cmd) = tool_input.get("command").and_then(Value::as_str) else {
            let mut extra = Map::new();
            extra.insert("tool_name".into(), json!(tool));
            extra.insert("session_id".into(), str_field(&payload, "session_id"));
            extra.insert("tool_use_id".into(), str_field(&payload, "tool_use_id"));
            log_error(
                &loaded,
                "bash_input",
                "tool_input.command missing or not a string",
                extra,
            );
            return empty;
        };
        let source = ContextSource {
            transcript_path: payload
                .get("transcript_path")
                .and_then(Value::as_str)
                .filter(|p| !p.is_empty())
                .map(std::path::PathBuf::from),
            tool_use_id: payload
                .get("tool_use_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            request_override: None,
        };
        let (adjudicator, judge_timeout) = adjudicator(&loaded.config, env, source);
        let opts = Options {
            mode: loaded.config.mode,
            home: env.home.clone().unwrap_or_default(),
            adjudicator,
            judge_timeout,
        };
        match engine::analyze(cmd, &opts) {
            Err(e) => {
                let mut extra = Map::new();
                extra.insert("tool_use_id".into(), str_field(&payload, "tool_use_id"));
                log_error(&loaded, "analyze", &e.to_string(), extra);
                return empty;
            }
            Ok(a) => {
                if let Some(o) = &a.judge
                    && let Some(e) = o.error_message()
                {
                    let mut extra = Map::new();
                    extra.insert("session_id".into(), str_field(&payload, "session_id"));
                    extra.insert("tool_use_id".into(), str_field(&payload, "tool_use_id"));
                    extra.insert(
                        "backend".into(),
                        json!(o.backend.as_deref().unwrap_or("jev")),
                    );
                    extra.insert("decision".into(), json!(o.decision.as_str()));
                    if let Some(j) = &o.jev {
                        extra.insert("level".into(), json!(j.level));
                        extra.insert("state_hash".into(), json!(j.state_hash));
                        extra.insert("request_id".into(), json!(j.request_id));
                        extra.insert("attempts".into(), json!(j.attempts));
                    }
                    log_error(&loaded, "judge", e, extra);
                }
                let decision = decision_output(&a, loaded.config.decide_all);
                rec.insert(
                    "would_emit".into(),
                    json!(
                        decision
                            .as_ref()
                            .map(|d| d["hookSpecificOutput"]["permissionDecision"].clone())
                    ),
                );
                if let Ok(Value::Object(fields)) = serde_json::to_value(&a) {
                    rec.extend(fields);
                }
                if !loaded.config.dry_run
                    && let Some(d) = decision
                {
                    stdout = d.to_string();
                }
            }
        }
    } else {
        rec.insert(
            "tool_input".into(),
            logging::truncate_strings(&tool_input, loaded.config.max_field_bytes),
        );
    }
    rec.insert(
        "latency_us".into(),
        json!(start.elapsed().as_micros() as u64),
    );
    write(&loaded, rec);
    if loaded.config.dry_run {
        stdout.clear();
    }
    HookOutput { stdout }
}

/// `cancelli judge "<cmd>" [--transcript PATH] [--request TEXT]`: run Jev on
/// one command (regardless of CARE's verdict) and return the judge record.
/// Nothing is logged.
pub fn judge_cli(
    command: &str,
    transcript: Option<std::path::PathBuf>,
    request: Option<String>,
    decide_all: bool,
    env: &Env,
) -> jev::JudgeRecord {
    let loaded = config::load(
        env,
        &CliOverrides {
            decide_all,
            ..CliOverrides::default()
        },
    );
    let source = ContextSource {
        transcript_path: transcript,
        tool_use_id: None,
        request_override: request,
    };
    jev::judge(
        command,
        &source,
        &jev_settings(&loaded.config),
        &loaded.config.api_key(env),
    )
}
