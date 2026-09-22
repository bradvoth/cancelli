//! Claude Code `PreToolUse` hook handling: stdin JSON → analysis → one log
//! record → (enforce mode only) a decision on stdout. Fails open: every
//! internal error becomes an `error` record and empty stdout.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::config::{self, CliOverrides, Env, Loaded};
use crate::engine::{self, Analysis, Options};
use crate::logging;
use crate::policy::Mode;
use crate::resolution::{Final, StubAdjudicator};
use crate::rules;

/// Hook invocation arguments (from the CLI).
#[derive(Debug, Clone, Default)]
pub struct HookArgs {
    /// `--dry-run`.
    pub dry_run: bool,
    /// `--mode`.
    pub mode: Option<Mode>,
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

/// Decision JSON for enforce mode (D6: built, not registered).
pub fn decision_output(a: &Analysis) -> Option<Value> {
    let rules: Vec<&str> = a.fired_rules.iter().map(|r| r.id.as_str()).collect();
    let rules = if rules.is_empty() {
        "none".to_string()
    } else {
        rules.join(",")
    };
    let (decision, reason) = match a.r#final {
        Final::Allow => return None,
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
    Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
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
        let opts = Options {
            mode: loaded.config.mode,
            home: env.home.clone().unwrap_or_default(),
            adjudicator: Arc::new(StubAdjudicator),
            judge_timeout: Duration::from_millis(loaded.config.judge_timeout_ms),
        };
        match engine::analyze(cmd, &opts) {
            Err(e) => {
                let mut extra = Map::new();
                extra.insert("tool_use_id".into(), str_field(&payload, "tool_use_id"));
                log_error(&loaded, "analyze", &e.to_string(), extra);
                return empty;
            }
            Ok(a) => {
                let decision = decision_output(&a);
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
