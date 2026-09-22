//! Claude Code `PreToolUse` hook handling: stdin JSON → analysis → one log
//! record → (enforce mode only) a decision on stdout. Fails open: every
//! internal error becomes an `error` record and empty stdout.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::config::{self, CliOverrides, Config, Env, Loaded};
use crate::engine::{self, Analysis, Options};
use crate::fixes::Tags;
use crate::jev::client::Transport;
use crate::jev::decide::Verdict as JevVerdict;
use crate::jev::transcript::ContextSource;
use crate::jev::{self, Action, JevAdjudicator, JudgeRecord};
use crate::logging;
use crate::policy::Mode;
use crate::resolution::{self, Adjudicator, Final, JudgeInput, JudgeOutcome, StubAdjudicator};
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
    // D20: which tunables produced this record.
    m.insert("config_fingerprint".into(), json!(loaded.fingerprint));
    m.insert("overrides".into(), json!(loaded.overrides));
    m.insert(
        "rubric_hash".into(),
        json!(loaded.config.tunables.jev.rubric_hash()),
    );
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

/// The `judge` error record (D15) for a failed judge call, if it failed.
/// D21 records (`unscored`) also name the tool.
fn log_judge_error(loaded: &Loaded, payload: &Value, o: &JudgeOutcome, unscored: bool) {
    let Some(e) = o.error_message() else { return };
    let mut extra = Map::new();
    extra.insert("session_id".into(), str_field(payload, "session_id"));
    extra.insert("tool_use_id".into(), str_field(payload, "tool_use_id"));
    if unscored {
        extra.insert("tool_name".into(), str_field(payload, "tool_name"));
        extra.insert("unscored".into(), json!(true));
    }
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
    log_error(loaded, "judge", e, extra);
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
        tuning: c.tunables.jev.clone(),
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

/// Decision JSON for a Jev verdict: `deny`/`ask` always, `allow` only with
/// `decide_all` (D13; on by default, D22). The reason names the tier (or
/// the failure, D15) and what CARE said (`care`).
fn jev_output(j: &JudgeRecord, care: &str, decide_all: bool) -> Option<Value> {
    let why = match (&j.error, j.tier, j.tier_rule.as_deref()) {
        (Some(e), _, _) => format!("Jev unavailable ({e})"),
        (None, Some(t), Some(rule)) => format!("Jev {t}: {rule}"),
        _ => "Jev".to_string(),
    };
    match j.verdict {
        JevVerdict::Allow if !decide_all => None,
        v => emit(
            v.as_str(),
            format!("cancelli: {} -> {}; {care}", why, v.as_str()),
        ),
    }
}

/// D21: decision JSON for a call CARE cannot score. Treated exactly as a
/// Bash WARN: the judge's verdict decides; a judge failure or a stub asks.
pub fn unscored_decision_output(o: &JudgeOutcome, reason: &str, decide_all: bool) -> Option<Value> {
    let care = format!("CARE cannot score this call ({reason}), treated as WARN (D21)");
    if let Some(j) = o.jev.as_ref() {
        return jev_output(j, &care, decide_all);
    }
    let backend = o.backend.as_deref().unwrap_or("judge");
    match o.decision {
        Final::Allow if !decide_all => None,
        Final::Allow => emit("allow", format!("cancelli: {backend} -> allow; {care}")),
        Final::Deny => emit("deny", format!("cancelli: {backend} -> deny; {care}")),
        Final::Ask => emit("ask", format!("cancelli: {backend} failed -> ask; {care}")),
        Final::Unadjudicated => emit(
            "ask",
            format!("cancelli: no judge configured -> ask; {care}"),
        ),
    }
}

/// Decision JSON for enforce mode. CARE DENY denies; CARE ALLOW and a Jev
/// `allow` emit `allow` only with `decide_all` (D13, default on per D22),
/// otherwise nothing; a Jev verdict names its tier; Jev failures ask (D15).
pub fn decision_output(a: &Analysis, decide_all: bool) -> Option<Value> {
    let rules: Vec<&str> = a.fired_rules.iter().map(|r| r.id.as_str()).collect();
    let rules = if rules.is_empty() {
        "none".to_string()
    } else {
        rules.join(",")
    };
    if let Some(j) = a.judge.as_ref().and_then(|o| o.jev.as_ref()) {
        let care = format!("CARE WARN score {}, rules {}", a.aggregate, rules);
        return jev_output(j, &care, decide_all);
    }
    let (decision, reason) = match a.r#final {
        Final::Allow if !decide_all => return None,
        Final::Allow => (
            "allow",
            format!(
                "cancelli (CARE): ALLOW, score {} [{}], rules {}",
                a.aggregate,
                a.provisional.get(a.mode).as_str(),
                rules
            ),
        ),
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

    // D21: CARE scores a Bash command; every other call is unscorable.
    let scored: Result<&str, &'static str> = if tool != "Bash" {
        Err("non-shell tool")
    } else {
        match tool_input.get("command") {
            None | Some(Value::Null) => Err("missing command"),
            Some(Value::String(c)) if c.trim().is_empty() => Err("empty command"),
            Some(Value::String(c)) => Ok(c),
            Some(_) => Err("command is not a string"),
        }
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

    match scored {
        Ok(cmd) => {
            let (adjudicator, judge_timeout) = adjudicator(&loaded.config, env, source);
            let opts = Options {
                mode: loaded.config.mode,
                home: env.home.clone().unwrap_or_default(),
                adjudicator,
                judge_timeout,
                care: loaded.config.tunables.care.clone(),
            };
            match engine::analyze(cmd, &opts) {
                Err(e) => {
                    let mut extra = Map::new();
                    extra.insert("tool_use_id".into(), str_field(&payload, "tool_use_id"));
                    log_error(&loaded, "analyze", &e.to_string(), extra);
                    return empty;
                }
                Ok(a) => {
                    if let Some(o) = &a.judge {
                        log_judge_error(&loaded, &payload, o, false);
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
        }
        Err(reason) => {
            rec.insert(
                "tool_input".into(),
                logging::truncate_strings(&tool_input, loaded.config.max_field_bytes),
            );
            if !loaded.config.tunables.jev.skips(tool) {
                // D21: CARE can't score it, so it is a WARN for Jev.
                let (adjudicator, judge_timeout) = adjudicator(&loaded.config, env, source);
                let input = JudgeInput {
                    action: Action::Tool {
                        name: tool.to_string(),
                        input: tool_input.clone(),
                    },
                    prompt: None,
                };
                let mut tags = Tags::default();
                let outcome = resolution::run_judge(adjudicator, &input, judge_timeout, &mut tags);
                log_judge_error(&loaded, &payload, &outcome, true);
                let decision = unscored_decision_output(&outcome, reason, loaded.config.decide_all);
                rec.insert("care".into(), json!({"supported": false, "reason": reason}));
                rec.insert("unscored".into(), json!(true));
                rec.insert("provisional".into(), json!("WARN"));
                rec.insert("would_adjudicate".into(), json!(true));
                rec.insert(
                    "would_emit".into(),
                    json!(
                        decision
                            .as_ref()
                            .map(|d| d["hookSpecificOutput"]["permissionDecision"].clone())
                    ),
                );
                rec.insert("judge".into(), json!(outcome));
                rec.insert("final".into(), json!(outcome.decision));
                rec.insert(
                    "fixes_applied".into(),
                    json!(tags.fixes.into_iter().collect::<Vec<_>>()),
                );
                if !loaded.config.dry_run
                    && let Some(d) = decision
                {
                    stdout = d.to_string();
                }
            }
        }
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
