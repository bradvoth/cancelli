//! D25: `cancelli eval --logs <files…> --config <path> [--offline] [--json]`
//! re-runs logged tool calls under another configuration and reports which
//! decisions change.
//!
//! Every logged `event` record is turned back into its `PreToolUse` payload
//! and run through [`hook::evaluate_call`], the hook's own decision path
//! (no duplicated decision logic), with one difference: the judge is a
//! [`ReplayJudge`].
//!
//! * **CARE** is replayed exactly from the logged `command`.
//! * **Jev**: when the would-be state and the rubric are unchanged and the
//!   effective backend (`base_url` host + `expected_model`) is the one the
//!   record was judged with, the logged answers are reused and evaluated
//!   under the new config (calibration, thresholds, tier order, verdicts).
//!   Otherwise the configured backend is queried: the logged state is
//!   resent if the record has one; a call that newly reaches the judge gets
//!   its state rebuilt from the record's `transcript_path` + `tool_use_id`
//!   when the transcript still exists, else it is reported as "needs judge
//!   (no state)". `--offline` never queries and reports "needs judge".
//! * **Non-Bash** calls replay per D21 and `jev.skip_tools`. Logged
//!   `tool_input` strings over `log.max_field_bytes` are truncated, so the
//!   logged judge state is preferred; with neither, the call is reported as
//!   "input truncated".
//! * Older records (no `would_emit`, no D21 fields, stub-era
//!   `unadjudicated`) get a best-effort old decision, noted as such.
//!
//! The compared decision is `final` (allow / ask / deny; `unadjudicated`
//! counts as ask, what enforce mode emits for it), or `none` when the call
//! has no decision (a pre-D21 or `skip_tools` pass-through). `decide_all`
//! only changes whether an allow is emitted, not the decision.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::config::{self, CliOverrides, Config, Env, Loaded};
use crate::hook;
use crate::jev::client::{self, DEFAULT_EXPECTED_MODEL, KeySource, Secret};
use crate::jev::state::Level;
use crate::jev::transcript::{Context, ContextSource};
use crate::jev::{self, JudgeRecord};
use crate::resolution::{Adjudication, Adjudicator, Final, JudgeInput};

/// Host of the default base URL: what a pre-D23 record (no
/// `judge.backend_host`) was judged against. `TYPESAFE_BASE_URL` overrides
/// at the time were not recorded.
pub const LEGACY_HOST: &str = "api.typesafe.ai";

/// A decision as compared by eval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Allowed.
    Allow,
    /// Ask the user.
    Ask,
    /// Denied.
    Deny,
    /// No decision (pass-through).
    None,
    /// The judge would have to be asked (offline, no state, truncated
    /// input).
    NeedsJudge,
}

impl Decision {
    /// Display name.
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Ask => "ask",
            Decision::Deny => "deny",
            Decision::None => "none",
            Decision::NeedsJudge => "needs judge",
        }
    }

    /// Row/column order of the transition matrix.
    pub const ALL: [Decision; 5] = [
        Decision::Allow,
        Decision::Ask,
        Decision::Deny,
        Decision::None,
        Decision::NeedsJudge,
    ];
}

/// How the replayed call's judge answer was obtained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "detail")]
pub enum JudgeSource {
    /// The logged answers, evaluated under the new config.
    Reused,
    /// The logged state, resent to the configured backend (why the logged
    /// answers could not be reused).
    Resent(String),
    /// A state rebuilt from the transcript, sent to the configured backend
    /// (why no logged answers were reused).
    Rebuilt(String),
    /// Not judged: why.
    NeedsJudge(String),
    /// Not judged: the logged input is truncated and no state was logged.
    InputTruncated,
}

impl JudgeSource {
    fn label(&self) -> String {
        match self {
            JudgeSource::Reused => "answers reused".into(),
            JudgeSource::Resent(r) => format!("logged state resent ({r})"),
            JudgeSource::Rebuilt(r) => format!("state rebuilt from transcript ({r})"),
            JudgeSource::NeedsJudge(r) => format!("needs judge ({r})"),
            JudgeSource::InputTruncated => "input truncated".into(),
        }
    }
}

/// One replayed record.
#[derive(Debug, Clone, Serialize)]
pub struct RecordResult {
    /// Log file.
    pub file: String,
    /// 1-based line.
    pub line: usize,
    /// Record timestamp.
    pub ts: String,
    /// Tool.
    pub tool_name: String,
    /// `tool_use_id`.
    pub tool_use_id: Option<String>,
    /// The command or target, abbreviated.
    pub target: String,
    /// Logged decision.
    pub old: Decision,
    /// How the old decision was derived, when not read directly.
    pub old_note: Option<String>,
    /// Decision under the new config.
    pub new: Decision,
    /// `old != new`.
    pub changed: bool,
    /// Reasons (CARE score/skip/rule changes, tier changes, calibration, …).
    pub why: Vec<String>,
    /// Judge source for the new decision (None: no judge involved).
    pub judge: Option<JudgeSource>,
    /// Logged Jev tier.
    pub old_tier: Option<String>,
    /// New Jev tier.
    pub new_tier: Option<String>,
    /// New `would_emit` (what enforce mode would print).
    pub would_emit: Option<String>,
}

/// Eval arguments.
#[derive(Debug, Clone)]
pub struct EvalArgs {
    /// Log files (JSONL).
    pub logs: Vec<PathBuf>,
    /// Config to evaluate.
    pub config: PathBuf,
    /// Never query a backend.
    pub offline: bool,
}

/// The whole report.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Config path.
    pub config: String,
    /// Its `config_fingerprint`.
    pub config_fingerprint: String,
    /// Its `overrides[]`.
    pub overrides: Vec<String>,
    /// Config diagnostics (`level: message`).
    pub diagnostics: Vec<String>,
    /// `--offline`.
    pub offline: bool,
    /// Non-empty lines read.
    pub lines: usize,
    /// Skipped lines by reason.
    pub skipped: BTreeMap<String, usize>,
    /// Replayed records, sorted by (ts, tool_use_id, file, line).
    pub results: Vec<RecordResult>,
}

impl Report {
    /// Records replayed.
    pub fn replayed(&self) -> usize {
        self.results.len()
    }
    /// Records whose decision changed.
    pub fn changed(&self) -> usize {
        self.results.iter().filter(|r| r.changed).count()
    }
    /// `old -> new -> count`.
    pub fn matrix(&self) -> BTreeMap<(Decision, Decision), usize> {
        let mut m = BTreeMap::new();
        for r in &self.results {
            *m.entry((r.old, r.new)).or_insert(0) += 1;
        }
        m
    }
}

// ------------------------------------------------------------ replay judge --

/// What the record logged about its Jev call.
#[derive(Debug, Clone)]
struct Logged {
    state: String,
    state_hash: String,
    level: Level,
    context: Value,
    model: Option<String>,
    answers: Option<Value>,
    error: Option<String>,
    rubric_hash: String,
    host: String,
    expected_model: String,
}

impl Logged {
    fn from_record(r: &Value) -> Option<Logged> {
        let j = r.get("judge")?;
        let state = j.get("state")?.as_str()?.to_string();
        let s = |k: &str| j.get(k).and_then(Value::as_str).map(str::to_string);
        Some(Logged {
            state,
            state_hash: s("state_hash").unwrap_or_default(),
            level: s("level")
                .as_deref()
                .and_then(Level::parse)
                .unwrap_or(Level::L0),
            context: j.get("context").cloned().unwrap_or(Value::Null),
            model: s("model"),
            answers: j.get("answers").filter(|a| a.is_object()).cloned(),
            error: s("error"),
            rubric_hash: s("rubric_hash").unwrap_or_default(),
            host: s("backend_host").unwrap_or_else(|| LEGACY_HOST.into()),
            expected_model: s("expected_model").unwrap_or_else(|| DEFAULT_EXPECTED_MODEL.into()),
        })
    }

    fn context(&self) -> Context {
        let n = |k: &str| {
            self.context
                .get(k)
                .and_then(Value::as_u64)
                .map_or(0, |v| v as usize)
        };
        Context {
            level: self.level,
            level_reason: "logged state (cancelli eval)".into(),
            user_request: String::new(),
            prior_actions: Vec::new(),
            prompts_total: n("prompts_total"),
            prompts_kept: n("prompts_kept"),
            actions_total: n("actions_total"),
            bad_lines: n("bad_lines"),
        }
    }
}

/// The judge `cancelli eval` plugs into the hook's decision path.
pub struct ReplayJudge {
    settings: jev::Settings,
    key: Result<(Secret, KeySource), String>,
    source: ContextSource,
    logged: Option<Logged>,
    /// Ok: the logged answers may be reused; Err: why not.
    reuse: Result<(), String>,
    /// The `jev.context` limits are provably the ones the state was built
    /// with.
    context_same: bool,
    offline: bool,
    input_truncated: bool,
    note: Arc<Mutex<Option<JudgeSource>>>,
}

impl ReplayJudge {
    fn not_judged(&self, why: JudgeSource) -> JudgeRecord {
        let ctx = Context {
            level: Level::L0,
            level_reason: "not judged (cancelli eval)".into(),
            user_request: String::new(),
            prior_actions: Vec::new(),
            prompts_total: 0,
            prompts_kept: 0,
            actions_total: 0,
            bad_lines: 0,
        };
        let mut rec = jev::new_record(ctx, String::new(), String::new(), &self.settings, &self.key);
        rec.error = Some(why.label());
        self.set(why);
        rec
    }

    fn set(&self, s: JudgeSource) {
        if let Ok(mut n) = self.note.lock() {
            *n = Some(s);
        }
    }

    fn transcript_exists(&self) -> bool {
        self.source
            .transcript_path
            .as_deref()
            .is_some_and(Path::exists)
    }
}

impl Adjudicator for ReplayJudge {
    fn name(&self) -> &str {
        "jev"
    }
    fn failure_decision(&self) -> Final {
        Final::Ask
    }
    fn adjudicate(&self, input: &JudgeInput) -> Adjudication {
        let rec = match (&self.logged, &self.reuse) {
            (Some(l), Ok(())) => {
                self.set(JudgeSource::Reused);
                jev::judge_logged_answers(
                    &l.state,
                    &l.state_hash,
                    l.context(),
                    l.model.as_deref().unwrap_or_default(),
                    l.answers.as_ref().unwrap_or(&Value::Null),
                    &self.settings,
                )
            }
            (None, _) if self.input_truncated => self.not_judged(JudgeSource::InputTruncated),
            (None, _) if self.offline => {
                self.not_judged(JudgeSource::NeedsJudge("offline; no logged state".into()))
            }
            (Some(_), Err(why)) if self.offline => {
                self.not_judged(JudgeSource::NeedsJudge(format!("offline; {why}")))
            }
            (Some(l), Err(why))
                if self.context_same || self.input_truncated || !self.transcript_exists() =>
            {
                self.set(JudgeSource::Resent(why.clone()));
                jev::judge_state(
                    &l.state,
                    &l.state_hash,
                    l.context(),
                    &self.settings,
                    &self.key,
                )
            }
            (_, reuse) if self.transcript_exists() => {
                self.set(JudgeSource::Rebuilt(
                    reuse.clone().err().unwrap_or_default(),
                ));
                jev::judge_action(&input.action, &self.source, &self.settings, &self.key)
            }
            _ => self.not_judged(JudgeSource::NeedsJudge("no state".into())),
        };
        Adjudication::Jev(Box::new(rec))
    }
}

// --------------------------------------------------------------- records --

/// A logged value is a truncation marker (`logging::truncate_strings`).
fn is_truncated(v: &Value) -> bool {
    match v {
        Value::Object(o) => {
            (o.len() == 3
                && o.contains_key("truncated")
                && o.contains_key("len")
                && o.contains_key("sha256"))
                || o.values().any(is_truncated)
        }
        Value::Array(a) => a.iter().any(is_truncated),
        _ => false,
    }
}

/// The `PreToolUse` payload a record was logged from.
fn payload_of(r: &Value, tool: &str) -> Value {
    let mut p = Map::new();
    for k in [
        "session_id",
        "transcript_path",
        "cwd",
        "permission_mode",
        "hook_event_name",
        "tool_name",
        "tool_use_id",
    ] {
        if let Some(v) = r.get(k) {
            p.insert(k.into(), v.clone());
        }
    }
    let input = match (tool, r.get("command")) {
        ("Bash", Some(Value::String(c))) => json!({"command": c}),
        _ => r.get("tool_input").cloned().unwrap_or(Value::Null),
    };
    p.insert("tool_input".into(), input);
    Value::Object(p)
}

fn old_decision(r: &Value, tool: &str) -> (Decision, Option<String>) {
    match r.get("final").and_then(Value::as_str) {
        Some("allow") => (Decision::Allow, None),
        Some("ask") => (Decision::Ask, None),
        Some("deny") => (Decision::Deny, None),
        Some("unadjudicated") => (
            Decision::Ask,
            Some("stub-era 'unadjudicated', counted as ask (what enforce mode emitted)".into()),
        ),
        Some(other) => (Decision::None, Some(format!("unknown final {other:?}"))),
        None if tool != "Bash" && r.get("unscored").is_none() && r.get("care").is_none() => {
            let why = if r.get("config_fingerprint").is_some() {
                "no decision logged (jev.skip_tools pass-through, or pre-D21)"
            } else {
                "pre-D21 record: logged raw, no decision"
            };
            (Decision::None, Some(why.into()))
        }
        None => (
            Decision::None,
            Some("no final in the record (older version)".into()),
        ),
    }
}

fn decision_of(ev: &Map<String, Value>) -> Decision {
    match ev.get("final").and_then(Value::as_str) {
        Some("allow") => Decision::Allow,
        Some("ask") | Some("unadjudicated") => Decision::Ask,
        Some("deny") => Decision::Deny,
        _ => Decision::None,
    }
}

fn clip(s: &str, n: usize) -> String {
    let one = s.lines().next().unwrap_or("");
    let more = one.len() < s.len();
    let mut out: String = one.chars().take(n).collect();
    if more || one.chars().count() > n {
        out.push('…');
    }
    out
}

fn target_of(r: &Value, tool: &str) -> String {
    if tool == "Bash"
        && let Some(c) = r.get("command").and_then(Value::as_str)
    {
        return clip(c, 60);
    }
    let input = r.get("tool_input").unwrap_or(&Value::Null);
    for k in [
        "file_path",
        "path",
        "url",
        "query",
        "pattern",
        "command",
        "notebook_path",
        "description",
        "prompt",
        "skill",
    ] {
        if let Some(v) = input.get(k) {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Object(o) => o
                    .get("truncated")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                other => other.to_string(),
            };
            return clip(&s, 60);
        }
    }
    clip(&input.to_string(), 60)
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for k in path {
        cur = cur.get(*k)?;
    }
    cur.as_str()
}

fn tier_of(j: Option<&Value>) -> Option<String> {
    j.and_then(|j| j.get("tier"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn fmt_opt(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "none".into(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

fn rule_ids(v: &Value) -> BTreeSet<String> {
    v.get("fired_rules")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|r| r.get("id").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Why the decision moved: CARE (mode, verdict, score, skip predicate,
/// rules), the judge (reached or not, tier, calibration, answer source) and
/// D21/skip_tools pass-through.
fn reasons(
    old: &Value,
    new: &Value,
    tool: &str,
    judge: &Option<JudgeSource>,
    old_note: &Option<String>,
) -> Vec<String> {
    let mut why = Vec::new();
    if tool == "Bash" && old.get("command").is_some() {
        let om = old
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("balanced");
        let nm = new
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("balanced");
        if om != nm {
            why.push(format!("mode {om}→{nm}"));
        }
        let op = str_at(old, &["provisional", om]).unwrap_or("?");
        let np = str_at(new, &["provisional", nm]).unwrap_or("?");
        if op != np {
            why.push(format!("CARE {op}→{np}"));
        }
        if old.get("aggregate") != new.get("aggregate") {
            why.push(format!(
                "score {}→{}",
                fmt_opt(old.get("aggregate")),
                fmt_opt(new.get("aggregate"))
            ));
        }
        if old.get("skip_predicate") != new.get("skip_predicate") {
            why.push(format!(
                "skip {}→{}",
                fmt_opt(old.get("skip_predicate")),
                fmt_opt(new.get("skip_predicate"))
            ));
        }
        let (or, nr) = (rule_ids(old), rule_ids(new));
        let added: Vec<&String> = nr.difference(&or).collect();
        let removed: Vec<&String> = or.difference(&nr).collect();
        if !added.is_empty() || !removed.is_empty() {
            let mut s = String::from("rules");
            for a in added {
                s.push_str(&format!(" +{a}"));
            }
            for r in removed {
                s.push_str(&format!(" -{r}"));
            }
            why.push(s);
        }
    }
    let oj = old.get("judge").filter(|j| !j.is_null());
    let nj = new.get("judge").filter(|j| !j.is_null());
    match (oj, nj) {
        (None, Some(_)) => why.push(if tool == "Bash" {
            "newly reaches the judge".into()
        } else {
            "D21: now judged (CARE cannot score it)".into()
        }),
        (Some(_), None) if tool != "Bash" => why.push("jev.skip_tools: not judged".into()),
        (Some(_), None) => why.push("no longer reaches the judge".into()),
        _ => {}
    }
    if let (Some(o), Some(n)) = (oj, nj) {
        let (ot, nt) = (tier_of(Some(o)), tier_of(Some(n)));
        let oe = o.get("error").is_some_and(|e| !e.is_null());
        let ne = n.get("error").is_some_and(|e| !e.is_null());
        if ot != nt
            && !matches!(
                judge,
                Some(JudgeSource::NeedsJudge(_) | JudgeSource::InputTruncated)
            )
        {
            let show = |t: Option<String>, err: bool, j: &Value| match (t, err) {
                (Some(t), _) => t,
                (None, true) => "error".into(),
                (None, false) => j
                    .get("decision")
                    .and_then(Value::as_str)
                    .unwrap_or("none")
                    .to_string(),
            };
            why.push(format!("tier {}→{}", show(ot, oe, o), show(nt, ne, n)));
        }
        if let Some(c) = n.get("calibration").filter(|c| !c.is_null()) {
            why.push(format!(
                "calibrated ({} axes, sha {})",
                c.get("axes").and_then(Value::as_array).map_or(0, Vec::len),
                c.get("sha").and_then(Value::as_str).unwrap_or("?")
            ));
        }
    }
    if let Some(j) = judge {
        why.push(j.label());
    }
    if let Some(n) = old_note {
        why.push(format!("old: {n}"));
    }
    why
}

// -------------------------------------------------------------------- run --

fn skip(r: &mut Report, why: &str) {
    *r.skipped.entry(why.to_string()).or_insert(0) += 1;
}

/// Replay the logs under the config.
pub fn run(args: &EvalArgs, env: &Env) -> Result<Report, String> {
    if !args.config.exists() {
        return Err(format!("config {} not found", args.config.display()));
    }
    let loaded = config::load_from(Some(args.config.clone()), env, &CliOverrides::default());
    // The key is resolved only when a backend may be queried.
    let key = if args.offline {
        Err("offline".to_string())
    } else {
        loaded.config.api_key(env)
    };
    let rubric_hash = loaded.config.tunables.jev.rubric_hash().to_string();
    let host = client::host_of(&loaded.config.judge_base_url);
    let expected = loaded.config.tunables.judge.expected_model.clone();
    let new_ctx_overridden = loaded
        .overrides
        .iter()
        .any(|k| k.starts_with("jev.context."));

    let mut report = Report {
        config: args.config.display().to_string(),
        config_fingerprint: loaded.fingerprint.clone(),
        overrides: loaded.overrides.clone(),
        diagnostics: loaded
            .diagnostics
            .iter()
            .map(|d| format!("{}: {}", d.level, d.message))
            .collect(),
        offline: args.offline,
        lines: 0,
        skipped: BTreeMap::new(),
        results: Vec::new(),
    };

    for file in &args.logs {
        let f = std::fs::File::open(file).map_err(|e| format!("{}: {e}", file.display()))?;
        for (i, line) in std::io::BufReader::new(f).lines().enumerate() {
            let line = line.map_err(|e| format!("{}: {e}", file.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            report.lines += 1;
            let Ok(r) = serde_json::from_str::<Value>(&line) else {
                skip(&mut report, "not JSON");
                continue;
            };
            let kind = r.get("kind").and_then(Value::as_str).unwrap_or("?");
            if kind != "event" {
                skip(&mut report, &format!("not an event (kind={kind})"));
                continue;
            }
            let Some(tool) = r
                .get("tool_name")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                skip(&mut report, "no tool_name");
                continue;
            };
            let result = replay_one(
                &r,
                &tool,
                &loaded,
                env,
                &key,
                args.offline,
                &ReplayCtx {
                    rubric_hash: &rubric_hash,
                    host: &host,
                    expected: &expected,
                    new_ctx_overridden,
                },
            );
            match result {
                Ok(mut res) => {
                    res.file = file.display().to_string();
                    res.line = i + 1;
                    report.results.push(res);
                }
                Err(e) => skip(&mut report, &format!("replay failed: {e}")),
            }
        }
    }
    report.results.sort_by(|a, b| {
        (&a.ts, &a.tool_use_id, &a.file, a.line).cmp(&(&b.ts, &b.tool_use_id, &b.file, b.line))
    });
    Ok(report)
}

struct ReplayCtx<'a> {
    rubric_hash: &'a str,
    host: &'a str,
    expected: &'a str,
    new_ctx_overridden: bool,
}

fn replay_one(
    r: &Value,
    tool: &str,
    loaded: &Loaded,
    env: &Env,
    key: &Result<(Secret, KeySource), String>,
    offline: bool,
    rc: &ReplayCtx<'_>,
) -> Result<RecordResult, String> {
    let payload = payload_of(r, tool);
    let logged = Logged::from_record(r);
    let old_ctx_overridden = r
        .get("overrides")
        .and_then(Value::as_array)
        .is_some_and(|a| {
            a.iter()
                .any(|k| k.as_str().is_some_and(|k| k.starts_with("jev.context.")))
        });
    let context_same = !old_ctx_overridden && !rc.new_ctx_overridden;
    let reuse = match &logged {
        None => Err("no logged state".to_string()),
        Some(l) => {
            if l.answers.is_none() || l.model.is_none() {
                Err(format!(
                    "the logged judge call failed ({})",
                    l.error.as_deref().unwrap_or("no answers")
                ))
            } else if l.rubric_hash != rc.rubric_hash {
                Err(format!("rubric {}→{}", l.rubric_hash, rc.rubric_hash))
            } else if l.host != rc.host || l.expected_model != rc.expected {
                Err(format!(
                    "backend {}/{}→{}/{}",
                    l.host, l.expected_model, rc.host, rc.expected
                ))
            } else if !context_same {
                Err("jev.context limits may differ".into())
            } else {
                Ok(())
            }
        }
    };
    let input_truncated =
        tool != "Bash" && is_truncated(payload.get("tool_input").unwrap_or(&Value::Null));
    let note: Arc<Mutex<Option<JudgeSource>>> = Arc::new(Mutex::new(None));
    let settings = hook::jev_settings(&loaded.config);
    let factory = |c: &Config, source: ContextSource| -> (Arc<dyn Adjudicator>, Duration) {
        if c.judge_backend == "stub" {
            return hook::adjudicator(c, env, source);
        }
        let j = ReplayJudge {
            settings: settings.clone(),
            key: key.clone(),
            source,
            logged: logged.clone(),
            reuse: reuse.clone(),
            context_same,
            offline,
            input_truncated,
            note: Arc::clone(&note),
        };
        (
            Arc::new(j),
            jev::backstop(Duration::from_millis(c.judge_budget_ms)),
        )
    };
    let ev = hook::evaluate_call(&payload, loaded, env, &factory);
    let event = ev.event.ok_or_else(|| {
        ev.errors
            .first()
            .map_or("analysis failed".to_string(), |e| {
                e.get("error")
                    .map_or("analysis failed".into(), |x| x.to_string())
            })
    })?;
    let judge = note.lock().ok().and_then(|n| n.clone());
    let (old, old_note) = old_decision(r, tool);
    let new = match &judge {
        Some(JudgeSource::NeedsJudge(_) | JudgeSource::InputTruncated) => Decision::NeedsJudge,
        _ => decision_of(&event),
    };
    let new_v = Value::Object(event.clone());
    let why = reasons(r, &new_v, tool, &judge, &old_note);
    Ok(RecordResult {
        file: String::new(),
        line: 0,
        ts: r
            .get("ts")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        tool_name: tool.to_string(),
        tool_use_id: r
            .get("tool_use_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        target: target_of(r, tool),
        old,
        old_note,
        new,
        changed: old != new,
        why,
        judge,
        old_tier: tier_of(r.get("judge")),
        new_tier: tier_of(event.get("judge")),
        would_emit: event
            .get("would_emit")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

// ---------------------------------------------------------------- output --

fn pad(s: &str, n: usize) -> String {
    let w = s.chars().count();
    if w >= n {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(n - w))
    }
}

/// Human-readable report: summary, transition matrix, changed calls.
pub fn render_text(r: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "cancelli eval: config {} (config_fingerprint {}; overrides {:?}){}\n",
        r.config,
        r.config_fingerprint,
        r.overrides,
        if r.offline { "; offline" } else { "" }
    ));
    for d in &r.diagnostics {
        out.push_str(&format!("  config {d}\n"));
    }
    let skipped: usize = r.skipped.values().sum();
    out.push_str(&format!(
        "records: {} lines, replayed {}, skipped {}, changed {}\n",
        r.lines,
        r.replayed(),
        skipped,
        r.changed()
    ));
    for (why, n) in &r.skipped {
        out.push_str(&format!("  skipped {n}: {why}\n"));
    }
    let mut nj: BTreeMap<String, usize> = BTreeMap::new();
    for x in &r.results {
        if let Some(j @ (JudgeSource::NeedsJudge(_) | JudgeSource::InputTruncated)) = &x.judge {
            *nj.entry(j.label()).or_insert(0) += 1;
        }
    }
    for (why, n) in &nj {
        out.push_str(&format!("  {n}: {why}\n"));
    }
    let old_notes = r.results.iter().filter(|x| x.old_note.is_some()).count();
    if old_notes > 0 {
        out.push_str(&format!(
            "  {old_notes}: old decision annotated (older record format, stub-era or pass-through; see why)\n"
        ));
    }

    out.push_str("\ntransition matrix (rows old, columns new)\n");
    let m = r.matrix();
    let w = 12;
    out.push_str(&pad("old \\ new", w));
    for c in Decision::ALL {
        out.push_str(&format!("{:>12}", c.as_str()));
    }
    out.push('\n');
    for row in Decision::ALL {
        if row == Decision::NeedsJudge {
            continue;
        }
        out.push_str(&pad(row.as_str(), w));
        for col in Decision::ALL {
            out.push_str(&format!("{:>12}", m.get(&(row, col)).copied().unwrap_or(0)));
        }
        out.push('\n');
    }

    let changed: Vec<&RecordResult> = r.results.iter().filter(|x| x.changed).collect();
    out.push_str(&format!("\nchanged calls ({})\n", changed.len()));
    if !changed.is_empty() {
        out.push_str(&format!(
            "{}{}{}{}why\n",
            pad("ts", 20),
            pad("tool", 14),
            pad("command / target", 50),
            pad("old → new", 22)
        ));
    }
    for x in changed {
        let ts: String = x.ts.chars().take(19).collect();
        out.push_str(&format!(
            "{}{}{}{}{}\n",
            pad(&ts, 20),
            pad(&clip(&x.tool_name, 12), 14),
            pad(&clip(&x.target, 47), 50),
            pad(&format!("{} → {}", x.old.as_str(), x.new.as_str()), 22),
            x.why.join("; ")
        ));
    }
    out
}

/// Machine-readable report: one JSON object per replayed record (sorted),
/// then one `{"summary": …}` line.
pub fn render_json(r: &Report) -> String {
    let mut out = String::new();
    for x in &r.results {
        out.push_str(&serde_json::to_string(x).unwrap_or_default());
        out.push('\n');
    }
    let matrix: Vec<Value> = r
        .matrix()
        .into_iter()
        .map(|((o, n), c)| json!({"old": o, "new": n, "count": c}))
        .collect();
    let summary = json!({"summary": {
        "config": r.config,
        "config_fingerprint": r.config_fingerprint,
        "overrides": r.overrides,
        "diagnostics": r.diagnostics,
        "offline": r.offline,
        "lines": r.lines,
        "replayed": r.replayed(),
        "skipped": r.skipped,
        "changed": r.changed(),
        "transitions": matrix,
    }});
    out.push_str(&summary.to_string());
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_markers_are_found_anywhere() {
        assert!(!is_truncated(
            &json!({"file_path": "/x", "content": "short"})
        ));
        assert!(is_truncated(&json!({"edits": [{"new_string":
            {"truncated": "abc", "len": 9000, "sha256": "00"}}]})));
    }

    #[test]
    fn old_decisions_of_older_record_formats() {
        let d = |v: Value, t: &str| old_decision(&v, t);
        assert_eq!(d(json!({"final": "deny"}), "Bash").0, Decision::Deny);
        let (x, n) = d(json!({"final": "unadjudicated"}), "Bash");
        assert_eq!(x, Decision::Ask);
        assert!(n.unwrap().contains("stub-era"));
        let (x, n) = d(json!({"tool_input": {}}), "Read");
        assert_eq!(x, Decision::None);
        assert!(n.unwrap().contains("pre-D21"));
        let (x, _) = d(json!({"final": "ask", "unscored": true}), "Read");
        assert_eq!(x, Decision::Ask);
    }

    #[test]
    fn targets_are_abbreviated() {
        assert_eq!(
            target_of(&json!({"command": "rm -rf /tmp/x\necho hi"}), "Bash"),
            "rm -rf /tmp/x…"
        );
        assert_eq!(
            target_of(
                &json!({"tool_input": {"file_path": "/a/b.rs", "content": "x"}}),
                "Write"
            ),
            "/a/b.rs"
        );
    }
}
