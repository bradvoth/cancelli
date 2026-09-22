//! Jev as the WARN adjudicator (D11–D17): `jev-1.13.0`, TypeSafe AI's
//! hosted "System One" API, or since D23 any `/v1/systemone`-compatible
//! server (e.g. jev-rs on a local model), with optional per-axis
//! calibration of its answers (D24).
//!
//! Called for unresolved CARE WARNs and, since D21, for every tool call
//! CARE cannot score (an [`Action::Tool`], rendered in the POC's
//! `Name(json)` form) unless `jev.skip_tools` lists it.
//!
//! Pipeline for one unresolved CARE WARN: transcript -> [`transcript::Context`]
//! (level L2/L1/L0) -> [`state::State`] (the POC's render template, D16) ->
//! one `POST /v1/systemone` with the rubric's questions for that level ->
//! [`evaluate`]: model check (`judge.expected_model`) -> completeness ->
//! calibration (`judge.calibration_file`) -> [`decide::signals`] ->
//! [`decide::tier`] -> verdict (D14). Every failure is `ask` plus an error
//! (D15). The result is a [`JudgeRecord`], logged in full in dry-run and
//! enforce mode alike (D17). `cancelli eval` (D25) reuses [`evaluate`] on
//! logged answers and [`judge_state`] to resend a logged state.

pub mod calibration;
pub mod client;
pub mod decide;
pub mod pyjson;
pub mod rubric;
pub mod state;
pub mod transcript;

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

use crate::resolution::{Adjudication, Adjudicator, Final, JudgeInput};
use crate::tunables::{CalibrationState, ContextLimits, JevTunables};
use client::{KeySource, Secret, Transport};
use decide::{Answers, Usage, Verdict};
use pyjson::{J, compact};
use rubric::Rubric;
use state::Level;
use transcript::{Context, ContextSource};

/// Documented deviations from the POC (README "Jev deviations").
pub const DEVIATIONS: &[(&str, &str)] = &[
    (
        "JEV-DEV-001",
        "user_request keeps the most recent prompt (POC keeps the oldest 4,000 chars)",
    ),
    (
        "JEV-DEV-002",
        "prior-turn results are never read, so the 12,000-char history budget counts call text only",
    ),
    (
        "JEV-DEV-003",
        "transport: 3 s per request, 5 s budget, one retry (POC: SDK 60 s, 2 retries, 30 s budget); failures ask",
    ),
    (
        "JEV-DEV-004",
        "no answer cache: every unresolved WARN is a fresh call",
    ),
];

/// Everything the judge needs besides the command and the key.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Transport.
    pub transport: Transport,
    /// Requested model (`judge.model`).
    pub model: String,
    /// D23: the `response.model` the backend must report.
    pub expected_model: String,
    /// D23: false = a missing key is fine (no `Authorization` header).
    pub api_key_required: bool,
    /// D24: calibration applied to the answers.
    pub calibration: CalibrationState,
    /// D13: a Jev `allow` emits `allow`.
    pub decide_all: bool,
    /// Jev tunables (D19), including the rubric in use.
    pub tuning: JevTunables,
}

/// The judge record (logged as `judge`; printed by `cancelli judge`).
#[derive(Debug, Clone, Serialize)]
pub struct JudgeRecord {
    /// Always `jev` (any `/v1/systemone` server, D23).
    pub backend: &'static str,
    /// D23: `host[:port]` of `judge.base_url`.
    pub backend_host: String,
    /// D23: the `response.model` required (`judge.expected_model`).
    pub expected_model: String,
    /// Achieved context level.
    pub level: Level,
    /// Why that level, and context counts.
    pub context: Context,
    /// Axis ids sent.
    pub questions_sent: Vec<String>,
    /// The rendered state (exact request text).
    pub state: String,
    /// POC `state_hash` of the state.
    pub state_hash: String,
    /// Rubric hash.
    pub rubric_hash: String,
    /// `response.model` (the backend's reported model).
    pub model: Option<String>,
    /// Raw answers, as reported.
    pub answers: Option<Value>,
    /// D24: the answers after calibration (the ones the signals read);
    /// absent without a calibration file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answers_calibrated: Option<Value>,
    /// D24: which calibration was applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calibration: Option<calibration::Applied>,
    /// Declared signals.
    pub signals: Option<BTreeMap<String, f64>>,
    /// Tier name (`T1`..`T6`) when answers were usable.
    pub tier: Option<&'static str>,
    /// Tier predicate text (with the thresholds in force).
    pub tier_rule: Option<String>,
    /// Verdict (`ask` on any failure).
    pub verdict: Verdict,
    /// What enforce mode emits for this verdict (`null` = nothing).
    pub would_emit: Option<Verdict>,
    /// Wall time of the whole judge step.
    pub latency_ms: f64,
    /// Token usage.
    pub usage: Option<Usage>,
    /// `x-typesafe-request-id`.
    pub request_id: Option<String>,
    /// HTTP attempts.
    pub attempts: u32,
    /// Where the key came from (never the key).
    pub key_source: Option<String>,
    /// Failure (D15), redacted.
    pub error: Option<String>,
}

impl JudgeRecord {
    /// The CARE-level decision this record implies.
    pub fn decision(&self) -> Final {
        match self.verdict {
            Verdict::Allow => Final::Allow,
            Verdict::Ask => Final::Ask,
            Verdict::Deny => Final::Deny,
        }
    }
}

/// The proposed action Jev judges.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// A CARE-scored Bash command: `tool: bash`, `args: <command>`.
    Shell(String),
    /// D21: a call CARE cannot score, rendered in the POC's `Name(json)`
    /// form (`tool: <Name>`, `args: <json.dumps(input, sort_keys=True)>`).
    Tool {
        /// `tool_name` verbatim.
        name: String,
        /// `tool_input` verbatim.
        input: Value,
    },
}

/// Build the state for a Bash command from a context: `tool: bash`,
/// `args: <command>` (ShellRisk / smoke-gate mapping).
pub fn build_state(command: &str, ctx: &Context) -> state::State {
    build_state_with(command, ctx, &ContextLimits::default())
}

/// [`build_state`] under `jev.context` limits.
pub fn build_state_with(command: &str, ctx: &Context, limits: &ContextLimits) -> state::State {
    state::state_from_shell_command_with(
        command,
        &ctx.user_request,
        &ctx.prior_actions,
        &[],
        ctx.level,
        limits,
    )
}

/// Build the state for any [`Action`]; [`Action::Shell`] is exactly
/// [`build_state_with`].
pub fn build_action_state(action: &Action, ctx: &Context, limits: &ContextLimits) -> state::State {
    match action {
        Action::Shell(command) => build_state_with(command, ctx, limits),
        Action::Tool { name, input } => state::state_from_tool_call_with(
            name,
            input,
            &ctx.user_request,
            &ctx.prior_actions,
            ctx.level,
            limits,
        ),
    }
}

/// The rubric a judge call uses: `jev.rubric_file` when it loaded, else the
/// embedded one, with the a6 gate set to `jev.thresholds.unknown_f5_gate`
/// (identity-neutral: `when` is not part of the rubric hash or the wire
/// questions).
pub fn effective_rubric(t: &JevTunables) -> Result<Cow<'_, Rubric>, String> {
    let base: &Rubric = match &t.rubric {
        Some(r) => r,
        None => rubric::rubric()?,
    };
    let gate = t.thresholds.unknown_f5_gate;
    match base.axis(A6).and_then(|a| a.when.as_ref()) {
        Some(w) if w.over != gate => {
            let mut r = base.clone();
            if let Some(w) = r
                .axes
                .iter_mut()
                .find(|a| a.id == A6)
                .and_then(|a| a.when.as_mut())
            {
                w.over = gate;
            }
            Ok(Cow::Owned(r))
        }
        _ => Ok(Cow::Borrowed(base)),
    }
}

/// The destination-class axis whose `when` gate `unknown_f5_gate` sets.
pub const A6: &str = "a6_destination_class";

/// The request body: `{"state", "model", "questions"}`.
pub fn request_body(state_text: &str, model: &str, questions: J) -> String {
    compact(&J::Obj(vec![
        ("state".into(), J::s(state_text)),
        ("model".into(), J::s(model)),
        ("questions".into(), questions),
    ]))
}

fn would_emit(v: Verdict, decide_all: bool) -> Option<Verdict> {
    match v {
        Verdict::Allow if !decide_all => None,
        other => Some(other),
    }
}

/// Judge one Bash command.
pub fn judge(
    command: &str,
    src: &ContextSource,
    s: &Settings,
    key: &Result<(Secret, KeySource), String>,
) -> JudgeRecord {
    judge_action(&Action::Shell(command.to_string()), src, s, key)
}

/// An empty record for a state about to be judged.
pub fn new_record(
    ctx: Context,
    state_text: String,
    state_hash: String,
    s: &Settings,
    key: &Result<(Secret, KeySource), String>,
) -> JudgeRecord {
    JudgeRecord {
        backend: "jev",
        backend_host: client::host_of(&s.transport.base_url),
        expected_model: s.expected_model.clone(),
        level: ctx.level,
        context: ctx,
        questions_sent: Vec::new(),
        state: state_text,
        state_hash,
        rubric_hash: String::new(),
        model: None,
        answers: None,
        answers_calibrated: None,
        calibration: None,
        signals: None,
        tier: None,
        tier_rule: None,
        verdict: Verdict::Ask,
        would_emit: None,
        latency_ms: 0.0,
        usage: None,
        request_id: None,
        attempts: 0,
        key_source: match key {
            Ok((_, src)) => Some(src.to_string()),
            Err(_) if !s.api_key_required => Some("none (judge.api_key_required = false)".into()),
            Err(_) => None,
        },
        error: None,
    }
}

/// The key to send: the resolved one, none when not required (D23), or the
/// resolution error.
pub fn key_to_send<'k>(
    key: &'k Result<(Secret, KeySource), String>,
    s: &Settings,
) -> Result<Option<&'k Secret>, String> {
    match key {
        Ok((k, _)) => Ok(Some(k)),
        Err(_) if !s.api_key_required => Ok(None),
        Err(e) => Err(e.clone()),
    }
}

/// Judge one proposed action (a Bash command, or a D21 unscorable call).
pub fn judge_action(
    action: &Action,
    src: &ContextSource,
    s: &Settings,
    key: &Result<(Secret, KeySource), String>,
) -> JudgeRecord {
    let t0 = Instant::now();
    let limits = &s.tuning.context;
    let ctx = transcript::build_with(src, limits);
    let st = build_action_state(action, &ctx, limits);
    let rec = new_record(ctx, st.render(), st.state_hash(), s, key);
    query(rec, s, key, None, t0)
}

/// D25: judge an already-rendered state (a logged `judge.state`) at its
/// level, exactly as [`judge_action`] does after building a state.
pub fn judge_state(
    state_text: &str,
    state_hash: &str,
    ctx: Context,
    s: &Settings,
    key: &Result<(Secret, KeySource), String>,
) -> JudgeRecord {
    let t0 = Instant::now();
    let rec = new_record(ctx, state_text.into(), state_hash.into(), s, key);
    query(rec, s, key, None, t0)
}

/// D25: evaluate logged answers (reported by `model`) for a logged state
/// under these settings, without any network call.
pub fn judge_logged_answers(
    state_text: &str,
    state_hash: &str,
    ctx: Context,
    model: &str,
    answers: &Value,
    s: &Settings,
) -> JudgeRecord {
    let t0 = Instant::now();
    let none: Result<(Secret, KeySource), String> = Err(String::new());
    let mut rec = new_record(ctx, state_text.into(), state_hash.into(), s, &none);
    rec.key_source = None;
    query(
        rec,
        s,
        &none,
        Some((model.to_string(), answers.clone())),
        t0,
    )
}

/// Send the record's state (or take `logged` answers instead), then
/// [`evaluate`]; failures ask (D15).
fn query(
    mut rec: JudgeRecord,
    s: &Settings,
    key: &Result<(Secret, KeySource), String>,
    logged: Option<(String, Value)>,
    t0: Instant,
) -> JudgeRecord {
    let result = (|| -> Result<(), String> {
        let rubric = effective_rubric(&s.tuning)?;
        let rubric: &Rubric = &rubric;
        rec.rubric_hash = rubric.hash.clone();
        let caps = rec.level.capabilities();
        rec.questions_sent = rubric.axes_at(caps).map(|a| a.id.clone()).collect();
        // Typed answers keep the wire order of choice labels (argmax ties
        // go to the first label); logged answers (a JSON object) come back
        // in label order.
        let (model, answers, answers_raw) = match logged {
            Some((model, raw)) => {
                let answers: Answers = serde_json::from_value(raw.clone())
                    .map_err(|e| format!("unparseable logged answers: {e}"))?;
                (model, answers, raw)
            }
            None => {
                let secret = key_to_send(key, s)?;
                let body = request_body(&rec.state, &s.model, rubric.questions_json(caps));
                let reply = client::post(&s.transport, secret, &body).map_err(|f| {
                    rec.attempts = f.attempts;
                    rec.request_id = f.request_id.clone();
                    f.error
                })?;
                rec.attempts = reply.attempts;
                rec.request_id = reply.request_id.clone();
                rec.usage = reply.response.usage;
                (
                    reply.response.model,
                    reply.response.answers,
                    reply.answers_raw,
                )
            }
        };
        evaluate(&mut rec, rubric, caps, &model, answers, answers_raw, s)
    })();
    if let Err(e) = result {
        rec.verdict = Verdict::Ask;
        rec.error = Some(client::redact(&e, key.as_ref().ok().map(|(k, _)| k)));
    }
    rec.would_emit = would_emit(rec.verdict, s.decide_all);
    rec.latency_ms = (t0.elapsed().as_secs_f64() * 10_000.0).round() / 10.0;
    rec
}

/// Answers -> verdict: the model check (D23), completeness (D15),
/// calibration (D24), signals, tier and verdict (D14). Fills `rec`; an
/// `Err` means D15 ask. Shared by the hook and `cancelli eval` (D25).
pub fn evaluate(
    rec: &mut JudgeRecord,
    rubric: &Rubric,
    caps: &[&str],
    model: &str,
    answers: Answers,
    answers_raw: Value,
    s: &Settings,
) -> Result<(), String> {
    rec.model = Some(model.to_string());
    rec.answers = Some(answers_raw);
    if model != s.expected_model {
        return Err(format!(
            "response.model {model:?} != expected_model {:?}",
            s.expected_model
        ));
    }
    decide::check_complete(rubric, caps, &answers)?;
    let answers = match &s.calibration {
        CalibrationState::None => answers,
        CalibrationState::Invalid { path, error } => {
            return Err(format!(
                "calibration_file {} refused ({error}); not using uncalibrated answers",
                path.display()
            ));
        }
        CalibrationState::Loaded(c) => {
            c.check(&rubric.hash, model)?;
            let (cal, axes) = c.apply(&answers)?;
            rec.answers_calibrated = serde_json::to_value(&cal).ok();
            rec.calibration = Some(c.applied(axes));
            cal
        }
    };
    let sig = decide::signals(rubric, &answers, caps);
    let unavailable: Vec<decide::TierId> = decide::unavailable_tiers(rubric)
        .into_iter()
        .map(|(t, _)| t)
        .collect();
    let t = decide::tier_with(&sig, &s.tuning, &unavailable);
    rec.signals = Some(sig);
    rec.tier = Some(t.name);
    rec.tier_rule = Some(t.rule);
    rec.verdict = t.verdict;
    Ok(())
}

/// The Jev backend behind the [`Adjudicator`] trait.
pub struct JevAdjudicator {
    /// Settings.
    pub settings: Settings,
    /// Resolved key (or why there is none).
    pub key: Result<(Secret, KeySource), String>,
    /// Transcript/context source for this hook call.
    pub source: ContextSource,
}

impl Adjudicator for JevAdjudicator {
    fn name(&self) -> &str {
        "jev"
    }
    fn failure_decision(&self) -> Final {
        Final::Ask
    }
    fn adjudicate(&self, input: &JudgeInput) -> Adjudication {
        Adjudication::Jev(Box::new(judge_action(
            &input.action,
            &self.source,
            &self.settings,
            &self.key,
        )))
    }
}

/// Backstop for the worker-thread timeout (FIX-008): the budget plus room
/// for reading the transcript.
pub fn backstop(budget: Duration) -> Duration {
    budget + Duration::from_millis(1500)
}
