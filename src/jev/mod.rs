//! Jev (`jev-1.13.0`, TypeSafe AI's hosted "System One" API) as the WARN
//! adjudicator (D11–D17).
//!
//! Called for unresolved CARE WARNs and, since D21, for every tool call
//! CARE cannot score (an [`Action::Tool`], rendered in the POC's
//! `Name(json)` form) unless `jev.skip_tools` lists it.
//!
//! Pipeline for one unresolved CARE WARN: transcript -> [`transcript::Context`]
//! (level L2/L1/L0) -> [`state::State`] (the POC's render template, D16) ->
//! one `POST /v1/systemone` with the rubric's questions for that level ->
//! model check -> [`decide::signals`] -> [`decide::tier`] -> verdict (D14).
//! Every failure is `ask` plus an error (D15). The result is a
//! [`JudgeRecord`], logged in full in dry-run and enforce mode alike (D17).

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
use crate::tunables::{ContextLimits, JevTunables};
use client::{KeySource, PINNED_MODEL, Secret, Transport};
use decide::{Usage, Verdict};
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
    /// D13: a Jev `allow` emits `allow`.
    pub decide_all: bool,
    /// Jev tunables (D19), including the rubric in use.
    pub tuning: JevTunables,
}

/// The judge record (logged as `judge`; printed by `cancelli judge`).
#[derive(Debug, Clone, Serialize)]
pub struct JudgeRecord {
    /// Always `jev`.
    pub backend: &'static str,
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
    /// `response.model`.
    pub model: Option<String>,
    /// Raw answers.
    pub answers: Option<Value>,
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
    let mut rec = JudgeRecord {
        backend: "jev",
        level: ctx.level,
        context: ctx.clone(),
        questions_sent: Vec::new(),
        state: st.render(),
        state_hash: st.state_hash(),
        rubric_hash: String::new(),
        model: None,
        answers: None,
        signals: None,
        tier: None,
        tier_rule: None,
        verdict: Verdict::Ask,
        would_emit: None,
        latency_ms: 0.0,
        usage: None,
        request_id: None,
        attempts: 0,
        key_source: key.as_ref().ok().map(|(_, src)| src.to_string()),
        error: None,
    };
    let result = (|| -> Result<(), String> {
        let rubric = effective_rubric(&s.tuning)?;
        let rubric: &Rubric = &rubric;
        rec.rubric_hash = rubric.hash.clone();
        let caps = ctx.level.capabilities();
        rec.questions_sent = rubric.axes_at(caps).map(|a| a.id.clone()).collect();
        let (secret, _) = key.as_ref().map_err(Clone::clone)?;
        let body = request_body(&rec.state, &s.model, rubric.questions_json(caps));
        let reply = client::post(&s.transport, secret, &body).map_err(|f| {
            rec.attempts = f.attempts;
            rec.request_id = f.request_id.clone();
            f.error
        })?;
        rec.attempts = reply.attempts;
        rec.request_id = reply.request_id.clone();
        rec.model = Some(reply.response.model.clone());
        rec.usage = reply.response.usage;
        rec.answers = Some(reply.answers_raw.clone());
        if reply.response.model != PINNED_MODEL {
            return Err(format!(
                "response.model {:?} != pinned {PINNED_MODEL:?}",
                reply.response.model
            ));
        }
        decide::check_complete(rubric, caps, &reply.response.answers)?;
        let sig = decide::signals(rubric, &reply.response.answers, caps);
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
    })();
    if let Err(e) = result {
        rec.verdict = Verdict::Ask;
        rec.error = Some(client::redact(&e, key.as_ref().ok().map(|(k, _)| k)));
    }
    rec.would_emit = would_emit(rec.verdict, s.decide_all);
    rec.latency_ms = (t0.elapsed().as_secs_f64() * 10_000.0).round() / 10.0;
    rec
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
