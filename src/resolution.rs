//! Stage 3 — Resolution: skip predicates (paper Eqs. 8–11), the judge prompt
//! (paper Prompt 1 = `care/resolution.py` template), the [`Adjudicator`]
//! trait with a stub (D7) and the Jev backend (D11, `crate::jev`), FIX-004
//! output parsing for text judges and the FIX-008 timeout.

use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use serde::Serialize;

use crate::fixes::Tags;
use crate::jev::JudgeRecord;
use crate::path::{Access, PathResult, PathTier};
use crate::pattern::FiredRule;
use crate::pyre::py_float_repr;
use crate::rules::{RuleBank, Tier};
use crate::semantic::RiskClass;

/// θ_rule (resolution.py:44; paper App. A.6).
pub const THETA_RULE: f64 = 0.80;
/// θ_sem (resolution.py:45).
pub const THETA_SEM: f64 = 0.70;

/// FIX-003: paper H_sem = {destructive, priv-escalate, exec-chaining,
/// persist-modify, network-exfil} mapped onto the L2 class enum. The repo
/// set additionally contains WRITE_SENSITIVE and RESOURCE_ABUSE and lacks
/// NETWORK_FETCH (whose lexicon score, 0.40, never reaches θ_sem anyway).
pub const H_SEM_PAPER: &[RiskClass] = &[
    RiskClass::Destructive,
    RiskClass::PrivilegeOrPermission,
    RiskClass::ExecutionChain,
    RiskClass::Persistence,
    RiskClass::NetworkFetch,
];

/// `L2_HIGH_RISK_CLASSES` of the reference (resolution.py:50-53).
pub const H_SEM_REPO: &[RiskClass] = &[
    RiskClass::WriteSensitive,
    RiskClass::ExecutionChain,
    RiskClass::PrivilegeOrPermission,
    RiskClass::Persistence,
    RiskClass::Destructive,
    RiskClass::ResourceAbuse,
];

/// Judge system prompt (verbatim `ESCALATE_SYSTEM`).
pub const JUDGE_SYSTEM: &str = include_str!("../data/judge_system.txt");
/// Judge user template (verbatim `ESCALATE_USER_TMPL`).
pub const JUDGE_USER_TEMPLATE: &str = include_str!("../data/judge_user.txt");

/// An L2 atom classification, as consumed by `p_sem`.
#[derive(Debug, Clone)]
pub struct SemAtom {
    /// Class.
    pub class: RiskClass,
    /// Score.
    pub score: f64,
}

fn p_rule_paper(fired: &[FiredRule]) -> Option<String> {
    fired
        .iter()
        .find(|m| matches!(m.tier, Tier::Mitre | Tier::Gtfobins) && m.pi * m.conf >= THETA_RULE)
        .map(|m| format!("p_rule:{}", m.id))
}

fn p_rule_repo(fired: &[FiredRule], bank: &RuleBank) -> Option<String> {
    for m in fired {
        if m.tier == Tier::Mitre && m.conf >= THETA_RULE {
            return Some(format!("p_rule:{}", m.id));
        }
        if let Some(r) = bank.rules.iter().find(|r| r.id == m.id)
            && !r.mitre.is_empty()
            && r.confidence >= THETA_RULE
        {
            return Some(format!("p_rule:{}", m.id));
        }
    }
    None
}

/// Paper `p_spath` (App. A.6): write-context access to a system/critical
/// tier, or any access to a secret-bearing path.
pub fn p_spath_paper(paths: &[PathResult]) -> bool {
    paths.iter().flat_map(|p| &p.hits).any(|h| match h.tier {
        PathTier::Secret => true,
        PathTier::Critical => h.secret_bearing || h.access == Access::Write,
        PathTier::SystemRoot => true,
        PathTier::SensitiveSystem => h.access == Access::Write,
        PathTier::Traversal => false,
    })
}

fn p_sem(atoms: &[SemAtom], set: &[RiskClass]) -> Option<String> {
    atoms
        .iter()
        .find(|a| set.contains(&a.class) && a.score >= THETA_SEM)
        .map(|a| format!("p_sem:{}", a.class.as_str()))
}

/// Evaluate `skip(c) = p_rule ∨ p_spath ∨ p_sem` (paper definitions) and
/// tag FIX-001..003 wherever a predicate's outcome differs from the repo's.
pub fn skip_predicate(
    fired: &[FiredRule],
    path_score: f64,
    paths: &[PathResult],
    atoms: &[SemAtom],
    bank: &RuleBank,
    tags: &mut Tags,
) -> Option<String> {
    let rule = p_rule_paper(fired);
    if rule != p_rule_repo(fired, bank) {
        tags.fix("FIX-001");
    }
    let spath = p_spath_paper(paths);
    if spath != (path_score > 0.0) {
        tags.fix("FIX-002");
    }
    let sem = p_sem(atoms, H_SEM_PAPER);
    if sem != p_sem(atoms, H_SEM_REPO) {
        tags.fix("FIX-003");
    }
    rule.or_else(|| spath.then(|| "p_spath".to_string()))
        .or(sem)
}

/// The reference's skip reason (for parity/debug output only).
pub fn skip_predicate_reference(
    fired: &[FiredRule],
    path_score: f64,
    atoms: &[SemAtom],
    bank: &RuleBank,
) -> Option<String> {
    p_rule_repo(fired, bank)
        .or_else(|| (path_score > 0.0).then(|| "p_spath".to_string()))
        .or_else(|| p_sem(atoms, H_SEM_REPO))
}

/// A rendered judge prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JudgePrompt {
    /// System message.
    pub system: String,
    /// User message.
    pub user: String,
}

/// Fill the user template exactly as `ESCALATE_USER_TMPL.format(...)`:
/// raw command, `repr(round(score, 4))`, comma-joined layer names and rule
/// IDs (or `none`). Single pass, so placeholder text inside the command is
/// never re-expanded.
pub fn render_prompt(
    raw_cmd: &str,
    score_rounded: f64,
    layers: &[&str],
    rules: &[String],
) -> JudgePrompt {
    let layers = if layers.is_empty() {
        "none".to_string()
    } else {
        layers.join(",")
    };
    let rules = if rules.is_empty() {
        "none".to_string()
    } else {
        rules.join(",")
    };
    let score = py_float_repr(score_rounded);
    let mut out = String::with_capacity(JUDGE_USER_TEMPLATE.len() + raw_cmd.len());
    let mut rest = JUDGE_USER_TEMPLATE;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let after = &rest[i..];
        let (val, len) = if after.starts_with("{cmd}") {
            (raw_cmd, 5)
        } else if after.starts_with("{score}") {
            (score.as_str(), 7)
        } else if after.starts_with("{layers}") {
            (layers.as_str(), 8)
        } else if after.starts_with("{rules}") {
            (rules.as_str(), 7)
        } else {
            ("{", 1)
        };
        out.push_str(val);
        rest = &after[len..];
    }
    out.push_str(rest);
    JudgePrompt {
        system: JUDGE_SYSTEM.to_string(),
        user: out,
    }
}

/// What a judge sees for one unresolved WARN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JudgeInput {
    /// The raw Bash command.
    pub command: String,
    /// CARE Prompt 1 (text judges).
    pub prompt: JudgePrompt,
}

/// What an adjudicator returned.
#[derive(Debug, Clone)]
pub enum Adjudication {
    /// No judge is configured (stub).
    Unadjudicated,
    /// Raw model text (text judges; FIX-004 parsing).
    Response(String),
    /// Transport or model error.
    Error(String),
    /// A Jev judgement (its own verdict, including failures -> ask).
    Jev(Box<JudgeRecord>),
}

/// A WARN-band judge (paper "J").
pub trait Adjudicator: Send + Sync {
    /// Backend name for logs.
    fn name(&self) -> &str;
    /// Whether calls may block (run on a worker thread under a timeout).
    fn blocking(&self) -> bool {
        true
    }
    /// Decision when the judge errors or times out: DENY for text judges
    /// (paper: fail closed), ASK for Jev (D15).
    fn failure_decision(&self) -> Final {
        Final::Deny
    }
    /// Adjudicate one WARN.
    fn adjudicate(&self, input: &JudgeInput) -> Adjudication;
}

/// D7 stub: never calls a model.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubAdjudicator;

impl Adjudicator for StubAdjudicator {
    fn name(&self) -> &str {
        "stub"
    }
    fn blocking(&self) -> bool {
        false
    }
    fn adjudicate(&self, _input: &JudgeInput) -> Adjudication {
        Adjudication::Unadjudicated
    }
}

/// Parsed judge output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeVerdict {
    /// First token SAFE.
    Safe,
    /// First token DANGEROUS.
    Dangerous,
    /// Anything else (fail closed).
    Unparseable,
}

/// FIX-004: paper `first_token().upper() in {SAFE, DANGEROUS}`; anything
/// else is unparseable and maps to DENY.
pub fn parse_judge_output(text: &str) -> JudgeVerdict {
    match text
        .split_whitespace()
        .next()
        .map(str::to_uppercase)
        .as_deref()
    {
        Some("SAFE") => JudgeVerdict::Safe,
        Some("DANGEROUS") => JudgeVerdict::Dangerous,
        _ => JudgeVerdict::Unparseable,
    }
}

/// Reference parsing (resolution.py:204-207): `True` = DENY.
pub fn reference_judge_denies(text: &str) -> bool {
    let ans = text.trim().to_uppercase();
    ans.contains("DANGEROUS") || ans.contains("UNSAFE")
}

/// Final decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Final {
    /// Allowed.
    Allow,
    /// Denied.
    Deny,
    /// Ask the user (Jev T3–T5, or Jev failed; D14/D15).
    Ask,
    /// WARN without skip, and the judge is a stub.
    Unadjudicated,
}

impl Final {
    /// Name as logged.
    pub fn as_str(self) -> &'static str {
        match self {
            Final::Allow => "allow",
            Final::Deny => "deny",
            Final::Ask => "ask",
            Final::Unadjudicated => "unadjudicated",
        }
    }
}

/// Outcome of a judge call. For Jev, the [`JudgeRecord`] fields are
/// flattened in (and carry `backend`/`error` themselves).
#[derive(Debug, Clone, Serialize)]
pub struct JudgeOutcome {
    /// Backend name (text judges and the stub).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Final decision it implies.
    pub decision: Final,
    /// Raw response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    /// Parsed verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<JudgeVerdict>,
    /// Error / timeout description (text judges, and the FIX-008 backstop).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The Jev record.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub jev: Option<Box<JudgeRecord>>,
}

impl JudgeOutcome {
    /// The error, wherever it is recorded.
    pub fn error_message(&self) -> Option<&str> {
        self.error
            .as_deref()
            .or_else(|| self.jev.as_ref().and_then(|j| j.error.as_deref()))
    }
}

/// Call the adjudicator; blocking backends run on a worker thread bounded by
/// `timeout` (FIX-008: the reference sets no timeout). Errors and timeouts
/// take the backend's [`Adjudicator::failure_decision`]: DENY (fail closed,
/// as in the paper) for text judges, ASK for Jev (D15).
pub fn run_judge(
    adj: Arc<dyn Adjudicator>,
    input: &JudgeInput,
    timeout: Duration,
    tags: &mut Tags,
) -> JudgeOutcome {
    let backend = Some(adj.name().to_string());
    let on_failure = adj.failure_decision();
    let result = if adj.blocking() {
        let (tx, rx) = mpsc::channel();
        let p = input.clone();
        let a = Arc::clone(&adj);
        let spawned = std::thread::Builder::new()
            .name("cancelli-judge".into())
            .spawn(move || {
                let _ = tx.send(a.adjudicate(&p));
            });
        match spawned {
            Err(e) => Adjudication::Error(format!("spawn: {e}")),
            Ok(_) => match rx.recv_timeout(timeout) {
                Ok(a) => a,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    tags.fix("FIX-008");
                    Adjudication::Error(format!("timeout after {} ms", timeout.as_millis()))
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    Adjudication::Error("judge thread ended without a result".into())
                }
            },
        }
    } else {
        adj.adjudicate(input)
    };
    match result {
        Adjudication::Unadjudicated => JudgeOutcome {
            backend,
            decision: Final::Unadjudicated,
            raw: None,
            verdict: None,
            error: None,
            jev: None,
        },
        Adjudication::Error(e) => JudgeOutcome {
            backend,
            decision: on_failure,
            raw: None,
            verdict: None,
            error: Some(e),
            jev: None,
        },
        Adjudication::Jev(rec) => JudgeOutcome {
            backend: None,
            decision: rec.decision(),
            raw: None,
            verdict: None,
            error: None,
            jev: Some(rec),
        },
        Adjudication::Response(text) => {
            let verdict = parse_judge_output(&text);
            let decision = if verdict == JudgeVerdict::Safe {
                Final::Allow
            } else {
                Final::Deny
            };
            if (decision == Final::Deny) != reference_judge_denies(&text) {
                tags.fix("FIX-004");
            }
            JudgeOutcome {
                backend,
                decision,
                raw: Some(text),
                verdict: Some(verdict),
                error: None,
                jev: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(cmd: &str) -> JudgeInput {
        JudgeInput {
            command: cmd.into(),
            prompt: render_prompt(cmd, 0.2, &[], &[]),
        }
    }

    #[test]
    fn prompt_matches_reference_format() {
        let p = render_prompt(
            "rsync -avz ./data user@host:/backup/",
            0.345,
            &["L2_Semantic", "L4_Pattern"],
            &["SE-P-103".to_string()],
        );
        assert_eq!(
            p.user,
            "Command:\n```\nrsync -avz ./data user@host:/backup/\n```\n\n\
             Static analyzer flagged this as borderline (WARN).\n\
             \x20 composite risk score: 0.345\n\
             \x20 triggered layers:    L2_Semantic,L4_Pattern\n\
             \x20 fired rule IDs:       SE-P-103\n\n\
             If you cannot confidently classify this as a routine, reversible benign action, reply DANGEROUS.\n\n\
             Reply with exactly one word: SAFE or DANGEROUS."
        );
        assert!(p.system.starts_with("You are a strict security analyst"));
        assert!(p.system.ends_with("Otherwise reply DANGEROUS."));
        let q = render_prompt("echo {score}", 0.2, &[], &[]);
        assert!(q.user.contains("echo {score}"));
        assert!(q.user.contains("triggered layers:    none"));
    }

    #[test]
    fn judge_parsing_fix_004() {
        assert_eq!(parse_judge_output("SAFE"), JudgeVerdict::Safe);
        assert_eq!(parse_judge_output("  dangerous\n"), JudgeVerdict::Dangerous);
        assert_eq!(parse_judge_output("<think>"), JudgeVerdict::Unparseable);
        assert_eq!(parse_judge_output(""), JudgeVerdict::Unparseable);
        assert_eq!(parse_judge_output("SAFE."), JudgeVerdict::Unparseable);
        // reference: garbage -> ALLOW
        assert!(!reference_judge_denies("<think>"));
        let mut t = Tags::default();
        struct Garbage;
        impl Adjudicator for Garbage {
            fn name(&self) -> &str {
                "garbage"
            }
            fn adjudicate(&self, _: &JudgeInput) -> Adjudication {
                Adjudication::Response("<think>".into())
            }
        }
        let o = run_judge(
            Arc::new(Garbage),
            &input("x"),
            Duration::from_secs(5),
            &mut t,
        );
        assert_eq!(o.decision, Final::Deny);
        assert!(t.fixes.contains("FIX-004"));
    }

    #[test]
    fn judge_timeout_fails_closed_fix_008() {
        struct Slow;
        impl Adjudicator for Slow {
            fn name(&self) -> &str {
                "slow"
            }
            fn adjudicate(&self, _: &JudgeInput) -> Adjudication {
                std::thread::sleep(Duration::from_secs(2));
                Adjudication::Response("SAFE".into())
            }
        }
        let mut t = Tags::default();
        let start = std::time::Instant::now();
        let o = run_judge(
            Arc::new(Slow),
            &input("x"),
            Duration::from_millis(50),
            &mut t,
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(o.decision, Final::Deny);
        assert!(o.error.unwrap().contains("timeout"));
        assert!(t.fixes.contains("FIX-008"));
    }

    #[test]
    fn stub_is_unadjudicated() {
        let mut t = Tags::default();
        let o = run_judge(
            Arc::new(StubAdjudicator),
            &input("x"),
            Duration::from_millis(1),
            &mut t,
        );
        assert_eq!(o.decision, Final::Unadjudicated);
        assert!(t.fixes.is_empty());
    }
}
