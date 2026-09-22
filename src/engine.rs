//! CARE pipeline orchestration: canonicalization → L1–L4 → L5 → Resolution.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::canon::{self, View};
use crate::fixes::Tags;
use crate::jev::Action;
use crate::path::{self, PathResult};
use crate::pattern::{self, FiredRule};
use crate::policy::{self, Mode, Provisional, Verdict};
use crate::pyre::py_round;
use crate::resolution::{
    self, Adjudicator, Final, JudgeInput, JudgeOutcome, JudgePrompt, SemAtom, StubAdjudicator,
};
use crate::rules;
use crate::semantic::{self, RiskClass};
use crate::structure::{self, Structure};
use crate::tunables::CareTunables;

/// Per-call options.
#[derive(Clone)]
pub struct Options {
    /// Configured operating mode (decides `final`).
    pub mode: Mode,
    /// Home directory for `~` expansion in L3.
    pub home: String,
    /// WARN-band judge.
    pub adjudicator: Arc<dyn Adjudicator>,
    /// Judge timeout (FIX-008).
    pub judge_timeout: Duration,
    /// CARE tunables (D18); the default reproduces the built-in constants.
    pub care: CareTunables,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            mode: Mode::Balanced,
            home: std::env::var("HOME").unwrap_or_default(),
            adjudicator: Arc::new(StubAdjudicator),
            judge_timeout: Duration::from_millis(2000),
            care: CareTunables::default(),
        }
    }
}

/// One L2 atom classification.
#[derive(Debug, Clone, Serialize)]
pub struct AtomClass {
    /// Atom text (truncated to 120 chars as in the reference trace).
    pub atom: String,
    /// View index.
    pub view: usize,
    /// Class.
    pub class: RiskClass,
    /// Score.
    pub score: f64,
    /// Reason.
    pub reason: String,
}

/// L1 evidence.
#[derive(Debug, Clone, Serialize)]
pub struct L1 {
    /// δ_struct (max over views).
    pub score: f64,
    /// Per-view structure.
    pub views: Vec<Structure>,
}

/// L2 evidence.
#[derive(Debug, Clone, Serialize)]
pub struct L2 {
    /// s_sem (max over atoms).
    pub score: f64,
    /// Class of the maximal atom.
    pub max_class: RiskClass,
    /// Every atom.
    pub atoms: Vec<AtomClass>,
}

/// L3 evidence.
#[derive(Debug, Clone, Serialize)]
pub struct L3 {
    /// s_path (max over views).
    pub score: f64,
    /// Reason of the maximal view.
    pub reason: String,
    /// Per-view results.
    pub views: Vec<PathResult>,
}

/// L4 evidence.
#[derive(Debug, Clone, Serialize)]
pub struct L4 {
    /// s_pat.
    pub score: f64,
    /// Fired rule IDs in bank order.
    pub matches: Vec<String>,
}

/// Layer evidence.
#[derive(Debug, Clone, Serialize)]
pub struct Layers {
    /// L1 structure.
    #[serde(rename = "L1")]
    pub l1: L1,
    /// L2 semantic.
    #[serde(rename = "L2")]
    pub l2: L2,
    /// L3 path.
    #[serde(rename = "L3")]
    pub l3: L3,
    /// L4 pattern.
    #[serde(rename = "L4")]
    pub l4: L4,
}

/// Rounded per-layer scores (reference `details.scoring`).
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub struct Scores {
    /// s_sem.
    pub sem: f64,
    /// s_path.
    pub path: f64,
    /// s_pat.
    pub pat: f64,
    /// δ_struct.
    pub r#struct: f64,
}

/// Full analysis of one Bash command.
#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    /// Raw command.
    pub command: String,
    /// Canonicalization views.
    pub views: Vec<View>,
    /// What the reference's `normalize` would have produced (debug only;
    /// present when it differs from the raw command).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_normalized: Option<String>,
    /// Per-layer evidence.
    pub layers: Layers,
    /// Fired L4 rules.
    pub fired_rules: Vec<FiredRule>,
    /// Layers with a non-zero score.
    pub triggered_layers: Vec<&'static str>,
    /// Rounded layer scores.
    pub scores: Scores,
    /// Aggregate score (Eq. 6), rounded to 4 dp.
    pub aggregate: f64,
    /// Provisional verdicts under every mode.
    pub provisional: Provisional,
    /// Configured mode.
    pub mode: Mode,
    /// Paper skip predicate (evaluated regardless of verdict).
    pub skip_predicate: Option<String>,
    /// What the reference's skip predicate would say (debug/parity).
    pub skip_predicate_reference: Option<String>,
    /// WARN in the configured mode and no skip predicate fired.
    pub would_adjudicate: bool,
    /// Exact judge prompt when `would_adjudicate`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub judge_prompt: Option<JudgePrompt>,
    /// Judge outcome when `would_adjudicate`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub judge: Option<JudgeOutcome>,
    /// Final decision.
    pub r#final: Final,
    /// Activated FIX IDs.
    pub fixes_applied: Vec<&'static str>,
    /// Activated EXT IDs.
    pub ext_applied: Vec<&'static str>,
}

/// Engine error (only the embedded rule bank can fail to load).
#[derive(Debug)]
pub struct EngineError(pub String);

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EngineError {}

/// Analyze one command.
pub fn analyze(cmd: &str, opts: &Options) -> Result<Analysis, EngineError> {
    let bank = rules::bank().map_err(|e| EngineError(e.to_string()))?;
    let mut tags = Tags::default();

    // Stage 1
    let views = canon::views(cmd, &mut tags);
    let refnorm = canon::reference_normalized(cmd);

    // L1
    let l1_views: Vec<Structure> = views
        .iter()
        .enumerate()
        .map(|(i, v)| structure::analyze_with(i, &v.text, &mut tags, &opts.care.structure))
        .collect();
    let struct_score = l1_views
        .iter()
        .map(|s| s.structure_risk)
        .fold(0.0, f64::max);

    // L2 — per atom over all views, max
    let mut atoms: Vec<AtomClass> = Vec::new();
    for (s, v) in l1_views.iter().zip(&views) {
        let list: Vec<String> = if s.atoms.is_empty() {
            vec![v.text.clone()]
        } else {
            s.atoms.clone()
        };
        for a in list {
            if atoms.iter().any(|x| x.atom == a) {
                continue;
            }
            let c = semantic::classify_with(&a, &mut tags, &opts.care.class_base);
            atoms.push(AtomClass {
                atom: a,
                view: s.view,
                class: c.class,
                score: c.score,
                reason: c.reason,
            });
        }
    }
    let mut sem_score = 0.0;
    let mut max_class = RiskClass::ReadOnly;
    for a in &atoms {
        if a.score > sem_score {
            sem_score = a.score;
            max_class = a.class;
        }
    }

    // L3 — per view, max
    let l3_views: Vec<PathResult> = views
        .iter()
        .enumerate()
        .map(|(i, v)| path::validate_with(i, &v.text, &opts.home, &mut tags, &opts.care.path))
        .collect();
    let mut path_score = 0.0;
    let mut path_reason = "paths_ok".to_string();
    for p in &l3_views {
        if p.score > path_score {
            path_score = p.score;
            path_reason = p.reason.clone();
        }
    }

    // L4
    let pat = pattern::detect_with(bank, &views, &opts.care);
    let pat_score = pat.score;

    // L5
    let mut triggered = Vec::new();
    if struct_score > 0.0 {
        triggered.push("L1_AST");
    }
    if sem_score > 0.0 {
        triggered.push("L2_Semantic");
    }
    if path_score > 0.0 {
        triggered.push("L3_Path");
    }
    if pat_score > 0.0 {
        triggered.push("L4_Pattern");
    }
    let final_score = policy::compose_with(
        &opts.care.weights,
        sem_score,
        path_score,
        pat_score,
        struct_score,
    );
    let provisional = Provisional::of_with(final_score, &opts.care.modes);
    let aggregate = py_round(final_score, 4);

    // Stage 3
    let sem_atoms: Vec<SemAtom> = atoms
        .iter()
        .map(|a| SemAtom {
            class: a.class,
            score: a.score,
        })
        .collect();
    let skip = resolution::skip_predicate(
        &pat.fired, path_score, &l3_views, &sem_atoms, bank, &opts.care, &mut tags,
    );
    let skip_ref =
        resolution::skip_predicate_reference(&pat.fired, path_score, &sem_atoms, bank, &opts.care);
    let rule_ids: Vec<String> = pat.fired.iter().map(|r| r.id.clone()).collect();
    let verdict = provisional.get(opts.mode);
    let would_adjudicate = verdict == Verdict::Warn && skip.is_none();
    let (judge_prompt, judge, fin) = match verdict {
        Verdict::Allow => (None, None, Final::Allow),
        Verdict::Deny => (None, None, Final::Deny),
        Verdict::Warn if skip.is_some() => (None, None, Final::Deny),
        Verdict::Warn => {
            let prompt = resolution::render_prompt(cmd, aggregate, &triggered, &rule_ids);
            let input = JudgeInput {
                action: Action::Shell(cmd.to_string()),
                prompt: Some(prompt.clone()),
            };
            let outcome = resolution::run_judge(
                Arc::clone(&opts.adjudicator),
                &input,
                opts.judge_timeout,
                &mut tags,
            );
            let d = outcome.decision;
            (Some(prompt), Some(outcome), d)
        }
    };

    Ok(Analysis {
        command: cmd.to_string(),
        reference_normalized: (refnorm != cmd).then_some(refnorm),
        views,
        layers: Layers {
            l1: L1 {
                score: struct_score,
                views: l1_views,
            },
            l2: L2 {
                score: sem_score,
                max_class,
                atoms,
            },
            l3: L3 {
                score: path_score,
                reason: path_reason,
                views: l3_views,
            },
            l4: L4 {
                score: pat_score,
                matches: rule_ids,
            },
        },
        fired_rules: pat.fired,
        triggered_layers: triggered,
        scores: Scores {
            sem: py_round(sem_score, 4),
            path: py_round(path_score, 4),
            pat: py_round(pat_score, 4),
            r#struct: py_round(struct_score, 4),
        },
        aggregate,
        provisional,
        mode: opts.mode,
        skip_predicate: skip,
        skip_predicate_reference: skip_ref,
        would_adjudicate,
        judge_prompt,
        judge,
        r#final: fin,
        fixes_applied: tags.fixes.into_iter().collect(),
        ext_applied: tags.exts.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> Options {
        Options {
            home: "/home/user".into(),
            ..Options::default()
        }
    }

    #[test]
    fn worked_examples() {
        let a = analyze("rsync -avz ./data user@host:/backup/", &opts()).unwrap();
        assert_eq!(a.aggregate, 0.345);
        assert_eq!(a.provisional.balanced, Verdict::Warn);
        assert_eq!(a.skip_predicate, None);
        assert!(a.would_adjudicate);
        assert_eq!(a.r#final, Final::Unadjudicated);
        assert!(a.judge_prompt.as_ref().unwrap().user.contains("SE-P-103"));

        let a = analyze("rm -rf node_modules", &opts()).unwrap();
        assert_eq!(a.aggregate, 0.27);
        assert_eq!(a.skip_predicate.as_deref(), Some("p_sem:DESTRUCTIVE"));
        assert_eq!(a.r#final, Final::Deny);

        let a = analyze("grep -rn 'TODO' src/", &opts()).unwrap();
        assert_eq!(a.r#final, Final::Allow);
        assert_eq!(a.aggregate, 0.0);
    }
}
