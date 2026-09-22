//! L4 — provenance-weighted pattern rules (s_pat), port of
//! `PatternDetector.detect` (pattern.py:239-272).

use serde::Serialize;

use crate::canon::View;
use crate::pyre::py_round;
use crate::rules::{RuleBank, Tier};
use crate::tunables::CareTunables;

/// One fired rule.
#[derive(Debug, Clone, Serialize)]
pub struct FiredRule {
    /// Rule ID.
    pub id: String,
    /// Provenance tier.
    pub tier: Tier,
    /// Confidence.
    pub conf: f64,
    /// Provenance weight π(tier).
    pub pi: f64,
    /// Failure family.
    pub family: String,
    /// π·conf rounded to 3 dp (reference `effective_score`).
    pub effective: f64,
    /// Description.
    pub description: String,
    /// Index of the first view the rule matched.
    pub view: usize,
}

/// L4 result.
#[derive(Debug, Clone, Serialize)]
pub struct PatternResult {
    /// s_pat = max π·conf (unrounded).
    pub score: f64,
    /// Fired rules in bank order.
    pub fired: Vec<FiredRule>,
}

/// Match every rule against every view (FIX-006: views replace the
/// reference's single marker-augmented string).
pub fn detect(bank: &RuleBank, views: &[View]) -> PatternResult {
    detect_with(bank, views, &CareTunables::default())
}

/// [`detect`] with tunables: provenance weights π (`care.provenance`) and
/// per-rule overrides (`care.rules."SE-P-NNN"`). A disabled rule is never
/// matched; an overridden confidence is the one reported in `conf` and so
/// also the one `p_rule` uses.
pub fn detect_with(bank: &RuleBank, views: &[View], t: &CareTunables) -> PatternResult {
    let mut best = 0.0_f64;
    let mut fired = Vec::new();
    for r in &bank.rules {
        if !t.rule_enabled(&r.id) {
            continue;
        }
        let Some(view) = views.iter().position(|v| r.pattern.is_match(&v.text)) else {
            continue;
        };
        let pi = t.provenance.get(r.tier);
        let conf = t.rule_confidence(&r.id, r.confidence);
        let eff = pi * conf;
        fired.push(FiredRule {
            id: r.id.clone(),
            tier: r.tier,
            conf,
            pi,
            family: r.family.clone(),
            effective: py_round(eff, 3),
            description: r.description.clone(),
            view,
        });
        if eff > best {
            best = eff;
        }
    }
    PatternResult { score: best, fired }
}
