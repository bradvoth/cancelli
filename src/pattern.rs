//! L4 — provenance-weighted pattern rules (s_pat), port of
//! `PatternDetector.detect` (pattern.py:239-272).

use serde::Serialize;

use crate::canon::View;
use crate::pyre::py_round;
use crate::rules::{RuleBank, Tier};

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
    let mut best = 0.0_f64;
    let mut fired = Vec::new();
    for r in &bank.rules {
        let Some(view) = views.iter().position(|v| r.pattern.is_match(&v.text)) else {
            continue;
        };
        let pi = r.tier.weight();
        let eff = pi * r.confidence;
        fired.push(FiredRule {
            id: r.id.clone(),
            tier: r.tier,
            conf: r.confidence,
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
