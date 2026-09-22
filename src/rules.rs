//! The CARE L4 rule bank, loaded from the vendored
//! `data/rule_provenance.json` (reference `care/rules/rule_provenance.json`
//! at the pinned commit; identical to the in-code `PATTERN_RULES_SPEC`,
//! verified field-by-field and in order).

use std::sync::OnceLock;

use serde::Deserialize;

use crate::pyre::{PyRegex, PyRegexError};

/// Raw embedded artifact.
pub const RULES_JSON: &str = include_str!("../data/rule_provenance.json");

/// Provenance tier of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// MITRE ATT&CK.
    Mitre,
    /// GTFOBins.
    Gtfobins,
    /// Author-curated manual case.
    Manual,
}

impl Tier {
    /// Provenance weight π(tier) (paper App. A.4; `pattern.py`
    /// `PROVENANCE_TIER_WEIGHT`).
    pub fn weight(self) -> f64 {
        match self {
            Tier::Mitre => 1.00,
            Tier::Gtfobins => 0.85,
            Tier::Manual => 0.60,
        }
    }

    /// Lowercase name as used in the JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Mitre => "mitre",
            Tier::Gtfobins => "gtfobins",
            Tier::Manual => "manual",
        }
    }
}

#[derive(Debug, Deserialize)]
struct RuleRecord {
    rule_id: String,
    description: String,
    failure_family: String,
    mitre_techniques: Vec<String>,
    confidence: f64,
    provenance_tier: Tier,
    pattern_regex: String,
}

#[derive(Debug, Deserialize)]
struct Meta {
    version: String,
    date: String,
    total_rules: usize,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(rename = "_meta")]
    meta: Meta,
    rules: Vec<RuleRecord>,
}

/// A compiled L4 rule.
#[derive(Debug)]
pub struct Rule {
    /// `SE-P-NNN`.
    pub id: String,
    /// Short label.
    pub description: String,
    /// `F1`..`F7`.
    pub family: String,
    /// MITRE technique IDs.
    pub mitre: Vec<String>,
    /// Author-assigned confidence.
    pub confidence: f64,
    /// Provenance tier.
    pub tier: Tier,
    /// Source pattern (Python syntax).
    pub pattern_src: String,
    /// Compiled pattern (case-insensitive, as `re.IGNORECASE`).
    pub pattern: PyRegex,
}

/// The loaded rule bank.
#[derive(Debug)]
pub struct RuleBank {
    /// Rules in file order (the reference's evaluation order).
    pub rules: Vec<Rule>,
    /// `_meta.version` + `_meta.date`, logged as `rules_version`.
    pub version: String,
}

/// Errors loading the embedded bank.
#[derive(Debug)]
pub enum RuleLoadError {
    /// JSON did not parse.
    Json(String),
    /// A rule's regex did not compile.
    Regex(String, PyRegexError),
    /// `_meta.total_rules` disagrees with the rule list.
    Count(usize, usize),
}

impl std::fmt::Display for RuleLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleLoadError::Json(e) => write!(f, "rule JSON: {e}"),
            RuleLoadError::Regex(id, e) => write!(f, "rule {id}: {e}"),
            RuleLoadError::Count(a, b) => write!(f, "rule count {a} != meta {b}"),
        }
    }
}

impl std::error::Error for RuleLoadError {}

/// Parse and compile a rule-bank JSON document.
pub fn load(json: &str) -> Result<RuleBank, RuleLoadError> {
    let file: RuleFile =
        serde_json::from_str(json).map_err(|e| RuleLoadError::Json(e.to_string()))?;
    if file.rules.len() != file.meta.total_rules {
        return Err(RuleLoadError::Count(
            file.rules.len(),
            file.meta.total_rules,
        ));
    }
    let mut rules = Vec::with_capacity(file.rules.len());
    for r in file.rules {
        let pattern = PyRegex::new(&r.pattern_regex, true)
            .map_err(|e| RuleLoadError::Regex(r.rule_id.clone(), e))?;
        rules.push(Rule {
            id: r.rule_id,
            description: r.description,
            family: r.failure_family,
            mitre: r.mitre_techniques,
            confidence: r.confidence,
            tier: r.provenance_tier,
            pattern_src: r.pattern_regex,
            pattern,
        });
    }
    Ok(RuleBank {
        rules,
        version: format!("{}+{}", file.meta.version, file.meta.date),
    })
}

/// The embedded bank, compiled once per process.
pub fn bank() -> Result<&'static RuleBank, &'static RuleLoadError> {
    static BANK: OnceLock<Result<RuleBank, RuleLoadError>> = OnceLock::new();
    BANK.get_or_init(|| load(RULES_JSON)).as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_139_rules_compile() {
        let b = load(RULES_JSON).expect("bank loads");
        assert_eq!(b.rules.len(), 139);
        let mut counts = std::collections::BTreeMap::new();
        for r in &b.rules {
            *counts.entry(r.tier.as_str()).or_insert(0) += 1;
        }
        assert_eq!(counts["mitre"], 92);
        assert_eq!(counts["gtfobins"], 31);
        assert_eq!(counts["manual"], 16);
    }

    #[test]
    fn only_expected_rules_need_backtracking() {
        let b = load(RULES_JSON).unwrap();
        let fancy: Vec<&str> = b
            .rules
            .iter()
            .filter(|r| r.pattern.is_fancy())
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(fancy, vec!["SE-P-069", "SE-P-094", "SE-P-139"]);
    }

    #[test]
    fn provenance_weights() {
        assert_eq!(Tier::Mitre.weight(), 1.00);
        assert_eq!(Tier::Gtfobins.weight(), 0.85);
        assert_eq!(Tier::Manual.weight(), 0.60);
    }
}
