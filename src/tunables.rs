//! Tunables (D18–D20): the numeric knobs of CARE (`[care]`) and of the Jev
//! adjudicator (`[jev]`) in `config.toml`, plus the decision-relevant
//! backend identity of `[judge]` (D23 `expected_model`, D24
//! `calibration_file`).
//!
//! * [`Tunables::default`] reproduces the built-in constants exactly, so an
//!   empty or absent config changes nothing (the parity and Jev fidelity
//!   suites run on it; a golden snapshot pins it).
//! * [`load`] reads the `care`/`jev` tables of the config file and validates
//!   every value on its own: an invalid value falls back to *its* default
//!   with an `error` diagnostic naming the key; unknown keys are warnings.
//!   Nothing here can fail the hook (fail open).
//! * [`Tunables::canonical`] is the flat, dotted-key view of the effective
//!   values. It drives `config_fingerprint` (a short hash of its canonical
//!   JSON), `overrides[]` (keys whose value differs from the default),
//!   `cancelli config` and `cancelli config --init`.
//!
//! Lexicons, path catalogs and regexes stay embedded (D18).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use toml::{Table, Value as TV};

use crate::config::{Diagnostic, Env, expand_tilde};
use crate::jev::A6;
use crate::jev::calibration::{self, Calibration};
use crate::jev::client::DEFAULT_EXPECTED_MODEL;
use crate::jev::decide::{TIERS, TierId, Verdict as JevVerdict, unavailable_tiers};
use crate::jev::rubric::{self, EXPECTED_RUBRIC_HASH, Rubric};
use crate::jev::state::{Level, MAX_FIELD_CHARS, MAX_PRIOR_CHARS};
use crate::policy::{self, Mode};
use crate::resolution::{H_SEM_PAPER, THETA_RULE, THETA_SEM};
use crate::rules::{self, Tier as RuleTier};
use crate::semantic::RiskClass;

// ------------------------------------------------------------------ CARE --

/// L5 layer weights (paper Eq. 6).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Weights {
    /// w_sem (L2).
    pub sem: f64,
    /// w_path (L3).
    pub path: f64,
    /// w_pat (L4).
    pub pat: f64,
    /// w_struct (L1).
    pub r#struct: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Weights {
            sem: policy::W_SEM,
            path: policy::W_PATH,
            pat: policy::W_PAT,
            r#struct: policy::W_STRUCT,
        }
    }
}

/// One mode's thresholds (paper Eq. 7).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Band {
    /// ALLOW below.
    pub tau_low: f64,
    /// DENY at or above.
    pub tau_high: f64,
}

impl Band {
    /// The built-in band of a mode.
    pub fn of(m: Mode) -> Band {
        let (tau_low, tau_high) = m.thresholds();
        Band { tau_low, tau_high }
    }
}

/// Per-mode thresholds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Modes {
    /// strict.
    pub strict: Band,
    /// balanced.
    pub balanced: Band,
    /// auto.
    pub auto: Band,
}

/// D27: the default balanced band (wide WARN). Only read-only heads fall
/// below τ_low; τ_high keeps DENY for a high-precision core. Paper: 0.15/0.35.
pub const WIDE_WARN_BALANCED: Band = Band {
    tau_low: 0.04,
    tau_high: 0.55,
};

impl Default for Modes {
    fn default() -> Self {
        Modes {
            balanced: WIDE_WARN_BALANCED,
            ..Modes::paper()
        }
    }
}

impl Modes {
    /// The paper's bands (Eq. 7) for every mode.
    pub fn paper() -> Self {
        Modes {
            strict: Band::of(Mode::Strict),
            balanced: Band::of(Mode::Balanced),
            auto: Band::of(Mode::Auto),
        }
    }

    /// The band of a mode.
    pub fn get(&self, m: Mode) -> Band {
        match m {
            Mode::Strict => self.strict,
            Mode::Balanced => self.balanced,
            Mode::Auto => self.auto,
        }
    }

    fn get_mut(&mut self, m: Mode) -> &mut Band {
        match m {
            Mode::Strict => &mut self.strict,
            Mode::Balanced => &mut self.balanced,
            Mode::Auto => &mut self.auto,
        }
    }
}

/// Provenance weights π per rule tier (paper App. A.4).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Provenance {
    /// MITRE ATT&CK.
    pub mitre: f64,
    /// GTFOBins.
    pub gtfobins: f64,
    /// Manual.
    pub manual: f64,
}

impl Default for Provenance {
    fn default() -> Self {
        Provenance {
            mitre: RuleTier::Mitre.weight(),
            gtfobins: RuleTier::Gtfobins.weight(),
            manual: RuleTier::Manual.weight(),
        }
    }
}

impl Provenance {
    /// π(tier).
    pub fn get(&self, t: RuleTier) -> f64 {
        match t {
            RuleTier::Mitre => self.mitre,
            RuleTier::Gtfobins => self.gtfobins,
            RuleTier::Manual => self.manual,
        }
    }
}

/// L2 class base scores, indexed like [`RiskClass::ALL`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClassBase(pub [f64; 10]);

impl Default for ClassBase {
    fn default() -> Self {
        ClassBase(RiskClass::ALL.map(RiskClass::base))
    }
}

impl ClassBase {
    /// Base score of a class.
    pub fn get(&self, c: RiskClass) -> f64 {
        self.0[c.index()]
    }
}

/// L1 structure ladder values (paper App. A.1; first match wins).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StructurePenalties {
    /// A pipeline ending in an interpreter.
    pub pipe_to_exec: f64,
    /// `eval` / `source` / `.` as a command head.
    pub eval: f64,
    /// Command substitution nested ≥ 2 deep.
    pub nested_substitution: f64,
    /// Any `$()` / backticks.
    pub command_substitution: f64,
    /// A pipeline.
    pub pipe: f64,
}

impl Default for StructurePenalties {
    fn default() -> Self {
        // care/structure.py scoring ladder.
        StructurePenalties {
            pipe_to_exec: 1.0,
            eval: 0.9,
            nested_substitution: 0.6,
            command_substitution: 0.30,
            pipe: 0.05,
        }
    }
}

/// L3 path tier scores.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PathScores {
    /// Destructive head on a system-root target (early return).
    pub system_root: f64,
    /// Critical path pattern (early return).
    pub critical: f64,
    /// Secret-bearing path.
    pub secret: f64,
    /// Sensitive system path, write context.
    pub sensitive_write: f64,
    /// Sensitive system path, read-only head.
    pub sensitive_read: f64,
    /// Sensitive system path, neither.
    pub sensitive_ambiguous: f64,
    /// `../` under a read-only head.
    pub traversal_read: f64,
    /// `../` otherwise.
    pub traversal: f64,
}

impl Default for PathScores {
    fn default() -> Self {
        // care/path.py:151-245.
        PathScores {
            system_root: 1.0,
            critical: 1.0,
            secret: 0.85,
            sensitive_write: 0.70,
            sensitive_read: 0.10,
            sensitive_ambiguous: 0.35,
            traversal_read: 0.3,
            traversal: 0.5,
        }
    }
}

/// A per-rule override. Only values that differ from the bank are kept.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RuleOverride {
    /// `false` removes the rule from L4 matching (and so from `p_rule`).
    pub enabled: bool,
    /// Replaces the bank confidence in L4 (π·conf) and `p_rule`.
    pub confidence: Option<f64>,
}

/// CARE tunables (`[care]`, D18).
#[derive(Debug, Clone, PartialEq)]
pub struct CareTunables {
    /// L5 weights.
    pub weights: Weights,
    /// Per-mode τ_low / τ_high.
    pub modes: Modes,
    /// θ_rule.
    pub theta_rule: f64,
    /// θ_sem.
    pub theta_sem: f64,
    /// H_sem, sorted in [`RiskClass::ALL`] order, deduplicated.
    pub h_sem: Vec<RiskClass>,
    /// π per rule tier.
    pub provenance: Provenance,
    /// L2 class base scores.
    pub class_base: ClassBase,
    /// L1 ladder.
    pub structure: StructurePenalties,
    /// L3 scores.
    pub path: PathScores,
    /// Per-rule overrides by SE-P id.
    pub rules: BTreeMap<String, RuleOverride>,
}

fn sorted_classes(v: &[RiskClass]) -> Vec<RiskClass> {
    RiskClass::ALL
        .iter()
        .copied()
        .filter(|c| v.contains(c))
        .collect()
}

/// D27: default per-rule overrides. SE-P-003 (rm -rf on a system dir) drops
/// below θ_rule so it WARNs to the judge unless its score reaches τ_high.
pub const WIDE_WARN_RULES: &[(&str, f64)] = &[("SE-P-003", 0.75)];

/// D27: the built-in defaults are the wide-WARN profile: the paper's values
/// ([`CareTunables::paper`]) with the balanced band [`WIDE_WARN_BALANCED`],
/// an empty H_sem (no class-only auto-deny) and [`WIDE_WARN_RULES`].
impl Default for CareTunables {
    fn default() -> Self {
        CareTunables {
            modes: Modes::default(),
            h_sem: Vec::new(),
            rules: WIDE_WARN_RULES
                .iter()
                .map(|&(id, c)| {
                    (
                        id.to_string(),
                        RuleOverride {
                            enabled: true,
                            confidence: Some(c),
                        },
                    )
                })
                .collect(),
            ..CareTunables::paper()
        }
    }
}

impl CareTunables {
    /// The paper / Python-reference values (parity, tests/parity.rs).
    pub fn paper() -> Self {
        CareTunables {
            weights: Weights::default(),
            modes: Modes::paper(),
            theta_rule: THETA_RULE,
            theta_sem: THETA_SEM,
            h_sem: sorted_classes(H_SEM_PAPER),
            provenance: Provenance::default(),
            class_base: ClassBase::default(),
            structure: StructurePenalties::default(),
            path: PathScores::default(),
            rules: BTreeMap::new(),
        }
    }

    /// Is the rule matched at all?
    pub fn rule_enabled(&self, id: &str) -> bool {
        self.rules.get(id).is_none_or(|o| o.enabled)
    }

    /// The confidence used for a rule (override or the bank's).
    pub fn rule_confidence(&self, id: &str, bank: f64) -> f64 {
        self.rules
            .get(id)
            .and_then(|o| o.confidence)
            .unwrap_or(bank)
    }
}

// ------------------------------------------------------------------- Jev --

/// Tier thresholds (spec §4.2; all comparisons strict `>`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JevThresholds {
    /// transport: `a5_outbound_data >`.
    pub transport: f64,
    /// sensitive: `max(a1_reads_credentials, a7_personal_data) >`.
    pub sensitive: f64,
    /// unknown: `a6_destination_class=unknown_remote` (argmax one-hot) `>`.
    pub unknown: f64,
    /// a6 is read only when `f5_exceeds_approval >` this (its `when` gate).
    pub unknown_f5_gate: f64,
    /// T2: `f5_exceeds_approval >`.
    pub f5_deny: f64,
    /// T5: `f5_exceeds_approval >`.
    pub f5_ask: f64,
    /// T3: `d1_obfuscated >`.
    pub obfuscated: f64,
    /// T3: `b4_reversibility` (normalised) `>`.
    pub irreversible: f64,
}

impl Default for JevThresholds {
    fn default() -> Self {
        // FINDINGS §5 / spec §4.2 (composition_experiment.py output), and the
        // rubric's a6 declaration (use: predicate, when f5 > 0.8).
        JevThresholds {
            transport: 0.95,
            sensitive: 0.5,
            unknown: 0.5,
            unknown_f5_gate: 0.8,
            f5_deny: 0.9,
            f5_ask: 0.5,
            obfuscated: 0.2,
            irreversible: 0.25,
        }
    }
}

/// Context limits (spec §3.3, D16).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ContextLimits {
    /// Clip for args, the user request and each prior call.
    pub field_chars: usize,
    /// History budget for prior calls.
    pub history_chars: usize,
    /// Highest context level sent (L0, L1 or L2).
    pub max_level: Level,
}

impl Default for ContextLimits {
    fn default() -> Self {
        ContextLimits {
            field_chars: MAX_FIELD_CHARS,
            history_chars: MAX_PRIOR_CHARS,
            max_level: Level::L2,
        }
    }
}

/// Jev tunables (`[jev]`, D19).
#[derive(Debug, Clone)]
pub struct JevTunables {
    /// Tier thresholds.
    pub thresholds: JevThresholds,
    /// First-match order of T1..T5 (a tier left out never fires; T6 is the
    /// fall-through).
    pub tier_order: Vec<TierId>,
    /// Verdict per tier, indexed like [`TierId::ALL`].
    pub verdicts: [JevVerdict; 6],
    /// Context limits.
    pub context: ContextLimits,
    /// `rubric_file` as loaded (None: embedded rubric).
    pub rubric_file: Option<PathBuf>,
    /// The loaded alternative rubric (None: embedded rubric).
    pub rubric: Option<Arc<Rubric>>,
    /// D21: tool names exempted from Jev when CARE cannot score them
    /// (logged raw, no judge, no decision). Sorted, deduplicated.
    pub skip_tools: Vec<String>,
}

impl Default for JevTunables {
    fn default() -> Self {
        JevTunables {
            thresholds: JevThresholds::default(),
            tier_order: TierId::ALL[..5].to_vec(),
            verdicts: TIERS.map(|t| t.verdict),
            context: ContextLimits::default(),
            rubric_file: None,
            rubric: None,
            skip_tools: Vec::new(),
        }
    }
}

impl JevTunables {
    /// D21: whether an unscorable call to `tool` skips Jev (exact,
    /// case-sensitive name match).
    pub fn skips(&self, tool: &str) -> bool {
        self.skip_tools.iter().any(|t| t == tool)
    }

    /// Hash of the rubric in use.
    pub fn rubric_hash(&self) -> &str {
        self.rubric
            .as_ref()
            .map_or(EXPECTED_RUBRIC_HASH, |r| r.hash.as_str())
    }
}

// ----------------------------------------------------------------- judge --

/// State of `judge.calibration_file` (D24).
#[derive(Debug, Clone, Default, PartialEq)]
pub enum CalibrationState {
    /// No file configured: answers are used as reported.
    #[default]
    None,
    /// A valid file.
    Loaded(Arc<Calibration>),
    /// Configured but unreadable or invalid: every judge call fails to
    /// `ask` with this error (never silently uncalibrated).
    Invalid {
        /// Configured path.
        path: PathBuf,
        /// Why.
        error: String,
    },
}

/// Decision-relevant `[judge]` keys (D23, D24).
#[derive(Debug, Clone, PartialEq)]
pub struct JudgeTunables {
    /// D23: the `response.model` a backend must report (else D15 ask).
    pub expected_model: String,
    /// D24: the calibration applied to the backend's answers.
    pub calibration: CalibrationState,
}

impl Default for JudgeTunables {
    fn default() -> Self {
        JudgeTunables {
            expected_model: DEFAULT_EXPECTED_MODEL.to_string(),
            calibration: CalibrationState::None,
        }
    }
}

impl JudgeTunables {
    /// Fingerprint value of `judge.calibration_file`: `"none"`, the file's
    /// sha (content, not path), or `"invalid"`.
    pub fn calibration_id(&self) -> String {
        match &self.calibration {
            CalibrationState::None => "none".into(),
            CalibrationState::Loaded(c) => format!("sha256:{}", c.sha),
            CalibrationState::Invalid { .. } => "invalid".into(),
        }
    }
}

// ----------------------------------------------------------------- whole --

/// Every tunable.
#[derive(Debug, Clone, Default)]
pub struct Tunables {
    /// `[care]`.
    pub care: CareTunables,
    /// `[jev]`.
    pub jev: JevTunables,
    /// `[judge]` expected_model and calibration_file.
    pub judge: JudgeTunables,
}

/// Documentation of one tunable key (`config --init`, README).
#[derive(Debug, Clone, Copy)]
pub struct Knob {
    /// Dotted key.
    pub key: &'static str,
    /// One-line meaning.
    pub doc: &'static str,
    /// Where the default comes from.
    pub source: &'static str,
}

const P_WEIGHTS: &str = "paper Eq. 6, App. A.5; care/policy.py:15-18";
const P_MODES: &str = "paper Eq. 7; care/modes.py:32-55";
const P_WIDE_WARN: &str = "D27 wide-WARN default (paper Eq. 7: 0.15/0.35)";
const P_CLASS: &str = "care/common.py:28-39 CLASS_BASE_SCORE";
const P_STRUCT: &str = "paper App. A.1; care/structure.py scoring ladder";
const P_PATH: &str = "care/path.py:151-245 PathValidator.validate";
const P_PROV: &str = "paper App. A.4; care/pattern.py PROVENANCE_TIER_WEIGHT";
const P_TIERS: &str = "FINDINGS §5; jev-integration-spec §4.2";
const P_CTX: &str = "POC jev_gate/prepare.py; jev-integration-spec §3.3";

/// Every scalar/list tunable, in canonical order. Per-rule keys
/// (`care.rules."SE-P-NNN".enabled|confidence`) are documented separately.
pub const KNOBS: &[Knob] = &[
    Knob {
        key: "care.weights.sem",
        doc: "L5 weight of s_sem (L2 semantic)",
        source: P_WEIGHTS,
    },
    Knob {
        key: "care.weights.path",
        doc: "L5 weight of s_path (L3 path)",
        source: P_WEIGHTS,
    },
    Knob {
        key: "care.weights.pat",
        doc: "L5 weight of s_pat (L4 rules)",
        source: P_WEIGHTS,
    },
    Knob {
        key: "care.weights.struct",
        doc: "L5 weight of δ_struct (L1 structure)",
        source: P_WEIGHTS,
    },
    Knob {
        key: "care.modes.strict.tau_low",
        doc: "strict: ALLOW below this score",
        source: P_MODES,
    },
    Knob {
        key: "care.modes.strict.tau_high",
        doc: "strict: DENY at or above this score",
        source: P_MODES,
    },
    Knob {
        key: "care.modes.balanced.tau_low",
        doc: "balanced: ALLOW below this score",
        source: P_WIDE_WARN,
    },
    Knob {
        key: "care.modes.balanced.tau_high",
        doc: "balanced: DENY at or above this score",
        source: P_WIDE_WARN,
    },
    Knob {
        key: "care.modes.auto.tau_low",
        doc: "auto: ALLOW below this score",
        source: P_MODES,
    },
    Knob {
        key: "care.modes.auto.tau_high",
        doc: "auto: DENY at or above this score",
        source: P_MODES,
    },
    Knob {
        key: "care.resolution.theta_rule",
        doc: "p_rule: a mitre/gtfobins rule with π·conf >= this skips the judge",
        source: "paper App. A.6; care/resolution.py:44 (FIX-001)",
    },
    Knob {
        key: "care.resolution.theta_sem",
        doc: "p_sem: an H_sem atom scoring >= this skips the judge",
        source: "paper App. A.6; care/resolution.py:45",
    },
    Knob {
        key: "care.resolution.h_sem",
        doc: "L2 classes that can fire p_sem",
        source: "D27 wide-WARN default (paper App. A.6 H_sem, FIX-003, has 5 classes)",
    },
    Knob {
        key: "care.provenance.mitre",
        doc: "π for MITRE-tier rules (L4 score and p_rule)",
        source: P_PROV,
    },
    Knob {
        key: "care.provenance.gtfobins",
        doc: "π for GTFOBins-tier rules",
        source: P_PROV,
    },
    Knob {
        key: "care.provenance.manual",
        doc: "π for manual-tier rules",
        source: P_PROV,
    },
    Knob {
        key: "care.class_base.READ_ONLY",
        doc: "L2 base score, READ_ONLY heads",
        source: P_CLASS,
    },
    Knob {
        key: "care.class_base.WRITE_LOCAL",
        doc: "L2 base score, WRITE_LOCAL heads",
        source: P_CLASS,
    },
    Knob {
        key: "care.class_base.WRITE_SENSITIVE",
        doc: "L2 base score, secret-path reads/writes",
        source: P_CLASS,
    },
    Knob {
        key: "care.class_base.NETWORK_FETCH",
        doc: "L2 base score, NETWORK_FETCH heads",
        source: P_CLASS,
    },
    Knob {
        key: "care.class_base.EXECUTION_CHAIN",
        doc: "L2 base score, shells/interpreters",
        source: P_CLASS,
    },
    Knob {
        key: "care.class_base.PRIVILEGE_OR_PERMISSION",
        doc: "L2 base score, privilege/permission heads",
        source: P_CLASS,
    },
    Knob {
        key: "care.class_base.PERSISTENCE",
        doc: "L2 base score, persistence heads",
        source: P_CLASS,
    },
    Knob {
        key: "care.class_base.DESTRUCTIVE",
        doc: "L2 base score, destructive heads (special cases like rm_rf keep their own scores)",
        source: P_CLASS,
    },
    Knob {
        key: "care.class_base.RESOURCE_ABUSE",
        doc: "L2 base score, resource-abuse heads",
        source: P_CLASS,
    },
    Knob {
        key: "care.class_base.UNKNOWN",
        doc: "L2 base score, unmapped heads",
        source: P_CLASS,
    },
    Knob {
        key: "care.structure.pipe_to_exec",
        doc: "δ_struct: pipeline ends in an interpreter",
        source: P_STRUCT,
    },
    Knob {
        key: "care.structure.eval",
        doc: "δ_struct: eval/source/. as a command head",
        source: P_STRUCT,
    },
    Knob {
        key: "care.structure.nested_substitution",
        doc: "δ_struct: command substitution nested >= 2 deep",
        source: P_STRUCT,
    },
    Knob {
        key: "care.structure.command_substitution",
        doc: "δ_struct: any $() or backticks",
        source: P_STRUCT,
    },
    Knob {
        key: "care.structure.pipe",
        doc: "δ_struct: any pipeline",
        source: P_STRUCT,
    },
    Knob {
        key: "care.path.system_root",
        doc: "s_path: destructive head on a system root (first hit decides)",
        source: P_PATH,
    },
    Knob {
        key: "care.path.critical",
        doc: "s_path: critical pattern (devices, shadow, keys, kernel; first hit decides)",
        source: P_PATH,
    },
    Knob {
        key: "care.path.secret",
        doc: "s_path: secret-bearing path",
        source: P_PATH,
    },
    Knob {
        key: "care.path.sensitive_write",
        doc: "s_path: sensitive system path, write context",
        source: P_PATH,
    },
    Knob {
        key: "care.path.sensitive_read",
        doc: "s_path: sensitive system path, read-only head",
        source: P_PATH,
    },
    Knob {
        key: "care.path.sensitive_ambiguous",
        doc: "s_path: sensitive system path, neither",
        source: P_PATH,
    },
    Knob {
        key: "care.path.traversal_read",
        doc: "s_path: ../ under a read-only head",
        source: P_PATH,
    },
    Knob {
        key: "care.path.traversal",
        doc: "s_path: ../ otherwise",
        source: P_PATH,
    },
    Knob {
        key: "jev.rubric_file",
        doc: "alternative rubric YAML (logged and fingerprinted by its rubric_hash)",
        source: "D19; embedded data/jev/v1_policy_distilled.yaml",
    },
    Knob {
        key: "jev.skip_tools",
        doc: "tool names CARE can't score that skip Jev and pass through unjudged (exact match, e.g. [\"Read\", \"mcp__github__get_issue\"])",
        source: "D21",
    },
    Knob {
        key: "jev.thresholds.transport",
        doc: "transport: a5_outbound_data > this (T1, T4)",
        source: P_TIERS,
    },
    Knob {
        key: "jev.thresholds.sensitive",
        doc: "sensitive: max(a1_reads_credentials, a7_personal_data) > this (T1, T4)",
        source: P_TIERS,
    },
    Knob {
        key: "jev.thresholds.unknown",
        doc: "unknown: a6 argmax one-hot for unknown_remote > this (T1)",
        source: "rubric a6 use: predicate; jev-integration-spec §4.2 declared row",
    },
    Knob {
        key: "jev.thresholds.unknown_f5_gate",
        doc: "a6 is read only when f5_exceeds_approval > this (overrides the rubric's a6 when.over)",
        source: "rubric a6 when.over; FINDINGS §5",
    },
    Knob {
        key: "jev.thresholds.f5_deny",
        doc: "T2: f5_exceeds_approval > this",
        source: P_TIERS,
    },
    Knob {
        key: "jev.thresholds.f5_ask",
        doc: "T5: f5_exceeds_approval > this",
        source: P_TIERS,
    },
    Knob {
        key: "jev.thresholds.obfuscated",
        doc: "T3: d1_obfuscated > this",
        source: P_TIERS,
    },
    Knob {
        key: "jev.thresholds.irreversible",
        doc: "T3: b4_reversibility (score/3) > this",
        source: P_TIERS,
    },
    Knob {
        key: "jev.tiers.order",
        doc: "first-match order of T1..T5; a tier left out never fires; T6 = none fired",
        source: P_TIERS,
    },
    Knob {
        key: "jev.verdicts.T1",
        doc: "verdict for T1 (allow|ask|deny)",
        source: "D14",
    },
    Knob {
        key: "jev.verdicts.T2",
        doc: "verdict for T2",
        source: "D14",
    },
    Knob {
        key: "jev.verdicts.T3",
        doc: "verdict for T3",
        source: "D14",
    },
    Knob {
        key: "jev.verdicts.T4",
        doc: "verdict for T4",
        source: "D14",
    },
    Knob {
        key: "jev.verdicts.T5",
        doc: "verdict for T5",
        source: "D14",
    },
    Knob {
        key: "jev.verdicts.T6",
        doc: "verdict when no tier fires (allow still emits only with decide_all, D13)",
        source: "D14",
    },
    Knob {
        key: "jev.context.field_chars",
        doc: "clip for args, the user request and each prior call (characters)",
        source: P_CTX,
    },
    Knob {
        key: "jev.context.history_chars",
        doc: "history budget for prior calls, newest kept first (characters)",
        source: P_CTX,
    },
    Knob {
        key: "jev.context.max_level",
        doc: "highest context level: L0 action, L1 +user request, L2 +prior calls",
        source: "D16; POC jev_gate/context.py",
    },
    Knob {
        key: "judge.expected_model",
        doc: "response.model the /v1/systemone backend must report; anything else asks (D15)",
        source: "D23",
    },
    Knob {
        key: "judge.calibration_file",
        doc: "per-axis calibration (JSON) pinned to rubric_hash + model; invalid or mismatched asks",
        source: "D24",
    },
];

/// Dotted key of a per-rule field.
pub fn rule_key(id: &str, field: &str) -> String {
    format!("care.rules.\"{id}\".{field}")
}

fn f(x: f64) -> Value {
    json!(x)
}

impl Tunables {
    /// Flat dotted-key view of the effective values, in [`KNOBS`] order,
    /// then per-rule overrides by id. `jev.rubric_file` is represented by
    /// the hash of the rubric in use (content, not path).
    pub fn entries(&self) -> Vec<(String, Value)> {
        let c = &self.care;
        let j = &self.jev;
        let mut v: Vec<(String, Value)> = vec![
            ("care.weights.sem".into(), f(c.weights.sem)),
            ("care.weights.path".into(), f(c.weights.path)),
            ("care.weights.pat".into(), f(c.weights.pat)),
            ("care.weights.struct".into(), f(c.weights.r#struct)),
        ];
        for m in [Mode::Strict, Mode::Balanced, Mode::Auto] {
            let b = c.modes.get(m);
            v.push((format!("care.modes.{}.tau_low", m.as_str()), f(b.tau_low)));
            v.push((format!("care.modes.{}.tau_high", m.as_str()), f(b.tau_high)));
        }
        v.push(("care.resolution.theta_rule".into(), f(c.theta_rule)));
        v.push(("care.resolution.theta_sem".into(), f(c.theta_sem)));
        v.push((
            "care.resolution.h_sem".into(),
            json!(c.h_sem.iter().map(|x| x.as_str()).collect::<Vec<_>>()),
        ));
        v.push(("care.provenance.mitre".into(), f(c.provenance.mitre)));
        v.push(("care.provenance.gtfobins".into(), f(c.provenance.gtfobins)));
        v.push(("care.provenance.manual".into(), f(c.provenance.manual)));
        for cl in RiskClass::ALL {
            v.push((
                format!("care.class_base.{}", cl.as_str()),
                f(c.class_base.get(cl)),
            ));
        }
        let s = &c.structure;
        v.push(("care.structure.pipe_to_exec".into(), f(s.pipe_to_exec)));
        v.push(("care.structure.eval".into(), f(s.eval)));
        v.push((
            "care.structure.nested_substitution".into(),
            f(s.nested_substitution),
        ));
        v.push((
            "care.structure.command_substitution".into(),
            f(s.command_substitution),
        ));
        v.push(("care.structure.pipe".into(), f(s.pipe)));
        let p = &c.path;
        v.push(("care.path.system_root".into(), f(p.system_root)));
        v.push(("care.path.critical".into(), f(p.critical)));
        v.push(("care.path.secret".into(), f(p.secret)));
        v.push(("care.path.sensitive_write".into(), f(p.sensitive_write)));
        v.push(("care.path.sensitive_read".into(), f(p.sensitive_read)));
        v.push((
            "care.path.sensitive_ambiguous".into(),
            f(p.sensitive_ambiguous),
        ));
        v.push(("care.path.traversal_read".into(), f(p.traversal_read)));
        v.push(("care.path.traversal".into(), f(p.traversal)));
        v.push(("jev.rubric_file".into(), json!(j.rubric_hash())));
        v.push(("jev.skip_tools".into(), json!(j.skip_tools)));
        let t = &j.thresholds;
        v.push(("jev.thresholds.transport".into(), f(t.transport)));
        v.push(("jev.thresholds.sensitive".into(), f(t.sensitive)));
        v.push(("jev.thresholds.unknown".into(), f(t.unknown)));
        v.push((
            "jev.thresholds.unknown_f5_gate".into(),
            f(t.unknown_f5_gate),
        ));
        v.push(("jev.thresholds.f5_deny".into(), f(t.f5_deny)));
        v.push(("jev.thresholds.f5_ask".into(), f(t.f5_ask)));
        v.push(("jev.thresholds.obfuscated".into(), f(t.obfuscated)));
        v.push(("jev.thresholds.irreversible".into(), f(t.irreversible)));
        v.push((
            "jev.tiers.order".into(),
            json!(j.tier_order.iter().map(|t| t.name()).collect::<Vec<_>>()),
        ));
        for id in TierId::ALL {
            v.push((
                format!("jev.verdicts.{}", id.name()),
                json!(j.verdicts[id.index()].as_str()),
            ));
        }
        v.push((
            "jev.context.field_chars".into(),
            json!(j.context.field_chars),
        ));
        v.push((
            "jev.context.history_chars".into(),
            json!(j.context.history_chars),
        ));
        v.push((
            "jev.context.max_level".into(),
            json!(j.context.max_level.short()),
        ));
        v.push((
            "judge.expected_model".into(),
            json!(self.judge.expected_model),
        ));
        v.push((
            "judge.calibration_file".into(),
            json!(self.judge.calibration_id()),
        ));
        for (id, o) in &c.rules {
            if !o.enabled {
                v.push((rule_key(id, "enabled"), json!(false)));
            }
            if let Some(x) = o.confidence {
                v.push((rule_key(id, "confidence"), f(x)));
            }
        }
        v
    }

    /// [`Tunables::entries`] as a sorted map (the canonical form).
    pub fn canonical(&self) -> BTreeMap<String, Value> {
        self.entries().into_iter().collect()
    }

    /// `config_fingerprint`: the first 16 hex digits of the sha256 of the
    /// canonical JSON (sorted keys, shortest round-trip floats). Independent
    /// of key order, spelling (`1` vs `1.0`) and file layout.
    pub fn fingerprint(&self) -> String {
        let text = serde_json::to_string(&self.canonical()).unwrap_or_default();
        let d = Sha256::digest(text.as_bytes());
        d.iter().take(8).map(|x| format!("{x:02x}")).collect()
    }

    /// `overrides[]`: dotted keys whose effective value differs from the
    /// default, sorted.
    pub fn overrides(&self) -> Vec<String> {
        let def = Tunables::default().canonical();
        let cur = self.canonical();
        let keys: BTreeSet<&String> = def.keys().chain(cur.keys()).collect();
        keys.into_iter()
            .filter(|k| def.get(*k) != cur.get(*k))
            .cloned()
            .collect()
    }
}

/// A canonical value in TOML syntax.
pub fn toml_value(v: &Value) -> String {
    match v {
        Value::Number(n) if n.is_u64() || n.is_i64() => n.to_string(),
        Value::Number(n) => format!("{:?}", n.as_f64().unwrap_or_default()),
        Value::String(s) => format!("{s:?}"),
        Value::Bool(b) => b.to_string(),
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(toml_value).collect::<Vec<_>>().join(", ")
        ),
        other => other.to_string(),
    }
}

// ------------------------------------------------------------------ load --

/// Result of reading the tunables.
#[derive(Debug, Clone, Default)]
pub struct Loaded {
    /// Effective tunables.
    pub tunables: Tunables,
    /// Dotted keys whose value came (validly) from the file.
    pub from_file: BTreeSet<String>,
}

#[derive(Clone, Copy)]
enum Range {
    /// [0, 1].
    Unit,
    /// ≥ 0.
    NonNeg,
}

struct Rd<'a> {
    diags: &'a mut Vec<Diagnostic>,
    set: BTreeSet<String>,
}

impl Rd<'_> {
    fn error(&mut self, key: &str, what: impl std::fmt::Display) {
        self.diags.push(Diagnostic {
            level: "error",
            message: format!("{key}: {what}; using the default"),
        });
    }

    fn warn(&mut self, message: String) {
        self.diags.push(Diagnostic {
            level: "warning",
            message,
        });
    }

    fn unknown(&mut self, t: &Table, prefix: &str, known: &[&str]) {
        for k in t.keys() {
            if !known.contains(&k.as_str()) {
                self.warn(format!("unknown config key `{prefix}.{k}` ignored"));
            }
        }
    }

    fn table<'t>(&mut self, t: &'t Table, prefix: &str, key: &str) -> Option<&'t Table> {
        match t.get(key)? {
            TV::Table(x) => Some(x),
            other => {
                let full = if prefix.is_empty() {
                    key.to_string()
                } else {
                    format!("{prefix}.{key}")
                };
                self.error(&full, format!("{other} is not a table"));
                None
            }
        }
    }

    fn num(&mut self, t: &Table, prefix: &str, key: &str, r: Range, slot: &mut f64) {
        let Some(v) = t.get(key) else { return };
        let full = format!("{prefix}.{key}");
        let x = match v {
            TV::Float(x) => *x,
            TV::Integer(i) => *i as f64,
            other => {
                self.error(&full, format!("{other} is not a number"));
                return;
            }
        };
        let ok = x.is_finite()
            && match r {
                Range::Unit => (0.0..=1.0).contains(&x),
                Range::NonNeg => x >= 0.0,
            };
        if !ok {
            let want = match r {
                Range::Unit => "a number in [0, 1]",
                Range::NonNeg => "a finite number >= 0",
            };
            self.error(&full, format!("{x} is not {want}"));
            return;
        }
        *slot = x;
        self.set.insert(full);
    }

    fn count(&mut self, t: &Table, prefix: &str, key: &str, min: i64, slot: &mut usize) {
        let Some(v) = t.get(key) else { return };
        let full = format!("{prefix}.{key}");
        match v.as_integer().filter(|n| *n >= min) {
            Some(n) => match usize::try_from(n) {
                Ok(n) => {
                    *slot = n;
                    self.set.insert(full);
                }
                Err(_) => self.error(&full, format!("{n} is out of range")),
            },
            None => self.error(&full, format!("{v} is not an integer >= {min}")),
        }
    }
}

fn is_rule_id(s: &str) -> bool {
    s.len() == 8 && s.starts_with("SE-P-") && s[5..].bytes().all(|b| b.is_ascii_digit())
}

fn load_care(t: &Table, rd: &mut Rd<'_>) -> CareTunables {
    let mut c = CareTunables::default();
    rd.unknown(
        t,
        "care",
        &[
            "weights",
            "modes",
            "resolution",
            "provenance",
            "class_base",
            "structure",
            "path",
            "rules",
        ],
    );
    if let Some(w) = rd.table(t, "care", "weights") {
        let p = "care.weights";
        rd.unknown(w, p, &["sem", "path", "pat", "struct"]);
        rd.num(w, p, "sem", Range::NonNeg, &mut c.weights.sem);
        rd.num(w, p, "path", Range::NonNeg, &mut c.weights.path);
        rd.num(w, p, "pat", Range::NonNeg, &mut c.weights.pat);
        rd.num(w, p, "struct", Range::NonNeg, &mut c.weights.r#struct);
    }
    if let Some(m) = rd.table(t, "care", "modes") {
        rd.unknown(m, "care.modes", &["strict", "balanced", "auto"]);
        for mode in [Mode::Strict, Mode::Balanced, Mode::Auto] {
            let Some(mt) = rd.table(m, "care.modes", mode.as_str()) else {
                continue;
            };
            let p = format!("care.modes.{}", mode.as_str());
            rd.unknown(mt, &p, &["tau_low", "tau_high"]);
            let def = c.modes.get(mode);
            let mut b = def;
            rd.num(mt, &p, "tau_low", Range::Unit, &mut b.tau_low);
            rd.num(mt, &p, "tau_high", Range::Unit, &mut b.tau_high);
            if b.tau_low >= b.tau_high {
                let why = format!("tau_low {} must be < tau_high {}", b.tau_low, b.tau_high);
                for (k, low) in [("tau_low", true), ("tau_high", false)] {
                    let full = format!("{p}.{k}");
                    if rd.set.remove(&full) {
                        rd.error(&full, &why);
                        if low {
                            b.tau_low = def.tau_low;
                        } else {
                            b.tau_high = def.tau_high;
                        }
                    }
                }
            }
            *c.modes.get_mut(mode) = b;
        }
    }
    if let Some(r) = rd.table(t, "care", "resolution") {
        let p = "care.resolution";
        rd.unknown(r, p, &["theta_rule", "theta_sem", "h_sem"]);
        rd.num(r, p, "theta_rule", Range::Unit, &mut c.theta_rule);
        rd.num(r, p, "theta_sem", Range::Unit, &mut c.theta_sem);
        if let Some(v) = r.get("h_sem") {
            let key = "care.resolution.h_sem";
            let parsed: Result<Vec<RiskClass>, String> = match v.as_array() {
                None => Err(format!("{v} is not an array of class names")),
                Some(a) => a
                    .iter()
                    .map(|x| {
                        x.as_str()
                            .and_then(RiskClass::parse)
                            .ok_or_else(|| format!("{x} is not a known class name"))
                    })
                    .collect(),
            };
            match parsed {
                Ok(v) => {
                    c.h_sem = sorted_classes(&v);
                    rd.set.insert(key.into());
                }
                Err(e) => rd.error(key, e),
            }
        }
    }
    if let Some(pv) = rd.table(t, "care", "provenance") {
        let p = "care.provenance";
        rd.unknown(pv, p, &["mitre", "gtfobins", "manual"]);
        rd.num(pv, p, "mitre", Range::Unit, &mut c.provenance.mitre);
        rd.num(pv, p, "gtfobins", Range::Unit, &mut c.provenance.gtfobins);
        rd.num(pv, p, "manual", Range::Unit, &mut c.provenance.manual);
    }
    if let Some(cb) = rd.table(t, "care", "class_base") {
        for k in cb.keys() {
            match RiskClass::parse(k) {
                Some(cl) => rd.num(
                    cb,
                    "care.class_base",
                    k,
                    Range::Unit,
                    &mut c.class_base.0[cl.index()],
                ),
                None => rd.error(
                    &format!("care.class_base.{k}"),
                    "not a known class name (READ_ONLY, WRITE_LOCAL, …)",
                ),
            }
        }
    }
    if let Some(s) = rd.table(t, "care", "structure") {
        let p = "care.structure";
        let st = &mut c.structure;
        rd.unknown(
            s,
            p,
            &[
                "pipe_to_exec",
                "eval",
                "nested_substitution",
                "command_substitution",
                "pipe",
            ],
        );
        rd.num(s, p, "pipe_to_exec", Range::Unit, &mut st.pipe_to_exec);
        rd.num(s, p, "eval", Range::Unit, &mut st.eval);
        rd.num(
            s,
            p,
            "nested_substitution",
            Range::Unit,
            &mut st.nested_substitution,
        );
        rd.num(
            s,
            p,
            "command_substitution",
            Range::Unit,
            &mut st.command_substitution,
        );
        rd.num(s, p, "pipe", Range::Unit, &mut st.pipe);
    }
    if let Some(pt) = rd.table(t, "care", "path") {
        let p = "care.path";
        let ps = &mut c.path;
        rd.unknown(
            pt,
            p,
            &[
                "system_root",
                "critical",
                "secret",
                "sensitive_write",
                "sensitive_read",
                "sensitive_ambiguous",
                "traversal_read",
                "traversal",
            ],
        );
        rd.num(pt, p, "system_root", Range::Unit, &mut ps.system_root);
        rd.num(pt, p, "critical", Range::Unit, &mut ps.critical);
        rd.num(pt, p, "secret", Range::Unit, &mut ps.secret);
        rd.num(
            pt,
            p,
            "sensitive_write",
            Range::Unit,
            &mut ps.sensitive_write,
        );
        rd.num(pt, p, "sensitive_read", Range::Unit, &mut ps.sensitive_read);
        rd.num(
            pt,
            p,
            "sensitive_ambiguous",
            Range::Unit,
            &mut ps.sensitive_ambiguous,
        );
        rd.num(pt, p, "traversal_read", Range::Unit, &mut ps.traversal_read);
        rd.num(pt, p, "traversal", Range::Unit, &mut ps.traversal);
    }
    if let Some(rt) = rd.table(t, "care", "rules") {
        let bank = rules::bank().ok();
        for (id, v) in rt {
            let key = format!("care.rules.\"{id}\"");
            if !is_rule_id(id) {
                rd.error(&key, "malformed rule id (expected SE-P-NNN)");
                continue;
            }
            let bank_rule = bank.and_then(|b| b.rules.iter().find(|r| r.id == *id));
            let Some(bank_rule) = bank_rule else {
                rd.error(&key, "no such rule in the embedded bank");
                continue;
            };
            let Some(tbl) = v.as_table() else {
                rd.error(&key, format!("{v} is not a table"));
                continue;
            };
            rd.unknown(tbl, &key, &["enabled", "confidence"]);
            // Keys left out keep the built-in default (which may itself be
            // an override, D27); a value equal to the bank's clears it.
            let mut o = RuleOverride {
                enabled: c.rule_enabled(id),
                confidence: None,
            };
            if let Some(e) = tbl.get("enabled") {
                let k = rule_key(id, "enabled");
                match e.as_bool() {
                    Some(b) => {
                        o.enabled = b;
                        rd.set.insert(k);
                    }
                    None => rd.error(&k, format!("{e} is not a boolean")),
                }
            }
            let mut conf = c.rule_confidence(id, bank_rule.confidence);
            rd.num(tbl, &key, "confidence", Range::Unit, &mut conf);
            if conf != bank_rule.confidence {
                o.confidence = Some(conf);
            }
            if !o.enabled || o.confidence.is_some() {
                c.rules.insert(id.clone(), o);
            } else {
                c.rules.remove(id);
            }
        }
    }
    c
}

fn load_jev(t: &Table, rd: &mut Rd<'_>, env: &Env) -> JevTunables {
    let mut j = JevTunables::default();
    rd.unknown(
        t,
        "jev",
        &[
            "rubric_file",
            "skip_tools",
            "thresholds",
            "tiers",
            "verdicts",
            "context",
        ],
    );
    if let Some(v) = t.get("skip_tools") {
        let key = "jev.skip_tools";
        let names: Option<Vec<&str>> = v.as_array().and_then(|a| {
            a.iter()
                .map(|x| {
                    x.as_str()
                        .filter(|s| !s.trim().is_empty() && s.trim() == *s)
                })
                .collect()
        });
        match names {
            None => rd.error(
                key,
                format!("{v} is not an array of non-empty tool names without surrounding spaces"),
            ),
            Some(names) => {
                let mut names: Vec<String> = names.into_iter().map(str::to_string).collect();
                names.sort();
                names.dedup();
                if names.iter().any(|n| n == "Bash") {
                    rd.warn(format!(
                        "{key}: \"Bash\" only exempts Bash calls without a command; \
                         CARE-scored Bash WARNs still go to Jev (D12)"
                    ));
                }
                j.skip_tools = names;
                rd.set.insert(key.into());
            }
        }
    }
    if let Some(th) = rd.table(t, "jev", "thresholds") {
        let p = "jev.thresholds";
        let x = &mut j.thresholds;
        rd.unknown(
            th,
            p,
            &[
                "transport",
                "sensitive",
                "unknown",
                "unknown_f5_gate",
                "f5_deny",
                "f5_ask",
                "obfuscated",
                "irreversible",
            ],
        );
        rd.num(th, p, "transport", Range::Unit, &mut x.transport);
        rd.num(th, p, "sensitive", Range::Unit, &mut x.sensitive);
        rd.num(th, p, "unknown", Range::Unit, &mut x.unknown);
        rd.num(
            th,
            p,
            "unknown_f5_gate",
            Range::Unit,
            &mut x.unknown_f5_gate,
        );
        rd.num(th, p, "f5_deny", Range::Unit, &mut x.f5_deny);
        rd.num(th, p, "f5_ask", Range::Unit, &mut x.f5_ask);
        rd.num(th, p, "obfuscated", Range::Unit, &mut x.obfuscated);
        rd.num(th, p, "irreversible", Range::Unit, &mut x.irreversible);
    }
    if let Some(ti) = rd.table(t, "jev", "tiers") {
        rd.unknown(ti, "jev.tiers", &["order"]);
        if let Some(v) = ti.get("order") {
            let key = "jev.tiers.order";
            let parsed: Result<Vec<TierId>, String> = match v.as_array() {
                None => Err(format!("{v} is not an array of tier names")),
                Some(a) => {
                    let mut out = Vec::new();
                    let mut err = None;
                    for x in a {
                        match x.as_str().and_then(TierId::parse) {
                            Some(TierId::T6) => {
                                err = Some("T6 is the fall-through and cannot be ordered".into())
                            }
                            Some(id) if out.contains(&id) => {
                                err = Some(format!("{} is listed twice", id.name()))
                            }
                            Some(id) => out.push(id),
                            None => err = Some(format!("{x} is not a tier name (T1..T5)")),
                        }
                    }
                    err.map_or(Ok(out), Err)
                }
            };
            match parsed {
                Ok(v) => {
                    j.tier_order = v;
                    rd.set.insert(key.into());
                }
                Err(e) => rd.error(key, e),
            }
        }
    }
    if let Some(vt) = rd.table(t, "jev", "verdicts") {
        for (k, v) in vt {
            let key = format!("jev.verdicts.{k}");
            let Some(id) = TierId::parse(k) else {
                rd.error(&key, "not a tier name (T1..T6)");
                continue;
            };
            let verdict = match v.as_str() {
                Some("allow") => JevVerdict::Allow,
                Some("ask") => JevVerdict::Ask,
                Some("deny") => JevVerdict::Deny,
                _ => {
                    rd.error(&key, format!("{v} is not allow|ask|deny"));
                    continue;
                }
            };
            j.verdicts[id.index()] = verdict;
            rd.set.insert(key);
        }
    }
    if let Some(cx) = rd.table(t, "jev", "context") {
        let p = "jev.context";
        rd.unknown(cx, p, &["field_chars", "history_chars", "max_level"]);
        rd.count(cx, p, "field_chars", 1, &mut j.context.field_chars);
        rd.count(cx, p, "history_chars", 0, &mut j.context.history_chars);
        if let Some(v) = cx.get("max_level") {
            let key = "jev.context.max_level";
            match v.as_str().and_then(Level::parse) {
                Some(Level::L3) => rd.error(
                    key,
                    "L3 includes tool results, which the hook never sends (D16)",
                ),
                Some(l) => {
                    j.context.max_level = l;
                    rd.set.insert(key.into());
                }
                None => rd.error(key, format!("{v} is not L0, L1 or L2")),
            }
        }
    }
    if let Some(v) = t.get("rubric_file") {
        let key = "jev.rubric_file";
        match v.as_str() {
            None => rd.error(key, format!("{v} is not a string")),
            Some(s) => {
                let path = expand_tilde(s, env);
                let loaded = std::fs::read_to_string(&path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))
                    .and_then(|text| rubric::parse(&text));
                match loaded {
                    Err(e) => rd.diags.push(Diagnostic {
                        level: "error",
                        message: format!(
                            "{key}: {} is not a valid rubric ({e}); using the embedded \
                             rubric {EXPECTED_RUBRIC_HASH}",
                            path.display()
                        ),
                    }),
                    Ok(r) => {
                        rd.warn(format!(
                            "{key}: using rubric {:?} from {} (rubric_hash {}); the jev tier \
                             thresholds were calibrated on the embedded rubric \
                             {EXPECTED_RUBRIC_HASH} and the ProCreations corpus",
                            r.name,
                            path.display(),
                            r.hash
                        ));
                        if r.model != DEFAULT_EXPECTED_MODEL {
                            rd.warn(format!(
                                "{key}: rubric model {:?} is not {DEFAULT_EXPECTED_MODEL:?}",
                                r.model
                            ));
                        }
                        j.rubric_file = Some(path);
                        j.rubric = Some(Arc::new(r));
                        rd.set.insert(key.into());
                    }
                }
            }
        }
    }
    j
}

/// Warnings about the rubric in use: tiers that read axes it lacks (they
/// can never fire), and an a6 gate it declares differently from
/// `jev.thresholds.unknown_f5_gate`. Only an alternative rubric can produce
/// them.
pub fn rubric_warnings(j: &JevTunables) -> Vec<String> {
    let Some(r) = &j.rubric else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, missing) in unavailable_tiers(r) {
        out.push(format!(
            "jev tier {} reads {} absent from rubric {}; {} cannot fire",
            id.name(),
            missing.join(", "),
            r.hash,
            id.name()
        ));
    }
    if let Some(w) = r.axis(A6).and_then(|a| a.when.as_ref())
        && w.over != j.thresholds.unknown_f5_gate
    {
        out.push(format!(
            "jev.rubric_file declares the {A6} gate over {}; jev.thresholds.unknown_f5_gate {} is used",
            w.over, j.thresholds.unknown_f5_gate
        ));
    }
    out
}

/// `[judge]` expected_model and calibration_file (the other `[judge]` keys
/// are transport settings read by `config`, which also reports unknown
/// keys). The calibration is validated against the rubric in use.
fn load_judge(t: &Table, rd: &mut Rd<'_>, env: &Env, jev: &JevTunables) -> JudgeTunables {
    let mut j = JudgeTunables::default();
    if let Some(v) = t.get("expected_model") {
        let key = "judge.expected_model";
        match v.as_str().filter(|s| !s.is_empty() && s.trim() == *s) {
            Some(s) => {
                j.expected_model = s.to_string();
                rd.set.insert(key.into());
            }
            None => rd.error(
                key,
                format!("{v} is not a non-empty model name without surrounding spaces"),
            ),
        }
    }
    if let Some(v) = t.get("calibration_file") {
        let key = "judge.calibration_file";
        match v.as_str() {
            None => rd.error(key, format!("{v} is not a string")),
            Some(s) => {
                let path = expand_tilde(s, env);
                rd.set.insert(key.into());
                let loaded = effective_rubric(jev)
                    .and_then(|r| calibration::load(&path, &r))
                    .and_then(|c| {
                        if c.file.model == j.expected_model {
                            Ok(c)
                        } else {
                            Err(format!(
                                "it is pinned to model {:?} but judge.expected_model is {:?}",
                                c.file.model, j.expected_model
                            ))
                        }
                    });
                j.calibration = match loaded {
                    Ok(c) => CalibrationState::Loaded(Arc::new(c)),
                    Err(e) => {
                        rd.diags.push(Diagnostic {
                            level: "error",
                            message: format!(
                                "{key}: {} refused ({e}); every judge call will ask (D24, D15)",
                                path.display()
                            ),
                        });
                        CalibrationState::Invalid { path, error: e }
                    }
                };
            }
        }
    }
    if j.expected_model != DEFAULT_EXPECTED_MODEL && j.calibration == CalibrationState::None {
        rd.warn(format!(
            "judge.expected_model {:?}: the jev tier thresholds were calibrated on \
             {DEFAULT_EXPECTED_MODEL:?}; consider judge.calibration_file (D24)",
            j.expected_model
        ));
    }
    j
}

fn effective_rubric(j: &JevTunables) -> Result<Rubric, String> {
    match &j.rubric {
        Some(r) => Ok((**r).clone()),
        None => rubric::rubric().cloned(),
    }
}

/// Read the `care`, `jev` and (decision-relevant) `judge` tables of a
/// parsed config file (None: no file, or not valid TOML). Every value is
/// validated on its own.
pub fn load(root: Option<&Table>, env: &Env, diags: &mut Vec<Diagnostic>) -> Loaded {
    let mut rd = Rd {
        diags,
        set: BTreeSet::new(),
    };
    let mut t = Tunables::default();
    if let Some(root) = root {
        if let Some(c) = rd.table(root, "", "care") {
            t.care = load_care(c, &mut rd);
        }
        if let Some(j) = rd.table(root, "", "jev") {
            t.jev = load_jev(j, &mut rd, env);
        }
        // `[judge]` not being a table is reported by `config`.
        if let Some(TV::Table(j)) = root.get("judge") {
            t.judge = load_judge(j, &mut rd, env, &t.jev);
        }
    }
    for w in rubric_warnings(&t.jev) {
        rd.warn(w);
    }
    Loaded {
        tunables: t,
        from_file: rd.set,
    }
}

// ------------------------------------------------------------- rendering --

fn table_of(key: &str) -> (&str, &str) {
    key.rsplit_once('.').unwrap_or(("", key))
}

/// `cancelli config` lines: every tunable with its value and source, then
/// every rule of the bank with its effective `enabled`/`confidence`.
pub fn render(l: &Loaded) -> String {
    let t = &l.tunables;
    let src = |k: &str| {
        if l.from_file.contains(k) {
            "file"
        } else {
            "default"
        }
    };
    let mut out = format!(
        "# tunables (D18-D20): config_fingerprint = {}; overrides = {:?}\n",
        t.fingerprint(),
        t.overrides()
    );
    for (k, v) in t.entries() {
        if k.starts_with("care.rules.") {
            continue;
        }
        let shown = if k == "judge.calibration_file" {
            match &t.judge.calibration {
                CalibrationState::None => "(none)".to_string(),
                CalibrationState::Loaded(c) => format!(
                    "{:?}  # sha256 {}, model {:?}, rubric_hash {}, fitted_at {}, {} axes",
                    c.path.display().to_string(),
                    c.sha,
                    c.file.model,
                    c.file.rubric_hash,
                    c.file.fitted_at,
                    c.file.axes.len()
                ),
                CalibrationState::Invalid { path, error } => format!(
                    "{:?}  # INVALID ({error}): every judge call asks",
                    path.display().to_string()
                ),
            }
        } else if k == "jev.rubric_file" {
            match &t.jev.rubric_file {
                Some(p) => format!(
                    "{:?}  # rubric_hash {}",
                    p.display().to_string(),
                    t.jev.rubric_hash()
                ),
                None => format!("(embedded)  # rubric_hash {}", t.jev.rubric_hash()),
            }
        } else {
            toml_value(&v)
        };
        out.push_str(&format!("{k} = {shown}  # {}\n", src(&k)));
    }
    if let Ok(bank) = rules::bank() {
        for r in &bank.rules {
            let ke = rule_key(&r.id, "enabled");
            let kc = rule_key(&r.id, "confidence");
            let s = if l.from_file.contains(&ke) || l.from_file.contains(&kc) {
                "file"
            } else {
                "default"
            };
            out.push_str(&format!(
                "care.rules.\"{}\" = {{ enabled = {}, confidence = {:?} }}  # {s}\n",
                r.id,
                t.care.rule_enabled(&r.id),
                t.care.rule_confidence(&r.id, r.confidence),
            ));
        }
    }
    out
}

/// The commented tunables section of `cancelli config --init`: every
/// tunable at its default with a one-line meaning and its provenance, all
/// commented out (`# `), explanations as `## `. Uncommenting any line
/// (with its `[table]` header) sets that value.
pub fn init_template() -> String {
    let def = Tunables::default();
    let values: BTreeMap<String, Value> = def.canonical();
    let mut out = String::from(
        "\n## ---------------------------------------------------------------- tunables\n\
         ## D18-D20. Every knob of CARE ([care]) and of the Jev adjudicator ([jev]) at\n\
         ## its built-in default, commented out so this file documents them without\n\
         ## pinning them. Uncomment a line and its [table] header to change a value.\n\
         ## An invalid value falls back to its own default with an error record; every\n\
         ## log record carries config_fingerprint and overrides[] (keys != default).\n\
         ## The jev tier thresholds were calibrated on the embedded rubric and the\n\
         ## ProCreations corpus (FINDINGS §5); recalibrate before trusting changes.\n",
    );
    let mut current = String::new();
    // `[judge]` keys live in the [judge] table of `config::DEFAULT_FILE`.
    for k in KNOBS.iter().filter(|k| !k.key.starts_with("judge.")) {
        let (table, leaf) = table_of(k.key);
        if table != current {
            out.push_str(&format!("\n# [{table}]\n"));
            current = table.to_string();
        }
        let v = if k.key == "jev.rubric_file" {
            "\"~/path/to/rubric.yaml\"".to_string()
        } else {
            toml_value(&values[k.key])
        };
        out.push_str(&format!(
            "## {}. Source: {}\n# {leaf} = {v}\n",
            k.doc, k.source
        ));
    }
    out.push_str(
        "\n## Per-rule overrides by SE-P id (data/rule_provenance.json): enabled = false\n\
         ## removes the rule from L4 and p_rule; confidence replaces the bank value in\n\
         ## π·conf and p_rule. Equivalent long form: [care.rules.\"SE-P-103\"] confidence = 0.85\n\
         # [care.rules]\n",
    );
    if let Ok(bank) = rules::bank() {
        for r in &bank.rules {
            out.push_str(&format!(
                "# \"{}\" = {{ enabled = {}, confidence = {:?} }}  # {} {}: {}\n",
                r.id,
                def.care.rule_enabled(&r.id),
                def.care.rule_confidence(&r.id, r.confidence),
                r.tier.as_str(),
                r.family,
                r.description
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_str(s: &str) -> (Loaded, Vec<Diagnostic>) {
        let t: Table = s.parse().unwrap();
        let mut d = Vec::new();
        let l = load(Some(&t), &Env::default(), &mut d);
        (l, d)
    }

    #[test]
    fn skip_tools_is_validated_sorted_and_fingerprinted() {
        let (l, d) = load_str("[jev]\nskip_tools = [\"Write\", \"Read\", \"Read\"]\n");
        assert!(d.is_empty(), "{d:?}");
        let j = &l.tunables.jev;
        assert_eq!(j.skip_tools, vec!["Read".to_string(), "Write".to_string()]);
        assert!(j.skips("Read") && !j.skips("read") && !j.skips("Edit"));
        assert_eq!(l.tunables.overrides(), vec!["jev.skip_tools".to_string()]);
        assert_ne!(l.tunables.fingerprint(), Tunables::default().fingerprint());
        // order and duplicates don't change the fingerprint
        let (l2, _) = load_str("[jev]\nskip_tools = [\"Read\", \"Write\"]\n");
        assert_eq!(l.tunables.fingerprint(), l2.tunables.fingerprint());
        // explicit empty list == default
        let (l3, _) = load_str("[jev]\nskip_tools = []\n");
        assert!(l3.tunables.overrides().is_empty());
        for bad in [
            "skip_tools = \"Read\"",
            "skip_tools = [\"Read\", 3]",
            "skip_tools = [\"\"]",
            "skip_tools = [\" Read\"]",
        ] {
            let (l, d) = load_str(&format!("[jev]\n{bad}\n"));
            assert!(l.tunables.jev.skip_tools.is_empty(), "{bad}");
            assert!(
                d.iter()
                    .any(|x| x.level == "error" && x.message.starts_with("jev.skip_tools")),
                "{bad}: {d:?}"
            );
        }
        let (_, d) = load_str("[jev]\nskip_tools = [\"Bash\"]\n");
        assert!(
            d.iter()
                .any(|x| x.level == "warning" && x.message.contains("Bash"))
        );
    }

    #[test]
    fn defaults_are_the_builtin_constants() {
        let t = Tunables::default();
        assert_eq!(t.care.weights.sem, 0.30);
        // D27 wide-WARN profile on top of the paper values.
        assert_eq!(
            t.care.modes.balanced,
            Band {
                tau_low: 0.04,
                tau_high: 0.55
            }
        );
        assert_eq!(t.care.modes.strict, Band::of(Mode::Strict));
        assert_eq!(t.care.modes.auto, Band::of(Mode::Auto));
        assert!(t.care.h_sem.is_empty());
        assert_eq!(t.care.rule_confidence("SE-P-003", 0.95), 0.75);
        assert_eq!(t.care.rules.len(), 1);
        let p = CareTunables::paper();
        assert_eq!(
            p.modes.balanced,
            Band {
                tau_low: 0.15,
                tau_high: 0.35
            }
        );
        assert_eq!(p.h_sem.len(), 5);
        assert!(p.rules.is_empty());
        assert_eq!(
            CareTunables {
                modes: t.care.modes,
                h_sem: t.care.h_sem.clone(),
                rules: t.care.rules.clone(),
                ..p
            },
            t.care,
            "the default differs from the paper only in the D27 keys"
        );
        assert_eq!(
            t.jev.verdicts.map(|v| v.as_str()),
            ["deny", "deny", "ask", "ask", "ask", "allow"]
        );
        for (id, tier) in TierId::ALL.iter().zip(TIERS.iter()) {
            assert_eq!(
                crate::jev::decide::rule_text(*id, &t.jev.thresholds),
                tier.rule
            );
        }
        assert!(t.overrides().is_empty());
        // Per-rule keys (D27 default overrides) are documented separately.
        let keys: Vec<String> = t
            .entries()
            .into_iter()
            .map(|(k, _)| k)
            .filter(|k| !k.starts_with("care.rules."))
            .collect();
        let knobs: Vec<&str> = KNOBS.iter().map(|k| k.key).collect();
        assert_eq!(keys, knobs, "KNOBS documents every key, in order");
    }

    /// D27: a rule key left out keeps the default override; a value equal
    /// to the bank's clears it; the paper profile is one file away.
    #[test]
    fn rule_overrides_merge_with_the_default() {
        let key = "care.rules.\"SE-P-003\".confidence".to_string();
        let (l, d) = load_str("[care.rules]\n\"SE-P-003\" = { enabled = true }\n");
        assert!(d.is_empty(), "{d:?}");
        assert_eq!(l.tunables.care.rule_confidence("SE-P-003", 0.95), 0.75);
        assert!(l.tunables.overrides().is_empty());

        let (l, _) = load_str("[care.rules]\n\"SE-P-003\" = { confidence = 0.95 }\n");
        assert!(l.tunables.care.rules.is_empty());
        assert_eq!(l.tunables.overrides(), vec![key.clone()]);

        let (l, _) = load_str("[care.rules]\n\"SE-P-003\" = { enabled = false }\n");
        let o = &l.tunables.care.rules["SE-P-003"];
        assert!(!o.enabled);
        assert_eq!(o.confidence, Some(0.75));

        let (l, d) = load_str(
            "[care.modes.balanced]\ntau_low = 0.15\ntau_high = 0.35\n\
             [care.resolution]\nh_sem = [\"NETWORK_FETCH\", \"EXECUTION_CHAIN\", \
             \"PRIVILEGE_OR_PERMISSION\", \"PERSISTENCE\", \"DESTRUCTIVE\"]\n\
             [care.rules]\n\"SE-P-003\" = { confidence = 0.95 }\n",
        );
        assert!(d.is_empty(), "{d:?}");
        assert_eq!(l.tunables.care, CareTunables::paper());
    }

    #[test]
    fn per_key_fallback_and_errors_name_the_key() {
        let (l, d) = load_str(
            "[care.weights]\nsem = -1\npath = 0.5\n[care.modes.balanced]\ntau_low = 0.6\n\
             [care.rules.\"SE-P-999\"]\nenabled = false\n[care.rules.\"bogus\"]\nenabled = false\n\
             [jev.tiers]\norder = [\"T1\", \"T9\"]\n[jev.verdicts]\nT7 = \"deny\"\n",
        );
        let c = &l.tunables.care;
        assert_eq!(c.weights.sem, 0.30);
        assert_eq!(c.weights.path, 0.5, "the rest of the section applies");
        assert_eq!(
            c.modes.balanced, WIDE_WARN_BALANCED,
            "falls back to the default"
        );
        assert_eq!(l.tunables.jev.tier_order.len(), 5);
        let errs: Vec<&str> = d
            .iter()
            .filter(|x| x.level == "error")
            .map(|x| x.message.as_str())
            .collect();
        for key in [
            "care.weights.sem",
            "care.modes.balanced.tau_low",
            "care.rules.\"SE-P-999\"",
            "care.rules.\"bogus\"",
            "jev.tiers.order",
            "jev.verdicts.T7",
        ] {
            assert!(errs.iter().any(|e| e.starts_with(key)), "{key} in {errs:?}");
        }
        assert_eq!(
            l.tunables.overrides(),
            vec!["care.weights.path".to_string()]
        );
    }

    #[test]
    fn rule_overrides_equal_to_the_bank_are_not_overrides() {
        let (l, d) = load_str("[care.rules.\"SE-P-103\"]\nenabled = true\nconfidence = 0.75\n");
        assert!(d.is_empty(), "{d:?}");
        assert!(l.tunables.overrides().is_empty());
        assert!(l.from_file.contains("care.rules.\"SE-P-103\".confidence"));
    }

    #[test]
    fn fingerprint_ignores_layout_and_spelling() {
        let (a, _) =
            load_str("[care.weights]\nsem = 0.5\npath = 1\n[care.provenance]\nmitre = 0.9\n");
        let (b, _) =
            load_str("care.provenance.mitre = 0.9\n[care.weights]\npath = 1.0\nsem = 0.50\n");
        assert_eq!(a.tunables.fingerprint(), b.tunables.fingerprint());
        assert_ne!(a.tunables.fingerprint(), Tunables::default().fingerprint());
        assert_eq!(a.tunables.fingerprint().len(), 16);
    }
}
