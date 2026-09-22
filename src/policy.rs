//! L5 — weighted aggregation and provisional triage (policy.py, modes.py).

use serde::{Deserialize, Serialize};

/// Aggregation weights (paper App. A.5; policy.py:15-18).
pub const W_SEM: f64 = 0.30;
/// Path weight.
pub const W_PATH: f64 = 0.30;
/// Pattern weight.
pub const W_PAT: f64 = 0.30;
/// Structure weight.
pub const W_STRUCT: f64 = 0.10;

/// Operating mode (modes.py:32-55): thresholds only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// τ = 0.10 / 0.20.
    Strict,
    /// τ = 0.15 / 0.35 (paper default).
    #[default]
    Balanced,
    /// τ = 0.20 / 0.50.
    Auto,
}

impl Mode {
    /// (τ_low, τ_high).
    pub fn thresholds(self) -> (f64, f64) {
        match self {
            Mode::Strict => (0.10, 0.20),
            Mode::Balanced => (0.15, 0.35),
            Mode::Auto => (0.20, 0.50),
        }
    }

    /// Lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Strict => "strict",
            Mode::Balanced => "balanced",
            Mode::Auto => "auto",
        }
    }

    /// Parse a mode name.
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "strict" => Some(Mode::Strict),
            "balanced" => Some(Mode::Balanced),
            "auto" => Some(Mode::Auto),
            _ => None,
        }
    }
}

/// Provisional verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    /// Below τ_low.
    Allow,
    /// In [τ_low, τ_high).
    Warn,
    /// At or above τ_high.
    Deny,
}

impl Verdict {
    /// Upper-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "ALLOW",
            Verdict::Warn => "WARN",
            Verdict::Deny => "DENY",
        }
    }
}

/// Eq. 6, evaluated in the reference's operand order so results are
/// bit-identical to Python.
pub fn compose(sem: f64, path: f64, pat: f64, strukt: f64) -> f64 {
    W_SEM * sem + W_PATH * path + W_PAT * pat + W_STRUCT * strukt
}

/// Eq. 7.
pub fn decide(score: f64, mode: Mode) -> Verdict {
    let (lo, hi) = mode.thresholds();
    if score < lo {
        Verdict::Allow
    } else if score < hi {
        Verdict::Warn
    } else {
        Verdict::Deny
    }
}

/// Provisional verdicts for all three modes.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Provisional {
    /// Strict.
    pub strict: Verdict,
    /// Balanced.
    pub balanced: Verdict,
    /// Auto.
    pub auto: Verdict,
}

impl Provisional {
    /// Decide under every mode.
    pub fn of(score: f64) -> Self {
        Provisional {
            strict: decide(score, Mode::Strict),
            balanced: decide(score, Mode::Balanced),
            auto: decide(score, Mode::Auto),
        }
    }

    /// Verdict for one mode.
    pub fn get(&self, m: Mode) -> Verdict {
        match m {
            Mode::Strict => self.strict,
            Mode::Balanced => self.balanced,
            Mode::Auto => self.auto,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paper_case_a() {
        assert!((compose(0.95, 1.0, 1.0, 0.90) - 0.975).abs() < 1e-9);
    }

    #[test]
    fn thresholds() {
        assert_eq!(decide(0.345, Mode::Balanced), Verdict::Warn);
        assert_eq!(decide(0.345, Mode::Strict), Verdict::Deny);
        assert_eq!(decide(0.345, Mode::Auto), Verdict::Warn);
        assert_eq!(decide(0.15, Mode::Balanced), Verdict::Warn);
        assert_eq!(decide(0.1499, Mode::Balanced), Verdict::Allow);
    }
}
