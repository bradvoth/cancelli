//! D24: optional per-axis calibration of a `/v1/systemone` backend's
//! answers onto Jev's scale, so the tier thresholds (calibrated on
//! `jev-1.13.0`) keep their meaning for another backend.
//!
//! The file (`[judge] calibration_file`, JSON) is pinned to the rubric
//! (`rubric_hash`) and to the backend's *reported* model (`model`); a
//! mismatch, or an unreadable/invalid file, refuses calibration and the
//! judge call fails to `ask` with an error (D15) — uncalibrated values are
//! never used silently.
//!
//! ```json
//! {
//!   "format": "cancelli-calibration/1",
//!   "rubric_hash": "0fd1f245ae1c7ef3",
//!   "model": "qwen-local",
//!   "fitted_at": "2026-09-22T12:00:00Z",
//!   "source": "cancelli calibrate --reference runs.jsonl",
//!   "axes": {
//!     "f5_exceeds_approval": {"type": "noul", "method": "platt", "a": 1.3, "b": -0.2, "n": 200},
//!     "a6_destination_class": {"type": "choice", "method": "temperature", "t": 0.7, "n": 200},
//!     "b4_reversibility": {"type": "score", "method": "temperature", "t": 1.4, "n": 200}
//!   }
//! }
//! ```
//!
//! * `noul`, method `platt`: `p' = σ(a·logit(p) + b)`, `p` clamped to
//!   `[1e-6, 1 − 1e-6]`.
//! * `choice` / `score`, method `temperature`: `p'_k ∝ max(p_k, 1e-6)^(1/t)`
//!   (temperature on the log-probabilities, renormalised); a choice's
//!   `choice` becomes the argmax, a score's `score` becomes `Σ k·p'_k`.
//! * `method` is a tag, so later methods (e.g. `isotonic`) can be added; an
//!   unknown method makes the file invalid.
//! * Axes absent from the file are used as reported.
//!
//! Fitting (`cancelli calibrate`): Platt minimises the cross-entropy against
//! Jev's `p` as a soft target (Newton's method; convex); the temperature
//! minimises `Σ KL(q_jev ‖ p'_t)` (golden-section search over `1/t`;
//! convex in `1/t`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::decide::{Answers, Ordered, WireAnswer};
use super::rubric::{Primitive, Rubric};

/// A `(target p, reference q)` pair of noul probabilities.
pub type ScalarPair = (f64, f64);
/// A `(target, reference)` pair of aligned probability vectors.
pub type VecPair = (Vec<f64>, Vec<f64>);

/// The `format` tag of version 1 files.
pub const FORMAT: &str = "cancelli-calibration/1";
/// Probability floor for logits and log-probabilities.
pub const EPS: f64 = 1e-6;

/// A calibration method with its parameters.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum Method {
    /// `σ(a·logit(p) + b)` (noul).
    Platt {
        /// Slope on `logit(p)`.
        a: f64,
        /// Intercept.
        b: f64,
    },
    /// `softmax(log p / t)` (choice, score).
    Temperature {
        /// Temperature (> 0).
        t: f64,
    },
}

/// Held-out quality of a fit (`cancelli calibrate`); informational.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct Metrics {
    /// Items the parameters were fitted on.
    pub n_train: usize,
    /// Held-out items the numbers below are measured on.
    pub n_test: usize,
    /// Brier vs Jev, uncalibrated.
    pub brier_before: Option<f64>,
    /// Brier vs Jev, calibrated.
    pub brier_after: Option<f64>,
    /// ECE vs Jev, uncalibrated.
    pub ece_before: Option<f64>,
    /// ECE vs Jev, calibrated.
    pub ece_after: Option<f64>,
}

/// One axis' calibration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AxisCal {
    /// Answer type: `noul` | `choice` | `score`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Method and parameters.
    #[serde(flatten)]
    pub method: Method,
    /// Pairs fitted on.
    pub n: usize,
    /// Held-out metrics, when fitted by `cancelli calibrate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Metrics>,
}

/// The calibration file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationFile {
    /// [`FORMAT`].
    pub format: String,
    /// Rubric the answers were fitted under.
    pub rubric_hash: String,
    /// The backend's reported `response.model`.
    pub model: String,
    /// When it was fitted (RFC 3339).
    pub fitted_at: String,
    /// What it was fitted from.
    pub source: String,
    /// Per-axis parameters.
    pub axes: BTreeMap<String, AxisCal>,
}

/// A loaded, validated calibration.
#[derive(Debug, Clone, PartialEq)]
pub struct Calibration {
    /// Contents.
    pub file: CalibrationFile,
    /// Where it was read from.
    pub path: PathBuf,
    /// First 16 hex digits of the file's sha256 (fingerprinted, logged).
    pub sha: String,
}

/// What the judge record logs about the calibration applied.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Applied {
    /// File path.
    pub file: String,
    /// File sha (16 hex).
    pub sha: String,
    /// Pinned rubric hash.
    pub rubric_hash: String,
    /// Pinned model.
    pub model: String,
    /// `fitted_at`.
    pub fitted_at: String,
    /// Axes that were transformed.
    pub axes: Vec<String>,
}

impl CalibrationFile {
    /// Structural validation against the rubric in use (not the model:
    /// that is checked against every response).
    pub fn validate(&self, rubric: &Rubric) -> Result<(), String> {
        if self.format != FORMAT {
            return Err(format!("format {:?} is not {FORMAT:?}", self.format));
        }
        if self.rubric_hash != rubric.hash {
            return Err(format!(
                "rubric_hash {:?} does not match the rubric in use {:?}",
                self.rubric_hash, rubric.hash
            ));
        }
        if self.model.trim().is_empty() {
            return Err("model is empty".into());
        }
        for (id, c) in &self.axes {
            let axis = rubric
                .axis(id)
                .ok_or_else(|| format!("axis {id:?} is not in rubric {}", rubric.hash))?;
            if c.kind != axis.primitive.as_str() {
                return Err(format!(
                    "axis {id}: type {:?} but the rubric asks {:?}",
                    c.kind,
                    axis.primitive.as_str()
                ));
            }
            match (axis.primitive, c.method) {
                (Primitive::Noul, Method::Platt { a, b }) => {
                    if !(a.is_finite() && b.is_finite()) {
                        return Err(format!("axis {id}: platt a/b must be finite"));
                    }
                }
                (Primitive::Choice | Primitive::Score, Method::Temperature { t }) => {
                    if !(t.is_finite() && t > 0.0) {
                        return Err(format!("axis {id}: temperature t must be finite and > 0"));
                    }
                }
                (p, m) => {
                    return Err(format!(
                        "axis {id}: method {} does not apply to {} answers",
                        method_name(&m),
                        p.as_str()
                    ));
                }
            }
        }
        Ok(())
    }
}

fn method_name(m: &Method) -> &'static str {
    match m {
        Method::Platt { .. } => "platt",
        Method::Temperature { .. } => "temperature",
    }
}

/// Parse file text (JSON) into a validated calibration.
pub fn parse(text: &str, path: &Path, rubric: &Rubric) -> Result<Calibration, String> {
    let file: CalibrationFile =
        serde_json::from_str(text).map_err(|e| format!("invalid calibration JSON: {e}"))?;
    file.validate(rubric)?;
    Ok(Calibration {
        file,
        path: path.to_path_buf(),
        sha: crate::logging::sha256_hex(text.as_bytes())[..16].to_string(),
    })
}

/// Read and validate a calibration file.
pub fn load(path: &Path, rubric: &Rubric) -> Result<Calibration, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    parse(&text, path, rubric)
}

/// `σ(x)`.
pub fn sigmoid(x: f64) -> f64 {
    if x >= 0.0 {
        1.0 / (1.0 + (-x).exp())
    } else {
        let e = x.exp();
        e / (1.0 + e)
    }
}

/// `logit(p)` with `p` clamped to `[EPS, 1 − EPS]`.
pub fn logit(p: f64) -> f64 {
    let p = p.clamp(EPS, 1.0 - EPS);
    (p / (1.0 - p)).ln()
}

/// Platt transform.
pub fn platt(p: f64, a: f64, b: f64) -> f64 {
    sigmoid(a * logit(p) + b)
}

/// Temperature transform of a probability vector (renormalised; floors at
/// [`EPS`]).
pub fn temper(p: &[f64], t: f64) -> Vec<f64> {
    let logits: Vec<f64> = p.iter().map(|x| x.max(EPS).ln() / t).collect();
    let m = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let e: Vec<f64> = logits.iter().map(|l| (l - m).exp()).collect();
    let z: f64 = e.iter().sum();
    e.into_iter().map(|x| x / z).collect()
}

/// Apply one axis' calibration to one answer.
pub fn apply_answer(id: &str, c: &AxisCal, w: &WireAnswer) -> Result<WireAnswer, String> {
    let mut out = w.clone();
    if w.kind != c.kind {
        return Err(format!(
            "axis {id}: answer type {:?} but the calibration is for {:?}",
            w.kind, c.kind
        ));
    }
    match c.method {
        Method::Platt { a, b } => {
            let p = w
                .noul
                .ok_or_else(|| format!("axis {id}: noul answer without a value"))?;
            out.noul = Some(platt(p, a, b));
        }
        Method::Temperature { t } => {
            let probs = w
                .probabilities
                .as_ref()
                .filter(|p| !p.0.is_empty())
                .ok_or_else(|| format!("axis {id}: {} answer without probabilities", w.kind))?;
            let q = temper(&probs.0.iter().map(|x| x.1).collect::<Vec<_>>(), t);
            let labels: Vec<(String, f64)> = probs
                .0
                .iter()
                .zip(q)
                .map(|((k, _), v)| (k.clone(), v))
                .collect();
            if w.kind == "score" {
                let mut s = 0.0;
                for (k, v) in &labels {
                    let lvl: f64 = k
                        .parse()
                        .map_err(|_| format!("axis {id}: score label {k:?} is not a level"))?;
                    s += lvl * v;
                }
                out.score = Some(s);
            } else {
                // first maximum, in wire order (like the signals' argmax)
                let mut top = &labels[0];
                for kv in &labels[1..] {
                    if kv.1 > top.1 {
                        top = kv;
                    }
                }
                out.choice = Some(top.0.clone());
            }
            out.probabilities = Some(Ordered(labels));
        }
    }
    Ok(out)
}

impl Calibration {
    /// Refuse a response the file is not pinned to (D24).
    pub fn check(&self, rubric_hash: &str, model: &str) -> Result<(), String> {
        if self.file.rubric_hash != rubric_hash {
            return Err(format!(
                "calibration_file {} is pinned to rubric_hash {:?}, not {rubric_hash:?}; refusing calibration",
                self.path.display(),
                self.file.rubric_hash
            ));
        }
        if self.file.model != model {
            return Err(format!(
                "calibration_file {} is pinned to model {:?}, but the backend reported {model:?}; refusing calibration",
                self.path.display(),
                self.file.model
            ));
        }
        Ok(())
    }

    /// Calibrate every answer the file covers.
    pub fn apply(&self, answers: &Answers) -> Result<(Answers, Vec<String>), String> {
        let mut out = answers.clone();
        let mut done = Vec::new();
        for (id, c) in &self.file.axes {
            if let Some(w) = answers.get(id) {
                out.insert(id.clone(), apply_answer(id, c, w)?);
                done.push(id.clone());
            }
        }
        Ok((out, done))
    }

    /// The log view.
    pub fn applied(&self, axes: Vec<String>) -> Applied {
        Applied {
            file: self.path.display().to_string(),
            sha: self.sha.clone(),
            rubric_hash: self.file.rubric_hash.clone(),
            model: self.file.model.clone(),
            fitted_at: self.file.fitted_at.clone(),
            axes,
        }
    }
}

// ------------------------------------------------------------- fitting --

/// Fit Platt `(a, b)` minimising `−Σ [q ln s + (1−q) ln(1−s)]`,
/// `s = σ(a·logit(p) + b)`, for pairs `(p_target, q_reference)`.
pub fn fit_platt(pairs: &[ScalarPair]) -> (f64, f64) {
    let xs: Vec<(f64, f64)> = pairs.iter().map(|(p, q)| (logit(*p), *q)).collect();
    let loss = |a: f64, b: f64| -> f64 {
        xs.iter()
            .map(|(x, q)| {
                let s = sigmoid(a * x + b).clamp(1e-15, 1.0 - 1e-15);
                -(q * s.ln() + (1.0 - q) * (1.0 - s).ln())
            })
            .sum()
    };
    let (mut a, mut b) = (1.0f64, 0.0f64);
    let mut cur = loss(a, b);
    for _ in 0..200 {
        let (mut ga, mut gb, mut haa, mut hab, mut hbb) = (0.0, 0.0, 1e-9, 0.0, 1e-9);
        for (x, q) in &xs {
            let s = sigmoid(a * x + b);
            let r = s - q;
            let w = s * (1.0 - s);
            ga += r * x;
            gb += r;
            haa += w * x * x;
            hab += w * x;
            hbb += w;
        }
        let det = haa * hbb - hab * hab;
        let (da, db) = if det.abs() > 1e-18 {
            ((hbb * ga - hab * gb) / det, (haa * gb - hab * ga) / det)
        } else {
            (ga / haa, gb / hbb)
        };
        let mut step = 1.0;
        let mut improved = false;
        while step > 1e-6 {
            let (na, nb) = (a - step * da, b - step * db);
            let l = loss(na, nb);
            if l.is_finite() && l <= cur {
                a = na;
                b = nb;
                cur = l;
                improved = true;
                break;
            }
            step /= 2.0;
        }
        if !improved || (da * step).abs() + (db * step).abs() < 1e-12 {
            break;
        }
    }
    (a, b)
}

/// `Σ_k q_k ln(q_k / p_k)` with `p` floored at [`EPS`].
pub fn kl(q: &[f64], p: &[f64]) -> f64 {
    q.iter()
        .zip(p)
        .filter(|(q, _)| **q > 0.0)
        .map(|(q, p)| q * (q / p.max(EPS)).ln())
        .sum()
}

/// Fit the temperature minimising `Σ KL(q ‖ temper(p, t))` for pairs
/// `(p_target, q_reference)` of aligned vectors. Searches `1/t` in
/// `[0.02, 50]`.
pub fn fit_temperature(pairs: &[VecPair]) -> f64 {
    let loss = |beta: f64| -> f64 {
        pairs
            .iter()
            .map(|(p, q)| kl(q, &temper(p, 1.0 / beta)))
            .sum()
    };
    let (mut lo, mut hi) = (0.02f64, 50.0f64);
    let g = (5f64.sqrt() - 1.0) / 2.0;
    let mut c = hi - g * (hi - lo);
    let mut d = lo + g * (hi - lo);
    let (mut fc, mut fd) = (loss(c), loss(d));
    for _ in 0..200 {
        if (hi - lo).abs() < 1e-10 {
            break;
        }
        if fc < fd {
            hi = d;
            d = c;
            fd = fc;
            c = hi - g * (hi - lo);
            fc = loss(c);
        } else {
            lo = c;
            c = d;
            fc = fd;
            d = lo + g * (hi - lo);
            fd = loss(d);
        }
    }
    1.0 / ((lo + hi) / 2.0)
}

/// Mean squared error of predicted vs reference probability vectors (a
/// noul answer is the 1-vector `[p]`; a choice/score the full vector, whose
/// squared errors are summed per item: the multi-class Brier score).
pub fn brier(pairs: &[VecPair]) -> Option<f64> {
    if pairs.is_empty() {
        return None;
    }
    let s: f64 = pairs
        .iter()
        .map(|(p, q)| p.iter().zip(q).map(|(a, b)| (a - b).powi(2)).sum::<f64>())
        .sum();
    Some(s / pairs.len() as f64)
}

/// Expected calibration error with 10 equal-width bins over every predicted
/// probability (class-wise for vectors): `Σ_b (n_b/N)·|mean p_b − mean q_b|`
/// with Jev's probability `q` as the soft target.
pub fn ece(pairs: &[VecPair]) -> Option<f64> {
    let mut bins = [(0usize, 0.0f64, 0.0f64); 10];
    let mut n = 0usize;
    for (p, q) in pairs {
        for (a, b) in p.iter().zip(q) {
            let i = ((a * 10.0).floor() as usize).min(9);
            bins[i].0 += 1;
            bins[i].1 += a;
            bins[i].2 += b;
            n += 1;
        }
    }
    if n == 0 {
        return None;
    }
    Some(
        bins.iter()
            .filter(|b| b.0 > 0)
            .map(|(c, sp, sq)| (*c as f64 / n as f64) * ((sp - sq) / *c as f64).abs())
            .sum(),
    )
}

/// A seeded, platform-independent shuffle (SplitMix64 + Fisher–Yates), for
/// the fixed held-out split.
pub fn shuffle<T>(v: &mut [T], seed: u64) {
    let mut s = seed;
    let mut next = || {
        s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    for i in (1..v.len()).rev() {
        let j = (next() % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jev::rubric::rubric;

    fn file(axes: &str) -> String {
        format!(
            r#"{{"format":"{FORMAT}","rubric_hash":"0fd1f245ae1c7ef3","model":"qwen-local",
            "fitted_at":"2026-09-22T00:00:00Z","source":"test","axes":{{{axes}}}}}"#
        )
    }

    #[test]
    fn parse_validates_against_the_rubric() {
        let r = rubric().unwrap();
        let p = Path::new("/c.json");
        let ok = file(
            r#""f5_exceeds_approval":{"type":"noul","method":"platt","a":2.0,"b":0.5,"n":10},
               "a6_destination_class":{"type":"choice","method":"temperature","t":0.5,"n":10}"#,
        );
        let c = parse(&ok, p, r).unwrap();
        assert_eq!(c.file.axes.len(), 2);
        assert_eq!(c.sha.len(), 16);
        for (bad, why) in [
            (
                file(r#""nope":{"type":"noul","method":"platt","a":1,"b":0,"n":1}"#),
                "not in rubric",
            ),
            (
                file(r#""f5_exceeds_approval":{"type":"noul","method":"temperature","t":1,"n":1}"#),
                "does not apply",
            ),
            (
                file(r#""b4_reversibility":{"type":"score","method":"temperature","t":0,"n":1}"#),
                "> 0",
            ),
            (
                file(r#""f5_exceeds_approval":{"type":"noul","method":"isotonic","n":1}"#),
                "invalid calibration JSON",
            ),
            (
                ok.replace("0fd1f245ae1c7ef3", "ffffffffffffffff"),
                "rubric_hash",
            ),
            (ok.replace(FORMAT, "v0"), "format"),
        ] {
            let e = parse(&bad, p, r).unwrap_err();
            assert!(e.contains(why), "{why}: {e}");
        }
    }

    #[test]
    fn transforms() {
        assert!((platt(0.3, 1.0, 0.0) - 0.3).abs() < 1e-12, "identity");
        assert!(platt(0.3, 1.0, 1.0) > 0.3);
        let t = temper(&[0.7, 0.2, 0.1], 1.0);
        assert!((t[0] - 0.7).abs() < 1e-9);
        let sharp = temper(&[0.7, 0.2, 0.1], 0.5);
        assert!(sharp[0] > 0.7 && (sharp.iter().sum::<f64>() - 1.0).abs() < 1e-12);
        let w: WireAnswer = serde_json::from_str(
            r#"{"type":"score","score":1.0,"probabilities":{"0":0.5,"1":0.0,"2":0.5}}"#,
        )
        .unwrap();
        let c = AxisCal {
            kind: "score".into(),
            method: Method::Temperature { t: 1.0 },
            n: 0,
            metrics: None,
        };
        let o = apply_answer("x", &c, &w).unwrap();
        assert!((o.score.unwrap() - 1.0).abs() < 1e-5);
    }

    #[test]
    fn fitters_recover_known_parameters() {
        // q = σ(a·logit(p) + b) exactly: p = σ((logit(q) − b)/a)
        let (a0, b0) = (1.7, -0.4);
        let pairs: Vec<(f64, f64)> = (1..200)
            .map(|i| {
                let q = i as f64 / 200.0;
                (sigmoid((logit(q) - b0) / a0), q)
            })
            .collect();
        let (a, b) = fit_platt(&pairs);
        assert!((a - a0).abs() < 1e-3 && (b - b0).abs() < 1e-3, "{a} {b}");
        // q = temper(p, t0): p = temper(q, 1/t0)
        let t0 = 0.6;
        let pairs: Vec<(Vec<f64>, Vec<f64>)> = (1..50)
            .map(|i| {
                let x = i as f64 / 50.0;
                let q = vec![x * 0.8, (1.0 - x) * 0.8, 0.2];
                (temper(&q, 1.0 / t0), q)
            })
            .collect();
        let t = fit_temperature(&pairs);
        assert!((t - t0).abs() < 1e-3, "{t}");
    }

    #[test]
    fn metrics_and_shuffle() {
        let same = vec![(vec![0.2, 0.8], vec![0.2, 0.8])];
        assert_eq!(brier(&same), Some(0.0));
        assert_eq!(ece(&same), Some(0.0));
        assert!(brier(&[(vec![1.0], vec![0.0])]).unwrap() == 1.0);
        assert_eq!(brier(&[]), None);
        let mut a: Vec<u32> = (0..20).collect();
        let mut b = a.clone();
        shuffle(&mut a, 42);
        shuffle(&mut b, 42);
        assert_eq!(a, b);
        assert_ne!(a, (0..20).collect::<Vec<_>>());
    }
}
