//! D24: `cancelli calibrate --reference <files…> --out <file>` fits a
//! calibration file (see [`crate::jev::calibration`]) from paired answers:
//! the reference is Jev (`jev-1.13.0`), the target is the configured
//! `/v1/systemone` backend on the same states.
//!
//! Each line of each `--reference` file is one of:
//!
//! * a **pair** (fixture / `--pairs-out` output): `{"id", "reference":
//!   {answers}, "target": {answers}, "target_model", "rubric_hash"?}`;
//! * a **tte run row** (`tte/data/runs/*.jsonl`): `state_rendered` +
//!   `answers` (Jev) + `rubric_hash` + `model`;
//! * a **cancelli log record** whose `judge` holds a successful Jev call
//!   (`state` + `answers`, `model` = `jev-1.13.0`).
//!
//! Rows and records only carry the reference; the target is obtained by
//! sending their state to the configured backend with the questions Jev
//! answered (raw answers, before any calibration). `--offline` never
//! queries and fits only on pair lines. Items whose rubric_hash differs
//! from the rubric in use are skipped.
//!
//! Items are split once with a fixed seed into a fitting set and a
//! held-out set (`--holdout`, default 0.25); parameters are fitted on the
//! first, Brier/ECE before and after are measured only on the second.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::config::{self, CliOverrides, Env};
use crate::hook;
use crate::jev::calibration::{
    self, AxisCal, CalibrationFile, FORMAT, Method, Metrics, ScalarPair, VecPair, brier, ece,
    fit_platt, fit_temperature, platt, temper,
};
use crate::jev::client::{self, DEFAULT_EXPECTED_MODEL};
use crate::jev::decide::{Answers, WireAnswer};
use crate::jev::rubric::{Primitive, Rubric};
use crate::jev::{self, request_body};
use crate::logging;

/// `cancelli calibrate` arguments.
#[derive(Debug, Clone)]
pub struct CalibrateArgs {
    /// Reference inputs (pairs, tte runs, cancelli logs).
    pub reference: Vec<PathBuf>,
    /// Calibration file to write.
    pub out: PathBuf,
    /// Never query the backend (fit on pair lines only).
    pub offline: bool,
    /// Also write every pair used as JSONL (refit later with `--offline`).
    pub pairs_out: Option<PathBuf>,
    /// Target model to pin (default: the backend's reported model).
    pub model: Option<String>,
    /// Held-out fraction.
    pub holdout: f64,
    /// Split seed.
    pub seed: u64,
    /// At most this many reference items (after deduplication).
    pub limit: Option<usize>,
    /// Fewest fitting pairs per axis.
    pub min_pairs: usize,
}

impl CalibrateArgs {
    /// Defaults for everything but inputs and output.
    pub fn new(reference: Vec<PathBuf>, out: PathBuf) -> Self {
        CalibrateArgs {
            reference,
            out,
            offline: false,
            pairs_out: None,
            model: None,
            holdout: 0.25,
            seed: 42,
            limit: None,
            min_pairs: 10,
        }
    }
}

#[derive(Debug, Clone)]
struct Item {
    id: String,
    reference: Answers,
    reference_raw: Value,
    state: Option<String>,
    target: Option<(String, Answers, Value)>,
}

fn answers_of(v: &Value) -> Option<Answers> {
    serde_json::from_value(v.clone()).ok()
}

/// Classify one input line into an item, or a skip reason.
fn item_of(v: &Value, rubric_hash: &str, n: usize) -> Result<Item, String> {
    let rh = |x: Option<&Value>| -> Result<(), String> {
        match x.and_then(Value::as_str) {
            Some(h) if h != rubric_hash => Err(format!("rubric_hash {h} (not {rubric_hash})")),
            _ => Ok(()),
        }
    };
    if let (Some(r), Some(t)) = (v.get("reference"), v.get("target")) {
        rh(v.get("rubric_hash"))?;
        let reference = answers_of(r).ok_or("pair: unparseable reference answers")?;
        let target = answers_of(t).ok_or("pair: unparseable target answers")?;
        let model = v
            .get("target_model")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        return Ok(Item {
            id: v
                .get("id")
                .and_then(Value::as_str)
                .map_or_else(|| format!("pair-{n}"), str::to_string),
            reference,
            reference_raw: r.clone(),
            state: v.get("state").and_then(Value::as_str).map(str::to_string),
            target: Some((model, target, t.clone())),
        });
    }
    let (state, answers, model, rhash, id) = if let Some(s) = v.get("state_rendered") {
        if !v.get("error").is_none_or(Value::is_null) {
            return Err("tte row: Jev error".into());
        }
        (
            s,
            v.get("answers"),
            v.get("model"),
            v.get("rubric_hash"),
            v.get("item_id")
                .and_then(Value::as_str)
                .map_or_else(|| format!("row-{n}"), str::to_string),
        )
    } else if let Some(j) = v.get("judge").filter(|j| j.get("state").is_some()) {
        if !j.get("error").is_none_or(Value::is_null) {
            return Err("cancelli record: judge call failed".into());
        }
        (
            &j["state"],
            j.get("answers"),
            j.get("model"),
            j.get("rubric_hash"),
            v.get("tool_use_id")
                .and_then(Value::as_str)
                .map_or_else(|| format!("record-{n}"), str::to_string),
        )
    } else {
        return Err("not a pair, tte row or cancelli judge record".into());
    };
    if model.and_then(Value::as_str) != Some(DEFAULT_EXPECTED_MODEL) {
        return Err(format!("reference is not {DEFAULT_EXPECTED_MODEL}"));
    }
    rh(rhash)?;
    let raw = answers.filter(|a| a.is_object()).ok_or("no answers")?;
    Ok(Item {
        id,
        reference: answers_of(raw).ok_or("unparseable answers")?,
        reference_raw: raw.clone(),
        state: Some(state.as_str().ok_or("state is not a string")?.to_string()),
        target: None,
    })
}

/// Aligned `(target, reference)` probability vectors of one axis, labels
/// in the reference's order (a label the target lacks counts 0).
fn vectors(t: &WireAnswer, r: &WireAnswer) -> Option<(Vec<f64>, Vec<f64>)> {
    let rp = r.probabilities.as_ref().filter(|p| !p.0.is_empty())?;
    let tp = t.probabilities.as_ref().filter(|p| !p.0.is_empty())?;
    let q: Vec<f64> = rp.0.iter().map(|x| x.1).collect();
    let p: Vec<f64> =
        rp.0.iter()
            .map(|(l, _)| tp.0.iter().find(|(k, _)| k == l).map_or(0.0, |x| x.1))
            .collect();
    Some((p, q))
}

/// Per-axis fit report line.
#[derive(Debug, Clone)]
pub struct AxisReport {
    /// Axis id.
    pub axis: String,
    /// Answer type.
    pub kind: String,
    /// The fitted calibration (None: skipped).
    pub fitted: Option<AxisCal>,
    /// Why it was skipped.
    pub skipped: Option<String>,
}

/// Result of a calibrate run.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The written file.
    pub file: CalibrationFile,
    /// Per-axis report.
    pub axes: Vec<AxisReport>,
    /// Input lines skipped, by reason.
    pub skipped: BTreeMap<String, usize>,
    /// Pairs used (fitting + held-out).
    pub pairs: usize,
    /// Backend queries made.
    pub queried: usize,
}

fn pairs_for(axis: &str, prim: Primitive, items: &[&Item]) -> (Vec<ScalarPair>, Vec<VecPair>) {
    let mut scalars = Vec::new();
    let mut vecs = Vec::new();
    for it in items {
        let (Some(r), Some((_, t, _))) = (it.reference.get(axis), it.target.as_ref()) else {
            continue;
        };
        let Some(t) = t.get(axis) else { continue };
        if t.kind != prim.as_str() || r.kind != prim.as_str() {
            continue;
        }
        match prim {
            Primitive::Noul => {
                if let (Some(p), Some(q)) = (t.noul, r.noul)
                    && p.is_finite()
                    && q.is_finite()
                {
                    scalars.push((p, q));
                }
            }
            _ => {
                if let Some(pq) = vectors(t, r) {
                    vecs.push(pq);
                }
            }
        }
    }
    (scalars, vecs)
}

fn fit_axis(
    axis: &str,
    prim: Primitive,
    train: &[&Item],
    test: &[&Item],
    min_pairs: usize,
) -> Result<AxisCal, String> {
    let (ts, tv) = pairs_for(axis, prim, train);
    let (es, ev) = pairs_for(axis, prim, test);
    let n = ts.len() + tv.len();
    if n < min_pairs {
        return Err(format!("{n} fitting pairs (< {min_pairs})"));
    }
    let as_vec = |v: &[ScalarPair]| -> Vec<VecPair> {
        v.iter().map(|(p, q)| (vec![*p], vec![*q])).collect()
    };
    let (method, before, after, n_test) = match prim {
        Primitive::Noul => {
            let (a, b) = fit_platt(&ts);
            let before = as_vec(&es);
            let after: Vec<VecPair> = es
                .iter()
                .map(|(p, q)| (vec![platt(*p, a, b)], vec![*q]))
                .collect();
            (Method::Platt { a, b }, before, after, es.len())
        }
        _ => {
            let t = fit_temperature(&tv);
            let after: Vec<VecPair> = ev.iter().map(|(p, q)| (temper(p, t), q.clone())).collect();
            (Method::Temperature { t }, ev.clone(), after, ev.len())
        }
    };
    Ok(AxisCal {
        kind: prim.as_str().to_string(),
        method,
        n,
        metrics: Some(Metrics {
            n_train: n,
            n_test,
            brier_before: brier(&before),
            brier_after: brier(&after),
            ece_before: ece(&before),
            ece_after: ece(&after),
        }),
    })
}

/// Fit and write the calibration file.
pub fn run(args: &CalibrateArgs, env: &Env) -> Result<Outcome, String> {
    if !(0.0..1.0).contains(&args.holdout) {
        return Err("--holdout must be in [0, 1)".into());
    }
    let loaded = config::load(env, &CliOverrides::default());
    let c = &loaded.config;
    let rubric: Rubric = jev::effective_rubric(&c.tunables.jev)?.into_owned();
    let mut skipped: BTreeMap<String, usize> = BTreeMap::new();
    let mut items: Vec<Item> = Vec::new();
    let mut seen_states = BTreeSet::new();
    let mut n = 0usize;
    for f in &args.reference {
        let file = std::fs::File::open(f).map_err(|e| format!("{}: {e}", f.display()))?;
        for line in std::io::BufReader::new(file).lines() {
            let line = line.map_err(|e| format!("{}: {e}", f.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            n += 1;
            let item = serde_json::from_str::<Value>(&line)
                .map_err(|_| "not JSON".to_string())
                .and_then(|v| item_of(&v, &rubric.hash, n));
            match item {
                Err(why) => *skipped.entry(why).or_insert(0) += 1,
                Ok(it) => {
                    if it.target.is_none()
                        && let Some(s) = &it.state
                        && !seen_states.insert(logging::sha256_hex(s.as_bytes()))
                    {
                        *skipped.entry("duplicate state".into()).or_insert(0) += 1;
                        continue;
                    }
                    items.push(it);
                }
            }
        }
    }
    if let Some(l) = args.limit {
        items.truncate(l);
    }

    // Targets for reference-only items.
    let mut queried = 0usize;
    let needs: usize = items.iter().filter(|i| i.target.is_none()).count();
    if needs > 0 && args.offline {
        *skipped
            .entry("needs the backend (--offline)".into())
            .or_insert(0) += needs;
        items.retain(|i| i.target.is_some());
    } else if needs > 0 {
        let expected = &c.tunables.judge.expected_model;
        if expected == DEFAULT_EXPECTED_MODEL {
            return Err(format!(
                "judge.expected_model is {DEFAULT_EXPECTED_MODEL:?}: calibrate fits another \
                 /v1/systemone backend against Jev; point [judge] base_url/expected_model at it \
                 (or use --offline with pair files)"
            ));
        }
        let mut s = hook::jev_settings(c);
        s.calibration = crate::tunables::CalibrationState::None;
        let key = c.api_key(env);
        let secret = jev::key_to_send(&key, &s)?;
        for it in items.iter_mut().filter(|i| i.target.is_none()) {
            let Some(state) = &it.state else { continue };
            let asked: Vec<&str> = rubric
                .axes
                .iter()
                .filter(|a| it.reference.contains_key(&a.id))
                .map(|a| a.id.as_str())
                .collect();
            let questions = crate::jev::pyjson::J::Obj(
                rubric
                    .axes
                    .iter()
                    .filter(|a| asked.contains(&a.id.as_str()))
                    .map(|a| (a.id.clone(), a.question()))
                    .collect(),
            );
            queried += 1;
            match client::post(
                &s.transport,
                secret,
                &request_body(state, &s.model, questions),
            ) {
                Ok(reply) if reply.response.model == *expected => {
                    it.target = Some((
                        reply.response.model,
                        reply.response.answers,
                        reply.answers_raw,
                    ));
                }
                Ok(reply) => {
                    *skipped
                        .entry(format!(
                            "backend reported model {:?} (expected {expected:?})",
                            reply.response.model
                        ))
                        .or_insert(0) += 1;
                }
                Err(f) => {
                    let e = client::redact(&f.error, key.as_ref().ok().map(|(k, _)| k));
                    *skipped
                        .entry(format!(
                            "backend error: {}",
                            e.chars().take(80).collect::<String>()
                        ))
                        .or_insert(0) += 1;
                }
            }
        }
        items.retain(|i| i.target.is_some());
    }
    if items.is_empty() {
        return Err(format!("no usable pairs (skipped: {skipped:?})"));
    }

    // The pinned model.
    let models: BTreeSet<&str> = items
        .iter()
        .filter_map(|i| i.target.as_ref().map(|t| t.0.as_str()))
        .filter(|m| !m.is_empty())
        .collect();
    let model = match (&args.model, models.len()) {
        (Some(m), _) => m.clone(),
        (None, 1) => models
            .iter()
            .next()
            .map(|m| m.to_string())
            .unwrap_or_default(),
        (None, 0) => return Err("the pairs carry no target_model; pass --model".into()),
        (None, _) => {
            return Err(format!(
                "pairs come from several target models {models:?}; pass --model or split the input"
            ));
        }
    };

    if let Some(p) = &args.pairs_out {
        let mut text = String::new();
        for it in &items {
            if let Some((m, _, raw)) = &it.target {
                text.push_str(
                    &json!({
                        "id": it.id,
                        "rubric_hash": rubric.hash,
                        "target_model": m,
                        "reference": it.reference_raw,
                        "target": raw,
                    })
                    .to_string(),
                );
                text.push('\n');
            }
        }
        std::fs::write(p, text).map_err(|e| format!("{}: {e}", p.display()))?;
    }

    // Fixed split by item.
    let mut order: Vec<usize> = (0..items.len()).collect();
    calibration::shuffle(&mut order, args.seed);
    let n_test = (items.len() as f64 * args.holdout).round() as usize;
    let test: Vec<&Item> = order[..n_test].iter().map(|i| &items[*i]).collect();
    let train: Vec<&Item> = order[n_test..].iter().map(|i| &items[*i]).collect();

    let mut axes = BTreeMap::new();
    let mut report = Vec::new();
    for a in &rubric.axes {
        match fit_axis(&a.id, a.primitive, &train, &test, args.min_pairs) {
            Ok(cal) => {
                report.push(AxisReport {
                    axis: a.id.clone(),
                    kind: a.primitive.as_str().into(),
                    fitted: Some(cal.clone()),
                    skipped: None,
                });
                axes.insert(a.id.clone(), cal);
            }
            Err(why) => report.push(AxisReport {
                axis: a.id.clone(),
                kind: a.primitive.as_str().into(),
                fitted: None,
                skipped: Some(why),
            }),
        }
    }
    let inputs: Vec<String> = args
        .reference
        .iter()
        .map(|p| {
            p.file_name()
                .map_or_else(|| p.display().to_string(), |f| f.to_string_lossy().into())
        })
        .collect();
    let file = CalibrationFile {
        format: FORMAT.into(),
        rubric_hash: rubric.hash.clone(),
        model,
        fitted_at: logging::ts(logging::now()),
        source: format!(
            "cancelli {} calibrate --reference {} ({} pairs, holdout {}, seed {})",
            crate::VERSION,
            inputs.join(" "),
            items.len(),
            args.holdout,
            args.seed
        ),
        axes,
    };
    let text = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())? + "\n";
    std::fs::write(&args.out, text).map_err(|e| format!("{}: {e}", args.out.display()))?;
    Ok(Outcome {
        file,
        axes: report,
        skipped,
        pairs: items.len(),
        queried,
    })
}

fn f4(x: Option<f64>) -> String {
    x.map_or_else(|| "n/a".into(), |v| format!("{v:.4}"))
}

/// The per-axis report printed after fitting.
pub fn render(o: &Outcome, out: &std::path::Path) -> String {
    let mut s = format!(
        "wrote {} (model {:?}, rubric_hash {}, {} pairs, {} backend queries)\n",
        out.display(),
        o.file.model,
        o.file.rubric_hash,
        o.pairs,
        o.queried
    );
    for (why, n) in &o.skipped {
        s.push_str(&format!("skipped {n}: {why}\n"));
    }
    s.push_str(&format!(
        "{:<28} {:<7} {:>6} {:>5} {:<22} {:>15} {:>15}\n",
        "axis", "type", "n_fit", "n_out", "parameters", "brier before→after", "ece before→after"
    ));
    for a in &o.axes {
        match &a.fitted {
            Some(c) => {
                let m = c.metrics.unwrap_or_default();
                let p = match c.method {
                    Method::Platt { a, b } => format!("a={a:.3} b={b:.3}"),
                    Method::Temperature { t } => format!("t={t:.3}"),
                };
                s.push_str(&format!(
                    "{:<28} {:<7} {:>6} {:>5} {:<22} {:>7}→{:<7} {:>7}→{:<7}\n",
                    a.axis,
                    a.kind,
                    m.n_train,
                    m.n_test,
                    p,
                    f4(m.brier_before),
                    f4(m.brier_after),
                    f4(m.ece_before),
                    f4(m.ece_after)
                ));
            }
            None => s.push_str(&format!(
                "{:<28} {:<7} skipped: {}\n",
                a.axis,
                a.kind,
                a.skipped.as_deref().unwrap_or("")
            )),
        }
    }
    s
}
