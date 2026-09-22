//! The Jev rubric, vendored verbatim from the POC
//! (`tte/rubrics/v1_policy_distilled.yaml`, hash `0fd1f245ae1c7ef3`).
//!
//! The instruction and criteria text *is* the calibrated artefact, so the
//! YAML is embedded byte-for-byte and parsed at runtime; a test recomputes
//! `rubric_hash` with the POC's exact algorithm (`jev_gate/rubric.py`) and
//! pins it.

use std::sync::OnceLock;

use serde_yaml::Value as Y;
use sha2::{Digest, Sha256};

use super::pyjson::{J, compact, py_dumps_sorted};
use crate::pyre::py_strip;

/// The embedded rubric YAML.
pub const RUBRIC_YAML: &str = include_str!("../../data/jev/v1_policy_distilled.yaml");
/// The rubric hash the POC's `lint` prints for [`RUBRIC_YAML`].
pub const EXPECTED_RUBRIC_HASH: &str = "0fd1f245ae1c7ef3";
/// Default cut for `use: predicate` (`signals.DEFAULT_THRESHOLD`).
pub const DEFAULT_THRESHOLD: f64 = 0.5;

/// Question primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Primitive {
    /// P(true).
    Noul,
    /// Ordered levels.
    Score,
    /// Label distribution.
    Choice,
}

impl Primitive {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Primitive::Noul => "noul",
            Primitive::Score => "score",
            Primitive::Choice => "choice",
        }
    }
}

/// How a reading is consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Use {
    /// The reading itself.
    Graded,
    /// A boolean at a cut (`>=`).
    Predicate,
}

/// A `when:` gate: read this axis only if `axis` reads strictly above `over`.
#[derive(Debug, Clone, PartialEq)]
pub struct When {
    /// Gate axis id.
    pub axis: String,
    /// Strict lower bound.
    pub over: f64,
}

/// One rubric axis.
#[derive(Debug, Clone)]
pub struct Axis {
    /// Question name.
    pub id: String,
    /// Group letter.
    pub group: String,
    /// Primitive.
    pub primitive: Primitive,
    /// `hazard` | `protective`.
    pub direction: String,
    /// `str(instructions).strip()`.
    pub instructions: String,
    /// Criteria (`true`/`false` keys normalised to strings), YAML order.
    pub criteria: J,
    /// Capability required (`""` = always evaluable).
    pub requires: String,
    /// Consumption.
    pub use_: Use,
    /// Predicate cut (None = [`DEFAULT_THRESHOLD`]).
    pub threshold: Option<f64>,
    /// Gate.
    pub when: Option<When>,
}

impl Axis {
    /// Is the evidence present at these capabilities?
    pub fn available_at(&self, caps: &[&str]) -> bool {
        self.requires.is_empty() || caps.contains(&self.requires.as_str())
    }

    /// Number of criteria levels (score axes).
    pub fn levels(&self) -> usize {
        match &self.criteria {
            J::Arr(a) => a.len(),
            J::Obj(o) => o.len(),
            _ => 0,
        }
    }

    fn identity(&self) -> J {
        J::Obj(vec![
            ("id".into(), J::s(&self.id)),
            ("primitive".into(), J::s(self.primitive.as_str())),
            ("direction".into(), J::s(&self.direction)),
            ("instructions".into(), J::s(&self.instructions)),
            ("criteria".into(), self.criteria.clone()),
            ("requires".into(), J::s(&self.requires)),
        ])
    }

    /// The wire question object.
    pub fn question(&self) -> J {
        J::Obj(vec![
            ("type".into(), J::s(self.primitive.as_str())),
            ("instructions".into(), J::s(&self.instructions)),
            ("criteria".into(), self.criteria.clone()),
        ])
    }
}

/// A loaded rubric.
#[derive(Debug, Clone)]
pub struct Rubric {
    /// `name:`.
    pub name: String,
    /// `model:`.
    pub model: String,
    /// Axes in file order.
    pub axes: Vec<Axis>,
    /// `rubric_hash` (16 hex).
    pub hash: String,
}

impl Rubric {
    /// Axis by id.
    pub fn axis(&self, id: &str) -> Option<&Axis> {
        self.axes.iter().find(|a| a.id == id)
    }

    /// Axes asked at these capabilities (`Rubric.questions(capabilities)`).
    pub fn axes_at<'a>(&'a self, caps: &'a [&'a str]) -> impl Iterator<Item = &'a Axis> + 'a {
        self.axes.iter().filter(move |a| a.available_at(caps))
    }

    /// The `questions` wire object for these capabilities, rubric order.
    pub fn questions_json(&self, caps: &[&str]) -> J {
        J::Obj(
            self.axes_at(caps)
                .map(|a| (a.id.clone(), a.question()))
                .collect(),
        )
    }

    /// Compact wire form of [`Rubric::questions_json`].
    pub fn questions_wire(&self, caps: &[&str]) -> String {
        compact(&self.questions_json(caps))
    }
}

/// `Rubric.hash`: sha256 of `json.dumps(sorted(identities, key=id),
/// sort_keys=True, ensure_ascii=False)`, first 16 hex digits.
pub fn rubric_hash(axes: &[Axis]) -> String {
    let mut ids: Vec<&Axis> = axes.iter().collect();
    ids.sort_by(|a, b| a.id.cmp(&b.id));
    let payload = py_dumps_sorted(&J::Arr(ids.iter().map(|a| a.identity()).collect()));
    let d = Sha256::digest(payload.as_bytes());
    d.iter().map(|x| format!("{x:02x}")).take(8).collect()
}

fn ystr(v: &Y) -> Option<String> {
    match v {
        Y::String(s) => Some(s.clone()),
        Y::Bool(b) => Some(if *b { "True" } else { "False" }.into()),
        Y::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn yf64(v: &Y) -> Option<f64> {
    match v {
        Y::Number(n) => n.as_f64(),
        _ => None,
    }
}

/// `_normalise_criteria` + conversion: YAML booleans as keys become
/// `"true"`/`"false"`; everything keeps document order.
fn criteria_json(v: &Y) -> Result<J, String> {
    match v {
        Y::Mapping(m) => {
            let mut out = Vec::new();
            for (k, x) in m {
                let key = match k {
                    Y::Bool(true) => "true".to_string(),
                    Y::Bool(false) => "false".to_string(),
                    other => ystr(other).ok_or("criteria key is not a scalar")?,
                };
                out.push((key, J::s(ystr(x).ok_or("criteria value is not a scalar")?)));
            }
            Ok(J::Obj(out))
        }
        Y::Sequence(s) => Ok(J::Arr(
            s.iter()
                .map(|x| ystr(x).map(J::Str).ok_or("criteria level is not a scalar"))
                .collect::<Result<_, _>>()?,
        )),
        _ => Err("criteria must be a mapping or a list".into()),
    }
}

/// Parse and validate a rubric (the checks of `rubric._validate` that matter
/// for consumption).
pub fn parse(text: &str) -> Result<Rubric, String> {
    let raw: Y = serde_yaml::from_str(text).map_err(|e| format!("rubric YAML: {e}"))?;
    let get = |m: &Y, k: &str| m.get(k).cloned();
    let axes_raw = raw
        .get("axes")
        .and_then(Y::as_sequence)
        .filter(|s| !s.is_empty())
        .ok_or("rubric has no axes")?;
    let mut axes = Vec::new();
    for (i, ax) in axes_raw.iter().enumerate() {
        let field = |k: &str| {
            get(ax, k)
                .and_then(|v| ystr(&v))
                .ok_or_else(|| format!("axis[{i}]: missing '{k}'"))
        };
        let id = field("id")?;
        let primitive = match field("primitive")?.as_str() {
            "noul" => Primitive::Noul,
            "score" => Primitive::Score,
            "choice" => Primitive::Choice,
            p => return Err(format!("{id}: bad primitive {p:?}")),
        };
        let direction = field("direction")?;
        if direction != "hazard" && direction != "protective" {
            return Err(format!("{id}: bad direction {direction:?}"));
        }
        let instructions = py_strip(&field("instructions")?).to_string();
        let criteria =
            criteria_json(&get(ax, "criteria").ok_or(format!("{id}: missing 'criteria'"))?)
                .map_err(|e| format!("{id}: {e}"))?;
        match (primitive, &criteria) {
            (Primitive::Noul, J::Obj(o))
                if o.len() == 2
                    && o.iter().any(|(k, _)| k == "true")
                    && o.iter().any(|(k, _)| k == "false") => {}
            (Primitive::Score, J::Arr(a)) if (2..=10).contains(&a.len()) => {}
            (Primitive::Choice, J::Obj(o)) if !o.is_empty() => {}
            _ => return Err(format!("{id}: criteria do not fit primitive")),
        }
        let requires = get(ax, "requires")
            .and_then(|v| ystr(&v))
            .unwrap_or_default();
        if !requires.is_empty() && requires != "results" && requires != "actions" {
            return Err(format!("{id}: bad requires {requires:?}"));
        }
        let use_ = match get(ax, "use").and_then(|v| ystr(&v)).as_deref() {
            None | Some("graded") => Use::Graded,
            Some("predicate") => Use::Predicate,
            Some(u) => return Err(format!("{id}: bad use {u:?}")),
        };
        let threshold = match get(ax, "threshold") {
            None => None,
            Some(v) => Some(yf64(&v).ok_or(format!("{id}: threshold not a number"))?),
        };
        let when = match get(ax, "when") {
            None => None,
            Some(w) => Some(When {
                axis: w
                    .get("axis")
                    .and_then(ystr)
                    .ok_or(format!("{id}: when.axis"))?,
                over: w
                    .get("over")
                    .and_then(yf64)
                    .ok_or(format!("{id}: when.over"))?,
            }),
        };
        axes.push(Axis {
            id,
            group: field("group")?,
            primitive,
            direction,
            instructions,
            criteria,
            requires,
            use_,
            threshold,
            when,
        });
    }
    for a in &axes {
        if let Some(w) = &a.when {
            let gate = axes
                .iter()
                .find(|g| g.id == w.axis)
                .ok_or(format!("{}: when names unknown axis", a.id))?;
            if gate.when.is_some() || gate.primitive == Primitive::Choice || gate.id == a.id {
                return Err(format!("{}: invalid when gate {}", a.id, w.axis));
            }
        }
    }
    let hash = rubric_hash(&axes);
    Ok(Rubric {
        name: raw.get("name").and_then(ystr).unwrap_or_default(),
        model: raw.get("model").and_then(ystr).unwrap_or_default(),
        axes,
        hash,
    })
}

/// The embedded rubric, parsed once.
pub fn rubric() -> Result<&'static Rubric, String> {
    static R: OnceLock<Result<Rubric, String>> = OnceLock::new();
    R.get_or_init(|| parse(RUBRIC_YAML))
        .as_ref()
        .map_err(Clone::clone)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rubric_hash_matches_python_algorithm() {
        let r = rubric().unwrap();
        assert_eq!(r.hash, EXPECTED_RUBRIC_HASH);
        assert_eq!(rubric_hash(&r.axes), "0fd1f245ae1c7ef3");
        // order-insensitive, like the POC
        let mut rev = r.axes.clone();
        rev.reverse();
        assert_eq!(rubric_hash(&rev), EXPECTED_RUBRIC_HASH);
        // any text change changes it
        let mut edited = r.axes.clone();
        edited[0].instructions.push(' ');
        assert_ne!(rubric_hash(&edited), EXPECTED_RUBRIC_HASH);
    }

    #[test]
    fn forty_axes_with_declarations() {
        let r = rubric().unwrap();
        assert_eq!(r.name, "v1_policy_distilled");
        assert_eq!(r.model, "jev-1.13.0");
        assert_eq!(r.axes.len(), 40);
        assert_eq!(
            r.axes.iter().filter(|a| a.direction == "hazard").count(),
            36
        );
        let a6 = r.axis("a6_destination_class").unwrap();
        assert_eq!(a6.primitive, Primitive::Choice);
        assert_eq!(a6.use_, Use::Predicate);
        assert_eq!(
            a6.when,
            Some(When {
                axis: "f5_exceeds_approval".into(),
                over: 0.8
            })
        );
        let e2 = r.axis("e2_persistence").unwrap();
        assert_eq!((e2.use_, e2.threshold), (Use::Predicate, Some(0.10)));
        assert_eq!(r.axis("d5_self_justifying").unwrap().requires, "results");
        assert_eq!(
            r.axis("f6_trajectory_escalation").unwrap().requires,
            "actions"
        );
        assert_eq!(r.axis("a4_data_volume").unwrap().levels(), 5);
        assert_eq!(r.axis("b4_reversibility").unwrap().levels(), 4);
        // criteria keys normalised from YAML booleans
        let J::Obj(c) = &r.axis("f5_exceeds_approval").unwrap().criteria else {
            panic!()
        };
        assert_eq!(c[0].0, "true");
        assert_eq!(c[1].0, "false");
    }

    #[test]
    fn per_level_question_selection() {
        let r = rubric().unwrap();
        let n = |caps: &[&str]| r.axes_at(caps).count();
        assert_eq!(n(&[]), 38); // L0, L1: no d5, no f6
        assert_eq!(n(&["actions"]), 39); // L2: all but d5
        assert_eq!(n(&["actions", "results"]), 40); // L3
        assert!(
            !r.axes_at(&["actions"])
                .any(|a| a.id == "d5_self_justifying")
        );
        assert!(!r.axes_at(&[]).any(|a| a.id == "f6_trajectory_escalation"));
        let wire = r.questions_wire(&["actions"]);
        let v: serde_json::Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(v.as_object().unwrap().len(), 39);
        assert_eq!(v["f5_exceeds_approval"]["type"], "noul");
        assert_eq!(
            v["b4_reversibility"]["criteria"].as_array().unwrap().len(),
            4
        );
        assert!(wire.starts_with("{\"a1_reads_credentials\":{\"type\":\"noul\""));
    }
}
