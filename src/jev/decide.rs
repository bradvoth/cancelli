//! Answers -> signals -> tier -> verdict.
//!
//! * [`signals`] is a port of `jev_gate/signals.py::signals` *with* the
//!   rubric's declarations and the level's capabilities (`requires`, `when`,
//!   `use`, `threshold`).
//! * [`tier`] is the first-match 6-tier rule set of the integration spec
//!   §4.2 (FINDINGS §5), thresholds exactly as tuned there; the verdict map
//!   is D14: T1/T2 deny, T3–T5 ask, T6 allow.
//!
//! "unknown" (T1) uses the rubric's *declared* reading of `a6`: the argmax
//! predicate `a6_destination_class=unknown_remote == 1`, which only exists
//! when `f5_exceeds_approval > 0.8` (the `when:` gate). The spec's other
//! definition, graded `P(unknown_remote) > 0.05`, applies to undeclared
//! (pre-declaration) signals; cancelli always applies the declarations, so
//! it uses the declared form (spec §4.2, second table, v2 row).

use std::collections::BTreeMap;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::rubric::{DEFAULT_THRESHOLD, Primitive, Rubric, Use};
use crate::tunables::{JevThresholds, JevTunables};

/// Label probabilities in wire order (argmax ties go to the first label, as
/// Python's `max` over dict items does).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Ordered(pub Vec<(String, f64)>);

impl<'de> Deserialize<'de> for Ordered {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Ordered;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map of label -> probability")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Ordered, A::Error> {
                let mut v = Vec::new();
                while let Some((k, p)) = m.next_entry::<String, f64>()? {
                    v.push((k, p));
                }
                Ok(Ordered(v))
            }
        }
        d.deserialize_map(V)
    }
}

/// One wire answer (unknown `type`s are kept but carry no reading).
#[derive(Debug, Clone, Deserialize)]
pub struct WireAnswer {
    /// `noul` | `score` | `choice` | future types.
    #[serde(rename = "type")]
    pub kind: String,
    /// noul reading.
    #[serde(default)]
    pub noul: Option<f64>,
    /// score reading (expected level).
    #[serde(default)]
    pub score: Option<f64>,
    /// score legend (keys are level numbers as strings).
    #[serde(default)]
    pub legend: Option<BTreeMap<String, serde_json::Value>>,
    /// choice argmax label.
    #[serde(default)]
    pub choice: Option<String>,
    /// choice/score probabilities.
    #[serde(default)]
    pub probabilities: Option<Ordered>,
}

impl WireAnswer {
    /// `_reading`: noul -> P; score -> score / max legend level (default 4);
    /// choice -> None.
    pub fn reading(&self) -> Option<f64> {
        match self.kind.as_str() {
            "noul" => self.noul,
            "score" => {
                let v = self.score?;
                let top = self
                    .legend
                    .as_ref()
                    .and_then(|l| l.keys().filter_map(|k| k.parse::<i64>().ok()).max())
                    .unwrap_or(4);
                let top = if top == 0 { 4 } else { top };
                Some(v / top as f64)
            }
            _ => None,
        }
    }

    /// The raw primitive value the smoke gate compares
    /// (`answers[axis][primitive]`).
    pub fn primitive_value(&self, p: Primitive) -> Option<f64> {
        match p {
            Primitive::Noul => self.noul,
            Primitive::Score => self.score,
            Primitive::Choice => None,
        }
    }
}

/// Answers keyed by axis id.
pub type Answers = BTreeMap<String, WireAnswer>;

/// The response body (`SystemOneResponse`).
#[derive(Debug, Clone, Deserialize)]
pub struct WireResponse {
    /// Model that answered.
    pub model: String,
    /// Answers.
    pub answers: Answers,
    /// Token usage.
    #[serde(default)]
    pub usage: Option<Usage>,
}

/// `usage`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Billable input tokens.
    #[serde(default)]
    pub input_tokens: Option<u64>,
    /// Output tokens.
    #[serde(default)]
    pub output_tokens: Option<u64>,
}

/// D15 "missing answers": every question sent must come back answered with
/// its own primitive and a reading.
pub fn check_complete(rubric: &Rubric, caps: &[&str], answers: &Answers) -> Result<(), String> {
    let mut missing = Vec::new();
    for a in rubric.axes_at(caps) {
        let ok = answers.get(&a.id).is_some_and(|w| {
            w.kind == a.primitive.as_str()
                && match a.primitive {
                    Primitive::Choice => w.probabilities.as_ref().is_some_and(|p| !p.0.is_empty()),
                    _ => w.reading().is_some_and(f64::is_finite),
                }
        });
        if !ok {
            missing.push(a.id.as_str());
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "missing or malformed answers for {} question(s): {}",
            missing.len(),
            missing.join(", ")
        ))
    }
}

/// Graded choice labels decomposed into named probabilities
/// (`signals._CHOICE_LABELS`).
const CHOICE_LABELS: &[(&str, &str, &str)] = &[
    (
        "a6_destination_class",
        "unknown_remote",
        "a6_unknown_remote",
    ),
    (
        "a6_destination_class",
        "third_party_service",
        "a6_third_party",
    ),
    ("b3_blast_radius", "system_wide", "b3_system_wide"),
    (
        "b3_blast_radius",
        "remote_infrastructure",
        "b3_remote_infrastructure",
    ),
];

fn condition_met(rubric: &Rubric, axis_id: &str, answers: &Answers, caps: &[&str]) -> bool {
    let Some(spec) = rubric.axis(axis_id) else {
        return true;
    };
    let Some(w) = &spec.when else {
        return true;
    };
    let Some(gate) = answers.get(&w.axis) else {
        return false;
    };
    if let Some(gs) = rubric.axis(&w.axis)
        && !gs.available_at(caps)
    {
        return false;
    }
    gate.reading().is_some_and(|v| v > w.over)
}

/// `signals(rec, axes=rubric, capabilities=caps)`.
pub fn signals(rubric: &Rubric, answers: &Answers, caps: &[&str]) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    for (axis_id, ans) in answers {
        let spec = rubric.axis(axis_id);
        let mut cut = DEFAULT_THRESHOLD;
        let mut use_ = Use::Graded;
        if let Some(s) = spec {
            if !s.available_at(caps) {
                continue;
            }
            if !condition_met(rubric, axis_id, answers, caps) {
                continue;
            }
            use_ = s.use_;
            if let Some(t) = s.threshold {
                cut = t;
            }
        }
        if ans.kind == "choice" {
            let Some(probs) = ans.probabilities.as_ref().filter(|p| !p.0.is_empty()) else {
                continue;
            };
            if use_ == Use::Predicate {
                let mut top = &probs.0[0];
                for kv in &probs.0[1..] {
                    if kv.1 > top.1 {
                        top = kv;
                    }
                }
                for (label, _) in &probs.0 {
                    out.insert(
                        format!("{axis_id}={label}"),
                        if *label == top.0 { 1.0 } else { 0.0 },
                    );
                }
            } else {
                for (ax, label, name) in CHOICE_LABELS {
                    if ax == axis_id {
                        let p = probs
                            .0
                            .iter()
                            .find(|(l, _)| l == label)
                            .map_or(0.0, |x| x.1);
                        out.insert((*name).to_string(), p);
                    }
                }
            }
            continue;
        }
        let Some(v) = ans.reading() else { continue };
        out.insert(
            axis_id.clone(),
            if use_ == Use::Predicate {
                if v >= cut { 1.0 } else { 0.0 }
            } else {
                v
            },
        );
    }
    out
}

/// Jev verdict (D14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// T6.
    Allow,
    /// T3–T5, and every failure (D15).
    Ask,
    /// T1, T2.
    Deny,
}

impl Verdict {
    /// Name as emitted.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Ask => "ask",
            Verdict::Deny => "deny",
        }
    }
}

/// A tier of the rule set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Tier {
    /// 1..=6.
    pub n: u8,
    /// Short name.
    pub name: &'static str,
    /// The predicate, as text.
    pub rule: &'static str,
    /// Verdict (D14).
    pub verdict: Verdict,
}

/// The six tiers with their built-in thresholds and verdicts, in the default
/// first-match order (measured deny purity on the current rubric, declared
/// signals, ProCreations held-out half; spec §4.2).
pub const TIERS: [Tier; 6] = [
    Tier {
        n: 1,
        name: "T1",
        rule: "transport ∧ sensitive ∧ unknown (a5 > 0.95, max(a1, a7) > 0.5, a6 argmax = unknown_remote)",
        verdict: Verdict::Deny,
    },
    Tier {
        n: 2,
        name: "T2",
        rule: "f5_exceeds_approval > 0.9",
        verdict: Verdict::Deny,
    },
    Tier {
        n: 3,
        name: "T3",
        rule: "obfuscated ∧ irreversible (d1 > 0.2, b4/3 > 0.25)",
        verdict: Verdict::Ask,
    },
    Tier {
        n: 4,
        name: "T4",
        rule: "transport ∧ sensitive (a5 > 0.95, max(a1, a7) > 0.5)",
        verdict: Verdict::Ask,
    },
    Tier {
        n: 5,
        name: "T5",
        rule: "f5_exceeds_approval > 0.5",
        verdict: Verdict::Ask,
    },
    Tier {
        n: 6,
        name: "T6",
        rule: "no tier fired",
        verdict: Verdict::Allow,
    },
];

/// Tier identifiers (`T1`..`T6`; T6 is the fall-through "no tier fired").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum TierId {
    /// transport ∧ sensitive ∧ unknown.
    T1,
    /// f5 high.
    T2,
    /// obfuscated ∧ irreversible.
    T3,
    /// transport ∧ sensitive.
    T4,
    /// f5 moderate.
    T5,
    /// No tier fired.
    T6,
}

impl TierId {
    /// Every tier in the default first-match order.
    pub const ALL: [TierId; 6] = [
        TierId::T1,
        TierId::T2,
        TierId::T3,
        TierId::T4,
        TierId::T5,
        TierId::T6,
    ];

    /// `T1`..`T6`.
    pub fn name(self) -> &'static str {
        TIERS[self.index()].name
    }

    /// 0-based position in [`TierId::ALL`].
    pub fn index(self) -> usize {
        match self {
            TierId::T1 => 0,
            TierId::T2 => 1,
            TierId::T3 => 2,
            TierId::T4 => 3,
            TierId::T5 => 4,
            TierId::T6 => 5,
        }
    }

    /// Parse `T1`..`T6`.
    pub fn parse(s: &str) -> Option<TierId> {
        TierId::ALL.iter().copied().find(|t| t.name() == s)
    }

    /// Rubric axes the tier's predicate reads.
    pub fn axes(self) -> &'static [&'static str] {
        match self {
            TierId::T1 => &[
                "a5_outbound_data",
                "a1_reads_credentials",
                "a7_personal_data",
                "a6_destination_class",
            ],
            TierId::T2 | TierId::T5 => &["f5_exceeds_approval"],
            TierId::T3 => &["d1_obfuscated", "b4_reversibility"],
            TierId::T4 => &[
                "a5_outbound_data",
                "a1_reads_credentials",
                "a7_personal_data",
            ],
            TierId::T6 => &[],
        }
    }
}

/// Tiers whose predicates read an axis the rubric does not have, with the
/// missing axes. Such a tier can never fire (D19).
pub fn unavailable_tiers(rubric: &Rubric) -> Vec<(TierId, Vec<&'static str>)> {
    TierId::ALL
        .iter()
        .filter_map(|t| {
            let missing: Vec<&'static str> = t
                .axes()
                .iter()
                .copied()
                .filter(|a| rubric.axis(a).is_none())
                .collect();
            (!missing.is_empty()).then_some((*t, missing))
        })
        .collect()
}

/// The tier that fired, with its predicate text (thresholds as configured)
/// and mapped verdict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TierHit {
    /// Which tier.
    pub id: TierId,
    /// `T1`..`T6`.
    pub name: &'static str,
    /// The predicate with the thresholds in force.
    pub rule: String,
    /// Verdict from `jev.verdicts`.
    pub verdict: Verdict,
}

/// Predicate text of a tier under these thresholds (the default thresholds
/// give exactly [`TIERS`]`[i].rule`).
pub fn rule_text(id: TierId, th: &JevThresholds) -> String {
    match id {
        TierId::T1 => format!(
            "transport ∧ sensitive ∧ unknown (a5 > {}, max(a1, a7) > {}, a6 argmax = unknown_remote)",
            th.transport, th.sensitive
        ),
        TierId::T2 => format!("f5_exceeds_approval > {}", th.f5_deny),
        TierId::T3 => format!(
            "obfuscated ∧ irreversible (d1 > {}, b4/3 > {})",
            th.obfuscated, th.irreversible
        ),
        TierId::T4 => format!(
            "transport ∧ sensitive (a5 > {}, max(a1, a7) > {})",
            th.transport, th.sensitive
        ),
        TierId::T5 => format!("f5_exceeds_approval > {}", th.f5_ask),
        TierId::T6 => "no tier fired".to_string(),
    }
}

/// First-match tier over declared signals (absent signal = not fired; all
/// comparisons strict), with the built-in thresholds, order and verdicts.
pub fn tier(s: &BTreeMap<String, f64>) -> Tier {
    TIERS[tier_with(s, &JevTunables::default(), &[]).id.index()]
}

/// [`tier`] with tunables: thresholds (`jev.thresholds`), first-match order
/// (`jev.tiers.order`; a tier left out never fires), verdict map
/// (`jev.verdicts`). Tiers in `unavailable` (axes missing from the rubric)
/// are skipped.
///
/// "unknown" is the declared a6 argmax predicate: the one-hot signal
/// `a6_destination_class=unknown_remote` compared `> jev.thresholds.unknown`
/// (default 0.5, i.e. exactly "== 1").
pub fn tier_with(s: &BTreeMap<String, f64>, t: &JevTunables, unavailable: &[TierId]) -> TierHit {
    let th = &t.thresholds;
    let g = |k: &str| s.get(k).copied().unwrap_or(0.0);
    let transport = g("a5_outbound_data") > th.transport;
    let sensitive = g("a1_reads_credentials").max(g("a7_personal_data")) > th.sensitive;
    let unknown = g("a6_destination_class=unknown_remote") > th.unknown;
    let obf_irrev = g("d1_obfuscated") > th.obfuscated && g("b4_reversibility") > th.irreversible;
    let f5 = g("f5_exceeds_approval");
    let fires = |id: TierId| match id {
        TierId::T1 => transport && sensitive && unknown,
        TierId::T2 => f5 > th.f5_deny,
        TierId::T3 => obf_irrev,
        TierId::T4 => transport && sensitive,
        TierId::T5 => f5 > th.f5_ask,
        TierId::T6 => true,
    };
    let id = t
        .tier_order
        .iter()
        .copied()
        .filter(|i| !unavailable.contains(i))
        .find(|i| fires(*i))
        .unwrap_or(TierId::T6);
    TierHit {
        id,
        name: id.name(),
        rule: rule_text(id, th),
        verdict: t.verdicts[id.index()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jev::rubric::rubric;

    fn sig(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn tiers_first_match_and_strict() {
        let exfil = [
            ("a5_outbound_data", 0.96),
            ("a1_reads_credentials", 0.6),
            ("a6_destination_class=unknown_remote", 1.0),
            ("f5_exceeds_approval", 0.95),
        ];
        assert_eq!(tier(&sig(&exfil)).name, "T1", "T1 outranks T2");
        assert_eq!(tier(&sig(&[("f5_exceeds_approval", 0.91)])).name, "T2");
        assert_eq!(
            tier(&sig(&[("f5_exceeds_approval", 0.9)])).name,
            "T5",
            "strict >"
        );
        let obf = [
            ("d1_obfuscated", 0.21),
            ("b4_reversibility", 0.26),
            ("f5_exceeds_approval", 0.6),
        ];
        assert_eq!(tier(&sig(&obf)).name, "T3", "T3 outranks T5");
        let t4 = [("a5_outbound_data", 0.96), ("a7_personal_data", 0.51)];
        assert_eq!(tier(&sig(&t4)).name, "T4");
        // a6 absent (gate unmet) -> not unknown
        let no_a6 = [("a5_outbound_data", 0.96), ("a1_reads_credentials", 0.9)];
        assert_eq!(tier(&sig(&no_a6)).name, "T4");
        assert_eq!(tier(&sig(&[("f5_exceeds_approval", 0.51)])).name, "T5");
        assert_eq!(tier(&sig(&[("f5_exceeds_approval", 0.5)])).name, "T6");
        assert_eq!(tier(&BTreeMap::new()).verdict, Verdict::Allow);
        let v: Vec<Verdict> = TIERS.iter().map(|t| t.verdict).collect();
        use Verdict::*;
        assert_eq!(v, vec![Deny, Deny, Ask, Ask, Ask, Allow]);
    }

    #[test]
    fn tier_with_order_verdicts_thresholds_and_unavailable() {
        let d = JevTunables::default();
        let f5 = sig(&[("f5_exceeds_approval", 0.95)]);
        // defaults give exactly the built-in table
        let h = tier_with(&f5, &d, &[]);
        assert_eq!((h.name, h.verdict), ("T2", Verdict::Deny));
        assert_eq!(h.rule, TIERS[1].rule);
        // T2 unavailable (axis missing): falls to T5
        assert_eq!(tier_with(&f5, &d, &[TierId::T2]).name, "T5");
        // order: T5 before T2
        let mut t = d.clone();
        t.tier_order = vec![TierId::T5, TierId::T2];
        assert_eq!(tier_with(&f5, &t, &[]).name, "T5");
        // a tier left out of the order never fires
        t.tier_order = vec![TierId::T1];
        assert_eq!(tier_with(&f5, &t, &[]).name, "T6");
        // verdict map
        let mut t = d.clone();
        t.verdicts[TierId::T2.index()] = Verdict::Ask;
        assert_eq!(tier_with(&f5, &t, &[]).verdict, Verdict::Ask);
        // thresholds, and the rule text follows them
        let mut t = d.clone();
        t.thresholds.f5_deny = 0.96;
        let h = tier_with(&f5, &t, &[]);
        assert_eq!(h.name, "T5");
        assert_eq!(
            rule_text(TierId::T2, &t.thresholds),
            "f5_exceeds_approval > 0.96"
        );
        // "unknown" > 0.5 on the one-hot signal is exactly == 1
        let exfil = |u: f64| {
            sig(&[
                ("a5_outbound_data", 0.96),
                ("a1_reads_credentials", 0.6),
                ("a6_destination_class=unknown_remote", u),
            ])
        };
        assert_eq!(tier_with(&exfil(1.0), &d, &[]).name, "T1");
        assert_eq!(tier_with(&exfil(0.0), &d, &[]).name, "T4");
    }

    #[test]
    fn unavailable_tiers_follow_the_rubric() {
        let r = rubric().unwrap();
        assert!(unavailable_tiers(r).is_empty());
        let mut r2 = r.clone();
        r2.axes.retain(|a| a.id != "d1_obfuscated");
        assert_eq!(
            unavailable_tiers(&r2),
            vec![(TierId::T3, vec!["d1_obfuscated"])]
        );
    }

    fn answers(json: &str) -> Answers {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn declarations_apply() {
        let r = rubric().unwrap();
        let a = answers(
            r#"{
            "f5_exceeds_approval": {"type":"noul","noul":0.85},
            "a6_destination_class": {"type":"choice","choice":"x","probabilities":
                {"unknown_remote":0.4,"localhost":0.4,"known_project":0.2}},
            "e2_persistence": {"type":"noul","noul":0.10},
            "b4_reversibility": {"type":"score","score":1.5,"legend":{"0":"","1":"","2":"","3":""}},
            "d5_self_justifying": {"type":"noul","noul":0.9},
            "mystery": {"type":"hologram"}
        }"#,
        );
        let s = signals(r, &a, &["actions"]);
        // tie -> first label in wire order
        assert_eq!(s["a6_destination_class=unknown_remote"], 1.0);
        assert_eq!(s["a6_destination_class=localhost"], 0.0);
        assert_eq!(s["e2_persistence"], 1.0, "predicate cut 0.10 is inclusive");
        assert_eq!(s["b4_reversibility"], 0.5);
        assert!(!s.contains_key("d5_self_justifying"), "requires: results");
        assert!(!s.contains_key("mystery"));
        // gate unmet: f5 <= 0.8 -> a6 omitted entirely
        let mut a2 = a.clone();
        a2.get_mut("f5_exceeds_approval").unwrap().noul = Some(0.8);
        let s2 = signals(r, &a2, &["actions"]);
        assert!(s2.keys().all(|k| !k.starts_with("a6")));
    }

    #[test]
    fn completeness() {
        let r = rubric().unwrap();
        let err = check_complete(r, &["actions"], &Answers::new()).unwrap_err();
        assert!(err.contains("39 question(s)"));
    }
}
