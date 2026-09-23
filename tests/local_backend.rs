//! D23 (any `/v1/systemone` server) and D24 (calibration) end to end,
//! through the real binary, against the local replay server
//! (tests/support). No Jev mock: the server replays real cached jev-1.13.0
//! answers under a local model name.

mod support;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde_json::{Value, json};
use support::{ALLOW_FIXTURE, ASK_FIXTURE, KEY, bin, records, serve};
use tempfile::TempDir;

const WARN_CMD: &str = "rsync -avz ./data user@host:/backup/";
const RUBRIC: &str = "0fd1f245ae1c7ef3";

struct Home {
    dir: TempDir,
}

impl Home {
    fn new(config: &str) -> Home {
        let dir = TempDir::new().unwrap();
        let cfg = dir.path().join(".config/cancelli");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(cfg.join("config.toml"), config).unwrap();
        Home { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn cmd(&self, args: &[&str]) -> std::process::Command {
        let mut c = bin();
        c.args(args).env("HOME", self.path());
        c
    }

    /// One hook call for WARN_CMD; returns (stdout, records).
    fn hook(&self, key: bool) -> (String, Vec<Value>) {
        let t = self.path().join("session.jsonl");
        let lines = [
            json!({"type": "user", "message": {"role": "user", "content": "Back up the data dir."}}),
            json!({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "toolu_prior", "name": "Bash", "input": {"command": "du -sh ./data"}}]}}),
        ];
        let text: Vec<String> = lines.iter().map(Value::to_string).collect();
        std::fs::write(&t, text.join("\n") + "\n").unwrap();
        let logdir = TempDir::new().unwrap();
        let payload = json!({
            "session_id": "s", "transcript_path": t, "cwd": "/work",
            "permission_mode": "default", "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_use_id": "toolu_cur",
            "tool_input": {"command": WARN_CMD},
        });
        let mut c = self.cmd(&["hook"]);
        c.env("CANCELLI_LOG_DIR", logdir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if key {
            c.env("TYPESAFE_API_KEY", KEY);
        }
        let mut child = c.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(0));
        (
            String::from_utf8(out.stdout).unwrap(),
            records(logdir.path()),
        )
    }
}

fn event(recs: &[Value]) -> &Value {
    recs.iter().find(|r| r["kind"] == "event").unwrap()
}

fn judge_error(recs: &[Value]) -> Option<&Value> {
    recs.iter()
        .find(|r| r["kind"] == "error" && r["stage"] == "judge")
}

fn local_config(url: &str, extra: &str) -> String {
    format!(
        "dry_run = false\ndecide_all = true\n[judge]\nbase_url = \"{url}\"\nmodel = \"qwen-local\"\n\
         expected_model = \"qwen-local\"\napi_key_required = false\ntimeout_ms = 2000\nbudget_ms = 3000\n{extra}"
    )
}

// ------------------------------------------------------------------ D23 --

#[test]
fn local_model_name_is_accepted_when_expected_and_no_key_is_needed() {
    let srv = serve(vec![ALLOW_FIXTURE], "qwen-local");
    let h = Home::new(&local_config(&srv.url, ""));
    let (stdout, recs) = h.hook(false);
    assert!(judge_error(&recs).is_none(), "{recs:?}");
    let ev = event(&recs);
    assert_eq!(ev["final"], "allow");
    let j = &ev["judge"];
    assert_eq!(j["tier"], "T6");
    assert_eq!(j["error"], Value::Null);
    // D23 backend identity
    assert_eq!(j["backend"], "jev");
    assert_eq!(j["backend_host"], srv.host());
    assert_eq!(j["expected_model"], "qwen-local");
    assert_eq!(j["model"], "qwen-local");
    assert!(j["key_source"].as_str().unwrap().starts_with("none"));
    assert!(
        stdout.contains("\"permissionDecision\":\"allow\""),
        "{stdout}"
    );
    // no key -> no Authorization header; the requested model is judge.model
    let req = &srv.requests()[0];
    assert_eq!(req.header("authorization"), None);
    assert_eq!(req.json()["model"], "qwen-local");
    assert!(req.json()["state"].as_str().unwrap().contains(WARN_CMD));

    // a key that is present is still sent
    let (_, recs) = h.hook(true);
    assert_eq!(event(&recs)["judge"]["tier"], "T6");
    assert_eq!(
        srv.requests()[1].header("authorization"),
        Some(format!("Bearer {KEY}").as_str())
    );
}

#[test]
fn a_model_other_than_expected_asks_with_an_error_record() {
    let srv = serve(vec![ALLOW_FIXTURE], "qwen-local");
    // expected_model left at its default, jev-1.13.0
    let h = Home::new(&format!(
        "dry_run = false\n[judge]\nbase_url = \"{}\"\napi_key_required = false\n",
        srv.url
    ));
    let (stdout, recs) = h.hook(false);
    let ev = event(&recs);
    assert_eq!(ev["final"], "ask");
    let j = &ev["judge"];
    assert_eq!(j["model"], "qwen-local");
    assert_eq!(j["expected_model"], "jev-1.13.0");
    assert_eq!(j["signals"], Value::Null, "answers not consumed");
    let err = judge_error(&recs).expect("D15 error record");
    assert!(
        err["error"]
            .as_str()
            .unwrap()
            .contains("response.model \"qwen-local\" != expected_model \"jev-1.13.0\""),
        "{err}"
    );
    assert_eq!(err["backend_host"], srv.host());
    assert!(stdout.contains("\"permissionDecision\":\"ask\""));
}

#[test]
fn key_required_by_default_asks_without_a_request() {
    let srv = serve(vec![ALLOW_FIXTURE], "qwen-local");
    let h = Home::new(&format!(
        "[judge]\nbase_url = \"{}\"\nexpected_model = \"qwen-local\"\n",
        srv.url
    ));
    let (_, recs) = h.hook(false);
    assert_eq!(event(&recs)["final"], "ask");
    assert!(
        judge_error(&recs).unwrap()["error"]
            .as_str()
            .unwrap()
            .contains("no Jev API key")
    );
    assert!(srv.requests().is_empty());
}

#[test]
fn config_shows_and_validates_the_new_judge_keys() {
    let h = Home::new(
        "[judge]\nexpected_model = \"qwen-local\"\napi_key_required = false\n\
         calibration_file = \"~/missing.json\"\n",
    );
    let out = String::from_utf8(h.cmd(&["config"]).output().unwrap().stdout).unwrap();
    assert!(
        out.contains("judge.api_key_required = false  # file\n"),
        "{out}"
    );
    assert!(
        out.contains("judge.expected_model = \"qwen-local\"  # file\n"),
        "{out}"
    );
    assert!(out.contains("# judge api key: none (not required"), "{out}");
    assert!(out.contains("judge.calibration_file = \""), "{out}");
    assert!(out.contains("INVALID"), "{out}");
    assert!(out.contains("# error: judge.calibration_file:"), "{out}");
    // fingerprinted
    let fp = |s: &str| {
        s.lines()
            .find(|l| l.contains("config_fingerprint ="))
            .unwrap()
            .to_string()
    };
    let d = Home::new("");
    let def = String::from_utf8(d.cmd(&["config"]).output().unwrap().stdout).unwrap();
    assert_ne!(fp(&out), fp(&def));
    assert!(fp(&out).contains("judge.expected_model"));
    assert!(
        fp(&def).contains("config_fingerprint = 371a6d0ee7fe7bda"),
        "{def}"
    );
    // invalid values fall back with an error naming the key
    let b = Home::new("[judge]\nexpected_model = \"\"\n");
    let out = String::from_utf8(b.cmd(&["config"]).output().unwrap().stdout).unwrap();
    assert!(
        out.contains("judge.expected_model = \"jev-1.13.0\"  # default"),
        "{out}"
    );
    assert!(out.contains("# error: judge.expected_model:"), "{out}");
    // --init writes them (commented) and they parse
    let i = TempDir::new().unwrap();
    let st = bin()
        .args(["config", "--init"])
        .env("HOME", i.path())
        .output()
        .unwrap();
    assert!(st.status.success());
    let text = std::fs::read_to_string(i.path().join(".config/cancelli/config.toml")).unwrap();
    for k in [
        "# expected_model = \"jev-1.13.0\"",
        "api_key_required = true",
        "# calibration_file = ",
    ] {
        assert!(text.contains(k), "{k}");
    }
}

// ------------------------------------------------------------------ D24 --

fn write_calibration(dir: &Path, model: &str, rubric: &str, axes: Value) -> PathBuf {
    let p = dir.join("cal.json");
    std::fs::write(
        &p,
        json!({"format": "cancelli-calibration/1", "rubric_hash": rubric, "model": model,
               "fitted_at": "2026-09-22T00:00:00Z", "source": "test", "axes": axes})
        .to_string(),
    )
    .unwrap();
    p
}

#[test]
fn calibration_moves_signals_and_tier_in_the_expected_direction() {
    // allow fixture (f5 0.13, T6): Platt b = +5 lifts f5 to ~0.96 -> T2 deny
    let srv = serve(vec![ALLOW_FIXTURE], "qwen-local");
    let tmp = TempDir::new().unwrap();
    let cal = write_calibration(
        tmp.path(),
        "qwen-local",
        RUBRIC,
        json!({"f5_exceeds_approval": {"type": "noul", "method": "platt", "a": 1.0, "b": 5.0, "n": 50},
               "a6_destination_class": {"type": "choice", "method": "temperature", "t": 0.5, "n": 50}}),
    );
    let h = Home::new(&local_config(
        &srv.url,
        &format!("calibration_file = \"{}\"\n", cal.display()),
    ));
    let (_, recs) = h.hook(false);
    assert!(judge_error(&recs).is_none(), "{recs:?}");
    let j = &event(&recs)["judge"];
    assert_eq!(
        j["answers"]["f5_exceeds_approval"]["noul"], 0.13,
        "raw kept"
    );
    let f5 = j["answers_calibrated"]["f5_exceeds_approval"]["noul"]
        .as_f64()
        .unwrap();
    assert!((f5 - 0.957).abs() < 0.01, "{f5}");
    assert_eq!(j["signals"]["f5_exceeds_approval"], json!(f5));
    assert_eq!(
        (j["tier"].as_str(), j["verdict"].as_str()),
        (Some("T2"), Some("deny"))
    );
    assert_eq!(event(&recs)["final"], "deny");
    let c = &j["calibration"];
    assert_eq!(c["model"], "qwen-local");
    assert_eq!(c["rubric_hash"], RUBRIC);
    assert_eq!(c["sha"].as_str().unwrap().len(), 16);
    assert_eq!(
        c["axes"],
        json!(["a6_destination_class", "f5_exceeds_approval"])
    );
    // the choice was tempered and renormalised
    let p = &j["answers_calibrated"]["a6_destination_class"]["probabilities"];
    let sum: f64 = p
        .as_object()
        .unwrap()
        .values()
        .map(|v| v.as_f64().unwrap())
        .sum();
    assert!((sum - 1.0).abs() < 1e-9);
    // the fingerprint names the calibration
    assert!(
        event(&recs)["overrides"]
            .as_array()
            .unwrap()
            .contains(&json!("judge.calibration_file"))
    );

    // ask fixture (f5 0.79, T5): b = -2 lowers f5 to ~0.34 -> T6 allow
    let srv = serve(vec![ASK_FIXTURE], "qwen-local");
    let cal = write_calibration(
        tmp.path(),
        "qwen-local",
        RUBRIC,
        json!({"f5_exceeds_approval": {"type": "noul", "method": "platt", "a": 1.0, "b": -2.0, "n": 50}}),
    );
    let h = Home::new(&local_config(
        &srv.url,
        &format!("calibration_file = \"{}\"\n", cal.display()),
    ));
    let (_, recs) = h.hook(false);
    let j = &event(&recs)["judge"];
    assert!(j["signals"]["f5_exceeds_approval"].as_f64().unwrap() < 0.5);
    assert_eq!(j["tier"], "T6");
    assert_eq!(event(&recs)["final"], "allow");
}

#[test]
fn mismatched_or_invalid_calibration_asks_with_error_records() {
    let srv = serve(vec![ALLOW_FIXTURE], "qwen-local");
    let tmp = TempDir::new().unwrap();
    let f5 = json!({"f5_exceeds_approval": {"type": "noul", "method": "platt", "a": 1.0, "b": 0.0, "n": 1}});
    let cases: Vec<(PathBuf, &str)> = vec![
        (
            write_calibration(tmp.path(), "other-model", RUBRIC, f5.clone()),
            "pinned to model \"other-model\"",
        ),
        (
            {
                let d = tmp.path().join("h");
                std::fs::create_dir_all(&d).unwrap();
                write_calibration(&d, "qwen-local", "ffffffffffffffff", f5.clone())
            },
            "rubric_hash",
        ),
        (
            {
                let p = tmp.path().join("bad.json");
                std::fs::write(&p, "{not json").unwrap();
                p
            },
            "invalid calibration JSON",
        ),
        (tmp.path().join("absent.json"), "cannot read"),
    ];
    for (path, why) in cases {
        let h = Home::new(&local_config(
            &srv.url,
            &format!("calibration_file = \"{}\"\n", path.display()),
        ));
        let (stdout, recs) = h.hook(false);
        let ev = event(&recs);
        assert_eq!(ev["final"], "ask", "{why}");
        assert_eq!(
            ev["judge"]["signals"],
            Value::Null,
            "{why}: not uncalibrated"
        );
        let cfg_err = recs
            .iter()
            .find(|r| r["kind"] == "error" && r["stage"] == "config")
            .unwrap_or_else(|| panic!("{why}: config error record"));
        assert!(
            cfg_err["error"].as_str().unwrap().contains(why),
            "{cfg_err}"
        );
        let je = judge_error(&recs).unwrap_or_else(|| panic!("{why}: judge error record"));
        assert!(
            je["error"].as_str().unwrap().contains("calibration_file"),
            "{je}"
        );
        assert!(stdout.contains("\"permissionDecision\":\"ask\""));
    }
}

// --------------------------------------------------------- calibrate CLI --

fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}
fn logit(p: f64) -> f64 {
    (p / (1.0 - p)).ln()
}
fn temper(p: &[f64], t: f64) -> Vec<f64> {
    let e: Vec<f64> = p.iter().map(|x| (x.ln() / t).exp()).collect();
    let z: f64 = e.iter().sum();
    e.iter().map(|x| x / z).collect()
}

#[test]
fn calibrate_offline_recovers_known_parameters_from_fixture_pairs() {
    // Reference q (Jev); target p generated so that the true calibration is
    // Platt(a=1.5, b=-0.7) on f5 and temperature 0.6 on a6 and b4.
    let (a0, b0, t0) = (1.5, -0.7, 0.6);
    let tmp = TempDir::new().unwrap();
    let mut lines = Vec::new();
    for i in 0..120 {
        let q = 0.02 + 0.96 * (i as f64 / 119.0);
        let p = sigmoid((logit(q) - b0) / a0);
        let x = (i % 10) as f64 / 10.0 + 0.05;
        let qa = [0.7 * x, 0.7 * (1.0 - x), 0.2, 0.1];
        let qb = [0.1 + 0.5 * x, 0.5 - 0.4 * x, 0.2, 0.2 - 0.1 * x];
        let (pa, pb) = (temper(&qa, 1.0 / t0), temper(&qb, 1.0 / t0));
        let labels_a = [
            "unknown_remote",
            "localhost",
            "known_project",
            "third_party_service",
        ];
        let choice = |l: &[&str], v: &[f64]| -> Value {
            let m: serde_json::Map<String, Value> = l
                .iter()
                .zip(v)
                .map(|(k, x)| (k.to_string(), json!(x)))
                .collect();
            json!({"type": "choice", "choice": l[0], "probabilities": m})
        };
        let score = |v: &[f64]| -> Value {
            let m: serde_json::Map<String, Value> = v
                .iter()
                .enumerate()
                .map(|(k, x)| (k.to_string(), json!(x)))
                .collect();
            let s: f64 = v.iter().enumerate().map(|(k, x)| k as f64 * x).sum();
            json!({"type": "score", "score": s, "probabilities": m})
        };
        lines.push(
            json!({"id": format!("p{i}"), "rubric_hash": RUBRIC, "target_model": "qwen-local",
                   "reference": {"f5_exceeds_approval": {"type": "noul", "noul": q},
                                 "a6_destination_class": choice(&labels_a, &qa),
                                 "b4_reversibility": score(&qb)},
                   "target": {"f5_exceeds_approval": {"type": "noul", "noul": p},
                              "a6_destination_class": choice(&labels_a, &pa),
                              "b4_reversibility": score(&pb)}})
            .to_string(),
        );
    }
    // lines the offline fit must skip
    lines.push(
        json!({"id": "x", "rubric_hash": "ffffffffffffffff", "target_model": "m",
                      "reference": {}, "target": {}})
        .to_string(),
    );
    lines.push(
        json!({"item_id": "row", "state_rendered": "s", "answers": {}, "model": "jev-1.13.0",
                      "rubric_hash": RUBRIC, "error": null})
        .to_string(),
    );
    let pairs = tmp.path().join("pairs.jsonl");
    std::fs::write(&pairs, lines.join("\n") + "\n").unwrap();
    let out = tmp.path().join("cal.json");
    let h = Home::new("");
    let o = h
        .cmd(&[
            "calibrate",
            "--offline",
            "--reference",
            pairs.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(o.stdout).unwrap();
    assert!(
        o.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let f: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(f["format"], "cancelli-calibration/1");
    assert_eq!(f["model"], "qwen-local");
    assert_eq!(f["rubric_hash"], RUBRIC);
    let ax = &f["axes"];
    let a = ax["f5_exceeds_approval"]["a"].as_f64().unwrap();
    let b = ax["f5_exceeds_approval"]["b"].as_f64().unwrap();
    assert!((a - a0).abs() < 0.01 && (b - b0).abs() < 0.01, "{a} {b}");
    for k in ["a6_destination_class", "b4_reversibility"] {
        let t = ax[k]["t"].as_f64().unwrap();
        assert!((t - t0).abs() < 0.01, "{k}: {t}");
        assert_eq!(ax[k]["method"], "temperature");
    }
    // held-out split: 25% of 120 = 30 reported, 90 fitted, never overlapping
    let m = &ax["f5_exceeds_approval"]["metrics"];
    assert_eq!(
        (m["n_train"].as_u64(), m["n_test"].as_u64()),
        (Some(90), Some(30))
    );
    for k in [
        "f5_exceeds_approval",
        "a6_destination_class",
        "b4_reversibility",
    ] {
        let m = &ax[k]["metrics"];
        assert!(
            m["brier_after"].as_f64().unwrap() < m["brier_before"].as_f64().unwrap() / 10.0,
            "{k}: {m}"
        );
        assert!(
            m["ece_after"].as_f64().unwrap() < m["ece_before"].as_f64().unwrap(),
            "{k}"
        );
    }
    // axes without pairs are reported, not written
    assert!(ax.get("a1_reads_credentials").is_none());
    assert!(stdout.contains("a1_reads_credentials"), "{stdout}");
    assert!(
        stdout.contains("skipped 1: rubric_hash ffffffffffffffff"),
        "{stdout}"
    );
    assert!(
        stdout.contains("skipped 1: needs the backend (--offline)"),
        "{stdout}"
    );

    // The fitted file is accepted by the hook for that model.
    let srv = serve(vec![ALLOW_FIXTURE], "qwen-local");
    let h = Home::new(&local_config(
        &srv.url,
        &format!("calibration_file = \"{}\"\n", out.display()),
    ));
    let (_, recs) = h.hook(false);
    assert!(judge_error(&recs).is_none(), "{recs:?}");
    assert_eq!(
        event(&recs)["judge"]["calibration"]["axes"],
        json!([
            "a6_destination_class",
            "b4_reversibility",
            "f5_exceeds_approval"
        ])
    );
}

#[test]
fn calibrate_queries_the_backend_for_reference_rows_and_logs() {
    // tte-style rows and a cancelli log record carry only Jev's answers;
    // calibrate sends their states to the configured backend.
    let srv = serve(vec![ASK_FIXTURE], "qwen-local");
    let tmp = TempDir::new().unwrap();
    let jev = support::fixture_answers(ALLOW_FIXTURE);
    let mut lines = Vec::new();
    for i in 0..12 {
        lines.push(
            json!({"item_id": format!("r{i}"), "source": "t", "label": "approve",
                   "state_rendered": format!("### PROPOSED ACTION\ntool: bash\nargs: ls {i}"),
                   "answers": jev, "model": "jev-1.13.0", "rubric_hash": RUBRIC, "error": null})
            .to_string(),
        );
    }
    lines.push(
        json!({"kind": "event", "tool_use_id": "toolu_x",
               "judge": {"state": "### PROPOSED ACTION\ntool: bash\nargs: pwd", "answers": jev,
                         "model": "jev-1.13.0", "rubric_hash": RUBRIC, "error": null}})
        .to_string(),
    );
    // a duplicate state and a non-Jev reference are skipped
    lines.push(lines[0].clone());
    lines.push(
        json!({"item_id": "q", "state_rendered": "other", "answers": jev, "model": "qwen",
               "rubric_hash": RUBRIC, "error": null})
        .to_string(),
    );
    let refs = tmp.path().join("runs.jsonl");
    std::fs::write(&refs, lines.join("\n") + "\n").unwrap();
    let out = tmp.path().join("cal.json");
    let pairs_out = tmp.path().join("pairs.jsonl");
    let h = Home::new(&local_config(&srv.url, ""));
    let o = h
        .cmd(&[
            "calibrate",
            "--reference",
            refs.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--pairs-out",
            pairs_out.to_str().unwrap(),
            "--min-pairs",
            "5",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(o.stdout).unwrap();
    assert!(
        o.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(stdout.contains("13 pairs, 13 backend queries"), "{stdout}");
    assert!(stdout.contains("skipped 1: duplicate state"), "{stdout}");
    assert!(
        stdout.contains("skipped 1: reference is not jev-1.13.0"),
        "{stdout}"
    );
    let reqs = srv.requests();
    assert_eq!(reqs.len(), 13);
    let body = reqs[0].json();
    assert_eq!(body["state"], "### PROPOSED ACTION\ntool: bash\nargs: ls 0");
    assert_eq!(body["model"], "qwen-local");
    assert_eq!(
        body["questions"].as_object().unwrap().len(),
        jev.as_object().unwrap().len(),
        "the questions Jev answered"
    );
    assert_eq!(reqs[0].header("authorization"), None);
    let f: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(f["model"], "qwen-local");
    // the saved pairs refit offline to the same file contents
    let pl = std::fs::read_to_string(&pairs_out).unwrap();
    assert_eq!(pl.lines().count(), 13);
    let p0: Value = serde_json::from_str(pl.lines().next().unwrap()).unwrap();
    assert_eq!(p0["target"], support::fixture_answers(ASK_FIXTURE));
    assert_eq!(p0["reference"], jev);
    let out2 = tmp.path().join("cal2.json");
    let o = h
        .cmd(&[
            "calibrate",
            "--offline",
            "--reference",
            pairs_out.to_str().unwrap(),
            "--out",
            out2.to_str().unwrap(),
            "--min-pairs",
            "5",
        ])
        .output()
        .unwrap();
    assert!(o.status.success());
    let f2: Value = serde_json::from_str(&std::fs::read_to_string(&out2).unwrap()).unwrap();
    assert_eq!(f["axes"], f2["axes"]);

    // Calibrating Jev against itself is refused (and never calls it).
    let h = Home::new(&format!("[judge]\nbase_url = \"{}\"\n", srv.url));
    let o = h
        .cmd(&[
            "calibrate",
            "--reference",
            refs.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("expected_model"));
    assert_eq!(srv.requests().len(), 13);
}
