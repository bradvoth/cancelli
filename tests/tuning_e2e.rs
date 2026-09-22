//! Tunables (D18–D20) end to end through the real `cancelli` binary, offline.
//!
//! Every test writes a temp `config.toml` under a temp `XDG_CONFIG_HOME`
//! (with a temp `HOME`), pipes a PreToolUse payload into `cancelli hook`,
//! and asserts on the log records and stdout. For each tunable group at
//! least one test shows the verdict (or, for context limits, the rendered
//! Jev state) actually changes relative to the same run on defaults.
//!
//! Jev runs use a local stand-in server that replays the POC's real cached
//! jev-1.13.0 answers (tests/fixtures/jev), as tests/jev_e2e.rs does. No
//! network is used.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tempfile::TempDir;

const KEY: &str = "tsk_test_DO_NOT_LOG_tuning";
const WARN_CMD: &str = "rsync -avz ./data user@host:/backup/";
/// POC fixtures: pair 2 deny (T2 deny, f5 0.97), pair 4 deny (T5 ask, f5 0.79).
const DENY_FIXTURE: &str = "8eac397736ea6725ba3d8f5ca58eac72a3cd35c39978d05a653070d992766a48";
const ASK_FIXTURE: &str = "200553f760e355d54f1a48d9e080ce80a9c7d8c3e96fdc2302894b805dc286c9";
const EMBEDDED_RUBRIC_HASH: &str = "0fd1f245ae1c7ef3";

// ------------------------------------------------------------ server --

/// Serve one cached fixture's answers (optionally renaming answer keys) to
/// every request; returns the base URL and the captured request bodies.
fn serve(
    fixture: &'static str,
    rename: Option<(&'static str, &'static str)>,
) -> (String, Arc<Mutex<Vec<String>>>) {
    let path = format!(
        "{}/tests/fixtures/jev/{fixture}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut answers = v["answers"].as_object().unwrap().clone();
    if let Some((from, to)) = rename {
        let a = answers.remove(from).unwrap();
        answers.insert(to.to_string(), a);
    }
    let body = json!({"model": "jev-1.13.0", "answers": answers, "usage": v["usage"]}).to_string();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = Arc::clone(&seen);
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut s) = conn else { continue };
            if let Some(b) = read_body(&mut s) {
                seen2.lock().unwrap().push(b);
            }
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                 x-typesafe-request-id: req_tuning\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    (url, seen)
}

fn read_body(s: &mut TcpStream) -> Option<String> {
    let mut r = BufReader::new(s.try_clone().ok()?);
    let mut len = 0usize;
    loop {
        let mut l = String::new();
        r.read_line(&mut l).ok()?;
        let l = l.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
        {
            len = v.trim().parse().ok()?;
        }
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body).ok()?;
    Some(String::from_utf8_lossy(&body).into_owned())
}

// --------------------------------------------------------------- runs --

struct Run {
    code: i32,
    stdout: String,
    records: Vec<Value>,
}

impl Run {
    fn event(&self) -> &Value {
        self.records
            .iter()
            .find(|r| r["kind"] == "event")
            .expect("event record")
    }
    fn config_errors(&self) -> Vec<String> {
        self.of_kind("error")
    }
    fn config_warnings(&self) -> Vec<String> {
        self.of_kind("warning")
    }
    fn of_kind(&self, kind: &str) -> Vec<String> {
        self.records
            .iter()
            .filter(|r| r["kind"] == kind && r["stage"] == "config")
            .map(|r| {
                r.get("error")
                    .or_else(|| r.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            })
            .collect()
    }
}

struct Env {
    _dir: TempDir,
    home: PathBuf,
    xdg: PathBuf,
    logs: PathBuf,
}

impl Env {
    fn new(config: &str) -> Env {
        let dir = TempDir::new().unwrap();
        let home = dir.path().join("home");
        let xdg = dir.path().join("xdg");
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(xdg.join("cancelli")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(xdg.join("cancelli/config.toml"), config).unwrap();
        Env {
            _dir: dir,
            home,
            xdg,
            logs,
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_cancelli"));
        c.args(args)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env("CANCELLI_LOG_DIR", &self.logs)
            .env_remove("CANCELLI_MODE")
            .env_remove("TYPESAFE_BASE_URL")
            .env_remove("TYPESAFE_API_KEY");
        for v in [
            "ALL_PROXY",
            "all_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
        ] {
            c.env_remove(v);
        }
        c
    }

    fn hook(&self, args: &[&str], cmd: &str, transcript: Option<&Path>, key: bool) -> Run {
        let payload = json!({
            "session_id": "sess-tuning",
            "transcript_path": transcript.map_or("/nonexistent/cancelli-tuning/t.jsonl".into(), |p| p.display().to_string()),
            "cwd": "/work",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use_id": "toolu_cur",
            "tool_input": {"command": cmd},
        })
        .to_string();
        let mut c = self.cmd(args);
        if key {
            c.env("TYPESAFE_API_KEY", KEY);
        }
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let mut records = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.logs) {
            for e in entries.flatten() {
                let text = std::fs::read_to_string(e.path()).unwrap();
                assert!(!text.contains(KEY), "API key leaked into the log");
                for line in text.lines().filter(|l| !l.is_empty()) {
                    records.push(serde_json::from_str(line).unwrap());
                }
            }
        }
        Run {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8(out.stdout).unwrap(),
            records,
        }
    }
}

/// CARE only: hook in dry-run, no API key (a WARN goes to Jev, which fails
/// before any network and asks).
fn care(config: &str, cmd: &str) -> Run {
    care_args(config, cmd, &["hook", "--dry-run"])
}

fn care_args(config: &str, cmd: &str, args: &[&str]) -> Run {
    let r = Env::new(config).hook(args, cmd, None, false);
    assert_eq!(r.code, 0);
    assert_eq!(r.stdout, "", "dry-run is silent");
    r
}

/// Jev: hook against the fixture server with a key.
fn jev(config: &str, url: &str, args: &[&str], transcript_calls: &[&str]) -> Run {
    let cfg = format!(
        "dry_run = false\n[judge]\nbase_url = \"{url}\"\ntimeout_ms = 2000\nbudget_ms = 4000\n{config}"
    );
    let env = Env::new(&cfg);
    let t = transcript(&env.home, transcript_calls);
    let r = env.hook(args, WARN_CMD, Some(&t), true);
    assert_eq!(r.code, 0);
    r
}

fn transcript(dir: &Path, calls: &[&str]) -> PathBuf {
    let mut lines = vec![
        json!({"type": "user", "message": {"role": "user", "content": "Back up the data dir to the backup host."}}),
    ];
    for (i, c) in calls.iter().enumerate() {
        lines.push(json!({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": format!("toolu_{i}"), "name": "Bash", "input": {"command": c}}]}}));
    }
    let p = dir.join("session.jsonl");
    let text: Vec<String> = lines.iter().map(Value::to_string).collect();
    std::fs::write(&p, text.join("\n") + "\n").unwrap();
    p
}

fn fired(ev: &Value) -> Vec<String> {
    ev["fired_rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect()
}

fn overrides(ev: &Value) -> Vec<String> {
    ev["overrides"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

fn decision(r: &Run) -> Option<String> {
    (!r.stdout.trim().is_empty()).then(|| {
        let v: Value = serde_json::from_str(r.stdout.trim()).unwrap();
        v["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap()
            .to_string()
    })
}

// ------------------------------------------------------------ CARE --

#[test]
fn defaults_log_fingerprint_and_no_overrides() {
    let r = care("", WARN_CMD);
    assert!(r.config_errors().is_empty() && r.config_warnings().is_empty());
    let ev = r.event();
    assert_eq!(ev["aggregate"], 0.345);
    assert_eq!(ev["provisional"]["balanced"], "WARN");
    assert_eq!(ev["final"], "ask");
    assert_eq!(ev["overrides"], json!([]));
    assert_eq!(
        ev["config_fingerprint"],
        cancelli::tunables::Tunables::default().fingerprint()
    );
    assert_eq!(ev["rubric_hash"], EMBEDDED_RUBRIC_HASH);
}

#[test]
fn modes_lowering_balanced_tau_high_turns_warn_into_deny() {
    let ev = care("[care.modes.balanced]\ntau_high = 0.30\n", WARN_CMD);
    let ev = ev.event();
    assert_eq!(ev["aggregate"], 0.345);
    assert_eq!(ev["provisional"]["balanced"], "DENY");
    assert_eq!(ev["provisional"]["strict"], "DENY");
    assert_eq!(ev["provisional"]["auto"], "WARN", "other modes untouched");
    assert_eq!(ev["final"], "deny");
    assert_eq!(ev["would_emit"], "deny");
    assert_eq!(ev["would_adjudicate"], false);
    assert_eq!(overrides(ev), vec!["care.modes.balanced.tau_high"]);
}

#[test]
fn rules_disabling_se_p_103_changes_fired_rules_and_verdict() {
    let base = care("", WARN_CMD);
    assert_eq!(fired(base.event()), vec!["SE-P-103"]);
    let r = care("[care.rules.\"SE-P-103\"]\nenabled = false\n", WARN_CMD);
    let ev = r.event();
    assert!(fired(ev).is_empty());
    assert_eq!(ev["layers"]["L4"]["score"], 0.0);
    assert_eq!(ev["aggregate"], 0.12);
    assert_eq!(ev["provisional"]["balanced"], "ALLOW");
    assert_eq!(ev["final"], "allow");
    assert_eq!(overrides(ev), vec!["care.rules.\"SE-P-103\".enabled"]);
    // A confidence override feeds both L4 and p_rule (π_mitre 1.0 · 0.85 >= 0.80).
    let r = care(
        "[care.rules]\n\"SE-P-103\" = { confidence = 0.85 }\n",
        WARN_CMD,
    );
    let ev = r.event();
    assert_eq!(ev["fired_rules"][0]["conf"], 0.85);
    assert_eq!(ev["scores"]["pat"], 0.85);
    assert_eq!(ev["skip_predicate"], "p_rule:SE-P-103");
    assert_eq!(ev["final"], "deny");
}

#[test]
fn provenance_raising_gtfobins_pi_fires_p_rule_on_a_gtfobins_shell() {
    let cmd = r"find . -exec /bin/sh \;";
    let base = care("", cmd);
    let ev = base.event();
    assert_eq!(fired(ev), vec!["SE-P-108"]);
    assert_eq!(ev["fired_rules"][0]["tier"], "gtfobins");
    assert_eq!(
        ev["skip_predicate"],
        Value::Null,
        "0.85 · 0.9 = 0.765 < 0.80"
    );
    assert_eq!(ev["final"], "ask");
    let r = care("[care.provenance]\ngtfobins = 0.9\n", cmd);
    let ev = r.event();
    assert_eq!(ev["fired_rules"][0]["pi"], 0.9);
    assert_eq!(ev["skip_predicate"], "p_rule:SE-P-108");
    assert_eq!(ev["final"], "deny");
}

#[test]
fn resolution_theta_rule_theta_sem_and_h_sem() {
    // θ_rule 0.75: the same GTFOBins shell now meets p_rule at π 0.85.
    let r = care(
        "[care.resolution]\ntheta_rule = 0.75\n",
        r"find . -exec /bin/sh \;",
    );
    assert_eq!(r.event()["skip_predicate"], "p_rule:SE-P-108");
    assert_eq!(r.event()["final"], "deny");
    // θ_sem 0.6: EXECUTION_CHAIN (0.60) now fires p_sem.
    let base = care("", "echo hi | sh");
    assert_eq!(base.event()["final"], "ask");
    let r = care("[care.resolution]\ntheta_sem = 0.6\n", "echo hi | sh");
    assert_eq!(r.event()["skip_predicate"], "p_sem:EXECUTION_CHAIN");
    assert_eq!(r.event()["final"], "deny");
    // H_sem without DESTRUCTIVE: rm -rf node_modules is no longer skipped.
    let base = care("", "rm -rf node_modules");
    assert_eq!(base.event()["skip_predicate"], "p_sem:DESTRUCTIVE");
    assert_eq!(base.event()["final"], "deny");
    let r = care(
        "[care.resolution]\nh_sem = [\"EXECUTION_CHAIN\", \"PERSISTENCE\"]\n",
        "rm -rf node_modules",
    );
    assert_eq!(r.event()["skip_predicate"], Value::Null);
    assert_eq!(r.event()["would_adjudicate"], true);
    assert_eq!(r.event()["final"], "ask");
}

#[test]
fn weights_raising_w_sem_turns_allow_into_warn() {
    let base = care("", "npx foo");
    assert_eq!(base.event()["final"], "allow");
    let r = care("[care.weights]\nsem = 0.5\n", "npx foo");
    let ev = r.event();
    assert_eq!(ev["aggregate"], 0.175);
    assert_eq!(ev["provisional"]["balanced"], "WARN");
    assert_eq!(ev["final"], "ask");
}

#[test]
fn class_base_raising_unknown_turns_allow_into_warn() {
    let r = care("[care.class_base]\nUNKNOWN = 0.6\n", "npx foo");
    let ev = r.event();
    assert_eq!(ev["scores"]["sem"], 0.6);
    assert_eq!(ev["aggregate"], 0.18);
    assert_eq!(ev["final"], "ask");
}

#[test]
fn structure_raising_the_pipe_penalty_changes_the_strict_verdict() {
    let args = ["hook", "--dry-run", "--mode", "strict"];
    let base = care_args("", "ls | wc -l", &args);
    assert_eq!(base.event()["provisional"]["strict"], "ALLOW");
    assert_eq!(base.event()["final"], "allow");
    let r = care_args("[care.structure]\npipe = 1.0\n", "ls | wc -l", &args);
    let ev = r.event();
    assert_eq!(ev["scores"]["struct"], 1.0);
    assert_eq!(ev["provisional"]["strict"], "WARN");
    assert_eq!(ev["final"], "ask");
}

#[test]
fn path_raising_traversal_read_turns_allow_into_warn() {
    let base = care("", "cat ../../x");
    assert_eq!(base.event()["final"], "allow");
    let r = care("[care.path]\ntraversal_read = 0.6\n", "cat ../../x");
    let ev = r.event();
    assert_eq!(ev["scores"]["path"], 0.6);
    assert_eq!(ev["provisional"]["balanced"], "WARN");
    assert_eq!(ev["final"], "ask");
}

// ------------------------------------------------------------- Jev --

#[test]
fn verdicts_mapping_t5_to_deny_changes_enforce_output_from_ask_to_deny() {
    let (url, _) = serve(ASK_FIXTURE, None);
    let base = jev("", &url, &["hook"], &["du -sh ./data"]);
    assert_eq!(base.event()["judge"]["tier"], "T5");
    assert_eq!(decision(&base).as_deref(), Some("ask"));
    let r = jev(
        "[jev.verdicts]\nT5 = \"deny\"\n",
        &url,
        &["hook"],
        &["du -sh ./data"],
    );
    assert_eq!(r.event()["judge"]["tier"], "T5");
    assert_eq!(r.event()["judge"]["verdict"], "deny");
    assert_eq!(r.event()["final"], "deny");
    assert_eq!(decision(&r).as_deref(), Some("deny"));
    assert_eq!(overrides(r.event()), vec!["jev.verdicts.T5"]);
}

#[test]
fn thresholds_raising_f5_ask_turns_t5_into_t6_and_the_a6_gate_is_tunable() {
    let (url, _) = serve(ASK_FIXTURE, None);
    let base = jev("", &url, &["hook", "--dry-run"], &[]);
    let j = &base.event()["judge"];
    assert_eq!(j["tier"], "T5");
    assert!(
        j["signals"]
            .as_object()
            .unwrap()
            .keys()
            .all(|k| !k.starts_with("a6_")),
        "f5 0.79 <= gate 0.8: a6 not read"
    );
    let r = jev(
        "[jev.thresholds]\nf5_ask = 0.8\n",
        &url,
        &["hook", "--dry-run"],
        &[],
    );
    let j = &r.event()["judge"];
    assert_eq!(j["tier"], "T6");
    assert_eq!(j["verdict"], "allow");
    assert_eq!(r.event()["final"], "allow");
    // lowering the a6 gate below f5 = 0.79 makes a6 readable
    let r = jev(
        "[jev.thresholds]\nunknown_f5_gate = 0.7\n",
        &url,
        &["hook", "--dry-run"],
        &[],
    );
    let sig = r.event()["judge"]["signals"].as_object().unwrap().clone();
    assert!(
        sig.contains_key("a6_destination_class=unknown_remote"),
        "{sig:?}"
    );
}

#[test]
fn tier_order_moving_t2_last_turns_deny_into_ask() {
    let (url, _) = serve(DENY_FIXTURE, None);
    let base = jev("", &url, &["hook", "--dry-run"], &[]);
    assert_eq!(base.event()["judge"]["tier"], "T2");
    assert_eq!(base.event()["final"], "deny");
    let r = jev(
        "[jev.tiers]\norder = [\"T1\", \"T3\", \"T4\", \"T5\", \"T2\"]\n",
        &url,
        &["hook", "--dry-run"],
        &[],
    );
    let j = &r.event()["judge"];
    assert_eq!(j["tier"], "T5");
    assert_eq!(j["tier_rule"], "f5_exceeds_approval > 0.5");
    assert_eq!(r.event()["final"], "ask");
}

#[test]
fn context_history_budget_clip_and_max_level_change_the_rendered_state() {
    let (url, seen) = serve(ASK_FIXTURE, None);
    let calls = ["ls -la ./data", "du -sh ./data", "wc -l ./data/index.csv"];
    let base = jev("", &url, &["hook", "--dry-run"], &calls);
    let state = base.event()["judge"]["state"].as_str().unwrap().to_string();
    assert!(state.contains(
        "[1] bash(ls -la ./data)\n[2] bash(du -sh ./data)\n[3] bash(wc -l ./data/index.csv)"
    ));
    // history budget 30: only the newest call fits (it is always kept)
    let r = jev(
        "[jev.context]\nhistory_chars = 30\n",
        &url,
        &["hook", "--dry-run"],
        &calls,
    );
    let j = &r.event()["judge"];
    let st = j["state"].as_str().unwrap();
    assert!(
        st.ends_with(
            "### PRIOR AGENT ACTIONS (most recent last)\n[1] bash(wc -l ./data/index.csv)"
        ),
        "{st}"
    );
    assert_ne!(j["state_hash"], base.event()["judge"]["state_hash"]);
    let wire: Value = serde_json::from_str(seen.lock().unwrap().last().unwrap()).unwrap();
    assert_eq!(wire["state"], st, "the budgeted state is what is sent");
    // field clip 10: args are clipped with the POC's marker
    let r = jev(
        "[jev.context]\nfield_chars = 10\n",
        &url,
        &["hook", "--dry-run"],
        &calls,
    );
    let st = r.event()["judge"]["state"].as_str().unwrap().to_string();
    assert!(
        st.contains("args: rsync -avz\n[... truncated, 26 more characters]"),
        "{st}"
    );
    // max level L1: no prior actions, 38 questions
    let r = jev(
        "[jev.context]\nmax_level = \"L1\"\n",
        &url,
        &["hook", "--dry-run"],
        &calls,
    );
    let j = &r.event()["judge"];
    assert_eq!(j["level"], "l1_request");
    assert!(
        j["context"]["level_reason"]
            .as_str()
            .unwrap()
            .contains("capped at l1_request")
    );
    assert!(!j["state"].as_str().unwrap().contains("PRIOR AGENT ACTIONS"));
    assert_eq!(j["questions_sent"].as_array().unwrap().len(), 38);
}

/// The embedded rubric with `f5_exceeds_approval` renamed.
fn renamed_rubric(dir: &Path) -> PathBuf {
    let text = std::fs::read_to_string(format!(
        "{}/data/jev/v1_policy_distilled.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
    .replace("f5_exceeds_approval", "f5_exceeds_mandate");
    let p = dir.join("renamed.yaml");
    std::fs::write(&p, text).unwrap();
    p
}

#[test]
fn rubric_file_with_a_renamed_axis_warns_and_its_tiers_never_fire() {
    let dir = TempDir::new().unwrap();
    let rubric = renamed_rubric(dir.path());
    let (url, seen) = serve(
        DENY_FIXTURE,
        Some(("f5_exceeds_approval", "f5_exceeds_mandate")),
    );
    let r = jev(
        &format!("[jev]\nrubric_file = \"{}\"\n", rubric.display()),
        &url,
        &["hook", "--dry-run"],
        &[],
    );
    assert!(r.config_errors().is_empty(), "{:?}", r.config_errors());
    let warnings = r.config_warnings();
    for t in ["T2", "T5"] {
        assert!(
            warnings
                .iter()
                .any(|w| w.starts_with(&format!("jev tier {t} reads f5_exceeds_approval"))),
            "{t}: {warnings:?}"
        );
    }
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("calibrated on the embedded rubric"))
    );
    let ev = r.event();
    let j = &ev["judge"];
    let hash = j["rubric_hash"].as_str().unwrap();
    assert_ne!(hash, EMBEDDED_RUBRIC_HASH);
    assert_eq!(
        ev["rubric_hash"], hash,
        "record and judge agree on the rubric used"
    );
    assert!(warnings.iter().any(|w| w.contains(hash)));
    assert!(overrides(ev).contains(&"jev.rubric_file".to_string()));
    assert_eq!(j["error"], Value::Null);
    assert!(j["signals"]["f5_exceeds_mandate"].as_f64().unwrap() > 0.9);
    assert_eq!(j["tier"], "T6", "T2 would fire on f5 = 0.97 but cannot");
    assert_eq!(j["verdict"], "allow");
    let wire: Value = serde_json::from_str(seen.lock().unwrap().last().unwrap()).unwrap();
    assert!(wire["questions"].get("f5_exceeds_mandate").is_some());
    assert!(wire["questions"].get("f5_exceeds_approval").is_none());
}

// ------------------------------------------------------------ invalid --

#[test]
fn invalid_values_fall_back_to_their_default_with_an_error_record() {
    let dir = TempDir::new().unwrap();
    let bad_rubric = dir.path().join("bad.yaml");
    std::fs::write(&bad_rubric, "name: x\naxes: []\n").unwrap();
    let cases: Vec<(String, &str)> = vec![
        ("[care.weights]\nsem = -0.3\n".into(), "care.weights.sem"),
        (
            "[care.modes.balanced]\ntau_low = 0.35\ntau_high = 0.15\n".into(),
            "care.modes.balanced.tau_low",
        ),
        (
            "[care.rules.\"SE-P-999\"]\nenabled = false\n".into(),
            "care.rules.\"SE-P-999\"",
        ),
        (
            "[jev.tiers]\norder = [\"T1\", \"T2\", \"TX\"]\n".into(),
            "jev.tiers.order",
        ),
        ("[jev.verdicts]\nT9 = \"deny\"\n".into(), "jev.verdicts.T9"),
        (
            format!("[jev]\nrubric_file = \"{}\"\n", bad_rubric.display()),
            "jev.rubric_file",
        ),
        (
            format!(
                "[jev]\nrubric_file = \"{}\"\n",
                dir.path().join("missing.yaml").display()
            ),
            "jev.rubric_file",
        ),
    ];
    let default_fp = cancelli::tunables::Tunables::default().fingerprint();
    for (cfg, key) in cases {
        let r = care(&cfg, WARN_CMD);
        let errs = r.config_errors();
        assert!(errs.iter().any(|e| e.starts_with(key)), "{key}: {errs:?}");
        let ev = r.event();
        assert_eq!(ev["aggregate"], 0.345, "{key}: default in force");
        assert_eq!(ev["provisional"]["balanced"], "WARN", "{key}");
        assert_eq!(ev["overrides"], json!([]), "{key}");
        assert_eq!(ev["config_fingerprint"], default_fp.as_str(), "{key}");
        assert_eq!(ev["rubric_hash"], EMBEDDED_RUBRIC_HASH, "{key}");
    }
    // only the invalid key falls back; its valid neighbours apply
    let r = care("[care.weights]\nsem = -1\npat = 0.5\n", WARN_CMD);
    assert_eq!(overrides(r.event()), vec!["care.weights.pat"]);
    // unknown keys are warnings, not errors
    let r = care(
        "[care.weights]\nsemantic = 0.1\n[jev.context]\nmax_chars = 1\n",
        WARN_CMD,
    );
    assert!(r.config_errors().is_empty());
    assert_eq!(r.config_warnings().len(), 2);
}

// -------------------------------------------------------- fingerprint --

#[test]
fn fingerprint_is_layout_independent_and_overrides_list_exactly_the_changed_keys() {
    let a = care(
        "[care.weights]\nsem = 0.25\npath = 0.30\n[jev.context]\nhistory_chars = 8000\n",
        "git status",
    );
    let b = care(
        "jev.context.history_chars = 8000\n[care.weights]\npath = 0.3\nsem = 0.250\n",
        "git status",
    );
    let fa = a.event()["config_fingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(fa.len(), 16);
    assert_eq!(fa, b.event()["config_fingerprint"].as_str().unwrap());
    assert_eq!(
        overrides(a.event()),
        vec!["care.weights.sem", "jev.context.history_chars"],
        "path = 0.30 equals the default, so it is not an override"
    );
    assert_eq!(overrides(a.event()), overrides(b.event()));
    let c = care(
        "[care.weights]\nsem = 0.26\n[jev.context]\nhistory_chars = 8000\n",
        "git status",
    );
    assert_ne!(fa, c.event()["config_fingerprint"].as_str().unwrap());
    // every record kind carries them, errors included
    let d = care("[care.weights]\nsem = 0.25\npath = \"x\"\n", "git status");
    for rec in &d.records {
        assert_eq!(rec["overrides"], json!(["care.weights.sem"]), "{rec}");
        assert!(rec["config_fingerprint"].is_string());
    }
}

// -------------------------------------------------------------- config --

fn fingerprint_line(out: &str) -> String {
    out.lines()
        .find(|l| l.starts_with("# tunables"))
        .unwrap()
        .to_string()
}

#[test]
fn config_lists_every_tunable_with_source_and_init_documents_without_pinning() {
    let env =
        Env::new("[care.provenance]\ngtfobins = 0.9\n[care.rules.\"SE-P-103\"]\nenabled = false\n");
    let out = String::from_utf8(env.cmd(&["config"]).output().unwrap().stdout).unwrap();
    for k in cancelli::tunables::KNOBS {
        assert!(
            out.lines().any(|l| l.starts_with(&format!("{} = ", k.key))),
            "{} missing",
            k.key
        );
    }
    assert!(out.contains("care.provenance.gtfobins = 0.9  # file\n"));
    assert!(out.contains("care.provenance.mitre = 1.0  # default\n"));
    assert!(
        out.contains("jev.rubric_file = (embedded)  # rubric_hash 0fd1f245ae1c7ef3  # default\n")
    );
    assert!(
        out.contains("care.rules.\"SE-P-103\" = { enabled = false, confidence = 0.75 }  # file\n")
    );
    assert!(out.contains("care.rules.\"SE-P-001\" = { enabled = true, confidence = "));
    assert_eq!(out.matches("care.rules.\"SE-P-").count(), 139);
    assert!(
        fingerprint_line(&out)
            .contains("\"care.provenance.gtfobins\", \"care.rules.\\\"SE-P-103\\\".enabled\"")
    );

    // --init: every tunable is present but commented out
    let fresh = Env::new("");
    std::fs::remove_file(fresh.xdg.join("cancelli/config.toml")).unwrap();
    let default_show = String::from_utf8(fresh.cmd(&["config"]).output().unwrap().stdout).unwrap();
    assert!(fresh.cmd(&["config", "--init"]).status().unwrap().success());
    let text = std::fs::read_to_string(fresh.xdg.join("cancelli/config.toml")).unwrap();
    for k in cancelli::tunables::KNOBS {
        let leaf = k.key.rsplit_once('.').unwrap().1;
        assert!(
            text.contains(&format!("\n# {leaf} = ")),
            "{} not documented",
            k.key
        );
    }
    assert_eq!(text.matches("\n# \"SE-P-").count(), 139);
    let show = String::from_utf8(fresh.cmd(&["config"]).output().unwrap().stdout).unwrap();
    assert!(
        !show.contains("# error") && !show.contains("# warning"),
        "{show}"
    );
    assert_eq!(
        fingerprint_line(&show),
        fingerprint_line(&default_show),
        "nothing pinned"
    );
    // uncommenting every tunable line reproduces the defaults exactly (except
    // rubric_file, whose example path does not exist)
    let (head, tunables) = text.split_at(text.find("## ----").unwrap());
    let uncommented: String = tunables
        .lines()
        .map(|l| match l.strip_prefix("# ") {
            Some(rest) if !rest.starts_with("rubric_file") => rest.to_string(),
            _ => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n");
    let uncommented = format!("{head}{uncommented}\n");
    std::fs::write(fresh.xdg.join("cancelli/config.toml"), uncommented).unwrap();
    let show = String::from_utf8(fresh.cmd(&["config"]).output().unwrap().stdout).unwrap();
    assert!(
        !show.contains("# error") && !show.contains("# warning"),
        "{show}"
    );
    assert_eq!(fingerprint_line(&show), fingerprint_line(&default_show));
    assert!(show.contains("care.weights.sem = 0.3  # file\n"));
}
