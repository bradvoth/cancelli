//! D25 `cancelli eval` end to end: a log written by the real hook binary
//! (against the local replay server, tests/support) plus hand-written
//! records in older formats, replayed under modified configs offline, with
//! the replay server, and against a different backend.

mod support;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde_json::{Value, json};
use support::{ALLOW_FIXTURE, ASK_FIXTURE, KEY, Server, bin, records, serve};
use tempfile::TempDir;

const WARN_CMD: &str = "rsync -avz ./data user@host:/backup/";

/// The paper's CARE values for the D27 keys. The fixture log is generated
/// under them (so `rm -rf node_modules` is a p_sem:DESTRUCTIVE deny), and
/// every replay config starts from them.
const PAPER_BAND: &str = "[care.modes.balanced]\ntau_low = 0.15\ntau_high = 0.35\n\
                          [care.rules]\n\"SE-P-003\" = { confidence = 0.95 }\n";
const PAPER_H_SEM: &str = "[care.resolution]\nh_sem = [\"NETWORK_FETCH\", \"EXECUTION_CHAIN\", \
                           \"PRIVILEGE_OR_PERMISSION\", \"PERSISTENCE\", \"DESTRUCTIVE\"]\n";

/// The calls of the session, in transcript order: (tool_use_id, tool, input).
fn calls() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        ("toolu_allow", "Bash", json!({"command": "ls -la"})),
        (
            "toolu_deny",
            "Bash",
            json!({"command": "rm -rf node_modules"}),
        ),
        ("toolu_warn", "Bash", json!({"command": WARN_CMD})),
        ("toolu_read", "Read", json!({"file_path": "/work/a.txt"})),
        (
            "toolu_write",
            "Write",
            json!({"file_path": "/work/big.txt", "content": "x".repeat(5000)}),
        ),
        (
            "toolu_old_read",
            "Read",
            json!({"file_path": "/work/old.txt"}),
        ),
    ]
}

struct Fixture {
    home: TempDir,
    log: PathBuf,
    transcript: PathBuf,
    srv: Server,
}

impl Fixture {
    fn cmd(&self, args: &[&str]) -> std::process::Command {
        let mut c = bin();
        c.args(args)
            .env("HOME", self.home.path())
            .env("TYPESAFE_API_KEY", KEY);
        c
    }

    fn config(&self, name: &str, text: &str) -> PathBuf {
        let p = self.home.path().join(name);
        std::fs::write(&p, text).unwrap();
        p
    }

    /// `cancelli eval --json` -> (records by tool_use_id, summary).
    fn eval_json(&self, config: &Path, offline: bool) -> (BTreeMap<String, Value>, Value) {
        let log = self.log.to_str().unwrap().to_string();
        let cfg = config.to_str().unwrap().to_string();
        let mut args = vec!["eval", "--logs", &log, "--config", &cfg, "--json"];
        if offline {
            args.push("--offline");
        }
        let o = self.cmd(&args).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let text = String::from_utf8(o.stdout).unwrap();
        let mut by_id = BTreeMap::new();
        let mut summary = Value::Null;
        for l in text.lines() {
            let v: Value = serde_json::from_str(l).unwrap();
            if let Some(s) = v.get("summary") {
                summary = s.clone();
            } else {
                by_id.insert(v["tool_use_id"].as_str().unwrap().to_string(), v);
            }
        }
        (by_id, summary)
    }

    fn eval_text(&self, config: &Path, offline: bool) -> String {
        let log = self.log.to_str().unwrap().to_string();
        let cfg = config.to_str().unwrap().to_string();
        let mut args = vec!["eval", "--logs", &log, "--config", &cfg];
        if offline {
            args.push("--offline");
        }
        let o = self.cmd(&args).output().unwrap();
        assert!(o.status.success());
        String::from_utf8(o.stdout).unwrap()
    }
}

/// Run the hook for the first five calls (Jev at the replay server), then
/// append older-format records and an error record.
fn fixture() -> Fixture {
    // warn -> T5 ask; read, write -> T6 allow; later requests -> allow
    let srv = serve(vec![ASK_FIXTURE, ALLOW_FIXTURE], "jev-1.13.0");
    let home = TempDir::new().unwrap();
    let cfg = home.path().join(".config/cancelli");
    std::fs::create_dir_all(&cfg).unwrap();
    std::fs::write(
        cfg.join("config.toml"),
        format!(
            "{PAPER_BAND}{PAPER_H_SEM}[judge]\nbase_url = \"{}\"\n",
            srv.url
        ),
    )
    .unwrap();
    let transcript = home.path().join("session.jsonl");
    let mut lines = vec![json!({"type": "user", "message": {"role": "user",
        "content": "Tidy the project and back up the data."}})];
    for (id, tool, input) in calls() {
        lines.push(json!({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": id, "name": tool, "input": input}]}}));
    }
    let text: Vec<String> = lines.iter().map(Value::to_string).collect();
    std::fs::write(&transcript, text.join("\n") + "\n").unwrap();

    let logdir = home.path().join("logs");
    for (id, tool, input) in calls().into_iter().take(5) {
        let payload = json!({
            "session_id": "sess", "transcript_path": transcript, "cwd": "/work",
            "permission_mode": "default", "hook_event_name": "PreToolUse",
            "tool_name": tool, "tool_use_id": id, "tool_input": input,
        });
        let mut c = bin();
        c.args(["hook", "--dry-run"])
            .env("HOME", home.path())
            .env("CANCELLI_LOG_DIR", &logdir)
            .env("TYPESAFE_API_KEY", KEY)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = c.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        assert!(child.wait_with_output().unwrap().status.success());
    }
    assert_eq!(srv.requests().len(), 3, "warn, read, write reached Jev");
    let mut recs = records(&logdir);
    assert_eq!(recs.len(), 5);
    let by = |id: &str| recs.iter().find(|r| r["tool_use_id"] == id).unwrap();
    assert_eq!(by("toolu_allow")["final"], "allow");
    assert_eq!(by("toolu_deny")["skip_predicate"], "p_sem:DESTRUCTIVE");
    assert_eq!(by("toolu_warn")["judge"]["tier"], "T5");
    assert_eq!(by("toolu_read")["judge"]["tier"], "T6");
    assert!(
        by("toolu_write")["tool_input"]["content"]["truncated"].is_string(),
        "logged input is truncated"
    );

    // Older formats: a pre-D21 Read (no decision), a stub-era WARN whose
    // transcript is gone, a pre-D21 Write with a truncated input, and an
    // error record.
    recs.push(
        json!({"kind": "event", "ts": "2026-09-01T10:00:00-04:00", "version": "0.1.0",
        "tool_name": "Read", "tool_use_id": "toolu_old_read", "session_id": "old",
        "transcript_path": transcript, "cwd": "/work", "mode": "balanced",
        "tool_input": {"file_path": "/work/old.txt"}}),
    );
    recs.push(
        json!({"kind": "event", "ts": "2026-09-01T10:00:01-04:00", "version": "0.1.0",
        "tool_name": "Bash", "tool_use_id": "toolu_old_stub", "session_id": "old",
        "transcript_path": "/nonexistent/session.jsonl", "cwd": "/work", "mode": "balanced",
        "command": WARN_CMD, "aggregate": 0.345, "skip_predicate": null,
        "provisional": {"strict": "WARN", "balanced": "WARN", "auto": "WARN"},
        "fired_rules": [{"id": "SE-P-103"}], "would_adjudicate": true,
        "judge": {"backend": "stub", "decision": "unadjudicated"}, "final": "unadjudicated"}),
    );
    recs.push(
        json!({"kind": "event", "ts": "2026-09-01T10:00:02-04:00", "version": "0.1.0",
        "tool_name": "Write", "tool_use_id": "toolu_old_write", "session_id": "old",
        "transcript_path": transcript, "cwd": "/work", "mode": "balanced",
        "tool_input": {"file_path": "/work/x.txt",
                       "content": {"truncated": "xxxx", "len": 5000, "sha256": "00"}}}),
    );
    recs.push(
        json!({"kind": "error", "ts": "2026-09-01T10:00:03-04:00", "stage": "judge",
        "error": "timeout"}),
    );
    let log = home.path().join("events.jsonl");
    let text: Vec<String> = recs.iter().map(Value::to_string).collect();
    std::fs::write(&log, text.join("\n") + "\n").unwrap();
    Fixture {
        home,
        log,
        transcript,
        srv,
    }
}

fn modified_config(f: &Fixture) -> PathBuf {
    f.config(
        "modified.toml",
        &format!(
            "{PAPER_BAND}[care.resolution]\n\
             h_sem = [\"NETWORK_FETCH\", \"EXECUTION_CHAIN\", \"PRIVILEGE_OR_PERMISSION\", \"PERSISTENCE\"]\n\
             [jev]\nskip_tools = [\"Read\"]\n[jev.thresholds]\nf5_ask = 0.8\n\
             [judge]\nbase_url = \"{}\"\n",
            f.srv.url
        ),
    )
}

fn transitions(by: &BTreeMap<String, Value>) -> Vec<(String, String, String, String)> {
    by.iter()
        .map(|(id, r)| {
            (
                id.clone(),
                r["old"].as_str().unwrap().to_string(),
                r["new"].as_str().unwrap().to_string(),
                r["judge"]["kind"].as_str().unwrap_or("-").to_string(),
            )
        })
        .collect()
}

fn t(id: &str, old: &str, new: &str, judge: &str) -> (String, String, String, String) {
    (id.into(), old.into(), new.into(), judge.into())
}

fn why(r: &Value) -> String {
    r["why"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}

#[test]
fn offline_eval_reports_exact_transitions() {
    let f = fixture();
    let cfg = modified_config(&f);
    let (by, s) = f.eval_json(&cfg, true);
    assert_eq!(
        transitions(&by),
        vec![
            t("toolu_allow", "allow", "allow", "-"),
            t("toolu_deny", "deny", "needs_judge", "needs_judge"),
            t("toolu_old_read", "none", "none", "-"),
            t("toolu_old_stub", "ask", "needs_judge", "needs_judge"),
            t("toolu_old_write", "none", "needs_judge", "input_truncated"),
            t("toolu_read", "allow", "none", "-"),
            t("toolu_warn", "ask", "allow", "reused"),
            t("toolu_write", "allow", "allow", "reused"),
        ]
    );
    let w = why(&by["toolu_deny"]);
    assert!(w.contains("skip p_sem:DESTRUCTIVE→none"), "{w}");
    assert!(w.contains("newly reaches the judge"), "{w}");
    assert!(w.contains("needs judge (offline; no logged state)"), "{w}");
    let w = why(&by["toolu_warn"]);
    assert!(
        w.contains("tier T5→T6") && w.contains("answers reused"),
        "{w}"
    );
    assert_eq!(
        (
            by["toolu_warn"]["old_tier"].as_str(),
            by["toolu_warn"]["new_tier"].as_str()
        ),
        (Some("T5"), Some("T6"))
    );
    assert!(why(&by["toolu_read"]).contains("jev.skip_tools: not judged"));
    assert!(
        by["toolu_old_stub"]["old_note"]
            .as_str()
            .unwrap()
            .contains("stub-era")
    );
    assert!(
        by["toolu_old_read"]["old_note"]
            .as_str()
            .unwrap()
            .contains("pre-D21")
    );
    assert_eq!(
        by["toolu_deny"]["target"], "rm -rf node_modules",
        "Bash replayed from the logged command"
    );
    // summary
    assert_eq!(s["lines"], 9);
    assert_eq!(s["replayed"], 8);
    assert_eq!(s["changed"], 5);
    assert_eq!(s["skipped"], json!({"not an event (kind=error)": 1}));
    assert_eq!(s["offline"], true);
    assert_eq!(
        s["overrides"],
        json!([
            // the paper pins differ from the D27 defaults
            "care.modes.balanced.tau_high",
            "care.modes.balanced.tau_low",
            "care.resolution.h_sem",
            "care.rules.\"SE-P-003\".confidence",
            "jev.skip_tools",
            "jev.thresholds.f5_ask"
        ])
    );
    assert_eq!(f.srv.requests().len(), 3, "offline never queries");
}

#[test]
fn online_eval_rebuilds_new_judge_calls_from_the_transcript() {
    let f = fixture();
    let cfg = modified_config(&f);
    let (by, s) = f.eval_json(&cfg, false);
    assert_eq!(
        transitions(&by),
        vec![
            t("toolu_allow", "allow", "allow", "-"),
            t("toolu_deny", "deny", "allow", "rebuilt"),
            t("toolu_old_read", "none", "none", "-"),
            t("toolu_old_stub", "ask", "needs_judge", "needs_judge"),
            t("toolu_old_write", "none", "needs_judge", "input_truncated"),
            t("toolu_read", "allow", "none", "-"),
            t("toolu_warn", "ask", "allow", "reused"),
            t("toolu_write", "allow", "allow", "reused"),
        ]
    );
    assert!(why(&by["toolu_old_stub"]).contains("needs judge (no state)"));
    assert_eq!(s["changed"], 5);
    // exactly one new request: the rebuilt state of the rm -rf call, with
    // the prior calls from the transcript and the key
    let reqs = f.srv.requests();
    assert_eq!(reqs.len(), 4);
    let r = &reqs[3];
    assert_eq!(
        r.header("authorization"),
        Some(format!("Bearer {KEY}").as_str())
    );
    let state = r.json()["state"].as_str().unwrap().to_string();
    assert!(state.starts_with("### PROPOSED ACTION\ntool: bash\nargs: rm -rf node_modules\n"));
    assert!(state.contains("Tidy the project and back up the data."));
    assert!(state.contains("[1] bash(ls -la)"), "{state}");
    assert!(!state.contains(WARN_CMD), "calls after it are not context");
}

#[test]
fn a_different_backend_gets_the_logged_states_resent() {
    let f = fixture();
    let local = serve(vec![ALLOW_FIXTURE], "qwen-local");
    let cfg = f.config(
        "local.toml",
        &format!(
            "{PAPER_BAND}{PAPER_H_SEM}[judge]\nbase_url = \"{}\"\nexpected_model = \"qwen-local\"\napi_key_required = false\n",
            local.url
        ),
    );
    let (by, _) = f.eval_json(&cfg, false);
    assert_eq!(
        transitions(&by),
        vec![
            t("toolu_allow", "allow", "allow", "-"),
            t("toolu_deny", "deny", "deny", "-"),
            t("toolu_old_read", "none", "allow", "rebuilt"),
            t("toolu_old_stub", "ask", "needs_judge", "needs_judge"),
            t("toolu_old_write", "none", "needs_judge", "input_truncated"),
            t("toolu_read", "allow", "allow", "resent"),
            t("toolu_warn", "ask", "allow", "resent"),
            t("toolu_write", "allow", "allow", "resent"),
        ]
    );
    // the resent states are exactly the logged ones (the Write's full
    // content, which the log itself only keeps truncated)
    let logged: Vec<Value> = std::fs::read_to_string(&f.log)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let state_of = |id: &str| {
        logged.iter().find(|r| r["tool_use_id"] == id).unwrap()["judge"]["state"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let sent: Vec<String> = local
        .requests()
        .iter()
        .map(|r| r.json()["state"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(sent.len(), 4);
    for id in ["toolu_warn", "toolu_read", "toolu_write"] {
        assert!(sent.contains(&state_of(id)), "{id}");
    }
    assert!(sent.iter().any(|s| s.contains("x".repeat(3000).as_str())));
    // api_key_required = false, but a key that is present is still sent
    let bearer = format!("Bearer {KEY}");
    assert!(
        local
            .requests()
            .iter()
            .all(|r| r.header("authorization") == Some(bearer.as_str()))
    );
    let w = why(&by["toolu_warn"]);
    assert!(w.contains("logged state resent (backend "), "{w}");
    assert!(w.contains(&format!("{}/qwen-local", local.host())), "{w}");
    assert_eq!(f.srv.requests().len(), 3, "the old backend is not asked");
    assert!(f.transcript.exists());
}

#[test]
fn same_config_replays_to_no_changes() {
    let f = fixture();
    // exactly the generation config, as a file
    let cfg = f.config(
        "same.toml",
        &format!(
            "{PAPER_BAND}{PAPER_H_SEM}[judge]\nbase_url = \"{}\"\n",
            f.srv.url
        ),
    );
    let (by, s) = f.eval_json(&cfg, true);
    for id in [
        "toolu_allow",
        "toolu_deny",
        "toolu_warn",
        "toolu_read",
        "toolu_write",
    ] {
        let r = &by[id];
        assert_eq!(r["changed"], false, "{id}: {r}");
        assert_eq!(r["old_tier"], r["new_tier"], "{id}");
    }
    for id in ["toolu_warn", "toolu_read", "toolu_write"] {
        assert_eq!(by[id]["judge"]["kind"], "reused", "{id}");
    }
    // only the older-format records move: D21 now judges the Read and the
    // Write, and the stub-era WARN needs the judge
    assert_eq!(s["changed"], 3);
}

#[test]
fn text_output_is_sorted_and_stable() {
    let f = fixture();
    let cfg = modified_config(&f);
    let a = f.eval_text(&cfg, true);
    let b = f.eval_text(&cfg, true);
    assert_eq!(a, b);
    assert!(
        a.contains("records: 9 lines, replayed 8, skipped 1, changed 5\n"),
        "{a}"
    );
    assert!(
        a.contains("  skipped 1: not an event (kind=error)\n"),
        "{a}"
    );
    assert!(a.contains("transition matrix (rows old, columns new)\n"));
    let row = |name: &str| {
        a.lines()
            .find(|l| l.starts_with(name))
            .unwrap()
            .split_whitespace()
            .skip(1)
            .map(|x| x.parse::<u32>().unwrap())
            .collect::<Vec<_>>()
    };
    // columns: allow ask deny none needs-judge
    assert_eq!(row("allow "), vec![2, 0, 0, 1, 0]);
    assert_eq!(row("ask "), vec![1, 0, 0, 0, 1]);
    assert_eq!(row("deny "), vec![0, 0, 0, 0, 1]);
    assert_eq!(row("none "), vec![0, 0, 0, 1, 1]);
    // changed calls sorted by ts: the 2026-09-01 records first
    let table: Vec<&str> = a
        .lines()
        .skip_while(|l| !l.starts_with("changed calls (5)"))
        .skip(2)
        .collect();
    assert_eq!(table.len(), 5, "{a}");
    assert!(
        table[0].starts_with("2026-09-01T10:00:01 Bash"),
        "{}",
        table[0]
    );
    assert!(table[0].contains("ask → needs judge"));
    assert!(table[1].contains("Write") && table[1].contains("input truncated"));
    let mut ts: Vec<&str> = table.iter().map(|l| &l[..19]).collect();
    let sorted = {
        let mut s = ts.clone();
        s.sort();
        s
    };
    assert_eq!(ts, sorted);
    ts.dedup();
}
