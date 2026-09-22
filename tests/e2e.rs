//! End-to-end tests: run the real `cancelli` binary, pipe realistic
//! PreToolUse payloads on stdin, and assert exit code, stdout and the exact
//! log record written under a temp `CANCELLI_LOG_DIR`.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;
use tempfile::TempDir;

struct Run {
    stdout: String,
    code: i32,
    records: Vec<Value>,
}

fn run(args: &[&str], stdin: &str) -> Run {
    let home = TempDir::new().unwrap();
    let logdir = TempDir::new().unwrap();
    run_in(args, stdin, home.path(), logdir.path())
}

fn run_in(args: &[&str], stdin: &str, home: &std::path::Path, logdir: &std::path::Path) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cancelli"))
        .args(args)
        .env("HOME", home)
        .env("CANCELLI_LOG_DIR", logdir)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("CANCELLI_MODE")
        // Never reach the network: with no key, Jev fails before connecting.
        .env_remove("TYPESAFE_API_KEY")
        .env_remove("TYPESAFE_BASE_URL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let mut records = Vec::new();
    if let Ok(entries) = std::fs::read_dir(logdir) {
        for e in entries.flatten() {
            let text = std::fs::read_to_string(e.path()).unwrap();
            for line in text.lines().filter(|l| !l.is_empty()) {
                records.push(serde_json::from_str(line).unwrap());
            }
        }
    }
    Run {
        stdout: String::from_utf8(out.stdout).unwrap(),
        code: out.status.code().unwrap_or(-1),
        records,
    }
}

fn run_enforce(args: &[&str], stdin: &str) -> Run {
    let home = TempDir::new().unwrap();
    let logdir = TempDir::new().unwrap();
    let cfg = home.path().join(".config/cancelli");
    std::fs::create_dir_all(&cfg).unwrap();
    std::fs::write(cfg.join("config.toml"), "dry_run = false\n").unwrap();
    run_in(args, stdin, home.path(), logdir.path())
}

fn payload(tool: &str, input: Value) -> String {
    serde_json::json!({
        "session_id": "sess-1",
        "transcript_path": "/nonexistent/cancelli-e2e/t.jsonl",
        "cwd": "/work",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_use_id": "tu-1",
        "tool_input": input,
    })
    .to_string()
}

#[test]
fn dry_run_bash_dangerous_is_silent_and_logged() {
    let r = run(
        &["hook", "--dry-run"],
        &payload("Bash", serde_json::json!({"command": "rm -rf /"})),
    );
    assert_eq!(r.code, 0);
    assert_eq!(r.stdout, "");
    let rec = r.records.iter().find(|r| r["kind"] == "event").unwrap();
    assert_eq!(rec["tool_name"], "Bash");
    assert_eq!(rec["command"], "rm -rf /");
    assert_eq!(rec["final"], "deny");
    assert_eq!(rec["dry_run"], true);
    assert_eq!(rec["would_emit"], "deny");
    assert_eq!(rec["skip_predicate"], "p_rule:SE-P-001");
    assert!(
        rec["fired_rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "SE-P-001")
    );
    assert!(rec["provisional"]["balanced"] == "DENY");
    assert!(rec["latency_us"].is_u64());
    assert!(rec["rules_version"].as_str().unwrap().starts_with("1.0"));
}

#[test]
fn dry_run_bash_benign_allows() {
    let r = run(
        &["hook", "--dry-run"],
        &payload("Bash", serde_json::json!({"command": "git status"})),
    );
    assert_eq!(r.code, 0);
    assert_eq!(r.stdout, "");
    let rec = r.records.iter().find(|r| r["kind"] == "event").unwrap();
    assert_eq!(rec["final"], "allow");
    assert_eq!(rec["aggregate"], 0.0);
    assert_eq!(rec["would_emit"], Value::Null);
}

#[test]
fn dry_run_obfuscated_base64_decodes_and_denies() {
    let cmd = "eval $(echo 'cm0gLXJmIC8=' | base64 -d)";
    let r = run(
        &["hook", "--dry-run"],
        &payload("Bash", serde_json::json!({"command": cmd})),
    );
    let rec = r.records.iter().find(|r| r["kind"] == "event").unwrap();
    assert_eq!(rec["final"], "deny");
    assert!(
        rec["fixes_applied"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "FIX-007")
    );
    assert!(
        rec["views"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["text"] == "rm -rf /")
    );
}

// Expectation changed by D11/D15 (stub -> Jev): a WARN with no skip now goes
// to Jev; with no API key that is a Jev failure, so `final` is "ask" (was
// "unadjudicated") with an error record. The CARE judge prompt is still
// logged. `backend = "stub"` keeps the old behaviour (next test).
#[test]
fn warn_without_skip_goes_to_jev_and_asks_without_key() {
    let cmd = "rsync -avz ./data user@host:/backup/";
    let r = run(
        &["hook", "--dry-run"],
        &payload("Bash", serde_json::json!({"command": cmd})),
    );
    assert_eq!((r.code, r.stdout.as_str()), (0, ""));
    let rec = r.records.iter().find(|r| r["kind"] == "event").unwrap();
    assert_eq!(rec["final"], "ask");
    assert_eq!(rec["would_adjudicate"], true);
    assert_eq!(rec["would_emit"], "ask");
    let user = rec["judge_prompt"]["user"].as_str().unwrap();
    assert!(user.contains("rsync -avz ./data user@host:/backup/"));
    assert!(user.contains("composite risk score: 0.345"));
    assert!(user.contains("fired rule IDs:       SE-P-103"));
    assert_eq!(rec["judge"]["backend"], "jev");
    assert_eq!(rec["judge"]["decision"], "ask");
    assert_eq!(rec["judge"]["verdict"], "ask");
    // the payload's transcript does not exist -> L0
    assert_eq!(rec["judge"]["level"], "l0_action");
    assert!(
        rec["judge"]["error"]
            .as_str()
            .unwrap()
            .contains("no Jev API key")
    );
    let err = r
        .records
        .iter()
        .find(|r| r["kind"] == "error" && r["stage"] == "judge")
        .unwrap();
    assert_eq!(err["tool_use_id"], "tu-1");
}

#[test]
fn stub_backend_keeps_warn_unadjudicated() {
    let home = TempDir::new().unwrap();
    let logdir = TempDir::new().unwrap();
    let cfg = home.path().join(".config/cancelli");
    std::fs::create_dir_all(&cfg).unwrap();
    std::fs::write(cfg.join("config.toml"), "[judge]\nbackend = \"stub\"\n").unwrap();
    let r = run_in(
        &["hook", "--dry-run"],
        &payload(
            "Bash",
            serde_json::json!({"command": "rsync -avz ./data user@host:/backup/"}),
        ),
        home.path(),
        logdir.path(),
    );
    let rec = r.records.iter().find(|r| r["kind"] == "event").unwrap();
    assert_eq!(rec["final"], "unadjudicated");
    assert_eq!(rec["would_emit"], "ask");
    assert_eq!(rec["judge"]["backend"], "stub");
    assert_eq!(rec["judge"]["decision"], "unadjudicated");
    assert!(!r.records.iter().any(|r| r["kind"] == "error"));
}

#[test]
fn non_bash_tools_are_logged_raw() {
    let r = run(
        &["hook", "--dry-run"],
        &payload(
            "Write",
            serde_json::json!({"file_path": "/work/x.rs", "content": "fn main() {}"}),
        ),
    );
    let rec = r.records.iter().find(|r| r["kind"] == "event").unwrap();
    assert_eq!(rec["tool_name"], "Write");
    assert_eq!(rec["tool_input"]["file_path"], "/work/x.rs");
    assert_eq!(rec["tool_input"]["content"], "fn main() {}");
    assert!(rec.get("command").is_none());
    assert!(rec.get("aggregate").is_none());
    // D21: unscored, so judged (no key here: ask, D15)
    assert_eq!(rec["care"]["reason"], "non-shell tool");
    assert_eq!(rec["judge"]["verdict"], "ask");
    assert_eq!(rec["final"], "ask");
}

#[test]
fn non_bash_large_field_is_truncated_with_sha() {
    let big = "A".repeat(5000);
    let r = run(
        &["hook", "--dry-run"],
        &payload("Read", serde_json::json!({"content": big})),
    );
    let rec = r.records.iter().find(|r| r["kind"] == "event").unwrap();
    let field = &rec["tool_input"]["content"];
    assert_eq!(field["len"], 5000);
    assert_eq!(field["truncated"].as_str().unwrap().len(), 4096);
    assert_eq!(field["sha256"].as_str().unwrap().len(), 64);
}

#[test]
fn mcp_tool_is_logged_raw() {
    let r = run(
        &["hook", "--dry-run"],
        &payload(
            "mcp__github__create_issue",
            serde_json::json!({"title": "bug", "body": "x"}),
        ),
    );
    let rec = r.records.iter().find(|r| r["kind"] == "event").unwrap();
    assert_eq!(rec["tool_name"], "mcp__github__create_issue");
    assert_eq!(rec["tool_input"]["title"], "bug");
}

#[test]
fn malformed_json_fails_open_with_error_record() {
    let r = run(&["hook", "--dry-run"], "this is not json");
    assert_eq!(r.code, 0);
    assert_eq!(r.stdout, "");
    let rec = r.records.iter().find(|r| r["kind"] == "error").unwrap();
    assert_eq!(rec["stage"], "parse_input");
    assert!(rec["stdin_sha256"].as_str().unwrap().len() == 64);
}

#[test]
fn empty_stdin_fails_open() {
    let r = run(&["hook", "--dry-run"], "");
    assert_eq!(r.code, 0);
    assert_eq!(r.stdout, "");
    assert!(
        r.records
            .iter()
            .any(|r| r["kind"] == "error" && r["stage"] == "parse_input")
    );
}

// Expectation changed by D21: a Bash call without a command used to be a
// `bash_input` error record; it is now unscorable, so it is a WARN for Jev
// (here with no key: ask plus a judge error record, D15).
#[test]
fn bash_without_command_goes_to_jev() {
    let r = run(
        &["hook", "--dry-run"],
        &payload("Bash", serde_json::json!({"description": "x"})),
    );
    assert_eq!(r.code, 0);
    assert_eq!(r.stdout, "");
    assert!(!r.records.iter().any(|r| r["stage"] == "bash_input"));
    let rec = r.records.iter().find(|r| r["kind"] == "event").unwrap();
    assert_eq!(rec["care"]["supported"], false);
    assert_eq!(rec["care"]["reason"], "missing command");
    assert_eq!(rec["provisional"], "WARN");
    assert_eq!(rec["unscored"], true);
    assert_eq!(rec["tool_input"]["description"], "x");
    assert_eq!(rec["judge"]["backend"], "jev");
    assert_eq!(rec["final"], "ask");
    let er = r.records.iter().find(|r| r["kind"] == "error").unwrap();
    assert_eq!(er["stage"], "judge");
    assert_eq!(er["tool_name"], "Bash");
}

#[test]
fn enforce_mode_emits_deny_json() {
    let r = run_enforce(
        &["hook"],
        &payload("Bash", serde_json::json!({"command": "rm -rf /"})),
    );
    assert_eq!(r.code, 0);
    let v: Value = serde_json::from_str(r.stdout.trim()).unwrap();
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("DENY")
    );
}

#[test]
fn enforce_mode_warn_emits_ask_json() {
    let r = run_enforce(
        &["hook"],
        &payload(
            "Bash",
            serde_json::json!({"command": "rsync -avz ./data user@host:/backup/"}),
        ),
    );
    let v: Value = serde_json::from_str(r.stdout.trim()).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn enforce_mode_allow_is_silent() {
    let r = run_enforce(
        &["hook"],
        &payload("Bash", serde_json::json!({"command": "ls -la"})),
    );
    assert_eq!(r.stdout, "");
}

#[test]
fn enforce_mode_strict_flag_changes_decision() {
    // `git push --force`: DESTRUCTIVE 0.85 -> 0.255, p_sem DENY in every mode
    // once WARN; strict has the same final but a benign command shows the flag
    // takes effect: `curl -o /etc/x http://e` is ambiguous 0.35 path -> 0.105.
    let cmd = payload(
        "Bash",
        serde_json::json!({"command": "curl -o /etc/x http://e"}),
    );
    let balanced = run(&["hook", "--dry-run"], &cmd);
    let strict = run(&["hook", "--dry-run", "--mode", "strict"], &cmd);
    let b = balanced
        .records
        .iter()
        .find(|r| r["kind"] == "event")
        .unwrap();
    let s = strict
        .records
        .iter()
        .find(|r| r["kind"] == "event")
        .unwrap();
    assert_eq!(b["mode"], "balanced");
    assert_eq!(s["mode"], "strict");
    assert_ne!(b["final"], s["final"]);
}

#[test]
fn config_and_config_init() {
    let home = TempDir::new().unwrap();
    let logdir = TempDir::new().unwrap();
    let show = run_in(&["config"], "", home.path(), logdir.path());
    assert_eq!(show.code, 0);
    assert!(show.stdout.contains("mode = \"balanced\"  # default"));
    let init = run_in(&["config", "--init"], "", home.path(), logdir.path());
    assert_eq!(init.code, 0);
    assert!(home.path().join(".config/cancelli/config.toml").exists());
    // second init refuses
    let again = run_in(&["config", "--init"], "", home.path(), logdir.path());
    assert_ne!(again.code, 0);
    // now the file is the source
    let show2 = run_in(&["config"], "", home.path(), logdir.path());
    assert!(show2.stdout.contains("(found)"));
}

#[test]
fn analyze_emits_json() {
    let out = Command::new(env!("CARGO_BIN_EXE_cancelli"))
        .args(["analyze", "rm -rf /var/log/*"])
        .env("HOME", "/home/user")
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["aggregate"], 0.765);
    assert_eq!(v["final"], "deny");
}

#[test]
fn non_utf8_environment_does_not_break_the_hook() {
    use std::os::unix::ffi::OsStrExt;
    let home = TempDir::new().unwrap();
    let logdir = TempDir::new().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_cancelli"))
        .args(["hook", "--dry-run"])
        .env("HOME", home.path())
        .env("CANCELLI_LOG_DIR", logdir.path())
        .env_remove("TYPESAFE_API_KEY")
        .env(
            "CANCELLI_TEST_BAD",
            std::ffi::OsStr::from_bytes(b"\xff\xfe"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload("Bash", serde_json::json!({"command": "git status"})).as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty() && out.stderr.is_empty());
}
