//! Jev end-to-end through the real `cancelli` binary, offline.
//!
//! A tiny local HTTP server stands in for api.typesafe.ai. It is used for
//! failure injection (hang, wrong model, 5xx) and to *replay the POC's real
//! cached jev-1.13.0 responses* (tests/fixtures/jev) so the success path,
//! the tier -> decision mapping and `decide_all` can be exercised without
//! the network. None of this is evidence about the live API; that is
//! tests/jev_live.rs (ignored, run by the user).
//!
//! Every run asserts the API key never reaches the log.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::TempDir;

const KEY: &str = "tsk_test_DO_NOT_LOG_7f3a9c";
const WARN_CMD: &str = "rsync -avz ./data user@host:/backup/";
/// Pair 2 approve (T6 allow), pair 2 deny (T2 deny), pair 4 deny (T5 ask).
const ALLOW_FIXTURE: &str = "8ad975ab57f8ebdfb26d6ec050a2db6a0539c43b4d186f497a38ec1eaffb5af6";
const DENY_FIXTURE: &str = "8eac397736ea6725ba3d8f5ca58eac72a3cd35c39978d05a653070d992766a48";
const ASK_FIXTURE: &str = "200553f760e355d54f1a48d9e080ce80a9c7d8c3e96fdc2302894b805dc286c9";

#[derive(Clone)]
enum Reply {
    /// 200 with a cached fixture's answers, reporting `model`.
    Replay(&'static str, &'static str),
    /// Accept, read, never answer.
    Hang,
    /// Status + body.
    Status(u16, &'static str),
}

#[derive(Debug, Clone)]
struct Captured {
    request_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

struct Server {
    url: String,
    seen: Arc<Mutex<Vec<Captured>>>,
}

fn fixture_body(hash: &str, model: &str) -> String {
    let path = format!(
        "{}/tests/fixtures/jev/{hash}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    json!({"model": model, "answers": v["answers"], "usage": v["usage"]}).to_string()
}

fn read_request(s: &mut TcpStream) -> Option<Captured> {
    let mut r = BufReader::new(s.try_clone().ok()?);
    let mut request_line = String::new();
    r.read_line(&mut request_line).ok()?;
    let mut headers = Vec::new();
    loop {
        let mut l = String::new();
        r.read_line(&mut l).ok()?;
        let l = l.trim_end().to_string();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    r.read_exact(&mut body).ok()?;
    Some(Captured {
        request_line: request_line.trim_end().to_string(),
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// Serve `replies` in order (the last one repeats).
fn serve(replies: Vec<Reply>) -> Server {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for (i, conn) in l.incoming().enumerate() {
            let Ok(mut s) = conn else { continue };
            let reply = replies[i.min(replies.len() - 1)].clone();
            if let Some(c) = read_request(&mut s) {
                seen2.lock().unwrap().push(c);
            }
            let (status, body, extra) = match reply {
                Reply::Hang => {
                    held.push(s);
                    continue;
                }
                Reply::Replay(h, model) => (200, fixture_body(h, model), ""),
                Reply::Status(code, b) => (code, b.to_string(), "retry-after-ms: 50\r\n"),
            };
            let resp = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                 x-typesafe-request-id: req_local_{i}\r\n{extra}connection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    Server { url, seen }
}

/// A command for the binary with proxy variables removed (ureq honours
/// `*_PROXY`, which would divert requests meant for the local server).
fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cancelli"));
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

fn refused_url() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    drop(l);
    url
}

struct Run {
    stdout: String,
    code: i32,
    records: Vec<Value>,
    elapsed: Duration,
}

impl Run {
    fn event(&self) -> &Value {
        self.records.iter().find(|r| r["kind"] == "event").unwrap()
    }
    fn judge(&self) -> &Value {
        &self.event()["judge"]
    }
    fn judge_error_record(&self) -> Option<&Value> {
        self.records
            .iter()
            .find(|r| r["kind"] == "error" && r["stage"] == "judge")
    }
}

struct Setup {
    base_url: String,
    dry_run: bool,
    decide_all_cfg: bool,
    key: bool,
    extra_judge: &'static str,
    args: Vec<&'static str>,
    /// The current call (`tool_use_id` "toolu_cur", also last in the
    /// transcript).
    tool_name: String,
    tool_input: Value,
    /// Appended to config.toml after `[judge]` (e.g. a `[jev]` table).
    extra_config: String,
}

impl Setup {
    fn new(base_url: &str) -> Self {
        Setup {
            base_url: base_url.into(),
            dry_run: true,
            decide_all_cfg: false,
            key: true,
            extra_judge: "timeout_ms = 1500\nbudget_ms = 3000\n",
            args: vec!["hook", "--dry-run"],
            tool_name: "Bash".into(),
            tool_input: json!({"command": WARN_CMD}),
            extra_config: String::new(),
        }
    }

    /// D21: the current call is `name(input)`.
    fn tool(base_url: &str, name: &str, input: Value) -> Self {
        Setup {
            tool_name: name.into(),
            tool_input: input,
            ..Setup::new(base_url)
        }
    }
}

fn transcript(dir: &std::path::Path) -> std::path::PathBuf {
    transcript_with(dir, "Bash", &json!({"command": WARN_CMD}))
}

/// The session transcript whose last tool_use (`toolu_cur`) is `name(input)`.
fn transcript_with(dir: &std::path::Path, name: &str, input: &Value) -> std::path::PathBuf {
    let lines = [
        json!({"type": "permission-mode", "permissionMode": "default"}),
        json!({"type": "user", "message": {"role": "user", "content": "Back up the data dir to the backup host."}}),
        json!({"type": "assistant", "message": {"content": [
            {"type": "thinking", "thinking": "PRIVATE-THOUGHT"},
            {"type": "text", "text": "AGENT-NARRATION"},
            {"type": "tool_use", "id": "toolu_prior", "name": "Bash",
             "input": {"command": "du -sh ./data", "description": "AGENT-DESCRIPTION"}}]}}),
        json!({"type": "user", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_prior", "content": "TOOL-RESULT-TEXT"}]}}),
        json!({"type": "user", "isMeta": true, "message": {"role": "user", "content": "META-CAVEAT"}}),
        json!({"type": "user", "message": {"role": "user", "content": "<system-reminder>SYSTEM-REMINDER-TEXT</system-reminder>"}}),
        json!({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "toolu_cur", "name": name, "input": input}]}}),
    ];
    let p = dir.join("session.jsonl");
    let text: Vec<String> = lines.iter().map(Value::to_string).collect();
    std::fs::write(&p, text.join("\n") + "\n").unwrap();
    p
}

fn run(s: &Setup) -> Run {
    let home = TempDir::new().unwrap();
    let logdir = TempDir::new().unwrap();
    let cfg = home.path().join(".config/cancelli");
    std::fs::create_dir_all(&cfg).unwrap();
    std::fs::write(
        cfg.join("config.toml"),
        format!(
            "dry_run = {}\ndecide_all = {}\n[judge]\nbase_url = \"{}\"\n{}{}",
            s.dry_run, s.decide_all_cfg, s.base_url, s.extra_judge, s.extra_config
        ),
    )
    .unwrap();
    let t = transcript_with(home.path(), &s.tool_name, &s.tool_input);
    let payload = json!({
        "session_id": "sess-jev",
        "transcript_path": t,
        "cwd": "/work",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": s.tool_name,
        "tool_use_id": "toolu_cur",
        "tool_input": s.tool_input,
    })
    .to_string();
    let mut cmd = bin();
    cmd.args(&s.args)
        .env("HOME", home.path())
        .env("CANCELLI_LOG_DIR", logdir.path())
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("CANCELLI_MODE")
        .env_remove("TYPESAFE_BASE_URL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if s.key {
        cmd.env("TYPESAFE_API_KEY", KEY);
    } else {
        cmd.env_remove("TYPESAFE_API_KEY");
    }
    let start = Instant::now();
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let elapsed = start.elapsed();
    let mut records = Vec::new();
    for e in std::fs::read_dir(logdir.path()).unwrap().flatten() {
        let text = std::fs::read_to_string(e.path()).unwrap();
        assert!(!text.contains(KEY), "API key leaked into the log");
        for line in text.lines().filter(|l| !l.is_empty()) {
            records.push(serde_json::from_str(line).unwrap());
        }
    }
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains(KEY));
    assert!(!String::from_utf8_lossy(&out.stderr).contains(KEY));
    Run {
        stdout,
        code: out.status.code().unwrap_or(-1),
        records,
        elapsed,
    }
}

/// D15 in dry-run: ask, an error record, exit 0, silent.
fn assert_failure_dry_run(r: &Run, error_has: &str) {
    assert_eq!(r.code, 0);
    assert_eq!(r.stdout, "", "dry-run is silent");
    let ev = r.event();
    assert_eq!(ev["final"], "ask");
    assert_eq!(ev["would_emit"], "ask");
    let j = r.judge();
    assert_eq!(j["backend"], "jev");
    assert_eq!(j["verdict"], "ask");
    assert_eq!(j["would_emit"], "ask");
    assert_eq!(j["tier"], Value::Null);
    let err = j["error"].as_str().unwrap();
    assert!(
        err.contains(error_has),
        "{err:?} should contain {error_has:?}"
    );
    let er = r.judge_error_record().expect("error record");
    assert_eq!(er["error"], j["error"]);
    assert_eq!(er["tool_use_id"], "toolu_cur");
    assert_eq!(er["decision"], "ask");
    // the state was still built and logged (D17)
    assert_eq!(j["level"], "l2_actions");
    assert_eq!(j["rubric_hash"], "0fd1f245ae1c7ef3");
    assert_eq!(j["state_hash"].as_str().unwrap().len(), 64);
}

#[test]
fn unreachable_base_url_is_ask() {
    let r = run(&Setup::new(&refused_url()));
    assert_failure_dry_run(&r, "transport");
    assert_eq!(
        r.judge()["attempts"],
        1,
        "connection refused is not retried"
    );
}

#[test]
fn hanging_server_times_out_retries_once_and_asks() {
    let srv = serve(vec![Reply::Hang]);
    let mut s = Setup::new(&srv.url);
    s.extra_judge = "timeout_ms = 300\nbudget_ms = 1200\n";
    let r = run(&s);
    assert_failure_dry_run(&r, "timeout");
    assert_eq!(r.judge()["attempts"], 2);
    assert!(r.elapsed < Duration::from_secs(4), "{:?}", r.elapsed);
    assert_eq!(srv.seen.lock().unwrap().len(), 2);
}

#[test]
fn missing_key_is_ask_without_network() {
    let srv = serve(vec![Reply::Replay(ALLOW_FIXTURE, "jev-1.13.0")]);
    let mut s = Setup::new(&srv.url);
    s.key = false;
    let r = run(&s);
    assert_failure_dry_run(&r, "no Jev API key");
    assert!(
        srv.seen.lock().unwrap().is_empty(),
        "no request without a key"
    );
    assert_eq!(r.judge()["attempts"], 0);
}

#[test]
fn key_file_with_loose_mode_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let kf = dir.path().join("key");
    std::fs::write(&kf, KEY).unwrap();
    std::fs::set_permissions(&kf, std::fs::Permissions::from_mode(0o644)).unwrap();
    let srv = serve(vec![Reply::Replay(ALLOW_FIXTURE, "jev-1.13.0")]);
    let mut s = Setup::new(&srv.url);
    s.key = false;
    let extra = format!(
        "timeout_ms = 1500\nbudget_ms = 3000\napi_key_file = \"{}\"\n",
        kf.display()
    );
    s.extra_judge = Box::leak(extra.into_boxed_str());
    let r = run(&s);
    assert_failure_dry_run(&r, "refusing");
    assert!(srv.seen.lock().unwrap().is_empty());
    // 0600 is accepted and used
    std::fs::set_permissions(&kf, std::fs::Permissions::from_mode(0o600)).unwrap();
    let r = run(&s);
    assert_eq!(r.judge()["error"], Value::Null);
    assert!(
        r.judge()["key_source"]
            .as_str()
            .unwrap()
            .starts_with("file ")
    );
    let seen = srv.seen.lock().unwrap();
    let auth = &seen[0]
        .headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .unwrap()
        .1;
    assert_eq!(auth, &format!("Bearer {KEY}"));
}

#[test]
fn wrong_model_is_ask() {
    let srv = serve(vec![Reply::Replay(ALLOW_FIXTURE, "jev-9.9.9")]);
    let r = run(&Setup::new(&srv.url));
    assert_failure_dry_run(&r, "response.model \"jev-9.9.9\"");
    let j = r.judge();
    assert_eq!(j["model"], "jev-9.9.9");
    assert_eq!(j["request_id"], "req_local_0");
    assert_eq!(
        j["signals"],
        Value::Null,
        "answers from the wrong model are not consumed"
    );
}

#[test]
fn server_error_then_success_uses_the_one_retry() {
    let srv = serve(vec![
        Reply::Status(503, "{\"detail\":\"overloaded\"}"),
        Reply::Replay(ALLOW_FIXTURE, "jev-1.13.0"),
    ]);
    let r = run(&Setup::new(&srv.url));
    let j = r.judge();
    assert_eq!(j["error"], Value::Null);
    assert_eq!(j["attempts"], 2);
    assert_eq!(j["request_id"], "req_local_1");
    // a persistent 4xx is not retried
    let srv = serve(vec![Reply::Status(401, "{\"detail\":\"bad key\"}")]);
    let r = run(&Setup::new(&srv.url));
    assert_failure_dry_run(&r, "HTTP 401");
    assert_eq!(r.judge()["attempts"], 1);
}

#[test]
fn dry_run_calls_jev_and_logs_the_full_judge_record() {
    let srv = serve(vec![Reply::Replay(ALLOW_FIXTURE, "jev-1.13.0")]);
    let r = run(&Setup::new(&srv.url));
    assert_eq!((r.code, r.stdout.as_str()), (0, ""));
    assert!(r.judge_error_record().is_none());
    let ev = r.event();
    assert_eq!(ev["would_adjudicate"], true);
    assert_eq!(ev["final"], "allow");
    assert_eq!(
        ev["would_emit"],
        Value::Null,
        "allow without decide_all emits nothing"
    );
    let j = r.judge();
    for k in [
        "backend",
        "level",
        "questions_sent",
        "state",
        "state_hash",
        "rubric_hash",
        "answers",
        "signals",
        "tier",
        "verdict",
        "would_emit",
        "latency_ms",
        "usage",
        "request_id",
        "error",
    ] {
        assert!(j.get(k).is_some(), "judge.{k} missing");
    }
    assert_eq!(j["tier"], "T6");
    assert_eq!(j["verdict"], "allow");
    assert_eq!(j["level"], "l2_actions");
    assert_eq!(j["questions_sent"].as_array().unwrap().len(), 39);
    let fx: Value = serde_json::from_str(&fixture_body(ALLOW_FIXTURE, "x")).unwrap();
    assert_eq!(j["usage"], fx["usage"]);
    assert!(j["usage"]["input_tokens"].as_u64().unwrap() > 3000);
    assert_eq!(j["request_id"], "req_local_0");
    assert_eq!(j["context"]["prompts_total"], 1);
    assert_eq!(j["context"]["actions_total"], 1);

    // What went over the wire.
    let seen = srv.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let c = &seen[0];
    assert_eq!(c.request_line, "POST /v1/systemone HTTP/1.1");
    let h = |k: &str| {
        c.headers
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(h("authorization"), Some(format!("Bearer {KEY}").as_str()));
    assert_eq!(h("content-type"), Some("application/json"));
    let body: Value = serde_json::from_str(&c.body).unwrap();
    assert_eq!(body["model"], "jev-1.13.0");
    assert_eq!(body["questions"].as_object().unwrap().len(), 39);
    let state = body["state"].as_str().unwrap();
    assert_eq!(state, j["state"].as_str().unwrap());
    assert_eq!(
        state,
        format!(
            "### PROPOSED ACTION\ntool: bash\nargs: {WARN_CMD}\n\n\
             ### USER REQUEST\nBack up the data dir to the backup host.\n\n\
             ### PRIOR AGENT ACTIONS (most recent last)\n[1] bash(du -sh ./data)"
        )
    );
    for leaked in [
        "PRIVATE-THOUGHT",
        "AGENT-NARRATION",
        "AGENT-DESCRIPTION",
        "TOOL-RESULT-TEXT",
        "META-CAVEAT",
        "SYSTEM-REMINDER-TEXT",
    ] {
        assert!(!c.body.contains(leaked), "{leaked} must not be sent");
    }
}

fn decision(r: &Run) -> Option<Value> {
    (!r.stdout.trim().is_empty()).then(|| {
        let v: Value = serde_json::from_str(r.stdout.trim()).unwrap();
        v["hookSpecificOutput"].clone()
    })
}

#[test]
fn enforce_allow_emits_only_with_decide_all() {
    let srv = serve(vec![Reply::Replay(ALLOW_FIXTURE, "jev-1.13.0")]);
    let mut s = Setup::new(&srv.url);
    s.dry_run = false;
    s.args = vec!["hook"];
    // off (default): nothing, normal permission flow decides
    let r = run(&s);
    assert_eq!(r.code, 0);
    assert_eq!(decision(&r), None);
    assert_eq!(r.judge()["would_emit"], Value::Null);
    // on via the flag
    s.args = vec!["hook", "--decide-all"];
    let r = run(&s);
    let d = decision(&r).unwrap();
    assert_eq!(d["permissionDecision"], "allow");
    assert!(
        d["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("Jev T6")
    );
    assert_eq!(r.event()["would_emit"], "allow");
    // on via config
    s.args = vec!["hook"];
    s.decide_all_cfg = true;
    let r = run(&s);
    assert_eq!(decision(&r).unwrap()["permissionDecision"], "allow");
    // dry-run ignores decide_all
    s.args = vec!["hook", "--dry-run", "--decide-all"];
    let r = run(&s);
    assert_eq!(r.stdout, "");
    assert_eq!(r.judge()["would_emit"], "allow");
}

#[test]
fn enforce_deny_and_ask_name_the_tier_regardless_of_decide_all() {
    for (fixture, want, tier) in [(DENY_FIXTURE, "deny", "T2"), (ASK_FIXTURE, "ask", "T5")] {
        for decide_all in [false, true] {
            let srv = serve(vec![Reply::Replay(fixture, "jev-1.13.0")]);
            let mut s = Setup::new(&srv.url);
            s.dry_run = false;
            s.decide_all_cfg = decide_all;
            s.args = vec!["hook"];
            let r = run(&s);
            let d = decision(&r).unwrap();
            assert_eq!(d["permissionDecision"], want);
            let reason = d["permissionDecisionReason"].as_str().unwrap();
            assert!(reason.contains(&format!("Jev {tier}")), "{reason}");
            assert_eq!(r.judge()["tier"], tier);
        }
    }
    // failure in enforce mode: ask, naming the failure
    let mut s = Setup::new(&refused_url());
    s.dry_run = false;
    s.args = vec!["hook"];
    let r = run(&s);
    let d = decision(&r).unwrap();
    assert_eq!(d["permissionDecision"], "ask");
    assert!(
        d["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("Jev unavailable")
    );
}

#[test]
fn static_verdicts_never_reach_jev() {
    let srv = serve(vec![Reply::Replay(ALLOW_FIXTURE, "jev-1.13.0")]);
    for cmd in ["rm -rf /", "git status"] {
        let home = TempDir::new().unwrap();
        let logdir = TempDir::new().unwrap();
        let cfg = home.path().join(".config/cancelli");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(
            cfg.join("config.toml"),
            format!("[judge]\nbase_url = \"{}\"\n", srv.url),
        )
        .unwrap();
        let mut child = bin()
            .args(["hook", "--dry-run"])
            .env("HOME", home.path())
            .env("CANCELLI_LOG_DIR", logdir.path())
            .env("TYPESAFE_API_KEY", KEY)
            .env_remove("TYPESAFE_BASE_URL")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let p = json!({"tool_name": "Bash", "tool_input": {"command": cmd}}).to_string();
        child.stdin.take().unwrap().write_all(p.as_bytes()).unwrap();
        assert!(child.wait_with_output().unwrap().status.success());
    }
    assert!(
        srv.seen.lock().unwrap().is_empty(),
        "CARE ALLOW/DENY are final (D12)"
    );
}

#[test]
fn judge_subcommand_prints_the_record() {
    let srv = serve(vec![Reply::Replay(DENY_FIXTURE, "jev-1.13.0")]);
    let home = TempDir::new().unwrap();
    let cfg = home.path().join(".config/cancelli");
    std::fs::create_dir_all(&cfg).unwrap();
    std::fs::write(
        cfg.join("config.toml"),
        format!("[judge]\nbase_url = \"{}\"\n", srv.url),
    )
    .unwrap();
    let t = transcript(home.path());
    let out = bin()
        .args([
            "judge",
            "rm -rf ./build",
            "--request",
            "Run the tests. Don't change anything.",
        ])
        .arg("--transcript")
        .arg(&t)
        .env("HOME", home.path())
        .env("TYPESAFE_API_KEY", KEY)
        .env_remove("TYPESAFE_BASE_URL")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["tier"], "T2");
    assert_eq!(v["verdict"], "deny");
    assert_eq!(v["level"], "l2_actions");
    // no current tool_use id: every tool use in the transcript is prior
    assert_eq!(v["context"]["actions_total"], 2);
    let state = v["state"].as_str().unwrap();
    assert!(state.contains("### USER REQUEST\nRun the tests. Don't change anything.\n"));
    assert!(state.ends_with(&format!("[1] bash(du -sh ./data)\n[2] bash({WARN_CMD})")));
    // without a key: record with error, exit 1
    let out = bin()
        .args(["judge", "ls"])
        .env("HOME", home.path())
        .env_remove("TYPESAFE_API_KEY")
        .env_remove("TYPESAFE_BASE_URL")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["verdict"], "ask");
    assert_eq!(v["level"], "l0_action");
}

#[test]
fn config_shows_jev_keys_and_sources() {
    let home = TempDir::new().unwrap();
    let out = bin()
        .arg("config")
        .env("HOME", home.path())
        .env("TYPESAFE_API_KEY", KEY)
        .env("TYPESAFE_BASE_URL", "http://127.0.0.1:1")
        .output()
        .unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    for line in [
        "decide_all = true  # default",
        "judge.backend = \"jev\"  # default",
        "judge.base_url = \"http://127.0.0.1:1\"  # env",
        "judge.model = \"jev-1.13.0\"  # default",
        "judge.api_key_env = \"TYPESAFE_API_KEY\"  # default",
        "judge.api_key_file = (unset)  # default",
        "judge.timeout_ms = 3000  # default",
        "judge.budget_ms = 5000  # default",
        "# judge api key: found (env $TYPESAFE_API_KEY)",
    ] {
        assert!(s.contains(line), "missing {line:?} in\n{s}");
    }
    assert!(!s.contains(KEY));
}

// ------------------------------------------------------------------ D21 --
// Tool calls CARE cannot score are a WARN for Jev.

/// Each unscorable call, and its POC `Name(json)` args text (Python
/// `json.dumps(input, sort_keys=True, ensure_ascii=False)`).
fn d21_calls() -> Vec<(&'static str, Value, &'static str)> {
    vec![
        (
            "Write",
            json!({"file_path": "/work/notes.md", "content": "héllo\nworld"}),
            r#"{"content": "héllo\nworld", "file_path": "/work/notes.md"}"#,
        ),
        (
            "Read",
            json!({"file_path": "/home/u/.ssh/id_rsa"}),
            r#"{"file_path": "/home/u/.ssh/id_rsa"}"#,
        ),
        (
            "WebFetch",
            json!({"url": "https://example.com/x", "prompt": "summarise"}),
            r#"{"prompt": "summarise", "url": "https://example.com/x"}"#,
        ),
        (
            "mcp__server__tool",
            json!({"query": "q", "limit": 5, "deep": true, "tags": ["a", "b"]}),
            r#"{"deep": true, "limit": 5, "query": "q", "tags": ["a", "b"]}"#,
        ),
    ]
}

/// The L2 state for an unscorable call made in the test transcript.
fn d21_state(name: &str, args: &str) -> String {
    format!(
        "### PROPOSED ACTION\ntool: {name}\nargs: {args}\n\n\
         ### USER REQUEST\nBack up the data dir to the backup host.\n\n\
         ### PRIOR AGENT ACTIONS (most recent last)\n[1] bash(du -sh ./data)"
    )
}

fn assert_d21_record(r: &Run, name: &str, reason: &str) {
    let ev = r.event();
    assert_eq!(ev["tool_name"], name);
    assert_eq!(ev["care"], json!({"supported": false, "reason": reason}));
    assert_eq!(ev["provisional"], "WARN");
    assert_eq!(ev["unscored"], true);
    assert_eq!(ev["would_adjudicate"], true);
    assert!(ev.get("command").is_none() && ev.get("aggregate").is_none());
    assert!(ev["tool_input"].is_object(), "raw input still logged");
    assert_eq!(ev["final"], r.judge()["decision"]);
    assert_eq!(r.judge()["backend"], "jev");
}

#[test]
fn d21_unscored_tools_are_judged_in_dry_run_with_name_json_state() {
    for (name, input, args) in d21_calls() {
        let srv = serve(vec![Reply::Replay(ALLOW_FIXTURE, "jev-1.13.0")]);
        let r = run(&Setup::tool(&srv.url, name, input.clone()));
        assert_eq!(
            (r.code, r.stdout.as_str()),
            (0, ""),
            "{name}: dry-run is silent"
        );
        assert!(r.judge_error_record().is_none());
        assert_d21_record(&r, name, "non-shell tool");
        let ev = r.event();
        assert_eq!(ev["final"], "allow");
        assert_eq!(ev["would_emit"], Value::Null);
        let j = r.judge();
        assert_eq!(j["tier"], "T6");
        assert_eq!(j["level"], "l2_actions");
        // the current tool_use is excluded from the priors, as for Bash
        assert_eq!(j["context"]["actions_total"], 1);
        let state = j["state"].as_str().unwrap();
        assert_eq!(state, d21_state(name, args), "{name}");
        // the proposed action is the POC's `Name(json)` call text, split
        let mut lines = state.lines().skip(1);
        let tool = lines.next().unwrap().strip_prefix("tool: ").unwrap();
        let a = lines.next().unwrap().strip_prefix("args: ").unwrap();
        assert_eq!(format!("{tool}({a})"), format!("{name}({args})"));
        // exactly this state went over the wire
        let seen = srv.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let body: Value = serde_json::from_str(&seen[0].body).unwrap();
        assert_eq!(body["state"], j["state"]);
        assert_eq!(body["model"], "jev-1.13.0");
    }
}

#[test]
fn d21_enforce_output_per_tier() {
    for (name, input, _) in d21_calls() {
        for (fixture, decide_all, want, tier) in [
            (DENY_FIXTURE, false, Some("deny"), "T2"),
            (ASK_FIXTURE, false, Some("ask"), "T5"),
            (ALLOW_FIXTURE, false, None, "T6"),
            (ALLOW_FIXTURE, true, Some("allow"), "T6"),
        ] {
            let srv = serve(vec![Reply::Replay(fixture, "jev-1.13.0")]);
            let mut s = Setup::tool(&srv.url, name, input.clone());
            s.dry_run = false;
            s.decide_all_cfg = decide_all;
            s.args = vec!["hook"];
            let r = run(&s);
            assert_eq!(r.code, 0);
            assert_d21_record(&r, name, "non-shell tool");
            assert_eq!(r.judge()["tier"], tier);
            match want {
                None => assert_eq!(r.stdout, "", "{name} {tier}: allow is silent"),
                Some(w) => {
                    let d = decision(&r).unwrap();
                    assert_eq!(d["hookEventName"], "PreToolUse");
                    assert_eq!(d["permissionDecision"], w, "{name} {tier}");
                    let reason = d["permissionDecisionReason"].as_str().unwrap();
                    assert!(reason.contains(&format!("Jev {tier}")), "{reason}");
                    assert!(reason.contains("non-shell tool"), "{reason}");
                    assert_eq!(r.event()["would_emit"], w);
                }
            }
        }
    }
}

#[test]
fn d21_bash_without_a_usable_command_goes_to_jev() {
    for (input, reason, args) in [
        (
            json!({"description": "x"}),
            "missing command",
            r#"{"description": "x"}"#,
        ),
        (
            json!({"command": ""}),
            "empty command",
            r#"{"command": ""}"#,
        ),
        (
            json!({"command": "  \n"}),
            "empty command",
            r#"{"command": "  \n"}"#,
        ),
        (
            json!({"command": ["ls"]}),
            "command is not a string",
            r#"{"command": ["ls"]}"#,
        ),
    ] {
        let srv = serve(vec![Reply::Replay(DENY_FIXTURE, "jev-1.13.0")]);
        let mut s = Setup::tool(&srv.url, "Bash", input);
        s.dry_run = false;
        s.args = vec!["hook"];
        let r = run(&s);
        assert!(
            !r.records.iter().any(|x| x["kind"] == "error"),
            "{reason}: no error record"
        );
        assert_d21_record(&r, "Bash", reason);
        assert_eq!(r.judge()["state"], d21_state("Bash", args));
        assert_eq!(decision(&r).unwrap()["permissionDecision"], "deny");
        assert_eq!(srv.seen.lock().unwrap().len(), 1);
    }
}

#[test]
fn d21_skip_tools_pass_through_unjudged() {
    let srv = serve(vec![Reply::Replay(DENY_FIXTURE, "jev-1.13.0")]);
    let (_, read, _) = d21_calls().remove(1);
    let mut s = Setup::tool(&srv.url, "Read", read);
    s.dry_run = false;
    s.args = vec!["hook"];
    s.extra_config = "[jev]\nskip_tools = [\"Read\"]\n".into();
    let r = run(&s);
    assert_eq!((r.code, r.stdout.as_str()), (0, ""), "no decision");
    let ev = r.event();
    assert_eq!(ev["tool_input"]["file_path"], "/home/u/.ssh/id_rsa");
    for k in [
        "judge",
        "final",
        "care",
        "provisional",
        "unscored",
        "would_emit",
    ] {
        assert!(ev.get(k).is_none(), "skipped Read has no {k}");
    }
    assert_eq!(ev["overrides"], json!(["jev.skip_tools"]));
    assert!(
        srv.seen.lock().unwrap().is_empty(),
        "Read never reaches Jev"
    );
    // Write is still judged under the same config
    let (_, write, _) = d21_calls().remove(0);
    s.tool_name = "Write".into();
    s.tool_input = write;
    let r = run(&s);
    assert_d21_record(&r, "Write", "non-shell tool");
    assert_eq!(decision(&r).unwrap()["permissionDecision"], "deny");
    assert_eq!(srv.seen.lock().unwrap().len(), 1);
}

#[test]
fn d21_failures_ask_with_an_error_record() {
    let (_, input, _) = d21_calls().remove(0);
    // no key (dry-run): no request, ask, error record, silent
    let srv = serve(vec![Reply::Replay(ALLOW_FIXTURE, "jev-1.13.0")]);
    let mut s = Setup::tool(&srv.url, "Write", input.clone());
    s.key = false;
    let r = run(&s);
    assert_failure_dry_run(&r, "no Jev API key");
    assert_d21_record(&r, "Write", "non-shell tool");
    let er = r.judge_error_record().unwrap();
    assert_eq!(er["tool_name"], "Write");
    assert_eq!(er["unscored"], true);
    assert!(srv.seen.lock().unwrap().is_empty());
    // unreachable server (dry-run)
    let r = run(&Setup::tool(&refused_url(), "Write", input.clone()));
    assert_failure_dry_run(&r, "transport");
    assert_d21_record(&r, "Write", "non-shell tool");
    // unreachable server (enforce): ask, naming the failure
    let mut s = Setup::tool(&refused_url(), "Write", input);
    s.dry_run = false;
    s.args = vec!["hook"];
    let r = run(&s);
    assert_eq!(r.code, 0);
    let d = decision(&r).unwrap();
    assert_eq!(d["permissionDecision"], "ask");
    assert!(
        d["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("Jev unavailable")
    );
    assert!(r.judge_error_record().is_some());
}
