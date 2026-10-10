//! D28: Jev through OpenRouter's Decisions API, end to end through the
//! real binary, against the local replay server (tests/support), which
//! answers under OpenRouter's dated model slug.

mod support;

use std::io::Write;
use std::path::Path;
use std::process::Stdio;

use serde_json::{Value, json};
use support::{ALLOW_FIXTURE, KEY, bin, records, serve};
use tempfile::TempDir;

const WARN_CMD: &str = "rsync -avz ./data user@host:/backup/";
/// What OpenRouter reports as `response.model`.
const OR_MODEL: &str = "typesafe/jev-1.13-20260917";
const DECISIONS: &str = "POST /api/alpha/decisions HTTP/1.1";

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

    /// One hook call for WARN_CMD under `vars`; returns (stdout, records).
    fn hook(&self, vars: &[(&str, &str)]) -> (String, Vec<Value>) {
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
            .envs(vars.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
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

const BASE: &str = "dry_run = false\ndecide_all = true\n";

#[test]
fn provider_in_the_file_uses_the_decisions_endpoint_key_and_model() {
    let srv = serve(vec![ALLOW_FIXTURE], OR_MODEL);
    let h = Home::new(&format!(
        "{BASE}[judge]\nprovider = \"openrouter\"\nbase_url = \"{}\"\ntimeout_ms = 2000\nbudget_ms = 3000\n",
        srv.url
    ));
    let (stdout, recs) = h.hook(&[("OPENROUTER_API_KEY", KEY)]);
    assert!(judge_error(&recs).is_none(), "{recs:?}");
    let ev = event(&recs);
    assert_eq!(ev["final"], "allow");
    let j = &ev["judge"];
    assert_eq!(j["tier"], "T6");
    assert_eq!(j["error"], Value::Null);
    assert_eq!(j["backend"], "jev");
    assert_eq!(j["backend_host"], srv.host());
    assert_eq!(j["backend_path"], "/api/alpha/decisions");
    assert_eq!(j["expected_model"], "typesafe/jev-1.13-*");
    assert_eq!(j["model"], OR_MODEL);
    assert_eq!(j["key_source"], "env $OPENROUTER_API_KEY");
    assert!(
        stdout.contains("\"permissionDecision\":\"allow\""),
        "{stdout}"
    );
    // What went over the wire: OpenRouter's path, key and model slug.
    let req = &srv.requests()[0];
    assert_eq!(req.request_line, DECISIONS);
    assert_eq!(
        req.header("authorization"),
        Some(format!("Bearer {KEY}").as_str())
    );
    assert_eq!(req.json()["model"], "typesafe/jev-1.13");
    assert!(req.json()["state"].as_str().unwrap().contains(WARN_CMD));
}

#[test]
fn an_exported_openrouter_key_alone_changes_nothing() {
    let srv = serve(vec![ALLOW_FIXTURE], OR_MODEL);
    // No `provider` in the file: TypeSafe stays the provider, its key
    // variable is the one looked up, OPENROUTER_BASE_URL is not read, and
    // no request leaves (D15 ask: no key).
    let h = Home::new(BASE);
    let (stdout, recs) = h.hook(&[
        ("OPENROUTER_API_KEY", KEY),
        ("OPENROUTER_BASE_URL", &srv.url),
    ]);
    let err = judge_error(&recs).expect("D15 error record");
    assert!(
        err.to_string().contains("$TYPESAFE_API_KEY is unset"),
        "{err}"
    );
    let ev = event(&recs);
    let j = &ev["judge"];
    assert_eq!(j["backend_host"], "api.typesafe.ai");
    assert_eq!(j["backend_path"], "/v1/systemone");
    assert_eq!(j["expected_model"], "jev-1.13.0");
    assert_eq!(j["key_source"], Value::Null);
    assert_eq!(ev["final"], "ask");
    assert!(
        stdout.contains("\"permissionDecision\":\"ask\""),
        "{stdout}"
    );
    assert!(srv.requests().is_empty(), "{:?}", srv.requests());
}

#[test]
fn a_new_dated_snapshot_is_accepted_but_another_listing_is_refused() {
    let config =
        |url: &str| format!("{BASE}[judge]\nprovider = \"openrouter\"\nbase_url = \"{url}\"\n");
    // OpenRouter re-dates the slug on a patch release: still Jev 1.13.
    let srv = serve(vec![ALLOW_FIXTURE], "typesafe/jev-1.13-20991231");
    let h = Home::new(&config(&srv.url));
    let (_, recs) = h.hook(&[("OPENROUTER_API_KEY", KEY)]);
    assert!(judge_error(&recs).is_none(), "{recs:?}");
    let j = &event(&recs)["judge"];
    assert_eq!(j["tier"], "T6");
    assert_eq!(j["model"], "typesafe/jev-1.13-20991231");
    assert_eq!(j["expected_model"], "typesafe/jev-1.13-*");

    // Another listing is not: D15 ask with the error record.
    let srv = serve(vec![ALLOW_FIXTURE], "typesafe/jev-1.14-20991231");
    let h = Home::new(&config(&srv.url));
    let (stdout, recs) = h.hook(&[("OPENROUTER_API_KEY", KEY)]);
    let err = judge_error(&recs).expect("D15 error record");
    assert!(
        err.to_string()
            .contains("!= expected_model \\\"typesafe/jev-1.13-*\\\""),
        "{err}"
    );
    assert_eq!(event(&recs)["final"], "ask");
    assert!(
        stdout.contains("\"permissionDecision\":\"ask\""),
        "{stdout}"
    );
}

#[test]
fn a_local_backend_ignores_an_exported_openrouter_key() {
    let srv = serve(vec![ALLOW_FIXTURE], "qwen-local");
    // A local-backend setup (D23) with an OpenRouter key exported: nothing
    // changes, and the key is not even looked at (D28).
    let h = Home::new(&format!(
        "{BASE}[judge]\nbase_url = \"{}\"\nmodel = \"qwen-local\"\nexpected_model = \"qwen-local\"\n\
         api_key_required = false\n",
        srv.url
    ));
    let (_, recs) = h.hook(&[("OPENROUTER_API_KEY", KEY)]);
    assert!(judge_error(&recs).is_none(), "{recs:?}");
    let j = &event(&recs)["judge"];
    assert_eq!(j["tier"], "T6");
    assert!(j["key_source"].as_str().unwrap().starts_with("none"));
    let req = &srv.requests()[0];
    assert_eq!(req.request_line, "POST /v1/systemone HTTP/1.1");
    assert_eq!(req.header("authorization"), None);
    assert_eq!(req.json()["model"], "qwen-local");
}

#[test]
fn config_reports_the_provider_its_source_and_no_override() {
    let h = Home::new("[judge]\nprovider = \"openrouter\"\n");
    let out = h
        .cmd(&["config"])
        .env("OPENROUTER_API_KEY", KEY)
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    for line in [
        "judge.provider = \"openrouter\"  # file\n",
        "judge.base_url = \"https://openrouter.ai\"  # default\n",
        "judge.path = \"/api/alpha/decisions\"  # default\n",
        "judge.model = \"typesafe/jev-1.13\"  # default\n",
        "judge.api_key_env = \"OPENROUTER_API_KEY\"  # default\n",
        "# judge api key: found (env $OPENROUTER_API_KEY)\n",
        "judge.expected_model = \"typesafe/jev-1.13-*\"  # default\n",
        // the provider's default is not an override of the tunables
        "; overrides = []\n",
    ] {
        assert!(text.contains(line), "missing {line:?} in:\n{text}");
    }
    assert!(!text.contains(KEY));
    // Still Jev: no "calibrated on jev-1.13.0" warning.
    assert!(!text.contains("tier thresholds were calibrated"), "{text}");

    // Without `provider`, an exported OpenRouter key changes nothing.
    let h = Home::new("");
    let out = h
        .cmd(&["config"])
        .env("OPENROUTER_API_KEY", KEY)
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    for line in [
        "judge.provider = \"typesafe\"  # default\n",
        "judge.path = \"/v1/systemone\"  # default\n",
        "judge.api_key_env = \"TYPESAFE_API_KEY\"  # default\n",
        "# judge api key: no Jev API key: $TYPESAFE_API_KEY is unset",
    ] {
        assert!(text.contains(line), "missing {line:?} in:\n{text}");
    }
    assert!(!text.contains(KEY));
}
