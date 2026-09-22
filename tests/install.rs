//! D9: `cargo install --path . --root <tmp>` must produce a self-contained
//! binary that runs `hook --dry-run` with nothing from the source checkout.
//!
//! Ignored by default (a release build is slow); run with
//! `cargo test --test install -- --ignored`. CI runs it explicitly.

use std::io::Write;
use std::process::{Command, Stdio};

use tempfile::TempDir;

#[test]
#[ignore = "slow: builds a release binary via cargo install"]
fn installed_binary_runs_hook() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = TempDir::new().unwrap();
    let target = TempDir::new().unwrap();

    let status = Command::new(env!("CARGO"))
        .args(["install", "--path", manifest, "--root"])
        .arg(root.path())
        .args(["--target-dir"])
        .arg(target.path())
        .arg("--locked")
        .status()
        .expect("run cargo install");
    assert!(status.success(), "cargo install failed");

    let bin = root.path().join("bin").join("cancelli");
    assert!(bin.exists(), "installed binary missing");

    // Run it from a directory with no relation to the source checkout.
    let run_dir = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let logdir = TempDir::new().unwrap();
    let mut child = Command::new(&bin)
        .args(["hook", "--dry-run"])
        .current_dir(run_dir.path())
        .env("HOME", home.path())
        .env("CANCELLI_LOG_DIR", logdir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
    })
    .to_string();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty(), "dry-run must be silent");

    let mut found = false;
    for e in std::fs::read_dir(logdir.path()).unwrap().flatten() {
        let text = std::fs::read_to_string(e.path()).unwrap();
        for line in text.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            if v["kind"] == "event" && v["command"] == "rm -rf /" {
                assert_eq!(v["final"], "deny");
                assert!(
                    v["fired_rules"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|f| f["id"] == "SE-P-001")
                );
                found = true;
            }
        }
    }
    assert!(found, "no event record from the installed binary");
}
