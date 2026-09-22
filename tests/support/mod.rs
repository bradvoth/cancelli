//! A local `/v1/systemone` replay server (the tests/jev_e2e.rs pattern) and
//! helpers shared by the D23–D25 end-to-end tests. It replays the POC's real
//! cached `jev-1.13.0` answers (tests/fixtures/jev) under any reported
//! model name, so a "local backend" can be exercised offline. It binds
//! 127.0.0.1:0 (an ephemeral port).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

/// Pair 2 approve: T6 allow (f5 0.13).
pub const ALLOW_FIXTURE: &str = "8ad975ab57f8ebdfb26d6ec050a2db6a0539c43b4d186f497a38ec1eaffb5af6";
/// Pair 4 deny: T5 ask (f5 0.79).
pub const ASK_FIXTURE: &str = "200553f760e355d54f1a48d9e080ce80a9c7d8c3e96fdc2302894b805dc286c9";
/// A test API key that must never reach a log.
pub const KEY: &str = "tsk_test_DO_NOT_LOG_d23d25";

/// One HTTP request as received.
#[derive(Debug, Clone)]
pub struct Captured {
    /// Lower-cased header names and values.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: String,
}

impl Captured {
    /// A header value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    /// The JSON body.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }
}

/// A running replay server.
pub struct Server {
    /// `http://127.0.0.1:<port>`.
    pub url: String,
    /// Requests seen, in order.
    pub seen: Arc<Mutex<Vec<Captured>>>,
}

impl Server {
    /// `127.0.0.1:<port>`.
    pub fn host(&self) -> String {
        self.url.trim_start_matches("http://").to_string()
    }
    /// Requests so far.
    pub fn requests(&self) -> Vec<Captured> {
        self.seen.lock().unwrap().clone()
    }
}

/// The fixture's answers.
pub fn fixture_answers(hash: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/jev/{hash}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    v["answers"].clone()
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
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// Serve fixture replies in order (the last repeats), each reporting
/// `model` as `response.model`.
pub fn serve(fixtures: Vec<&'static str>, model: &'static str) -> Server {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = Arc::clone(&seen);
    std::thread::spawn(move || {
        for (i, conn) in l.incoming().enumerate() {
            let Ok(mut s) = conn else { continue };
            if let Some(c) = read_request(&mut s) {
                seen2.lock().unwrap().push(c);
            }
            let fx = fixtures[i.min(fixtures.len() - 1)];
            let body = json!({"model": model, "answers": fixture_answers(fx),
                              "usage": {"input_tokens": 100, "output_tokens": 10}})
            .to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                 x-typesafe-request-id: req_local_{i}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    Server { url, seen }
}

/// The binary, with proxy variables and ambient cancelli/Jev variables
/// removed.
pub fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cancelli"));
    for v in [
        "ALL_PROXY",
        "all_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "XDG_CONFIG_HOME",
        "CANCELLI_MODE",
        "TYPESAFE_BASE_URL",
        "TYPESAFE_API_KEY",
    ] {
        c.env_remove(v);
    }
    c
}

/// Every JSONL record in a directory's files.
pub fn records(dir: &std::path::Path) -> Vec<Value> {
    let mut out = Vec::new();
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    for p in files {
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.contains(KEY), "API key leaked into {}", p.display());
        for line in text.lines().filter(|l| !l.is_empty()) {
            out.push(serde_json::from_str(line).unwrap());
        }
    }
    out
}
