//! Blocking HTTP transport for `POST {base_url}/v1/systemone` (ureq +
//! rustls), the API key, and the retry/budget policy.
//!
//! * Per-attempt timeout `timeout_ms`, total budget `budget_ms`.
//! * At most one retry, only on 408/429/5xx or a timeout, and only if the
//!   wait (`retry-after-ms`, else `retry-after` seconds or HTTP-date, else
//!   500 ms, the SDK's initial backoff) plus a minimal attempt still fits in
//!   the budget.
//! * The key is read from the env var named by `api_key_env`, else from
//!   `api_key_file` (refused if group/other have any permission). It is held
//!   in [`Secret`] (redacted `Debug`), never logged, and scrubbed from every
//!   error string by [`redact`].

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::decide::WireResponse;

/// Model the rubric was calibrated against (D15).
pub const PINNED_MODEL: &str = "jev-1.13.0";
/// Response header carrying the request id.
pub const REQUEST_ID_HEADER: &str = "x-typesafe-request-id";
/// Backoff when a retryable response carries no hint.
pub const DEFAULT_BACKOFF: Duration = Duration::from_millis(500);
/// Smallest attempt worth starting inside the budget.
pub const MIN_ATTEMPT: Duration = Duration::from_millis(200);

/// An API key. `Debug` never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wrap a key (surrounding whitespace removed).
    pub fn new(s: &str) -> Secret {
        Secret(s.trim().to_string())
    }
    fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// Replace every occurrence of the key in `s`.
pub fn redact(s: &str, key: Option<&Secret>) -> String {
    match key {
        Some(k) if k.0.len() >= 4 => s.replace(k.expose(), "[REDACTED]"),
        _ => s.to_string(),
    }
}

/// Where the key came from (for `cancelli config` and logs; never the key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// Env var name.
    Env(String),
    /// File path.
    File(PathBuf),
}

impl std::fmt::Display for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeySource::Env(n) => write!(f, "env ${n}"),
            KeySource::File(p) => write!(f, "file {}", p.display()),
        }
    }
}

/// Read a key file, refusing any group/other permission bits.
pub fn read_key_file(path: &Path) -> Result<Secret, String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("api_key_file {}: {}", path.display(), e.kind()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "api_key_file {} has mode {mode:04o}; refusing (must be 0600 or stricter)",
            path.display()
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("api_key_file {}: {}", path.display(), e.kind()))?;
    let key = Secret::new(&text);
    if key.0.is_empty() {
        return Err(format!("api_key_file {} is empty", path.display()));
    }
    Ok(key)
}

/// Resolve the key: env var first, then the file.
pub fn resolve_key(
    env_value: Option<&str>,
    env_name: &str,
    file: Option<&Path>,
) -> Result<(Secret, KeySource), String> {
    if let Some(v) = env_value.filter(|v| !v.trim().is_empty()) {
        return Ok((Secret::new(v), KeySource::Env(env_name.to_string())));
    }
    match file {
        Some(p) => read_key_file(p).map(|k| (k, KeySource::File(p.to_path_buf()))),
        None => Err(format!(
            "no Jev API key: ${env_name} is unset and judge.api_key_file is not configured"
        )),
    }
}

/// Transport settings.
#[derive(Debug, Clone)]
pub struct Transport {
    /// Base URL (no trailing slash needed).
    pub base_url: String,
    /// Per-attempt timeout.
    pub timeout: Duration,
    /// Total budget.
    pub budget: Duration,
}

/// A successful exchange.
#[derive(Debug, Clone)]
pub struct Reply {
    /// Parsed body.
    pub response: WireResponse,
    /// `answers` as raw JSON (for the log).
    pub answers_raw: serde_json::Value,
    /// `x-typesafe-request-id`.
    pub request_id: Option<String>,
    /// Attempts made.
    pub attempts: u32,
}

/// A failed exchange (already redacted).
#[derive(Debug, Clone)]
pub struct Failure {
    /// What went wrong.
    pub error: String,
    /// Request id, if a response arrived.
    pub request_id: Option<String>,
    /// Attempts made.
    pub attempts: u32,
}

enum Attempt {
    Done(u16, Option<String>, Option<Duration>, String),
    Timeout(String),
    Other(String),
}

/// Parse `retry-after-ms` / `retry-after` (seconds or HTTP-date).
pub fn retry_after(
    ms: Option<&str>,
    after: Option<&str>,
    now: time::OffsetDateTime,
) -> Option<Duration> {
    if let Some(v) = ms.and_then(|s| s.trim().parse::<f64>().ok())
        && v.is_finite()
        && v >= 0.0
    {
        return Some(Duration::from_secs_f64(v / 1000.0));
    }
    let a = after?.trim();
    if let Ok(v) = a.parse::<f64>() {
        return (v.is_finite() && v >= 0.0).then(|| Duration::from_secs_f64(v));
    }
    let fmt = time::macros::format_description!(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
    );
    let t = time::PrimitiveDateTime::parse(a, &fmt).ok()?.assume_utc();
    let d = t - now;
    Some(if d.is_negative() {
        Duration::ZERO
    } else {
        d.unsigned_abs()
    })
}

fn attempt(url: &str, key: &Secret, body: &str, timeout: Duration) -> Attempt {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .user_agent(format!("cancelli/{}", crate::VERSION))
        .build()
        .into();
    let res = agent
        .post(url)
        .header("Authorization", &format!("Bearer {}", key.expose()))
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .send(body);
    match res {
        Ok(mut r) => {
            let status = r.status().as_u16();
            let h = |n: &str| {
                r.headers()
                    .get(n)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            let rid = h(REQUEST_ID_HEADER);
            let wait = retry_after(
                h("retry-after-ms").as_deref(),
                h("retry-after").as_deref(),
                time::OffsetDateTime::now_utc(),
            );
            match r.body_mut().read_to_string() {
                Ok(text) => Attempt::Done(status, rid, wait, text),
                Err(ureq::Error::Timeout(t)) => {
                    Attempt::Timeout(format!("timeout reading body ({t})"))
                }
                Err(e) => Attempt::Other(format!("reading body: {e}")),
            }
        }
        Err(ureq::Error::Timeout(t)) => Attempt::Timeout(format!("timeout ({t})")),
        Err(e) => Attempt::Other(format!("transport: {e}")),
    }
}

fn retryable(status: u16) -> bool {
    status == 408 || status == 429 || (500..=599).contains(&status)
}

fn snippet(s: &str) -> String {
    let t: String = s.chars().take(300).collect();
    t.replace('\n', " ")
}

/// POST the body; parse and return the response. Never exceeds the budget
/// (plus connection-setup slack inside ureq's own timeout).
pub fn post(t: &Transport, key: &Secret, body: &str) -> Result<Reply, Failure> {
    let start = Instant::now();
    let url = format!("{}/v1/systemone", t.base_url.trim_end_matches('/'));
    let mut attempts = 0u32;
    let fail = |error: String, request_id: Option<String>, attempts: u32| Failure {
        error: redact(&error, Some(key)),
        request_id,
        attempts,
    };
    loop {
        let remaining = t.budget.saturating_sub(start.elapsed());
        if remaining < MIN_ATTEMPT && attempts > 0 {
            return Err(fail("budget exhausted".into(), None, attempts));
        }
        attempts += 1;
        let per = t.timeout.min(remaining.max(MIN_ATTEMPT));
        let (err, wait, rid) = match attempt(&url, key, body, per) {
            Attempt::Done(status, rid, _, text) if (200..300).contains(&status) => {
                let answers_raw = serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| v.get("answers").cloned())
                    .unwrap_or(serde_json::Value::Null);
                return match serde_json::from_str::<WireResponse>(&text) {
                    Ok(response) => Ok(Reply {
                        response,
                        answers_raw,
                        request_id: rid,
                        attempts,
                    }),
                    Err(e) => Err(fail(
                        format!("unparseable response (HTTP {status}): {e}"),
                        rid,
                        attempts,
                    )),
                };
            }
            Attempt::Done(status, rid, wait, text) => {
                let msg = format!("HTTP {status}: {}", snippet(&text));
                if !retryable(status) {
                    return Err(fail(msg, rid, attempts));
                }
                (msg, wait.unwrap_or(DEFAULT_BACKOFF), rid)
            }
            Attempt::Timeout(msg) => (msg, DEFAULT_BACKOFF, None),
            Attempt::Other(msg) => return Err(fail(msg, None, attempts)),
        };
        if attempts >= 2 {
            return Err(fail(format!("{err} (after retry)"), rid, attempts));
        }
        let elapsed = start.elapsed();
        if elapsed + wait + MIN_ATTEMPT > t.budget {
            return Err(fail(
                format!(
                    "{err}; no retry: wait {} ms would exceed the {} ms budget",
                    wait.as_millis(),
                    t.budget.as_millis()
                ),
                rid,
                attempts,
            ));
        }
        std::thread::sleep(wait);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_never_debug_printed_and_redacted() {
        let k = Secret::new(" tsk_live_abcdef123456 \n");
        assert_eq!(format!("{k:?}"), "Secret(***)");
        assert_eq!(
            redact("bad header Bearer tsk_live_abcdef123456!", Some(&k)),
            "bad header Bearer [REDACTED]!"
        );
    }

    #[test]
    fn key_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("k");
        std::fs::write(&p, "abc123xyz\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = read_key_file(&p).unwrap_err();
        assert!(e.contains("0644") && e.contains("refusing"), "{e}");
        assert!(!e.contains("abc123xyz"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_key_file(&p).unwrap(), Secret::new("abc123xyz"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(read_key_file(&p).is_ok());
    }

    #[test]
    fn key_precedence() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("k");
        std::fs::write(&p, "from-file").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (k, s) = resolve_key(Some("from-env"), "TYPESAFE_API_KEY", Some(&p)).unwrap();
        assert_eq!(
            (k, s),
            (
                Secret::new("from-env"),
                KeySource::Env("TYPESAFE_API_KEY".into())
            )
        );
        let (k, s) = resolve_key(Some("  "), "TYPESAFE_API_KEY", Some(&p)).unwrap();
        assert_eq!(
            (k, s),
            (Secret::new("from-file"), KeySource::File(p.clone()))
        );
        let e = resolve_key(None, "X_KEY", None).unwrap_err();
        assert!(e.contains("$X_KEY"));
    }

    #[test]
    fn retry_after_forms() {
        let now = time::macros::datetime!(2026-09-22 12:00:00 UTC);
        assert_eq!(
            retry_after(Some("250"), Some("9"), now),
            Some(Duration::from_millis(250))
        );
        assert_eq!(
            retry_after(None, Some("2"), now),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            retry_after(None, Some("Tue, 22 Sep 2026 12:00:03 GMT"), now),
            Some(Duration::from_secs(3))
        );
        assert_eq!(
            retry_after(None, Some("Tue, 22 Sep 2026 11:00:00 GMT"), now),
            Some(Duration::ZERO)
        );
        assert_eq!(retry_after(None, Some("soon"), now), None);
        assert_eq!(retry_after(None, None, now), None);
    }

    #[test]
    fn retryable_statuses() {
        for s in [408, 429, 500, 502, 503, 599] {
            assert!(retryable(s));
        }
        for s in [400, 401, 403, 404, 422] {
            assert!(!retryable(s));
        }
    }
}
