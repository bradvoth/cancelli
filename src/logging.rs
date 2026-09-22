//! JSONL event log: `<dir>/events-YYYY-MM-DD.jsonl` (local date), file mode
//! 0600, one `O_APPEND` write per record so parallel sessions never
//! interleave partial lines.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Current local time (UTC if the local offset cannot be determined).
pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc())
}

/// RFC 3339 timestamp.
pub fn ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

/// Log file for a given date.
pub fn file_for(dir: &Path, t: OffsetDateTime) -> PathBuf {
    dir.join(format!(
        "events-{:04}-{:02}-{:02}.jsonl",
        t.year(),
        u8::from(t.month()),
        t.day()
    ))
}

/// Append one record (serialized as a single line).
pub fn append(dir: &Path, t: OffsetDateTime, record: &Value) -> std::io::Result<PathBuf> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let path = file_for(dir, t);
    let mut line = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    line.push(b'\n');
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&path)?;
    // A single write(2); regular-file appends are not short in practice, but
    // finish the line if the kernel ever returns a partial count.
    let n = f.write(&line)?;
    if n < line.len() {
        f.write_all(&line[n..])?;
    }
    Ok(path)
}

/// Hex SHA-256.
pub fn sha256_hex(b: &[u8]) -> String {
    let d = Sha256::digest(b);
    d.iter().map(|x| format!("{x:02x}")).collect()
}

/// Replace every string longer than `max` bytes with
/// `{"truncated": <prefix>, "len": <bytes>, "sha256": <hex>}`.
pub fn truncate_strings(v: &Value, max: usize) -> Value {
    match v {
        Value::String(s) if s.len() > max => {
            let mut cut = max;
            while !s.is_char_boundary(cut) {
                cut -= 1;
            }
            let mut m = Map::new();
            m.insert("truncated".into(), Value::String(s[..cut].to_string()));
            m.insert("len".into(), Value::from(s.len()));
            m.insert("sha256".into(), Value::String(sha256_hex(s.as_bytes())));
            Value::Object(m)
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| truncate_strings(x, max)).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| (k.clone(), truncate_strings(x, max)))
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn append_creates_0600_and_lines() {
        let d = tempfile::tempdir().unwrap();
        let t = now();
        let p = append(d.path(), t, &serde_json::json!({"a": 1})).unwrap();
        append(d.path(), t, &serde_json::json!({"b": "x\ny"})).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text, "{\"a\":1}\n{\"b\":\"x\\ny\"}\n");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn truncation() {
        let v = serde_json::json!({"content": "é".repeat(3000), "n": 1, "short": "x"});
        let t = truncate_strings(&v, 4096);
        assert_eq!(t["content"]["len"], 6000);
        assert_eq!(t["content"]["truncated"].as_str().unwrap().len(), 4096);
        assert_eq!(t["content"]["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(t["short"], "x");
        assert_eq!(t["n"], 1);
    }
}
