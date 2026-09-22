//! Registry of deliberate divergences from the CARE reference.
//!
//! `FIX-NNN`: paper-over-repo reconciliations (D1) and reference bug fixes
//! (D2). `EXT-NNN`: macOS extensions. Each analysis records which ones were
//! *activated* for that command (`fixes_applied` / `ext_applied`), so log
//! records can be filtered and the parity suite can check that every
//! divergence from the reference is attributable.

use std::collections::BTreeSet;

use serde::Serialize;

/// How an ID's activation is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Detection {
    /// The code path that differs from the reference tags the analysis.
    Runtime,
    /// Not observable at runtime (e.g. it depends on what bashlex would have
    /// done); parity allowlist entries are accepted without a runtime tag.
    Static,
}

/// One registry entry.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    /// `FIX-NNN` / `EXT-NNN`.
    pub id: &'static str,
    /// One-line summary.
    pub title: &'static str,
    /// Detection mode.
    pub detection: Detection,
}

/// All FIX/EXT IDs. README tables and `docs/COMMIT_MSG.txt` list the same
/// IDs (checked by `tests/docs_consistency.rs`).
pub const REGISTRY: &[Entry] = &[
    Entry {
        id: "FIX-001",
        title: "p_rule: catalog tiers (mitre, gtfobins) with pi*conf >= 0.80 (paper Eq. 9)",
        detection: Detection::Runtime,
    },
    Entry {
        id: "FIX-002",
        title: "p_spath: write to system/critical tier or any secret-tier access (paper Eq. 11)",
        detection: Detection::Runtime,
    },
    Entry {
        id: "FIX-003",
        title: "p_sem: H_sem = {DESTRUCTIVE, PRIVILEGE_OR_PERMISSION, EXECUTION_CHAIN, PERSISTENCE, NETWORK_FETCH} (paper Eq. 10)",
        detection: Detection::Runtime,
    },
    Entry {
        id: "FIX-004",
        title: "Judge output: first token must be SAFE or DANGEROUS, anything else DENY (paper Prompt 1)",
        detection: Detection::Runtime,
    },
    Entry {
        id: "FIX-005",
        title: "L1 sees $()/backtick/<() substitutions: flags, nesting depth, inner atoms",
        detection: Detection::Runtime,
    },
    Entry {
        id: "FIX-006",
        title: "Canonicalization yields views instead of appending marker text",
        detection: Detection::Runtime,
    },
    Entry {
        id: "FIX-007",
        title: "Padded base64 payloads are decoded",
        detection: Detection::Runtime,
    },
    Entry {
        id: "FIX-008",
        title: "Judge call has a hard timeout (fail closed)",
        detection: Detection::Runtime,
    },
    Entry {
        id: "FIX-009",
        title: "Lexicon conflict: `git tag` listing is READ_ONLY, creating/deleting WRITE_LOCAL",
        detection: Detection::Runtime,
    },
    Entry {
        id: "FIX-010",
        title: "L3 treats mkfs.<fs> heads as write/destructive like mkfs",
        detection: Detection::Runtime,
    },
    Entry {
        id: "FIX-011",
        title: "L1 extracts commands inside if/for/while/until/case/function bodies",
        detection: Detection::Runtime,
    },
    Entry {
        id: "FIX-012",
        title: "Parser replacement (D4): brush-parser accepts/rejects different inputs than bashlex",
        detection: Detection::Static,
    },
    Entry {
        id: "FIX-013",
        title: "Pipe-to-interpreter compares the basename of the pipeline tail (`| /bin/sh`)",
        detection: Detection::Runtime,
    },
    Entry {
        id: "EXT-001",
        title: "macOS secret paths: ~/Library/Keychains/, /Library/Keychains/",
        detection: Detection::Runtime,
    },
    Entry {
        id: "EXT-002",
        title: "macOS /private/{etc,var,tmp} aliases resolved to /etc, /var, /tmp",
        detection: Detection::Runtime,
    },
    Entry {
        id: "EXT-003",
        title: "macOS sensitive-system paths: /System/, /Library/Launch{Agents,Daemons}/, ~/Library/LaunchAgents/, /Library/StartupItems/",
        detection: Detection::Runtime,
    },
    Entry {
        id: "EXT-004",
        title: "macOS system-root sinks: /System, /Library, /Applications, /Users, /private, /Volumes",
        detection: Detection::Runtime,
    },
    Entry {
        id: "EXT-005",
        title: "macOS block devices /dev/diskN, /dev/rdiskN are critical",
        detection: Detection::Runtime,
    },
    Entry {
        id: "EXT-006",
        title: "macOS `base64 -D` decode flag triggers payload decoding",
        detection: Detection::Runtime,
    },
];

/// Look up an ID.
pub fn entry(id: &str) -> Option<&'static Entry> {
    REGISTRY.iter().find(|e| e.id == id)
}

/// Activated FIX/EXT IDs for one analysis.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Tags {
    /// FIX IDs.
    pub fixes: BTreeSet<&'static str>,
    /// EXT IDs.
    pub exts: BTreeSet<&'static str>,
}

impl Tags {
    /// Record a FIX activation.
    pub fn fix(&mut self, id: &'static str) {
        debug_assert!(entry(id).is_some(), "unknown id {id}");
        self.fixes.insert(id);
    }

    /// Record an EXT activation.
    pub fn ext(&mut self, id: &'static str) {
        debug_assert!(entry(id).is_some(), "unknown id {id}");
        self.exts.insert(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_unique_and_well_formed() {
        let mut seen = BTreeSet::new();
        for e in REGISTRY {
            assert!(e.id.starts_with("FIX-") || e.id.starts_with("EXT-"));
            assert_eq!(e.id.len(), 7);
            assert!(seen.insert(e.id), "duplicate {}", e.id);
        }
    }
}
