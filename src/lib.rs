//! cancelli — a Rust port of CARE (Canonicalization, Attribution, and
//! Resolution Engine; arXiv 2607.21642, reference implementation
//! `prisma-research/CARE`, MIT) packaged as a Claude Code `PreToolUse` hook.
//!
//! All logic lives in this library (D8); `src/main.rs` only parses CLI
//! arguments.

pub mod calibrate;
pub mod canon;
pub mod config;
pub mod engine;
pub mod eval;
pub mod fixes;
pub mod hook;
pub mod jev;
pub mod logging;
pub mod path;
pub mod pattern;
pub mod policy;
pub mod pyre;
pub mod resolution;
pub mod rules;
pub mod semantic;
pub mod structure;
pub mod tunables;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
