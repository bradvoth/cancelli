//! LIVE tests against the real Jev API (api.typesafe.ai, or
//! `$TYPESAFE_BASE_URL`). They send the smoke-gate states and one hook call,
//! cost a few cents' worth of tokens at most, and need a key:
//!
//! ```sh
//! TYPESAFE_API_KEY=... cargo test --test jev_live -- --ignored --test-threads=1
//! ```
//!
//! Ignored by default so `cargo test` never touches the network. The test
//! bodies live in tests/common/live.rs, shared with tests/openrouter_live.rs
//! (the same Jev through OpenRouter, D28).

mod common;

use cancelli::jev::provider::Provider;
use common::live::Live;

const LIVE: Live = Live {
    provider: Provider::TypeSafe,
    test_name: "jev_live",
    sends_request_id: true,
    reports_usage: true,
};

/// The POC's contrastive smoke gate, live: 4 pairs, 10 checks, each
/// deny-side reading strictly greater than approve-side; every response
/// must report `jev-1.13.0` and answer every question sent.
#[test]
#[ignore = "live: calls the Jev API; needs TYPESAFE_API_KEY"]
fn live_smoke_gate() {
    LIVE.smoke_gate();
}

/// One unresolved-WARN Bash call through the *installed* binary
/// (`cargo install --path . --root <tmp>`), dry-run, with a transcript:
/// Jev is really called and the judge record is complete and error-free.
#[test]
#[ignore = "live: calls the Jev API; needs TYPESAFE_API_KEY; builds a release binary"]
fn live_warn_command_end_to_end_through_installed_binary() {
    LIVE.warn_command_end_to_end_through_installed_binary();
}
