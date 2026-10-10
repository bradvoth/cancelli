//! LIVE tests against Jev through OpenRouter's Decisions API (D28:
//! openrouter.ai, or `$OPENROUTER_BASE_URL`). The same checks as
//! tests/jev_live.rs (tests/common/live.rs), with OpenRouter's path, key
//! variable, request model and dated-snapshot `expected_model`. They cost
//! a few cents' worth of tokens at most and need a key:
//!
//! ```sh
//! OPENROUTER_API_KEY=... cargo test --test openrouter_live -- --ignored --test-threads=1
//! ```
//!
//! Ignored by default so `cargo test` never touches the network.

mod common;

use cancelli::jev::provider::Provider;
use common::live::Live;

const LIVE: Live = Live {
    provider: Provider::OpenRouter,
    test_name: "openrouter_live",
    // Live run 2026-10-10: OpenRouter sends no x-typesafe-request-id
    // (`request_id` is null, printed) and reports `usage` in TypeSafe's
    // shape (`input_tokens`, `output_tokens`; asserted).
    sends_request_id: false,
    reports_usage: true,
};

/// The POC's contrastive smoke gate through OpenRouter: 4 pairs, 10
/// checks; every response must report a `typesafe/jev-1.13-*` snapshot and
/// answer every question sent.
#[test]
#[ignore = "live: calls OpenRouter; needs OPENROUTER_API_KEY"]
fn live_smoke_gate() {
    LIVE.smoke_gate();
}

/// One unresolved-WARN Bash call through the *installed* binary with
/// `provider = "openrouter"` in the config file: the decisions endpoint,
/// the OpenRouter key and a Jev snapshot show in a complete, error-free
/// judge record.
#[test]
#[ignore = "live: calls OpenRouter; needs OPENROUTER_API_KEY; builds a release binary"]
fn live_warn_command_end_to_end_through_installed_binary() {
    LIVE.warn_command_end_to_end_through_installed_binary();
}
