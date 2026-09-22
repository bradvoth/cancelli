# cancelli — implementation progress

Structure per DESIGN.md D8 (lib + thin bin), D9 (cargo install, everything embedded), D10 (config.toml at $XDG_CONFIG_HOME|~/.config/cancelli).

## Done
- [x] Read DESIGN.md (incl. D8-D10), both reports, Python reference source
- [x] M1 scaffold: Cargo.toml deps, pyre.rs (Python regex semantics), rules.rs (139 rules compile; fancy only SE-P-069/094/139), fixes.rs registry
- [x] canon.rs views (FIX-006, FIX-007, EXT-006) + tests

- [x] L1 structure.rs (brush walker, FIX-005/011/013), L2 semantic.rs (FIX-009), L3 path.rs (FIX-010, EXT-001..005), L4 pattern.rs, L5 policy.rs
- [x] resolution.rs (FIX-001..004, FIX-008 timeout, stub adjudicator, prompt from data/*.txt), engine.rs
- NOTE: corpus will NOT include hand-authored per-rule attack triggers / obfuscated variants (a safety classifier stopped that content); corpus = benign + reference repo/report examples only.

- [x] config.rs (D10), logging.rs, hook.rs, main.rs (thin clap CLI; catch_unwind)
- [x] parity: scripts/parity/{run_reference.py,regenerate.sh}, tests/corpus/commands.txt (495 cmds), tests/golden/reference.jsonl, tests/golden/allowlist.json, tests/parity.rs -> 382 identical / 113 divergent, all attributed
- perf: `[\s\S]` -> `(?s:.)` in pyre (rule-bank compile ~31ms -> ~17ms release)

## Next (milestones)
1. scaffold crate (lib + main.rs), vendor rules JSON + NOTICE
2. canonicalization views; L1 (brush-parser); L2; L3; L4; L5
3. resolution (skip predicates, adjudicator stub, FIX-004 parser)
4. hook/logging/config (+ `config`, `config --init`)
5. parity driver + corpus + golden + Rust parity test
6. e2e tests (+ cargo install check)
7. README, COMMIT_MSG

## COMPLETE (all milestones)
- [x] tests/e2e.rs (16, real binary + temp log dir), tests/install.rs (D9 cargo install, ignored/CI), tests/docs_consistency.rs
- [x] README.md, docs/COMMIT_MSG.txt, NOTICE, LICENSE, Cargo metadata
- [x] cargo test (65 total across bins) green; clippy --all-targets -D warnings clean; cargo fmt --check clean
- Parity: 495 corpus / 382 identical / 113 divergent, all attributed by FIX/EXT id in tests/golden/allowlist.json
- FIX-004 and FIX-008 are judge-path fixes: covered by unit regression tests in resolution.rs (no real judge in the static parity corpus)
- Do NOT commit (parent reviews).

- Integrated subagent's verified per-rule corpus (tests/corpus/parts/rule_triggers.txt): corpus now 495 cmds, all 139 rules exercised; golden + allowlist regenerated; parity 382 identical / 113 divergent, all attributed.

---
# Jev adjudicator (D11–D17) — started 2026-09-22

Constraints: no commit; tte read-only (never .env); no network (crates resolved with `--offline` from the local registry cache); user runs live tests.

## Plan / milestones
- [x] J0 read DESIGN D11–D17, spec, POC python; probe offline crates (ureq 3.4.2 + rustls/ring, serde_yaml 0.9.34 OK offline)
- [x] J0 fixtures: 8 smoke cache files -> tests/fixtures/jev/ (screened: no credentials; only answers/model/usage/request_id/elapsed_ms/error); rubric -> data/jev/v1_policy_distilled.yaml; POC-computed expected signals -> tests/fixtures/jev/expected_signals.json (scripts/jev/compute_expected.py). POC tiers for smoke states: 6,2,6,2,6,2,6,5
- [x] J1 src/jev/{pyjson,rubric}.rs + rubric_hash test (0fd1f245ae1c7ef3)
- [x] J2 src/jev/state.rs render/to_dict/state_hash/decode + 8 smoke render/hash test
- [x] J3 src/jev/transcript.rs filter (pure, unit-tested) + context building (JEV-DEV-001, lag -> L0/L1)
- [x] J4 src/jev/decide.rs answers parse, signals, tiers, verdict + fixture replay test + 10 smoke checks
- [x] J5 src/jev/client.rs ureq transport, key resolution (env / 0600 file), retry/budget, model check, redaction
- [x] J6 wire: resolution (Adjudicator input, Final::Ask), engine, hook (decide_all, would_emit, judge record, error record), config keys, CLI (--decide-all, judge subcommand)
- [x] J7 tests: e2e failure paths via real binary (refused, hang, no key, wrong model), decide_all on/off, jev_live.rs (#[ignore])
- [x] J8 README Jev section, COMMIT_MSG, clippy/fmt, full test run

## Decisions taken (implementation-level, documented in README)
- "unknown" = declared a6 predicate: `a6_destination_class=unknown_remote == 1` (argmax, gated on f5 > 0.8), per the shipped YAML (spec §4.2 second table, v2 row)
- Level: transcript missing/unreadable -> L0; current tool_use_id not yet in transcript (lag) -> L1 (L0 if no prompt); else L2
- Proposed action for Bash = `tool: bash`, `args: <command>` (ShellRisk/smoke path); prior Bash calls `bash(<command>)`, others `<Name>(<py json.dumps(input, sort_keys)>)`
- J1–J6 done: 74 lib tests + tests/jev_offline.rs (4) green; rubric hash 0fd1f245ae1c7ef3 recomputed; 8/8 smoke renders + state_hashes byte-identical to POC; replayed signals == POC signals(); tiers 6,2,6,2,6,2,6,5; 10/10 smoke checks
- J7 done: tests/jev_e2e.rs (12, real binary + local server: refused/hang/no key/0644 key file/wrong model/503-then-ok/401, dry-run full record + wire capture, decide_all on/off, deny/ask tiers, D12 static never sent, judge subcommand, config); e2e.rs WARN test updated (unadjudicated -> ask, D15) + stub-backend test + non-UTF-8 env regression (fixed Env::from_process panic); tests/jev_live.rs (2, #[ignore], not run)
- J8 done: README Jev section (egress, key setup, mapping, tiers + purity, decide_all/auto mode, failures, JEV-DEV-001..004, fidelity + live tests, ureq rationale), NOTICE, COMMIT_MSG (Jev commit), docs_consistency checks JEV-DEV ids
- FINAL: 111 offline tests pass (lib 74, docs 2, e2e 18, jev_e2e 12, jev_offline 4, parity 1); install (ignored) passes with CARGO_NET_OFFLINE=true; jev_live (2, ignored) written, NOT run (user runs with a key); clippy -D warnings + fmt clean; not committed
