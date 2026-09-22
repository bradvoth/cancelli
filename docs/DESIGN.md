# cancelli — design

A Rust port of CARE (arXiv 2607.21642, reference impl `prisma-research/CARE` @ `e8166db0c39fa058285b203305649a13eb31fc0b`, MIT) packaged as a Claude Code `PreToolUse` hook.

Research notes: `docs/research/care-paper-report.md`, `docs/research/care-repo-report.md`.

## Decisions (agreed with the user, 2026-09-21)

| # | Decision | Choice |
|---|----------|--------|
| D1 | Spec source when paper and repo disagree | **Paper wins.** Repo is the source for concrete rule text, lexicons, path catalogs, weights the paper omits. |
| D2 | Bugs in the reference | **Port with bugs fixed.** Each fix gets an ID `FIX-NNN`, a README table row, a commit-message line, and a regression test. |
| D3 | Tool scope | **Bash scored by CARE; all other tools logged raw, unscored.** |
| D4 | Bash parser | **brush-parser** (replaces bashlex). |
| D5 | Data | **JSONL, PreToolUse only.** No PostToolUse outcome join. |
| D6 | Mode | **Dry-run for now** (`--dry-run`): never emits a decision. |
| D7 | LLM judge on WARN | **Stubbed.** Behind an `Adjudicator` trait; step 2 is a local open-weight model ("Jev"). |
| D11 | Judge = Jev (2026-09-22) | The WARN adjudicator is **Jev** (the `jev_gate` POC in `~/Documents/tte`, findings in `JEV_GATE_FINDINGS.md`). Jev is the **final decider**, and its tiers map to allow / ask / deny. |
| D12 | Jev scope | **Jev only sees calls CARE leaves at WARN with no skip predicate firing** (paper Resolution). CARE's static ALLOW and DENY are final and never sent to Jev. |
| D13 | Jev allow: decide or pass | **Configurable.** `--decide-all` flag / `decide_all = true` in config.toml: a Jev `allow` emits `permissionDecision: "allow"`, which skips Claude Code's prompt. Default `false`: a Jev `allow` emits nothing, so normal permission rules decide. Jev `ask`/`deny` always emit. It applies only to Jev's verdicts; CARE's static ALLOW always passes silently. It has no effect in dry-run. |
| D14 | Jev tier → verdict | Tiers are evaluated first-match in `docs/research/jev-integration-spec.md` §4.2. **T1** (transport ∧ sensitive ∧ unknown) and **T2** (`f5 > 0.9`) → **deny**. **T3–T5** → **ask**. **T6** (no tier fired) → **allow** (subject to D13). Thresholds are exactly those in the spec, recalibrated later against Claude Code traffic. |
| D15 | Jev failure | No key, timeout, transport or HTTP error, unparseable response, missing answers, or `response.model != "jev-1.13.0"` all produce **ask**, plus an error record in the log. |
| D16 | Jev context | **L2 exactly as in the POC** render template (spec §3): proposed action; the user's request from genuine user prompts in the transcript; prior agent tool calls with args verbatim, clipped as in the POC; tool results **never** included (reasoning-blind). |
| D17 | Jev in dry-run | **Called for real** on unresolved WARNs. The full request state, answers, tier, verdict, latency, usage and request-id are logged. No decision is emitted. |
| D18 | CARE tunables (2026-09-22) | Scalars go in `config.toml` `[care]`: L5 layer weights; per-mode τlow/τhigh; θrule, θsem; provenance π per tier; H_sem class set; L2 class base scores; L1 structure penalties; L3 path tier scores. **Per-rule overrides** by SE-P id: `enabled`, `confidence`. Lexicons, path catalogs and regexes stay embedded. |
| D19 | Jev tunables | `[jev]`: every tier threshold (a5 transport, a1/a7 sensitive, a6 unknown incl. its f5 gate, f5 deny/ask cut-offs, d1/b4), tier order, tier→verdict map, context limits (4,000 / 12,000 chars, max level). Also **`rubric_file`**, an alternative rubric YAML, validated at load with its rubric_hash logged. An invalid file falls back to the embedded rubric with an error record. Tiers referencing axes the rubric lacks can't fire, and produce a warning record. |
| D20 | Tunable guardrails | Every default equals today's behaviour, so an empty config changes nothing, and the parity and fidelity tests run on defaults. Values are validated at load; an invalid value falls back to its default with an error record (fail open). Each log record carries `config_fingerprint`, a hash of the effective tunables, plus `overrides[]`, the keys that differ from default. `cancelli config` lists every tunable with its source. |
| D8 | Crate structure | **Library + thin binary.** All logic (pipeline, hook I/O, logging, config) lives in the lib (`src/lib.rs` + modules); `src/main.rs` only parses CLI args and calls into the lib. |
| D9 | Install | **`cargo install --path .`** → `~/.cargo/bin/cancelli`; the hook command is `cancelli hook --dry-run`. Nothing may depend on the source checkout at runtime (rules/prompt embedded via `include_str!`). |
| D10 | Config | **`~/.config/cancelli/config.toml`** (`$XDG_CONFIG_HOME/cancelli/config.toml` if set; deliberately *not* macOS `~/Library/Application Support`). |

## Config (D10)

Precedence: CLI flag > env var > config file > built-in default. A missing file means defaults. An unreadable or invalid file means defaults plus an error record in the log (fail open). Unknown keys produce a warning record, not a failure. `cancelli config` prints the effective config and where each value came from. `cancelli config --init` writes a commented default file if none exists.

```toml
mode = "balanced"          # strict | balanced | auto
dry_run = true             # the --dry-run flag forces true
decide_all = false         # D13; --decide-all forces true (top-level: must precede any [table])

[log]
dir = "~/.local/share/cancelli"   # env CANCELLI_LOG_DIR overrides
max_field_bytes = 4096            # non-Bash string truncation threshold

[judge]
backend = "jev"            # "jev" | "stub"
base_url = "https://api.typesafe.ai"   # env TYPESAFE_BASE_URL overrides
model = "jev-1.13.0"       # pinned; response.model must match
api_key_env = "TYPESAFE_API_KEY"
# api_key_file = "~/.config/cancelli/jev_api_key"   # 0600; used if the env var is unset
timeout_ms = 3000          # per request
budget_ms = 5000           # total incl. one retry on 408/429/5xx; must stay well under the hook timeout
```

The key is never written to logs or to config.toml. When `api_key_file` has group or other permissions, it is refused with an error record, and the D15 behaviour applies.

## Paper-over-repo reconciliations (D1)

| ID | Topic | Repo behaviour | Port behaviour (paper) |
|----|-------|----------------|------------------------|
| FIX-001 | `p_rule` skip predicate | raw conf ≥ 0.80 on any rule with a MITRE T-ID (fallback catches GTFOBins/manual) | fires iff a fired rule has tier ∈ {mitre, gtfobins} and π·conf ≥ 0.80 (π = 1.00/0.85/0.60) |
| FIX-002 | `p_spath` skip predicate | any L3 hit | write to system/critical tier, or any access to secret tier |
| FIX-003 | `H_sem` high-risk class set | WRITE_SENSITIVE, EXECUTION_CHAIN, PRIVILEGE, PERSISTENCE, DESTRUCTIVE, RESOURCE_ABUSE | destructive, priv-escalate, exec-chaining, persist-modify, network-exfil (map onto repo class enum; document the mapping) |
| FIX-004 | Judge output parsing | substring DANGEROUS/UNSAFE → DENY, else ALLOW (garbage → ALLOW) | first token ∈ {SAFE, DANGEROUS}; anything else → DENY (fail-closed). Applies to the future real judge; stub never parses. |

## Reference bug fixes (D2)

Numbered continuing from above (FIX-005…), covering at least repo report §9 items 2 (`$()` detection dead under a successful parse), 3 (canonicalization markers polluting L1/L2/L4), 4 (padded base64 not decoded), 7 (no judge timeout — enforce one), and 11 (duplicate/conflicting lexicon entries). Each is verified against the Python reference before being declared a bug.

Not bugs (paper-faithful, kept, observable in dry-run data): everyday dev commands (`rm -rf node_modules`, `git push --force`, `sudo …`) reaching DENY via `p_sem`.

## Implementation defaults (not user-decided; revisit with data)

- **Views.** Canonicalization produces a list of views (raw + each decoded/unwrapped payload) instead of appending marker text. Each layer scores `max` over views (paper: ĉ keeps original tokens).
- **Multi-command input.** Per simple command ("atom") scoring, `max` over atoms (repo behaviour).
- **Parse failure.** Mirror repo fallback behaviour; brush-parser's strictness vs bashlex is measured by the parity suite and reported.
- **macOS paths.** Extension tiers (`~/Library/Keychains`, `/private/etc`, `/System`, `~/Library/LaunchAgents`, …) labeled `EXT-NNN`, listed in README, tagged in log records so they can be filtered out.
- **All modes logged.** One score, provisional verdicts for strict/balanced/auto all recorded; `balanced` is the configured mode.
- **Fail open.** Any internal error → log an error record, exit 0, no stdout. A hook must never break the session.
- **Non-Bash tools.** Log `tool_name` and `tool_input`; string fields > 4 KiB are truncated and accompanied by length + sha256.
- **Log location.** `$CANCELLI_LOG_DIR` or `~/.local/share/cancelli/`, file `events-YYYY-MM-DD.jsonl` (local date), mode 0600, append with a single `write` per record (O_APPEND) for safety across parallel sessions.

## Hook contract

- stdin: Claude Code PreToolUse JSON (`session_id`, `transcript_path`, `cwd`, `permission_mode`, `hook_event_name`, `tool_name`, `tool_input`, `tool_use_id`, …). Unknown fields ignored; raw payload keys preserved in the log.
- `--dry-run`: exit 0, empty stdout, always.
- Enforce mode (built, not registered): DENY → `hookSpecificOutput.permissionDecision = "deny"` with reason; unadjudicated WARN → `"ask"`; ALLOW → no output (normal permission flow, never auto-approve).

## Log record (per PreToolUse)

`ts, version, rules_version, session_id, tool_use_id, cwd, permission_mode, tool_name, mode, dry_run, latency_us` plus, for Bash: `command, views[], layers{L1,L2,L3,L4: score + evidence}, fired_rules[{id, tier, conf, pi, family}], aggregate, provisional{strict,balanced,auto}, skip_predicate, would_adjudicate, judge_prompt (when would_adjudicate), final, fixes_applied[], ext_applied[]`; for others: `tool_input` (truncated per above). Every record also carries `config_fingerprint`, `overrides[]` and `rubric_hash` (D20).

## Testing

- **E2E:** build the binary, pipe real PreToolUse JSON on stdin, assert exit code, empty stdout in dry-run, and exact log-record content (verdicts, fired rules, skip predicate, judge prompt).
- **Parity:** `scripts/parity/` pins the Python reference at the commit above, runs it over a corpus, and commits golden output. A Rust test compares every record; any divergence must be listed under a `FIX-`/`EXT-` ID or the test fails.
- **Regression:** one test per `FIX-`/`EXT-` ID demonstrating the corrected behaviour.
