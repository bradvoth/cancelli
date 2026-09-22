# cancelli

`cancelli` is a Rust port of **CARE** — the *Canonicalization, Attribution,
and Resolution Engine* from ["CARE: Pre-Execution Command Verification for
Shell-Executing LLM Agents"](https://arxiv.org/abs/2607.21642) — packaged as
a [Claude Code](https://claude.com/claude-code) `PreToolUse` hook. It scores
each `Bash` command an agent is about to run through CARE's static pipeline
and writes a structured JSONL record, so you can see what a command-level
guard *would* decide before turning enforcement on.

For now it runs in **dry-run**: it always allows the command and only logs.
Borderline (WARN) commands are adjudicated by **Jev** (`jev-1.13.0`, TypeSafe
AI's hosted model; decisions D11–D17), which sees the user's request and the
agent's prior tool calls. See [Jev adjudicator](#jev-adjudicator), including
**what data leaves your machine**.

## What it does

For a `Bash` tool call it runs the CARE pipeline:

1. **Canonicalization** — unwrap `sh -c`, resolve `$IFS`/variable splitting,
   collapse `$(echo x)`, decode base64/hex/octal payloads. cancelli produces
   a list of *views* (raw + each decoded form) rather than appending marker
   text to one string, so the layers below match the deobfuscated command
   without the marker pollution the reference suffers from (FIX-006).
2. **L1 structure** (`brush-parser`), **L2 semantic** (~250-head lexicon),
   **L3 path** (sensitivity tiers, read/write aware), **L4 pattern** (the
   139-rule provenance bank).
3. **L5 aggregation** `0.30·sem + 0.30·path + 0.30·pat + 0.10·struct`, then a
   provisional verdict per mode (strict `0.10/0.20`, balanced `0.15/0.35`,
   auto `0.20/0.50`).
4. **Resolution** — the paper's skip predicates (`p_rule ∨ p_spath ∨ p_sem`);
   a WARN with no skip goes to Jev, whose tier decides allow / ask / deny.
   CARE's static ALLOW and DENY are final and never sent to Jev (D12).

Every other tool (`Write`, `Read`, `mcp__…`, …) is logged raw and unscored
(decision D3); string fields over 4 KiB are truncated with a length and
SHA-256.

CARE targets Linux bash/sh; cancelli adds a small set of macOS path
extensions (the `EXT-` table). It is a complementary pre-execution signal,
**not** a sandbox. The CARE layers read only the command string plus
`$HOME`/cwd. Only for unresolved WARNs does the Jev step also read the session
transcript: the human prompts and the agent's prior tool calls, never tool
results or the agent's prose.

## Install

```sh
cargo install --path .
```

This builds `~/.cargo/bin/cancelli`. Everything it needs (the rule bank, the
judge prompt and the Jev rubric) is embedded in the binary with
`include_str!`, so nothing depends on the source checkout at runtime
(decision D9). Jev additionally needs network access to its API and a key
(see [Key setup](#key-setup)). Requires the Rust
2024 edition toolchain (≥ 1.98).

Build/test from source:

```sh
cargo build --release
cargo test                       # unit + e2e + parity + Jev offline + docs consistency
cargo test --test install -- --ignored   # cargo-install smoke test (slow)
TYPESAFE_API_KEY=... cargo test --test jev_live -- --ignored   # live Jev API (see below)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Register as a hook

cancelli does not modify your settings. Add this to
`~/.claude/settings.json` yourself (matcher `"*"` so every tool is logged;
`--dry-run` so it never changes a decision):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "cancelli hook --dry-run" }
        ]
      }
    ]
  }
}
```

The hook reads the PreToolUse JSON on stdin, appends one log record, and
(in dry-run) prints nothing and exits 0. It **fails open**: any error — bad
JSON, a missing command, an internal panic — is logged as an `error` record
and the session proceeds.

Even in dry-run, an unresolved WARN calls Jev (D17). That adds one API round
trip to those calls only: the POC measured p50 226 ms, p95 437 ms and a max of
3.0 s over 8,984 calls, and cancelli caps it at `budget_ms`. Without a key
there is no call; the WARN is logged as a Jev failure (`ask`).

### CLI

```
cancelli hook   [--dry-run] [--mode strict|balanced|auto] [--decide-all]   # read stdin, log
cancelli analyze "<command>" [--mode …]                     # full CARE analysis JSON (no Jev call)
cancelli judge "<command>" [--transcript PATH] [--request TEXT] [--decide-all]
                                                            # ask Jev, print the judge record
cancelli config [--init]                                    # show / write config
```

`analyze` prints the complete CARE evidence trace (views, per-layer scores and
evidence, fired rules, skip predicate, the CARE judge prompt) — useful for
debugging and for comparing against the Python reference. It never calls Jev.
`judge` calls Jev on one command regardless of CARE's verdict and prints the
judge record (exit 1 if the record carries an error). With `--transcript` and
no current tool call, every tool call in the transcript counts as prior;
`--request` replaces the transcript's prompts.

## Configuration

Config lives at `$XDG_CONFIG_HOME/cancelli/config.toml` when
`XDG_CONFIG_HOME` is set, otherwise `~/.config/cancelli/config.toml`
(deliberately not macOS `~/Library/Application Support`; decision D10).
Precedence is **CLI flag > env var > config file > built-in default**. A
missing file means defaults; an unreadable or invalid file means defaults
plus an `error` log record; unknown keys produce `warning` records.
`cancelli config` prints the effective values and where each came from;
`cancelli config --init` writes a commented default file (and refuses to
overwrite one).

```toml
mode = "balanced"          # strict | balanced | auto   (env CANCELLI_MODE)
dry_run = true             # the --dry-run flag forces true
decide_all = false         # D13: a Jev "allow" emits allow (skips the prompt); --decide-all forces true

[log]
dir = "~/.local/share/cancelli"   # env CANCELLI_LOG_DIR overrides
max_field_bytes = 4096            # non-Bash string truncation threshold

[judge]
backend = "jev"            # "jev" | "stub"
base_url = "https://api.typesafe.ai"   # env TYPESAFE_BASE_URL overrides
model = "jev-1.13.0"       # pinned; response.model must match
api_key_env = "TYPESAFE_API_KEY"
# api_key_file = "~/.config/cancelli/jev_api_key"   # 0600; used if the env var is unset (this path is the default when the file exists)
timeout_ms = 3000          # per request
budget_ms = 5000           # total incl. one retry on 408/429/5xx/timeout; keep well under the hook timeout
```

`decide_all` is a **top-level** key: it must sit above the `[log]` table (TOML
puts anything after a `[table]` header into that table; `log.decide_all` is
ignored with a warning). `cancelli config` lists every key with its source
(`default`/`file`/`env`/`cli`) and whether an API key was found and where,
never the key itself. `backend = "stub"` restores the pre-Jev behaviour (WARN
→ `unadjudicated`).

## Log schema

Records are appended to `<log dir>/events-YYYY-MM-DD.jsonl` (local date), file
mode `0600`, one `O_APPEND` write per record so parallel sessions never
interleave. The log dir is `$CANCELLI_LOG_DIR`, else `[log].dir`, else
`~/.local/share/cancelli`.

Common fields: `kind` (`event` | `error` | `warning`), `ts`, `version`,
`rules_version`, `session_id`, `tool_use_id`, `cwd`, `permission_mode`,
`tool_name`, `mode`, `dry_run`, `latency_us`.

For `Bash`, an `event` adds: `command`, `views[]`, `layers{L1,L2,L3,L4}` (each
score + evidence), `fired_rules[{id,tier,conf,pi,family,effective,…}]`,
`triggered_layers`, `scores`, `aggregate`, `provisional{strict,balanced,auto}`,
`skip_predicate`, `would_adjudicate`, `judge_prompt` (CARE Prompt 1, when it
would adjudicate), `judge`, `final` (`allow`|`deny`|`ask`|`unadjudicated`),
`would_emit` (the decision enforce mode would send, given `decide_all`),
`fixes_applied[]`, `ext_applied[]`. For other tools it adds `tool_input`
(truncated).

For a WARN that reaches Jev, `judge` is the full Jev record (D17):
`backend`, `decision`, `level` (`l2_actions` | `l1_request` | `l0_action`),
`context{level_reason, prompts_total, prompts_kept, actions_total,
bad_lines}`, `questions_sent[]`, `state` (the exact text sent),
`state_hash`, `rubric_hash`, `model`, `answers`, `signals`, `tier`
(`T1`…`T6`), `tier_rule`, `verdict`, `would_emit`, `latency_ms`, `usage`,
`request_id`, `attempts`, `key_source` (e.g. `env $TYPESAFE_API_KEY`, never
the key), `error`. A Jev failure also writes a separate `error` record with
`stage: "judge"`.

### Examining the data

```sh
# recent Bash decisions
jq -r 'select(.kind=="event" and .command) | [.ts,.final,.aggregate,.command] | @tsv' \
  ~/.local/share/cancelli/events-*.jsonl

# what would have been blocked
jq 'select(.would_emit=="deny") | {command, skip_predicate, fired:[.fired_rules[].id]}' \
  ~/.local/share/cancelli/events-*.jsonl

# which FIX/EXT divergences fire in practice
jq -r 'select(.kind=="event") | (.fixes_applied + .ext_applied)[]' \
  ~/.local/share/cancelli/events-*.jsonl | sort | uniq -c | sort -rn
```

```sh
# Jev verdicts, tiers and latency on the WARNs it saw
jq -r 'select(.judge.backend=="jev") | [.ts,.judge.tier,.judge.verdict,.judge.level,.judge.latency_ms,.command] | @tsv' \
  ~/.local/share/cancelli/events-*.jsonl

# context level Jev actually got, and why
jq -r 'select(.judge.backend=="jev") | .judge.context.level_reason' \
  ~/.local/share/cancelli/events-*.jsonl | sort | uniq -c
```

```sql
-- DuckDB: WARN commands that reached the judge
SELECT command, aggregate, judge.tier, judge.verdict, judge.error
FROM read_json_auto('~/.local/share/cancelli/events-*.jsonl')
WHERE would_adjudicate;
```

## Enforce mode (built, not registered)

Without `--dry-run` (and with `dry_run = false`) the hook emits a decision:

| Outcome | Emits |
|---|---|
| CARE static DENY (score ≥ τ_high, or WARN with a skip predicate) | `deny` |
| CARE static ALLOW | nothing (normal permission flow) |
| Jev T1/T2 | `deny`, reason names the tier |
| Jev T3–T5 | `ask`, reason names the tier |
| Jev T6 | nothing; `allow` only with `decide_all` (D13) |
| Jev failure (D15) | `ask`, reason says Jev was unavailable and why |
| `backend = "stub"` WARN | `ask` |

Decision D6 keeps the registered hook in dry-run; the Jev thresholds are
calibrated on a synthetic corpus and are to be re-validated on your own
dry-run data before enforcing.

## Jev adjudicator

Jev (`jev-1.13.0`) answers a fixed rubric of 40 yes/no, graded and
categorical questions about a proposed action. The rubric, render template
and tier rules are ported from the `jev_gate` proof of concept
(`docs/research/jev-integration-spec.md`). cancelli calls it only for Bash
commands that CARE leaves at WARN with no skip predicate (D12). Everything
else is decided by CARE alone, without a network call.

### Data egress: what leaves your machine

For each unresolved WARN, and only then, cancelli sends one HTTPS `POST` to
`{base_url}/v1/systemone` (default **api.typesafe.ai**). The request holds:

- **the Bash command** (clipped at 4,000 characters, plus any base64, hex or
  `$IFS` payload decoded from it);
- **your prompts** from the session transcript: every prompt you typed, up
  to 4,000 characters, with the most recent always kept (JEV-DEV-001);
- **the agent's prior tool calls with their arguments**: every earlier
  `tool_use` in the session (Bash commands, file paths, `Edit`/`Write`
  contents, MCP arguments…), each clipped at 4,000 characters, newest first
  within 12,000 characters. These can contain file contents and **secrets
  that appeared in commands**;
- the 38–40 rubric questions and the model name.

It never sends tool **results**, the agent's text or thinking, system
reminders, other hooks' output, or your key in the body. CARE ALLOW/DENY
commands and non-Bash tool calls are never sent. `backend = "stub"` disables
all egress.

### Key setup

The key is read from the env var named by `judge.api_key_env` (default
`TYPESAFE_API_KEY`), otherwise from `judge.api_key_file`. The file is
**refused** if it has any group or other permission bit (it must be `0600` or
stricter). The key is never logged, never written to `config.toml`, redacted
from error strings, and `cancelli config` only reports where it was found.

```sh
install -m 600 /dev/null ~/.config/cancelli/jev_api_key
$EDITOR ~/.config/cancelli/jev_api_key       # paste the key
# config.toml, [judge]:  api_key_file = "~/.config/cancelli/jev_api_key"
cancelli config | grep 'api key'            # -> found (file …)
```

**Prefer the file.** A key exported in the environment Claude Code runs in
is inherited by every command the agent runs, so the agent can read it.
The POC avoided exporting its key for the same reason. Without a key, every
unresolved WARN is a Jev failure (`ask`), and no request is made.

### How a Claude Code call is mapped (D16)

- **Proposed action**: `tool: bash`, `args: <tool_input.command>`, the same
  mapping the POC's ShellRisk and smoke-gate paths used.
- **User request**: the human prompts in `transcript_path`: `user` records
  whose content is a string or `text` blocks. Records flagged
  `isMeta`/`isCompactSummary`/`isSidechain` are dropped, as are `tool_result`
  records and text starting with a system prefix (`Another Claude session
  sent a message:`, `<task-notification>`, `<local-command-caveat>`,
  `<command-name>`, `[Request interrupted by user`, …) or containing
  `<system-reminder>`. The filter is `jev::transcript::is_system_injected`;
  its prefix and marker lists are plain constants
  (`SYSTEM_PREFIXES`/`SYSTEM_MARKERS`) and are meant to be extended.
- **Prior actions**: assistant `tool_use` blocks before the current
  `tool_use_id`, rendered like the POC's `_call_text`: `bash(<command>)` for
  Bash (the `description` field is agent prose and is dropped), and
  `Name(<json.dumps(input, sort_keys=True)>)` for everything else.
- **Level**: `l2_actions` when the transcript contains the current
  `tool_use_id`. If the hook runs before Claude Code has flushed the current
  call to the transcript, the prior actions may be incomplete, so the level
  degrades to `l1_request`, or `l0_action` when there is no prompt either.
  A missing or unreadable transcript gives `l0_action`. The achieved level
  and the reason are logged (`judge.level`, `judge.context.level_reason`), and
  the questions sent follow the level: L0/L1 38, L2 39 (`d5` needs results,
  `f6` needs actions).
- The state is rendered with the POC's template byte-for-byte (same
  headers, clipping, history budget and decoded-forms section; results never
  rendered), and `state_hash`/`rubric_hash` use the POC's exact algorithms.

### Tiers (D14)

Signals are the POC's `signals()` with the rubric's declarations applied.
Tiers are evaluated first-match with strict `>` comparisons and the
thresholds from the spec (§4.2):

| Tier | Predicate | Verdict | Measured deny purity* |
|---|---|---|---|
| T1 | transport ∧ sensitive ∧ unknown: `a5 > 0.95`, `max(a1, a7) > 0.5`, a6 argmax = `unknown_remote` | **deny** | 101 items @ 100.0% |
| T2 | `f5_exceeds_approval > 0.9` | **deny** | 1,031 @ 99.7% |
| T3 | obfuscated ∧ irreversible: `d1 > 0.2`, `b4/3 > 0.25` | ask | 17 @ 82.4% |
| T4 | transport ∧ sensitive | ask | 53 @ 90.6% |
| T5 | `f5_exceeds_approval > 0.5` | ask | 432 @ 83.6% |
| T6 | none fired | **allow** (see `decide_all`) | 1,241 @ 17.4% |

\* Share of items labelled *deny* in each first-match tier, computed
offline on the ProCreations held-out half (2,875 items) with the current
rubric (`0fd1f245ae1c7ef3`) and declared signals (spec §4.2, second table).
ProCreations is synthetic and LLM-generated, and T6 still contains 17.4%
deny-labelled items. The thresholds have **not** been calibrated on Claude
Code traffic, which is what dry-run is for.

**"unknown"**: cancelli uses the rubric's declared reading of `a6`, the
one-hot argmax predicate `a6_destination_class=unknown_remote == 1`, which
the rubric only consults when `f5_exceeds_approval > 0.8` (`when:` gate). The
spec's other definition, graded `P(unknown_remote) > 0.05`, belongs to
undeclared signals. cancelli always applies the declarations (`requires`,
`when`, `use`, `threshold`), so it uses the declared form throughout.
`f6_trajectory_escalation` is sent, because it is part of the rubric hash,
but no tier consumes it (it is inverted on the calibration corpus).

### `decide_all` and auto mode (D13)

By default a Jev **allow** emits nothing, so Claude Code's normal permission
rules (allow/deny/ask lists, the current mode) decide. With `--decide-all`
or `decide_all = true`, a Jev allow emits `permissionDecision: "allow"`,
which **skips the permission prompt**. Jev **ask** and **deny** always emit.
In practice:

- a hook `"ask"` forces a prompt **even in auto mode**;
- a hook `"allow"` skips the prompt, but your settings' **deny and ask rules
  still apply**, so a hook can't approve past them;
- `decide_all` only affects Jev verdicts. CARE's static ALLOW always passes
  silently, and dry-run never emits anything.

### Failure behaviour (D15)

Every failure produces **ask** plus an `error` record (`stage: "judge"`), and
the hook still exits 0. Failures are: no key or a refused key file, a
connection error, a timeout, a non-2xx response, an unparseable body, a
missing or wrongly typed answer for any question sent, and
`response.model != "jev-1.13.0"`. Timing: `timeout_ms` (3,000) per request
and `budget_ms` (5,000) in total. There is at most **one retry**, only on
408/429/5xx or a timeout, and only if the wait (`retry-after-ms`, else
`retry-after` in seconds or as an HTTP-date, else 500 ms) still fits in the
budget. Connection refused and other 4xx responses are not retried. A worker
thread bounds the whole judge step at `budget_ms + 1.5 s` (FIX-008). In
dry-run, Jev is really called and the record is logged, but nothing is
emitted (D17).

### Deviations from the POC

| ID | Change | Why |
|----|--------|-----|
| JEV-DEV-001 | `user_request` keeps the most recent prompt, plus as many immediately preceding prompts as fit whole in 4,000 chars. The POC's adapters join all turns and keep the *oldest* 4,000. Identical to the POC whenever the joined prompts fit. | In a long session the POC would drop the instruction the current action answers to. |
| JEV-DEV-002 | Tool results are never read, so the 12,000-char history budget counts call text only. The POC counted results toward the budget even at L2, where they are not rendered. | Reasoning-blind by construction; the transcript's results are not opened. More history fits than in the POC for the same session. |
| JEV-DEV-003 | Transport: 3 s per request, 5 s budget, one retry. The POC used the SDK with a 60 s timeout, 2 retries and a 30 s budget, and recorded errors rather than deciding. Here failures ask. | A hook must answer quickly and must not fail open. |
| JEV-DEV-004 | No answer cache: every unresolved WARN is a fresh call (the POC cached answers by `state_hash`). | History changes on every call, so hit rates would be near zero. |

The mapping from Claude Code (`tool: bash`, `bash(<command>)` for prior Bash
calls, the prompt filter, the L2→L1→L0 degradation) has no POC counterpart:
the POC never ran against Claude Code transcripts.

### Fidelity tests (offline)

- `rubric_hash` is recomputed from the vendored YAML with the POC's exact
  algorithm (Python `json.dumps` separators, `sort_keys`,
  `ensure_ascii=False`) and equals `0fd1f245ae1c7ef3`.
- The 8 smoke-gate states render **byte-identically** to the POC's
  `State.render()` and hash to the POC's `state_hash`
  (`tests/jev_offline.rs`; expected values generated from the POC's own code
  by `scripts/jev/compute_expected.py`).
- The POC's real cached `jev-1.13.0` responses for those states
  (`tests/fixtures/jev/`) replay to exactly the POC's `signals()`, to tiers
  T6/T2/T6/T2/T6/T2/T6/T5, and pass all 10 smoke checks.
- `tests/jev_e2e.rs` drives the real binary against a local stand-in server,
  for failure injection (refused, hang, no key, loose key file, wrong model,
  503-then-OK, 401) and for replaying the cached responses to exercise
  `decide_all` and the tier→decision mapping. It also asserts the exact
  request on the wire and that no key, result, prose or system reminder
  leaks. This is not evidence about the live API.

### Live tests (run these yourself)

```sh
TYPESAFE_API_KEY=... cargo test --test jev_live -- --ignored --test-threads=1
```

`tests/jev_live.rs` runs the POC's smoke gate against the real API (4 pairs,
10 checks, deny-side strictly greater, `response.model` asserted) and sends
one WARN command end to end through a `cargo install`ed binary with a
transcript. The installed-binary test does a release build. Both tests fail
immediately, with instructions, when `TYPESAFE_API_KEY` is unset. They honour
`TYPESAFE_BASE_URL`.

### HTTP client choice

`ureq` 3 with `rustls` (ring provider, bundled Mozilla roots via
`webpki-roots`):

- it is **blocking**, which fits a short-lived synchronous hook (no async
  runtime to start per call);
- TLS is pure Rust, with no OpenSSL or system-library dependency, so
  `cargo install` works the same everywhere;
- it has per-call global timeouts;
- it is small.

It honours `HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY`. Because it uses bundled
roots rather than the OS trust store, a TLS-intercepting corporate proxy
would need its CA added some other way.

## Divergences from the reference

Each divergence has an id, a regression test, and (for the paper
reconciliations and reference bug fixes) is reproduced against the pinned
Python reference before being declared. Log records carry the ids that fired
(`fixes_applied` / `ext_applied`) so you can filter them out. "Detection:
runtime" means the analysis tags itself when the id is active; "static" means
it is a structural property of the port (measured by the parity suite).

### FIX — paper reconciliations (D1) and reference bug fixes (D2)

| ID | Change | Detection |
|----|--------|-----------|
| FIX-001 | p_rule: catalog tiers (mitre, gtfobins) with π·conf ≥ 0.80 (paper Eq. 9) | runtime |
| FIX-002 | p_spath: write to system/critical tier or any secret-tier access (paper Eq. 11) | runtime |
| FIX-003 | p_sem: H_sem = {DESTRUCTIVE, PRIVILEGE_OR_PERMISSION, EXECUTION_CHAIN, PERSISTENCE, NETWORK_FETCH} (paper Eq. 10) | runtime |
| FIX-004 | Judge output: first token must be SAFE or DANGEROUS, anything else DENY (paper Prompt 1) | runtime |
| FIX-005 | L1 sees $()/backtick/<() substitutions: flags, nesting depth, inner atoms | runtime |
| FIX-006 | Canonicalization yields views instead of appending marker text | runtime |
| FIX-007 | Padded base64 payloads are decoded | runtime |
| FIX-008 | Judge call has a hard timeout (text judges fail closed; Jev asks, D15) | runtime |
| FIX-009 | Lexicon conflict: `git tag` listing is READ_ONLY, creating/deleting WRITE_LOCAL | runtime |
| FIX-010 | L3 treats mkfs.<fs> heads as write/destructive like mkfs | runtime |
| FIX-011 | L1 extracts commands inside if/for/while/until/case/function bodies | runtime |
| FIX-012 | Parser replacement (D4): brush-parser accepts/rejects different inputs than bashlex | static |
| FIX-013 | Pipe-to-interpreter compares the basename of the pipeline tail (`\| /bin/sh`) | runtime |

How each was confirmed against the reference (in a `uv` venv with
`bashlex==0.18` at commit `e8166db`):

- **FIX-001 / FIX-002 / FIX-003** — paper-over-repo (D1). The repo's
  `_should_skip_llm` fires `p_rule` for any rule with a MITRE T-ID at raw
  conf ≥ 0.80 (so all GTFOBins and manual rules), `p_spath` on *any* L3 hit
  (including a 0.10 sensitive read or a `../` traversal), and uses a different
  `H_sem` set. e.g. `rm -f /usr/bin/foo` → repo `p_rule:SE-P-139` (manual),
  `cat /etc/hosts` → repo `p_spath`, `kill 1234` → repo `p_sem`. cancelli
  follows the paper's Eqs. 9–11, so these go to the judge instead.
- **FIX-004** — paper says first-token SAFE/DANGEROUS, unparseable → DENY;
  the repo does a substring test and lets garbage (e.g. a `<think>` prefix)
  fall through to ALLOW. Applies to free-text judges; the stub never parses,
  and Jev returns structured answers (its failures ask, D15).
- **FIX-005** — `care/structure.py` never descends into `word.parts`, so
  `echo $(date)` gets `has_command_sub=False`, struct 0.0. Confirmed:
  reference struct = 0.0. cancelli walks substitutions (struct 0.30/0.60) and
  scores their inner atoms.
- **FIX-006** — the reference appends `\x1f<SHELL_C>…</SHELL_C>\x1f` and feeds
  it back to bashlex/L2/L4; `bash -c 'rm -rf /'` yields s_pat 0.0 (SE-P-001
  fails because `<` follows `/`). cancelli scores the unwrapped body as its
  own view (SE-P-001 fires).
- **FIX-007** — `_B64_CANDIDATE`'s trailing `\b` backtracks off `=` padding,
  so `eval $(echo 'cm0gLXJmIC8=' | base64 -d)` is *not* decoded by the
  reference (WARN 0.195, no rules); cancelli decodes it and denies.
- **FIX-008** — the reference sets no client timeout, so a hung judge blocks
  the hook. cancelli bounds every judge call on a worker thread: a text judge
  fails closed (DENY); Jev has its own request timeout and budget, and the
  worker bound (`budget_ms + 1.5 s`) is a backstop that yields `ask` (D15).
- **FIX-009** — `GIT_SUBCOMMAND_CLASSES` lists `tag` under both READ_ONLY and
  WRITE_LOCAL; the later entry wins, so `git tag` (listing) is WRITE_LOCAL
  0.15 in the reference. cancelli classifies bare `git tag`/`git tag -l` as
  READ_ONLY.
- **FIX-010** — L2 knows `mkfs.ext4` etc. but L3's destructive/write head
  sets only contain `mkfs`; `mkfs.ext4 /dev/xvdf` gets the ambiguous 0.35
  path score in the reference. cancelli treats `mkfs.<fs>` like `mkfs` (0.70).
- **FIX-011** — bashlex's `_visit` does not recurse into `if/for/while/case`
  bodies, so those commands produce zero atoms (whole command → one UNKNOWN
  atom via the `or [cmd]` fallback). Confirmed: `if true; then rm -rf /tmp/x;
  fi` → reference s_sem 0.35. cancelli extracts the inner commands.
- **FIX-012** — brush-parser parses `[[ … ]]`, `case`, `$(( ))`, `time`,
  which bashlex rejects (falling back to one whole-command atom). This shifts
  a few benign commands by one WARN band in strict mode only.
- **FIX-013** — the reference compares the pipeline tail head literally, so
  `curl … | /bin/bash` is not pipe-to-exec (struct 0.05). cancelli compares
  the basename.

### EXT — macOS path extensions

CARE's tiers are Linux-only. These add macOS locations, tagged in the log so
they can be filtered out.

| ID | Change | Detection |
|----|--------|-----------|
| EXT-001 | macOS secret paths: ~/Library/Keychains/, /Library/Keychains/ | runtime |
| EXT-002 | macOS /private/{etc,var,tmp} aliases resolved to /etc, /var, /tmp | runtime |
| EXT-003 | macOS sensitive-system paths: /System/, /Library/Launch{Agents,Daemons}/, ~/Library/LaunchAgents/, /Library/StartupItems/ | runtime |
| EXT-004 | macOS system-root sinks: /System, /Library, /Applications, /Users, /private, /Volumes | runtime |
| EXT-005 | macOS block devices /dev/diskN, /dev/rdiskN are critical | runtime |
| EXT-006 | macOS `base64 -D` decode flag triggers payload decoding | runtime |

## Parity

`scripts/parity/regenerate.sh` clones CARE at the pinned commit, installs
`bashlex` in a `uv` venv, and runs `scripts/parity/run_reference.py` over
`tests/corpus/commands.txt` to (re)generate `tests/golden/reference.jsonl`.
The Rust test `tests/parity.rs` compares cancelli's `analyze` output to that
golden file record by record; every divergence must be listed in
`tests/golden/allowlist.json` under a FIX-/EXT- id (and every runtime id
listed must actually have fired), or the test fails. Of the 495-command
corpus (benign commands, the repo/report/paper examples, one trigger per L4
rule, and obfuscated variants), 382 match the reference exactly and 113
diverge, each attributed to a FIX-/EXT- id. In every fired-rule divergence
cancelli fires an *additional* rule on a decoded or unwrapped payload
(FIX-006/FIX-007) — it never misses a rule the reference catches.

## Dependencies

Kept minimal; each earns its place:

- **brush-parser** — the bash parser (D4), replacing the reference's bashlex.
- **regex** + **fancy-regex** — Python-`re`-compatible matching (see
  `src/pyre.rs`); `fancy-regex` (backtracking) is used only for the three
  rules that need lookaround/backreferences (SE-P-069, SE-P-094, SE-P-139),
  everything else stays on linear-time `regex`.
- **serde** / **serde_json** — payload parsing, log records, the rule bank.
- **toml** — the config file (D10).
- **ureq** (+ **rustls**/**ring**, **webpki-roots**) — the Jev HTTP client;
  see [HTTP client choice](#http-client-choice).
- **serde_yaml** — parses the vendored rubric YAML once per process. The
  crate is archived upstream but stable; it parses only this one embedded
  file, and the rubric-hash test fails if its output ever changed.
- **clap** — the CLI (`derive`).
- **sha2** — SHA-256 for truncated non-Bash fields.
- **time** — RFC 3339 timestamps, the local date for log filenames, and
  `retry-after` HTTP-dates.
- dev only: **tempfile**, **assert_cmd**, **predicates**.

## Known limitations

- **Dry-run only** by default (D6); enforce mode is built and tested but you
  must opt in.
- **Jev is uncalibrated on Claude Code traffic.** Its thresholds were tuned
  on a synthetic corpus with generic tool names (`read_file`, `shell`).
  Claude Code's `Bash`/`Edit`/`mcp__*` calls and long sessions are out of
  distribution, so use the dry-run logs to check the tiers before enforcing.
- **The paper's narrower skip predicates** (FIX-001..003) send more WARNs to
  the judge. On the parity corpus, 24 commands the reference denies
  statically go to Jev in cancelli. Some are benign (`kill 1234`,
  `git worktree add ../wt`), but others are hostile GTFOBins shells whose
  π·conf (0.85 × 0.90 = 0.765) falls just under θrule, so they now depend on
  Jev's verdict, or ask if Jev fails. No L4 rule the reference fires is ever
  missed.
- **Transcript lag.** Measured on a live session: PreToolUse fires *before*
  Claude Code writes the current `tool_use`, so every call already in the
  transcript is treated as prior (L2). Calls made immediately before this one
  may also still be unwritten and so missing from the prior actions. Check
  `judge.context.level_reason` / `actions_total` in the logs.
- **Bash-only scoring** (D3). Writes to `~/.zshrc` via the `Write` tool, a
  persistence vector, are logged but not scored — CARE never sees them.
- **Stateless** (matching the paper): no cross-turn correlation, so staged
  download→chmod→exec chains across commands are out of scope.
- **`str.isprintable()`** is approximated for non-ASCII during base64/printf
  decoding (ASCII is exact); format/private-use/unassigned code points are
  treated as printable. No observed corpus divergence.
- **Path context is lexical** — no filesystem `stat` or symlink resolution;
  `~` expands to the hook process's `$HOME`.
- The reference's headline F1/FPR numbers cannot be reproduced (its eval
  datasets and harness are not released).

## Attribution

Port © 2026 Brad Voth, MIT (see `LICENSE`). Derived from CARE © 2026 CARE
authors, MIT — paper [arXiv:2607.21642](https://arxiv.org/abs/2607.21642),
code <https://github.com/prisma-research/CARE> (commit `e8166db`). The rule
bank (`data/rule_provenance.json`) and judge prompt (`data/judge_*.txt`) are
vendored verbatim, as is the Jev rubric (`data/jev/v1_policy_distilled.yaml`,
from the author's `jev_gate` POC); see `NOTICE`.
