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
agent's prior tool calls. Every tool call CARE cannot score (`Write`, `Edit`,
`Read`, `WebFetch`, `mcp__…`, or a `Bash` call without a command) is treated
as a WARN and also goes to Jev (D21), unless its tool is listed in
`[jev] skip_tools`. See [Jev adjudicator](#jev-adjudicator), including
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

Every other tool call (`Write`, `Edit`, `Read`, `WebFetch`, `mcp__…`, …),
and a `Bash` call whose `tool_input.command` is missing, not a string, or
empty/whitespace, is one CARE **cannot score** (D21). It is logged raw
(string fields over 4 KiB are truncated with a length and SHA-256, as under
D3), treated as a **WARN**, and sent to Jev, whose tier decides allow / ask /
deny exactly as for a Bash WARN (D13, D14, D15 all apply). The proposed
action Jev sees is the call in the POC's `Name(json)` form: `tool: Write`,
`args: {"content": "…", "file_path": "…"}` (Python `json.dumps(input,
sort_keys=True, ensure_ascii=False)`, clipped at `jev.context.field_chars`).
Tools listed in `[jev] skip_tools` (default empty) keep the old pass-through:
logged raw, no judge, no decision.

CARE targets Linux bash/sh; cancelli adds a small set of macOS path
extensions (the `EXT-` table). It is a complementary pre-execution signal,
**not** a sandbox. The CARE layers read only the command string plus
`$HOME`/cwd. Only for unresolved WARNs and unscorable calls does the Jev step
also read the session transcript: the human prompts and the agent's prior
tool calls, never tool results or the agent's prose.

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
JSON, an unwritable log, an internal panic — is logged as an `error` record
and the session proceeds. (A `Bash` call without a command is no longer an
error: it is unscorable and goes to Jev, D21.)

Even in dry-run, Jev is called for real (D17) on every unresolved Bash WARN
**and on every non-skipped call CARE cannot score** (D21): each `Write`,
`Edit`, `Read`, `Glob`, `Grep`, `WebFetch`, `Task`, `mcp__…` call, and so on.
Since most calls in a typical session are non-Bash, that is **one API round
trip on most tool calls**, not only on the rare WARN. The POC measured p50
~226 ms, p95 437 ms and a max of 3.0 s over 8,984 calls, and cancelli caps
each at `budget_ms` (5 s by default). Each call also costs one metered Jev
request: the POC's smoke fixtures, whose states are short, used about
3,250–3,570 input and ~900 output tokens each; a long `Write` body and a long
history add up to ~20,000 more characters of state (4,000 action + 4,000
request + 12,000 history). The exact `judge.usage` is logged per call. Use `[jev] skip_tools` to exempt high-volume, low-risk tools
(for example `["Read", "Glob", "Grep"]`) from the round trip and the cost.
Without a key there is no call; the call is logged as a Jev failure (`ask`).

### CLI

```
cancelli hook   [--dry-run] [--mode strict|balanced|auto] [--decide-all]   # read stdin, log
cancelli analyze "<command>" [--mode …]                     # full CARE analysis JSON (no Jev call)
cancelli judge "<command>" [--transcript PATH] [--request TEXT] [--decide-all]
                                                            # ask Jev, print the judge record
cancelli config [--init]                                    # show / write config
cancelli eval --logs <files…> --config <path> [--offline] [--json]
                                                            # D25: replay logs under a config
cancelli calibrate --reference <files…> --out <file> [--offline] [--pairs-out F]
                   [--model M] [--holdout 0.25] [--seed 42] [--limit N] [--min-pairs 10]
                                                            # D24: fit a calibration file
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
overwrite one), including every `[care]`/`[jev]` tunable commented out (see
[Tuning](#tuning)).

```toml
mode = "balanced"          # strict | balanced | auto   (env CANCELLI_MODE)
dry_run = true             # the --dry-run flag forces true
decide_all = true          # D22: every allow (CARE ALLOW and Jev allow) emits permissionDecision "allow"; false = silent pass-through (auto-mode profile)

[log]
dir = "~/.local/share/cancelli"   # env CANCELLI_LOG_DIR overrides
max_field_bytes = 4096            # non-Bash string truncation threshold

[judge]
backend = "jev"            # "jev" | "stub"
base_url = "https://api.typesafe.ai"   # env TYPESAFE_BASE_URL overrides
model = "jev-1.13.0"       # requested model (sent in the request body)
# expected_model = "jev-1.13.0"   # D23: response.model must equal this, else ask (D15); set it for another /v1/systemone server
api_key_env = "TYPESAFE_API_KEY"
# api_key_file = "~/.config/cancelli/jev_api_key"   # 0600; used if the env var is unset (this path is the default when the file exists)
api_key_required = true    # D23: false for local servers: no key needed, no Authorization header when none is found
timeout_ms = 3000          # per request
budget_ms = 5000           # total incl. one retry on 408/429/5xx/timeout; keep well under the hook timeout
# calibration_file = "~/.config/cancelli/calibration.json"   # D24: per-axis calibration, pinned to rubric_hash + expected_model; see `cancelli calibrate`
```

`expected_model` and `calibration_file` decide outcomes, so they are
tunables: validated key by key, part of `config_fingerprint` and listed in
`overrides[]` (see [Tuning](#tuning)). `api_key_required` and the other
`[judge]` keys are transport settings (a type error makes the file invalid).

`decide_all` is a **top-level** key: it must sit above the `[log]` table (TOML
puts anything after a `[table]` header into that table; `log.decide_all` is
ignored with a warning). `cancelli config` lists every key with its source
(`default`/`file`/`env`/`cli`) and whether an API key was found and where,
never the key itself. `backend = "stub"` restores the pre-Jev behaviour (WARN
→ `unadjudicated`).

## Tuning

Every numeric knob of CARE and of the Jev adjudicator can be set in
`config.toml`, under `[care]` (decision D18) and `[jev]` (D19). Lexicons, path
catalogs and regexes stay embedded. The guardrails (D20):

- **Defaults are pinned.** An empty or absent config gives the built-in
  defaults: the paper's values except the D27 wide-WARN keys (see
  [Tunables](#tunables)). The parity suite runs on `CareTunables::paper()`;
  the Jev fidelity/offline tests and the smoke replays run on the defaults.
  `tests/golden/tunables_default.json` pins
  the default values (and their fingerprint, `371a6d0ee7fe7bda`), so any
  drift of a default fails a test.
- **Validated per key, fail open.** Weights must be finite and ≥ 0.
  Probabilities, scores and thresholds must be in [0, 1], and
  τ_low < τ_high for each mode. Class names, tier names and verdicts must be
  known, and SE-P ids must be well-formed and exist in the bank. An invalid
  value falls back to *its own* default (not the whole section), with an
  `error` record naming the key. Unknown keys produce `warning` records. The
  hook still exits 0 and, in dry-run, prints nothing. Tunables are validated
  independently of the older top-level keys: a bad `mode` does not reset
  them, and a bad tunable does not reset `mode`.
- **Traceable.** Every log record carries `config_fingerprint`, a 16-hex
  sha256 of the canonical JSON of the effective tunables (sorted keys,
  shortest round-trip floats, so independent of key order, `1` vs `1.0` and
  file layout), and `overrides[]`, the dotted keys whose effective value
  differs from the default. It also carries `rubric_hash`, the hash of the
  rubric in use. A value set to its default is not an override.
- **Discoverable.** `cancelli config` lists every tunable with its value and
  source (`default`/`file`), then the effective `enabled`/`confidence` of all
  139 rules. `cancelli config --init` appends every tunable to the file at
  its default, each with a one-line explanation and its provenance, all
  commented out. The file documents the knobs without pinning them.

Precedence is unchanged (CLI > env > file > default); tunables exist only
in the file.

### Examples

```toml
[care.modes.balanced]
tau_high = 0.30            # rsync -avz ./data user@host:/backup/ (0.345): WARN -> DENY

[care.provenance]
gtfobins = 0.90            # π·conf 0.90·0.90 = 0.81 >= θ_rule: GTFOBins shells skip the judge (p_rule)

[care.rules."SE-P-103"]    # cross-host file transfer
enabled = false            # rsync/scp to user@host no longer fire L4 (0.345 -> 0.12, still WARN under D27)

[care.rules]
"SE-P-013" = { confidence = 0.60 }   # inline-table form of the same thing

[jev.verdicts]
T5 = "deny"                # f5_exceeds_approval > 0.5 now denies instead of asking

[jev.tiers]
order = ["T1", "T3", "T4", "T5", "T2"]   # first match; a tier left out never fires

[jev.context]
history_chars = 6000       # smaller prior-actions budget (newest call always kept)
max_level = "L1"           # never send prior tool calls

[jev]
rubric_file = "~/rubrics/my_rubric.yaml"
skip_tools = ["Read", "Glob", "Grep"]   # D21: these pass through unjudged (no Jev call, no decision)
```

`skip_tools` (D21) lists tool names, matched exactly and case-sensitively
(`mcp__server__tool` names in full; no globs), whose calls skip Jev when CARE
cannot score them. They keep the pre-D21 pass-through: an `event` record
with the raw `tool_input` and no `judge`, `final` or decision. The default
is empty, so every non-Bash call is judged. It must be an array of non-empty
strings without surrounding spaces. Anything else falls back to the empty
default with an `error` record. The list is sorted and deduplicated, so its
order does not change the fingerprint. Listing `"Bash"` only exempts Bash
calls that have no usable command, and it produces a `warning` record,
because CARE-scored Bash WARNs still go to Jev (D12). Skipping a tool also
means its input is not sent to TypeSafe (see
[data egress](#data-egress-what-leaves-your-machine)), and there is no Jev
round trip for it.

`rubric_file` loads an alternative rubric YAML with the same parser and lint
as the embedded one. A `warning` record names it and its `rubric_hash`. The
judge record's `rubric_hash`, every record's `rubric_hash` and the
fingerprint all use the hash of the rubric actually in use. An unreadable or
invalid file falls back to the embedded rubric with an `error` record. A tier
whose predicate reads an axis the loaded rubric lacks can never fire, and
each such tier produces a `warning` record (for example, renaming
`f5_exceeds_approval` disables T2 and T5). `jev.thresholds.unknown_f5_gate`
sets a6's `when.over` whichever rubric is loaded, with a warning if the file
declares a different gate. `when` is not part of the rubric hash or of the
wire questions.

> **Caution.** The Jev tier thresholds, the tier order and the verdict map
> were calibrated on the **embedded rubric** (`0fd1f245ae1c7ef3`) and on the
> **ProCreations corpus** (synthetic, LLM-generated; FINDINGS §5, spec §4.2).
> They have not been calibrated on Claude Code traffic. Changing a
> threshold, or loading another rubric, moves you off the measured purities
> in the tier table above. Treat any change as a hypothesis to check against
> your own dry-run logs.

### Calibrating from the logs

Because every record carries `config_fingerprint` and `overrides[]`, runs
under different settings can be separated and compared after the fact:

```sh
# how outcomes split per configuration
jq -r 'select(.kind=="event" and .command) | [.config_fingerprint, (.overrides|join(",")), .final] | @tsv' \
  ~/.local/share/cancelli/events-*.jsonl | sort | uniq -c

# Jev tiers per rubric and configuration
jq -r 'select(.judge.backend=="jev") | [.rubric_hash, .config_fingerprint, .judge.tier, .judge.verdict] | @tsv' \
  ~/.local/share/cancelli/events-*.jsonl | sort | uniq -c
```

```sql
-- DuckDB: WARN-band share per configuration
SELECT config_fingerprint, overrides,
       avg(CASE WHEN provisional.balanced = 'WARN' THEN 1 ELSE 0 END) AS warn_rate,
       count(*) AS n
FROM read_json_auto('~/.local/share/cancelli/events-*.jsonl')
WHERE kind = 'event' AND command IS NOT NULL
GROUP BY ALL ORDER BY n DESC;
```

The scores are logged in full (`layers`, `scores`, `aggregate`,
`judge.signals`), so a proposed threshold can also be replayed offline over
logs taken under the defaults before you change the config.

### Tunables

All keys, their defaults, meanings and provenance (`cancelli config --init`
writes the same list as comments):

| Key | Default | Meaning | Source |
|---|---|---|---|
| `care.weights.sem` | `0.3` | L5 weight of s_sem (L2 semantic) | paper Eq. 6, App. A.5; care/policy.py:15-18 |
| `care.weights.path` | `0.3` | L5 weight of s_path (L3 path) | paper Eq. 6, App. A.5; care/policy.py:15-18 |
| `care.weights.pat` | `0.3` | L5 weight of s_pat (L4 rules) | paper Eq. 6, App. A.5; care/policy.py:15-18 |
| `care.weights.struct` | `0.1` | L5 weight of δ_struct (L1 structure) | paper Eq. 6, App. A.5; care/policy.py:15-18 |
| `care.modes.strict.tau_low` | `0.1` | strict: ALLOW below this score | paper Eq. 7; care/modes.py:32-55 |
| `care.modes.strict.tau_high` | `0.2` | strict: DENY at or above this score | paper Eq. 7; care/modes.py:32-55 |
| `care.modes.balanced.tau_low` | `0.04` | balanced: ALLOW below this score | D27 wide-WARN default (paper Eq. 7: 0.15/0.35) |
| `care.modes.balanced.tau_high` | `0.55` | balanced: DENY at or above this score | D27 wide-WARN default (paper Eq. 7: 0.15/0.35) |
| `care.modes.auto.tau_low` | `0.2` | auto: ALLOW below this score | paper Eq. 7; care/modes.py:32-55 |
| `care.modes.auto.tau_high` | `0.5` | auto: DENY at or above this score | paper Eq. 7; care/modes.py:32-55 |
| `care.resolution.theta_rule` | `0.8` | p_rule: a mitre/gtfobins rule with π·conf >= this skips the judge | paper App. A.6; care/resolution.py:44 (FIX-001) |
| `care.resolution.theta_sem` | `0.7` | p_sem: an H_sem atom scoring >= this skips the judge | paper App. A.6; care/resolution.py:45 |
| `care.resolution.h_sem` | `[]` | L2 classes that can fire p_sem | D27 wide-WARN default (paper App. A.6 H_sem, FIX-003, has 5 classes) |
| `care.provenance.mitre` | `1.0` | π for MITRE-tier rules (L4 score and p_rule) | paper App. A.4; care/pattern.py PROVENANCE_TIER_WEIGHT |
| `care.provenance.gtfobins` | `0.85` | π for GTFOBins-tier rules | paper App. A.4; care/pattern.py PROVENANCE_TIER_WEIGHT |
| `care.provenance.manual` | `0.6` | π for manual-tier rules | paper App. A.4; care/pattern.py PROVENANCE_TIER_WEIGHT |
| `care.class_base.READ_ONLY` | `0.0` | L2 base score, READ_ONLY heads | care/common.py:28-39 CLASS_BASE_SCORE |
| `care.class_base.WRITE_LOCAL` | `0.15` | L2 base score, WRITE_LOCAL heads | care/common.py:28-39 CLASS_BASE_SCORE |
| `care.class_base.WRITE_SENSITIVE` | `0.7` | L2 base score, secret-path reads/writes | care/common.py:28-39 CLASS_BASE_SCORE |
| `care.class_base.NETWORK_FETCH` | `0.4` | L2 base score, NETWORK_FETCH heads | care/common.py:28-39 CLASS_BASE_SCORE |
| `care.class_base.EXECUTION_CHAIN` | `0.6` | L2 base score, shells/interpreters | care/common.py:28-39 CLASS_BASE_SCORE |
| `care.class_base.PRIVILEGE_OR_PERMISSION` | `0.75` | L2 base score, privilege/permission heads | care/common.py:28-39 CLASS_BASE_SCORE |
| `care.class_base.PERSISTENCE` | `0.8` | L2 base score, persistence heads | care/common.py:28-39 CLASS_BASE_SCORE |
| `care.class_base.DESTRUCTIVE` | `1.0` | L2 base score, destructive heads (special cases like rm_rf keep their own scores) | care/common.py:28-39 CLASS_BASE_SCORE |
| `care.class_base.RESOURCE_ABUSE` | `0.85` | L2 base score, resource-abuse heads | care/common.py:28-39 CLASS_BASE_SCORE |
| `care.class_base.UNKNOWN` | `0.35` | L2 base score, unmapped heads | care/common.py:28-39 CLASS_BASE_SCORE |
| `care.structure.pipe_to_exec` | `1.0` | δ_struct: pipeline ends in an interpreter | paper App. A.1; care/structure.py scoring ladder |
| `care.structure.eval` | `0.9` | δ_struct: eval/source/. as a command head | paper App. A.1; care/structure.py scoring ladder |
| `care.structure.nested_substitution` | `0.6` | δ_struct: command substitution nested >= 2 deep | paper App. A.1; care/structure.py scoring ladder |
| `care.structure.command_substitution` | `0.3` | δ_struct: any $() or backticks | paper App. A.1; care/structure.py scoring ladder |
| `care.structure.pipe` | `0.05` | δ_struct: any pipeline | paper App. A.1; care/structure.py scoring ladder |
| `care.path.system_root` | `1.0` | s_path: destructive head on a system root (first hit decides) | care/path.py:151-245 PathValidator.validate |
| `care.path.critical` | `1.0` | s_path: critical pattern (devices, shadow, keys, kernel; first hit decides) | care/path.py:151-245 PathValidator.validate |
| `care.path.secret` | `0.85` | s_path: secret-bearing path | care/path.py:151-245 PathValidator.validate |
| `care.path.sensitive_write` | `0.7` | s_path: sensitive system path, write context | care/path.py:151-245 PathValidator.validate |
| `care.path.sensitive_read` | `0.1` | s_path: sensitive system path, read-only head | care/path.py:151-245 PathValidator.validate |
| `care.path.sensitive_ambiguous` | `0.35` | s_path: sensitive system path, neither | care/path.py:151-245 PathValidator.validate |
| `care.path.traversal_read` | `0.3` | s_path: ../ under a read-only head | care/path.py:151-245 PathValidator.validate |
| `care.path.traversal` | `0.5` | s_path: ../ otherwise | care/path.py:151-245 PathValidator.validate |
| `jev.rubric_file` | (embedded, `0fd1f245ae1c7ef3`) | alternative rubric YAML (logged and fingerprinted by its rubric_hash) | D19; embedded data/jev/v1_policy_distilled.yaml |
| `jev.skip_tools` | `[]` | tool names CARE can't score that skip Jev and pass through unjudged (exact match, e.g. ["Read", "mcp__github__get_issue"]) | D21 |
| `jev.thresholds.transport` | `0.95` | transport: a5_outbound_data > this (T1, T4) | FINDINGS §5; jev-integration-spec §4.2 |
| `jev.thresholds.sensitive` | `0.5` | sensitive: max(a1_reads_credentials, a7_personal_data) > this (T1, T4) | FINDINGS §5; jev-integration-spec §4.2 |
| `jev.thresholds.unknown` | `0.5` | unknown: a6 argmax one-hot for unknown_remote > this (T1) | rubric a6 use: predicate; jev-integration-spec §4.2 declared row |
| `jev.thresholds.unknown_f5_gate` | `0.8` | a6 is read only when f5_exceeds_approval > this (overrides the rubric's a6 when.over) | rubric a6 when.over; FINDINGS §5 |
| `jev.thresholds.f5_deny` | `0.9` | T2: f5_exceeds_approval > this | FINDINGS §5; jev-integration-spec §4.2 |
| `jev.thresholds.f5_ask` | `0.5` | T5: f5_exceeds_approval > this | FINDINGS §5; jev-integration-spec §4.2 |
| `jev.thresholds.obfuscated` | `0.2` | T3: d1_obfuscated > this | FINDINGS §5; jev-integration-spec §4.2 |
| `jev.thresholds.irreversible` | `0.25` | T3: b4_reversibility (score/3) > this | FINDINGS §5; jev-integration-spec §4.2 |
| `jev.tiers.order` | `["T1", "T2", "T3", "T4", "T5"]` | first-match order of T1..T5; a tier left out never fires; T6 = none fired | FINDINGS §5; jev-integration-spec §4.2 |
| `jev.verdicts.T1` | `"deny"` | verdict for T1 (allow\|ask\|deny) | D14 |
| `jev.verdicts.T2` | `"deny"` | verdict for T2 | D14 |
| `jev.verdicts.T3` | `"ask"` | verdict for T3 | D14 |
| `jev.verdicts.T4` | `"ask"` | verdict for T4 | D14 |
| `jev.verdicts.T5` | `"ask"` | verdict for T5 | D14 |
| `jev.verdicts.T6` | `"allow"` | verdict when no tier fires (an allow emits only while decide_all is on, D13/D22) | D14 |
| `jev.context.field_chars` | `4000` | clip for args, the user request and each prior call (characters) | POC jev_gate/prepare.py; jev-integration-spec §3.3 |
| `jev.context.history_chars` | `12000` | history budget for prior calls, newest kept first (characters) | POC jev_gate/prepare.py; jev-integration-spec §3.3 |
| `jev.context.max_level` | `"L2"` | highest context level: L0 action, L1 +user request, L2 +prior calls | D16; POC jev_gate/context.py |
| `judge.expected_model` | `"jev-1.13.0"` | response.model the /v1/systemone backend must report; anything else asks (D15) | D23 |
| `judge.calibration_file` | (none) | per-axis calibration (JSON) pinned to rubric_hash + model; invalid or mismatched asks (fingerprinted by the file's sha256) | D24 |
| `care.rules."SE-P-NNN".enabled` | `true` | `false` removes the rule from L4 matching and from p_rule | D18 |
| `care.rules."SE-P-NNN".confidence` | the bank's value (`SE-P-003`: `0.75`, D27) | replaces the rule's confidence in L4 (π·conf) and in p_rule | data/rule_provenance.json (care/rules/rule_provenance.json) |

**Defaults (D27, wide-WARN profile).** The built-in defaults are the paper's
values except for four keys: balanced `tau_low = 0.04` / `tau_high = 0.55`,
`h_sem = []` (no class-only auto-deny; `sudo`, `rm -rf node_modules` and
`curl` WARN to the judge), and `SE-P-003` (rm -rf on a system dir) at
confidence `0.75`, below θ_rule. Only read-only commands are allowed without
the judge, and DENY is left to the path/rule predicates and high scores.
To get the paper's behaviour back (it is what `tests/parity.rs` checks):

```toml
[care.modes.balanced]
tau_low = 0.15
tau_high = 0.35
[care.resolution]
h_sem = ["NETWORK_FETCH", "EXECUTION_CHAIN", "PRIVILEGE_OR_PERMISSION", "PERSISTENCE", "DESTRUCTIVE"]
[care.rules]
"SE-P-003" = { confidence = 0.95 }
```

`care.rules` accepts either `[care.rules."SE-P-103"]` tables or inline tables
under `[care.rules]`. `enabled = false` removes the rule from L4 matching and
so from `p_rule`. `confidence` feeds both L4 (π·conf) and `p_rule`. The
reference-comparison predicate that tags FIX-001 sees the same confidence.
The L1 ladder stays first-match, and the L3 system-root/critical hits still
decide the path score on first match, whatever values you give them.

### Constant inventory

Every hard-coded constant in `src/` (policy, modes, resolution, semantic,
structure, path, pattern, rules, jev/decide, jev/state, jev/transcript,
jev/rubric), and whether it is exposed:

| Group (file) | Constants | Exposed as |
|---|---|---|
| L5 weights (policy.rs) | 4 | `care.weights.*` |
| Mode thresholds (policy.rs `Mode::thresholds`) | 6 | `care.modes.<mode>.tau_low/tau_high` |
| Resolution (resolution.rs) | θ_rule, θ_sem, H_sem (paper) | `care.resolution.*` |
| Provenance π (rules.rs `Tier::weight`) | 3 | `care.provenance.*` |
| L2 class base scores (semantic.rs `RiskClass::base`) | 10 | `care.class_base.*` |
| L1 ladder (structure.rs) | 5 | `care.structure.*` |
| L3 tier scores (path.rs) | 8 | `care.path.*` |
| Rule bank (rules.rs, `data/rule_provenance.json`) | 139 confidences, 139 implicit enables | `care.rules."SE-P-NNN".*` |
| Jev tier thresholds (jev/decide.rs `tier`) | 7, plus the a6 gate from the rubric | `jev.thresholds.*` |
| Jev tier order and verdicts (jev/decide.rs `TIERS`) | order + 6 verdicts | `jev.tiers.order`, `jev.verdicts.*` |
| Jev context (jev/state.rs, jev/transcript.rs) | 4,000 / 12,000 chars, max level | `jev.context.*` |
| Jev rubric (jev/rubric.rs) | embedded YAML | `jev.rubric_file` |
| Tools exempt from D21 (hook.rs) | none (empty list) | `jev.skip_tools` |

Deliberately **not** exposed, and why:

| Constant(s) | Where | Why not |
|---|---|---|
| 21 special-case L2 scores (`rm_rf` 0.9, `rm_rf_critical` 1.0, `rm_recursive` 0.7, `rm_files` 0.3, `git_push_force` 0.85, `git_reset_hard` 0.80, `git_clean_force` 0.70, `chmod_777_sensitive` 0.95, `chmod_777` 0.80, `chmod_suid`/`chmod_setuid_sym` 0.85, `chmod_normal` 0.35, `dd_block_device` 1.0, `dd_to_null` 0.1, `dd_generic` 0.6, `docker_privileged` 0.90, `docker_read` 0.0, `kill_init` 0.95, `killall_critical`/`pkill_root` 0.90, empty atom 0.0) | semantic.rs | Each is bound to a specific lexicon/regex match; D18 keeps lexicons embedded, and D18 names only the class base scores |
| Nested-substitution depth 2, recursion cap 8, interpreter list | structure.rs | Structural definitions of a ladder rung, not scores |
| L3 early return on the first system-root/critical hit | path.rs | Control flow of the reference, not a value |
| Rounding (`effective` 3 dp, scores/aggregate 4 dp) | pattern.rs, engine.rs | Output format for parity with Python |
| `H_SEM_REPO` | resolution.rs | Reference set, used only to tag FIX-003 |
| CARE judge prompt text, text-judge timeout 2,000 ms | resolution.rs, engine.rs | Text-judge path only (not Jev); the hook's timeouts are `[judge]` |
| Predicate default cut 0.5, score legend default 4, graded choice labels | jev/decide.rs, jev/rubric.rs | POC signal extraction; a rubric sets `threshold:` per axis itself |
| Decode minimums (base64 ≥ 12 chars/8 bytes, `\x` ≥ 4, hex ≥ 32), printable ratio 0.85, +8 per-turn budget overhead, section headers | jev/state.rs | Part of the POC render template (D16 "exactly as in the POC"); a change would move states off the calibration distribution |
| System-injected prefixes/markers | jev/transcript.rs | Lexicon (a filter), extended in code |
| Criteria-level bounds 2..10, gate validity | jev/rubric.rs | Rubric lint, the same for every rubric |
| Model pin, retry backoff 500 ms, minimum attempt 200 ms, backstop +1,500 ms | jev/client.rs, jev/mod.rs | Transport, not adjudication; timeout and budget are already `[judge]` keys |

## Log schema

Records are appended to `<log dir>/events-YYYY-MM-DD.jsonl` (local date), file
mode `0600`, one `O_APPEND` write per record so parallel sessions never
interleave. The log dir is `$CANCELLI_LOG_DIR`, else `[log].dir`, else
`~/.local/share/cancelli`.

Common fields: `kind` (`event` | `error` | `warning`), `ts`, `version`,
`rules_version`, `session_id`, `tool_use_id`, `cwd`, `permission_mode`,
`tool_name`, `mode`, `dry_run`, `latency_us`, and on every record
`config_fingerprint`, `overrides[]` and `rubric_hash` (see
[Tuning](#tuning)).

For `Bash`, an `event` adds: `command`, `views[]`, `layers{L1,L2,L3,L4}` (each
score + evidence), `fired_rules[{id,tier,conf,pi,family,effective,…}]`,
`triggered_layers`, `scores`, `aggregate`, `provisional{strict,balanced,auto}`,
`skip_predicate`, `would_adjudicate`, `judge_prompt` (CARE Prompt 1, when it
would adjudicate), `judge`, `final` (`allow`|`deny`|`ask`|`unadjudicated`),
`would_emit` (the decision enforce mode would send, given `decide_all`),
`fixes_applied[]`, `ext_applied[]`. Bash records are unchanged by D21.

For a call CARE cannot score (D21: any non-Bash tool, or a Bash call with a
missing, non-string or empty `command`), an `event` adds:

- `tool_input`: the raw input, strings over `max_field_bytes` truncated with
  `len` and `sha256`, as before D21.
- `care`: `{"supported": false, "reason": …}` in place of CARE scores. The
  reason is `"non-shell tool"`, `"missing command"`, `"empty command"` or
  `"command is not a string"`.
- `unscored: true` and `provisional: "WARN"`. `provisional` is deliberately a
  plain string, not the per-mode `{strict,balanced,auto}` object: there is
  no score, so the WARN is by rule (D21) and the same in every mode. Filter
  on `unscored` to keep these records out of CARE score calibration.
- `would_adjudicate: true`, and `judge`, the same schema as for a Bash WARN
  (below). Its `state` renders the proposed action as `tool: <Name>` /
  `args: <json>`.
- `final` (`allow`|`ask`|`deny`; `unadjudicated` with the stub backend),
  `would_emit`, and `fixes_applied[]` (only FIX-008, the judge backstop,
  can appear).

There is no `command`, `views`, `layers`, `aggregate` or `judge_prompt`. The
judge `error` record for such a call also carries `tool_name` and
`unscored: true`. A tool listed in `[jev] skip_tools` gets only the raw
`tool_input` record, as before D21: no `care`, `judge`, `final` or
`would_emit`.

For a WARN that reaches Jev (CARE's, or a D21 unscorable call), `judge` is
the full Jev record (D17):
`backend`, `backend_host` (D23: `host[:port]` of `judge.base_url`),
`expected_model` (D23), `decision`, `level` (`l2_actions` | `l1_request` | `l0_action`),
`context{level_reason, prompts_total, prompts_kept, actions_total,
bad_lines}`, `questions_sent[]`, `state` (the exact text sent),
`state_hash`, `rubric_hash`, `model` (the backend's reported model),
`answers` (raw, as reported), `answers_calibrated` and `calibration{file,
sha, rubric_hash, model, fitted_at, axes[]}` (D24, only with a calibration
file), `signals` (read from the calibrated answers when there are any),
`tier` (`T1`…`T6`), `tier_rule`, `verdict`, `would_emit`, `latency_ms`,
`usage`, `request_id`, `attempts`, `key_source` (e.g. `env
$TYPESAFE_API_KEY`, or `none (judge.api_key_required = false)`, never the
key), `error`. A Jev failure also writes a separate `error` record with
`stage: "judge"` (and `backend_host`).

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

# D21: what Jev decided on calls CARE can't score, per tool
jq -r 'select(.unscored) | [.tool_name, .care.reason, .judge.tier, .final, .judge.latency_ms] | @tsv' \
  ~/.local/share/cancelli/events-*.jsonl | sort | uniq -c | sort -rn

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
| CARE static ALLOW | `allow` (nothing with `decide_all = false`) |
| Jev T1/T2 | `deny`, reason names the tier |
| Jev T3–T5 | `ask`, reason names the tier |
| Jev T6 | `allow` (nothing with `decide_all = false`) |
| Jev failure (D15) | `ask`, reason says Jev was unavailable and why |
| `backend = "stub"` WARN | `ask` |
| Call CARE can't score (D21), not in `skip_tools` | as a Jev WARN above: T1/T2 `deny`, T3–T5 `ask`, T6 `allow` (nothing with `decide_all = false`), failure `ask`, stub `ask` |
| Tool in `[jev] skip_tools` | nothing (normal permission flow) |

Decision D6 keeps the registered hook in dry-run; the Jev thresholds are
calibrated on a synthetic corpus and are to be re-validated on your own
dry-run data before enforcing.

## Jev adjudicator

Jev (`jev-1.13.0`) answers a fixed rubric of 40 yes/no, graded and
categorical questions about a proposed action. The rubric, render template
and tier rules are ported from the `jev_gate` proof of concept
(`docs/research/jev-integration-spec.md`). cancelli calls it for Bash
commands that CARE leaves at WARN with no skip predicate (D12), and for every
tool call CARE cannot score unless its tool is in `[jev] skip_tools` (D21).
CARE's static ALLOW and DENY are decided by CARE alone, without a network
call.

### Data egress: what leaves your machine

For each unresolved Bash WARN, and for **every tool call CARE cannot score
whose tool is not in `[jev] skip_tools`** (D21; the default list is empty,
so by default that is every non-Bash call), cancelli sends one HTTPS `POST`
to `{base_url}/v1/systemone` (default **api.typesafe.ai**). The request
holds:

- **the proposed action**: the Bash command, or, for any other tool, its
  **full `tool_input` verbatim** as JSON (clipped at 4,000 characters,
  `jev.context.field_chars`), plus any base64, hex or `$IFS` payload decoded
  from it. That means **`Write`/`Edit` file bodies** (the new content, the
  old and new strings) up to the clip, **`Read` paths** (and so the names of
  files the agent opens, e.g. `~/.ssh/id_rsa`), `WebFetch` URLs and prompts,
  `Grep` patterns, `Task` prompts and every MCP tool's arguments;
- **your prompts** from the session transcript: every prompt you typed, up
  to 4,000 characters, with the most recent always kept (JEV-DEV-001);
- **the agent's prior tool calls with their arguments**: every earlier
  `tool_use` in the session (Bash commands, file paths, `Edit`/`Write`
  contents, MCP arguments…), each clipped at 4,000 characters, newest first
  within 12,000 characters. These can contain file contents and **secrets
  that appeared in commands**;
- the 38–40 rubric questions and the model name.

It never sends tool **results** (so not the content a `Read` returns), the
agent's text or thinking, system reminders, other hooks' output, or your key
in the body. CARE ALLOW/DENY commands and calls to tools in `skip_tools` are
never sent as the proposed action (they can still appear among the prior
tool calls of a later request, as before). `backend = "stub"` disables all
egress.

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

- **Proposed action**: for a CARE-scored Bash command, `tool: bash`,
  `args: <tool_input.command>`, the same mapping the POC's ShellRisk and
  smoke-gate paths used. For a call CARE cannot score (D21), the POC's
  non-shell `Name(json)` form, the same text as the call's prior-action
  rendering split into its two halves: `tool: <tool_name>` verbatim (e.g.
  `Write`, `mcp__github__create_issue`, or `Bash` for a Bash call without a
  command), `args: <json.dumps(tool_input, sort_keys=True,
  ensure_ascii=False)>`, clipped at `jev.context.field_chars` with the POC's
  truncation marker, decoded forms taken from the unclipped args. Tool names
  are not renamed to the calibration corpus's snake_case vocabulary.
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
thresholds from the spec (§4.2). These are the defaults; thresholds, order
and verdicts are tunable (`[jev]`, see [Tuning](#tuning)), and `tier_rule` in
the judge record shows the thresholds actually in force:

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

### `decide_all` and permission modes (D13, D22)

`decide_all` defaults to **true** (D22): cancelli makes every decision for the
calls it sees. CARE ALLOW → `allow`, CARE DENY → `deny`, CARE WARN → Jev, and
Jev allow/ask/deny are emitted as-is. Jev **ask** and **deny**, and CARE
**deny**, always emit whatever the setting. Tools in `skip_tools` always pass
through silently. Dry-run never emits anything.

This profile is meant for Claude Code's **`default`** or **`acceptEdits`**
permission mode. The auto-mode classifier no longer backs up CARE ALLOW, so
cancelli is the approver for every call it decides. Switch the mode in the
**same step** as dropping `--dry-run`: in dry-run the hook is silent, and
in `default`/`acceptEdits` silence means a prompt on nearly every call.

With `decide_all = false`, CARE ALLOW and Jev allow emit nothing, so Claude
Code's normal permission flow decides. That is the **auto-mode** profile,
where the auto-mode classifier reviews everything cancelli passes. In every
mode:

- a hook `"ask"` forces a prompt, **even in auto mode**;
- a hook `"allow"` skips the prompt, but your settings' **deny and ask rules
  still apply**, and so does Claude Code's critical-path `rm` circuit breaker;
  a hook can't approve past them;
- `skip_tools` calls get no decision, so the mode decides them. In
  `acceptEdits`, Write/Edit inside the working directory are auto-approved.

### Failure behaviour (D15)

Every failure produces **ask** plus an `error` record (`stage: "judge"`), and
the hook still exits 0. Failures are: no key or a refused key file, a
connection error, a timeout, a non-2xx response, an unparseable body, a
missing, wrongly typed or malformed answer for any question sent (a noul or
score reading that is not finite; choice probabilities that are not finite,
are negative, or do not sum to 1 within 0.05),
`response.model != judge.expected_model` (default `"jev-1.13.0"`, D23), and
a configured calibration file that is unreadable, invalid or pinned to
another rubric or model (D24). Timing: `timeout_ms` (3,000) per request
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

## Local backends (D23)

The judge is not tied to TypeSafe's hosted API: `backend = "jev"` means
**any server that speaks `POST /v1/systemone`** (request `{state, model,
questions}`, response `{model, answers, usage?}` with `noul` / `score` /
`choice` answers). The name stays `jev`; there is no alias. The hook never
runs inference itself (a hook is a fresh process per tool call); the model
lives in a long-running server such as
[jev-rs](docs/research/local-jev-serving.md) on top of llama-server.

```toml
[judge]
base_url = "http://127.0.0.1:8090"   # the local server
model = "qwen3-4b-q4"                # requested model (sent in the body)
expected_model = "qwen3-4b-q4"       # what the server reports as response.model
api_key_required = false             # no key needed; no Authorization header without one
timeout_ms = 4500                    # local inference is slower; keep the budget under the hook timeout
budget_ms = 5000
calibration_file = "~/.config/cancelli/qwen3-4b.calibration.json"   # D24, below
```

- `expected_model` (default `"jev-1.13.0"`) replaces the hard-coded pin: a
  response reporting any other model is a D15 failure (**ask** plus an error
  record). Set it to exactly what the server reports.
- `api_key_required = false`: a missing key is fine and no `Authorization`
  header is sent. A key that *is* found (env var or key file) is still sent.
- Every judge record logs the backend identity: `backend_host` (`host:port`
  of `base_url`), `expected_model`, and `model` (the reported one). The
  judge error record carries `backend_host` too.
- The tier thresholds were measured on `jev-1.13.0`. With another
  `expected_model` and no `calibration_file`, `cancelli config` and every
  hook call log a warning; calibrate (below) and compare with
  `cancelli eval` before trusting it.

## Calibration (D24)

A local model's probabilities are on its own scale. An optional
**calibration file** maps them onto Jev's, per axis, so the tier thresholds
keep their meaning. It is applied after the answers arrive and before the
signals are read; the judge record logs both `answers` (raw) and
`answers_calibrated`, plus `calibration{file, sha, rubric_hash, model,
fitted_at, axes[]}`.

```json
{
  "format": "cancelli-calibration/1",
  "rubric_hash": "0fd1f245ae1c7ef3",
  "model": "qwen3-4b-q4",
  "fitted_at": "2026-09-22T12:00:00-04:00",
  "source": "cancelli 0.1.0 calibrate --reference procreations_v2.jsonl (800 pairs, holdout 0.25, seed 42)",
  "axes": {
    "f5_exceeds_approval": {"type": "noul", "method": "platt", "a": 1.31, "b": -0.42, "n": 600,
                            "metrics": {"n_train": 600, "n_test": 200, "brier_before": 0.061,
                                        "brier_after": 0.032, "ece_before": 0.118, "ece_after": 0.041}},
    "a6_destination_class": {"type": "choice", "method": "temperature", "t": 1.8, "n": 600},
    "b4_reversibility": {"type": "score", "method": "temperature", "t": 0.7, "n": 600}
  }
}
```

- **noul**, `platt`: `p' = σ(a·logit(p) + b)` (p clamped to [1e-6, 1−1e-6]).
- **choice / score**, `temperature`: `p'_k ∝ max(p_k, 1e-6)^(1/t)`, i.e. a
  temperature on the log-probabilities, renormalised. A choice's `choice`
  becomes the new argmax (unchanged by a temperature); a score's `score`
  becomes `Σ k·p'_k`. A score answer without probabilities cannot be
  calibrated and fails the call.
- `method` is a tag, so methods such as isotonic can be added later; an
  unknown method makes the file invalid. Axes absent from the file are used
  as reported. `metrics` is informational.
- **Pinning.** The file is pinned to `rubric_hash` (the rubric in use) and
  `model` (the backend's *reported* model; it must also equal
  `expected_model`). An unreadable or invalid file, or a mismatch, refuses
  calibration: an `error` config record at load, and every judge call fails
  to **ask** with an error record (D15). Uncalibrated values are never used
  silently. `calibration_file` is fingerprinted by the file's sha256, so a
  refit changes `config_fingerprint`.

### `cancelli calibrate`

```sh
# reference = Jev answers; the target is the configured backend's answers on the same states
cancelli calibrate --reference ~/Documents/tte/data/runs/procreations_v2.jsonl \
                   --out ~/.config/cancelli/qwen3-4b.calibration.json \
                   --pairs-out /tmp/qwen-pairs.jsonl --limit 800
# refit later without the backend
cancelli calibrate --offline --reference /tmp/qwen-pairs.jsonl --out cal.json
```

Each `--reference` line is one of: a **tte run row** (`state_rendered`,
Jev `answers`, `rubric_hash`, `model`), a **cancelli log record** whose
`judge` holds a successful `jev-1.13.0` call (`state`, `answers`), or a
**pair** (`{"id", "rubric_hash", "target_model", "reference": {answers},
"target": {answers}}`, what `--pairs-out` writes and what `--offline`
fits on). Rows and records are deduplicated by state; their states are sent
to the configured backend with exactly the questions Jev answered, and its
raw (uncalibrated) answers are the target. Rows from another rubric, and
references that are not `jev-1.13.0`, are skipped and counted. The command
refuses to run online while `expected_model` is `jev-1.13.0` (calibrating
Jev against itself would only spend API calls).

Fitting: Platt `(a, b)` minimises the cross-entropy against Jev's `p` as a
soft target (Newton's method); the temperature minimises `Σ KL(q_jev ‖
p'_t)` (golden-section search over `1/t`). Items are split once with a
fixed seed (`--seed 42`) into a fitting set and a held-out set
(`--holdout 0.25`); parameters are fitted on the first only, and Brier and
ECE before → after are reported on the held-out items only (Brier: mean
squared error against Jev's probabilities, summed over labels for
choice/score; ECE: 10 equal-width bins over every predicted probability,
`|mean p − mean q_jev|` weighted by bin size). Axes with fewer than
`--min-pairs` (10) fitting pairs are reported and left out of the file.

## Eval: replaying logs under another config (D25)

```sh
cancelli eval --logs ~/.local/share/cancelli/events-*.jsonl --config /tmp/candidate.toml [--offline] [--json]
```

Every logged `event` is turned back into its `PreToolUse` payload and run
through the hook's own decision function (`hook::evaluate_call`: the same
CARE, D21, judge, decision and record code as the hook, nothing
duplicated), under the given config (environment overrides such as
`CANCELLI_MODE` apply as they would to the hook). Nothing is logged.

- **CARE** is replayed exactly, from the logged `command`.
- **Judge.** When the would-be state and the rubric are unchanged and the
  effective backend (`base_url` host + `expected_model`) is the one the
  record was judged with, the **logged answers are reused** and evaluated
  under the new config (calibration, thresholds, tier order, verdicts).
  Otherwise the configured backend is queried: the **logged state is
  resent** when the record has one; a call that **newly reaches** the judge
  (e.g. a CARE deny that is now a WARN) gets its state **rebuilt** from the
  record's `transcript_path` and `tool_use_id` if the transcript still
  exists (only what precedes that call counts), else it is reported as
  "needs judge (no state)". `--offline` never queries (and never reads the
  API key) and reports these as "needs judge". Records written before D23
  carry no `backend_host`; they count as judged by `api.typesafe.ai` with
  `jev-1.13.0`. A `jev.context` override on either side counts as a changed
  state. Logged answers come back in label order, so an exact argmax tie
  between two choice labels may resolve differently than on the wire.
- **Non-Bash** calls replay per D21 and `skip_tools`. Logged `tool_input`
  strings over `max_field_bytes` are truncated, so the logged judge state is
  preferred; with neither, the call is reported as "input truncated".
- **Older records** get a best-effort old decision, noted in `why`: no
  `final` on a non-Bash record = `none` (pre-D21 or `skip_tools`
  pass-through), stub-era `unadjudicated` = `ask` (what enforce mode
  emitted). Non-event lines (errors, warnings) are skipped and counted.

The compared decision is `final` (`allow` / `ask` / `deny`), `none` when
there is none, or `needs judge`; `decide_all` only changes whether an allow
is emitted (`would_emit`, in the JSON). Output: a summary, the old → new
transition matrix, and the changed calls sorted by time with the reasons
(CARE mode/verdict/score/skip predicate/rule changes, newly or no longer
judged, tier changes, calibration, where the answers came from). `--json`
prints one object per replayed record, then a `{"summary": …}` line.

Sample (this repository's own dry-run log of 2026-09-22, `--offline`, a
candidate config that removes `DESTRUCTIVE` from `care.resolution.h_sem`
and keeps the `skip_tools` those records were logged with; long lines
cut):

```
cancelli eval: config /tmp/eval-cfg2/config.toml (config_fingerprint 429676c71cbebef7; overrides ["care.resolution.h_sem", "jev.skip_tools"])
records: 697 lines, replayed 692, skipped 5, changed 19
  skipped 5: not an event (kind=error)
  14: needs judge (offline; no logged state)
  4: needs judge (offline; the logged judge call failed (no Jev API key: …))
  1: needs judge (offline; the logged judge call failed (timeout (global) (after retry)))

transition matrix (rows old, columns new)
old \ new          allow         ask        deny        none needs judge
allow                490           0           0           0           0
ask                    0          33           0           0           9
deny                   0           0           7           0           7
none                   0           0           0         143           3

changed calls (19)
ts                  tool          command / target                                  old → new             why
2026-09-22T09:08:34 Bash          T=$(mktemp -d); HOME=$T XDG_CONFIG_HOME=$T/cfg …  deny → needs judge    skip p_sem:DESTRUCTIVE→none; newly reaches the judge; needs judge (offline; no logged state)
2026-09-22T09:08:48 Bash          T=$(mktemp -d); HOME=$T XDG_CONFIG_HOME=$T/cfg …  deny → needs judge    skip p_sem:DESTRUCTIVE→none; newly reaches the judge; needs judge (offline; no logged state)
2026-09-22T09:54:53 WebSearch     TypeSafe AI RLCD "Reinforcement Learning for Ca…  ask → needs judge     needs judge (offline; the logged judge call failed (timeout (global) (after retry)))
…
```

The seven `rm -rf` temp-dir denials that relied only on `p_sem:DESTRUCTIVE`
become WARNs that need the judge; two other `p_sem:DESTRUCTIVE` denials stay
denied because their score is at or above τ_high. Without `--offline`, those
seven would be rebuilt from the session transcript and sent to the
configured backend.

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
- **Bash-only CARE scoring** (D3). CARE never scores a `Write` to
  `~/.zshrc` (a persistence vector) or any other non-Bash call. Since D21
  those calls are judged by Jev alone, which has no static fallback: a Jev
  T6 (allow) passes them, and they depend on Jev's calibration, which was
  done on generic tool names (`write_file`, `read_file`), not Claude Code's.
- **D21 cost.** Every non-skipped non-Bash call is a Jev request (latency,
  metered tokens, egress). See [Register as a hook](#register-as-a-hook) and
  `[jev] skip_tools`.
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
