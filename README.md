# cancelli

`cancelli` is a Rust port of **CARE** — the *Canonicalization, Attribution,
and Resolution Engine* from ["CARE: Pre-Execution Command Verification for
Shell-Executing LLM Agents"](https://arxiv.org/abs/2607.21642) — packaged as
a [Claude Code](https://claude.com/claude-code) `PreToolUse` hook. It scores
each `Bash` command an agent is about to run through CARE's static pipeline
and writes a structured JSONL record, so you can see what a command-level
guard *would* decide before turning enforcement on.

For now it runs in **dry-run**: it always allows the command and only logs. A
future step plugs a local open-weight judge into the stubbed `Adjudicator` to
resolve the borderline (WARN) cases.

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
   a WARN with no skip would go to the LLM judge, which is currently a stub
   that records the exact prompt it would send and returns *unadjudicated*.

Every other tool (`Write`, `Read`, `mcp__…`, …) is logged raw and unscored
(decision D3); string fields over 4 KiB are truncated with a length and
SHA-256.

CARE targets Linux bash/sh; cancelli adds a small set of macOS path
extensions (the `EXT-` table). It is a complementary pre-execution signal,
**not** a sandbox — it reads only the command string plus `$HOME`/cwd, never
the conversation.

## Install

```sh
cargo install --path .
```

This builds `~/.cargo/bin/cancelli`. Everything it needs (the rule bank and
the judge prompt) is embedded in the binary with `include_str!`, so nothing
depends on the source checkout at runtime (decision D9). Requires the Rust
2024 edition toolchain (≥ 1.98).

Build/test from source:

```sh
cargo build --release
cargo test                       # unit + e2e + parity + docs consistency
cargo test --test install -- --ignored   # cargo-install smoke test (slow)
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

### CLI

```
cancelli hook   [--dry-run] [--mode strict|balanced|auto]   # read stdin, log
cancelli analyze "<command>"    [--mode …]                  # full analysis JSON
cancelli config [--init]                                    # show / write config
```

`analyze` prints the complete evidence trace (views, per-layer scores and
evidence, fired rules, skip predicate, the judge prompt that would be sent) —
useful for debugging and for comparing against the Python reference.

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

[log]
dir = "~/.local/share/cancelli"   # env CANCELLI_LOG_DIR overrides
max_field_bytes = 4096            # non-Bash string truncation threshold

[judge]                    # step 2; ignored while the stub is active
backend = "stub"
# base_url = "http://127.0.0.1:8006/v1"
# model = ""
# timeout_ms = 2000
```

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
`skip_predicate`, `would_adjudicate`, `judge_prompt` (when it would
adjudicate), `judge`, `final` (`allow`|`deny`|`unadjudicated`),
`would_emit` (the decision enforce mode would send), `fixes_applied[]`,
`ext_applied[]`. For other tools it adds `tool_input` (truncated).

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

```sql
-- DuckDB: WARN commands that would reach the judge
SELECT command, aggregate, judge_prompt.user
FROM read_json_auto('~/.local/share/cancelli/events-*.jsonl')
WHERE would_adjudicate;
```

## Enforce mode (built, not registered)

Without `--dry-run` (and with `dry_run = false`) the hook emits a decision:
`final = deny` → `permissionDecision: "deny"`; a WARN with no judge →
`"ask"`; ALLOW → no output (normal permission flow — it never auto-approves).
Decision D6 keeps the registered hook in dry-run until the judge lands.

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
| FIX-008 | Judge call has a hard timeout (fail closed) | runtime |
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
  fall through to ALLOW. Applies to the real judge; the stub never parses.
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
  the hook. cancelli bounds the (future) call and fails closed.
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
- **clap** — the CLI (`derive`).
- **sha2** — SHA-256 for truncated non-Bash fields.
- **time** — RFC 3339 timestamps and the local date for log filenames.
- dev only: **tempfile**, **assert_cmd**, **predicates**.

## Known limitations

- **Dry-run only** by default (D6); enforce mode is built and tested but you
  must opt in.
- **The judge is a stub** (D7). WARN-with-no-skip commands are logged as
  `unadjudicated` with the exact prompt that would be sent.
- **Do not enforce until the judge is real.** The paper's narrower skip
  predicates (FIX-001..003) send more WARNs to the judge. On the parity corpus,
  24 commands the reference denies statically become `unadjudicated` in
  cancelli. Some are benign (`kill 1234`, `git worktree add ../wt`), but others
  are hostile GTFOBins shells whose π·conf (0.85 × 0.90 = 0.765) falls just
  under θrule. With the stub, enforce mode would turn these into `ask`. No
  L4 rule the reference fires is ever missed.
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

## Step 2: the judge

The WARN-band judge is behind the `Adjudicator` trait (`src/resolution.rs`).
The stub returns *unadjudicated*; the log already records the verbatim prompt
(paper Prompt 1 / `resolution.py` template) that a real judge would receive.
`parse_judge_output` implements the paper's fail-closed parsing (FIX-004) and
`run_judge` enforces the timeout (FIX-008), both unit-tested, so a local
open-weight backend drops in by implementing one method and pointing
`[judge]` at it. The plan is a local model ("Jev") served over an
OpenAI-compatible endpoint, matching the reference's deployment shape.

## Attribution

Port © 2026 Brad Voth, MIT (see `LICENSE`). Derived from CARE © 2026 CARE
authors, MIT — paper [arXiv:2607.21642](https://arxiv.org/abs/2607.21642),
code <https://github.com/prisma-research/CARE> (commit `e8166db`). The rule
bank (`data/rule_provenance.json`) and judge prompt (`data/judge_*.txt`) are
vendored verbatim; see `NOTICE`.
