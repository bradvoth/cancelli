#!/usr/bin/env python3
"""Run the pinned CARE reference over the parity corpus and write golden JSONL.

Usage:
    python3 run_reference.py --care-dir <CARE checkout> \
        --corpus tests/corpus/commands.txt --out tests/golden/reference.jsonl

The CARE checkout must be at the pinned commit (checked). HOME is forced to
/home/user so `~` expansion is deterministic (the Rust parity test uses the
same value). Only the deterministic engine and the pure skip-predicate
function are exercised; the LLM judge is never called.
"""
import argparse
import json
import os
import subprocess
import sys

PINNED = "e8166db0c39fa058285b203305649a13eb31fc0b"
PARITY_HOME = "/home/user"


def read_corpus(path):
    cmds = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if line.startswith("json:"):
                cmds.append(json.loads(line[5:]))
            else:
                cmds.append(line)
    return cmds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--care-dir", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    head = subprocess.run(["git", "-C", args.care_dir, "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    if head != PINNED:
        sys.exit(f"CARE checkout is at {head}, expected {PINNED}")

    os.environ["HOME"] = PARITY_HOME
    sys.path.insert(0, args.care_dir)
    import bashlex  # noqa: F401  (the reference silently degrades without it)
    from care import CAREEngine, CARE
    from care.policy import decide
    from care.modes import policy_for

    eng = CAREEngine()
    guard = CARE(use_judge=True)
    cfgs = {m: policy_for(m) for m in ("strict", "balanced", "auto")}

    with open(args.out, "w", encoding="utf-8") as out:
        for cmd in read_corpus(args.corpus):
            r = eng.analyze(cmd)
            sc = r.details["scoring"]
            skip, reason = guard._should_skip_llm(r)
            if r.decision == "WARN":
                final = "deny" if skip else "unadjudicated"
            else:
                final = r.decision.lower()
            rec = {
                "cmd": cmd,
                "decision": r.decision,
                "provisional": {m: decide(sc["final_score"], c) for m, c in cfgs.items()},
                "scores": {"sem": sc["sem_score"], "path": sc["path_score"],
                           "pat": sc["pat_score"], "struct": sc["struct_score"]},
                "aggregate": r.score,
                "fired_rules": [m["rule_id"] for m in r.fired_rules],
                "skip_reason": reason,
                "final": final,
            }
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
