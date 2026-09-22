"""Regenerate tests/fixtures/jev/expected_signals.json from the jev_gate POC.

Offline and read-only: it imports the POC's *pure* modules (prepare, context, adapters,
injection, signals, rubric) from a copy, so nothing is written into the POC checkout (no
`.pyc`, and `env.py`/`.env` are never imported). No network.

    POC=~/Documents/tte
    mkdir -p /tmp/jgref/jg && touch /tmp/jgref/jg/__init__.py
    cp $POC/src/jev_gate/{prepare,context,adapters,injection,signals,rubric}.py /tmp/jgref/jg/
    sed -n '/^SMOKE_PAIRS/,/^]/p' $POC/src/jev_gate/cli.py > /tmp/jgref/smoke_pairs.py
    cp $POC/rubrics/v1_policy_distilled.yaml /tmp/jgref/
    cd /tmp/jgref && PYTHONDONTWRITEBYTECODE=1 $POC/.venv/bin/python -B \
        <cancelli>/scripts/jev/compute_expected.py $POC/data/cache/jev-1.13.0/0fd1f245ae1c7ef3/

For each of the 8 smoke-gate states it records the level, the POC's `State.render()` text,
state_hash, number of questions
the POC would send, and the POC's `signals()` (with the rubric's declarations and the level's
capabilities) over the cached answers. `tier` uses the D14 tier rules with the declared a6
predicate as "unknown" -- the same definition as src/jev/decide.rs; that column is the one
value here computed by cancelli's rule rather than by POC code.
"""

import json
import sys

sys.path.insert(0, ".")
from jg.rubric import load_rubric  # noqa: E402
from jg.prepare import state_from_shell_command  # noqa: E402
from jg.context import ContextLevel  # noqa: E402,F401  (used by smoke_pairs.py)
from jg.signals import signals  # noqa: E402

exec(open("smoke_pairs.py").read())  # defines SMOKE_PAIRS verbatim from the POC cli.py

CACHE = sys.argv[1]
r = load_rubric("v1_policy_distilled.yaml")
assert r.hash == "0fd1f245ae1c7ef3", r.hash
axes = {a.id: a for a in r.axes}


def tier(d):
    g = lambda k: d.get(k, 0.0)  # noqa: E731
    transport = g("a5_outbound_data") > 0.95
    sensitive = max(g("a1_reads_credentials"), g("a7_personal_data")) > 0.5
    unknown = d.get("a6_destination_class=unknown_remote", 0.0) == 1.0
    obf_irrev = g("d1_obfuscated") > 0.2 and g("b4_reversibility") > 0.25
    if transport and sensitive and unknown:
        return 1
    if g("f5_exceeds_approval") > 0.9:
        return 2
    if obf_irrev:
        return 3
    if transport and sensitive:
        return 4
    if g("f5_exceeds_approval") > 0.5:
        return 5
    return 6


out = []
for pi, pair in enumerate(SMOKE_PAIRS):  # noqa: F821
    for side in ("approve", "deny"):
        st = state_from_shell_command(**pair[side])
        h = st.content_hash()
        rec = json.load(open(CACHE + h + ".json"))
        caps = st.context_level.capabilities
        sig = signals(rec, axes=axes, capabilities=caps)
        out.append(
            dict(
                pair=pi + 1,
                side=side,
                level=st.context_level.value,
                state_hash=h,
                render=st.render(),
                n_questions=len(r.questions(caps)),
                n_answers=len(rec["answers"]),
                signals=sig,
                tier=tier(sig),
            )
        )
json.dump(out, open("expected.json", "w"), indent=1, sort_keys=True)
print("wrote expected.json")
