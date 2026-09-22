#!/usr/bin/env bash
# Regenerate tests/golden/reference.jsonl from the pinned CARE reference.
# Requires git and uv. Usage: scripts/parity/regenerate.sh [workdir]
set -euo pipefail
PINNED=e8166db0c39fa058285b203305649a13eb31fc0b
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${1:-$(mktemp -d)}"
if [ ! -d "$WORK/CARE/.git" ]; then
  git clone --quiet https://github.com/prisma-research/CARE "$WORK/CARE"
fi
git -C "$WORK/CARE" checkout --quiet "$PINNED"
if [ ! -x "$WORK/venv/bin/python" ]; then
  uv venv --quiet "$WORK/venv"
  VIRTUAL_ENV="$WORK/venv" uv pip install --quiet "bashlex==0.18"
fi
"$WORK/venv/bin/python" "$ROOT/scripts/parity/run_reference.py" \
  --care-dir "$WORK/CARE" \
  --corpus "$ROOT/tests/corpus/commands.txt" \
  --out "$ROOT/tests/golden/reference.jsonl"
echo "wrote $ROOT/tests/golden/reference.jsonl"
