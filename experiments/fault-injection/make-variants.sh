#!/bin/bash
# Build one frozen variant worktree per code defect. Idempotent: skips variants
# that already have a dist/ build.
set -euo pipefail
EXP="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$EXP/../.." && pwd)"
BASE="${1:-/tmp/mab-mut}"

for D in D1 D2 D3 D4 D5 D6 D9; do
  DIR="$BASE/$D"
  if [ ! -d "$DIR" ]; then
    git -C "$REPO" worktree add "$DIR" 7b7e973 2>&1 | tail -1
    python3 "$EXP/apply-patches.py" "$D" "$DIR"
  fi
  if [ ! -d "$DIR/dist" ]; then
    (cd "$DIR" && npm ci --prefer-offline --no-audit --no-fund >/dev/null 2>&1 && npm run build >"$DIR/build.log" 2>&1) || {
      echo "$D BUILD FAILED:"; tail -5 "$DIR/build.log"; exit 1;
    }
  fi
  echo "$D ready at $DIR"
done
