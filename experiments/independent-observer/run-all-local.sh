#!/bin/bash
# Local end-to-end verification of the independent-observer experiment.
# Runs all three roles as separate OS processes against frozen worktrees.
# The 3-machine run uses the same scripts, one role per machine (see README.md).
set -euo pipefail

EXP="$(cd "$(dirname "$0")" && pwd)"
WORK="${1:-/tmp/mab-exp}"
V1_DIR="$WORK/v1"
HEAD_DIR="$WORK/head"
OUT="$WORK/results"

mkdir -p "$OUT"
# Ledgers append, so stale files from an earlier run would pollute the evidence.
rm -rf "$OUT/effect-v1" "$OUT/effect-head"
rm -f "$OUT/ledger-v1.jsonl" "$OUT/ledger-head.jsonl"
rm -f "$OUT/sut-v1.json" "$OUT/sut-head.json" "$OUT/obs-v1.json" "$OUT/obs-head.json"
rm -f "$OUT/replay-v1.txt" "$OUT/replay-head.txt" "$OUT/evidence-table.json" "$OUT/evidence-table.md"
mkdir -p "$OUT/effect-v1" "$OUT/effect-head"

echo "--- [input source] generating shared stimulus"
node "$EXP/make-stimulus.mjs" "$OUT/stimulus.json"

echo "--- [sut/v1] unexpected-type call against pristine 631196d"
node "$EXP/run-sut.mjs" v1 "$V1_DIR" "$OUT/effect-v1" "$OUT/ledger-v1.jsonl" "$OUT/stimulus.json" "$OUT/sut-v1.json"

echo "--- [sut/head] unexpected-type call against pristine 7b7e973"
node "$EXP/run-sut.mjs" head "$HEAD_DIR" "$OUT/effect-head" "$OUT/ledger-head.jsonl" "$OUT/stimulus.json" "$OUT/sut-head.json"

echo "--- [sut] each version replays its own ledger"
# replay always rewrites evidence/replay-report.json under its cwd, so back up
# and restore the SUT's own evidence around each invocation.
cp "$V1_DIR/evidence/replay-report.json" "$OUT/replay-report-v1-backup.json"
(cd "$V1_DIR" && node dist/src/replay.js "$OUT/ledger-v1.jsonl") > "$OUT/replay-v1.txt" 2>&1 || true
cp "$OUT/replay-report-v1-backup.json" "$V1_DIR/evidence/replay-report.json"
cp "$HEAD_DIR/evidence/replay-report.json" "$OUT/replay-report-head-backup.json"
(cd "$HEAD_DIR" && node dist/src/replay.js "$OUT/ledger-head.jsonl") > "$OUT/replay-head.txt" 2>&1 || true
cp "$OUT/replay-report-head-backup.json" "$HEAD_DIR/evidence/replay-report.json"

echo "--- [observer] independent read-back (no SUT imports)"
node "$EXP/observe.mjs" "$OUT/effect-v1" "$OUT/ledger-v1.jsonl" "corp/public/notes.md" "v1-631196d" "$OUT/obs-v1.json"
node "$EXP/observe.mjs" "$OUT/effect-head" "$OUT/ledger-head.jsonl" "corp/public/notes.md" "head-7b7e973" "$OUT/obs-head.json"

echo "--- [evidence] machine-generated table"
node "$EXP/compare.mjs" "$OUT" "$OUT/evidence-table.json" "$OUT/evidence-table.md"
