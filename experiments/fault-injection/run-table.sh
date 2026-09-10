#!/bin/bash
# Mutation-matrix runner. Per code variant: full suite, runtime probe, own
# replay, independent observation. Plus ledger-level defects D7a/D7b/D8 on a
# pristine HEAD worktree. Results land in <OUT>/<D>/.
set -euo pipefail
EXP="$(cd "$(dirname "$0")" && pwd)"
OBS="$EXP/../independent-observer"
MUTS="${1:-/tmp/mab-mut}"
PRISTINE="${2:-/tmp/mab-exp/head}"
OUT="${3:-/tmp/mab-mut/results}"
TARGET="corp/public/notes.md"

run_replay() { # <sut_dir> <ledger> <out_txt>
  local sut="$1" ledger="$2" out="$3"
  cp "$sut/evidence/replay-report.json" "$out.backup.json"
  (cd "$sut" && node dist/src/replay.js "$ledger") > "$out" 2>&1 || true
  cp "$out.backup.json" "$sut/evidence/replay-report.json"
}

for D in D1 D2 D3 D4 D5 D6 D9; do
  M="$MUTS/$D"; R="$OUT/$D"
  mkdir -p "$R"
  echo "=== $D (suite) ==="
  (cd "$M" && npm run test:only >"$R/suite.txt" 2>&1) || true
  grep -E "ℹ (pass|fail) [0-9]+" "$R/suite.txt" | tail -2 || true
  echo "=== $D (probe) ==="
  rm -rf "$R/effect-$D"
  node "$EXP/variant-probe.mjs" "$M" "$R" "$D" | head -c 600; echo
  echo "=== $D (replay + observer) ==="
  run_replay "$M" "$R/ledger-$D.jsonl" "$R/replay-$D.txt"
  tail -2 "$R/replay-$D.txt" | head -1
  node "$OBS/observe.mjs" "$R/effect-$D" "$R/ledger-$D.jsonl" "$TARGET" "$D" "$R/obs-$D.json" | head -c 400; echo
done

echo "=== ledger-level defects on pristine HEAD ==="
RL="$OUT/L-base"; mkdir -p "$RL"
# The Ledger appends, so stale base files would pile up entries across runs.
rm -f "$RL/ledger-base.jsonl" "$RL/ledger-D7a.jsonl" "$RL/ledger-D7b.jsonl" "$RL/ledger-D8.jsonl"
rm -f "$RL/replay-D7a.txt" "$RL/replay-D7b.txt" "$RL/replay-D8.txt"
rm -f "$RL/obs-base.json" "$RL/obs-D7a.json" "$RL/obs-D7b.json" "$RL/obs-D8-roadmap.json" "$RL/obs-D8-notes.json"
rm -rf "$RL/effect-base" "$RL/effect-D8"
cat > "$RL/make-base.mjs" <<EOF
import { EnforcementPoint } from 'file://$PRISTINE/dist/src/enforce.js';
import { Ledger } from 'file://$PRISTINE/dist/src/ledger.js';
import { loadPolicy, loadEntities } from 'file://$PRISTINE/dist/src/policy.js';
import { permitAllMediator } from 'file://$PRISTINE/dist/src/mediation.js';
import { snapshotDocuments } from 'file://$PRISTINE/dist/src/tools.js';
import { writeFileSync, mkdirSync } from 'node:fs';
const ledger = new Ledger('$RL/ledger-base.jsonl');
const pep = new EnforcementPoint({
  policy: loadPolicy('v1', []), entities: () => loadEntities(), ledger,
  session: { type: 'Mcp::Session', id: 'sess-writer-delegated' },
  now: () => 2000, wallClock: '2026-08-07T00:00:00.000Z', mediator: permitAllMediator(),
});
const r1 = pep.handle({ tool: 'write_document', args: { path: 'corp/public/notes.md', content: 'ledger-base-one' } });
const r2 = pep.handle({ tool: 'write_document', args: { path: 'corp/public/roadmap.md', content: 'ledger-base-two!!' } });
console.log(JSON.stringify([r1.entry.decision.decision, r2.entry.decision.decision]));
const docs = snapshotDocuments().documents;
for (const [k, v] of docs) {
  if (v === 'ledger-base-one' || v === 'ledger-base-two!!') {
    mkdirSync('$RL/effect-base/' + k.split('/').slice(0, -1).join('/'), { recursive: true });
    writeFileSync('$RL/effect-base/' + k, v);
  }
}
EOF
node "$RL/make-base.mjs"
python3 - "$RL/ledger-base.jsonl" <<'EOF'
import json, sys
base = sys.argv[1]
entries = [json.loads(l) for l in open(base) if l.strip()]
# D7a: alter the mediation record post-hoc (reason + hash), chain untouched.
# Deep-copy through JSON: a shallow copy would alias the nested mediation
# object and silently tamper the D8 prefix too.
a = json.loads(json.dumps(entries))
a[0]['mediation']['reason'] = 'edited: permit-all (edited post-hoc)'
open(base.replace('ledger-base', 'ledger-D7a'), 'w').write('\n'.join(json.dumps(e) for e in a) + '\n')
# D8: truncate the last entry (the roadmap write vanishes from the record)
open(base.replace('ledger-base', 'ledger-D8'), 'w').write(json.dumps(entries[0]) + '\n')
print('D7a/D8 ledgers written;', len(entries), 'base entries')
EOF
cat > "$RL/rehash.mjs" <<EOF
// D7b: same mediation tamper as D7a, but re-hash the chain with the SUT's own
// hash function, so chain-integrity cannot be the thing that catches it.
import { readFileSync, writeFileSync } from 'node:fs';
import { canonicalJson, sha256 } from 'file://$PRISTINE/dist/src/canonical.js';
import { GENESIS } from 'file://$PRISTINE/dist/src/ledger.js';
const [src, dst] = process.argv.slice(2);
let prev = GENESIS;
const out = [];
for (const line of readFileSync(src, 'utf8').split('\n').filter((l) => l.trim())) {
  const e = JSON.parse(line);
  e.mediation.reason = 'edited: permit-all (edited post-hoc, chain re-hashed)';
  delete e.hash;
  e.prevHash = prev;
  e.hash = sha256(canonicalJson(e));
  prev = e.hash;
  out.push(JSON.stringify(e));
}
writeFileSync(dst, out.join('\n') + '\n');
console.log('D7b ledger written');
EOF
node "$RL/rehash.mjs" "$RL/ledger-D7a.jsonl" "$RL/ledger-D7b.jsonl"
# D7b needs the tamper present before re-hash: rehash reads D7a (already
# tampered) and re-tampers identically, so the input tamper is idempotent.
for D in D7a D7b D8; do
  run_replay "$PRISTINE" "$RL/ledger-$D.jsonl" "$RL/replay-$D.txt"
  echo "--- $D replay verdict:"; grep -E "verdict|FAILED|ALL STAGES|INCOMPLETE|findings" "$RL/replay-$D.txt" | head -5 || true
done
rm -rf "$RL/effect-D8" && cp -r "$RL/effect-base" "$RL/effect-D8"
node "$OBS/observe.mjs" "$RL/effect-base" "$RL/ledger-base.jsonl" "corp/public/notes.md" "L-base" "$RL/obs-base.json" >/dev/null
node "$OBS/observe.mjs" "$RL/effect-base" "$RL/ledger-D7a.jsonl" "corp/public/notes.md" "D7a" "$RL/obs-D7a.json" >/dev/null
node "$OBS/observe.mjs" "$RL/effect-base" "$RL/ledger-D7b.jsonl" "corp/public/notes.md" "D7b" "$RL/obs-D7b.json" >/dev/null
node "$OBS/observe.mjs" "$RL/effect-D8" "$RL/ledger-D8.jsonl" "corp/public/roadmap.md" "D8-roadmap" "$RL/obs-D8-roadmap.json" >/dev/null
node "$OBS/observe.mjs" "$RL/effect-D8" "$RL/ledger-D8.jsonl" "corp/public/notes.md" "D8-notes-control" "$RL/obs-D8-notes.json" >/dev/null
echo "--- D8 observer (truncated-away target):"; grep -o '"comparison": "[A-Z_]*"' "$RL/obs-D8-roadmap.json" || true
echo "--- D8 observer (retained target, control):"; grep -o '"comparison": "[A-Z_]*"' "$RL/obs-D8-notes.json" || true
echo "ledger-level done"
