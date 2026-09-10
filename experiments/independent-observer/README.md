# Independent-observer experiment (slides 9, 10, 17)

One unexpected-type stimulus, two frozen versions, one independent witness.

- **MacBook (caller/input source):** generates the shared stimulus.
- **RTX (system under test):** runs pristine `v1 (631196d)` and `HEAD (7b7e973)`
  in separate frozen worktrees, exports each version's post-execution bytes to
  the real filesystem, and replays each version's own ledger.
- **Mac mini (independent observer):** touches neither SUT. It stats/hashes the
  effect files and reads the ledgers as plain JSON text (`observe.mjs` imports
  only `node:fs`, `node:path`, `node:crypto` — grep it), then builds the
  evidence table.

Locally verified end-to-end on 2026-09-08 (`run-all-local.sh`):
`v1 → ALLOW (byteLen=0) / VERIFIED / 100,000 bytes → DIVERGENCE`;
`HEAD → REFUSE / nothing executed / no write`.

## 0. Prerequisites (all machines)

- node >= 20.11, git, this repo checked out (any commit; the SUT pins itself).
- Worktrees are created from the repo checkout on the RTX box.

## 1. MacBook — input source (1 command)

```bash
node experiments/independent-observer/make-stimulus.mjs /tmp/mab-exp/results/stimulus.json
```

Send `stimulus.json` to the RTX box (tailscale `scp`, AirDrop, USB — any
channel; the stimulus is public by design).

## 2. RTX — system under test

```bash
cd ~/mcp-authority-boundary
git worktree add /tmp/mab-exp/v1 631196d
git worktree add /tmp/mab-exp/head 7b7e973
(cd /tmp/mab-exp/v1 && npm ci --prefer-offline --no-audit --no-fund && npm run build)
(cd /tmp/mab-exp/head && npm ci --prefer-offline --no-audit --no-fund && npm run build)

EXP=experiments/independent-observer
OUT=/tmp/mab-exp/results
mkdir -p $OUT/effect-v1 $OUT/effect-head
node $EXP/run-sut.mjs v1   /tmp/mab-exp/v1   $OUT/effect-v1   $OUT/ledger-v1.jsonl   $OUT/stimulus.json $OUT/sut-v1.json
node $EXP/run-sut.mjs head /tmp/mab-exp/head $OUT/effect-head $OUT/ledger-head.jsonl $OUT/stimulus.json $OUT/sut-head.json
# NOTE: replay rewrites evidence/replay-report.json under its cwd. Back it up
# first and restore it after, or it will clobber the SUT's shipped evidence
# (and flip evidence-composition.test.ts red).
cp /tmp/mab-exp/v1/evidence/replay-report.json $OUT/replay-report-v1-backup.json
(cd /tmp/mab-exp/v1 && node dist/src/replay.js $OUT/ledger-v1.jsonl) > $OUT/replay-v1.txt 2>&1 || true
cp $OUT/replay-report-v1-backup.json /tmp/mab-exp/v1/evidence/replay-report.json
cp /tmp/mab-exp/head/evidence/replay-report.json $OUT/replay-report-head-backup.json
(cd /tmp/mab-exp/head && node dist/src/replay.js $OUT/ledger-head.jsonl) > $OUT/replay-head.txt 2>&1 || true
cp $OUT/replay-report-head-backup.json /tmp/mab-exp/head/evidence/replay-report.json
```

`run-sut.mjs` drives each version's own `EnforcementPoint.handle` (the same
path its server uses) and exports post-execution bytes verbatim. On refusal
nothing is exported — reading the fixture map on a deny would manufacture an
effect the SUT never produced, so the script refuses to do it.

Send to the mini: `stimulus.json`, `sut-v1.json`, `sut-head.json`,
`ledger-v1.jsonl`, `ledger-head.jsonl`, `replay-v1.txt`, `replay-head.txt`,
and the two `effect-*` directories (with the files inside, if any).

## 3. Mac mini — independent observer / evidence custodian

```bash
# IN = directory holding everything received from RTX
EXP=experiments/independent-observer   # same scripts, checked out on the mini
node $EXP/observe.mjs $IN/effect-v1   $IN/ledger-v1.jsonl   corp/public/notes.md v1-631196d   $IN/obs-v1.json
node $EXP/observe.mjs $IN/effect-head $IN/ledger-head.jsonl corp/public/notes.md head-7b7e973 $IN/obs-head.json
node $EXP/compare.mjs $IN $IN/evidence-table.json $IN/evidence-table.md
cat $IN/evidence-table.md
```

Expected machine-generated table:

| Version | Cedar | Ledger / replay | Independent world observer |
|---|---|---|---|
| v1 (631196d) | ALLOW (byteLen=0) | VERIFIED | 100,000 bytes vs 0 authorized → DIVERGENCE |
| head (7b7e973) | REFUSE (unresolvable-resource) | INCOMPLETE (nothing executed) | no write |

That table is the slide: the counterexample is no longer a log produced by
the program under investigation — a third machine states what happened.

## 4. Teardown (RTX)

```bash
git worktree remove --force /tmp/mab-exp/v1
git worktree remove --force /tmp/mab-exp/head
```

## Files

- `make-stimulus.mjs` — input source; array-where-string-expected, 100k payload.
- `run-sut.mjs` — SUT driver; imports only the pinned worktree's own build.
- `observe.mjs` — independent witness; node stdlib only, no SUT imports.
- `compare.mjs` — evidence table from SUT results + observations + replays.
- `run-all-local.sh` — all three roles as separate local processes (CI for
  the procedure itself; the 3-machine run is the finding).
