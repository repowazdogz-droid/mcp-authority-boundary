# Independent-observer experiment (slides 9, 10, 17)

One unexpected-type stimulus, two frozen versions, one observer that shares no code
with either.

**What "independent" means here, exactly.** `observe.mjs` is independent in its
*imports*: it uses `node:fs`, `node:path` and `node:crypto` and nothing from `src/`
or `dist/` (grep it; `test/observer-export.test.ts` and the manifest in
`experiments/hardening/RESULTS.json` pin its bytes). It is **not** independent in
*custody*: the harness (`run-sut.mjs`) is what exports v1's in-memory effect map
to a real file, and the observer measures that export. `test/observer-export.test.ts`
measures that the export is byte-identical to the in-memory value (in-memory
sha256, file sha256 as re-read by the harness, and file sha256 as re-hashed by the
test all agree), so what the observer sees is what v1's executor produced, but a
process that controls the harness controls the export. The three-machine procedure
below separates those roles onto separate hosts; **no Mac mini output is archived in
this repository**, and nothing here should be read as a record of such a run.

Roles:

- **Input source:** generates the shared stimulus (`make-stimulus.mjs`).
- **System under test:** runs pristine `v1 (631196d)` and `HEAD (7b7e973)` in separate
  frozen worktrees, exports each version's post-execution bytes to the real filesystem,
  and replays each version's own ledger (`run-sut.mjs`).
- **Observer:** touches neither SUT. It stats/hashes the effect files and reads the
  ledgers as plain JSON text (`observe.mjs`), then builds the evidence table
  (`compare.mjs`).

`run-all-local.sh` runs all three roles as separate OS processes on one host against
the frozen worktrees; that is the run this repository re-executes and the only run it
records. It produces:
`v1 → ALLOW (byteLen=0) / VERIFIED / 100,000 bytes → DIVERGENCE`;
`HEAD → REFUSE / nothing executed / no write`.

## Second-machine check (three files, one command)

To observe from a machine that holds none of this repository, copy exactly three
files from a `run-all-local.sh` results directory (default `/tmp/mab-exp/results`):

1. `experiments/independent-observer/observe.mjs` (from the repo)
2. `results/effect-v1/corp/public/notes.md` (the exported effect, 100,000 bytes)
3. `results/ledger-v1.jsonl` (v1's own ledger for the run)

On the second machine, with the effect file placed under a directory as
`EFFECT/corp/public/notes.md`:

```bash
node observe.mjs EFFECT ledger-v1.jsonl corp/public/notes.md v1-631196d obs-v1.json
```

Expected output line (one JSON object; the load-bearing fields):

```
"fileBytes":100000,"fileSha256":"d69e68988157833272305aaf21f453c800346e8a3640db6578e260215542e5d4","ledgerDecision":"allow", ... "ledgerCedarByteLen":0, ... "comparison":"DIVERGENCE"
```

A different `fileSha256`, or any `comparison` other than `DIVERGENCE`, means the
copied files are not the ones this repository's run produced.

## 0. Prerequisites (all machines)

- node >= 20.11, git, this repo checked out (any commit; the SUT pins itself).
- Worktrees are created from the repo checkout on the SUT host.

## 1. Input host — input source (1 command)

```bash
node experiments/independent-observer/make-stimulus.mjs /tmp/mab-exp/results/stimulus.json
```

Send `stimulus.json` to the SUT host (`scp`, USB — any channel; the stimulus is
public by design).

## 2. SUT host — system under test

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

Send to the observer host: `stimulus.json`, `sut-v1.json`, `sut-head.json`,
`ledger-v1.jsonl`, `ledger-head.jsonl`, `replay-v1.txt`, `replay-head.txt`,
and the two `effect-*` directories (with the files inside, if any).

## 3. Observer host — independent observer / evidence custodian

```bash
# IN = directory holding everything received from the SUT host
EXP=experiments/independent-observer   # only observe.mjs and compare.mjs are needed here
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

That table is the slide when the roles run on separate hosts: the counterexample is
then stated by a process that shares no code with the program under investigation.
This repository records only single-host `run-all-local.sh` runs: the author's machine, and the
`counterexample` job of GitHub Actions run 34483375841 (GitHub-hosted runner, commit `3ccac8a`).
No run with the roles on separate hosts is recorded.

## 4. Teardown (SUT host)

```bash
git worktree remove --force /tmp/mab-exp/v1
git worktree remove --force /tmp/mab-exp/head
```

## Files

- `make-stimulus.mjs` — input source; array-where-string-expected, 100k payload.
- `run-sut.mjs` — SUT driver; imports only the pinned worktree's own build.
- `observe.mjs` — independent witness; node stdlib only, no SUT imports.
- `compare.mjs` — evidence table from SUT results + observations + replays.
- `run-all-local.sh` — all three roles as separate local processes on one host;
  the run this repository re-executes and records.
