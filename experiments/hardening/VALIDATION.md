# Validation, 2026-09-08

- Full regression suite: **169 passed, 0 failed**.
- Default end-to-end scenario run: **25 scenarios, 27 entries**, four replay stages PASS.
- SQL differential experiment: **240 accepted queries**, each checked as raw SQL,
  canonical SQL and through the actual tool path, with SQLite as the independent oracle.
- Real-file campaign: **17 cases met their declared outcomes**, including expected
  failures. This does not mean every mutant passed replay. The symlink control also passed.
- Lean 4.33.1: trace binding, at-most-once execution, positive execution and mutant
  double-spend trace checked. Standard axioms only; the verification script rejects
  `sorryAx` and unexpected axiom dependencies.
- Two full default scenario generations produced identical ledger, journal and seal hashes.
- `git diff --check`: clean.

Default evidence SHA-256:

```text
ledger: 44ff579fc83b1678babe2c3aa71fa4678b41882f0a3ff31bd335e8e003e8e226
intents: 44f12a94066b77669a58d375f49e0b3c2ebd8d8102fc06a3e92fa4051d6d31a5
seal: eb82054fe355b97cedb56a58497bee9edaaa0266f5e1126d39615f43c67f2df6
```

[RESULTS.json](RESULTS.json) contains the tested source hashes, runtime versions,
full per-case outcomes, and the directory containing raw experiment artifacts.
The modifications are local and uncommitted. The historical Git base named in
that report does not by itself identify this modified version.

The pre-hardening generated evidence was copied before regeneration to
`/private/tmp/mab-evidence-before-hardening.MG9RSR/evidence`.

For interpreting the results, use the [experiment guide](README.md) and
[current claim limits](../../docs/HARDENING.md). Historical Newcastle slides
still refer to earlier frozen commits; do not substitute current outcomes into
their old tables without relabeling the version and measurement setup.

## Addendum, 2026-09-10 (branch `hardening-2026-09-10`)

The modifications described above are now committed on branch `hardening-2026-09-10`
(snapshot `d08b6be`, base `7b7e973` on `main`). Re-measured on that branch:

- Full regression suite: **177 passed, 0 failed** (was 169; +8 from
  `test/observer-export.test.ts`, `test/grant-binding.test.ts`,
  `test/filter-vs-repair.test.ts`, `test/formal-vectors.test.ts`).
- SQL differential: **240 accepted queries, 0 mismatches**.
- Real-file campaign: **19 cases met their declared outcomes**, including one declared
  known miss (`transient-extra-write`: replay ALL STAGES PASS, observer AGREE) and its
  caught counterpart (`transient-revert`: replay ALL STAGES PASS, observer DIVERGENCE).
- Source manifest in `RESULTS.json`: 71 files, now covering
  `experiments/independent-observer/`, `formal/` (including `vectors.json`), the new
  tests, `docs/REPAIR.md` and `docs/THREAT_MODEL.md`. Single digest over the sorted
  (path, hash) pairs, from `npm run manifest:digest`:

  ```text
  e2b829ad127bc865756024f071ba45e9d990eb03e0c64f9d62f7712e85651121
  ```

- `experiments/independent-observer/run-all-local.sh`: 1.18 s wall on this host; no
  internet socket observed by `lsof -i` polling during the run (6 polls; the same poller
  sees a deliberately opened listening socket), and the same script completes under
  `sandbox-exec` with `(deny network*)`, a profile under which `curl` fails.
  Single-host run; no second-machine observation is archived here.
