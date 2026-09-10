# Mutation campaign: which verification layers detect which defects?

Each defect is a small, plausible boundary regression applied to a pristine
`HEAD (7b7e973)` worktree (see `apply-patches.py`; every anchor must match
exactly once). Ledger-level defects (D7a/D7b/D8) are post-hoc edits to a
pristine two-write ledger. Results: `matrix.md` / `matrix.json`.

## Reproduce

```bash
experiments/fault-injection/make-variants.sh /tmp/mab-mut        # 7 frozen variants, built
experiments/fault-injection/run-table.sh /tmp/mab-mut /tmp/mab-exp/head /tmp/mab-mut/results
node experiments/fault-injection/tabulate.mjs /tmp/mab-mut/results <matrix.json> <matrix.md>
```

`run-table.sh` per code variant runs the full suite (`test:only`), a runtime
probe (`variant-probe.mjs`, which drives the variant's own build the way the repo's
tests do), the variant's own replay (with the SUT evidence backup/restore from
the observer runbook), and the independent observer.

## How to read it

No single column sees everything; that is the talk's thesis, now measured:

- **D4 is visible ONLY to the test suite.** Cedar allows (0 bytes, within
  policy), replay passes (the record is self-consistent), the observer agrees
  (0 written vs 0 authorized). The three A1-group tests (A1/A8/F1) are the
  sole witnesses. This is the precise sense in which the repair's tests, not
  the engine, carry the representation boundary.
- **D1 and D2 are masked by neighboring layers.** D1 (executor consumes raw
  args) never fires because resolution refuses non-strings first; D2 (digest
  check removed) never fires because the mediation linkage check throws one
  step earlier (`mediation clears operation ...`). Both suites stay 155/0.
  Masked, not absent — verified by probes that die at the masking layer.
- **D9 (combined variant: D1+D4 together) still fails closed.** Even with
  both v1 flaws reintroduced, the HEAD mediation linkage throws before any
  write. The layer that blocks the original bug class is the linkage, and this
  row isolates it.
- **D5 (grant reuse) is live and suite-invisible.** No existing test spends
  the same grant twice, so 155/0 stays green while the probe double-spends
  successfully. The observer sees 11 bytes with zero ledger lines.
- **D3/D6 fail loud.** The enforce-time effect comparison throws before
  anything is recorded (20 suite failures each, all downstream of the throw),
  and the observer reports the stray `.shadow` file against an empty ledger.
- **D7a vs D7b separates chain integrity from mediation semantics.** Editing
  the mediation record breaks the hash chain (replay: 2 findings). Re-hashing
  the chain with the SUT's own hash function makes the same lie fully
  invisible: replay ALL STAGES PASS, observer AGREE. No shipped layer checks
  what the mediation record *says*.
- **D8 is the decisive row.** Truncating the last entry replays ALL STAGES PASS
  (the ledger cannot witness itself, L6, demonstrated not asserted) while the
  observer reports EFFECT_WITHOUT_RECORD on the truncated target and AGREE on
  the retained control.

## Honest limitations

- D3/D6's 20 failures include cascade effects (any test that writes throws);
  the count measures blast radius, not 20 independent detections.
- Replay/observer cells marked n/a are probe-construction facts (direct
  executor probes record no ledger), not layer verdicts.
- The observer checks authorization↔effect correspondence (target, size,
  sha); it cannot judge whether the authorization was wise (D4 agrees 0=0).
- D2/D5 muse local probes, not multi-machine runs; the 3-machine procedure
  in `../independent-observer/README.md` applies unchanged.
