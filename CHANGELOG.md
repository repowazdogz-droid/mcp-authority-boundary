# Changelog

Dates are tag dates. v1.1.0 is a git tag without a GitHub release.

## 1.1.1 (2026-10-16)

- **CI could report a failing suite as green.** `verify.yml` piped `npm test`, the hardening campaign and the observer run into `tee` under GitHub's implicit shell (`bash -e`, no `pipefail`), so each step exited with `tee`'s status. An explicit `shell: bash` default now runs every step under `bash -eo pipefail`.
- **Negative control for that fix.** `test/ci-can-fail.test.ts` fails only when `CI_NEGATIVE_CONTROL=1`. A new CI step runs it through the same `tee` pipe and requires a non-zero exit with exactly one failure. In normal runs the test passes and asserts nothing about the system. `npm test` now reports 183 tests (182 at v1.1.0).
- `package.json` version set to 1.1.1. It had stayed at 1.0.0 through the v1.1.0 tag.
- `experiments/hardening/RESULTS.json` regenerated, because `package.json` and `package-lock.json` are in its source manifest; the new manifest digest is in VERIFY.md.
- README opens with the claim, a reproduction command and its limits. Added CITATION.cff and this file. No change to `src/`, `policies/` or `formal/`.

## 1.1.0 (2026-09-23)

Hardened state, same code and evidence as tag `newcastle-2026-09-11` (`3ccac8a`); this tag changed docs and the CI trigger only.

- Independent observer experiment: v1 (`631196d`) and the repaired base (`7b7e973`) receive the same malformed call; an observer that imports nothing from the repository reads the written file and both ledgers.
- `formal/Boundary.lean` and `formal/Conformance.lean`: an abstract transition system and a trace check of recorded TypeScript runs against it (a trace check, not a refinement proof).
- Hardening campaign over SQL and real-file cases, with an executor-compromise threat model and a labelled `knownMiss` negative control.
- Tests for grant single-use under concurrency and decision-time versus execution-time policy.
- Corrections to v1.0.0: claim D (effect verification) was overstated and is narrowed; `MCP_SESSION_ID` is now required, where v1.0.0 defaulted an absent value to the highest-authority session.
- 182 tests.

## 1.0.0 (2026-08-07)

First release. Implementation frozen at `c3f7ade`: 24 scenarios, 26 ledger entries, 15/15 determining-policy coverage, 100 tests, four replay stages PASS, ledger byte-identical across runs and across Node 20/22/24/25.
