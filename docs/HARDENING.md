# Current hardening status

This supersedes the previous pass's broad claim that a local seal had closed D8.
The older limitation and audit findings remain useful historical witnesses.

| Gap | Implemented change | Evidence and limit |
|---|---|---|
| SQL extraction missed comma-joined tables | Whole-input parser for a specified SELECT subset; parsed projection reaches execution | 240 raw/canonical pairs checked against SQLite table access and rows; unsupported SQL is refused |
| Authorization API trusted separately supplied request and operation | PDP revalidates canonical operation, digest, action, resource and context before minting | Regression attempts receive no grant |
| Grant fields and mediation content could change after authorization | Freeze issued grants; recompute the content hash of mediation | Mutation and actual grant reuse tests fail before execution |
| Prototype tool names and leading backslash paths | Own-property tool lookup; separator normalization before absolute/drive checks | Recorded denials and path idempotence/refusal tests |
| A2 widened intermediate delegation | Check both edges in the allowed depth-two chain, including start time, depth and grandparent revocation | The original laundered descendant now denies; a valid two-hop chain still allows |
| Effect could precede discovery of a sealed/unwritable ledger | Whole-call exclusive lock, readiness check, fsynced authorization intent, completed-record reconciliation | Sealed/prepare-failure paths leave the world unchanged; completion failure retains an allow and unknown outcome |
| D8 local seal was replaceable | Exclusive sealing, stale/corrupt writer rejection, optional verifier-held anchor | Rewritten local seal plus truncated journal fails against the pre-tamper anchor; a compromised anchor remains outside the guarantee |
| D7 rehashed mediation escaped replay | Recompute mediation binding and check prepared authorization against completion | Semantic binding failure survives a recomputed ledger hash |
| Observer examined an exported map and only the last entry | Real-file backend plus a separate observer reading the whole before/after world | 17 cases distinguish clean controls, missing/extra effects, truncation and outcome uncertainty |
| Proof was a single-transition toy | Reachability invariant and single-use theorem; positive trace and mutant double-spend trace | Kernel-checked in pinned Lean; TypeScript refinement and external-effect semantics remain open |

Commands and detailed controls: [experiment guide](../experiments/hardening/README.md).
Machine-generated results and exact source hashes: [RESULTS.json](../experiments/hardening/RESULTS.json).

The default 25-scenario demo and its 27-entry ledger still have the same execution
mix: five reads, one email and two shell simulations. Its replay effect stage
still does not establish independent world observation. The real-file campaign
is a separate artifact with its own explicit controls and narrower claims.

No claim of production security, authenticated session establishment, general
SQL support, hostile-filesystem confinement, arbitrary side-effect atomicity,
or full policy adequacy follows from these changes.
