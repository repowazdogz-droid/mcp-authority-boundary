# Hardening experiment

Run from the repository root:

```sh
npm test
npm run test:formal
npm run experiment:hardening
```

Requirements: the project's Node dependencies, Python 3 with SQLite, and Lean
4.33.1 for the proof check. No model API, credentials, network service, or external
database is used. The runner creates a fresh owned directory on every invocation
and never reuses a previous world. `RESULTS.json` names the full artifact directory
and records source hashes, the Git base, runtime versions and outcomes. A Git base
alone does not identify the modified source; use the recorded hashes.

## SQL correspondence

The corpus enumerates 240 accepted queries from two tables, six projections,
five whitespace forms, two keyword/identifier cases and two terminator forms.
The runner submits each original query and its canonical form to a separate
Python/SQLite process. SQLite's authorizer reports the tables actually accessed.
The runner checks equality of the accessed table set, absence of mutation
callbacks, and equality of result rows and columns before/after canonicalization.
It then executes every query through the actual enforcement/PDP/tool path and
compares the returned CSV rows with SQLite. It seals and replays that 240-entry
query ledger as a separate artifact. Unknown fixture columns fail before preparation.

The negative control is `SELECT * FROM analytics.metrics, crm.customers`.
The historical extractor names only `analytics.metrics`, while SQLite accesses
both tables. The repaired parser refuses this query.

The accepted language is deliberately limited to SELECT projections from one
unquoted table, with optional schema qualification and final semicolon. General
SQL, including legitimate WHERE queries, is outside the contract. The experiment
uses SQLite as an independent semantic oracle for this subset. It does not prove
compatibility with every database or every string.

Primary API references: [SQLite authorizer](https://www.sqlite.org/c3ref/set_authorizer.html)
and [Python sqlite3](https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.set_authorizer).

## File effects and fault injection

`file-worker.mjs` drives the compiled EnforcementPoint/PDP/grant/tool path in a
child process. A host-configured backend performs real file reads, replacements
and deletions inside a fresh fixture directory. These are actual effects of the
tool executor, not files reconstructed from an in-memory export afterwards.

`observer.mjs` runs in another process. It imports only standard filesystem,
path and hashing libraries. It captures a baseline and later compares the whole
world with the expected state obtained by applying all completed write/delete
records in order. It does not infer an effect from file existence alone and does
not use only the last ledger record. Unexpected files and missing effects count
as divergences. Read errors and symlinks yield ERROR, never silent agreement.

The 17 cases include multiple writes to the same and different targets; zero,
4095-, 4096- and 4097-byte payloads; a 100,000-character array; multibyte UTF-8;
an allowed write followed by delete; wrong-target, no-write and extra-write
mutants; preparation/completion I/O failures; D8 truncation; a rewritten local
seal and truncated intent journal; and D7 rehashed mediation metadata.

An additional filesystem control verifies that the adapter refuses a symlink
and preserves the disposable outside target. The file adapter assumes the runner
owns directory topology throughout a call. It is not a proof against concurrent
directory replacement, hostile mounts, or an operating-system compromise.

The controller retains an end seal before post-run mutations and gives that copy
to replay. D8 must fail even when the mutant rewrites the co-located seal and
truncates the intent journal. This is a custody boundary in a local experiment,
not authentication between independent machines. The record and seal can both
be forged if the verifier's trust anchor is also under attacker control.

The extra-write mutant intentionally passes replay while the observer detects
an additional file. The no-write mutant leaves the initial world intact while
the unresolved intent makes replay fail. These controls distinguish record
consistency, outcome uncertainty and observed effects.

## Proof and remaining obligations

The Lean model proves binding and at-most-once execution by induction over all
reachable traces of its operational semantics. It also constructs a positive
execution and a reachable double-spend trace when the single-use premise is
removed. The main proofs depend on standard `propext` and `Quot.sound`, with no
`sorryAx` or custom axioms. Model-to-TypeScript refinement is not established.

Final-state observation cannot detect a transient effect that is later undone,
or count repeated writes of identical bytes. Write-ahead intents retain the
authorized operation across a completion failure, but cannot establish whether
an arbitrary external service committed. Stale locks require explicit recovery.
Power-loss and directory-fsync durability are not established. All experiment
roles share one host and one author. External review and independent-host runs
remain valuable extensions.

The older `experiments/fault-injection/` campaign remains pinned to its historical
commit. Its results and the Newcastle historical slide table should not be
silently relabeled as results from this hardening run.
