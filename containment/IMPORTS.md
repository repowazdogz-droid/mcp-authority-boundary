# Coupling to the rest of the repo

The exact dependency surface between this layer and the per-call boundary it
extends. Kept current by hand and checkable in one command:

```
grep -rn "\.\./\.\./src/" src/ test/
```

This file originally existed to answer the repo-placement question from a
measured coupling surface rather than an impression of one. That question is
now settled - this layer lives in `mcp-authority-boundary`, see `CLAIMS.md` -
so the file's remaining job is to keep the surface visible and small, and to
make it obvious if it starts growing.

## Runtime values imported (4 modules, 6 symbols)

| Module | Symbol | Used by | Why |
|---|---|---|---|
| `../../src/resolve.ts` | `resolveCall` | `src/mediator.ts` | Produce the canonical operation. **Deliberately not reimplemented** - a second resolver is a second opinion about what the operation is, which is audit finding A1. |
| `../../src/canonical.ts` | `sha256`, `canonicalJson` | `src/mediator.ts` | Hash-chain the mediation ledger with the same canonicalisation the boundary uses, so digests are comparable across the two layers. |
| `../../src/enforce.ts` | `EnforcementPoint` | `src/fixture.ts` | The real per-call layer. T1 is only meaningful if this is the shipped object. |
| `../../src/ledger.ts` | `Ledger` | `src/fixture.ts` | Required by `EnforcementConfig`. |
| `../../src/policy.ts` | `loadPolicy`, `loadEntities` | `src/fixture.ts` | Load the **unmodified** Cedar policy set, and append fixture entities through the `loadEntities(extra)` seam. |
| `../../src/tools.ts` | `snapshotDocuments`, `restoreDocuments` | `test/acceptance.test.ts` | Isolate the fixture world between tests. Test-only. |

## Types imported (type-only, erased at runtime)

`EnforcementPoint`, `ToolResult`, `EntityStore`, `LedgerEntry`, `ModelToolCall`,
`ResolvedOperation`, `Decision`, `EntityUid`, `WorldSnapshot`.

## The load-bearing coupling

Exactly one: **`ResolvedOperation` and its `operationSha256`**, the canonical
operation representation (`src/types.ts:41`). Everything else is either a
convenience (`Ledger`), a test utility (`snapshotDocuments`), or the per-call
layer itself, which any version of this would depend on anyway.

This layer never reads a model's raw arguments. That is not an accident of
implementation; it is the property that makes "what was mediated" and "what was
authorized" the same object, and it is why `mediator.ts` re-checks the digest
against the host's ledger entry after execution.

## What is NOT imported, and what this layer does not touch

- No Cedar policy is read, written, or extended by this layer. `policies/` is
  byte-identical to v1.0.0.
- `entities/entities.json` is not edited. Fixture entities are appended in
  memory via `loadEntities(extra)`.
- No file under `src/` is modified. The merge changed exactly three tracked
  files outside `containment/`: `tsconfig.json` (one entry added to `include`),
  `package.json` (one test glob added), and `docs/LIMITATIONS.md` (new L11).

## Build wiring

None specific to this layer. It compiles with the repository's single
`tsconfig.json` (which lists `containment/**/*.ts` alongside `src` and `test`)
and its tests run in the repository's single `npm test`, which is now 133 tests:
100 for the per-call boundary and 33 here.

That is the concrete payoff of merging. While this layer lived outside the repo
it needed a second `package.json`, a second `tsconfig.json`, a `#host/*` subpath
import map, a `hostsrc` symlink to obtain types (the repo builds with
`declaration: false`), and `dist/policies` and `dist/entities` symlinks to
satisfy `policy.ts`, which resolves those directories relative to
`import.meta.url`. All six pieces of scaffolding existed only to reach across a
repository boundary, and all six were deleted when that boundary went away.

## If it were ever extracted

The scaffolding above is what extraction costs, and it is worth recording that
none of it was the hard part. The hard part is that the coupling is to
`ResolvedOperation` and its digest, so a repository boundary there is a version
boundary on the exact representation whose divergence was audit finding A1.
`CLAIMS.md` states the full argument.
