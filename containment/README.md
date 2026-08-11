# Agent authority-containment layer

A minimal, falsifiable enforcement layer that catches **authority
amplification**: the case where every individual tool call is correctly
authorized, yet ordinary authorized resources compose into new effective
authority - without any call bypassing the per-call authorization layer.

It extends the Cedar per-call boundary in this repository. It does not replace
it.

> The per-call layer answers *was this call authorized?*
> This layer answers *does the authorized world itself contain dangerous authority paths?*

Read `CLAIMS.md` before citing anything here. Read `HONESTY.md` for what a green
test run does not tell you.

## Run it

From the repository root:

```
npm test
```

Expect 133 tests, 0 failures - 100 for the per-call boundary and 33 for this
layer (12 pure checker, 15 mediator, 6 acceptance tests T1-T5). This layer has
no build or test scaffolding of its own; it compiles with the repository's
`tsconfig.json` and runs in the repository's single test command.

To run only this layer's tests:

```
npm run build && node --test dist/containment/test/*.test.js
```

## The result

| | |
|---|---|
| **T1** | The per-call layer authorizes **every** call in the attack trace. Four steps, four Cedar `allow` verdicts, no `forbid` policy fired. The gap is real, not a strawman. |
| **T2** | The static checker flags `CRIT` on the shared resource, naming both agents as the witness. |
| **T3** | The runtime mediator blocks the external effect before Cedar is consulted, attributes it to the originating agent, and records why. |
| **T4** | The repaired deployment passes the checker with nothing outstanding - and T4b shows the repair re-routes the function through the mediator rather than deleting it. |
| **T5** | The attack cannot complete against the repaired deployment. The **per-call layer denies it unaided**, as `no-matching-permit`. |

T5 is the interesting one. The containment layer's job is not to sit in the path
forever catching this attack; it is to tell you that the declared topology is
wrong, so that fixing the topology makes the per-call layer sufficient on its
own.

## The attack

Two agents, each individually constrained. Neither is compromised in any way the
per-call layer can see - no injection, no forged identity, no malformed argument,
no policy mistake.

```
  agent A                         agent B
  scope: corp/finance             scope: corp/pubrel
     |                                |
     | 1. read q3-forecast.md         |
     |    (its own territory)         |
     v                                |
  [ corp/handoff/status.md ] <--------+  3. read
     ^   child of BOTH scopes            (its own territory)
     |   and mirrored to a partner portal
     | 2. write
     |                                |
     |                                v  4. publish onward
```

`corp/handoff` is a child of `corp/finance` **and** of `corp/pubrel`, because it
is where the two agents hand work to each other. Every step is inside the acting
agent's own scope. At the end, B - which has no authority over `corp/finance` -
is holding finance content, and step 2 was itself an external publication,
because the handoff directory is mirrored outside.

Cedar has no vocabulary for "this document is mirrored to a partner portal", so
the per-call layer cannot weigh that fact even in principle.

## Structure

| File | Lines | What |
|---|---|---|
| `src/graph.ts` | 254 | The capability graph and the C1/C2/CRIT/DECL invariants. **Pure - imports nothing.** |
| `src/deployments.ts` | 217 | Vulnerable and repaired deployments, each declared as a graph and as Cedar entities. |
| `src/mediator.ts` | 389 | Runtime effect-sink mediation, budgets, circuit breaker, ledger, in-series wrapper. |
| `src/fixture.ts` | 237 | The attack trace and the two drivers (raw per-call, and mediated). |
| `test/graph.test.ts` | 118 | The checker, in isolation. |
| `test/mediator.test.ts` | 189 | Classification, fail-closed, budgets, rate limit, breaker, delegation, ledger. |
| `test/acceptance.test.ts` | 194 | T1-T5. |

`src/graph.ts` is the independently testable core: a total function from a
declared graph to a list of violations, with no dependency on Cedar, on a policy
set, or on a running agent.

## Static and runtime are different halves

**Static** covers the declared graph. It cannot see resources created at runtime
- which is how the real incident this fixture is modelled on survived
revocation, by encoding messages in newly created directory names.

**Runtime** covers effects as they happen, including writes to resources nobody
declared (refused, fail-closed). It cannot see a dangerous shape that no agent
happens to exercise.

Neither is complete. Both are conditional on the declaration being truthful.

## Constraints this build accepted

The general safety question for access-control systems is undecidable (Harrison,
Ruzzo and Ullman 1976), and channels below a model's resource granularity are
not addressed by anything at that granularity (Lampson 1973). This layer is a
decidable check over a bounded, declared deployment model and claims nothing
beyond it.

## Relationship to the per-call boundary

Cedar policies are byte-identical to v1.0.0 and `entities/entities.json` is
untouched; fixture entities are appended in memory through the existing
`loadEntities(extra)` seam. `IMPORTS.md` lists the exact coupling surface - four
modules, six runtime symbols, one of them load-bearing.

**The claims are separate.** This layer does not strengthen, weaken or restate
the boundary's claims A-D, and those claims do not depend on anything here. See
`docs/LIMITATIONS.md` L11, which states the separation and repeats the three
limitations of this layer that a reader must not miss, and `CLAIMS.md` for what
this layer does and does not establish.
