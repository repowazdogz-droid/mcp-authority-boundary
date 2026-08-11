# Honesty notes

Things that are true about this layer and are not visible from a passing test
run. `CLAIMS.md` states the scope of what is enforced; this file records the
weaknesses found while building it, including the ones no test can fail on.

---

## H1. The mediator is in series by construction of the call path, not structurally

`MediatedSession.handle` runs the mediator before the host enforcement point, so
a denial there means Cedar is never consulted and the effect never occurs. T3
asserts exactly this: the blocked step has `cedar === null`.

That is real, and it is weaker than it sounds. **Anyone holding the underlying
`EnforcementPoint` can call it directly and skip this object entirely.** The
fixture does precisely that on purpose - `harness({mediated: false})` hands out
raw drivers, which is how T1 and T5 obtain unmediated Cedar verdicts. The same
door is open to any other caller.

So the containment layer is in series for callers who go through it, which is a
statement about how the system is assembled, not a property of the system.

The host solved the equivalent problem for itself and the fix is instructive.
`src/mediation.ts` makes tool execution require an `ExecutionGrant`, and the
capability to mint one is claimed exactly once, at module load, by the PDP:

```ts
export function claimMinter(): Minter {
  if (minterClaimed) throw new Error('...already been claimed by the PDP');
  ...
}
```

A second minting path cannot be added by importing the module - it has to be
added by editing that file, which is a reviewable act. Applying the same shape
here would mean the tool layer requiring evidence of mediation in addition to
its grant, which means changing `consumeGrant`, `ExecutionGrant`, and the PDP
that mints it.

**Coupling points that a structural fix would have to touch** (found by building
against them, listed for whoever does the work):

| Host location | What would change |
|---|---|
| `src/mediation.ts` - `ExecutionGrant` | Carry a mediation attestation alongside `operationSha256`. |
| `src/mediation.ts` - `consumeGrant` | Verify that attestation, and refuse without it, the way it already refuses on a digest mismatch. |
| `src/pdp.ts` - `authorize` | Accept the mediation record as an input to minting, so an unmediated allow cannot produce a spendable grant. |
| `src/enforce.ts` - `EnforcementPoint.handle` | Either call the mediator itself, or stop being publicly constructible. |

None of that is possible from outside the host repo. This is the single
strongest argument in the repo-placement question, and it is an argument for
merging.

## H2. Every guarantee is conditional on the declaration being truthful

The static checker reads the DECLARED graph. `egress` in particular is a
human-supplied claim: Cedar has no vocabulary for "this document is mirrored to
a partner portal", which is exactly why the per-call layer cannot weigh it, and
exactly why nothing verifies it either.

An operator who omits the `egress` flag from a resource that has it gets a clean
`check()` and a mediator that permits the write. Both layers agree, confidently,
and both are wrong. There is no test in this repo that can fail on that, because
the layer's input is the declaration.

This is the same class as the host's `docs/LIMITATIONS.md` L2 - "nothing checks
that the policy means what its author intended" - moved up one level. The
containment layer inherits it and adds a second instance of it.

The runtime half narrows this but does not close it. A write to a resource
absent from the declared graph is classified `namespace-creation` and denied
(`test/mediator.test.ts`, "an undeclared target fails closed"), so an
*undeclared* resource is caught. A resource that is declared but declared
*wrongly* is not.

## H3. The digest re-check catches representation drift, not semantic drift

After execution, `MediatedSession.handle` compares the digest it mediated
against `entry.operationSha256` from the host ledger and throws
`RepresentationDriftError` on a mismatch. That catches the case where the object
this layer reasoned about is not the object the host authorized.

What it does not catch: both layers agreeing on an operation that means
something other than what either believes. The two resolutions share
`resolveCall`, so they share its bugs - if the SQL table regex mis-parses a
query into a plausible wrong table (the host's L3), both layers agree on the
wrong answer and the check passes. It is a consistency check between two uses of
one function, not an independent oracle.

`RepresentationDriftError` is also **not exercised by any test**, because no
input has been found that produces a divergence. It is a live assertion, not a
demonstrated catch, and it should not be cited as one.

## H4. What the fixture does and does not establish

It establishes that *this* amplification, in *this* declared deployment, passes
the per-call layer and is caught by this one. Five acceptance tests and one
attack trace are an existence proof about a shape, not coverage of a class.

Specifically not established:
- that C1/C2/CRIT are the right invariants, or a complete set, for any real deployment;
- that the repair generalises - it was constructed for this fixture;
- anything about deployments with more than two agents, delegation chains at
  runtime, or resources created during the run.

## H5. Effects are simulated, inherited from the host

No real network connection opens, no real credential is spent. `execute_shell`
and `query_database` are classified as credential-bearing sinks and unit-tested
as such, but the fixture never exercises them against anything real. The host's
`docs/LIMITATIONS.md` L7 applies unchanged.

## H6. One author

The invariants, the deployment declarations, the attack trace and the repair
were all written by the same author in one session, and the attack was written
knowing the invariants. The host repo says the same of itself (L8). Two defects
were found by tests during the build - a mislabelled sink kind, and a wrong test
assumption about channel classification - which is evidence the tests do
something, and not evidence that the design is right.
