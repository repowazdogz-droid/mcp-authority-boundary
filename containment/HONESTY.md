# Honesty notes

Things that are true about this layer and are not visible from a passing test
run. `CLAIMS.md` states the scope of what is enforced; this file records the
weaknesses found while building it, including the ones no test can fail on.

---

## H1. The mediator is structurally unbypassable (as of the H1 change)

**This entry previously said the opposite, and the old text is kept below because
the history matters more than a tidy document.**

### What holds now

Effect mediation is mandatory and enforced at the point of execution:

- `EnforcementConfig.mediator` is required, with no default and no optional
  marker. A deployment must choose what sits behind mediation.
- `EnforcementPoint.handle` mediates every operation between resolution and
  authorization. A denial means no grant is minted at all.
- `consumeGrant` refuses to execute without a mediation record whose digest is
  the one the grant is bound to, whose `operationSha256` is the operation being
  executed, and whose verdict is `allow`.

Holding an `EnforcementPoint` therefore no longer buys an unmediated execution,
which is exactly what it used to buy.

### What this does NOT mean

**It does not mean every deployment contains effects.** `permitAllMediator()`
permits everything and stamps `NO_MEDIATION_CONFIGURED` into every record it
issues. A deployment using it has effect mediation in the mechanical sense and
no effect containment in the useful sense. That is a deployment choice, visible
in the config and in every ledger entry, and it is the exact analogue of L2: a
permissive policy is enforced faithfully. Do not read "structurally
unbypassable" as "contained".

**It does not cover delegation.** `handleDelegation` mints no grant and runs no
tool, so it is outside the mechanism entirely. Capability creation is one of the
effect sinks this layer classifies, and at the enforcement point it is still
Cedar-gated only. That is a real remaining gap, not an oversight.

**The negative controls are what make this believable, and they were not free.**
When the refusals were first switched on, the entire suite stayed green - not
one existing test reached them, because the existing `consumeGrant` tests pass
non-grant objects that throw at the first check. A guarantee whose failure path
is never taken is not demonstrated. Each of the four refusals is now made to
fire, with a positive control proving they do not simply block everything, and
the whole set was verified by mutation: with the checks disabled, exactly the
four negative controls fail.

### What it said before, and why

> The mediator is in series by construction of the call path, not structurally.
> `MediatedSession.handle` runs the mediator before the host enforcement point,
> so a denial there means Cedar is never consulted and the effect never occurs.
> That is real, and it is weaker than it sounds. Anyone holding the underlying
> `EnforcementPoint` can call it directly and skip this object entirely. The
> fixture does precisely that on purpose - `harness({mediated: false})` hands
> out raw drivers, which is how T1 and T5 obtain unmediated Cedar verdicts. The
> same door is open to any other caller. So the containment layer is in series
> for callers who go through it, which is a statement about how the system is
> assembled, not a property of the system.

`MediatedSession` no longer exists. Its deletion is the change, not a side
effect of it: a wrapper that callers may decline to use cannot carry a security
property, and the fix was to move the obligation to the point where execution
actually happens.

The cost was paid by T1, which had been using that same bypass. See H3.

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

## H3. The digest re-check is GONE, and T1 now claims less

Two things changed here and both are losses worth stating plainly.

### The differential check was removed

Previously `MediatedSession.handle` resolved the call independently, mediated on
that result, then compared its digest against the host's ledger entry and threw
`RepresentationDriftError` on a mismatch. With mediation inside
`EnforcementPoint.handle` there is exactly one resolution, so there is nothing
left to compare and the check is deleted.

It was never worth much - it compared two uses of one shared function
(`resolveCall`), so if that function mis-parsed, both layers agreed on the wrong
answer and the check passed - and it never caught anything: no input producing a
divergence was ever found. **It must not be cited, in its old form or its
absence, as a demonstrated catch.** But removing an unexercised check is still
removing a check, and it is recorded here rather than quietly dropped.

### T1 asserts something narrower than it used to

T1 used to assert that the per-call layer both AUTHORIZED and EXECUTED all four
steps of the attack, and it obtained that by routing through
`harness({mediated: false})` - the bypass.

It now asserts only that **the real PDP allows all four operations**, obtained
from `Pdp.decide`: the same engine, the same unmodified policy set, the same
request derivation, and no grant minted, so it neither needs mediation nor
circumvents it. The enforcement point no longer executes step 2, because the
mediator refuses it.

The fairness assertion survives in substance - the gap is real, every individual
call is authorized, no `forbid` fires, nothing is a strawman. But "authorized"
and "executed" are different claims and only the first is now made. Keeping a
test-only bypass to preserve the stronger-sounding one would have resurrected
precisely the flag audit finding A9 removed, which is not a trade worth making
for a test.

The execution half is demonstrated separately, in **T1b**, against a deployment
configured with `permitAllMediator()`. That is not a bypass: the mechanism runs
in full and the deployment has chosen to permit every effect, which is what any
deployment that has not adopted effect containment looks like.

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
