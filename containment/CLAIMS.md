# Claims

What this layer enforces, what it does not, and the threat model it assumes.
Read `HONESTY.md` alongside it for the weaknesses found while building.

---

## The problem it addresses

The per-call authorization layer in this repository answers: **was this call
authorized?** It answers it well - complete mediation, execution bound to the
authorized canonical operation, fail-closed on every ambiguity.

It cannot answer: **does the authorized world itself contain dangerous authority
paths?** Two agents, each correctly constrained, sharing one ordinary resource,
compose into effective authority neither was granted - without a single call
being unauthorized. `test/acceptance.test.ts` T1 exhibits that: four calls, four
Cedar `allow` verdicts from `permit-read-tier` and `permit-write-tier`, no
`forbid` policy even close to firing, and at the end an agent with no authority
over `corp/finance` is holding finance content and has published it onward.

This layer is an addition to that boundary, not a replacement for it. T5 is the
demonstration that they are complementary: after the topology repair, the
per-call layer denies the attack unaided.

## What it enforces

**Statically, over the declared graph** (`src/graph.ts`, a pure function):

- **C1** - a resource written by one agent principal and read by a different
  agent principal must be declared-and-mediated.
- **C2** - a resource that is egress-bearing and writable by any agent principal
  must be declared-and-mediated.
- **CRIT** - a resource satisfying both, unmediated, is flagged critical. This is
  the amplification shape.
- **DECL** - mediation claimed by an agent principal, or by an undeclared one, is
  refused rather than honoured. Without this, any deployment could silence the
  checker by naming one of its own agents as the mediator.

"Declared-and-mediated" means the authority edge is owned by a principal of kind
`mediator`. A path routed through another agent is not mediated.

**At runtime, in series** (`src/mediator.ts`): operations are authorized at the
security-sensitive consequence rather than at the tool-call entry. The mediated
sinks are egress writes, cross-principal channel writes, credential use, network
connections, creation of an undeclared resource, and delegation. Each decision is
attributed to the originating agent principal, metered against a per-principal
egress budget and rate limit, subject to a per-principal circuit breaker, and
appended to a hash-chained ledger.

Runtime authorization consumes the host's frozen `ResolvedOperation` and its
digest - never the model's raw arguments - and re-checks that digest against the
host's ledger entry after execution.

## What it does NOT do

**It does not solve confinement.** The general safety question for
access-control systems is undecidable (Harrison, Ruzzo and Ullman 1976). This is
a decidable check over a bounded, declared model. Any reading of this artifact
that implies general containment is wrong.

**It does not address covert channels below its resource granularity.** Its unit
is a declared resource. Timing, ordering, sizes, error rates, and encodings in
names or metadata are all below that resolution and it says nothing about them
(Lampson 1973). The real-world incident this fixture is modelled on survived
revocation by encoding messages in newly created directory names - which is
precisely a channel below the granularity of anything declared in advance.

**It does not cover undeclared resources except by refusing them.** A resource
absent from the declared graph is denied at runtime as `namespace-creation`
(fail-closed), which is a refusal, not an analysis.

**It does not verify the declaration.** See `HONESTY.md` H2. A wrongly declared
`egress` flag produces a confident, wrong, clean result from both halves.

**It does not detect an adversary operating below the model's resolution** -
inside a resource, inside a single principal, or through a mediator it has been
told to trust.

**It is not structurally unbypassable.** See `HONESTY.md` H1.

## Threat model

**Principals.** A fixed, declared set, partitioned into agent principals and
mediator (system) principals. In the fixture: two agents, one mediator. Agents
are assumed to be fully compliant with any instruction that reaches them, i.e.
an agent will attempt anything its authority permits. Mediators are TRUSTED and
nothing here constrains a compromised one.

**Resources.** A fixed, declared set, each with per-principal read/write access,
an `egress` flag, and an optional mediator. Resources created during a run are
outside the static model and are refused at runtime.

**Egress points.** Only those declared. In the fixture, one:
`corp/handoff/status.md` is mirrored to a partner-facing portal (vulnerable), and
after repair that capability moves to `corp/portal/published.md`, written only by
the mediator.

**Time window.** One logical session at a fixed clock (`NOW = 5000`), inside
every declared session's validity window. Budgets and rate limits are per
principal within that window. Nothing here reasons about authority accumulating
across sessions, or about revocation.

**Assumed sound and inherited from the host** (`docs/THREAT_MODEL.md`): sessions
are bound out of band and cannot be minted or named by a model; the Cedar engine
and policy set are correct; the enforcement point is the only path to the tool
layer; effects are simulated against an in-process fixture world.

**Out of scope.** Model behaviour, prompt injection (the host addresses that
separately), destructive operations such as deletion, availability, and anything
requiring information-flow tracking through argument construction.

## Repo placement - DECIDED

**Merged into `mcp-authority-boundary` as `containment/`, 2026-08-11.** Decided
by the maintainer after the build; logged in the durable decision record. The
trade-off observed while building, which is what the decision rested on, is
below.

**For a separate repo:** the checker is genuinely independent. `src/graph.ts` is
254 lines, imports nothing at all, and its 12 unit tests run without Cedar, a
policy set, or an enforcement point. That is a real asset and it does not need
the host to be worth anything.

**For merging, and this is the stronger side:**

1. *The coupling that matters is irreducible and central.* The whole design rests
   on mediating the host's canonical `ResolvedOperation` rather than re-parsing
   arguments. A separate repo does not reduce that coupling, it just makes it a
   version boundary - and a version skew in exactly that representation
   reintroduces the divergence class the host's audit finding A1 was about.
2. *The structural fix requires host edits.* `HONESTY.md` H1 lists four host
   locations that would have to change for the mediator to be unbypassable
   rather than in-series-by-convention. Outside the repo, that fix is
   permanently unavailable, and the layer stays weaker than it needs to be.
3. *The host actively resists external consumption right now.* It builds with
   `declaration: false`, so a consumer gets no types; and `policy.ts` pins
   `POLICY_DIR`/`ENTITY_FILE` relative to `import.meta.url`, so a consumer must
   arrange the directory layout the host expects. Both are one-line host
   changes, and both can only be made inside the host.
4. *T1 needs the real thing.* The fairness assertion is only worth stating
   because it runs the shipped `EnforcementPoint` against the shipped policy set.
   A stand-in per-call layer would make the whole demonstration a strawman.

The counter-argument, which was real and was addressed rather than dismissed:
the repository is a released, tagged (`v1.0.0`) research artifact with a
carefully bounded set of claims, and adding a second layer with its own separate
claims risks blurring what that artifact establishes. The mitigation is
`docs/LIMITATIONS.md` **L11**, written as part of the merge, which states that
these claims are additional and separately scoped, that claims A-D are unchanged
and do not depend on this layer, and that L1 ("authorization bounds authority,
not intent") is adjacent to but NOT the same gap - L1 is about authority versus
intent for one principal, this layer is about per-call versus composed authority
across several. L11 also repeats this layer's three load-bearing limitations, so
that reading `docs/LIMITATIONS.md` alone cannot leave a stronger impression than
the artifact supports.

### Structural mediation - DONE

The weakness recorded here as "not done" has since been closed. Effect mediation
is mandatory: `EnforcementConfig.mediator` is required, `EnforcementPoint.handle`
mediates every operation before authorization, and `consumeGrant` refuses to
execute without a mediation record bound to the grant, naming the operation, and
carrying an `allow` verdict. `MediatedSession` - the wrapper callers could
decline to use - is deleted.

Three honest qualifications, all detailed in `HONESTY.md` H1 and H3:

- **Unbypassable is not contained.** `permitAllMediator()` satisfies the
  mechanism and permits everything, saying so in every ledger record. What sits
  behind mediation is a deployment choice.
- **Delegation is not covered.** It mints no grant and runs no tool, so
  capability creation remains Cedar-gated only. A real remaining gap.
- **Two things were lost.** The cross-layer digest re-check is gone (one
  resolution now, nothing to compare), and T1 asserts that the real PDP allows
  the four attack operations rather than that the enforcement point executes
  them. The execution half moved to T1b, against a deployment configured to
  permit every effect.

