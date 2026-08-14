# Limitations

Read this before citing the artifact. Each entry names something the artifact does **not**
establish, and where possible points at the scenario or test that makes the gap visible
rather than leaving it as prose.

---

## L1. Authorization bounds authority, not intent

The central limitation, and the reason scenario **S18** is in the demo output rather than in
this file alone.

An agent that has been compromised can still do harm using authority it legitimately holds.
S18 is the indirect-injection attack from S07 with the exfiltration target changed to the
user's own inbox: both steps are allowed, correctly, because the session holds write
authority over internal mail and the document is inside its scope.

"May this principal take this action on this resource" and "should this action be taken now,
given why the agent came to want it" are different questions. This artifact answers the
first. Nothing here answers the second, and a policy engine is the wrong shape of tool for
it.

## L2. Nothing checks that the policy means what its author intended

The artifact verifies that decisions follow from the policy set. It has no way to check that
the policy set expresses the authority anybody intended to grant.

This is not hypothetical. The first version of the Cedar schema declared
`dangerousGroup in [mutatingGroup]`, which silently gave every write-tier session
`delete_file` and `execute_shell`. Cedar validated it, every test passed, and every decision
was correctly derived from a policy set that granted more than intended. It was found by
working an expected outcome out by hand, not by any mechanism in this repository.

A policy that is wrong will be enforced faithfully.

## L3. The correspondence layer HAD known defects; some are closed, one remains

**Read `docs/AUDIT.md` and `docs/REPAIR.md` before relying on this section.** An adversarial
audit of this artifact falsified its original central claim by exhibiting a working
authorization/execution divergence (A1), and found two further correspondence defects (A3, A4).
All three are closed and are pinned by before/after regression tests.

What is closed: type confusion between the measuring path and the executing path, because
there is now one validated frozen operation and the tool layer has no access to raw arguments;
a frozen clock, because time is read per decision; a cached entity store, because it is read
per decision.

What remains, unchanged by the repair:

Cedar can only be as correct as the request it is handed. `resolve.ts` is the code that
turns a tool call into that request, and it is ordinary, unverified TypeScript.

The SQL resolver extracts table names with a regular expression, which is not a parser. It
refuses anything it cannot bind to exactly one known table, so its failure mode is false
denials rather than false allows, but a query it mis-parses into a *plausible* single table
would be authorised against the wrong resource, and every downstream check including replay
would agree with it. The statement class is now recorded alongside the table, which makes a
mis-classification visible in the evidence without preventing it.

Path canonicalisation has the same shape and is better tested, but it is `posix.normalize`
plus a prefix check, not a filesystem-level guarantee. It knows nothing about symlinks,
because the documents here are an in-memory map rather than real files.

## L4. Taint tracking is a turn-level flag, not information flow

`context.sourceTrust` becomes `tool_output` once the agent has read anything in the current
turn, and drives one forbid rule about external egress. That is all it is.

It has no notion of *which* content flowed into *which* argument. It over-blocks: an agent
that reads a public roadmap cannot then email an outside address for the rest of the turn,
even though nothing sensitive was involved. It also under-blocks in the obvious direction,
since a fresh turn clears it. `test/injection.test.ts` demonstrates both the set and the
reset explicitly.

Real information-flow control would track provenance through argument construction. That is
a substantially harder problem and this is not an approximation of it.

## L5. The security property is demonstrated, not proven

**Do not read claims A and B as implying C or D.** The README lists four claims deliberately
apart: mediation, authorization binding, policy adequacy, and effect verification. This
artifact supports A and B; it explicitly does not support C, and keeps two live
counterexamples to C (findings A2 and A6) rather than closing them, because an artifact that
demonstrated only successes would be less useful; and D is not established by the shipped
evidence at all (L7).

The property "no sequence of prompts can cause execution of a tool action that Cedar denies"
is universally quantified over an infinite set. It is not established by running 25
scenarios, and this artifact does not claim to have established it.

What is actually supported, in decreasing order of strength:

1. **A construction argument, runtime-checked.** The tool layer is unreachable without a
   grant that only the PDP mints after an `allow`. Forging, reusing and bypassing are each
   tested and each fails. This is an argument about this codebase, not a theorem.
2. **A ledger-level invariant, checked over every run.** No entry carries a tool result
   without an `allow`; every tool-action `allow` carries a result. Checked at runtime, in
   the metrics, and again by the independent verifier.
3. **A scenario set.** 25 authored scenarios, all matching their declared outcomes.

A machine-checked proof would need a formalisation of the enforcement point, not just of the
policy language. That is not in scope here.

## L6. The ledger cannot witness itself

The hash chain proves the file has not been edited or reordered since it was written. Any
change to a past entry breaks that entry's hash and, because links are recomputed rather
than read, every link after it. `test/replay.test.ts` demonstrates edits, deletions, and a
re-hashed forgery.

It proves nothing about whether the log reflects reality. An adversary with code execution
inside the server process can write a perfectly consistent chain describing events that
never occurred. The chain is tamper-evidence against later editing, not evidence of faithful
recording.

Two consequences worth stating separately:

- **Truncation of the tail leaves a valid prefix.** Dropping the last N entries produces a
  ledger that verifies cleanly. The chain gives integrity and ordering, not completeness.
  There is a test that asserts exactly this, deliberately, so the gap is visible rather than
  implied.
- **Replay shares the engine, and three of its four stages share more.** Stage 2 shares the
  Cedar build and the classifier; stage 3 shares the request-derivation function; only stage 4
  compares two things derived by different routes, and it does so **for two of the six tools,
  neither of which the shipped ledger ever executes** (L7), and even then it compares a recorded
  world observation against a fresh derivation rather than re-observing the world, which is
  impossible once the process is gone. The stage table in `EVIDENCE.md` states what each buys.

The check in replay that carries real weight is the one that discards the recorded verdict
entirely and re-derives it from the recorded request plus the policy files on disk, which
the verifier holds independently of the log. That is a genuine reconstruction. It is not an
independent oracle.

## L7. Effects are simulated, and for four of six tools the check is not an observation

**Released v1.0.0 overstated this claim; the correction is in the README, under the claim
table.** `test/evidence-composition.test.ts` guards against the combination recurring.

No real shell command runs, no real mail is sent, no real database is queried. The
effect-consistency stage reads back an in-process fixture world, so claim D is scoped to
"the observed fixture state transition matches the authorized operation" and no further. A
real filesystem brings symlinks, races, partial writes and permissions, none of which this
fixture has. Whether a real tool would honour the operation it was handed is exactly the
question the fixture cannot answer.

**This entry used to stop there, and stopping there overstated claim D.** The correction is
recorded rather than applied silently. Claim D is not uniform across the six tools, because
the two sides of the comparison do not come from different places for all of them:

| Tool | What `observeEffect` reads | Independent of the operation? | Executions in the shipped ledger |
|---|---|---|---|
| `write_document` | re-reads the `documents` map | **Yes.** A tool that wrote elsewhere, or wrote something else, is caught | **0** (two denials). Demonstrated instead in `test/external-effect.test.ts` |
| `delete_file` | checks absence in the `documents` map | **Yes** | **0** (two denials). Demonstrated nowhere |
| `read_document` | tail of `readLog` | **No** | 5 |
| `send_email` | tail of `outbox` | **No** | 1 |
| `execute_shell` | tail of `shellLog` | **No** | 2 |
| `query_database` | tail of `dbLog` | **No** | 0 (one denial) |

**The right-hand column is the one that decides what claim D is worth, and an earlier draft of
this entry omitted it.** The two tools with independent read-back are the two the ledger never
executes: every `write_document` and `delete_file` entry is a denial. So all eight of stage 4's
checks in the shipped evidence are the weak kind, and the stage establishes nothing about
independent observation no matter how green it reports. Adding a successful write or delete
scenario purely to change that would be manufacturing coverage, so the claim is narrowed
instead.

For the bottom four, `executeTool` appends that log entry *from the operation it was handed*,
in the same call. So `expectedEffectOf(op)` and `observeEffect(op)` are two derivations of one
object rather than two views of a world.

That does not make the comparison dead, and an earlier draft of this entry said it did. It
fires if the tool records something other than what it was authorized to do: mutating
`executeTool` to log an altered host, recipient or path makes the corresponding scenario fail.
What it cannot detect is a divergence between that record and a real effect, because for these
four tools the record is the only world there is. It checks the tool against its own account of
itself, which is a narrower thing than the two rows above, and it was being reported alongside
them without the distinction.

`test/external-effect.test.ts` pins both halves: tampering with the `documents` map behind the
tool's back turns the `write_document` check red, and `observeEffect` on a shell operation that
was never executed returns the fingerprint of the one that was — it does not read its argument
at all. Both assertions were mutation-tested: breaking either branch of `observeEffect` fails
exactly the corresponding test.

**Read claim D as: NOT established by the shipped evidence.** Independent fixture read-back is
implemented for `write_document` and `delete_file` only; the ledger executes neither, so every
stage-4 check it contains is consistency of the record with itself. The read-back is
demonstrated for `write_document` in `test/external-effect.test.ts`, by tampering with the
`documents` map behind the tool's back and requiring the check to go red, and it is
demonstrated for `delete_file` nowhere at all. The `effect-consistency` line in the replay
output and the stage table in `EVIDENCE.md` are worded to match; this is the same distinction
L6 draws about the ledger, arriving one layer down.

## L8. One policy set, one entity store, one author

The scenario set, the policy set and the entity store were written by the same person, and
the scenarios were written knowing the policies. Coverage of 15/15 means every policy was
determining at least once; it does not mean every policy is correct, and it certainly does
not mean the policy set is complete for any real organisation.

No second author, no second coder for the attack classification, and no adversarial review
by someone who did not write the policies.

## L9. The live-model mode measures something different

`npm run demo:live` replaces the scripted adversary with a real Claude model. If it complies
with an injection and Cedar denies the result, that is evidence about model behaviour under
these particular prompts on a particular day. It is not evidence about the boundary, which
is already tested against a strictly stronger adversary that always complies.

It is also nondeterministic, needs network and an API key, and breaks ledger
reproducibility. It is off by default for those reasons.

## L10. MCPSecBench class references are the author's mapping

Where a scenario cites a structural class from MCPSecBench (arXiv:2508.13220), that mapping
was made by this artifact's author by reading the benchmark's taxonomy. It is an
interpretation. The benchmark does not assert these correspondences, this artifact does not
run the benchmark, and no score against it is claimed.

## L11. The containment layer's claims are ADDITIONAL and SEPARATELY SCOPED

`containment/` holds a second layer, added after this artifact's v1.0.0 release. Read this
entry before reading anything across the two as one set of claims, because they are not one
set of claims.

**Nothing in `containment/` strengthens, weakens, or restates claims A, B, C or D.** Those
four are about the per-call boundary: complete mediation, authorization-execution binding,
policy adequacy, effect verification. They stand exactly as they did at v1.0.0, established
by exactly the evidence they were established by, and the containment layer neither adds to
that evidence nor depends on being believed for any of it. Its own claims live in
`containment/CLAIMS.md` and are scoped there; its own weaknesses live in
`containment/HONESTY.md`. Neither file amends this one.

**It is a different gap from L1, and the resemblance is the trap.** L1 says authorization
bounds authority but not intent: a compromised agent can still do harm with authority it
legitimately holds, and no policy engine answers "should this action be taken now, given why
the agent came to want it". That is a claim about ONE principal and its intent.

The containment layer addresses something else: authority that exists in the deployment but
belongs to NO principal individually. Two agents, each correctly constrained, each acting
entirely within its own scope and with no compromised intent anywhere, compose through one
shared resource into effective authority neither was granted. `containment/` T1 exhibits
this against the unmodified policy set in this repository - four calls, four Cedar `allow`
verdicts from `permit-read-tier` and `permit-write-tier`, no `forbid` policy fired - after
which an agent holding no authority over `corp/finance` is holding finance content.

L1 is about the gap between authority and intent. L11 is about the gap between per-call
authority and composed authority. An artifact that closed L1 completely would still have
this one, and vice versa. Do not cite either as covering the other.

**Three limitations of that layer are load-bearing and are repeated here** so that reading
this file alone cannot leave a reader with a stronger impression than the artifact supports:

- **Effect mediation is mandatory, and that part IS structural now.** This entry
  originally said the opposite, and the change is recorded rather than silently
  corrected. `EnforcementConfig.mediator` is required with no default;
  `EnforcementPoint.handle` mediates every operation before authorization, so a
  refusal means no grant is minted; and `consumeGrant` refuses to execute
  without a mediation record bound to the grant, naming the operation being
  executed, and carrying an `allow` verdict. Holding an `EnforcementPoint` no
  longer buys an unmediated execution. **But do not read "unbypassable" as
  "contained":** `permitAllMediator()` permits every effect and stamps that fact
  into every ledger entry, and a deployment using it has mediation in the
  mechanical sense and no containment in the useful sense - the same relationship
  L2 describes between a permissive policy and faithful enforcement. Delegation
  is NOT covered: it mints no grant and runs no tool, so capability creation
  remains Cedar-gated only, which is a real remaining gap.
- **Every guarantee is conditional on the declaration being truthful, and nothing verifies
  it.** The static checker reads a DECLARED graph, and the `egress` flag on a resource is a
  human-supplied claim that no mechanism in this repository checks - Cedar has no vocabulary
  for "this document is mirrored to a partner portal", which is precisely why the per-call
  layer cannot weigh it and precisely why nothing validates it either. An operator who omits
  that flag from a resource that has it gets a clean `check()` and a permissive mediator,
  both confident and both wrong. This is L2 ("nothing checks that the policy means what its
  author intended") reappearing one level up, and the containment layer inherits it rather
  than fixing it.
- **The cross-layer digest re-check has been REMOVED, and T1 claims less than it
  did.** `RepresentationDriftError` compared two independent resolutions of the
  same call; with mediation inside `handle` there is only one resolution, so the
  check is gone. It never caught anything and was never an independent oracle -
  it compared two uses of one shared function - so it must not be cited as a
  demonstrated catch in either its old form or its absence. Relatedly, T1 now
  asserts that the real PDP **allows** all four attack operations, not that the
  enforcement point **executes** them; the enforcement point does not, because
  mediation refuses step 2. The execution half is shown separately in T1b,
  against a deployment configured to permit every effect. Preserving the older,
  stronger-sounding T1 would have required a test-only bypass, which is the flag
  audit finding A9 removed.

The containment layer accepts the same two bounds this artifact does and adds no exception
to either: the general safety question for access-control systems is undecidable (Harrison,
Ruzzo and Ullman 1976), and channels below a model's resource granularity are not addressed
by anything operating at that granularity (Lampson 1973).
