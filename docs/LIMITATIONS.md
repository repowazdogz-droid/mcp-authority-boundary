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

**Do not read claims A, B and D as implying C.** The README lists four claims deliberately
apart: mediation, authorization binding, policy adequacy, and effect verification. This
artifact supports A, B and D and explicitly does not support C, and keeps two live
counterexamples to C (findings A2 and A6) rather than closing them, because an artifact that
demonstrated only successes would be less useful.

The property "no sequence of prompts can cause execution of a tool action that Cedar denies"
is universally quantified over an infinite set. It is not established by running 24
scenarios, and this artifact does not claim to have established it.

What is actually supported, in decreasing order of strength:

1. **A construction argument, runtime-checked.** The tool layer is unreachable without a
   grant that only the PDP mints after an `allow`. Forging, reusing and bypassing are each
   tested and each fails. This is an argument about this codebase, not a theorem.
2. **A ledger-level invariant, checked over every run.** No entry carries a tool result
   without an `allow`; every tool-action `allow` carries a result. Checked at runtime, in
   the metrics, and again by the independent verifier.
3. **A scenario set.** 24 authored scenarios, all matching their declared outcomes.

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
  compares two things derived by different routes, and even it compares a recorded world
  observation against a fresh derivation rather than re-observing the world, which is
  impossible once the process is gone. The stage table in `EVIDENCE.md` states what each buys.

The check in replay that carries real weight is the one that discards the recorded verdict
entirely and re-derives it from the recorded request plus the policy files on disk, which
the verifier holds independently of the log. That is a genuine reconstruction. It is not an
independent oracle.

## L7. Effects are simulated, and the effect check inherits that

No real shell command runs, no real mail is sent, no real database is queried. The
effect-consistency stage reads back an in-process fixture world, so claim D is scoped to
"the observed fixture state transition matches the authorized operation" and no further. A
real filesystem brings symlinks, races, partial writes and permissions, none of which this
fixture has. Whether a real tool would honour the operation it was handed is exactly the
question the fixture cannot answer.

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
