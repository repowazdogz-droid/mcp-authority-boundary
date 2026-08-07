# Repair record

Date: 2026-08-07. Follows `docs/AUDIT.md`, which stays intact: nothing there has been
deleted, softened, or rewritten to look anticipated. This file records what changed, and it
records the repaired claim as a **new** claim rather than backdating the original.

## The claim that died, and the one that replaced it

| | |
|---|---|
| **Original claim** | "A compromised or adversarial LLM cannot cause execution of a tool action that Cedar denies, because authorization is enforced independently at the MCP boundary." |
| **Witness** | `write_document` with `content: [<100,000 chars>]`. `resolve.ts` measured only strings and substituted `''`, so Cedar authorized a 0-byte write; `tools.ts` coerced with `String()` and wrote 100,000 bytes under a 4096-byte cap. |
| **Which step failed** | Not the decision. The *correspondence* between the request Cedar was given and the operation that executed. Two code paths independently read `call.args` and disagreed. |
| **Repaired claim** | "For every mediated tool execution, the operation executed is derived from the same canonical, validated representation that Cedar authorized." |
| **Judgment** | **PRINCIPLED**, not witness-excluding. See below. |

### Why this is a principled repair and not a patch around the witness

A witness-excluding repair would have been: reject arrays in `content`. That closes the one
exhibited input and leaves the class untouched, and the next `{}`, `null`, or number lands
again.

What was done instead removes the *possibility of a second reader*. There is now exactly one
place where an argument becomes a validated value (`asString` in `resolve.ts`, which refuses
rather than converts), exactly one object carrying every security-relevant execution value
(`ResolvedOperation`, deep-frozen), and the execution layer has no access to the raw
arguments at all — `executeTool(op, grant)` takes no `args` and `src/tools.ts` contains no
reference to `call.args`. A condition anyone would have accepted before seeing the witness:
*the thing authorized and the thing executed must be the same object*.

The test that distinguishes the two repairs is `F1`, which sweeps ten non-string types across
all ten string-valued fields of all six tools — 100 combinations — and requires every one to
fail closed before Cedar. A witness-excluding fix would pass one of those and fail 99.

## What changed

**1. One canonical representation.** `raw call → validate + canonicalise once → frozen
ResolvedOperation → Cedar request derived from it → decide → grant bound to its digest →
execute exactly it → observe the world → compare.` The Cedar request is produced by
`cedarRequestFromOperation(op)`, not assembled alongside the operation, so there is no second
derivation to drift.

**2. The grant binds to the operation, not the tool name.** `consumeGrant` recomputes the
operation's digest at execution time and refuses on mismatch. This closes audit finding A5
(the grant carried a resource nothing checked) as a consequence rather than as a separate fix.

**3. The bypass is gone.** `executeTool` no longer takes `unsafe_bypassAuthorization`, which
closes A9. The unmediated baseline no longer executes anything: it resolves each attacker call
and reports the canonical operation that *would* run. The reported figure is now "18 would
execute", which is a weaker and more accurate statement than the previous "18 executed".

**4. A defect the audit missed, found while repairing it.** `mintGrant` was a plain export, so
any module could mint a grant and complete mediation rested on nobody doing so — the same
"property of callers" weakness as A9, one layer down. Minting is now a one-shot capability:
`claimMinter()` hands it out once, `pdp.ts` claims it at module load, and every later caller
throws. Pinned by a test.

**5. Time is read per decision.** `now: () => number`. Demonstrated through the real MCP
transport: one server process, four calls at t=2000/4000/6000/8000 against a grant expiring at
5000, giving allow, allow, deny, deny with no restart.

**6. The entity store is read per decision.** `entities: () => EntityStore`. Flipping `revoked`
on disk now changes the next decision in a running process, which is what `ARCHITECTURE.md`
already claimed. The claim and the code now agree.

**7. The verifier reports four stages, never collapsed.** See `docs/EVIDENCE.md`.

## A residual the repair introduced, found by the post-repair falsification pass

`send_email` read its body as `clean['body'] ?? ''`, so an explicit `null` was treated as an
absent field and coerced to the empty string — the same reject-versus-coerce mistake as A1,
reintroduced two hours after fixing it, in code whose comment claimed nothing was coerced.

No authorization/execution divergence resulted (both sides saw `''`), so it was a claim defect
rather than a security defect. It was caught by `F1` sweeping `null` across every field, not by
review, and it is recorded here rather than quietly corrected because the pattern is the
interesting part: the general fix was applied in nine places and missed in two, and only the
exhaustive sweep found the gap.

Absence and wrong-type are now distinguished explicitly (`'body' in clean ? … : ''`).

## Findings deliberately NOT fixed

Left open, with scope stated, because closing them would change the policy set or the
threat model rather than the binding this repair is about:

- **A2** transitive attenuation laundering. Kept as the concrete policy-adequacy
  counterexample: the implementation is correct relative to a policy that does not express
  the intended property. The exact grandparent clause that would close it is in `AUDIT.md`.
- **A6** destructive SQL authorized as a read-only action. **Severity changed by this repair,
  and the change is recorded rather than claimed as a fix.** `statementClass` is now computed,
  carried on the operation, recorded in the ledger, and included in the effect fingerprint, so
  a `DELETE` is visible as `mutating` in the evidence. The policy still authorizes it under
  `permit-read-tier`. A6 moves from *invisible* to *recorded but not gated*: MITIGATED, not
  CLOSED. `F6b` asserts both halves.
- **A7** the closed-world entity store denies legitimate actions before Cedar. Unchanged.

## Verification of the repair

```
demo    24 scenarios, 26 ledger entries, 8 allow / 18 deny, coverage 15/15
replay  chain-integrity PASS 26 | policy-replay PASS 26
        auth-exec-binding PASS 24 (2 n/a) | effect-consistency PASS 7 (19 n/a)
tests   100 pass, 0 fail
ledger  byte-identical across runs, sha256 92aeae05964d0e39d2052e2c8bfb101189792953d104cef88642775e451ec464
```

Negative controls, because a stage that has only ever passed is uncharacterised:

- Tampering one `observedEffect` turns **effect-consistency** red and leaves
  auth-exec-binding green.
- Tampering one recorded `operation` turns **auth-exec-binding** red and leaves
  effect-consistency green.

Both also break chain integrity, as they should. The two tampers hitting different stages is
what shows the stages are four checks rather than one check reported four times.
