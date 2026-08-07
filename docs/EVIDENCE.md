# Evidence

Everything in this document is produced by `npm run verify` and lands in `evidence/`.
The numbers come first, then the frame that says what they mean. The frame is the more
important half.

## Artifacts produced

| File | Contents |
|---|---|
| `evidence/ledger.jsonl` | Every authorization decision, hash-chained |
| `evidence/replay-report.json` | The verifier's findings and verdict |
| `evidence/metrics.json` | The counts below, machine-readable |
| `evidence/baseline.json` | What the same calls do with authorization removed |
| `evidence/transcript.md` | The full run, as printed |
| `evidence/attack-matrix.md` | Scenario to policy mapping |
| `evidence/screenshot.svg` | Terminal rendering of the run (`npm run screenshot`) |

## The counts

Reproduced verbatim from `evidence/metrics.json` on a clean run:

```
scenarios                                    24
ledger entries                               26
  allow                                       8
  deny                                       18
    explicit-forbid                          12
    no-matching-permit (Cedar default deny)   6
policy coverage (determining at least once)  15/15
forged authority fields stripped              4
tool executions                               7
tool-action allow decisions                   7
mediation invariant                          HOLDS
same calls, authorization removed            18 would execute
tests                                       100 passed
```

Replay, over the same ledger, in four separately-reported stages. They are never collapsed
into a single verdict, because the adversarial audit showed that a single `VERIFIED` hid an
authorization/execution divergence:

```
stage                checked  n/a  failures  verdict   establishes
chain-integrity           26    0         0  PASS      the file has not been edited or reordered
policy-replay             26    0         0  PASS      the decision is reproducible from the recorded
                                                       request (shares Cedar build + classifier)
auth-exec-binding         24    2         0  PASS      the recorded request is what the recorded
                                                       operation derives (shares the derivation fn)
effect-consistency         7   19         0  PASS      the world state observed after execution
                                                       matches the authorized operation
verdict  ALL STAGES PASS
```

Negative controls, run because a stage that has only ever passed is uncharacterised. Each
tamper turns exactly one substantive stage red and leaves the other green, which is what shows
these are four checks and not one check reported four times:

| Tamper | chain | policy-replay | auth-exec | effect |
|---|---|---|---|---|
| flip one `observedEffect.byteLen` | FAIL | PASS | PASS | **FAIL** |
| flip one recorded `operation.byteLen` | FAIL | PASS | **FAIL** | PASS |

The ledger is byte-identical across runs. Both the logical clock and the wall clock are
pinned, so the hash chain reproduces exactly:

```
sha256(evidence/ledger.jsonl) = 92aeae05964d0e39d2052e2c8bfb101189792953d104cef88642775e451ec464
```

## What frame these numbers were measured in

**Target population versus what was observed.** The intended question is about attacks on
MCP-mediated agents in general. What was observed is 24 scenarios that the author of the
policy set also wrote. This is the single largest caveat in the artifact and no other
caveat comes close. It is a hand-built corpus, not a sample of anything: it was not drawn
from incident data, from a red-team exercise, or from a benchmark suite. A different author
would have written different scenarios, and every count here would move.

**Unit of analysis.** One authorization decision, which is one ledger entry. n = 26. The
scenario count (24) is a different unit and the two are not interchangeable: two scenarios
contain two steps each, and S13 is one request evaluated under two policy versions.

**Denominator and exclusions.** The denominator is every step declared in
`src/scenarios.ts`. Nothing was excluded, and nothing failed to produce a decision.

The `policy coverage` figure has its own denominator, and that denominator was wrong in an
earlier version of this document. It counts the union of policy ids across every policy
version the run exercised, which is 15: the 14 base policies plus the one deployed by the
revocation overlay. Dividing by the base set alone put an overlay policy in the numerator
that was not in the denominator and reported 10/14 when the honest figure was 9 of 15 base
policies covered. The metric now names the uncovered policies rather than only counting
them, in `metrics.json`, so the figure is checkable rather than trusted. Coverage means
"Cedar reported this policy as determining for at least one decision", which is a weaker
property than "this policy has been tested": a policy can be determining once and still be
wrong in the cases nobody wrote a scenario for.

**Label scheme, and who authored it.** Two different things get labelled and they have very
different standing:

- *Which policy was determining*, and *whether the decision was allow or deny*, come from
  Cedar. They are instrument output, not author judgment.
- *Which scenarios count as attacks*, *what the expected outcome is*, and *which
  MCPSecBench class each maps to* are authored by one person with no second coder. These
  are trusted base. The MCPSecBench mapping in particular is an interpretation of that
  benchmark's classes, not something the benchmark asserts.

**Missing data.** Every step declared in `src/scenarios.ts` produced a ledger entry. A request
whose arguments the host cannot bind to a known resource also produces an entry, classified
`unresolvable-resource`, rather than being dropped.

One class of request produces no entry at all. It is recorded here rather than left for a
reader to discover, because a measurement section that claimed complete coverage of attempts
would be the exact failure this artifact is about. `isToolName` tests `name in TOOL_ACTION`,
and JavaScript's `in` operator walks the prototype chain, so a tool name that is an inherited
`Object.prototype` key (`constructor`, `toString`, `valueOf`, `hasOwnProperty`,
`isPrototypeOf`, `__proto__`) passes that guard. No `switch` branch then matches, the canonical
operation is never built, and the resolver throws.

Observed behaviour on the current build, over the MCP transport: the caller receives JSON-RPC
error `-32603`, no grant is minted, no tool runs, the fixture world is unchanged, the server
continues serving subsequent calls, and no ledger entry is written for the attempt. A sequence
of four calls in which one used such a name produced three entries. A genuinely unknown tool
name, by contrast, is denied and logged normally as `unresolvable-resource`.

This is fail-closed with respect to execution and it is not an authorization bypass: claims A,
B and D in the README are unaffected. What it does mean is narrower and worth stating plainly.
The ledger is a complete record of *decisions*, not of *attempts*, and the five denial kinds in
`src/types.ts` do not cover this outcome. Anyone treating the ledger as an exhaustive audit
trail of everything an agent tried should know that a request rejected by an exception upstream
of the decision point leaves no trace in it.

**Sensitivity.** The counts were re-derived under one alternative: running every scenario
through the in-process enforcement point (the test suite) instead of over the MCP
transport. Decisions, denial kinds and determining policies match. That varies the
transport and nothing else. It was **not** varied against a different policy set, a
different entity store, a different scenario ordering, or a different resolver, and the
result almost certainly depends on all four.

**Multiplicity.** The scenario list was iterated during development. Two scenarios were
reworked after their first outcome was not the one intended, and both reworks were the
result of finding a genuine defect rather than of tuning until the number looked right;
both defects are recorded below. No scenario was dropped for producing an inconvenient
result, and S18 exists specifically to keep an inconvenient result in view.

**What these numbers say nothing about.** They say nothing about how often these attacks
occur in the wild, nothing about what fraction of real attacks this design would stop,
nothing about whether a real model would comply with these injections in production,
nothing about performance under a policy set anybody else would write, and nothing about
Cedar's own correctness. `18/18 executed` in the baseline is a property of the scenario
set, not an estimate of exploitability.

## The one number that is not a sample statistic

The mediation invariant is different in kind from everything above. It is not measured over
a chosen corpus; it is a property checked over every entry of every run:

> No ledger entry carries a tool result unless its decision was `allow`, and every
> tool-action `allow` carries a tool result.

Checked in three places, deliberately: at runtime by `consumeGrant`, over the log by
`computeMetrics`, and again by the independent replay verifier. It can still only be
checked over runs that happened. It is not a proof that no run could violate it.

## What the verifier does when the record is wrong

A verifier that has only ever returned VERIFIED is untested. Two demonstrations, both
reproducible from the commands in [QUICKSTART.md](QUICKSTART.md):

**Flipping one recorded decision** produces four findings from three independent checks: a
hash mismatch at that entry, a cascade failure at the next, a re-decision disagreement, and
a mediation-invariant violation. The re-decision finding is the load-bearing one, because it
does not depend on the chain: it discards the recorded verdict and re-derives it from the
recorded request under the pinned policy. An attacker who recomputed the whole chain
correctly would still be caught by it.

**Changing a policy file** after a run flags every entry decided under the old version, by
comparing the recorded policy-set hash against the hash of the files on disk. This is what
makes drift between the policy that was reviewed and the policy that ran detectable rather
than assumed.

## Defects this apparatus found in itself

Recording these because a verification apparatus that has never caught anything is
untested, and because two of them are exactly the failure modes the artifact is about.

1. **Nested action groups gave write-tier sessions delete and shell.** The Cedar schema
   originally declared `dangerousGroup in [mutatingGroup]`, on the reasoning that deleting
   a file is a kind of mutation. Because `permit-write-tier` matches `action in
   mutatingGroup`, every write-tier grant silently acquired `delete_file` and
   `execute_shell`. Tier inheritance was being expressed twice, once in the Permission
   hierarchy and once in the action hierarchy, and the two multiplied. Found by working
   through S06's expected outcome by hand. Fixed by making the three action groups a
   partition. Pinned by `test/regression.test.ts`.

2. **Request ids collided across scenarios.** Ids were `<session>#<counter>` with the
   counter local to a server process. Each scenario spawns a fresh server, so the counter
   restarted and ids repeated across the ledger. The in-process single-use check could not
   see it, because the collisions were in different processes. Found by the replay
   verifier's duplicate-id check on its first run. Fixed by anchoring ids to the ledger
   position.

3. **Single-use enforcement keyed on a name rather than a capability.** The fix for (2)
   exposed the inverse: `spent` was a set of id strings, so two independent enforcement
   points in the same process could legitimately mint the same id and the second execution
   would be refused as a replay. Found by the test suite, which runs many enforcement
   points in one process. Fixed by tracking the grant object.

4. **The hash chain did not cascade.** `verifyChain` linked each entry to the previous
   entry's *recorded* hash. Editing an entry's content therefore failed only that entry's
   own hash check while every subsequent link still lined up, so tampering did not
   propagate. Found by a test that asserted the cascade and did not get it. Fixed by
   linking on the recomputed hash.

5. **The coverage metric had a mismatched denominator.** Described above. It inflated the
   reported figure, and it was found only because the number was checked against the list
   of policy ids by hand while writing this document, not by any test. That is the least
   comfortable finding here: a metric that reports a plausible number is not scrutinised
   the way a failing assertion is.

Findings 2, 3 and 4 were caught by the verification apparatus. Findings 1 and 5 were caught
by working a number out by hand, which is worth stating plainly: the apparatus catches
record-level and protocol-level defects well, and it caught nothing about whether the
policy expresses the intended authority, nor about whether a summary statistic over its own
output was computed correctly. Nothing in this repository checks that the policy set means
what its author intended it to mean. See [LIMITATIONS.md](LIMITATIONS.md), L2.
