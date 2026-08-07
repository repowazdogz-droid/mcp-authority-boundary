# Quickstart

Fifteen minutes, in order.

## 0. Run it (about 30 seconds)

```bash
npm install
npm run verify
```

Node 20.11 or newer. No API key, no network after `npm install`, no other toolchain. You
should see 24 scenarios, a replay verdict of `VERIFIED`, and 66 passing tests.

## 1. Read the policy set first (5 minutes)

The policies are the artifact. The TypeScript exists to put requests to them.

```
policies/mcp.cedarschema          start here: everything the engine may reason about
policies/00-least-privilege.cedar three permit tiers, no blanket permit anywhere
policies/10-delegation.cedar      attenuation, minting, chain invariants
policies/20-guardrails.cedar      absolute forbids
policies/overlay-revocation/      a revocation, deployed as a new policy version
```

Two things to notice in the schema. The capability tiers `read in write in admin` form an
entity hierarchy, so `Permission::"write" in principal.permission` is a transitive
containment test rather than a set comparison. The three action groups deliberately do
**not** nest, and the comment explains what went wrong when they did.

## 2. Watch the run (3 minutes)

```bash
npm run demo
```

Each scenario prints the tool call the model emitted, the decision, the determining policy
ids, a prose explanation derived from those, any authority fields stripped from the model's
arguments, and the ledger position and hash.

The four to look at:

- **S07** indirect prompt injection. The payload is in the *document*, and the session doing
  the reading is the fully privileged root session. The denial comes from a forbid rule that
  no grant can buy back.
- **S10** privilege escalation by forged arguments. Watch the `ignored model-supplied
  authority fields` line.
- **S14** transport bypass. Same denial, from a client that imports none of this
  repository's client code.
- **S18** the negative control. Both steps ALLOW, correctly. Read the note under it.

## 3. Verify it independently (2 minutes)

```bash
npm run replay
```

This discards every recorded verdict and re-derives it from the recorded request plus the
policy files on disk, then checks chain integrity, policy pinning, and the mediation
invariant. Then break something and watch it fail:

```bash
# flip a recorded decision in the middle of the ledger
sed -i.bak '10s/"decision":"deny"/"decision":"allow"/' evidence/ledger.jsonl
npm run replay
mv evidence/ledger.jsonl.bak evidence/ledger.jsonl
```

One edit, four independent findings:

```
chain integrity  BROKEN
findings         4
  #9  [chain-integrity] hash mismatch: recorded bab897f0483f, recomputed 46547844139c
  #10 [chain-integrity] prevHash bab897f0483f does not match the previous entry's
                        recomputed hash 46547844139c
  #9  [re-decision]     recorded allow, re-decided deny
  #-1 [mediation]       7 executions against 8 tool-action allow decisions
```

The third of those is the one that matters. The first two say the file was edited. The third
discards the recorded verdict entirely, re-derives it from the recorded request against the
pinned policy, and disagrees. That check would still fire if the attacker had recomputed
every hash in the chain correctly.

Or change a policy and replay an old ledger against it:

```bash
npm run demo
# append any rule to a .cedar file, then:
npm run replay
#   #20 [policy-pinning] recorded policy hash 478baf45f1b3 but policy files on
#                        disk hash to c9577e6aa14d
```

Every entry decided under the changed version is flagged. The ledger says which policy set
made each decision, so drift between "the policy we reviewed" and "the policy that ran" is
detectable rather than assumed.

## 4. Check the numbers (2 minutes)

```bash
cat evidence/metrics.json
cat evidence/replay-report.json
```

Then read [EVIDENCE.md](EVIDENCE.md), which states what frame those numbers were measured
in. The short version: the scenario set is authored by the same person who wrote the
policies, so the counts describe the artifact and not the world.

## 5. Try to break it (as long as you like)

Add a scenario to `src/scenarios.ts` with the outcome you expect, then run `npm test`. A
scenario whose declared expectation does not match reality fails the build.

Things worth attempting:

- A tool call whose arguments name a different session, in any spelling.
- A path that reaches outside the session's scope by some route canonicalisation misses.
- A delegation proposal that widens one dimension while narrowing the others.
- A SQL query that binds to a table the session may reach while touching one it may not.
- A sequence that gets a tool to run without a preceding `allow` in the ledger.

The last one is the actual research question. If you find it, the construction argument in
[ARCHITECTURE.md](ARCHITECTURE.md) is wrong, and that is the most useful thing you could
report.

## Optional: a real model

```bash
export ANTHROPIC_API_KEY=...
npm run demo:live
```

This answers a different and weaker question than the default run. See
[LIMITATIONS.md](LIMITATIONS.md), L9.
