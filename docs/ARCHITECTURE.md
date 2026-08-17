# Architecture

## The shape

```
  user turn
      |
      v
  +--------------+
  |  LLM agent   |   emits { tool: string, args: object }
  +--------------+   nothing else. It cannot name a principal,
      |              set a clock, or reference a policy.
      v
  +--------------+
  |  MCP client  |   forwards verbatim. No checks here, deliberately.
  +--------------+
      |
      |  JSON-RPC over stdio
      v
+=========================================================+
|  MCP SERVER PROCESS                                     |
|                                                         |
|   session identity  <---- bound at spawn, out of band   |
|   clock             <---- () => number, read PER decision|
|   entity store      <---- () => store,  read PER decision|
|   policy set        <---- loaded from disk, hashed      |
|                                                         |
|   1. resolve.ts   validate types (reject, never coerce) |
|        canonicalise paths and addresses                 |
|        bind to a real resource entity                   |
|        -> ONE frozen ResolvedOperation                  |
|                  |                                      |
|                  v                                      |
|   2. pdp.ts       request DERIVED from the operation    |
|                   Cedar isAuthorized(...)               |
|                   -> allow | deny + determining ids     |
|                   -> anything else maps to DENY         |
|                  |                                      |
|                  |  grant bound to sha256(operation)    |
|                  v                                      |
|   3. tools.ts     executes the operation. No raw args.  |
|                  |                                      |
|                  v                                      |
|   4. observe      read the world back; compare to the   |
|                   authorized effect; throw on mismatch  |
|                  |                                      |
|                  v                                      |
|   5. ledger.ts    append, hash-chained. Denials too.    |
+=========================================================+
```

## Why the gate is in the server and not between client and server

The natural reading of "authorization layer between the MCP client and the MCP server" puts
a proxy in the middle. This artifact does not do that, and the reason is the second and
third questions you should ask of any safeguard.

**Position.** A control is in series when it sits on the only path to the action and can
prevent it. A control that observes alongside can be ignored. A client-side check is in
series only with respect to *that client*.

**Route choice.** The actor being constrained is the agent, and the agent chooses which
client code runs. If complying means routing through a checking client and bypassing means
opening a socket, then the check governs the traffic that chose to arrive. Its clean logs
are then a selection effect rather than evidence, because the callers who went around it
are precisely the ones missing from the record. This is Saltzer and Schroeder's
psychological-acceptability principle read from the attacker's side: the sanctioned path has
to be the cheapest one, or it is not the path.

Putting the gate behind the transport makes compliance unavoidable rather than cheap. Every
caller traverses it, including one written to avoid it.

**Scenario S14 is the negative control for this claim.** `src/rawclient.ts` imports nothing
from `src/client.ts`. It spawns the server and writes newline-delimited JSON-RPC at it. If
the gate were in the client, that scenario would execute the delete. It denies, with the
same determining policy as the cooperative path.

The corresponding honest statement: this places the gate at the boundary of *this* server.
It does not defend against an agent that has a second, ungoverned MCP server available, and
it does not defend against tampering with the server binary. Both are in
[THREAT_MODEL.md](THREAT_MODEL.md).

## The binding between authorization and execution

The pipeline produces exactly one canonical object and everything else is derived from it:

```
raw call
  -> validate every field to its expected type, REJECTING wrong types (no coercion)
  -> canonicalise paths and addresses
  -> freeze a ResolvedOperation carrying every security-relevant execution value
  -> derive the Cedar request from the operation      (cedarRequestFromOperation)
  -> decide
  -> mint a grant bound to sha256(operation)
  -> executeTool(operation, grant); consumeGrant re-derives the digest and compares
  -> observe the fixture world and compare to the authorized effect
```

`executeTool` takes no raw arguments and `src/tools.ts` contains no reference to `call.args`,
so the two-readers-disagree failure the audit exhibited (A1) has no place to occur. A
regression test asserts both properties over the source text, because the guarantee is
structural and a future edit could quietly remove it.

## Correspondence: the request must describe the effect, not the label

A gate that checks a label passes anything wearing the label. Every input to the decision is
therefore derived from what the tool would actually do:

| Field | Derived how | Attack it closes |
|---|---|---|
| `principal` | Read from `MCP_SESSION_ID` in the process environment at startup; supplied by whoever launches the process. Required, with no default: an absent or blank value refuses startup. Authentication of that binding is assumed, not implemented — see [A2](ASSUMPTIONS.md) | S10: forged `principal` in the arguments |
| `action` | Fixed mapping from tool name, declared in the schema | Tool cannot be silently reclassified |
| `resource` | Path canonicalised, then looked up in the entity store | S11: `corp/public/../finance/...` |
| `context.byteLen` | Measured from the payload to be written | A declared `length` argument is not consulted |
| `context.recipientDomain` | Parsed from the resolved mailbox | |
| `context.now` | Host clock function, called per decision | The model cannot move time; a live session still expires |
| `context.sourceTrust` | Whether the turn has read a resource | S07: indirect injection |

Arguments matching an identity-shaped key, or beginning with `_`, are stripped before
resolution and recorded in the ledger as `ignoredModelFields`. The attempt is evidence, so
it is retained rather than discarded silently.

## Fail-closed classification

Cedar answers `deny` in structurally different situations, and collapsing them produces
explanations that are confidently wrong. `pdp.ts` separates four:

| Situation | Recorded as |
|---|---|
| A forbid policy matched | `explicit-forbid`, with the ids |
| Nothing matched | `no-matching-permit` (Cedar's default deny) |
| A policy errored during evaluation | `evaluation-error` |
| The request did not typecheck against the schema | `request-validation-failure` |

The third case is the one that has to be got right. When a policy errors, Cedar skips it and
continues. A skipped policy might have been a forbid, so an `allow` returned alongside
evaluation errors is not a decision anyone should act on. **This PDP treats any evaluation
error as a denial, including when Cedar itself said allow.** `test/failclosed.test.ts` pins
all four.

A fifth case never reaches Cedar at all: a call the host cannot bind to a real resource is
refused as `unresolvable-resource`, rather than being authorised against a guessed one.

## Complete mediation, made structural

`tools.ts` exposes no function that takes a plain argument list. Every tool requires an
`ExecutionGrant`, whose constructor rejects any caller that does not hold a module-private
symbol, and which is additionally checked against a `WeakSet` of grants this process
actually minted. Only `pdp.ts` mints one, and only after Cedar returned `allow`.

The grant carries the digest of the authorized operation, and `consumeGrant` recomputes that
digest from the operation being executed. A grant is therefore spendable on exactly one
operation, not merely on one tool name.

Four ways round it are tested and all four fail: constructing a grant directly, constructing a
look-alike with the right prototype and fields, reusing a spent grant, and obtaining a second
minting capability (`claimMinter` is one-shot and the PDP claims it at module load).

This is a construction argument about this codebase, not a theorem about MCP servers. It is
backed by a runtime check and by a ledger-level invariant, both described in
[EVIDENCE.md](EVIDENCE.md).

## Delegation and the attenuation argument

Minting a delegated session is itself an authorization decision. The parent session is the
principal, the proposed child is the resource, and `permit-delegate-attenuated` is the
definition of attenuation: the child's capability tier, resource scope, validity window and
write budget must each be no wider than the parent's, it must name the parent it descends
from, and it must sit exactly one hop deeper.

Two of those dimensions are enforced structurally rather than by comparison. Capability
tiers form an entity hierarchy (`read in write in admin`) and scopes form another, so
`resource.permission in principal.permission` is a transitive containment test that Cedar
evaluates directly. Narrowing is picking a descendant.

Because every hop passes the same policy, the argument runs by induction: if every session
in a chain was minted under this policy, the leaf's authority is contained in the root
grant's. That is an argument about this policy set, exercised by
`test/attenuation.test.ts`. It is **not** a machine-checked proof, and it has a stated
premise: that no session enters the store by any other route.

That premise is load-bearing, so the artifact does not rely on it alone.
`forbid-widening-delegation` re-checks the invariant against the immediate parent at every
decision, so a session that somehow appeared already widened is still refused (S17). The
depth bound is explicit because Cedar has no recursion, and `forbid-revoked-ancestor` makes
revoking a parent take its children down without enumerating them (S22).

## Two revocation mechanisms, and why both are here

- **Data plane** (S21): flip `revoked` on the session entity. The entity store is read on
  every decision, so this takes effect on the next decision in an already-running process,
  with no deployment and no restart. That sentence was false until the adversarial audit
  (finding A4) caught the store being cached for the life of the process; test `A4` now holds
  it true by flipping the file under a running enforcement point.
- **Control plane** (S13b): deploy a forbid policy. This changes the policy-set hash, so the
  ledger records it as a distinct version, and both the before and after entries replay
  correctly against the version each was decided under.

They have different operational properties and the artifact demonstrates both rather than
picking one.

## Why the policy set is loaded, not embedded

`policy.ts` reads the `.cedar` files, extracts each policy's `@id` annotation, validates the
whole set against the schema in **strict** mode, and hashes the schema plus every policy
source. A set that does not typecheck never reaches a decision; the load throws. The hash is
recorded on every ledger entry, which is what lets `replay.ts` confirm that the policy on
disk is the policy that made the decision.

A policy without an `@id` is a load-time error. An unnamed policy cannot be cited in an
explanation, and an explanation that cannot name its rule is not an explanation.
