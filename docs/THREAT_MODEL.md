# Threat model

## The adversary

**Fully in control of the language model.** Not "the model might be jailbroken" but "the
model is the attacker's". It emits whatever tool call the attacker wants, immediately, with
no resistance, no hesitation, and no alignment. This is the `ScriptedAdversary` in
`src/agent.ts`, and it is strictly stronger than any real model, which is why it is the
default rather than the optional path.

**In control of resource content.** Documents, database rows and tool outputs may contain
text written to manipulate the agent. The finance document in this artifact carries an HTML
comment addressed to AI assistants instructing them to exfiltrate it.

**In control of the client.** The attacker may replace the MCP client with one of their own
and speak the protocol directly (S14).

**In control of tool arguments.** Including arguments that look like authority claims:
`principal`, `permission`, `session_id`, `_authority_override` (S10).

**Able to induce delegation.** The attacker may attempt to have sub-sessions minted, and
may attempt to have them minted wider than the parent (S16).

## The adversary is NOT

- Able to execute code inside the server process.
- Able to modify the policy files, the entity store, or the server binary.
- Able to forge or choose the session bound to the transport.
- Able to move the host clock.
- Able to write to the ledger except through the enforcement point.

Those are the trust boundary. Each is stated as a premise in
[ASSUMPTIONS.md](ASSUMPTIONS.md), because an adversary who crosses any one of them defeats
the artifact entirely and no amount of policy will help.

## What is defended

The property under test:

> No tool action executes unless Cedar, evaluating the request that describes the effect
> that action would have, under the policy version recorded alongside it, returned `allow`.

This holds regardless of what the model emits, because the model's output is data that a
decision is made *about*, never an input the decision *trusts*. The scenarios exercise
prompt injection direct and indirect, tool misuse, the confused deputy, privilege escalation
by forged arguments, cross-resource access by path traversal, capability escalation by
delegation, expiry, revocation on both planes, and transport bypass.

## What is out of scope, and why it is not counted as caught

This boundary mediates tool *requests*. An attack that never becomes a tool request is
structurally beyond its reach, and the attack matrix marks such attacks out of scope rather
than claiming them.

| Out of scope | Why | What would actually cover it |
|---|---|---|
| Transport interception, MITM on stdio or a socket | Below the layer that decides | Channel authentication, mutual TLS |
| Host or OS compromise | Anything with code execution in the server process can mint its own grants and write a consistent ledger | Host integrity, attestation |
| Supply-chain substitution of the server or of Cedar | The gate is the thing being replaced | Signed builds, reproducible builds, SBOM |
| DNS or network redirection of a tool's egress | The tool's actual destination is resolved by the host below this layer | Egress policy at the network layer |
| Side channels in permitted output | Covered by no authorization decision | Output filtering, information-flow control |
| A second, ungoverned MCP server | This gate is at the boundary of *this* server | Governing the agent's whole tool surface |
| Denial of service | No policy denies it | Rate limiting, quotas |

The first two matter most. A hash-chained ledger is tamper-evident against post-hoc edits by
someone who has the file. It is not evidence against an adversary who was inside the process
when the entries were written, because such an adversary can write a perfectly consistent
chain describing events that never happened. See [LIMITATIONS.md](LIMITATIONS.md), L6.

## The attack that succeeds

Scenario **S18** is an attack that the boundary permits, correctly.

The injected payload asks the agent to forward the finance forecast to the user's own
internal inbox rather than to an outside address. Both steps are allowed: the session holds
write authority over internal mail and the forecast is inside its scope. No authority was
exceeded. The agent did something the user did not ask for, using authority the user gave
it.

This is the boundary of the whole approach, not a bug in this policy set. Authorization
answers "may this principal take this action on this resource". It does not answer "should
this action be taken now, given why the agent came to want it". A policy could be written to
make S18 fail, by forbidding any egress after an untrusted read regardless of destination,
and the cost would be an agent that cannot email the user about a document it just read. The
artifact keeps S18 permitted and visible rather than tuning the policy until every scenario
is a catch.

## Position of each mechanism

| Mechanism | In series or monitoring | Can it prevent? |
|---|---|---|
| Cedar PDP in front of dispatch | In series | Yes |
| `ExecutionGrant` requirement | In series | Yes |
| Path canonicalisation | In series | Yes |
| Identity-field stripping | In series | Yes |
| Turn-level taint flag | In series, but coarse | Yes, bluntly. See L4 |
| Hash-chained ledger | Monitoring | **No.** It records; it does not prevent |
| Replay verifier | After the fact | **No.** It detects; it does not prevent |

The last two rows are the ones to keep straight. The ledger and the verifier are evidence
mechanisms. They make a past decision inspectable and reproducible. They stop nothing, and
nothing in this artifact claims they do.
