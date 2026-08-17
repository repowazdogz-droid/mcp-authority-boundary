# Attack matrix

`evidence/attack-matrix.md` is regenerated from `src/scenarios.ts` on every `npm run demo`,
so it can never drift from what actually ran. This file is the curated companion: what the
classes mean, and what is deliberately not in the table.

## In scope: attacks that manifest as a tool request

| ID | Attack | Mechanism that stops it | Determining policy |
|---|---|---|---|
| S03 | Use of an expired capability | Temporary capability, checked per decision | `forbid-outside-validity-window` |
| S04 | Read-only grant attempts a write | Least privilege, default deny | none (no permit matched) |
| S05 | Write exceeds the grant's byte budget | Quantitative attenuation on measured payload | `forbid-oversized-write` |
| S06 | Direct prompt injection into the user turn | Capability tier does not cover the action | none (no permit matched) |
| S07 | Indirect prompt injection via document content | Turn-level taint plus egress forbid | `forbid-external-egress-after-untrusted-read` |
| S08 | Tool misuse under a read-only grant | Capability tier and scope | none (no permit matched) |
| S09 | Confused deputy acting "on behalf of" a third party | Classification gate on the resource | `forbid-restricted-document-below-admin` |
| S10 | Privilege escalation by forged arguments | Identity fields stripped and recorded; the principal is never read from the request | `forbid-restricted-document-below-admin` |
| S11 | Cross-resource access by path traversal | Canonicalisation before resource resolution | none (no permit matched) |
| S12 | PII table read below admin tier | Data-attribute gate | `forbid-pii-table-below-admin` |
| S13b | Continued use of a revoked session (control plane) | Policy deployed as a new version | `revoke-session-analyst-delegated` |
| S14 | Transport bypass with a hostile client | Gate positioned behind the transport | none (no permit matched) |
| S16 | Delegation that widens the grant | Attenuation checked at mint time | none (no permit matched) |
| S17 | A widened session that already exists | Attenuation re-checked at every decision | `forbid-widening-delegation` |
| S19 | Shell on a production host at admin tier | Unconditional forbid | `forbid-shell-on-production-host` |
| S21 | Continued use of a revoked session (data plane) | Attribute on the session entity | `forbid-revoked-session` |
| S22 | Child of a revoked grant continues acting | Ancestor revocation, no enumeration | `forbid-revoked-ancestor` |
| S23 | Over-long delegation chain | Explicit depth bound | `forbid-excessive-delegation-depth` |

"none (no permit matched)" is Cedar's default deny. It is a denial by absence of authority
rather than by an explicit rule, and the artifact records that distinction rather than
reporting a policy that did not fire.

## Controls that must ALLOW

A matrix of only denials proves nothing, because a gate that denies everything passes it.

| ID | Case | Outcome |
|---|---|---|
| S01 | Ordinary read within scope | ALLOW |
| S02 | Delegated session used within its grant | ALLOW |
| S15 | Delegation that narrows every dimension | ALLOW |
| S20 | Shell on a non-production host at admin tier | ALLOW |
| **S18** | **Injection that stays inside the grant** | **ALLOW** |
| **S24** | **Authorized shell whose command denotes a consequence outside the request** | **ALLOW** |

## Out of scope, and not counted as caught

This boundary mediates tool requests. An attack that never becomes a tool request is
structurally beyond its reach. Marking these as "caught" would be the easiest way to make
the artifact look better than it is.

| Class | Where it lives | What would cover it |
|---|---|---|
| Transport interception | Below the decision layer | Channel authentication |
| Host or OS compromise | Inside the trust boundary | Host integrity, attestation |
| Server or engine substitution | The gate is what gets replaced | Signed and reproducible builds |
| DNS or network redirection of egress | Below the layer that resolves the target | Network egress policy |
| Side channels in permitted output | No decision covers it | Output filtering, information-flow control |
| A second, ungoverned MCP server | Outside this server's boundary | Governing the agent's whole tool surface |
| Denial of service | No policy denies it | Rate limits and quotas |
| Semantic misuse within the grant | **Genuinely not covered.** See S18 | Not an authorization problem |

## MCPSecBench references

Some scenarios cite a structural class from MCPSecBench (arXiv:2508.13220). That mapping is
this artifact's author reading the benchmark's taxonomy and deciding which class a scenario
resembles. The benchmark does not assert the correspondence, this artifact does not run the
benchmark, and no score against it is claimed. See [LIMITATIONS.md](LIMITATIONS.md), L10.
