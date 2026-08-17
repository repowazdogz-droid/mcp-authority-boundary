# Assumptions

Everything the artifact's claim rests on but does not itself establish. These are premises,
not findings. If one of them is false in a given deployment, the demonstration says nothing
about that deployment.

## A1. The Cedar engine is correct

Decisions are as sound as `@cedar-policy/cedar-wasm` 4.12.0. The artifact does not verify
Cedar, and its replay verifier cannot: replay re-runs the same engine, so agreement between
the original decision and the replayed one is agreement between a thing and a rerun of that
thing. It establishes reproducibility, not correctness.

Cedar is a reasonable thing to depend on here. It has a formal specification, a
differential-testing programme against a mechanised model, and default-deny semantics with
unconditional `forbid`. None of that is demonstrated by this repository, and none of it is
claimed as a result of this repository.

## A2. Session establishment is authenticated

The principal is read from `MCP_SESSION_ID` in the server's process environment at startup,
and is supplied by whoever launches the process. **Authenticated session establishment is
assumed, not implemented.** A real deployment would bind the session during an authenticated
handshake and that binding would be the security-critical step. Nothing in this repository
performs it, and possession of the launch path is therefore equivalent to possession of any
session named in it.

The artifact demonstrates enforcement only **after** a session identity has been supplied at
process launch. Within that boundary it establishes the narrower property that matters for the
research question: given a supplied session, the enforcement point fixes that identity for its
lifetime and nothing the model emits can change which session a decision is made under.
Scenario S10, `test/regression.test.ts` and `test/session-establishment.test.ts` exercise that.
Whether the supplied identity is genuine is assumed here, not shown.

Session identity is required and has no default. An absent or blank `MCP_SESSION_ID` refuses
startup with exit code 2, and an unrecognised one fails closed at the first decision. Until
2026-08-17 the server defaulted to `sess-alice-root` when the variable was unset, which meant a
launcher that omitted one environment variable ran as the highest-authority session in the
entity store rather than failing. That default is removed. Removing it does not authenticate
anything; it removes one hazard — a missing identity silently becoming the most privileged one.

## A3. The host process is not compromised

The enforcement point, the PDP, the tool layer and the ledger writer share a process.
Anything with code execution inside it can mint grants and write a self-consistent chain.
Process integrity is assumed and is the largest single assumption after A1.

## A4. Policy files and the entity store are trusted inputs

They are read from disk with no signature check. A deployment would need to know that the
policy set on disk is the one that was reviewed. The artifact hashes both and records the
hashes on every decision, so a change is *detectable* after the fact by anyone re-running
the verifier. Detectable is not prevented.

## A5. The clock is host-controlled

`context.now` is a logical clock injected at spawn and pinned per scenario so the run is
reproducible. In deployment this would be a real clock, and the ledger would no longer be
byte-identical across runs. Nothing about the decisions changes; only the reproducibility
property does.

## A6. The tool set is fixed and its actions are correctly classified

The tool-to-action mapping lives in the Cedar schema's action groups, so it cannot be
changed without editing a file the validator checks. `test/regression.test.ts` asserts that
the tools advertised over MCP and the tools the resolver can map are the same set, so a tool
cannot be exposed without being authorizable. That the classification is *right* — that
`delete_file` genuinely belongs in the dangerous tier — is a judgment call by the policy
author, not a verified property.

## A7. The resolver maps calls to the resources they actually touch

This is the correspondence premise and it is the most fragile one in the code. Cedar can
only be as correct as the request it is handed. If `resolve.ts` binds a call to the wrong
resource, the decision is a correct answer to the wrong question, and every downstream check
including replay will agree with it.

Where resolution is uncertain the code refuses rather than guesses, which converts a class
of correspondence errors into false denials. The SQL path is the clearest case: a regex is
not a parser, so any query the resolver cannot bind to exactly one known table is refused.
The consequence is denied legitimate queries, not permitted illegitimate ones. See
[LIMITATIONS.md](LIMITATIONS.md), L3.

## A8. Tool effects are simulated

No tool in this artifact shells out, sends mail, or touches a database. Effects are applied
to an in-process sandbox and recorded in an effect log, which is what the unmediated
baseline reads. This keeps the repository safe to clone and run. It also means the artifact
demonstrates that a *request* was refused, not that a real side effect was prevented, and
the gap between those two is the tool implementations, which are assumed to honour the
grant they were given.

## A9. The scenario set is authored, not sampled

Every scenario was written by the same person who wrote the policies. It is a hand-built
corpus. It is not a sample of real attacks, and no count derived from it estimates anything
about the world. This is stated as a measurement premise in [EVIDENCE.md](EVIDENCE.md) and
repeated here because it is the assumption most likely to be forgotten when a number is
quoted out of context.

## A10. A ledger records what happened

The chain proves the file has not been edited since it was written. It does not prove the
file describes reality. Nothing in the artifact witnesses the recording step itself. See
[LIMITATIONS.md](LIMITATIONS.md), L6.
