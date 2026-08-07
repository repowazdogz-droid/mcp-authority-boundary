// Policy-plane revocation.
//
// This file is NOT part of the base policy set. Loading it produces a different
// policy-set hash, which the ledger records as a distinct policy version. The
// revocation scenario runs the identical request against v1 and v2 and shows the
// decision flip, with both entries independently replayable against the policy
// version each was decided under.
//
// Two revocation mechanisms exist in this artifact and they are not the same
// thing: `forbid-revoked-session` in 20-guardrails.cedar revokes by flipping an
// attribute on the session entity (data plane, immediate, no deployment); this
// file revokes by deploying a new policy (control plane, auditable, versioned).

@id("revoke-session-analyst-delegated")
@doc("Incident response 2026-08-07: the delegated analyst session is revoked at the policy plane pending review.")
forbid (
  principal == Mcp::Session::"sess-analyst-delegated",
  action,
  resource
);
