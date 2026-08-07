// Delegated authority and attenuation.
//
// Minting a sub-grant is an authorization decision like any other. The parent
// session is the principal, the proposed child session is the resource, and the
// permit below is the definition of "attenuation": a child may narrow every
// dimension and widen none.
//
// Because every hop is evaluated by this same policy, and Cedar's `in` is
// transitive, the leaf session's authority is contained in the root grant's by
// induction over the chain. That argument is stated in docs/ARCHITECTURE.md and
// exercised by test/attenuation.test.ts; it is an argument about this policy
// set, not a machine-checked proof.

@id("permit-delegate-attenuated")
@doc("A live session may mint a child session whose capability, scope, validity window and write budget are all no wider than its own.")
permit (
  principal is Mcp::Session,
  action == Mcp::Action::"delegate",
  resource is Mcp::Session
)
when {
  // capability tier: child's tier must sit at or below the parent's
  resource.permission in principal.permission
  // resource scope: child's scope must be the parent's scope or a subtree of it
  && resource.scope in principal.scope
  // temporary capability: the child's window must be inside the parent's
  && resource.notBefore >= principal.notBefore
  && resource.expiresAt <= principal.expiresAt
  // quantitative budget may only shrink
  && resource.maxWriteBytes <= principal.maxWriteBytes
  // the chain must actually be recorded, and must point at this parent
  && resource has delegatedFrom
  && resource.delegatedFrom == principal
  && resource.depth == principal.depth + 1
  // a parent may only delegate while its own authority is live
  && context.now < principal.expiresAt
  && context.now >= principal.notBefore
  && !principal.revoked
};

@id("forbid-widening-delegation")
@doc("Defence in depth: even if a child session is introduced by some path other than the delegate action, it can never out-rank the grant it claims to descend from.")
forbid (
  principal is Mcp::Session,
  action,
  resource
)
when {
  principal has delegatedFrom
  && !(principal.permission in principal.delegatedFrom.permission
       && principal.scope in principal.delegatedFrom.scope
       && principal.expiresAt <= principal.delegatedFrom.expiresAt
       && principal.maxWriteBytes <= principal.delegatedFrom.maxWriteBytes)
};

@id("forbid-revoked-ancestor")
@doc("Revoking a parent grant takes its children down with it, without having to enumerate them.")
forbid (
  principal is Mcp::Session,
  action,
  resource
)
when {
  principal has delegatedFrom && principal.delegatedFrom.revoked
};

@id("forbid-excessive-delegation-depth")
@doc("Bounded delegation chains. Cedar cannot express unbounded recursion, so the depth bound is explicit rather than implied.")
forbid (
  principal is Mcp::Session,
  action,
  resource
)
when {
  principal.depth > 2
};
