// Least privilege: there is no blanket permit anywhere in this policy set.
//
// Cedar is default-deny. Nothing below grants authority that is not tied to
// BOTH a capability tier and a resource scope, and every permit additionally
// requires the session to be inside its validity window. Three policies, one
// per tier, keyed on the action groups declared in mcp.cedarschema.
//
// Reading `Permission::"write" in principal.permission`: the tier the action
// REQUIRES must be a descendant of the tier the session was GRANTED. Because
// read in write in admin, an admin session satisfies all three tests and a
// read session satisfies only the first.

@id("permit-read-tier")
@doc("A session granted read (or above) may perform read-only actions on resources inside its scope, while its capability is live.")
permit (
  principal is Mcp::Session,
  action in Mcp::Action::"readOnlyGroup",
  resource
)
when {
  Mcp::Permission::"read" in principal.permission
  && resource in principal.scope
  && context.now >= principal.notBefore
  && context.now < principal.expiresAt
};

@id("permit-write-tier")
@doc("A session granted write (or above) may perform mutating actions on resources inside its scope, while its capability is live.")
permit (
  principal is Mcp::Session,
  action in Mcp::Action::"mutatingGroup",
  resource
)
when {
  Mcp::Permission::"write" in principal.permission
  && resource in principal.scope
  && context.now >= principal.notBefore
  && context.now < principal.expiresAt
};

@id("permit-admin-tier")
@doc("A session granted admin may perform dangerous actions on resources inside its scope, while its capability is live.")
permit (
  principal is Mcp::Session,
  action in Mcp::Action::"dangerousGroup",
  resource
)
when {
  Mcp::Permission::"admin" in principal.permission
  && resource in principal.scope
  && context.now >= principal.notBefore
  && context.now < principal.expiresAt
};
