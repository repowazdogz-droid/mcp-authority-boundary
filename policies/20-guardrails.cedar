// Absolute limits. In Cedar, forbid beats permit unconditionally, so nothing
// below can be bought back by a broader grant, a delegation, or a policy added
// later. These are the rules that survive a fully compromised agent.

@id("forbid-outside-validity-window")
@doc("Temporary capability. A session that has expired, or has not yet begun, can do nothing at all - including delegate.")
forbid (
  principal is Mcp::Session,
  action,
  resource
)
when {
  context.now >= principal.expiresAt || context.now < principal.notBefore
};

@id("forbid-revoked-session")
@doc("Data-plane revocation: flipping one attribute on the session entity kills it on the next decision, with no policy deployment.")
forbid (
  principal is Mcp::Session,
  action,
  resource
)
when {
  principal.revoked
};

@id("forbid-shell-on-production-host")
@doc("No shell on a production host, at any capability tier. An admin grant does not buy this back.")
forbid (
  principal is Mcp::Session,
  action == Mcp::Action::"executeShell",
  resource is Mcp::Host
)
when {
  resource.production
};

@id("forbid-restricted-document-below-admin")
@doc("Classification gate driven by resource data rather than by scope: restricted documents need an admin tier even for a read.")
forbid (
  principal is Mcp::Session,
  action in Mcp::Action::"readOnlyGroup",
  resource is Mcp::Document
)
when {
  resource.classification == "restricted"
  && !(Mcp::Permission::"admin" in principal.permission)
};

@id("forbid-oversized-write")
@doc("Quantitative attenuation, evaluated against the payload the tool would actually write - not against a length the model declares.")
forbid (
  principal is Mcp::Session,
  action == Mcp::Action::"writeDocument",
  resource is Mcp::Document
)
when {
  context.byteLen > principal.maxWriteBytes
};

@id("forbid-external-egress-after-untrusted-read")
@doc("Indirect prompt injection guard: once content from a resource has entered the turn, this session may not send mail outside the organisation. Coarse and turn-level by design - see docs/LIMITATIONS.md, L4.")
forbid (
  principal is Mcp::Session,
  action == Mcp::Action::"sendEmail",
  resource is Mcp::Mailbox
)
when {
  context.sourceTrust == "tool_output" && resource.external
};

@id("forbid-pii-table-below-admin")
@doc("A table flagged as holding personal data is readable only at admin tier, whatever the scope says.")
forbid (
  principal is Mcp::Session,
  action == Mcp::Action::"queryDatabase",
  resource is Mcp::Table
)
when {
  resource.containsPii
  && !(Mcp::Permission::"admin" in principal.permission)
};
