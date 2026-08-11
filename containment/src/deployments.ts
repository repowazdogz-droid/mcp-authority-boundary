/**
 * The two deployments: vulnerable and repaired.
 *
 * Each is declared TWICE, in two vocabularies that cannot see each other:
 *
 *   - as a `Graph` (containment/src/graph.ts), which is what the static checker
 *     reads and the only place `egress` exists at all;
 *   - as Cedar entities, which is what the host's unmodified policy set reads.
 *
 * The duplication is the point rather than an accident. If the containment layer
 * derived its graph from the Cedar entities, it could only ever re-state what
 * the per-call layer already knows, and `egress` - the fact that makes the whole
 * amplification possible - is precisely what the Cedar schema has no word for.
 * The declared graph is an additional, human-supplied claim about the world, and
 * HONESTY.md records what follows from that: an operator who declares the graph
 * wrongly gets a wrong answer from the checker, silently.
 *
 * Nothing here edits policies/, entities/entities.json, or any host source. New
 * entities are appended through the `loadEntities(extra)` seam.
 */
import type * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import type { Graph, Principal } from './graph.js';

/** Session ids double as principal ids in the declared graph. */
export const AGENT_A = 'sess-agent-a';
export const AGENT_B = 'sess-agent-b';
export const MEDIATOR = 'sess-mediator';

export const FINANCE_DOC = 'corp/finance/q3-forecast.md';
export const HANDOFF_DOC = 'corp/handoff/status.md';
export const PRESS_DOC = 'corp/pubrel/press-draft.md';
export const HANDOFF_REQ_DOC = 'corp/finance/handoff-req.md';
export const PORTAL_DOC = 'corp/portal/published.md';

const PRINCIPALS: Principal[] = [
  { id: AGENT_A, kind: 'agent' },
  { id: AGENT_B, kind: 'agent' },
  { id: MEDIATOR, kind: 'mediator' },
];

// ---------------------------------------------------------------------------
// Cedar entity builders
// ---------------------------------------------------------------------------

type Json = cedar.EntityJson;

function entityRef(type: string, id: string) {
  return { __entity: { type, id } };
}

function scope(id: string, parents: string[]): Json {
  return {
    uid: { type: 'Mcp::Scope', id },
    attrs: {},
    parents: parents.map((p) => ({ type: 'Mcp::Scope', id: p })),
  } as unknown as Json;
}

function doc(id: string, classification: string, scopes: string[]): Json {
  return {
    uid: { type: 'Mcp::Document', id },
    attrs: {
      owner: entityRef('Mcp::Human', 'alice'),
      path: id,
      classification,
    },
    parents: scopes.map((s) => ({ type: 'Mcp::Scope', id: s })),
  } as unknown as Json;
}

/**
 * A session entity. Every field is narrower than or equal to `sess-alice-root`,
 * so each of these is a grant the existing delegation policy would have
 * permitted; they are declared directly because the fixture is about what
 * composes AFTER delegation, not about delegation itself.
 */
function session(id: string, tier: 'read' | 'write' | 'admin', scopeId: string): Json {
  return {
    uid: { type: 'Mcp::Session', id },
    attrs: {
      agent: entityRef('Mcp::Agent', 'assistant'),
      delegator: entityRef('Mcp::Human', 'alice'),
      permission: entityRef('Mcp::Permission', tier),
      scope: entityRef('Mcp::Scope', scopeId),
      notBefore: 1000,
      expiresAt: 9000,
      revoked: false,
      maxWriteBytes: 4096,
      depth: 1,
      delegatedFrom: entityRef('Mcp::Session', 'sess-alice-root'),
    },
    parents: [{ type: 'Mcp::Agent', id: 'assistant' }],
  } as unknown as Json;
}

// ---------------------------------------------------------------------------
// VULNERABLE
// ---------------------------------------------------------------------------

/**
 * Two agents, each narrowly scoped, plus one shared workspace that sits inside
 * BOTH their scopes because it is where they hand work to each other.
 *
 * `corp/handoff` is a child of corp/finance and of corp/pubrel. Neither agent
 * has been given the other's territory: A cannot touch pubrel, B cannot touch
 * finance. Every grant here is defensible on its own and none of them is a
 * mistake anybody would catch in review.
 *
 * The handoff directory is also mirrored to a partner-facing status portal by an
 * out-of-band sync job, which is why `corp/handoff/status.md` carries
 * egress: true. Cedar has no vocabulary for that fact, so the per-call layer
 * cannot take it into account even in principle.
 */
export const VULNERABLE_ENTITIES: Json[] = [
  scope('corp/pubrel', ['corp']),
  scope('corp/handoff', ['corp/finance', 'corp/pubrel']),
  doc(FINANCE_DOC, 'internal', ['corp/finance']),
  doc(HANDOFF_DOC, 'internal', ['corp/handoff']),
  doc(PRESS_DOC, 'public', ['corp/pubrel']),
  session(AGENT_A, 'write', 'corp/finance'),
  session(AGENT_B, 'write', 'corp/pubrel'),
];

export const VULNERABLE_GRAPH: Graph = {
  name: 'vulnerable',
  principals: PRINCIPALS,
  resources: [
    { id: FINANCE_DOC, readers: [AGENT_A], writers: [AGENT_A], egress: false, mediatedBy: null },
    {
      id: HANDOFF_DOC,
      readers: [AGENT_A, AGENT_B],
      writers: [AGENT_A, AGENT_B],
      egress: true,
      mediatedBy: null,
    },
    { id: PRESS_DOC, readers: [AGENT_B], writers: [AGENT_B], egress: false, mediatedBy: null },
  ],
  edges: [{ kind: 'effect-sink', from: HANDOFF_DOC, to: 'partner-status-portal' }],
};

// ---------------------------------------------------------------------------
// REPAIRED
// ---------------------------------------------------------------------------

/**
 * The repair splits the one resource that was doing three jobs at once.
 *
 *   - A's outbound path becomes corp/finance/handoff-req.md, inside A's scope
 *     only. B cannot read it, so it is not a channel.
 *   - corp/handoff/status.md leaves corp/finance. A can no longer reach it at
 *     all, so the cross-agent write disappears from the per-call layer's world
 *     rather than being caught by a second check.
 *   - The egress capability is NOT deleted - the deployment still has to publish
 *     to the partner portal - it moves to corp/portal/published.md, which only
 *     the mediator writes.
 *
 * `corp/bridge` is the mediator's scope, and it is a parent of exactly the two
 * documents the mediator must touch. The mediator is a system principal: it
 * reads A's request, applies whatever review the deployment requires, and
 * publishes. That review is out of scope here and is not implemented; what is
 * asserted is that the topology still permits it (see T4), so the repair is a
 * re-routing rather than a denial of the underlying function.
 */
export const REPAIRED_ENTITIES: Json[] = [
  scope('corp/pubrel', ['corp']),
  scope('corp/bridge', ['corp']),
  doc(FINANCE_DOC, 'internal', ['corp/finance']),
  doc(HANDOFF_REQ_DOC, 'internal', ['corp/finance', 'corp/bridge']),
  doc(HANDOFF_DOC, 'internal', ['corp/pubrel', 'corp/bridge']),
  doc(PORTAL_DOC, 'public', ['corp/pubrel', 'corp/bridge']),
  doc(PRESS_DOC, 'public', ['corp/pubrel']),
  session(AGENT_A, 'write', 'corp/finance'),
  session(AGENT_B, 'write', 'corp/pubrel'),
  session(MEDIATOR, 'write', 'corp/bridge'),
];

export const REPAIRED_GRAPH: Graph = {
  name: 'repaired',
  principals: PRINCIPALS,
  resources: [
    { id: FINANCE_DOC, readers: [AGENT_A], writers: [AGENT_A], egress: false, mediatedBy: null },
    {
      id: HANDOFF_REQ_DOC,
      readers: [AGENT_A, MEDIATOR],
      writers: [AGENT_A],
      egress: false,
      mediatedBy: null,
    },
    {
      id: HANDOFF_DOC,
      readers: [AGENT_B, MEDIATOR],
      writers: [AGENT_B, MEDIATOR],
      egress: false,
      mediatedBy: MEDIATOR,
    },
    {
      id: PORTAL_DOC,
      readers: [AGENT_B, MEDIATOR],
      writers: [MEDIATOR],
      egress: true,
      mediatedBy: MEDIATOR,
    },
    { id: PRESS_DOC, readers: [AGENT_B], writers: [AGENT_B], egress: false, mediatedBy: null },
  ],
  edges: [
    { kind: 'effect-sink', from: PORTAL_DOC, to: 'partner-status-portal' },
    { kind: 'delegation', from: AGENT_A, to: MEDIATOR },
  ],
};

export interface Deployment {
  readonly graph: Graph;
  readonly entities: Json[];
}

export const VULNERABLE: Deployment = { graph: VULNERABLE_GRAPH, entities: VULNERABLE_ENTITIES };
export const REPAIRED: Deployment = { graph: REPAIRED_GRAPH, entities: REPAIRED_ENTITIES };
