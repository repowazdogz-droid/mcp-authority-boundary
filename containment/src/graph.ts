/**
 * The capability graph and its static invariants.
 *
 * This module is PURE and imports nothing - not from the host, not from Node.
 * That is deliberate: the checker is the part of this layer that has to be
 * believable on its own, so it is a total function from a declared graph to a
 * list of violations, testable without Cedar, without a policy set, and without
 * a running agent.
 *
 * WHAT IT CHECKS AND WHAT IT CANNOT
 *
 * It checks the DECLARED graph. Every guarantee below is conditional on the
 * declaration being truthful and complete. A resource nobody declared, an egress
 * path nobody wrote down, or an edge that only comes into existence at runtime
 * is invisible here by construction - see HONESTY.md. Static checking and
 * runtime effect mediation each cover what the other cannot, and neither is
 * complete. Nothing in this file establishes confinement in the general sense;
 * that problem is undecidable (Harrison, Ruzzo and Ullman 1976) and this is a
 * decidable check over a bounded, declared model instead.
 */

/**
 * Principals are partitioned. The partition is the whole point of the layer:
 * "mediated" means an authority edge is owned by a principal that is NOT one of
 * the agents being constrained. A path routed through another agent is not
 * mediated, however much machinery sits in the middle.
 */
export type PrincipalKind = 'agent' | 'mediator';

export interface Principal {
  readonly id: string;
  readonly kind: PrincipalKind;
}

/**
 * A resource, carrying its per-principal access and whether it can reach
 * external authority.
 *
 * `egress` is the flag the per-call authorization layer has no vocabulary for.
 * A Cedar policy set can say who may write a document; it has no way to say that
 * this particular document is synced to a partner portal, and therefore that a
 * write to it is a publication.
 *
 * `mediatedBy` names the mediator principal that owns the authority edge into
 * this resource, or null. A non-null value is only honoured when it names a
 * declared principal of kind 'mediator' - see the DECL checks.
 */
export interface Resource {
  readonly id: string;
  readonly readers: readonly string[];
  readonly writers: readonly string[];
  readonly egress: boolean;
  readonly mediatedBy: string | null;
}

/**
 * Non-access relations. Read and write edges are NOT listed here: they are
 * derived from the access matrix by `edgesOf` so that there is exactly one
 * representation of "p can write r". Two representations of the same fact is
 * how the host repo's audit finding A1 happened, and this file declines to
 * repeat it.
 */
export type EdgeKind = 'read' | 'write' | 'delegation' | 'capability-creation' | 'effect-sink';

export interface Edge {
  readonly kind: EdgeKind;
  readonly from: string;
  readonly to: string;
}

export interface Graph {
  readonly name: string;
  readonly principals: readonly Principal[];
  readonly resources: readonly Resource[];
  /** Delegation, capability-creation and effect-sink bindings only. */
  readonly edges: readonly Edge[];
}

export type Severity = 'critical' | 'high' | 'declaration-error';

export type InvariantId = 'C1' | 'C2' | 'CRIT' | 'DECL';

export interface Violation {
  readonly invariant: InvariantId;
  readonly severity: Severity;
  readonly resource: string;
  /** The specific principals that make the violation true. Never empty. */
  readonly witness: readonly string[];
  readonly message: string;
}

/** The full edge view, read and write edges included, derived not stored. */
export function edgesOf(graph: Graph): Edge[] {
  const derived: Edge[] = [];
  for (const r of graph.resources) {
    for (const p of r.readers) derived.push({ kind: 'read', from: p, to: r.id });
    for (const p of r.writers) derived.push({ kind: 'write', from: p, to: r.id });
  }
  return [...derived, ...graph.edges];
}

function principalIndex(graph: Graph): Map<string, Principal> {
  return new Map(graph.principals.map((p) => [p.id, p]));
}

/**
 * A resource is declared-and-mediated when `mediatedBy` names a principal that
 * exists AND is a mediator. Anything else is a declaration the checker refuses
 * to honour rather than a mediation it accepts.
 */
function isMediated(r: Resource, index: Map<string, Principal>): boolean {
  if (r.mediatedBy === null) return false;
  return index.get(r.mediatedBy)?.kind === 'mediator';
}

function agentsAmong(ids: readonly string[], index: Map<string, Principal>): string[] {
  return ids.filter((id) => index.get(id)?.kind === 'agent');
}

/**
 * Check the declared graph.
 *
 * Every violation is reported separately, so a resource that is both a
 * cross-principal channel and an egress pivot yields C1, C2 and CRIT rather than
 * one merged finding. The three say different things and a repair can close one
 * without closing the others.
 */
export function check(graph: Graph): Violation[] {
  const index = principalIndex(graph);
  const out: Violation[] = [];

  // DECL first. A graph that does not describe itself consistently cannot be
  // meaningfully checked, and a mediatedBy pointing at an agent would otherwise
  // silently satisfy C1 and C2 - the exact confusion the partition exists to
  // prevent.
  for (const r of graph.resources) {
    for (const id of [...r.readers, ...r.writers]) {
      if (!index.has(id)) {
        out.push({
          invariant: 'DECL',
          severity: 'declaration-error',
          resource: r.id,
          witness: [id],
          message: `resource ${r.id} grants access to undeclared principal ${id}`,
        });
      }
    }
    if (r.mediatedBy !== null) {
      const m = index.get(r.mediatedBy);
      if (m === undefined) {
        out.push({
          invariant: 'DECL',
          severity: 'declaration-error',
          resource: r.id,
          witness: [r.mediatedBy],
          message: `resource ${r.id} claims mediation by undeclared principal ${r.mediatedBy}`,
        });
      } else if (m.kind !== 'mediator') {
        out.push({
          invariant: 'DECL',
          severity: 'critical',
          resource: r.id,
          witness: [r.mediatedBy],
          message:
            `resource ${r.id} claims mediation by ${r.mediatedBy}, which is an agent principal. ` +
            `An authority edge owned by a constrained agent is not mediation.`,
        });
      }
    }
  }

  for (const r of graph.resources) {
    const mediated = isMediated(r, index);
    const agentWriters = agentsAmong(r.writers, index);
    const agentReaders = agentsAmong(r.readers, index);

    // C1 - cross-principal channel. Distinct agent principals, one writing and
    // one reading the same resource, is a message board whatever the resource
    // was declared for.
    const channel: string[] = [];
    for (const w of agentWriters) {
      for (const rd of agentReaders) {
        if (w !== rd) channel.push(`${w}->${rd}`);
      }
    }
    const c1 = channel.length > 0 && !mediated;
    if (c1) {
      out.push({
        invariant: 'C1',
        severity: 'high',
        resource: r.id,
        witness: channel,
        message:
          `unmediated cross-principal channel on ${r.id}: ` +
          `${channel.join(', ')} can coordinate through it without any per-call denial`,
      });
    }

    // C2 - agent-to-egress. An agent principal that can write a resource which
    // reaches outside is holding external authority the per-call policy never
    // named.
    const c2 = r.egress && agentWriters.length > 0 && !mediated;
    if (c2) {
      out.push({
        invariant: 'C2',
        severity: 'high',
        resource: r.id,
        witness: agentWriters,
        message:
          `unmediated agent write to egress-bearing ${r.id}: ` +
          `${agentWriters.join(', ')} can cause an external effect through it`,
      });
    }

    // CRIT - the conjunction. Not a sum of two problems: a resource that is both
    // a channel and an egress point lets one agent's reads become another
    // agent's external publication, with every individual call authorized.
    if (c1 && c2) {
      out.push({
        invariant: 'CRIT',
        severity: 'critical',
        resource: r.id,
        witness: [...new Set([...agentWriters, ...agentReaders])],
        message:
          `${r.id} is simultaneously agent-writable, cross-principal-readable and ` +
          `egress-bearing, with no mediator on any of the three. This is the ` +
          `authority-amplification shape: composed authorized edges yield ` +
          `effective authority no principal was granted.`,
      });
    }
  }

  return out;
}

/** Convenience predicates used by the tests and the mediator. */
export function hasCritical(violations: readonly Violation[]): boolean {
  return violations.some((v) => v.severity === 'critical');
}

export function byInvariant(violations: readonly Violation[], id: InvariantId): Violation[] {
  return violations.filter((v) => v.invariant === id);
}

export function findResource(graph: Graph, id: string): Resource | undefined {
  return graph.resources.find((r) => r.id === id);
}

export function formatViolations(violations: readonly Violation[]): string {
  if (violations.length === 0) return '  (no violations)';
  return violations
    .map((v) => `  [${v.severity.toUpperCase()}] ${v.invariant} ${v.resource}: ${v.message}`)
    .join('\n');
}
