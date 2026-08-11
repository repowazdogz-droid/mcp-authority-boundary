/**
 * Runtime effect-sink mediation.
 *
 * The static checker reads the DECLARED graph. This reads what an agent is
 * actually about to do. The two cover different things and neither is complete:
 * a resource created at runtime is invisible to the checker, and a dangerous
 * shape that no agent ever exercises is invisible here. HONESTY.md states the
 * boundary; this file implements the runtime half.
 *
 * WHERE THE AUTHORIZATION HAPPENS
 *
 * Not at the tool-call entry, which is where the per-call layer already sits and
 * where the question "is this call authorized" is already answered correctly.
 * Here it happens at the security-sensitive CONSEQUENCE: this write reaches a
 * resource that leaves the organisation; this write lands somewhere a different
 * agent can read it; this operation spends a credential. Those are the moments
 * at which effective authority changes, and they are not in one-to-one
 * correspondence with tool calls.
 *
 * WHAT IT IS BOUND TO
 *
 * The frozen `ResolvedOperation` from the host's own resolver, and its digest.
 * This module never reads a model's raw arguments and never re-implements
 * parsing, because a second resolver is a second opinion about what the
 * operation IS, and that divergence is the host's audit finding A1. The digest
 * is re-checked against the host's ledger entry after execution, so a drift
 * between what this layer mediated and what the host authorized is caught rather
 * than assumed absent.
 */
import { sha256, canonicalJson } from '../../src/canonical.js';
import type { EffectMediation, EffectMediator } from '../../src/mediation.js';
import type { EntityUid, ResolvedOperation } from '../../src/types.js';
import { findResource, type Graph, type Principal } from './graph.js';

/**
 * The effect sinks this layer mediates.
 *
 * `namespace-creation` is the runtime answer to the static checker's blind spot:
 * a write to a resource that was never declared is, by definition, the creation
 * of something the declared graph does not describe.
 */
export type SinkKind =
  | 'egress-write'
  | 'channel-write'
  | 'credential-use'
  | 'network-connection'
  | 'namespace-creation'
  | 'delegation';

export interface Sink {
  readonly kind: SinkKind;
  readonly target: string;
  /** Bytes this operation pushes through the sink; 0 where not a write. */
  readonly bytes: number;
}

export type Verdict = 'allow' | 'deny';

export interface MediationRecord {
  readonly seq: number;
  /** The agent this effect is attributed to. Never inferred from the payload. */
  readonly principal: string;
  readonly operationSha256: string | null;
  readonly sinks: readonly Sink[];
  readonly verdict: Verdict;
  readonly reason: string;
  readonly egressBytesAfter: number;
  readonly sinkOpsInWindowAfter: number;
  readonly breakerOpen: boolean;
  readonly prevHash: string;
  readonly hash: string;
}

export interface Budgets {
  /** Total bytes one principal may push through egress sinks. */
  readonly egressBytes: number;
  /** Sink-reaching operations one principal may make per logical-time window. */
  readonly sinkOpsPerWindow: number;
  readonly windowSize: number;
  /** Denials after which a principal is cut off entirely. */
  readonly breakerTrip: number;
}

export const DEFAULT_BUDGETS: Budgets = {
  egressBytes: 8192,
  sinkOpsPerWindow: 8,
  windowSize: 1000,
  breakerTrip: 3,
};

interface PrincipalState {
  egressBytes: number;
  window: number;
  sinkOpsInWindow: number;
  denials: number;
  breakerOpen: boolean;
}

/**
 * Classify the effect sinks an operation reaches.
 *
 * Pure, and exported so it can be tested without a running enforcement point.
 * `read_document` and `delete_file` reach no sink: neither changes what
 * authority exists in the deployment. Deletion is destructive and this layer
 * does not address it - that is a different property and claiming it here would
 * be overreach.
 */
export function classifySinks(
  op: ResolvedOperation,
  graph: Graph,
  actor: string,
): Sink[] {
  switch (op.tool) {
    case 'read_document':
    case 'delete_file':
      return [];

    case 'write_document': {
      const r = findResource(graph, op.path);
      if (r === undefined) {
        // Undeclared. The static checker cannot have reasoned about this.
        return [{ kind: 'namespace-creation', target: op.path, bytes: op.byteLen }];
      }
      const sinks: Sink[] = [];
      if (r.egress) sinks.push({ kind: 'egress-write', target: op.path, bytes: op.byteLen });

      // Symmetric with C1: a channel needs an agent at BOTH ends. A mediator
      // writing something agents read is publication, which is what a mediator
      // is for, and labelling it a channel would make the ledger's account of
      // how authority changed actively misleading.
      const actorIsAgent = graph.principals.some(
        (q: Principal) => q.id === actor && q.kind === 'agent',
      );
      const otherAgentReaders = r.readers.filter(
        (p) => p !== actor && graph.principals.some((q) => q.id === p && q.kind === 'agent'),
      );
      if (actorIsAgent && otherAgentReaders.length > 0) {
        sinks.push({ kind: 'channel-write', target: op.path, bytes: op.byteLen });
      }
      return sinks;
    }

    case 'send_email':
      return [{ kind: 'egress-write', target: op.to, bytes: op.byteLen }];

    case 'execute_shell':
      return [
        { kind: 'network-connection', target: op.host, bytes: 0 },
        { kind: 'credential-use', target: op.host, bytes: 0 },
      ];

    case 'query_database':
      return [{ kind: 'credential-use', target: op.table, bytes: 0 }];
  }
}

/**
 * Is this sink mediated for this actor?
 *
 * Two ways to be satisfied, and only two: the target resource is declared with a
 * `mediatedBy` naming a mediator principal, or the actor IS a mediator. An
 * undeclared target satisfies neither, which is the fail-closed rule.
 */
function sinkIsMediated(sink: Sink, graph: Graph, actor: string): boolean {
  const actorIsMediator = graph.principals.some((p) => p.id === actor && p.kind === 'mediator');
  if (actorIsMediator) return true;
  const r = findResource(graph, sink.target);
  if (r === undefined) return false;
  if (r.mediatedBy === null) return false;
  return graph.principals.some((p) => p.id === r.mediatedBy && p.kind === 'mediator');
}

const GENESIS = '0'.repeat(64);

export class Mediator implements EffectMediator {
  private readonly state = new Map<string, PrincipalState>();
  private readonly records: MediationRecord[] = [];
  private prevHash = GENESIS;

  constructor(
    private readonly graph: Graph,
    private readonly budgets: Budgets = DEFAULT_BUDGETS,
  ) {}

  ledger(): readonly MediationRecord[] {
    return this.records;
  }

  private stateFor(principal: string): PrincipalState {
    let s = this.state.get(principal);
    if (s === undefined) {
      s = { egressBytes: 0, window: -1, sinkOpsInWindow: 0, denials: 0, breakerOpen: false };
      this.state.set(principal, s);
    }
    return s;
  }

  private record(
    principal: string,
    operationSha256: string | null,
    sinks: readonly Sink[],
    verdict: Verdict,
    reason: string,
  ): MediationRecord {
    const s = this.stateFor(principal);
    const body = {
      seq: this.records.length,
      principal,
      operationSha256,
      sinks: [...sinks],
      verdict,
      reason,
      egressBytesAfter: s.egressBytes,
      sinkOpsInWindowAfter: s.sinkOpsInWindow,
      breakerOpen: s.breakerOpen,
      prevHash: this.prevHash,
    };
    const entry: MediationRecord = { ...body, hash: sha256(canonicalJson(body)) };
    this.prevHash = entry.hash;
    this.records.push(entry);
    return entry;
  }

  /**
   * Decide, and commit the budget consumption on an allow.
   *
   * `now` is the host's logical clock, passed in rather than read, so a decision
   * is a function of values the caller can reproduce.
   */
  mediate(
    principal: string,
    operation: ResolvedOperation | null,
    operationSha256: string | null,
    now: number,
  ): MediationRecord {
    const s = this.stateFor(principal);

    if (s.breakerOpen) {
      return this.record(principal, operationSha256, [], 'deny', 'circuit-breaker-open');
    }
    if (operation === null) {
      return this.deny(principal, operationSha256, [], 'unresolvable-operation');
    }

    const sinks = classifySinks(operation, this.graph, principal);
    if (sinks.length === 0) {
      return this.record(principal, operationSha256, [], 'allow', 'no-effect-sink-reached');
    }

    const unmediated = sinks.filter((k) => !sinkIsMediated(k, this.graph, principal));
    if (unmediated.length > 0) {
      const undeclared = unmediated.some((k) => findResource(this.graph, k.target) === undefined);
      return this.deny(
        principal,
        operationSha256,
        sinks,
        undeclared
          ? `unmediated effect sink on undeclared target (${unmediated.map((k) => `${k.kind}:${k.target}`).join(', ')}); failing closed`
          : `unmediated effect sink (${unmediated.map((k) => `${k.kind}:${k.target}`).join(', ')})`,
      );
    }

    const window = Math.floor(now / this.budgets.windowSize);
    if (s.window !== window) {
      s.window = window;
      s.sinkOpsInWindow = 0;
    }
    if (s.sinkOpsInWindow + 1 > this.budgets.sinkOpsPerWindow) {
      return this.deny(principal, operationSha256, sinks, 'rate-limit-exceeded');
    }

    const egressBytes = sinks
      .filter((k) => k.kind === 'egress-write')
      .reduce((n, k) => n + k.bytes, 0);
    if (s.egressBytes + egressBytes > this.budgets.egressBytes) {
      return this.deny(principal, operationSha256, sinks, 'egress-budget-exhausted');
    }

    s.sinkOpsInWindow += 1;
    s.egressBytes += egressBytes;
    return this.record(principal, operationSha256, sinks, 'allow', 'mediated-sink-within-budget');
  }

  /**
   * Delegation and capability creation are effect sinks too: they change what
   * authority exists rather than using authority that already exists.
   */
  mediateDelegation(principal: string, childId: string): MediationRecord {
    const s = this.stateFor(principal);
    if (s.breakerOpen) {
      return this.record(principal, null, [], 'deny', 'circuit-breaker-open');
    }
    const sinks: Sink[] = [{ kind: 'delegation', target: childId, bytes: 0 }];
    const actorIsMediator = this.graph.principals.some(
      (p) => p.id === principal && p.kind === 'mediator',
    );
    if (!actorIsMediator) {
      return this.deny(principal, null, sinks, 'unmediated capability creation by an agent principal');
    }
    return this.record(principal, null, sinks, 'allow', 'mediated-delegation');
  }

  private deny(
    principal: string,
    operationSha256: string | null,
    sinks: readonly Sink[],
    reason: string,
  ): MediationRecord {
    const s = this.stateFor(principal);
    s.denials += 1;
    if (s.denials >= this.budgets.breakerTrip) s.breakerOpen = true;
    return this.record(principal, operationSha256, sinks, 'deny', reason);
  }

  /**
   * The EffectMediator interface the enforcement point requires.
   *
   * This is what makes the layer structural rather than conventional. There is
   * no wrapper object a caller can decline to use: `EnforcementPoint.handle`
   * calls this on every operation, and `consumeGrant` refuses to execute
   * without the record it returns. The old `MediatedSession` wrapper - which
   * was in series only for callers who chose to route through it - is gone,
   * and its deletion is the point of the change rather than a side effect.
   */
  mediateOperation(
    principal: EntityUid,
    operation: ResolvedOperation,
    operationSha256: string,
    now: number,
  ): EffectMediation {
    const record = this.mediate(principal.id, operation, operationSha256, now);
    return {
      operationSha256,
      verdict: record.verdict,
      reason: record.reason,
      hash: record.hash,
    };
  }
}
