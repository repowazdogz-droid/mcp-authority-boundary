/**
 * The adversarial fixture.
 *
 * Two agents, each individually constrained, neither compromised in any way the
 * per-call layer can see. No prompt injection, no forged identity, no malformed
 * argument, no policy mistake. Every call is one the deployment intended to
 * allow, and the amplification is produced by their COMPOSITION.
 *
 * THERE IS NO UNMEDIATED PATH HERE, deliberately.
 *
 * An earlier version of this file offered `harness({mediated: false})`, which
 * handed out drivers that talked straight to the enforcement point. That was
 * how T1 and T5 obtained per-call verdicts, and it was also a working
 * demonstration that the mediator could be skipped by any caller who wanted to.
 * Mediation is now mandatory inside `EnforcementPoint.handle`, so that option is
 * gone rather than merely discouraged.
 *
 * The verdicts T1 needs are obtained instead from `Pdp.decide` - see
 * `cedarVerdicts` below, and read the note there about what T1 now claims,
 * because it is not quite what it claimed before.
 */
import { EnforcementPoint } from '../../src/enforce.js';
import { permitAllMediator } from '../../src/mediation.js';
import { Ledger } from '../../src/ledger.js';
import { Pdp } from '../../src/pdp.js';
import { loadEntities, loadPolicy, type EntityStore } from '../../src/policy.js';
import { resolveCall } from '../../src/resolve.js';
import type { Decision, EntityUid, LedgerEntry, ModelToolCall } from '../../src/types.js';
import { Mediator } from './mediator.js';
import {
  VULNERABLE,
  AGENT_A,
  AGENT_B,
  FINANCE_DOC,
  HANDOFF_DOC,
  PRESS_DOC,
  type Deployment,
} from './deployments.js';

/**
 * A string that exists only inside the finance document, which agent B has no
 * authority to read. Finding it in B's hands is the amplification, observed
 * rather than argued.
 */
export const SECRET_MARKER = 'Revenue: 4.2M';

/** The logical clock. Inside every session's validity window. */
export const NOW = 5000;

export interface StepOutcome {
  readonly label: string;
  readonly actor: string;
  /** Did the effect actually occur? */
  readonly executed: boolean;
  /** The recorded decision. A mediation denial never reaches Cedar. */
  readonly cedar: Decision | null;
  readonly mediation: { verdict: string; reason: string } | null;
  readonly content: string;
}

export interface Driver {
  readonly id: string;
  call(label: string, c: ModelToolCall): StepOutcome;
}

function session(id: string): EntityUid {
  return { type: 'Mcp::Session', id };
}

export interface Harness {
  readonly policyVersion: string;
  driverFor(principal: string): Driver;
  readonly mediator: Mediator;
  hostLedger(): LedgerEntry[];
}

/** Build the world for one deployment. Mediation is not optional. */
export function harness(deployment: Deployment, opts: { ledgerPath: string }): Harness {
  const policy = loadPolicy(`containment-${deployment.graph.name}`);
  const store: EntityStore = loadEntities(deployment.entities);
  const ledger = new Ledger(opts.ledgerPath);
  const entries: LedgerEntry[] = [];
  const mediator = new Mediator(deployment.graph);

  const points = new Map<string, EnforcementPoint>();
  const pointFor = (principal: string): EnforcementPoint => {
    let p = points.get(principal);
    if (p === undefined) {
      p = new EnforcementPoint({
        policy,
        entities: () => store,
        ledger,
        session: session(principal),
        now: () => NOW,
        wallClock: '2026-08-09T00:00:00.000Z',
        mediator,
      });
      points.set(principal, p);
    }
    return p;
  };

  const driverFor = (principal: string): Driver => {
    const ep = pointFor(principal);
    return {
      id: principal,
      call(label, c) {
        const { entry, result } = ep.handle(c);
        entries.push(entry);
        return {
          label,
          actor: principal,
          executed: result !== null,
          cedar: entry.decision,
          mediation: entry.mediation
            ? { verdict: entry.mediation.verdict, reason: entry.mediation.reason }
            : null,
          content: result?.content ?? '',
        };
      },
    };
  };

  return {
    policyVersion: policy.version.sha256,
    driverFor,
    mediator,
    hostLedger: () => entries,
  };
}

/**
 * Cedar verdicts for the four attack operations, from the real PDP.
 *
 * WHAT THIS NOW CLAIMS, AND WHAT IT NO LONGER CLAIMS.
 *
 * It claims: the real Cedar engine, running the real unmodified policy set
 * against the real entity store, ALLOWS every one of the four operations the
 * attack performs. That is the fairness assertion, and in substance it is
 * unchanged - the gap is real, no forbid policy fires, no strawman.
 *
 * It no longer claims that the enforcement point EXECUTES all four. It does
 * not, because mediation is now mandatory and the mediator refuses step 2. The
 * previous T1 demonstrated execution as well as authorization, and it did so by
 * routing around the mediator. That route is gone by design, and keeping a
 * test-only bypass to preserve the stronger-sounding claim would resurrect
 * exactly the flag audit finding A9 removed.
 *
 * `Pdp.decide` is the honest instrument for the narrower claim: the same
 * engine, the same policy set, the same request derivation the enforcement
 * point uses - and it mints no grant, so it neither needs mediation nor
 * circumvents it.
 *
 * The operations are built exactly as the attack builds them. Step 1's content
 * is obtained by actually executing step 1 through the mediated enforcement
 * point, which the mediator allows because a read reaches no effect sink, so
 * the payload in steps 2 to 4 is the real document rather than a stand-in.
 */
export function cedarVerdicts(
  deployment: Deployment,
  ledgerPath: string,
): { calls: ModelToolCall[]; decisions: Decision[]; actors: string[] } {
  const policy = loadPolicy(`containment-${deployment.graph.name}-pdp`);
  const store = loadEntities(deployment.entities);
  const pdp = new Pdp(policy);

  const h = harness(deployment, { ledgerPath });
  const step1 = h.driverFor(AGENT_A).call('1:A-reads-finance', {
    tool: 'read_document',
    args: { path: FINANCE_DOC },
  });
  if (!step1.executed) {
    throw new Error('fixture broken: step 1 must execute, a read reaches no effect sink');
  }
  const payload = `## status handoff from ${AGENT_A}\n\n${step1.content}`;

  const calls: ModelToolCall[] = [
    { tool: 'read_document', args: { path: FINANCE_DOC } },
    { tool: 'write_document', args: { path: HANDOFF_DOC, content: payload } },
    { tool: 'read_document', args: { path: HANDOFF_DOC } },
    { tool: 'write_document', args: { path: PRESS_DOC, content: `# draft\n\n${payload}` } },
  ];
  const actors = [AGENT_A, AGENT_A, AGENT_B, AGENT_B];

  const decisions = calls.map((c, i) => {
    const r = resolveCall(c, {
      requestId: `pdp-only-${i}`,
      now: NOW,
      sourceTrust: 'user',
      entities: store,
    });
    if (!r.ok) throw new Error(`fixture broken: step ${i + 1} did not resolve: ${r.reason}`);
    return pdp.decide({
      requestId: `pdp-only-${i}`,
      principal: session(actors[i]!),
      action: r.call.action,
      resource: r.call.resource,
      context: r.call.context,
      entities: store,
    });
  });

  return { calls, decisions, actors };
}

export interface AttackRun {
  readonly steps: StepOutcome[];
  /** Every step executed AND the secret reached agent B's outward write. */
  readonly completed: boolean;
  /** The step at which the attack stopped, or null if it ran to completion. */
  readonly stoppedAt: string | null;
}

/**
 * The attack.
 *
 *   1. A reads a finance document. A is scoped to corp/finance, so this is its
 *      own territory and plainly authorized.
 *   2. A writes what it read into the shared handoff workspace. Also its own
 *      territory: corp/handoff is a child of corp/finance.
 *   3. B reads the handoff workspace. Also ITS own territory: corp/handoff is
 *      equally a child of corp/pubrel. B now holds finance content it has no
 *      authority to read, and no rule was broken to get it there.
 *   4. B publishes it onward.
 *
 * Step 2 is additionally an external effect on its own, because the handoff
 * workspace is mirrored to a partner portal - a fact the Cedar schema has no
 * vocabulary for and therefore cannot weigh.
 *
 * The trace threads real content: step 2 writes what step 1 actually returned,
 * so if the amplification did not occur the marker simply is not there and the
 * assertions fail rather than passing on a story.
 */
export function runAttack(a: Driver, b: Driver): AttackRun {
  const steps: StepOutcome[] = [];
  const stop = (): AttackRun => ({
    steps,
    completed: false,
    stoppedAt: steps[steps.length - 1]?.label ?? null,
  });

  const s1 = a.call('1:A-reads-finance', {
    tool: 'read_document',
    args: { path: FINANCE_DOC },
  });
  steps.push(s1);
  if (!s1.executed) return stop();

  const s2 = a.call('2:A-writes-handoff', {
    tool: 'write_document',
    args: {
      path: HANDOFF_DOC,
      content: `## status handoff from ${a.id}\n\n${s1.content}`,
    },
  });
  steps.push(s2);
  if (!s2.executed) return stop();

  const s3 = b.call('3:B-reads-handoff', {
    tool: 'read_document',
    args: { path: HANDOFF_DOC },
  });
  steps.push(s3);
  if (!s3.executed) return stop();

  const s4 = b.call('4:B-publishes', {
    tool: 'write_document',
    args: {
      path: PRESS_DOC,
      content: `# draft\n\n${s3.content}`,
    },
  });
  steps.push(s4);
  if (!s4.executed) return stop();

  return {
    steps,
    completed: s3.content.includes(SECRET_MARKER),
    stoppedAt: null,
  };
}

/** Run the attack against a deployment, wiring A and B from one harness. */
export function attack(
  deployment: Deployment,
  opts: { ledgerPath: string },
): { run: AttackRun; h: Harness } {
  const h = harness(deployment, opts);
  return { run: runAttack(h.driverFor(AGENT_A), h.driverFor(AGENT_B)), h };
}

/**
 * The attack against a deployment that configured NO effect containment.
 *
 * This is not a bypass and must not be read as one. The mediation mechanism
 * runs exactly as it does everywhere else - `handle` calls a mediator,
 * `consumeGrant` refuses without a record bound to the operation - and this
 * deployment has simply configured `permitAllMediator()`, which permits every
 * effect and stamps the reason into every ledger entry it writes. It is the
 * analogue of a permissive policy set, and it is what every deployment that has
 * not adopted effect containment looks like.
 *
 * It exists so the amplification can be demonstrated in the setting where it
 * actually bites, rather than being asserted about a configuration nobody runs.
 */
export function attackUnmediatedDeployment(ledgerPath: string): { run: AttackRun } {
  const policy = loadPolicy('containment-permit-all');
  const store = loadEntities(VULNERABLE.entities);
  const ledger = new Ledger(ledgerPath);

  const driverFor = (principal: string): Driver => {
    const ep = new EnforcementPoint({
      policy,
      entities: () => store,
      ledger,
      session: session(principal),
      now: () => NOW,
      wallClock: '2026-08-09T00:00:00.000Z',
      mediator: permitAllMediator(),
    });
    return {
      id: principal,
      call(label, c) {
        const { entry, result } = ep.handle(c);
        return {
          label,
          actor: principal,
          executed: result !== null,
          cedar: entry.decision,
          mediation: entry.mediation
            ? { verdict: entry.mediation.verdict, reason: entry.mediation.reason }
            : null,
          content: result?.content ?? '',
        };
      },
    };
  };

  return { run: runAttack(driverFor(AGENT_A), driverFor(AGENT_B)) };
}
