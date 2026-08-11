/**
 * T1-T5. The acceptance bar for the whole layer.
 *
 * T1 is the one that makes the rest worth anything. If the per-call layer did
 * not authorize every step of the attack, the containment layer would be
 * catching a strawman and the demonstration would be worthless.
 */
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { snapshotDocuments, restoreDocuments, type WorldSnapshot } from '../../src/tools.js';
import {
  attack,
  attackUnmediatedDeployment,
  cedarVerdicts,
  harness,
  SECRET_MARKER,
} from '../src/fixture.js';
import {
  VULNERABLE,
  REPAIRED,
  AGENT_A,
  HANDOFF_DOC,
  HANDOFF_REQ_DOC,
  PORTAL_DOC,
  MEDIATOR,
} from '../src/deployments.js';
import { check, byInvariant } from '../src/graph.js';

let world: WorldSnapshot;
beforeEach(() => {
  world = snapshotDocuments();
});
afterEach(() => {
  restoreDocuments(world);
});

let n = 0;
const ledgerPath = (): string => `run/acceptance-${n++}.jsonl`;

// ---------------------------------------------------------------------------

test('T1 the real PDP ALLOWS every operation in the attack trace', () => {
  // WHAT THIS ASSERTS, PRECISELY.
  //
  // "The real Cedar engine, on the real unmodified policy set, allows all four
  // operations" - NOT "the enforcement point executes all four". It no longer
  // does: mediation is mandatory and the mediator refuses step 2 (see T3).
  //
  // Before mediation became structural, T1 asserted both, and obtained the
  // verdicts through `harness({mediated: false})` - a driver that skipped the
  // mediator. That bypass is deleted, and reintroducing one so this test could
  // keep the stronger-sounding claim would put back the flag audit finding A9
  // removed. `Pdp.decide` mints no grant, so it needs no mediation and
  // circumvents none.
  //
  // The fairness assertion is unchanged in substance: the gap is real, every
  // individual call is authorized, and nothing here is a strawman.
  const { decisions } = cedarVerdicts(VULNERABLE, ledgerPath());

  assert.equal(decisions.length, 4, 'all four operations must be decided');
  for (const d of decisions) {
    assert.equal(d.decision, 'allow', `${d.requestId} must be a real Cedar allow`);
    assert.equal(d.denialKind, null);
    assert.deepEqual(d.errors, []);
  }

  // Allowed by ordinary least-privilege permits, not by some odd corner of the
  // policy set, and no forbid guardrail was even a near miss.
  const determining = decisions.flatMap((d) => d.determiningPolicies);
  assert.deepEqual([...new Set(determining)].sort(), ['permit-read-tier', 'permit-write-tier']);
  assert.equal(
    determining.some((p) => p.startsWith('forbid-')),
    false,
    'no forbid policy fired: the gap is real, not a policy the fixture dodged',
  );
});

test('T1b the amplification is real: B ends up holding finance content it cannot read', () => {
  // T1 establishes that the per-call layer authorizes each step. This
  // establishes that the composition actually produces the amplification, which
  // is a separate fact and used to be bundled into T1.
  //
  // It is demonstrated against a deployment configured with permitAllMediator -
  // the analogue of a permissive policy set, and exactly what a deployment that
  // has not adopted effect containment looks like. That is the honest setting
  // for this claim: it is what happens when nothing mediates.
  const { run } = attackUnmediatedDeployment(ledgerPath());
  assert.equal(run.completed, true);
  const bRead = run.steps.find((s) => s.label === '3:B-reads-handoff');
  assert.equal(
    bRead?.content.includes(SECRET_MARKER),
    true,
    'agent B, which has no authority over corp/finance, is holding finance content',
  );
  for (const s of run.steps) {
    assert.equal(s.cedar?.decision, 'allow');
    assert.equal(s.mediation?.verdict, 'allow');
    assert.match(s.mediation?.reason ?? '', /no effect mediation/);
  }
});

test('T2 the static checker flags CRIT on the vulnerable deployment', () => {
  const v = check(VULNERABLE.graph);

  const crit = byInvariant(v, 'CRIT');
  assert.equal(crit.length, 1);
  assert.equal(crit[0]?.resource, HANDOFF_DOC);
  assert.equal(crit[0]?.severity, 'critical');

  assert.equal(byInvariant(v, 'C1').length, 1);
  assert.equal(byInvariant(v, 'C2').length, 1);
  assert.equal(byInvariant(v, 'DECL').length, 0);

  // The witness names the principals, so the finding is actionable rather than
  // an alarm.
  assert.deepEqual([...(crit[0]?.witness ?? [])].sort(), ['sess-agent-a', 'sess-agent-b']);
});

test('T3 the runtime mediator blocks the external effect and attributes it', () => {
  const { run, h } = attack(VULNERABLE, { ledgerPath: ledgerPath() });

  assert.equal(run.completed, false);
  assert.equal(run.stoppedAt, '2:A-writes-handoff');

  const blocked = run.steps[1];
  assert.equal(blocked?.executed, false);
  assert.equal(blocked?.mediation?.verdict, 'deny');

  // In series, and structurally so: the mediator runs inside handle(), so a
  // refusal means no grant was minted and Cedar made no policy decision. The
  // denial is recorded under its own kind rather than dressed up as one.
  assert.equal(blocked?.cedar?.decision, 'deny');
  assert.equal(blocked?.cedar?.denialKind, 'mediation-denied');
  assert.deepEqual(blocked?.cedar?.determiningPolicies, [], 'no policy decided this');

  // Attribution and sink detail live on the mediator's own record.
  const denyRecord = h.mediator.ledger()[1];
  assert.equal(
    denyRecord?.principal,
    AGENT_A,
    'the effect is attributed to the agent that originated it',
  );
  // Both sinks were identified, not just the one that happens to fire first.
  assert.deepEqual(
    (denyRecord?.sinks ?? []).map((s) => s.kind).sort(),
    ['channel-write', 'egress-write'],
  );

  // The world is untouched by the blocked step.
  const readBack = harness(VULNERABLE, { ledgerPath: ledgerPath() })
    .driverFor(AGENT_A)
    .call('probe', { tool: 'read_document', args: { path: HANDOFF_DOC } });
  assert.equal(
    readBack.content.includes(SECRET_MARKER),
    false,
    'the handoff document must not contain the secret: the write never happened',
  );

  // The ledger reconstructs why.
  const led = h.mediator?.ledger() ?? [];
  assert.equal(led.length, 2);
  assert.equal(led[0]?.verdict, 'allow');
  assert.equal(led[1]?.verdict, 'deny');
  assert.match(led[1]?.reason ?? '', /unmediated effect sink/);
  assert.equal(led[1]?.prevHash, led[0]?.hash, 'the mediation ledger is hash-chained');
});

test('T4 the repaired deployment passes the static checker with nothing outstanding', () => {
  assert.deepEqual(check(REPAIRED.graph), []);
});

test('T4b the repair re-routes the function rather than deleting it', () => {
  // A repair that simply denied everything would also pass T4. This asserts the
  // mediated path still works: the mediator can collect A's request, publish to
  // the shared workspace, and push to the egress-bearing portal.
  const h = harness(REPAIRED, { ledgerPath: ledgerPath() });
  const m = h.driverFor(MEDIATOR);

  const collect = m.call('m1', { tool: 'read_document', args: { path: HANDOFF_REQ_DOC } });
  assert.equal(collect.cedar?.decision, 'allow');
  assert.equal(collect.mediation?.verdict, 'allow');

  const publish = m.call('m2', {
    tool: 'write_document',
    args: { path: HANDOFF_DOC, content: 'reviewed status\n' },
  });
  assert.equal(publish.cedar?.decision, 'allow');
  assert.equal(publish.mediation?.verdict, 'allow');

  const egress = m.call('m3', {
    tool: 'write_document',
    args: { path: PORTAL_DOC, content: 'public status\n' },
  });
  assert.equal(egress.cedar?.decision, 'allow');
  assert.equal(egress.mediation?.verdict, 'allow');
  const egressRecord = h.mediator.ledger().at(-1);
  assert.deepEqual(
    (egressRecord?.sinks ?? []).map((s) => s.kind),
    ['egress-write'],
    'the egress sink still exists - it is mediated, not removed',
  );
  assert.ok(
    (egressRecord?.egressBytesAfter ?? 0) > 0,
    'mediated egress is still metered against a budget',
  );
});

test('T5 the attack cannot complete against the repaired deployment', () => {
  const { run } = attack(REPAIRED, { ledgerPath: ledgerPath() });

  assert.equal(run.completed, false);
  assert.equal(run.stoppedAt, '2:A-writes-handoff');

  // The load-bearing part: this is the PER-CALL layer denying, UNAIDED - and
  // "unaided" is now a checkable claim rather than a description. The mediator
  // ran, as it always does, and it ALLOWED the operation: after the repair the
  // handoff resource is mediator-owned, so A writing it reaches a mediated
  // sink. The refusal therefore came from Cedar alone, because the topology
  // repair moved the resource out of A's scope. The containment layer is not
  // what stops this trace.
  const denied = run.steps[1];
  assert.equal(denied?.mediation?.verdict, 'allow', 'the mediator did NOT stop this');
  assert.equal(denied?.cedar?.decision, 'deny');
  assert.equal(denied?.cedar?.denialKind, 'no-matching-permit');
  assert.deepEqual(denied?.cedar?.determiningPolicies, []);
  assert.equal(
    denied?.cedar?.explanation,
    'deny: no permit policy matched Mcp::Action::"writeDocument" on ' +
      'Mcp::Document::"corp/handoff/status.md" for Mcp::Session::"sess-agent-a" at t=5000; ' +
      'Cedar is default-deny, so this is a denial by absence of authority rather than by ' +
      'an explicit rule',
  );

  // And the secret never moves.
  assert.equal(
    run.steps.some((s) => s.content.includes(SECRET_MARKER) && s.actor !== AGENT_A),
    false,
  );
});
