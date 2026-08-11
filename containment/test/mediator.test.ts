/**
 * The mediator's own behaviour: sink classification, fail-closed, budgets, rate
 * limit, circuit breaker, delegation, ledger chaining.
 *
 * Pure - no Cedar, no enforcement point. T1-T5 exercise the composed path; this
 * file exists so that nothing built here is merely asserted to work.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { ResolvedOperation } from '../../src/types.js';
import { classifySinks, Mediator, type Budgets } from '../src/mediator.js';
import type { Graph } from '../src/graph.js';

const GRAPH: Graph = {
  name: 'unit',
  principals: [
    { id: 'a', kind: 'agent' },
    { id: 'b', kind: 'agent' },
    { id: 'm', kind: 'mediator' },
  ],
  resources: [
    { id: 'private', readers: ['a'], writers: ['a'], egress: false, mediatedBy: null },
    { id: 'b-private', readers: ['b'], writers: ['b'], egress: false, mediatedBy: null },
    { id: 'shared', readers: ['a', 'b'], writers: ['a'], egress: false, mediatedBy: null },
    { id: 'portal', readers: ['a', 'b'], writers: ['m'], egress: true, mediatedBy: 'm' },
    { id: 'leaky', readers: ['a'], writers: ['a'], egress: true, mediatedBy: null },
  ],
  edges: [],
};

function write(path: string, bytes: number): ResolvedOperation {
  return {
    tool: 'write_document',
    path,
    content: 'x'.repeat(bytes),
    byteLen: bytes,
    contentSha256: 'unused-in-these-tests',
  };
}

const TIGHT: Budgets = { egressBytes: 100, sinkOpsPerWindow: 2, windowSize: 1000, breakerTrip: 3 };

// --------------------------------------------------------------------------
// classification
// --------------------------------------------------------------------------

test('reads and deletes reach no effect sink', () => {
  assert.deepEqual(classifySinks({ tool: 'read_document', path: 'private' }, GRAPH, 'a'), []);
  assert.deepEqual(classifySinks({ tool: 'delete_file', path: 'private' }, GRAPH, 'a'), []);
});

test('a write nobody can read and that goes nowhere reaches no sink', () => {
  assert.deepEqual(classifySinks(write('private', 10), GRAPH, 'a'), []);
});

test('a write another agent can read is a channel', () => {
  const s = classifySinks(write('shared', 10), GRAPH, 'a');
  assert.deepEqual(s.map((x) => x.kind), ['channel-write']);
});

test('a mediator publishing is not a channel', () => {
  const s = classifySinks(write('portal', 10), GRAPH, 'm');
  assert.deepEqual(s.map((x) => x.kind), ['egress-write']);
});

test('a write to an undeclared resource is namespace creation', () => {
  const s = classifySinks(write('invented/at/runtime.md', 10), GRAPH, 'a');
  assert.deepEqual(s.map((x) => x.kind), ['namespace-creation']);
});

test('shell and database operations are classified as credential-bearing', () => {
  assert.deepEqual(
    classifySinks({ tool: 'execute_shell', host: 'build-01', command: 'ls' }, GRAPH, 'a')
      .map((x) => x.kind)
      .sort(),
    ['credential-use', 'network-connection'],
  );
  assert.deepEqual(
    classifySinks(
      { tool: 'query_database', table: 'crm.customers', statementClass: 'select', sql: 'select 1' },
      GRAPH,
      'a',
    ).map((x) => x.kind),
    ['credential-use'],
  );
});

// --------------------------------------------------------------------------
// decisions
// --------------------------------------------------------------------------

test('an operation reaching no sink is allowed without spending budget', () => {
  const m = new Mediator(GRAPH, TIGHT);
  const r = m.mediate('a', write('private', 10), 'digest', 5000);
  assert.equal(r.verdict, 'allow');
  assert.equal(r.reason, 'no-effect-sink-reached');
  assert.equal(r.egressBytesAfter, 0);
});

test('an unmediated egress write by an agent is denied', () => {
  const m = new Mediator(GRAPH, TIGHT);
  const r = m.mediate('a', write('leaky', 10), 'digest', 5000);
  assert.equal(r.verdict, 'deny');
  assert.match(r.reason, /unmediated effect sink/);
});

test('an undeclared target fails closed, and says so', () => {
  const m = new Mediator(GRAPH, TIGHT);
  const r = m.mediate('a', write('invented/at/runtime.md', 10), 'digest', 5000);
  assert.equal(r.verdict, 'deny');
  assert.match(r.reason, /undeclared target/);
  assert.match(r.reason, /failing closed/);
});

test('an unresolvable operation is denied rather than skipped', () => {
  const m = new Mediator(GRAPH, TIGHT);
  const r = m.mediate('a', null, null, 5000);
  assert.equal(r.verdict, 'deny');
  assert.equal(r.reason, 'unresolvable-operation');
});

test('mediated egress is metered and the budget is enforced', () => {
  const m = new Mediator(GRAPH, TIGHT);
  const first = m.mediate('m', write('portal', 60), 'd1', 5000);
  assert.equal(first.verdict, 'allow');
  assert.equal(first.egressBytesAfter, 60);

  const second = m.mediate('m', write('portal', 60), 'd2', 5000);
  assert.equal(second.verdict, 'deny');
  assert.equal(second.reason, 'egress-budget-exhausted');
  assert.equal(second.egressBytesAfter, 60, 'a denied operation spends nothing');
});

test('the rate limit counts sink-reaching operations per window', () => {
  const m = new Mediator(GRAPH, { ...TIGHT, egressBytes: 10_000 });
  assert.equal(m.mediate('m', write('portal', 1), 'd', 5000).verdict, 'allow');
  assert.equal(m.mediate('m', write('portal', 1), 'd', 5000).verdict, 'allow');
  const third = m.mediate('m', write('portal', 1), 'd', 5000);
  assert.equal(third.verdict, 'deny');
  assert.equal(third.reason, 'rate-limit-exceeded');

  // A later window resets the allowance.
  assert.equal(m.mediate('m', write('portal', 1), 'd', 9000).verdict, 'allow');
});

test('the circuit breaker trips after repeated denials and then refuses everything', () => {
  const m = new Mediator(GRAPH, TIGHT);
  for (let i = 0; i < 3; i++) {
    assert.equal(m.mediate('a', write('leaky', 1), 'd', 5000).verdict, 'deny');
  }
  // Even an operation that reaches no sink at all is now refused.
  const after = m.mediate('a', write('private', 1), 'd', 5000);
  assert.equal(after.verdict, 'deny');
  assert.equal(after.reason, 'circuit-breaker-open');
  assert.equal(after.breakerOpen, true);

  // The breaker is per principal, not global. Note the target has to be b's own
  // private resource: b writing `private` would be a channel-write, because a
  // can read it. Classification asks what the effect REACHES, never whether the
  // actor was authorized to attempt it - that question belongs to the per-call
  // layer and duplicating it here would be a second opinion about authority.
  assert.equal(m.mediate('b', write('b-private', 1), 'd', 5000).verdict, 'allow');
});

test('capability creation by an agent is denied; by a mediator it is allowed', () => {
  const m = new Mediator(GRAPH, TIGHT);
  const byAgent = m.mediateDelegation('a', 'child-session');
  assert.equal(byAgent.verdict, 'deny');
  assert.deepEqual(byAgent.sinks.map((s) => s.kind), ['delegation']);

  const byMediator = m.mediateDelegation('m', 'child-session');
  assert.equal(byMediator.verdict, 'allow');
});

test('the mediation ledger is hash-chained and attributes every record', () => {
  const m = new Mediator(GRAPH, TIGHT);
  m.mediate('a', write('private', 1), 'd1', 5000);
  m.mediate('b', write('leaky', 1), 'd2', 5000);
  m.mediate('m', write('portal', 1), 'd3', 5000);

  const led = m.ledger();
  assert.equal(led.length, 3);
  assert.deepEqual(led.map((r) => r.principal), ['a', 'b', 'm']);
  assert.deepEqual(led.map((r) => r.seq), [0, 1, 2]);
  assert.equal(led[0]?.prevHash, '0'.repeat(64));
  assert.equal(led[1]?.prevHash, led[0]?.hash);
  assert.equal(led[2]?.prevHash, led[1]?.hash);
  assert.equal(new Set(led.map((r) => r.hash)).size, 3);
});
