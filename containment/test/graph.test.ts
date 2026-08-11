/**
 * Unit tests for the pure checker.
 *
 * Nothing here imports the host, Cedar, or a policy set. If these pass, the
 * invariants are right as invariants, independently of whether the rest of the
 * layer is wired up correctly.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check, edgesOf, byInvariant, hasCritical, type Graph } from '../src/graph.js';

const A = { id: 'agent-a', kind: 'agent' } as const;
const B = { id: 'agent-b', kind: 'agent' } as const;
const M = { id: 'mediator', kind: 'mediator' } as const;

function g(resources: Graph['resources'], principals: Graph['principals'] = [A, B, M]): Graph {
  return { name: 'unit', principals, resources, edges: [] };
}

test('an empty graph has no violations', () => {
  assert.deepEqual(check(g([])), []);
});

test('a resource only one agent touches is not a channel', () => {
  const v = check(g([{ id: 'r', readers: ['agent-a'], writers: ['agent-a'], egress: false, mediatedBy: null }]));
  assert.deepEqual(v, []);
});

test('C1 fires when one agent writes and a different agent reads', () => {
  const v = check(g([{ id: 'board', readers: ['agent-b'], writers: ['agent-a'], egress: false, mediatedBy: null }]));
  const c1 = byInvariant(v, 'C1');
  assert.equal(c1.length, 1);
  assert.deepEqual(c1[0]?.witness, ['agent-a->agent-b']);
  assert.equal(c1[0]?.severity, 'high');
  // No egress, so no C2 and no conjunction.
  assert.equal(byInvariant(v, 'C2').length, 0);
  assert.equal(byInvariant(v, 'CRIT').length, 0);
});

test('C1 is silenced by a genuine mediator', () => {
  const v = check(g([{ id: 'board', readers: ['agent-b'], writers: ['agent-a'], egress: false, mediatedBy: 'mediator' }]));
  assert.deepEqual(v, []);
});

test('C1 does not fire when the writer is a mediator rather than an agent', () => {
  // The system principal publishing to a resource many agents read is the
  // repaired shape, not the vulnerable one.
  const v = check(g([{ id: 'bulletin', readers: ['agent-a', 'agent-b'], writers: ['mediator'], egress: false, mediatedBy: null }]));
  assert.deepEqual(v, []);
});

test('C2 fires when an agent can write an egress-bearing resource', () => {
  const v = check(g([{ id: 'portal', readers: ['agent-a'], writers: ['agent-a'], egress: true, mediatedBy: null }]));
  const c2 = byInvariant(v, 'C2');
  assert.equal(c2.length, 1);
  assert.deepEqual(c2[0]?.witness, ['agent-a']);
  assert.equal(byInvariant(v, 'C1').length, 0);
});

test('C2 does not fire when only a mediator writes the egress resource', () => {
  const v = check(g([{ id: 'portal', readers: ['agent-a'], writers: ['mediator'], egress: true, mediatedBy: null }]));
  assert.deepEqual(v, []);
});

test('CRIT fires on the conjunction, and C1 and C2 are still reported separately', () => {
  const v = check(g([{ id: 'shared', readers: ['agent-b'], writers: ['agent-a'], egress: true, mediatedBy: null }]));
  assert.equal(byInvariant(v, 'C1').length, 1);
  assert.equal(byInvariant(v, 'C2').length, 1);
  const crit = byInvariant(v, 'CRIT');
  assert.equal(crit.length, 1);
  assert.equal(crit[0]?.severity, 'critical');
  assert.deepEqual([...(crit[0]?.witness ?? [])].sort(), ['agent-a', 'agent-b']);
  assert.equal(hasCritical(v), true);
  assert.equal(v.length, 3);
});

test('mediation claimed by an agent principal is refused, not honoured', () => {
  // The load-bearing case. If this passed, any deployment could silence the
  // checker by naming one of its own agents as the mediator.
  const v = check(g([{ id: 'shared', readers: ['agent-b'], writers: ['agent-a'], egress: true, mediatedBy: 'agent-a' }]));
  const decl = byInvariant(v, 'DECL');
  assert.equal(decl.length, 1);
  assert.equal(decl[0]?.severity, 'critical');
  // and the mediation claim buys nothing:
  assert.equal(byInvariant(v, 'C1').length, 1);
  assert.equal(byInvariant(v, 'C2').length, 1);
  assert.equal(byInvariant(v, 'CRIT').length, 1);
});

test('access granted to an undeclared principal is a declaration error', () => {
  const v = check(g([{ id: 'r', readers: ['ghost'], writers: ['agent-a'], egress: false, mediatedBy: null }]));
  const decl = byInvariant(v, 'DECL');
  assert.equal(decl.length, 1);
  assert.deepEqual(decl[0]?.witness, ['ghost']);
  // An unknown principal is not counted as an agent, so no channel is inferred
  // from it. Fabricating a C1 out of a name nobody declared would be a guess.
  assert.equal(byInvariant(v, 'C1').length, 0);
});

test('mediation claimed by an undeclared principal is refused', () => {
  const v = check(g([{ id: 'r', readers: ['agent-b'], writers: ['agent-a'], egress: false, mediatedBy: 'nobody' }]));
  assert.equal(byInvariant(v, 'DECL').length, 1);
  assert.equal(byInvariant(v, 'C1').length, 1);
});

test('edgesOf derives read and write edges from the access matrix', () => {
  const graph: Graph = {
    name: 'edges',
    principals: [A, B, M],
    resources: [{ id: 'r', readers: ['agent-b'], writers: ['agent-a'], egress: false, mediatedBy: null }],
    edges: [{ kind: 'delegation', from: 'agent-a', to: 'agent-b' }],
  };
  const e = edgesOf(graph);
  assert.equal(e.length, 3);
  assert.deepEqual(e.filter((x) => x.kind === 'read'), [{ kind: 'read', from: 'agent-b', to: 'r' }]);
  assert.deepEqual(e.filter((x) => x.kind === 'write'), [{ kind: 'write', from: 'agent-a', to: 'r' }]);
  assert.equal(e.filter((x) => x.kind === 'delegation').length, 1);
});
