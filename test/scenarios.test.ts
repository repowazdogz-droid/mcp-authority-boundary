import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SCENARIOS } from '../src/scenarios.js';
import { harness } from './helper.js';

/**
 * Every scenario's declared outcome, asserted.
 *
 * This is the regression net for the policy set: any edit to a .cedar file that
 * changes a decision, a denial kind, or which policy was determining fails here
 * rather than quietly rewriting what the demo claims to show.
 */
for (const s of SCENARIOS) {
  test(`${s.id} ${s.title}`, () => {
    const { pep, restore } = harness({
      session: s.session,
      clock: s.clock,
      overlays: s.overlays,
      version: s.policyVersion,
    });
    try {
      s.steps.forEach((step, i) => {
        const expected = s.expect[i];
        assert.ok(expected, `${s.id} step ${i} has no declared expectation`);

        const entry =
          step.kind === 'tool' ? pep.handle(step.call).entry : pep.handleDelegation(step.child);
        const d = entry.decision;

        assert.equal(d.decision, expected.decision, `${s.id} step ${i}: ${d.explanation}`);
        if (expected.denialKind !== undefined) {
          assert.equal(d.denialKind, expected.denialKind, `${s.id} step ${i} denial kind`);
        }
        if (expected.policies !== undefined) {
          assert.deepEqual(
            [...d.determiningPolicies].sort(),
            [...expected.policies].sort(),
            `${s.id} step ${i} determining policies`,
          );
        }
      });
    } finally {
      restore();
    }
  });
}

test('the scenario set covers every declared attack family', () => {
  const families = new Set(SCENARIOS.map((s) => s.family));
  for (const required of [
    'baseline',
    'delegation',
    'least-privilege',
    'injection',
    'misuse',
    'escalation',
    'revocation',
    'bypass',
    'guardrail',
    'limitation',
  ]) {
    assert.ok(families.has(required), `no scenario exercises the ${required} family`);
  }
});

test('every negative control is permitted, and each marks a different edge', () => {
  const controls = SCENARIOS.filter((s) => s.negativeControl);
  // S18: authority versus intent. S24: the tool call versus its external consequence.
  // Two edges, not one, and neither is a catch.
  assert.deepEqual(
    controls.map((s) => s.id),
    ['S18', 'S24'],
  );
  for (const c of controls) {
    assert.ok(
      c.expect.every((e) => e.decision === 'allow'),
      `${c.id} must be permitted - a negative control marks the edge of the claim, not a catch`,
    );
  }
});
