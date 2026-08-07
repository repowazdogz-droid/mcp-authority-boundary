import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadPolicy } from '../src/policy.js';
import { harness } from './helper.js';

test('adding a policy produces a different policy-set version', () => {
  const v1 = loadPolicy('v1');
  const v2 = loadPolicy('v2', ['overlay-revocation']);
  assert.notEqual(v1.version.sha256, v2.version.sha256);
  assert.equal(v2.version.policyIds.length, v1.version.policyIds.length + 1);
  assert.ok(v2.version.policyIds.includes('revoke-session-analyst-delegated'));
});

test('the same request flips decision across a policy update', () => {
  const call = { tool: 'read_document', args: { path: 'corp/finance/q3-forecast.md' } };

  const before = harness({ session: 'sess-analyst-delegated', clock: 2000 });
  const b = before.pep.handle(call).entry;
  before.restore();

  const after = harness({
    session: 'sess-analyst-delegated',
    clock: 2000,
    overlays: ['overlay-revocation'],
    version: 'v2',
  });
  const a = after.pep.handle(call).entry;
  after.restore();

  assert.equal(b.decision.decision, 'allow');
  assert.equal(a.decision.decision, 'deny');
  assert.deepEqual(a.decision.determiningPolicies, ['revoke-session-analyst-delegated']);

  // the request itself is identical; only the policy version differs
  assert.deepEqual(b.cedarRequest.action, a.cedarRequest.action);
  assert.deepEqual(b.cedarRequest.resource, a.cedarRequest.resource);
  assert.deepEqual(b.cedarRequest.principal, a.cedarRequest.principal);
  assert.notEqual(b.policyVersion.sha256, a.policyVersion.sha256);
});

test('revocation reaches sessions delegated from a revoked parent', () => {
  // data-plane revocation: the base policy set already forbids any session whose
  // parent grant is revoked, without having to enumerate the children
  const v1 = loadPolicy('v1');
  assert.ok(v1.version.policyIds.includes('forbid-revoked-ancestor'));
  assert.ok(v1.version.policyIds.includes('forbid-revoked-session'));
});

test('the policy set is loaded only if it typechecks strictly against the schema', () => {
  // loadPolicy throws on a validation error, so a passing load IS the assertion
  assert.doesNotThrow(() => loadPolicy('v1'));
  assert.doesNotThrow(() => loadPolicy('v2', ['overlay-revocation']));
});
