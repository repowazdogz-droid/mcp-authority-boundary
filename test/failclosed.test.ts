import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Pdp } from '../src/pdp.js';
import { loadEntities, loadPolicy } from '../src/policy.js';
import { harness } from './helper.js';
import type { CedarContext } from '../src/types.js';

const CTX: CedarContext = {
  now: 2000,
  sourceTrust: 'user',
  byteLen: 0,
  recipientDomain: '',
  requestId: 'fc#0',
};

function pdp(): Pdp {
  return new Pdp(loadPolicy('v1'), loadEntities());
}

test('a request that does not typecheck against the schema is denied, not passed through', () => {
  const d = pdp().decide({
    requestId: 'fc#0',
    principal: { type: 'Mcp::Session', id: 'sess-alice-root' },
    action: { type: 'Mcp::Action', id: 'noSuchAction' },
    resource: { type: 'Mcp::Document', id: 'corp/public/roadmap.md' },
    context: CTX,
  });
  assert.equal(d.decision, 'deny');
  assert.equal(d.denialKind, 'request-validation-failure');
  assert.match(d.errors.join(' '), /does not exist in the supplied schema/);
});

test('a request naming an entity that does not exist is denied, and is not reported as a policy decision', () => {
  const d = pdp().decide({
    requestId: 'fc#1',
    principal: { type: 'Mcp::Session', id: 'sess-does-not-exist' },
    action: { type: 'Mcp::Action', id: 'readDocument' },
    resource: { type: 'Mcp::Document', id: 'corp/public/roadmap.md' },
    context: CTX,
  });
  assert.equal(d.decision, 'deny');
  // The important half: Cedar returns `deny` here, but with an empty reason and
  // an evaluation error. Reporting that as "denied by policy X" would be a false
  // explanation, so it is classified separately.
  assert.equal(d.denialKind, 'evaluation-error');
  assert.deepEqual(d.determiningPolicies, []);
});

test('a malformed context is denied rather than defaulted', () => {
  const d = pdp().decide({
    requestId: 'fc#2',
    principal: { type: 'Mcp::Session', id: 'sess-alice-root' },
    action: { type: 'Mcp::Action', id: 'readDocument' },
    resource: { type: 'Mcp::Document', id: 'corp/public/roadmap.md' },
    context: { now: 2000 }, // missing sourceTrust, byteLen, recipientDomain
  });
  assert.equal(d.decision, 'deny');
  assert.equal(d.denialKind, 'request-validation-failure');
});

test('a resource the host cannot resolve never reaches Cedar and is refused', () => {
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    for (const call of [
      { tool: 'read_document', args: { path: 'corp/public/nonexistent.md' } },
      { tool: 'read_document', args: { path: '/etc/passwd' } },
      { tool: 'read_document', args: { path: '../../../etc/passwd' } },
      { tool: 'send_email', args: { to: 'not-an-address', body: 'x' } },
      { tool: 'execute_shell', args: { command: 'ls' } },
      { tool: 'no_such_tool', args: {} },
      // two tables: the resolver refuses rather than guessing which one to authorise
      { tool: 'query_database', args: { sql: 'SELECT * FROM crm.customers JOIN analytics.metrics' } },
    ]) {
      const { entry } = pep.handle(call);
      assert.equal(entry.decision.decision, 'deny', JSON.stringify(call));
      assert.equal(entry.decision.denialKind, 'unresolvable-resource', JSON.stringify(call));
    }
  } finally {
    restore();
  }
});
