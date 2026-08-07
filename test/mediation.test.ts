import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ExecutionGrant, consumeGrant, mintGrant } from '../src/mediation.js';
import { executeTool } from '../src/tools.js';
import { readLedger } from '../src/ledger.js';
import { harness } from './helper.js';
import type { ResolvedCall } from '../src/types.js';

const CALL: ResolvedCall = {
  requestId: 'test#0',
  tool: 'read_document',
  action: { type: 'Mcp::Action', id: 'readDocument' },
  resource: { type: 'Mcp::Document', id: 'corp/public/roadmap.md' },
  args: { path: 'corp/public/roadmap.md' },
  context: { now: 2000, sourceTrust: 'user', byteLen: 0, recipientDomain: '', requestId: 'test#0' },
  ignoredModelFields: [],
};

test('a tool cannot run without a grant', () => {
  assert.throws(() => executeTool(CALL, null), /no grant issued by the policy decision point/);
  assert.throws(() => executeTool(CALL, undefined), /no grant issued/);
  assert.throws(() => executeTool(CALL, {}), /no grant issued/);
});

test('a forged grant object is rejected', () => {
  // an attacker who can construct objects still cannot construct this one
  assert.throws(
    () => new ExecutionGrant(Symbol('not-the-guard'), 'test#0', 'read_document', CALL.resource, 'x'),
    /may only be minted by the policy decision point/,
  );

  // nor one shaped like it
  const lookalike = Object.create(ExecutionGrant.prototype) as ExecutionGrant;
  Object.assign(lookalike, { requestId: 'test#0', tool: 'read_document', resource: CALL.resource });
  assert.throws(() => executeTool(CALL, lookalike), /no grant issued/);
});

test('a grant authorises exactly one execution', () => {
  const g = mintGrant('single-use#1', 'read_document', CALL.resource, 'sha');
  consumeGrant(g, 'read_document');
  assert.throws(() => consumeGrant(g, 'read_document'), /already spent/);
});

test('a grant for one tool does not authorise another', () => {
  const g = mintGrant('mismatch#1', 'read_document', CALL.resource, 'sha');
  assert.throws(() => consumeGrant(g, 'delete_file'), /authorises read_document, not delete_file/);
});

test('over a run, no tool result appears without an allow', () => {
  const { pep, ledgerPath, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    pep.handle({ tool: 'read_document', args: { path: 'corp/public/roadmap.md' } }); // allow
    pep.handle({ tool: 'delete_file', args: { path: 'corp/hr/salaries.csv' } }); // deny
    pep.handle({ tool: 'execute_shell', args: { host: 'prod-db-01', command: 'ls' } }); // deny

    const entries = readLedger(ledgerPath);
    for (const e of entries) {
      if (e.toolResult !== null) {
        assert.equal(e.decision.decision, 'allow', `entry ${e.seq} executed without an allow`);
      }
    }
    const executions = entries.filter((e) => e.toolResult !== null).length;
    const allows = entries.filter((e) => e.decision.decision === 'allow').length;
    assert.equal(executions, allows);
  } finally {
    restore();
  }
});
