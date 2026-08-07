import { test } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import type * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { harness } from './helper.js';
import { EnforcementPoint } from '../src/enforce.js';
import { Ledger } from '../src/ledger.js';
import { loadEntities, loadPolicy } from '../src/policy.js';
import { snapshotDocuments } from '../src/tools.js';
import { mintGrant, consumeGrant } from '../src/mediation.js';

/**
 * Adversarial audit probes.
 *
 * These are counterexamples, not feature tests. Each one names a finding from
 * docs/AUDIT.md and pins the behaviour that finding describes, so that a later
 * fix flips a test rather than silently changing the story.
 *
 * Tests named `DEFECT:` assert the CURRENT, WRONG behaviour on purpose. They are
 * the evidence that the defect is real. Fixing the defect must flip them.
 */

const ENTITIES = new URL('../../entities/entities.json', import.meta.url).pathname;

// ---------------------------------------------------------------------------
// A1. Authorization/execution divergence via argument type confusion
// ---------------------------------------------------------------------------

test('A1 write_document: Cedar is shown byteLen 0 while the tool writes the real payload', () => {
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const PAYLOAD = 'x'.repeat(100_000);
    // `content` is an ARRAY, not a string. resolve.ts measures only strings and
    // substitutes '' otherwise; tools.ts coerces with String() and writes it.
    const { entry } = pep.handle({
      tool: 'write_document',
      args: { path: 'corp/public/notes.md', content: [PAYLOAD] },
    });

    const ctx = entry.cedarRequest.context as { byteLen: number };
    assert.equal(ctx.byteLen, 0, 'Cedar was asked about a zero-byte write');
    assert.equal(entry.decision.decision, 'allow');

    const written = snapshotDocuments().get('corp/public/notes.md') ?? '';
    assert.equal(written.length, PAYLOAD.length, 'but 100000 bytes were written');

    // the grant's byte budget is 4096; the write exceeded it by 24x
    assert.ok(written.length > 4096 * 24);
  } finally {
    restore();
  }
});

test('A1b the same session is correctly denied when the payload is a string', () => {
  // the negative control: the policy DOES work, so A1 is a resolver defect and
  // not a policy defect
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const { entry } = pep.handle({
      tool: 'write_document',
      args: { path: 'corp/public/notes.md', content: 'x'.repeat(100_000) },
    });
    assert.equal(entry.decision.decision, 'deny');
    assert.deepEqual(entry.decision.determiningPolicies, ['forbid-oversized-write']);
  } finally {
    restore();
  }
});

test('A1c the ledger does not record the resolved arguments, so the divergence is invisible in the record', () => {
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const { entry } = pep.handle({
      tool: 'write_document',
      args: { path: 'corp/public/notes.md', content: ['y'.repeat(9000)] },
    });
    // the record holds the raw model call and the Cedar context, but nothing
    // that says what the tool actually received or wrote
    assert.equal((entry.cedarRequest.context as { byteLen: number }).byteLen, 0);
    assert.match(entry.toolResult!.summary, /wrote 9000 bytes/);
    // the ledger has no field for the resolved args, so a replay cannot compare
    // "what was authorized" against "what ran"
    assert.equal((entry as unknown as Record<string, unknown>)['resolvedArgs'], undefined);
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// A2. Transitive attenuation laundering
// ---------------------------------------------------------------------------

const AGENT = { __entity: { type: 'Mcp::Agent', id: 'assistant' } };
const ALICE = { __entity: { type: 'Mcp::Human', id: 'alice' } };
const perm = (id: string) => ({ __entity: { type: 'Mcp::Permission', id } });
const scope = (id: string) => ({ __entity: { type: 'Mcp::Scope', id } });
const sess = (id: string) => ({ __entity: { type: 'Mcp::Session', id } });

function session(id: string, attrs: Record<string, unknown>): cedar.EntityJson {
  return {
    uid: { type: 'Mcp::Session', id },
    attrs: { agent: AGENT, delegator: ALICE, revoked: false, ...attrs } as never,
    parents: [{ type: 'Mcp::Agent', id: 'assistant' }],
  } as cedar.EntityJson;
}

/** A widens root's expiry (9000 -> 99999). B is a faithful child of A. */
const A_WIDENED = session('sess-A-widened', {
  permission: perm('admin'),
  scope: scope('org'),
  notBefore: 1000,
  expiresAt: 99999,
  maxWriteBytes: 1048576,
  depth: 1,
  delegatedFrom: sess('sess-alice-root'),
});

const B_LAUNDERED = session('sess-B-laundered', {
  permission: perm('admin'),
  scope: scope('org'),
  notBefore: 1000,
  expiresAt: 99999,
  maxWriteBytes: 1048576,
  depth: 2,
  delegatedFrom: sess('sess-A-widened'),
});

function pepWith(extra: cedar.EntityJson[], sessionId: string, clock: number) {
  const policy = loadPolicy('v1');
  const entities = loadEntities(extra);
  const path = `/tmp/mab-adv-${sessionId}-${clock}.jsonl`;
  try {
    unlinkSync(path);
  } catch {
    /* first run */
  }
  return new EnforcementPoint({
    policy,
    entities,
    ledger: new Ledger(path),
    session: { type: 'Mcp::Session', id: sessionId },
    now: clock,
    wallClock: '2026-08-07T00:00:00.000Z',
  });
}

test('A2 the direct widener IS caught - the backstop works one level up', () => {
  const pep = pepWith([A_WIDENED], 'sess-A-widened', 2000);
  const { entry } = pep.handle({ tool: 'read_document', args: { path: 'corp/public/roadmap.md' } });
  assert.equal(entry.decision.decision, 'deny');
  assert.deepEqual(entry.decision.determiningPolicies, ['forbid-widening-delegation']);
});

test('DEFECT A2: a faithful child of a widened parent launders the widening', () => {
  // B is attenuated correctly with respect to A, and forbid-widening-delegation
  // only ever compares a session to its IMMEDIATE parent. So B inherits an
  // expiry that its grandparent never had.
  const pep = pepWith([A_WIDENED, B_LAUNDERED], 'sess-B-laundered', 2000);
  const { entry } = pep.handle({ tool: 'read_document', args: { path: 'corp/public/roadmap.md' } });
  assert.equal(entry.decision.decision, 'allow', 'B acts despite descending from a blocked grant');
  assert.deepEqual(entry.decision.determiningPolicies, ['permit-read-tier']);
});

test('DEFECT A2b: the laundered session outlives the root grant it descends from', () => {
  // t = 9500. The root session expired at 9000 and is denied. B, two hops below
  // it, is still allowed - derived authority strictly exceeds root authority.
  const root = pepWith([], 'sess-alice-root', 9500);
  const rootCall = root.handle({ tool: 'read_document', args: { path: 'corp/public/roadmap.md' } });
  assert.equal(rootCall.entry.decision.decision, 'deny');
  assert.deepEqual(rootCall.entry.decision.determiningPolicies, ['forbid-outside-validity-window']);

  const b = pepWith([A_WIDENED, B_LAUNDERED], 'sess-B-laundered', 9500);
  const bCall = b.handle({ tool: 'read_document', args: { path: 'corp/public/roadmap.md' } });
  assert.equal(bCall.entry.decision.decision, 'allow', 'the descendant outlives the ancestor');
});

// ---------------------------------------------------------------------------
// A3. The clock is captured once per enforcement point, not read per decision
// ---------------------------------------------------------------------------

test('DEFECT A3: expiry is evaluated against session-start time, so a live session never expires', () => {
  // The analyst grant expires at 5000. An enforcement point constructed at 2000
  // keeps answering 2000 forever, because EnforcementConfig.now is a number and
  // nothing re-reads a clock.
  const { pep, restore } = harness({ session: 'sess-analyst-delegated', clock: 2000 });
  try {
    for (let i = 0; i < 200; i++) {
      const { entry } = pep.handle({
        tool: 'read_document',
        args: { path: 'corp/finance/q3-forecast.md' },
      });
      assert.equal(entry.decision.decision, 'allow');
      assert.equal((entry.cedarRequest.context as { now: number }).now, 2000);
    }
    // 200 decisions later the clock has not moved. In deployment this is a
    // session that outlives its own expiry for as long as the process runs.
  } finally {
    restore();
  }
});

test('A3b expiry does fire when a NEW enforcement point is built past the window', () => {
  const { pep, restore } = harness({ session: 'sess-analyst-delegated', clock: 6000 });
  try {
    const { entry } = pep.handle({
      tool: 'read_document',
      args: { path: 'corp/finance/q3-forecast.md' },
    });
    assert.equal(entry.decision.decision, 'deny');
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// A4. The entity store is cached for the life of the enforcement point
// ---------------------------------------------------------------------------

test('DEFECT A4: flipping `revoked` on disk does not affect a running enforcement point', () => {
  const backup = readFileSync(ENTITIES, 'utf8');
  copyFileSync(ENTITIES, '/tmp/mab-entities.bak');
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const before = pep.handle({ tool: 'read_document', args: { path: 'corp/public/roadmap.md' } });
    assert.equal(before.entry.decision.decision, 'allow');

    // revoke the root session at the data plane, on disk
    const revoked = backup.replace(
      /("id": "sess-alice-root" \},\n[\s\S]*?)"revoked": false/,
      '$1"revoked": true',
    );
    assert.notEqual(revoked, backup, 'the edit must actually change the file');
    writeFileSync(ENTITIES, revoked);

    // the RUNNING enforcement point is unaffected: the store was read once
    const after = pep.handle({ tool: 'read_document', args: { path: 'corp/public/roadmap.md' } });
    assert.equal(
      after.entry.decision.decision,
      'allow',
      'revocation on disk did not reach the running process',
    );

    // a freshly constructed one does see it
    const fresh = harness({ session: 'sess-alice-root', clock: 2000 });
    const freshCall = fresh.pep.handle({
      tool: 'read_document',
      args: { path: 'corp/public/roadmap.md' },
    });
    fresh.restore();
    assert.equal(freshCall.entry.decision.decision, 'deny');
    assert.deepEqual(freshCall.entry.decision.determiningPolicies, ['forbid-revoked-session']);
  } finally {
    writeFileSync(ENTITIES, backup);
    restore();
  }
});

// ---------------------------------------------------------------------------
// A5. The grant is not bound to the resource it was issued for
// ---------------------------------------------------------------------------

test('DEFECT A5: consumeGrant checks the tool but never the resource or policy version', () => {
  const g = mintGrant(
    'audit#1',
    'read_document',
    { type: 'Mcp::Document', id: 'corp/public/roadmap.md' },
    'some-policy-sha',
  );
  // a grant issued for the public roadmap is accepted for any read_document
  // call; nothing at consumption compares grant.resource to the call's resource
  const consumed = consumeGrant(g, 'read_document');
  assert.equal(consumed.resource.id, 'corp/public/roadmap.md');
  // not reachable from agent input today, because handle() passes the same call
  // object it authorized - but the capability carries a resource that is never
  // checked, so the binding is decorative
});

// ---------------------------------------------------------------------------
// A6. Action classification versus what the tool actually accepts
// ---------------------------------------------------------------------------

test('DEFECT A6: a destructive SQL statement is authorized as a read-only action', () => {
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const { entry } = pep.handle({
      tool: 'query_database',
      args: { sql: 'DELETE FROM analytics.metrics WHERE 1=1' },
    });
    assert.equal(entry.cedarRequest.action.id, 'queryDatabase');
    assert.equal(entry.decision.decision, 'allow');
    // queryDatabase is declared in readOnlyGroup, so this DELETE was authorized
    // by permit-read-tier. The tool simulates, so nothing is destroyed here.
    assert.deepEqual(entry.decision.determiningPolicies, ['permit-read-tier']);
  } finally {
    restore();
  }
});

test('DEFECT A6b: the tool ignores the SQL entirely, so the resolver is never tested against real behaviour', () => {
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const { result } = pep.handle({
      tool: 'query_database',
      args: { sql: 'SELECT * FROM analytics.metrics' },
    });
    // rows are chosen by resource id, not by executing the query, so a resolver
    // that bound the wrong table would still return "correct-looking" data
    assert.match(result!.content, /day,visits/);
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// A7. Over-denial: the closed-world entity store does much of the work
// ---------------------------------------------------------------------------

test('A7 legitimate actions are denied because the resource is not pre-registered', () => {
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const denials = [
      // creating a new document is impossible: the entity must already exist
      { tool: 'write_document', args: { path: 'corp/public/new-report.md', content: 'hi' } },
      // emailing a real colleague who is not in the entity store
      { tool: 'send_email', args: { to: 'bob@example.com', body: 'hello' } },
      // a legitimate two-table join
      {
        tool: 'query_database',
        args: { sql: 'SELECT m.visits FROM analytics.metrics m JOIN crm.customers c ON 1=1' },
      },
    ];
    for (const call of denials) {
      const { entry } = pep.handle(call);
      assert.equal(entry.decision.decision, 'deny', JSON.stringify(call));
      assert.equal(
        entry.decision.denialKind,
        'unresolvable-resource',
        'denied by the host before Cedar, not by policy',
      );
    }
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// A8. What the replay verifier cannot see
// ---------------------------------------------------------------------------

test('A8 a ledger containing the A1 divergence replays as VERIFIED', async () => {
  const path = '/tmp/mab-adv-replay.jsonl';
  try {
    unlinkSync(path);
  } catch {
    /* fine */
  }
  const policy = loadPolicy('v1');
  const entities = loadEntities();
  const pep = new EnforcementPoint({
    policy,
    entities,
    ledger: new Ledger(path),
    session: { type: 'Mcp::Session', id: 'sess-writer-delegated' },
    now: 2000,
    wallClock: '2026-08-07T00:00:00.000Z',
  });
  pep.handle({
    tool: 'write_document',
    args: { path: 'corp/public/notes.md', content: ['z'.repeat(50_000)] },
  });

  const { readLedger, verifyChain } = await import('../src/ledger.js');
  const { Pdp } = await import('../src/pdp.js');
  const entries = readLedger(path);
  assert.ok(verifyChain(entries).ok, 'chain is intact');

  const pdp = new Pdp(loadPolicy('v1'), loadEntities());
  const fresh = pdp.decide({
    requestId: entries[0]!.requestId,
    principal: entries[0]!.cedarRequest.principal,
    action: entries[0]!.cedarRequest.action,
    resource: entries[0]!.cedarRequest.resource,
    context: entries[0]!.cedarRequest.context as never,
  });
  // the verifier re-derives the SAME allow, because it re-decides the recorded
  // request - and the recorded request is the resolver's output. The resolver
  // is upstream of everything replay can see.
  assert.equal(fresh.decision, entries[0]!.decision.decision);
  assert.equal(fresh.decision, 'allow');
});
