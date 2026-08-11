import { permitAllMediator } from '../src/mediation.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { harness } from './helper.js';
import { EnforcementPoint } from '../src/enforce.js';
import { Ledger } from '../src/ledger.js';
import { loadEntities, loadPolicy } from '../src/policy.js';
import { snapshotDocuments } from '../src/tools.js';
import { consumeGrant } from '../src/mediation.js';

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

test('A1 [WAS EXPLOITABLE, NOW BLOCKED] a non-string payload is refused before Cedar', () => {
  // HISTORICAL WITNESS (docs/AUDIT.md A1): this exact call was authorized as a
  // zero-byte write and then String()-coerced into a 100,000-byte write, under a
  // grant capped at 4096. The resolver now rejects non-strings instead of
  // substituting '' for them, so the operation never comes into existence.
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const PAYLOAD = 'x'.repeat(100_000);
    const before = snapshotDocuments().documents.get('corp/public/notes.md');

    const { entry } = pep.handle({
      tool: 'write_document',
      args: { path: 'corp/public/notes.md', content: [PAYLOAD] },
    });

    assert.equal(entry.decision.decision, 'deny');
    assert.equal(entry.decision.denialKind, 'unresolvable-resource');
    assert.match(entry.decision.explanation, /content must be a string; got array/);
    assert.equal(entry.operation, null, 'no canonical operation was ever built');

    const after = snapshotDocuments().documents.get('corp/public/notes.md');
    assert.equal(after, before, 'the document is untouched');
  } finally {
    restore();
  }
});

test('A1b the string case is still correctly denied by policy, not by type rejection', () => {
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const { entry } = pep.handle({
      tool: 'write_document',
      args: { path: 'corp/public/notes.md', content: 'x'.repeat(100_000) },
    });
    assert.equal(entry.decision.decision, 'deny');
    assert.deepEqual(entry.decision.determiningPolicies, ['forbid-oversized-write']);
    // and the operation DID exist, with an honest byte count
    assert.equal(entry.operation?.tool, 'write_document');
    assert.equal((entry.cedarRequest.context as { byteLen: number }).byteLen, 100_000);
  } finally {
    restore();
  }
});

test('A1c the ledger now records the canonical operation and both effect fingerprints', () => {
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const { entry } = pep.handle({
      tool: 'write_document',
      args: { path: 'corp/public/notes.md', content: 'y'.repeat(900) },
    });
    assert.equal(entry.decision.decision, 'allow');
    assert.ok(entry.operation, 'the operation is in the record');
    assert.ok(entry.operationSha256, 'and so is its digest');
    assert.equal((entry.cedarRequest.context as { byteLen: number }).byteLen, 900);
    assert.deepEqual(entry.observedEffect, entry.authorizedEffect);
    assert.equal(entry.observedEffect?.byteLen, 900);
  } finally {
    restore();
  }
});

test('A1d execution consumes the operation, so mutating the raw args after resolution changes nothing', () => {
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const args: Record<string, unknown> = { path: 'corp/public/notes.md', content: 'authorized' };
    const call = { tool: 'write_document', args };
    // hand the same mutable object to the enforcement point, then mutate it
    const { entry } = pep.handle(call);
    args['content'] = 'TAMPERED AFTER RESOLUTION';
    args['path'] = 'corp/hr/salaries.csv';

    assert.equal(entry.decision.decision, 'allow');
    const world = snapshotDocuments();
    assert.equal(world.documents.get('corp/public/notes.md'), 'authorized');
    assert.match(world.documents.get('corp/hr/salaries.csv') ?? '', /^name,salary/);
  } finally {
    restore();
  }
});

test('A1e the resolved operation is frozen, so it cannot be edited after authorization', () => {
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const { entry } = pep.handle({
      tool: 'write_document',
      args: { path: 'corp/public/notes.md', content: 'frozen' },
    });
    const op = entry.operation as { content: string };
    assert.ok(Object.isFrozen(op));
    // ESM is strict mode, so assignment to a frozen property throws
    assert.throws(() => {
      op.content = 'mutated';
    }, TypeError);
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
  const path = join(tmpdir(), `mab-adv-${sessionId}-${clock}.jsonl`);
  try {
    unlinkSync(path);
  } catch {
    /* first run */
  }
  return new EnforcementPoint({
    policy,
    entities: () => loadEntities(extra),
    ledger: new Ledger(path),
    session: { type: 'Mcp::Session', id: sessionId },
    now: () => clock,
    wallClock: '2026-08-07T00:00:00.000Z',
    mediator: permitAllMediator(),
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

test('A3 [WAS DEFECTIVE, NOW FIXED] a live enforcement point crosses its own expiry', () => {
  // HISTORICAL WITNESS (docs/AUDIT.md A3): `now` was a fixed number captured at
  // construction, so 200 consecutive decisions all saw t=2000 and a grant
  // expiring at 5000 never expired. The clock is now a function read per decision.
  let t = 2000;
  const { pep, restore } = harness({ session: 'sess-analyst-delegated', clock: () => t });
  try {
    const early = pep.handle({ tool: 'read_document', args: { path: 'corp/finance/q3-forecast.md' } });
    assert.equal(early.entry.decision.decision, 'allow');
    assert.equal(early.entry.logicalTime, 2000);

    // same enforcement point, same session, no restart - only time moves
    t = 6000;
    const late = pep.handle({ tool: 'read_document', args: { path: 'corp/finance/q3-forecast.md' } });
    assert.equal(late.entry.decision.decision, 'deny');
    assert.deepEqual(late.entry.decision.determiningPolicies, ['forbid-outside-validity-window']);
    assert.equal(late.entry.logicalTime, 6000);
  } finally {
    restore();
  }
});

test('A3c the clock is read per decision, so each entry records the time it actually saw', () => {
  let t = 1500;
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: () => (t += 1000) });
  try {
    const times = [0, 1, 2].map(
      () => pep.handle({ tool: 'read_document', args: { path: 'corp/public/roadmap.md' } }).entry.logicalTime,
    );
    assert.deepEqual(times, [2500, 3500, 4500]);
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

test('A4 [WAS DEFECTIVE, NOW FIXED] revocation on disk reaches a running enforcement point', () => {
  // HISTORICAL WITNESS (docs/AUDIT.md A4): the entity store was read once at
  // construction, so flipping `revoked` never reached a running process while
  // ARCHITECTURE.md claimed revocation was immediate. The store is now read per
  // decision.
  const backup = readFileSync(ENTITIES, 'utf8');
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const before = pep.handle({ tool: 'read_document', args: { path: 'corp/public/roadmap.md' } });
    assert.equal(before.entry.decision.decision, 'allow');

    const revoked = backup.replace(
      /("id": "sess-alice-root" \},\n[\s\S]*?)"revoked": false/,
      '$1"revoked": true',
    );
    assert.notEqual(revoked, backup, 'the edit must actually change the file');
    writeFileSync(ENTITIES, revoked);

    // SAME enforcement point, next decision, no restart
    const after = pep.handle({ tool: 'read_document', args: { path: 'corp/public/roadmap.md' } });
    assert.equal(after.entry.decision.decision, 'deny');
    assert.deepEqual(after.entry.decision.determiningPolicies, ['forbid-revoked-session']);
    // and the entry records the store it actually read
    assert.notEqual(after.entry.entitiesSha256, before.entry.entitiesSha256);
  } finally {
    writeFileSync(ENTITIES, backup);
    restore();
  }
});

// ---------------------------------------------------------------------------
// A5. The grant is not bound to the resource it was issued for
// ---------------------------------------------------------------------------

test('A5 [CLOSED BY THE NEW BINDING] a grant is bound to the operation digest', () => {
  // HISTORICAL: consumeGrant checked only the tool name, so the resource the
  // grant carried was decorative. It now compares the operation digest, which
  // subsumes the resource and every other security-relevant field.
  assert.throws(
    () => consumeGrant({ operationSha256: 'not-a-real-grant' }, { tool: 'read_document', path: 'x' }),
    /no grant issued by the policy decision point/,
  );
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

test('A8 the A1 divergence can no longer be recorded, so there is no such ledger to replay', async () => {
  const path = join(tmpdir(), 'mab-adv-replay.jsonl');
  try {
    unlinkSync(path);
  } catch {
    /* fine */
  }
  const policy = loadPolicy('v1');
  const pep = new EnforcementPoint({
    policy,
    entities: () => loadEntities(),
    ledger: new Ledger(path),
    session: { type: 'Mcp::Session', id: 'sess-writer-delegated' },
    now: () => 2000,
    wallClock: '2026-08-07T00:00:00.000Z',
    mediator: permitAllMediator(),
  });
  const { entry } = pep.handle({
    tool: 'write_document',
    args: { path: 'corp/public/notes.md', content: ['z'.repeat(50_000)] },
  });

  // previously this produced an allow with byteLen 0 and a 50KB write
  assert.equal(entry.decision.decision, 'deny');
  assert.equal(entry.operation, null);
  assert.equal(entry.observedEffect, null);

  const { readLedger, verifyChain } = await import('../src/ledger.js');
  const entries = readLedger(path);
  assert.ok(verifyChain(entries).ok);
  assert.equal(entries.filter((e) => e.toolResult !== null).length, 0);
});
