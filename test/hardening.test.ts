import { test } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { canonicalisePath, resolveCall } from '../src/resolve.js';
import { parseSelect } from '../src/sql.js';
import { Ledger, readLedger, readIntents, intentPath, sealPath, verifySeal } from '../src/ledger.js';
import { replay } from '../src/replay.js';
import { sha256Canonical } from '../src/canonical.js';
import { Pdp } from '../src/pdp.js';
import { loadEntities, loadPolicy } from '../src/policy.js';
import { permitAllMediator } from '../src/mediation.js';
import { executeTool, snapshotDocuments } from '../src/tools.js';
import { harness } from './helper.js';

test('SQL consumes the entire language: comma joins, writes and extensions fail closed', () => {
  for (const sql of [
    'SELECT * FROM analytics.metrics, crm.customers',
    'SELECT * FROM analytics.metrics JOIN crm.customers ON 1=1',
    'SELECT * FROM analytics.metrics UNION SELECT * FROM crm.customers',
    'SELECT * FROM analytics.metrics; DELETE FROM crm.customers',
    'DELETE FROM analytics.metrics WHERE 1=1',
    'SELECT * FROM analytics.metrics INTO OUTFILE x',
    'SELECT load_extension(x) FROM analytics.metrics',
    'SELECT * FROM analytics.metrics /* FROM crm.customers */',
    'WITH x AS (DELETE FROM crm.customers) SELECT * FROM analytics.metrics',
    'SELECT * FROM [crm.customers]', 'SELECT * FROM analytics.metrics garbage',
    'SELECT * FROM analytics.metrics\0', 'SELECT * FROM analytics.metrics;;',
  ]) assert.equal(parseSelect(sql), null, sql);
  assert.deepEqual(parseSelect(' SeLeCt\n day, visits FROM Analytics.Metrics ; '), {
    table: 'analytics.metrics', columns: ['day', 'visits'], sql: 'SELECT day, visits FROM analytics.metrics',
  });
  assert.equal(parseSelect('SELECT * FROM analytics.metrics')?.table, 'analytics.metrics');
});

test('virtual path normalization rejects separator and drive aliases before normalization', () => {
  for (const path of ['\\corp\\public\\notes.md', '\\\\server\\share', 'C:relative', 'C:\\absolute', '../outside']) {
    assert.equal(canonicalisePath(path), null, path);
  }
  for (const path of ['corp/public/../public/notes.md', 'corp\\public\\notes.md', '..named/file']) {
    const once = canonicalisePath(path);
    assert.ok(once);
    assert.equal(canonicalisePath(once), once);
  }
});

test('prototype tool names become recorded refusals', () => {
  const h = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    for (const tool of ['constructor', '__proto__', 'toString']) {
      const r = h.pep.handle({ tool, args: {} });
      assert.equal(r.entry.decision.denialKind, 'unresolvable-resource');
    }
    assert.equal(readLedger(h.ledgerPath).length, 3);
  } finally { h.restore(); }
});

test('unknown query columns fail before preparation and do not poison the next call', () => {
  const h = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const invalid = h.pep.handle({ tool: 'query_database', args: { sql: 'SELECT missing FROM analytics.metrics' } });
    assert.equal(invalid.entry.decision.denialKind, 'unresolvable-resource');
    assert.equal(readIntents(h.ledgerPath).length, 0);
    const valid = h.pep.handle({ tool: 'query_database', args: { sql: 'SELECT visits FROM analytics.metrics' } });
    assert.equal(valid.result?.content, 'visits\n42\n');
  } finally { h.restore(); }
});

function grantFixture() {
  const entities = loadEntities();
  const principal = { type: 'Mcp::Session', id: 'sess-alice-root' };
  const resolved = resolveCall({ tool: 'read_document', args: { path: 'corp/public/roadmap.md' } }, {
    requestId: 'hardening', now: 2000, sourceTrust: 'user', entities,
  });
  assert.ok(resolved.ok);
  const call = resolved.call;
  const mediation = permitAllMediator().mediateOperation(principal, call.operation, call.operationSha256, 2000);
  const input = { ...call, principal, entities, mediation };
  return { input, pdp: new Pdp(loadPolicy('v1')) };
}

test('PDP refuses mismatched request resource, action, size, digest and identity', () => {
  const { input, pdp } = grantFixture();
  for (const changed of [
    { ...input, resource: { ...input.resource, id: 'corp/public/notes.md' } },
    { ...input, action: { ...input.action, type: 'Wrong::Action' } },
    { ...input, context: { ...input.context, byteLen: 100 } },
    { ...input, context: { ...input.context, requestId: 'other' } },
    { ...input, operationSha256: '0'.repeat(64) },
  ]) {
    const r = pdp.authorize(changed);
    assert.equal(r.decision.decision, 'deny');
    assert.equal(r.grant, null);
  }
});

test('issued grants cannot be edited, reused, or paired with edited mediation content', () => {
  const { input, pdp } = grantFixture();
  const outcome = pdp.authorize(input);
  assert.ok(outcome.grant);
  assert.throws(() => Object.assign(outcome.grant!, { operationSha256: 'forged' }), TypeError);
  assert.throws(() => executeTool(input.operation, outcome.grant, { ...input.mediation, reason: 'edited' }),
    /mediation content/);
  assert.equal(executeTool(input.operation, outcome.grant, input.mediation).ok, true);
  assert.throws(() => executeTool(input.operation, outcome.grant, input.mediation), /already spent/);
});

test('sealed ledger refuses BEFORE a world mutation, and resealing cannot overwrite its anchor', () => {
  const h = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    new Ledger(h.ledgerPath).seal();
    const before = snapshotDocuments();
    assert.throws(() => h.pep.handle({ tool: 'write_document', args: { path: 'corp/public/notes.md', content: 'forbidden' } }), /sealed/);
    assert.deepEqual(snapshotDocuments(), before);
    assert.throws(() => new Ledger(h.ledgerPath).seal(), /sealed/);
  } finally { h.restore(); }
});

test('write-ahead I/O failure prevents the effect; completion failure retains an unresolved allow', () => {
  const h = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    mkdirSync(intentPath(h.ledgerPath));
    const before = snapshotDocuments();
    assert.throws(() => h.pep.handle({ tool: 'write_document', args: { path: 'corp/public/notes.md', content: 'blocked' } }));
    assert.deepEqual(snapshotDocuments(), before);
  } finally { h.restore(); }
  const h2 = harness({ session: 'sess-writer-delegated', clock: 2000 });
  const original = Ledger.prototype.append;
  try {
    Ledger.prototype.append = () => { throw new Error('injected disk failure'); };
    assert.throws(() => h2.pep.handle({ tool: 'write_document', args: { path: 'corp/public/notes.md', content: 'landed' } }), /injected/);
    assert.equal(snapshotDocuments().documents.get('corp/public/notes.md'), 'landed');
    assert.equal(readIntents(h2.ledgerPath)[0]!.decision.decision, 'allow');
    assert.ok(replay(h2.ledgerPath).findings.some(f => /outcome unknown/.test(f.detail)));
    assert.throws(() => h2.pep.handle({ tool: 'write_document', args: { path: 'corp/public/notes.md', content: 'again' } }), /unresolved/);
  } finally { Ledger.prototype.append = original; h2.restore(); }
});

test('trusted anchor catches tail loss even when attacker rewrites the co-located seal', () => {
  const h = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    for (const content of ['first', 'second']) h.pep.handle({ tool: 'write_document', args: { path: 'corp/public/notes.md', content } });
    new Ledger(h.ledgerPath).seal();
    const anchor = h.ledgerPath + '.held-by-verifier.json';
    copyFileSync(sealPath(h.ledgerPath), anchor);
    assert.equal(replay(h.ledgerPath, anchor).verdict, 'ALL STAGES PASS');
    const first = readLedger(h.ledgerPath)[0]!;
    writeFileSync(h.ledgerPath, JSON.stringify(first) + '\n');
    writeFileSync(sealPath(h.ledgerPath), JSON.stringify({ entries: 1, finalHash: first.hash }));
    assert.equal(verifySeal(h.ledgerPath, [first]).ok, true, 'co-located seal cannot authenticate itself');
    assert.equal(verifySeal(h.ledgerPath, [first], anchor).ok, false);
    assert.equal(replay(h.ledgerPath, anchor).verdict, 'FAILED');
  } finally { h.restore(); }
});

test('malformed seal is a failure, not a successful unchecked stage', () => {
  const h = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    writeFileSync(sealPath(h.ledgerPath), '{"entries":0,"finalHash":null}');
    assert.equal(verifySeal(h.ledgerPath, []).ok, false);
    assert.equal(replay(h.ledgerPath).verdict, 'FAILED');
  } finally { h.restore(); }
});

test('a competing process lock prevents effects, and stale writers cannot append', () => {
  const h = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const before = snapshotDocuments();
    writeFileSync(h.ledgerPath + '.lock', 'held by another process');
    assert.throws(() => h.pep.handle({ tool: 'write_document', args: { path: 'corp/public/notes.md', content: 'blocked' } }), /EEXIST/);
    assert.deepEqual(snapshotDocuments(), before);
  } finally { h.restore(); }
  const h2 = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const stale = new Ledger(h2.ledgerPath);
    h2.pep.handle({ tool: 'read_document', args: { path: 'corp/public/roadmap.md' } });
    assert.throws(() => stale.assertWritable(), /stale writer/);
  } finally { h2.restore(); }
});

test('re-hashing D7 mediation metadata cannot hide a stale mediation hash', () => {
  const h = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const { entry } = h.pep.handle({ tool: 'write_document', args: { path: 'corp/public/notes.md', content: 'control' } });
    entry.mediation!.reason = 'forged explanation';
    const { hash: _, ...body } = entry;
    entry.hash = sha256Canonical(body);
    writeFileSync(h.ledgerPath, JSON.stringify(entry) + '\n');
    writeFileSync(sealPath(h.ledgerPath), JSON.stringify({ entries: 1, finalHash: entry.hash }));
    const result = replay(h.ledgerPath);
    assert.ok(result.findings.some(f => /mediation content/.test(f.detail)));
  } finally { h.restore(); }
});
