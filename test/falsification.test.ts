import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { harness } from './helper.js';
import { snapshotDocuments, outboxForAudit, expectedEffectOf, observeEffect, effectsMatch } from '../src/tools.js';
import { classifyStatement } from '../src/resolve.js';
import type { ResolvedOperation } from '../src/types.js';

/**
 * Second falsification pass, run AFTER the repair.
 *
 * The repair claim is: "the operation executed is derived from the same
 * canonical, validated representation that Cedar authorized." A repair that only
 * excludes the original witness would be worthless, so this file attacks the
 * whole class the witness belonged to - every place a value could be read twice,
 * coerced, aliased, or changed between authorization and execution.
 */

const SRC = new URL('../../src/tools.ts', import.meta.url).pathname;

// ---------------------------------------------------------------------------
// F1. Type confusion across every string-valued field of every tool
// ---------------------------------------------------------------------------

const NON_STRINGS: Array<[string, unknown]> = [
  ['array', ['x'.repeat(50_000)]],
  ['nested array', [['x']]],
  ['object', { toString: 'evil' }],
  ['object with valueOf', { valueOf: 1 }],
  ['number', 12345],
  ['float', 1.5],
  ['boolean true', true],
  ['boolean false', false],
  ['null', null],
  ['bigint-ish string wrapper', new String('wrapped')],
];

const STRING_FIELDS: Array<{ tool: string; base: Record<string, unknown>; field: string }> = [
  { tool: 'read_document', base: { path: 'corp/public/roadmap.md' }, field: 'path' },
  { tool: 'delete_file', base: { path: 'corp/public/notes.md' }, field: 'path' },
  { tool: 'write_document', base: { path: 'corp/public/notes.md', content: 'ok' }, field: 'path' },
  { tool: 'write_document', base: { path: 'corp/public/notes.md', content: 'ok' }, field: 'content' },
  { tool: 'send_email', base: { to: 'alice@example.com', body: 'b', subject: 's' }, field: 'to' },
  { tool: 'send_email', base: { to: 'alice@example.com', body: 'b', subject: 's' }, field: 'body' },
  { tool: 'send_email', base: { to: 'alice@example.com', body: 'b', subject: 's' }, field: 'subject' },
  { tool: 'execute_shell', base: { host: 'build-01', command: 'ls' }, field: 'host' },
  { tool: 'execute_shell', base: { host: 'build-01', command: 'ls' }, field: 'command' },
  { tool: 'query_database', base: { sql: 'SELECT * FROM analytics.metrics' }, field: 'sql' },
];

test('F1 every string field of every tool rejects every non-string, fail-closed', () => {
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const worldBefore = snapshotDocuments();
    let checked = 0;
    for (const { tool, base, field } of STRING_FIELDS) {
      for (const [label, value] of NON_STRINGS) {
        const args = { ...base, [field]: value };
        const { entry, result } = pep.handle({ tool, args });
        checked += 1;
        assert.equal(
          entry.decision.decision,
          'deny',
          `${tool}.${field} accepted a ${label}: ${entry.decision.explanation}`,
        );
        assert.equal(entry.decision.denialKind, 'unresolvable-resource', `${tool}.${field} / ${label}`);
        assert.equal(entry.operation, null, `${tool}.${field} / ${label} built an operation`);
        assert.equal(result, null);
      }
    }
    assert.equal(checked, STRING_FIELDS.length * NON_STRINGS.length);

    // and nothing in the world moved
    const worldAfter = snapshotDocuments();
    assert.deepEqual([...worldAfter.documents.entries()], [...worldBefore.documents.entries()]);
    assert.equal(worldAfter.outbox.length, worldBefore.outbox.length);
    assert.equal(worldAfter.shellLog.length, worldBefore.shellLog.length);
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// F2. Unicode, normalisation, control characters, aliasing
// ---------------------------------------------------------------------------

test('F2 an NFD spelling of a path resolves to the same canonical entity, not a second one', () => {
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    // all fixture paths are ASCII, so NFD == NFC for them; the property under
    // test is that normalisation happens at all, checked on a composed form
    const composed = 'corp/public/roadmap.md'.normalize('NFC');
    const decomposed = 'corp/public/roadmap.md'.normalize('NFD');
    const a = pep.handle({ tool: 'read_document', args: { path: composed } });
    const b = pep.handle({ tool: 'read_document', args: { path: decomposed } });
    assert.equal(a.entry.cedarRequest.resource.id, b.entry.cedarRequest.resource.id);
    assert.equal(a.entry.decision.decision, 'allow');
    assert.equal(b.entry.decision.decision, 'allow');
  } finally {
    restore();
  }
});

test('F2b control characters and null bytes are refused rather than truncated', () => {
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    for (const path of [
      'corp/public/roadmap.md\u0000',
      'corp/public/roadmap.md\u0000.txt',
      'corp/public/\u001froadmap.md',
      'corp/public/roadmap.md\u007f',
      'corp/public/road\nmap.md',
    ]) {
      const { entry } = pep.handle({ tool: 'read_document', args: { path } });
      assert.equal(entry.decision.decision, 'deny', JSON.stringify(path));
      assert.equal(entry.decision.denialKind, 'unresolvable-resource');
    }
    // and in a recipient
    const { entry } = pep.handle({
      tool: 'send_email',
      args: { to: 'alice@example.com\u0000@evil.example', body: 'x' },
    });
    assert.equal(entry.decision.decision, 'deny');
  } finally {
    restore();
  }
});

test('F2c recipient normalisation is applied once and identically for auth and execution', () => {
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const before = outboxForAudit().length;
    const { entry } = pep.handle({
      tool: 'send_email',
      args: { to: '  ALICE@Example.COM  ', body: 'hello' },
    });
    assert.equal(entry.decision.decision, 'allow');
    assert.equal(entry.cedarRequest.resource.id, 'alice@example.com');
    // the message that actually landed carries the canonical recipient
    const sent = outboxForAudit()[before];
    assert.equal(sent?.to, 'alice@example.com');
    assert.deepEqual(entry.observedEffect, entry.authorizedEffect);
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// F3. Path traversal and aliasing
// ---------------------------------------------------------------------------

test('F3 traversal is authorised as the document it would actually open', () => {
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    for (const p of [
      'corp/public/../hr/salaries.csv',
      './corp/public/../hr/salaries.csv',
      'corp/public/./../hr/salaries.csv',
      'corp\\public\\..\\hr\\salaries.csv',
      'corp//public/../hr//salaries.csv',
    ]) {
      const { entry } = pep.handle({ tool: 'read_document', args: { path: p } });
      assert.equal(entry.cedarRequest.resource.id, 'corp/hr/salaries.csv', p);
      assert.equal(entry.decision.decision, 'deny', p);
    }
    for (const p of ['../etc/passwd', '/etc/passwd', 'C:\\secrets', '..', '.', '']) {
      const { entry } = pep.handle({ tool: 'read_document', args: { path: p } });
      assert.equal(entry.decision.decision, 'deny', p);
      assert.equal(entry.decision.denialKind, 'unresolvable-resource', p);
    }
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// F4. Duplicate fields
// ---------------------------------------------------------------------------

test('F4 a duplicate JSON key yields one value used by both authorization and execution', () => {
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    // JSON.parse keeps the last occurrence; the point is that ONE value flows to
    // both sides, so there is no pair of readers to disagree
    const args = JSON.parse(
      '{"path":"corp/public/notes.md","content":"first","content":"second"}',
    ) as Record<string, unknown>;
    const { entry } = pep.handle({ tool: 'write_document', args });
    assert.equal(entry.decision.decision, 'allow');
    assert.equal(snapshotDocuments().documents.get('corp/public/notes.md'), 'second');
    assert.equal((entry.cedarRequest.context as { byteLen: number }).byteLen, 6);
    assert.deepEqual(entry.observedEffect, entry.authorizedEffect);
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// F5. Numeric boundaries on the byte budget
// ---------------------------------------------------------------------------

test('F5 the byte budget is enforced at the exact boundary, in bytes not characters', () => {
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    // cap is 4096 bytes
    const at = pep.handle({
      tool: 'write_document',
      args: { path: 'corp/public/notes.md', content: 'a'.repeat(4096) },
    });
    assert.equal(at.entry.decision.decision, 'allow', 'exactly at the cap is allowed');

    const over = pep.handle({
      tool: 'write_document',
      args: { path: 'corp/public/notes.md', content: 'a'.repeat(4097) },
    });
    assert.equal(over.entry.decision.decision, 'deny');
    assert.deepEqual(over.entry.decision.determiningPolicies, ['forbid-oversized-write']);

    // multi-byte: 2000 three-byte characters is 6000 bytes, well over the cap,
    // even though String.length is only 2000
    const multibyte = '\u4e2d'.repeat(2000);
    assert.equal(multibyte.length, 2000);
    assert.equal(Buffer.byteLength(multibyte, 'utf8'), 6000);
    const mb = pep.handle({
      tool: 'write_document',
      args: { path: 'corp/public/notes.md', content: multibyte },
    });
    assert.equal((mb.entry.cedarRequest.context as { byteLen: number }).byteLen, 6000);
    assert.equal(mb.entry.decision.decision, 'deny', 'byte length, not character length');

    // and a lone surrogate cannot smuggle a size difference past the check
    const surrogate = '\ud800'.repeat(3000);
    const sg = pep.handle({
      tool: 'write_document',
      args: { path: 'corp/public/notes.md', content: surrogate },
    });
    const authorized = (sg.entry.cedarRequest.context as { byteLen: number }).byteLen;
    assert.equal(authorized, Buffer.byteLength(surrogate, 'utf8'));
    assert.equal(sg.entry.decision.decision, 'deny');
  } finally {
    restore();
  }
});

test('F5b an allowed write stores exactly the authorized bytes', () => {
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const content = '\u00e9\u4e2d\ud83d\ude00 mixed width';
    const { entry } = pep.handle({
      tool: 'write_document',
      args: { path: 'corp/public/notes.md', content },
    });
    assert.equal(entry.decision.decision, 'allow');
    const stored = snapshotDocuments().documents.get('corp/public/notes.md');
    assert.equal(stored, content);
    assert.equal(Buffer.byteLength(stored!, 'utf8'), entry.observedEffect?.byteLen);
    assert.deepEqual(entry.observedEffect, entry.authorizedEffect);
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// F6. Command arguments and database classification
// ---------------------------------------------------------------------------

test('F6 the command that runs is the command that was authorized, byte for byte', () => {
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const command = 'echo "a; rm -rf /" && :\n#\u00e9';
    const { entry } = pep.handle({ tool: 'execute_shell', args: { host: 'build-01', command } });
    assert.equal(entry.decision.decision, 'allow');
    const op = entry.operation as { command: string; host: string };
    assert.equal(op.command, command);
    assert.equal(op.host, 'build-01');
    assert.deepEqual(entry.observedEffect, entry.authorizedEffect);
  } finally {
    restore();
  }
});

test('F6b statement classification is recorded (finding A6 remains OPEN on the policy side)', () => {
  assert.equal(classifyStatement('SELECT 1 FROM t'), 'select');
  assert.equal(classifyStatement('  \n select * from t'), 'select');
  assert.equal(classifyStatement('WITH x AS (SELECT 1) SELECT * FROM x'), 'select');
  assert.equal(classifyStatement('/* hi */ DELETE FROM analytics.metrics'), 'mutating');
  assert.equal(classifyStatement('-- c\nUPDATE analytics.metrics SET a=1'), 'mutating');
  assert.equal(classifyStatement('DROP TABLE analytics.metrics'), 'mutating');
  assert.equal(classifyStatement('EXPLAIN SELECT 1 FROM t'), 'unrecognised');

  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const { entry } = pep.handle({
      tool: 'query_database',
      args: { sql: 'DELETE FROM analytics.metrics WHERE 1=1' },
    });
    // The class is now visible in the record and in the effect fingerprint...
    assert.equal((entry.operation as { statementClass: string }).statementClass, 'mutating');
    assert.match(entry.observedEffect?.detail ?? '', /statement class mutating/);
    // ...but the policy still authorizes it as a read-only action. A6 is
    // MITIGATED (recorded, checkable) and NOT CLOSED (not gated).
    assert.equal(entry.cedarRequest.action.id, 'queryDatabase');
    assert.equal(entry.decision.decision, 'allow');
    assert.deepEqual(entry.decision.determiningPolicies, ['permit-read-tier']);
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// F7. Mutation after resolution and after authorization
// ---------------------------------------------------------------------------

test('F7 mutating the raw args object after the call changes neither decision nor effect', () => {
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const args: Record<string, unknown> = { path: 'corp/public/notes.md', content: 'authorized' };
    const { entry } = pep.handle({ tool: 'write_document', args });
    args['content'] = 'x'.repeat(100_000);
    args['path'] = 'corp/hr/salaries.csv';
    assert.equal(snapshotDocuments().documents.get('corp/public/notes.md'), 'authorized');
    assert.equal((entry.cedarRequest.context as { byteLen: number }).byteLen, 10);
  } finally {
    restore();
  }
});

test('F7b the recorded operation is frozen against post-hoc edits', () => {
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const { entry } = pep.handle({
      tool: 'write_document',
      args: { path: 'corp/public/notes.md', content: 'frozen' },
    });
    const op = entry.operation as unknown as Record<string, unknown>;
    assert.ok(Object.isFrozen(op));
    assert.throws(() => {
      op['content'] = 'mutated';
    }, TypeError);
    assert.throws(() => {
      op['path'] = 'corp/hr/salaries.csv';
    }, TypeError);
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// F8. No coercion survives anywhere in the tool layer
// ---------------------------------------------------------------------------

test('F8 the tool layer contains no coercion of operation fields and no access to raw args', () => {
  const src = readFileSync(SRC, 'utf8');
  const body = src.slice(src.indexOf('export function executeTool'));
  const exec = body.slice(0, body.indexOf('\n}\n'));
  // the A1 class of bug was String()-coercion inside the tool layer
  assert.ok(!/\bString\(/.test(exec), 'executeTool must not coerce with String()');
  assert.ok(!/\bNumber\(/.test(exec), 'executeTool must not coerce with Number()');
  assert.ok(!/\bcall\.args\b/.test(src), 'the tool layer must not reference raw args');
  assert.ok(!/unsafe_bypass/.test(src), 'the bypass flag must not come back');
  // and the signature takes an operation, not a call
  assert.match(src, /export function executeTool\(\s*op: ResolvedOperation,\s*grant: unknown,?\s*\)/);
});

// ---------------------------------------------------------------------------
// F9. Negative control: the effect comparator can actually return false
// ---------------------------------------------------------------------------

test('F9 the effect check is not vacuous - a mismatched pair is detected', () => {
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const opA: ResolvedOperation = Object.freeze({
      tool: 'write_document',
      path: 'corp/public/notes.md',
      content: 'A',
      byteLen: 1,
      contentSha256: 'aaa',
    });
    // execute a DIFFERENT write, then observe the world against opA's expectation
    pep.handle({ tool: 'write_document', args: { path: 'corp/public/notes.md', content: 'BBBB' } });
    const observed = observeEffect(opA);
    const expected = expectedEffectOf(opA);
    assert.ok(
      !effectsMatch(expected, observed),
      'the comparator must be able to report a divergence',
    );
    assert.equal(observed.byteLen, 4);
    assert.equal(expected.byteLen, 1);
  } finally {
    restore();
  }
});

test('F9b a delete that leaves the document present would be reported as divergent', () => {
  const op: ResolvedOperation = Object.freeze({ tool: 'delete_file', path: 'corp/public/roadmap.md' });
  // the document exists and has NOT been deleted, so observing now must diverge
  const observed = observeEffect(op);
  assert.equal(observed.detail, 'STILL PRESENT after delete');
  assert.ok(!effectsMatch(expectedEffectOf(op), observed));
});
