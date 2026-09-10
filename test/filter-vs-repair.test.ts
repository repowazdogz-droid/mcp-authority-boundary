import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { V1_COMMIT, v1Build } from './v1-build.js';

/**
 * Measures, against the pristine v1 build (631196d), how much of the F1 type
 * sweep a witness-excluding repair would have closed. F1 is the 100-cell sweep
 * from test/falsification.test.ts: ten non-string values across the ten
 * string-valued fields of the six tools. Each cell is driven through v1's own
 * EnforcementPoint.handle - the same path its server used - and classified:
 *
 *   throw            handle() threw; in v1 that is String() coercion failing
 *                    INSIDE the executor, after Cedar had already allowed
 *   already refused  v1 denied it (its own typeof checks or entity lookup)
 *   closed by filter allowed by v1, and the value is an array - the one shape
 *                    an "arrays-only" patch around the A1 witness would reject
 *   still accepted   allowed by v1, and not an array: the residue a
 *                    witness-excluding fix leaves untouched
 *
 * The asserted counts are the measured values from this sweep at this commit.
 * They are a fact about these 100 cells and v1's code, not a rate over any
 * population of inputs. The fixture world is restored between cells so that no
 * cell's effect changes another cell's outcome.
 */
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

type Outcome = 'throw' | 'already refused' | 'closed by filter' | 'still accepted';

test(`arrays-only filter measured against the v1 (${V1_COMMIT}) F1 sweep`, async () => {
  const v1 = v1Build();
  const mod = (p: string) => import(pathToFileURL(join(v1, p)).href);
  const { EnforcementPoint } = await mod('dist/src/enforce.js');
  const { Ledger } = await mod('dist/src/ledger.js');
  const policyMod = await mod('dist/src/policy.js');
  const toolsMod = await mod('dist/src/tools.js');

  const work = mkdtempSync(join(tmpdir(), 'mab-filter-'));
  const pristine = toolsMod.snapshotDocuments();
  const counts: Record<Outcome, number> = { 'throw': 0, 'already refused': 0, 'closed by filter': 0, 'still accepted': 0 };
  const cells: Array<{ tool: string; field: string; value: string; outcome: Outcome; detail: string }> = [];
  let i = 0;
  for (const { tool, base, field } of STRING_FIELDS) {
    for (const [label, value] of NON_STRINGS) {
      const pep = new EnforcementPoint({
        policy: policyMod.loadPolicy('v1', []),
        entities: policyMod.loadEntities(),
        ledger: new Ledger(join(work, `ledger-${i++}.jsonl`)),
        session: { type: 'Mcp::Session', id: 'sess-alice-root' },
        now: 2000,
        wallClock: '2026-08-07T00:00:00.000Z',
      });
      let outcome: Outcome;
      let detail: string;
      try {
        const { entry } = pep.handle({ tool, args: { ...base, [field]: value } });
        if (entry.decision.decision !== 'allow') {
          outcome = 'already refused';
          detail = entry.decision.denialKind;
        } else {
          outcome = Array.isArray(value) ? 'closed by filter' : 'still accepted';
          detail = `allow (${entry.decision.determiningPolicies.join(',')}); ${entry.toolResult?.summary ?? ''}`;
        }
      } catch (error) {
        outcome = 'throw';
        detail = String(error).split('\n')[0]!;
      } finally {
        toolsMod.restoreDocuments(pristine);
      }
      counts[outcome] += 1;
      cells.push({ tool, field, value: label, outcome, detail });
    }
  }

  assert.equal(cells.length, 100);
  console.log(`filter-vs-repair (v1 ${V1_COMMIT}, F1 sweep, 100 cells):`);
  for (const k of Object.keys(counts) as Outcome[]) console.log(`  ${k.padEnd(17)} ${String(counts[k]).padStart(3)}`);
  const byField = new Map<string, Record<Outcome, number>>();
  for (const c of cells) {
    const key = `${c.tool}.${c.field}`;
    const row = byField.get(key) ?? { 'throw': 0, 'already refused': 0, 'closed by filter': 0, 'still accepted': 0 };
    row[c.outcome] += 1;
    byField.set(key, row);
  }
  for (const [key, row] of byField) {
    console.log(`  ${key.padEnd(24)} throw ${row['throw']}  refused ${row['already refused']}  closed ${row['closed by filter']}  accepted ${row['still accepted']}`);
  }

  // Measured at 631196d; a change here means v1's behaviour was misreported.
  assert.deepEqual(counts, {
    'throw': 7,
    'already refused': 56,
    'closed by filter': 8,
    'still accepted': 29,
  });
  // Where the throws happen matters: for content/body/command the executor's
  // String() coercion throws AFTER Cedar allowed (an authorized crash); for the
  // path/to fields v1 throws while formatting its own refusal message.
  for (const c of cells.filter((x) => x.outcome === 'throw')) console.log(`  throw  ${c.tool}.${c.field} = ${c.value}: ${c.detail}`);

  // The narrowest witness-excluding patch - arrays refused on write_document.content
  // only - closes the two array cells of that one field and nothing else.
  const witnessFieldOnly = cells.filter((c) => c.tool === 'write_document' && c.field === 'content' && c.outcome === 'closed by filter').length;
  console.log(`  arrays-only filter on the witness field alone closes ${witnessFieldOnly} of 100; on every field ${counts['closed by filter']} of 100`);
  assert.equal(witnessFieldOnly, 2);

  // The witness itself: write_document.content=array is ALLOWED by v1 at byteLen 0.
  const witness = cells.find((c) => c.tool === 'write_document' && c.field === 'content' && c.value === 'array')!;
  assert.equal(witness.outcome, 'closed by filter');
  assert.match(witness.detail, /wrote 50000 bytes/);
});
