import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readLedger } from '../src/ledger.js';
import { TOOL_NAMES } from '../src/resolve.js';
import type { ToolName } from '../src/types.js';

/**
 * The guard for the error class that produced the v1.0.0 claim-D overstatement.
 *
 * That error was not a wrong number. Every count was right. The error was
 * reporting a stage's headline count WITHOUT its composition, so a green
 * `effect-consistency PASS checked 7` read as evidence of independent effect
 * observation when all seven checks were the record-consistency kind and the
 * two tools that read fixture state back were never executed.
 *
 * So this derives the composition from the ledger itself - never from a
 * declared number - and refuses to let the shipped claim outrun it.
 */

/**
 * Which tools compare against state obtained independently of the record.
 *
 * AUTHORED, and therefore trusted base rather than evidence: it is a reading of
 * `observeEffect` in src/tools.ts, not something measured. `classificationIsTotal`
 * below is what stops it from silently going stale - a tool added to the server
 * without a decision recorded here fails the build instead of being absorbed
 * into whichever bucket happens to be checked first.
 */
const INDEPENDENT_READBACK = new Set<ToolName>(['write_document', 'delete_file']);
const RECORD_CONSISTENCY = new Set<ToolName>([
  'read_document',
  'send_email',
  'execute_shell',
  'query_database',
]);

interface Composition {
  independentReadback: number;
  recordConsistency: number;
  byTool: Record<string, number>;
  unexecuted: ToolName[];
}

/** Derived from executed ledger entries only. A denial executes nothing. */
function compositionOf(path: string): Composition {
  const byTool: Record<string, number> = {};
  for (const t of TOOL_NAMES) byTool[t] = 0;

  for (const e of readLedger(path)) {
    if (e.operation === null) continue;
    // An entry counts as executed exactly when stage 4 would check it.
    if (e.toolResult === null || e.observedEffect === null) continue;
    byTool[e.operation.tool] = (byTool[e.operation.tool] ?? 0) + 1;
  }

  let independentReadback = 0;
  let recordConsistency = 0;
  for (const t of TOOL_NAMES) {
    if (INDEPENDENT_READBACK.has(t)) independentReadback += byTool[t]!;
    if (RECORD_CONSISTENCY.has(t)) recordConsistency += byTool[t]!;
  }

  return {
    independentReadback,
    recordConsistency,
    byTool,
    unexecuted: TOOL_NAMES.filter((t) => byTool[t] === 0),
  };
}

/**
 * Extract one claim surface by its opening marker: the line it starts on, plus
 * any continuation lines, up to the first blank line. Shape-based rather than
 * prose-based, so quoting a retracted claim elsewhere in the file cannot trip
 * the guard.
 */
function rowOf(doc: string, marker: string): string {
  const lines = doc.split('\n');
  const start = lines.findIndex((l) => l.startsWith(marker));
  if (start === -1) return '';
  const out: string[] = [lines[start]!];
  for (let i = start + 1; i < lines.length; i += 1) {
    const l = lines[i]!;
    if (l.trim() === '' || l.startsWith('|') || l.startsWith('#')) break;
    if (marker.startsWith('>') && !l.startsWith('>')) break;
    out.push(l);
  }
  return out.join('\n');
}

test('the read-back classification is total over the tool set', () => {
  // The coverage-honesty guard. Without it, a seventh tool would be counted in
  // neither bucket and the composition would under-report rather than fail.
  const classified = new Set([...INDEPENDENT_READBACK, ...RECORD_CONSISTENCY]);
  assert.deepEqual(
    [...classified].sort(),
    [...TOOL_NAMES].sort(),
    'every tool must be classified as independent-read-back or record-consistency',
  );
  for (const t of INDEPENDENT_READBACK) {
    assert.ok(!RECORD_CONSISTENCY.has(t), `${t} cannot be in both buckets`);
  }
});

test('stage-4 composition is derived from the ledger, and reported honestly', () => {
  const c = compositionOf('evidence/ledger.jsonl');

  // Anchor: the derived total must equal what replay says it checked, so this
  // test cannot drift away from the artifact it is guarding.
  const report = JSON.parse(readFileSync('evidence/replay-report.json', 'utf8')) as {
    stages: Array<{ stage: string; checked: number; establishes: string }>;
  };
  const stage4 = report.stages.find((s) => s.stage === 'effect-consistency');
  assert.ok(stage4, 'the replay report must contain an effect-consistency stage');
  assert.equal(
    c.independentReadback + c.recordConsistency,
    stage4.checked,
    'derived composition must account for exactly the entries stage 4 checked',
  );

  // THE GUARD. When nothing with an independent read-back actually ran, no
  // shipped surface may assert that independent effect observation was
  // established. The counts stay green; the claim is what is constrained.
  //
  // It reads STRUCTURED claim surfaces, not free prose. A first version scanned
  // whole documents for the v1.0.0 wording and fired on the README's own
  // correction note, which QUOTES that wording in order to retract it. A regex
  // over prose sees text, not assertions. The three surfaces below are the
  // places a live claim actually lives, and each is extracted by shape.
  if (c.independentReadback === 0) {
    const claims: Array<[string, string]> = [
      // machine-generated, quotes nothing
      ['replay-report stage-4 establishes', stage4.establishes],
      // the claim-table row for D
      ['README claim table, row D', rowOf(readFileSync('README.md', 'utf8'), '| **D** |')],
      // the blockquoted D clause in the threat model
      [
        'THREAT_MODEL D clause',
        rowOf(readFileSync('docs/THREAT_MODEL.md', 'utf8'), '> **D (effect).**'),
      ],
    ];
    for (const [name, text] of claims) {
      assert.ok(text.length > 0, `${name} not found - the guard cannot read its claim surface`);
      assert.doesNotMatch(
        text,
        /observed in the world/i,
        `${name} asserts world observation while the ledger contains 0 executions of a tool ` +
          `with an independent read-back (${JSON.stringify(c.byTool)})`,
      );
      assert.match(
        text,
        /\bnot established\b|consistency of the record with itself|every check here is consistency/i,
        `${name} must disclose that stage 4 established no independent observation, because ` +
          `the ledger contains 0 executions of a read-back tool (${JSON.stringify(c.byTool)}). ` +
          `Narrow the claim or exercise the tool - do not add a scenario solely to make this pass.`,
      );
    }
  }
});

test('the current ledger composition is the one the docs describe', () => {
  // Not a guard, a pin: if a future change makes a read-back tool execute, this
  // fails and the docs that say "the ledger executes neither" must be revisited.
  const c = compositionOf('evidence/ledger.jsonl');
  assert.equal(c.independentReadback, 0, 'no write_document or delete_file execution is expected');
  assert.equal(c.recordConsistency, 8);
  assert.deepEqual(c.byTool, {
    read_document: 5,
    write_document: 0,
    send_email: 1,
    execute_shell: 2,
    query_database: 0,
    delete_file: 0,
  });
});
