import assert from 'node:assert/strict';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, readdirSync,
  symlinkSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { parseSelect } from '../../dist/src/sql.js';
import { replay } from '../../dist/src/replay.js';
import { Ledger, sealPath, intentPath } from '../../dist/src/ledger.js';
import { EnforcementPoint } from '../../dist/src/enforce.js';
import { loadEntities, loadPolicy } from '../../dist/src/policy.js';
import { permitAllMediator } from '../../dist/src/mediation.js';
import { FileBackend } from './file-backend.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../..');
mkdirSync(join(here, 'runs'), { recursive: true });
const output = mkdtempSync(join(here, 'runs/run-'));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const save = (path, data) => writeFileSync(path, JSON.stringify(data, null, 2) + '\n');
function run(command, args, input) {
  const result = spawnSync(command, args, { cwd: repo, input, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  assert.equal(result.status, 0, `${command} failed: ${result.error ?? result.stderr ?? result.stdout}`);
  return result.stdout;
}
function node(file, args) { return JSON.parse(run(process.execPath, [join(here, file), ...args])); }

// SQL cases are enumerated before evaluation, not selected by pass/fail outcome.
const queries = [];
for (const [table, columns] of [['analytics.metrics', ['day', 'visits']], ['crm.customers', ['id', 'email']]]) {
  for (const projection of ['*', ...columns, columns.join(', '), [...columns].reverse().join(', '), `${columns[0]},${columns[0]}`]) {
    for (const space of [' ', '  ', '\t', '\n', '\r\n']) {
      for (const upper of [false, true]) {
        for (const suffix of ['', ';']) {
          const sql = `SELECT${space}${projection}${space}FROM${space}${table}${suffix}`;
          queries.push(upper ? sql.toUpperCase() : sql.toLowerCase());
        }
      }
    }
  }
}
const parsed = queries.map(q => parseSelect(q));
assert.ok(parsed.every(Boolean));
const oracle = JSON.parse(run('python3', [join(here, 'sql-oracle.py')], JSON.stringify([
  ...queries, ...parsed.map(q => q.sql), 'SELECT * FROM analytics.metrics, crm.customers',
])));
const sqlLedger = new Ledger(join(output, 'sql-ledger.jsonl'));
const sqlPep = new EnforcementPoint({ policy: loadPolicy('v1'), entities: () => loadEntities(),
  ledger: sqlLedger, session: { type: 'Mcp::Session', id: 'sess-alice-root' }, now: () => 2000,
  wallClock: '2026-09-08T00:00:00.000Z', mediator: permitAllMediator() });
for (let i = 0; i < queries.length; i++) {
  const raw = oracle.results[i], canonical = oracle.results[i + queries.length];
  assert.equal(raw.error, null, queries[i]);
  assert.deepEqual(raw.reads, [parsed[i].table], queries[i]);
  assert.deepEqual(raw.writes, []);
  assert.deepEqual(canonical, raw, `raw/canonical SQL differential: ${queries[i]}`);
  const executed = sqlPep.handle({ tool: 'query_database', args: { sql: queries[i] } });
  assert.equal(executed.entry.decision.decision, 'allow');
  assert.equal(executed.result?.content, raw.columns.join(',') + '\n' + raw.rows.map(r => r.join(',')).join('\n') + '\n');
}
sqlLedger.seal();
assert.equal(replay(join(output, 'sql-ledger.jsonl')).verdict, 'ALL STAGES PASS');
const comma = 'SELECT * FROM analytics.metrics, crm.customers';
const oldExtracted = [...comma.matchAll(/\bfrom\s+([a-zA-Z_][\w.]*)/gi)].map(m => m[1]);
assert.deepEqual(oldExtracted, ['analytics.metrics']);
assert.deepEqual(oracle.results.at(-1).reads, ['analytics.metrics', 'crm.customers']);
assert.equal(parseSelect(comma), null);
const sqlReport = { acceptedCases: queries.length, threatModel: 'caller-only', sqlite: oracle.sqlite, mismatches: 0,
  scope: 'enumerated SELECT subset; SQLite table-access and result oracle, not all dialects',
  negativeControl: { query: comma, oldResolver: oldExtracted, sqliteReads: oracle.results.at(-1).reads,
    repaired: 'REFUSE' } };
save(join(output, 'sql.json'), { ...sqlReport, queries, oracle });

const write = (path, content) => ({ tool: 'write_document', args: { path, content } });
const notes = 'corp/public/notes.md', roadmap = 'corp/public/roadmap.md';
const specs = [
  { name: 'multiple-writes', calls: [write(notes, 'first'), write(roadmap, 'other'), write(notes, 'last')], replay: 'ALL STAGES PASS', world: 'AGREE' },
  ...[0, 4095, 4096].map(n => ({ name: `bytes-${n}`, calls: [write(notes, 'x'.repeat(n))], replay: 'ALL STAGES PASS', world: 'AGREE' })),
  { name: 'bytes-4097-refused', calls: [write(notes, 'x'.repeat(4097))], replay: 'INCOMPLETE', world: 'AGREE' },
  { name: 'array-100000-refused', calls: [write(notes, ['x'.repeat(100000)])], replay: 'INCOMPLETE', world: 'AGREE' },
  { name: 'utf8-boundary', calls: [write(notes, 'é'.repeat(2048))], replay: 'ALL STAGES PASS', world: 'AGREE' },
  { name: 'utf8-oversize-refused', calls: [write(notes, 'é'.repeat(2049))], replay: 'INCOMPLETE', world: 'AGREE' },
  { name: 'write-delete', session: 'sess-alice-root', calls: [write(notes, 'written'), { tool: 'delete_file', args: { path: notes } }], replay: 'ALL STAGES PASS', world: 'AGREE' },
  ...['shadow', 'no-write', 'extra-write', 'completion-failure', 'prepare-failure'].map(mutation => ({
    name: mutation, mutation, calls: [write(notes, 'new data')],
    replay: mutation === 'extra-write' ? 'ALL STAGES PASS' : mutation === 'prepare-failure' ? 'INCOMPLETE' : 'FAILED',
    world: ['shadow', 'extra-write', 'completion-failure'].includes(mutation) ? 'DIVERGENCE' : 'AGREE',
  })),
  // Negative controls for the observation limit. The extra-write mutant above is
  // the positive control (an unauthorized file that PERSISTS is caught). Here
  // the same unauthorized file is written and removed before the run ends:
  // every replay stage passes and the final-state observer reports AGREE. That
  // is a declared, measured miss, not an assertion of the limit in prose.
  { name: 'transient-extra-write', mutation: 'transient-extra-write', calls: [write(notes, 'new data')],
    replay: 'ALL STAGES PASS', world: 'AGREE',
    knownMiss: 'unauthorized transient file: written during the run, deleted before it ends; invisible to final-state observation' },
  // Reverting the AUTHORIZED write is not a miss for this observer: it compares
  // the final world against baseline plus completed records, so a recorded
  // write whose bytes are gone is a mismatch.
  { name: 'transient-revert', mutation: 'transient-revert', calls: [write(notes, 'new data')],
    replay: 'ALL STAGES PASS', world: 'DIVERGENCE' },
  { name: 'D8-tail-loss', calls: [write(notes, 'first'), write(roadmap, 'second')], tamper: 'tail', replay: 'FAILED', world: 'DIVERGENCE' },
  { name: 'D8-resealed-prefix', calls: [write(notes, 'first'), write(roadmap, 'second')], tamper: 'reseal', replay: 'FAILED', world: 'DIVERGENCE' },
  { name: 'D7-rehashed-mediation', calls: [write(notes, 'first')], tamper: 'mediation', replay: 'FAILED', world: 'AGREE' },
];
// THREAT MODEL LABEL. "caller-only" is the talk's adversary: fully in control of
// the model, the client and the arguments, but unable to modify the executor,
// the runtime, the ledger file or the host (docs/THREAT_MODEL.md). Every case
// that mutates the executor (shadow, no-write, extra-write, transient-*), injects
// a runtime fault (prepare/completion failure) or tampers with the ledger/seal
// files after the fact (D7, D8) is "executor-compromise": no prevention is
// claimed there, only what the replay verifier and the observer detect.
const threatModelOf = spec => spec.mutation || spec.tamper ? 'executor-compromise' : 'caller-only';
for (const spec of specs) {
  spec.threatModel = threatModelOf(spec);
  spec.threatDetail = spec.tamper ? `post-hoc ${spec.tamper} tampering of ledger/seal files`
    : ['completion-failure', 'prepare-failure'].includes(spec.mutation) ? 'runtime I/O fault injection'
    : spec.mutation ? 'executor mutation' : 'adversarial caller only';
}
const fileResults = [];
for (const spec of specs) {
  const directory = join(output, spec.name), root = join(directory, 'world');
  mkdirSync(join(root, 'corp/public'), { recursive: true });
  writeFileSync(join(root, notes), 'initial notes\n');
  writeFileSync(join(root, roadmap), 'initial roadmap\n');
  const before = join(directory, 'before.json'), ledger = join(directory, 'ledger.jsonl');
  save(before, node('observer.mjs', [root]));
  const caseFile = join(directory, 'case.json');
  save(caseFile, spec);
  const outcomes = node('file-worker.mjs', [root, ledger, caseFile]);
  save(join(directory, 'worker.json'), outcomes);
  if (spec.mutation?.startsWith('transient')) {
    assert.ok(outcomes.some(o => o.presentBeforeCleanup === true), `${spec.name}: transient effect never existed`);
  }
  const anchor = join(directory, 'verifier-held-anchor.json');
  const hasSeal = !outcomes.some(x => x.sealError);
  if (hasSeal) copyFileSync(sealPath(ledger), anchor);
  if (spec.tamper) {
    let entries = readFileSync(ledger, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
    if (spec.tamper === 'tail' || spec.tamper === 'reseal') entries.pop();
    if (spec.tamper === 'mediation') {
      entries[0].mediation.reason = 'altered after authorization';
      // Independent stable serializer, intentionally rehashing only the ledger.
      const canonical = x => x && typeof x === 'object' ? Array.isArray(x) ? '[' + x.map(canonical).join(',') + ']'
        : '{' + Object.keys(x).sort().map(k => JSON.stringify(k) + ':' + canonical(x[k])).join(',') + '}' : JSON.stringify(x);
      const { hash: _, ...body } = entries[0];
      entries[0].hash = hash(canonical(body));
    }
    writeFileSync(ledger, entries.map(x => JSON.stringify(x)).join('\n') + '\n');
    if (spec.tamper === 'reseal') {
      save(sealPath(ledger), { entries: entries.length, finalHash: entries.at(-1).hash });
      const intents = readFileSync(intentPath(ledger), 'utf8').split('\n').filter(Boolean).map(JSON.parse);
      writeFileSync(intentPath(ledger), JSON.stringify(intents[0]) + '\n');
    }
  }
  const verification = replay(ledger, hasSeal ? anchor : undefined);
  const observation = node('observer.mjs', [root, before, ledger]);
  save(join(directory, 'replay.json'), verification);
  save(join(directory, 'observer.json'), observation);
  assert.equal(verification.verdict, spec.replay, spec.name);
  assert.equal(observation.verdict, spec.world, spec.name);
  fileResults.push({ name: spec.name, threatModel: spec.threatModel, threatDetail: spec.threatDetail,
    replay: verification.verdict, observer: observation.verdict,
    ...(spec.knownMiss ? { knownMiss: spec.knownMiss } : {}),
    outcomes, findings: verification.findings.map(f => f.detail) });
}

// Filesystem negative control: a symlink cannot redirect the adapter outside
// the owned world. Both files here are disposable fixtures owned by the runner.
const linkRoot = join(output, 'symlink-control');
mkdirSync(linkRoot);
const outside = join(output, 'outside.txt');
writeFileSync(outside, 'unchanged');
symlinkSync(outside, join(linkRoot, 'link'));
assert.throws(() => new FileBackend(linkRoot).set('link', 'changed'), /symlink/);
assert.equal(readFileSync(outside, 'utf8'), 'unchanged');

const sourceFiles = [];
for (const directory of ['src', 'test', 'scripts', 'formal', 'policies', 'policies/overlay-revocation',
  'containment/src', 'containment/test', 'experiments/hardening', 'experiments/independent-observer']) {
  for (const name of readdirSync(join(repo, directory))) {
    if (/\.(ts|mjs|py|lean|cedar|cedarschema|sh)$/.test(name)) sourceFiles.push(join(directory, name));
  }
}
sourceFiles.push('package.json', 'package-lock.json', 'entities/entities.json', 'formal/lean-toolchain',
  'formal/vectors.json', 'docs/REPAIR.md', 'docs/THREAT_MODEL.md');
const sourceHashes = Object.fromEntries(sourceFiles.sort().map(p => [p, hash(readFileSync(join(repo, p)))]));
// Counts per threat model and per (replay, observer) outcome. The SQL corpus is
// 240 caller-only cases with one outcome; the file cases are listed individually.
const threatModels = {};
for (const f of fileResults) {
  const m = threatModels[f.threatModel] ??= { fileCases: 0, sqlCases: 0, outcomes: {} };
  m.fileCases += 1;
  const key = `replay=${f.replay} observer=${f.observer}${f.knownMiss ? ' (knownMiss)' : ''}`;
  m.outcomes[key] = (m.outcomes[key] ?? 0) + 1;
}
threatModels['caller-only'].sqlCases = queries.length;
threatModels['caller-only'].outcomes['sql: decision=allow replay=ALL STAGES PASS oracle=match'] = queries.length;
for (const [model, m] of Object.entries(threatModels)) {
  console.log(`threat model ${model}: ${m.fileCases} file cases, ${m.sqlCases} SQL cases`);
  for (const [outcome, n] of Object.entries(m.outcomes)) console.log(`  ${n}  ${outcome}`);
}
const report = { generatedAt: new Date().toISOString(), output, node: process.version,
  platform: process.platform, gitHead: run('git', ['rev-parse', 'HEAD']).trim(), sourceHashes,
  sql: sqlReport, files: fileResults, threatModels, symlinkControl: 'PASS',
  scope: 'local experiment with real files, separate observer process and controller-held pre-tamper anchor; shared host and author; no cryptographic machine independence',
  limitations: ['final-state observation misses transient effects outside the record (measured: transient-extra-write); a reverted recorded write is caught (measured: transient-revert)',
    'file adapter assumes the experiment owner controls directory topology during execution',
    'write-ahead logging records authorization; it cannot make arbitrary external effects transactional',
    'SQL oracle covers the accepted subset on this SQLite build'] };
save(join(output, 'report.json'), report);
save(join(here, 'RESULTS.json'), report);
console.log(JSON.stringify({ output, sqlCases: queries.length, fileCases: specs.length, passed: true }));
