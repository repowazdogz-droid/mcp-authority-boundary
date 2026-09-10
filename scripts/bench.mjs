// Per-stage overhead versus payload size, measured once on one machine.
//
// Stages, each timed on its own around the real function:
//   resolve    resolveCall: validate, canonicalise, freeze, sha256 the content and the operation
//   decide     Pdp.decide: the Cedar evaluation alone (request already derived)
//   digest     sha256Canonical over the frozen operation (the value the grant is bound to)
//   authorize  Pdp.authorize: re-resolve + digest compare + decide + mint. The mint
//              alone is not separately observable without exposing the minter,
//              so it is reported inside this stage and not as its own row.
//   consume    consumeGrant: issued? mediation bound and linked? digest match? unspent?
//
// Payloads 1 KB / 100 KB / 1 MB of 'x', write_document to corp/public/notes.md as
// sess-alice-root (maxWriteBytes 1048576, so 1 MB is allowed). 200 timed iterations
// per stage per size after 10 warm-up iterations. Median and p95 of wall-clock ms.
// This is ONE machine and ONE process; it supports no claim about scalability.
import { cpus, totalmem } from 'node:os';
import { performance } from 'node:perf_hooks';
import { resolveCall } from '../dist/src/resolve.js';
import { Pdp } from '../dist/src/pdp.js';
import { loadEntities, loadPolicy } from '../dist/src/policy.js';
import { permitAllMediator, consumeGrant } from '../dist/src/mediation.js';
import { sha256Canonical } from '../dist/src/canonical.js';
import { restoreDocuments, snapshotDocuments } from '../dist/src/tools.js';

const SIZES = [['1 KB', 1024], ['100 KB', 100 * 1024], ['1 MB', 1024 * 1024]];
const ITER = 200, WARM = 10;
const pdp = new Pdp(loadPolicy('v1'));
const entities = loadEntities();
const principal = { type: 'Mcp::Session', id: 'sess-alice-root' };
const mediator = permitAllMediator();
const snapshot = snapshotDocuments();

function stats(samples) {
  const s = [...samples].sort((a, b) => a - b);
  const q = (p) => s[Math.min(s.length - 1, Math.floor(p * s.length))];
  return { median: q(0.5), p95: q(0.95) };
}
const fmt = (x) => x.toFixed(3).padStart(9);

const rows = [];
for (const [label, bytes] of SIZES) {
  const content = 'x'.repeat(bytes);
  const t = { resolve: [], decide: [], digest: [], authorize: [], consume: [] };
  for (let i = 0; i < WARM + ITER; i++) {
    const timed = i >= WARM;
    const push = (k, v) => { if (timed) t[k].push(v); };
    const requestId = `bench-${label}-${i}`;

    let a = performance.now();
    const r = resolveCall({ tool: 'write_document', args: { path: 'corp/public/notes.md', content } },
      { requestId, now: 2000, sourceTrust: 'user', entities });
    push('resolve', performance.now() - a);
    if (!r.ok) throw new Error(r.reason);
    const call = r.call;

    a = performance.now();
    const d = pdp.decide({ requestId, principal, action: call.action, resource: call.resource, context: call.context, entities });
    push('decide', performance.now() - a);
    if (d.decision !== 'allow') throw new Error(d.explanation);

    a = performance.now();
    const digest = sha256Canonical(call.operation);
    push('digest', performance.now() - a);
    if (digest !== call.operationSha256) throw new Error('digest mismatch');

    const mediation = mediator.mediateOperation(principal, call.operation, call.operationSha256, 2000);
    a = performance.now();
    const outcome = pdp.authorize({ ...call, principal, entities, mediation });
    push('authorize', performance.now() - a);
    if (!outcome.grant) throw new Error(outcome.decision.explanation);

    a = performance.now();
    consumeGrant(outcome.grant, call.operation, mediation);
    push('consume', performance.now() - a);
  }
  for (const [stage, samples] of Object.entries(t)) rows.push({ label, bytes, stage, ...stats(samples) });
}
restoreDocuments(snapshot);

console.log(`bench: node ${process.version}, ${cpus()[0]?.model ?? 'unknown cpu'}, ${cpus().length} cores, ${(totalmem() / 2 ** 30).toFixed(0)} GB; ${ITER} iterations per cell after ${WARM} warm-up; wall-clock ms; one machine, one process, no scalability claim`);
console.log('stage      |  1 KB median   p95 | 100 KB median   p95 |   1 MB median   p95');
for (const stage of ['resolve', 'decide', 'digest', 'authorize', 'consume']) {
  const cells = SIZES.map(([label]) => rows.find((r) => r.label === label && r.stage === stage));
  console.log(`${stage.padEnd(10)} | ${cells.map((c) => `${fmt(c.median)} ${fmt(c.p95)}`).join(' | ')}`);
}
console.log(JSON.stringify({ node: process.version, iterations: ITER, rows: rows.map((r) => ({ ...r, median: +r.median.toFixed(4), p95: +r.p95.toFixed(4) })) }));
