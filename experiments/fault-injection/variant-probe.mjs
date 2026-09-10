// Per-defect runtime probe. Imports ONLY the variant worktree's own build and
// drives it the way the repo's own tests do (same EnforcementPoint / Pdp paths).
//
// Usage: node variant-probe.mjs <MUT_DIR> <OUT_DIR> <D1|D2|D3|D4|D5|D6|D9>
//
// Writes <OUT_DIR>/ledger-<D>.jsonl (whatever the SUT recorded; possibly empty
// when it threw before recording), mirrors only CHANGED documents to
// <OUT_DIR>/effect-<D>/, and writes <OUT_DIR>/probe-<D>.json.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';

const [mutDir, outDir, defect] = process.argv.slice(2);
const mod = (p) => import(pathToFileURL(join(mutDir, p)).href);
const { EnforcementPoint } = await mod('dist/src/enforce.js');
const { Ledger } = await mod('dist/src/ledger.js');
const policyMod = await mod('dist/src/policy.js');
const toolsMod = await mod('dist/src/tools.js');

const TARGET = 'corp/public/notes.md';
const SESSION = { type: 'Mcp::Session', id: 'sess-writer-delegated' };
const ARRAY_PAYLOAD = ['x'.repeat(100_000)];

const bytesOf = (m) => { const o = {}; for (const [k, v] of m) o[k] = v; return o; };

// mediator must come from the variant's own mediation module
const medMod = await mod('dist/src/mediation.js');
function makePepWithMed(ledger) {
  return new EnforcementPoint({
    policy: policyMod.loadPolicy('v1', []),
    entities: () => policyMod.loadEntities(),
    ledger,
    session: SESSION,
    now: () => 2000,
    wallClock: '2026-08-07T00:00:00.000Z',
    mediator: medMod.permitAllMediator(),
  });
}

function handleAttempt(pep, args) {
  try {
    const { entry } = pep.handle({ tool: 'write_document', args });
    return { decision: entry.decision.decision, denialKind: entry.decision.denialKind ?? null, threw: false };
  } catch (e) {
    return { decision: 'THREW', denialKind: null, threw: true, error: String(e).slice(0, 200) };
  }
}

function mirrorChanged(before, effectDir) {
  const after = toolsMod.snapshotDocuments();
  const aMap = after instanceof Map ? after : after.documents;
  const changed = [];
  for (const [k, v] of aMap) {
    if (before[k] !== v) {
      const dest = join(effectDir, k);
      mkdirSync(dirname(dest), { recursive: true });
      writeFileSync(dest, v);
      changed.push({ path: k, bytes: Buffer.byteLength(v, 'utf8') });
    }
  }
  return changed;
}

const snap0 = bytesOf(
  (() => { const s = toolsMod.snapshotDocuments(); return (s instanceof Map ? s : s.documents); })(),
);

const ledgerPath = join(outDir, `ledger-${defect}.jsonl`);
const effectDir = join(outDir, `effect-${defect}`);
mkdirSync(effectDir, { recursive: true });
writeFileSync(ledgerPath, '');
const ledger = new Ledger(ledgerPath);
const out = { defect, mutDir, target: TARGET };

// --- defect-specific stimuli ---------------------------------------------
if (defect === 'D1') {
  // Masking check: unexpected-type array must still be refused at resolution; a benign
  // string must flow through untouched.
  const pep = makePepWithMed(ledger);
  const nonstr = handleAttempt(pep, { path: TARGET, content: ARRAY_PAYLOAD });
  const benign = handleAttempt(pep, { path: TARGET, content: 'd1-benign-ok' });
  out.attempts = { nonstr, benign };
} else if (defect === 'D2' || defect === 'D5') {
  // Direct-executor probes: no EnforcementPoint, hence no ledger entries by
  // construction. The grant comes from the variant's own PDP.
  const { Pdp } = await mod('dist/src/pdp.js');
  const { resolveCall } = await mod('dist/src/resolve.js');
  const entities = policyMod.loadEntities();
  const pdp = new Pdp(policyMod.loadPolicy('v1', []));
  const med = medMod.permitAllMediator();
  const resolveOp = (content) => {
    const r = resolveCall(
      { tool: 'write_document', args: { path: TARGET, content } },
      { requestId: 'probe', now: 2000, sourceTrust: 'user', entities },
    );
    if (!r.ok) throw new Error('probe setup: resolution failed');
    return r.call;
  };
  if (defect === 'D2') {
    const a = resolveOp('INPUT-A-BYTES');
    const b = resolveOp('ALT-INPUT-BYTES');
    const mA = med.mediateOperation(SESSION, a.operation, a.operationSha256, 2000);
    const mB = med.mediateOperation(SESSION, b.operation, b.operationSha256, 2000);
    const outA = pdp.authorize({
      requestId: 'probe', principal: SESSION, action: a.action, resource: a.resource,
      context: a.context, entities, operation: a.operation, operationSha256: a.operationSha256, mediation: mA,
    });
    // Strongest attempt at reaching the grant-digest check: the grant's own
    // mediation record (passes the mediation-hash check) with a different
    // operation. Pristine dies at the linkage check one step earlier, which is
    // exactly the masking this defect tests.
    let threw = false, err = null;
    try {
      toolsMod.executeTool(b.operation, outA.grant, mA);
    } catch (e) { threw = true; err = String(e).slice(0, 160); }
    out.grantMismatch = { cedarDecisionForA: outA.decision.decision, threwOnB: threw, error: err };
  } else {
    const a = resolveOp('REUSE-BYTES');
    const mA = med.mediateOperation(SESSION, a.operation, a.operationSha256, 2000);
    const outA = pdp.authorize({
      requestId: 'probe', principal: SESSION, action: a.action, resource: a.resource,
      context: a.context, entities, operation: a.operation, operationSha256: a.operationSha256, mediation: mA,
    });
    toolsMod.executeTool(a.operation, outA.grant, mA);
    let secondThrew = false, err = null;
    try {
      toolsMod.executeTool(a.operation, outA.grant, mA);
    } catch (e) { secondThrew = true; err = String(e).slice(0, 160); }
    out.doubleSpend = { cedarDecision: outA.decision.decision, secondThrew, error: err };
  }
} else if (defect === 'D3' || defect === 'D6') {
  // Fail-loud check: the SUT must throw rather than record a divergent execution.
  const pep = makePepWithMed(ledger);
  out.attempt = handleAttempt(pep, { path: TARGET, content: 'probe-benign-bytes' });
} else if (defect === 'D4' || defect === 'D9') {
  const pep = makePepWithMed(ledger);
  out.attempt = handleAttempt(pep, { path: TARGET, content: ARRAY_PAYLOAD });
} else {
  throw new Error(`unknown defect ${defect}`);
}

out.exportedChanged = mirrorChanged(snap0, effectDir);
const probePath = join(outDir, `probe-${defect}.json`);
writeFileSync(probePath, JSON.stringify(out, null, 2));
console.log(JSON.stringify(out));
