// SUT role (RTX): drive ONE frozen version with the shared stimulus.
//
// Usage:
//   node run-sut.mjs <v1|head> <SUT_DIR> <EFFECT_DIR> <LEDGER_OUT> <STIMULUS> <RESULT_OUT>
//
// SUT_DIR is a pristine worktree at the pinned commit, built (npm ci && npm
// run build). This script imports that version's own enforcement path - the
// same path its server uses - feeds it the shared unexpected-type call, then exports
// the post-execution document bytes VERBATIM to EFFECT_DIR. The export is a
// byte-for-byte copy of the SUT's own post-execution state, not a
// reinterpretation: whatever the SUT's executor wrote is what hits the world
// the observer sees.
//
// On refusal nothing is exported and no file is created.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';

const [version, sutDir, effectDir, ledgerOut, stimulusPath, resultOut] = process.argv.slice(2);
if (!version || !sutDir || !effectDir || !ledgerOut || !stimulusPath || !resultOut) {
  console.error('usage: node run-sut.mjs <v1|head> <SUT_DIR> <EFFECT_DIR> <LEDGER_OUT> <STIMULUS> <RESULT_OUT>');
  process.exit(2);
}

const mod = (p) => import(pathToFileURL(join(sutDir, p)).href);
const { EnforcementPoint } = await mod('dist/src/enforce.js');
const { Ledger } = await mod('dist/src/ledger.js');
const policyMod = await mod('dist/src/policy.js');
const toolsMod = await mod('dist/src/tools.js');

const stimulus = JSON.parse(readFileSync(stimulusPath, 'utf8'));
const ledger = new Ledger(ledgerOut);
const session = { type: 'Mcp::Session', id: 'sess-writer-delegated' };

const cfg = {
  policy: policyMod.loadPolicy('v1', []),
  ledger,
  session,
  wallClock: '2026-08-07T00:00:00.000Z',
};
if (version === 'head') {
  cfg.entities = () => policyMod.loadEntities();
  cfg.now = () => 2000;
  const med = await mod('dist/src/mediation.js');
  cfg.mediator = med.permitAllMediator();
} else {
  cfg.entities = policyMod.loadEntities();
  cfg.now = 2000;
}

const pep = new EnforcementPoint(cfg);
const { entry } = pep.handle(stimulus.rawCall);
const allowed = entry.decision.decision === 'allow';

// Export the SUT's post-execution state for TARGET verbatim to the real
// filesystem. This is the "real effect": a file an independent machine can
// stat and hash without trusting this process.
const TARGET = stimulus.targetPath;
let exported = null;
// On refusal there is no execution, so there must be no export either. Reading
// the fixture map unconditionally would copy pre-existing fixture content and
// manufacture an effect the SUT never produced.
if (allowed) {
  const snap = toolsMod.snapshotDocuments();
  const docMap = snap instanceof Map ? snap : snap.documents;
  const stored = docMap.get(TARGET);
  if (stored !== undefined) {
    const dest = join(effectDir, TARGET);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, stored);
    exported = { path: TARGET, bytes: Buffer.byteLength(stored, 'utf8') };
  }
}

const result = {
  role: 'sut',
  version,
  commit: version === 'v1' ? '631196d' : '7b7e973',
  decision: entry.decision.decision,
  denialKind: entry.decision.denialKind ?? null,
  determiningPolicies: entry.decision.determiningPolicies ?? null,
  cedarByteLen: entry.cedarRequest?.context?.byteLen ?? null,
  toolResult: entry.toolResult?.summary ?? null,
  exported,
  ledger: ledgerOut,
};
writeFileSync(resultOut, JSON.stringify(result, null, 2));
console.log(JSON.stringify(result));
