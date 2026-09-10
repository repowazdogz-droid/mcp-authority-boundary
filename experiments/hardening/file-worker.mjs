import { readFileSync, writeFileSync } from 'node:fs';
import { EnforcementPoint } from '../../dist/src/enforce.js';
import { Ledger } from '../../dist/src/ledger.js';
import { loadEntities, loadPolicy } from '../../dist/src/policy.js';
import { permitAllMediator } from '../../dist/src/mediation.js';
import { useDocumentBackend } from '../../dist/src/tools.js';
import { FileBackend } from './file-backend.mjs';

const [root, ledgerPath, caseFile] = process.argv.slice(2);
const spec = JSON.parse(readFileSync(caseFile, 'utf8'));
const backend = new FileBackend(root);
const realSet = backend.set.bind(backend);
if (spec.mutation === 'shadow') backend.set = (path, content) => realSet(path + '.shadow', content);
if (spec.mutation === 'no-write') backend.set = () => {};
if (spec.mutation === 'extra-write') backend.set = (path, content) => {
  realSet(path, content); realSet(path + '.shadow', content);
};
// Transient effects: an effect that exists during the run and is gone before it
// ends. `cleanup` runs after every call returns, i.e. after the enforcement
// point's own in-process observation, and before the external observer looks.
const cleanup = [];
// Each cleanup records whether the transient state was really there before it
// was undone, so an inert mutant (nothing written, nothing to undo) cannot pass
// as a "miss"; run.mjs asserts that record.
if (spec.mutation === 'transient-extra-write') backend.set = (path, content) => {
  realSet(path, content); realSet(path + '.shadow', content);
  cleanup.push(() => {
    outcomes.push({ transient: path + '.shadow', presentBeforeCleanup: backend.has(path + '.shadow') });
    backend.delete(path + '.shadow');
  });
};
if (spec.mutation === 'transient-revert') backend.set = (path, content) => {
  const prior = backend.get(path);
  realSet(path, content);
  cleanup.push(() => {
    outcomes.push({ transient: path, presentBeforeCleanup: backend.get(path) === content, revertedTo: prior === undefined ? null : prior.length });
    if (prior === undefined) backend.delete(path); else realSet(path, prior);
  });
};
useDocumentBackend(backend);
writeFileSync(ledgerPath, '');
const ledger = new Ledger(ledgerPath);
if (spec.mutation === 'completion-failure') ledger.append = () => { throw new Error('injected completion failure'); };
if (spec.mutation === 'prepare-failure') ledger.prepare = () => { throw new Error('injected prepare failure'); };
const pep = new EnforcementPoint({ policy: loadPolicy('v1'), entities: () => loadEntities(), ledger,
  session: { type: 'Mcp::Session', id: spec.session ?? 'sess-writer-delegated' }, now: () => 2000,
  wallClock: '2026-09-08T00:00:00.000Z', mediator: permitAllMediator() });
const outcomes = [];
for (const call of spec.calls) {
  try { outcomes.push({ decision: pep.handle(call).entry.decision.decision }); }
  catch (error) { outcomes.push({ error: String(error) }); break; }
  finally { while (cleanup.length) cleanup.pop()(); }
}
try { ledger.seal(); } catch (error) { outcomes.push({ sealError: String(error) }); }
console.log(JSON.stringify(outcomes));
