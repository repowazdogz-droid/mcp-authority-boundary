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
}
try { ledger.seal(); } catch (error) { outcomes.push({ sealError: String(error) }); }
console.log(JSON.stringify(outcomes));
