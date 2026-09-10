import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolveCall } from '../src/resolve.js';
import { Pdp } from '../src/pdp.js';
import { loadEntities, loadPolicy } from '../src/policy.js';
import { permitAllMediator } from '../src/mediation.js';
import { executeTool } from '../src/tools.js';
import { harness } from './helper.js';
import type { CedarContext } from '../src/types.js';

/**
 * SCOPE: shared test vectors between formal/Boundary.lean and src/, NOT a
 * refinement proof.
 *
 * formal/vectors.json is written by the Lean evaluator when Boundary.lean is
 * checked (npm run test:formal). Each vector is a concrete evaluation of the
 * model's definitions: the `budget` policy on a request, and the two traces the
 * model's examples construct. This test feeds the same inputs through the
 * TypeScript resolver/decision/execution path and requires the same verdicts.
 *
 * What agreement establishes: on these inputs the two implementations decide
 * alike. What it does not establish: anything about inputs not in the list, or
 * that src/ refines the Lean model. The correspondence used here is authored:
 *
 *   model resource 7            <-> Mcp::Document "corp/public/notes.md"
 *   budget r = r.byteLen <= 4096 <-> sess-writer-delegated.maxWriteBytes = 4096,
 *                                   enforced by forbid-oversized-write
 *   Step.execute (unused g.id)  <-> consumeGrant's spent-set check
 */
interface BudgetVector { kind: 'budget'; resource: number; byteLen: number; allowed: boolean }
interface TraceVector {
  kind: 'trace'; name: string; request: BudgetVector; executionIds: number[];
  executions: number; nodup: boolean; reachableUnder: string;
}
const file = JSON.parse(readFileSync(new URL('../../formal/vectors.json', import.meta.url), 'utf8')) as {
  source: string; scope: string; vectors: Array<BudgetVector | TraceVector>;
};
const RESOURCE: Record<number, string> = { 7: 'corp/public/notes.md' };
const SESSION = 'sess-writer-delegated';

test('shared vectors: Lean budget verdicts agree with the Cedar decision path (not a refinement proof)', () => {
  assert.equal(file.source, 'formal/Boundary.lean');
  assert.match(file.scope, /not a refinement proof/);
  const h = harness({ session: SESSION, clock: 2000 });
  let agree = 0;
  try {
    for (const v of file.vectors) {
      if (v.kind !== 'budget') continue;
      const path = RESOURCE[v.resource]!;
      const { entry } = h.pep.handle({ tool: 'write_document', args: { path, content: 'x'.repeat(v.byteLen) } });
      const allowed = entry.decision.decision === 'allow';
      assert.equal((entry.cedarRequest.context as CedarContext).byteLen, v.byteLen, 'Cedar saw the vector\'s byteLen');
      assert.equal(allowed, v.allowed, `budget ⟨${v.resource}, ${v.byteLen}⟩ = ${v.allowed} but src/ decided ${entry.decision.decision}`);
      if (!allowed) {
        assert.equal(entry.decision.denialKind, 'explicit-forbid');
        assert.ok(entry.decision.determiningPolicies.includes('forbid-oversized-write'));
      }
      agree += 1;
      console.log(`formal-vectors: budget ⟨${v.resource}, ${v.byteLen}⟩ = ${v.allowed}  |  src/: ${entry.decision.decision}${allowed ? '' : ` (${entry.decision.determiningPolicies.join(',')})`}  AGREE`);
    }
  } finally { h.restore(); }
  assert.equal(agree, file.vectors.filter((v) => v.kind === 'budget').length);
});

test('shared vectors: Lean trace facts agree with grant consumption (not a refinement proof)', () => {
  const pdp = new Pdp(loadPolicy('v1'));
  const entities = loadEntities();
  const principal = { type: 'Mcp::Session', id: SESSION };
  let agree = 0;
  for (const v of file.vectors) {
    if (v.kind !== 'trace') continue;
    const r = resolveCall({ tool: 'write_document', args: { path: RESOURCE[v.request.resource]!, content: 'x'.repeat(v.request.byteLen) } }, {
      requestId: `vector-${v.name}`, now: 2000, sourceTrust: 'user', entities,
    });
    assert.ok(r.ok);
    const mediation = permitAllMediator().mediateOperation(principal, r.call.operation, r.call.operationSha256, 2000);
    const outcome = pdp.authorize({ ...r.call, principal, entities, mediation });
    assert.equal(outcome.decision.decision === 'allow', v.request.allowed);
    assert.ok(outcome.grant);
    // one grant, attempted as many times as the vector's trace executes it
    let executed = 0;
    let refused: string | null = null;
    for (let i = 0; i < v.executions; i++) {
      try { executeTool(r.call.operation, outcome.grant, mediation); executed += 1; }
      catch (error) { refused = String(error); break; }
    }
    const mutantOnly = v.reachableUnder.startsWith('ReuseStep only');
    if (mutantOnly) {
      // The model reaches this trace only without the single-use premise; src/
      // keeps the premise, so the second execution must be refused.
      assert.equal(v.nodup, false);
      assert.equal(executed, 1);
      assert.match(refused ?? '', /already spent/);
      console.log(`formal-vectors: trace ${v.name}: Lean executionIds ${JSON.stringify(v.executionIds)} nodup=${v.nodup} (${v.reachableUnder})  |  src/: executed 1, second refused "${refused?.split(': ').at(-1)}"  AGREE`);
    } else {
      assert.equal(v.nodup, true);
      assert.equal(executed, v.executions);
      assert.equal(refused, null);
      console.log(`formal-vectors: trace ${v.name}: Lean executionIds ${JSON.stringify(v.executionIds)} nodup=${v.nodup}  |  src/: executed ${executed}, no refusal  AGREE`);
    }
    agree += 1;
  }
  assert.equal(agree, file.vectors.filter((v) => v.kind === 'trace').length);
  const { restore } = harness({ session: SESSION, clock: 2000 });
  restore();
  console.log(`formal-vectors: ${file.vectors.length} vectors, ${file.vectors.length} agree (shared vectors, not a refinement proof)`);
});
