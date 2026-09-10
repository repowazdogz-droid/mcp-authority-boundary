import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveCall } from '../src/resolve.js';
import { Pdp } from '../src/pdp.js';
import { loadEntities, loadPolicy } from '../src/policy.js';
import { permitAllMediator } from '../src/mediation.js';
import { executeTool } from '../src/tools.js';
import { harness } from './helper.js';

/**
 * GRANT SINGLE-USE UNDER CONCURRENCY.
 *
 * One grant, N=100 concurrent consumers fired through Promise.all, 20 rounds.
 * The property under test is that exactly one consumer succeeds per round.
 *
 * What "concurrent" means here, stated so the green bar is not over-read: Node
 * runs JavaScript on one thread, and consumeGrant contains no await, so the
 * spent-set check and the spent-set insertion cannot interleave with another
 * consumer of the same grant inside this process. Each consumer below yields to
 * the event loop before consuming, so the 100 calls are genuinely interleaved
 * as tasks, but the check-then-mark inside consumeGrant is still one
 * synchronous step. This test therefore measures the property the runtime
 * gives the code, not a lock the code implements. A grant is an in-process
 * object held in a WeakSet: it cannot be handed to another process or thread,
 * so there is no cross-process race to measure. That is a boundary of the
 * result, not evidence about multi-process deployments.
 */
const SESSION = 'sess-writer-delegated';
const N = 100;
const ROUNDS = 20;

test(`one grant, ${N} concurrent consumers, ${ROUNDS} rounds: exactly one succeeds per round`, async () => {
  const pdp = new Pdp(loadPolicy('v1'));
  const entities = loadEntities();
  const principal = { type: 'Mcp::Session', id: SESSION };
  const mediator = permitAllMediator();
  const { restore } = harness({ session: SESSION, clock: 2000 });
  const successesPerRound: number[] = [];
  try {
    for (let round = 0; round < ROUNDS; round++) {
      const r = resolveCall({ tool: 'write_document', args: { path: 'corp/public/notes.md', content: `round ${round}` } }, {
        requestId: `race-${round}`, now: 2000, sourceTrust: 'user', entities,
      });
      assert.ok(r.ok);
      const mediation = mediator.mediateOperation(principal, r.call.operation, r.call.operationSha256, 2000);
      const outcome = pdp.authorize({ ...r.call, principal, entities, mediation });
      assert.equal(outcome.decision.decision, 'allow');
      assert.ok(outcome.grant);
      const grant = outcome.grant;

      const results = await Promise.all(
        Array.from({ length: N }, async (_, i) => {
          // yield so the N consumers interleave as event-loop tasks
          await new Promise<void>((resolve) => setImmediate(resolve));
          if (i % 2) await Promise.resolve();
          try { executeTool(r.call.operation, grant, mediation); return 'ok'; }
          catch (error) { return String(error); }
        }),
      );
      const ok = results.filter((x) => x === 'ok').length;
      const spent = results.filter((x) => /already spent/.test(x)).length;
      successesPerRound.push(ok);
      assert.equal(ok + spent, N, `round ${round}: every consumer either succeeded or was refused as spent; got ${JSON.stringify(results.filter((x) => x !== 'ok' && !/already spent/.test(x)).slice(0, 3))}`);
    }
  } finally { restore(); }
  const max = Math.max(...successesPerRound);
  console.log(`grant-race: ${ROUNDS} rounds × ${N} concurrent consumers; successes per round = [${successesPerRound.join(',')}]; max = ${max}`);
  assert.equal(max, 1, `more than one consumer succeeded in some round: ${JSON.stringify(successesPerRound)}`);
  assert.equal(Math.min(...successesPerRound), 1);
});
