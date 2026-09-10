import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveCall } from '../src/resolve.js';
import { Pdp } from '../src/pdp.js';
import { loadEntities, loadPolicy, type EntityStore } from '../src/policy.js';
import { permitAllMediator } from '../src/mediation.js';
import { executeTool } from '../src/tools.js';
import { sha256 } from '../src/canonical.js';
import { harness } from './helper.js';

/**
 * DECISION-TIME vs EXECUTION-TIME SEMANTICS.
 *
 * Obtain an allow and a grant; then change the world so the same request would
 * now be denied; then execute with the still-held grant. This file RECORDS what
 * happens. Whichever way it comes out is written into docs/ASSUMPTIONS.md as the
 * stated rule; the test pins that rule so it cannot drift silently.
 *
 * Three changes between mint and consume are tried:
 *   (1) policy plane: a forbid policy for the session is deployed (overlay)
 *   (2) data plane: the session entity is revoked in the store
 *   (3) time: the clock moves past the session's expiresAt
 *
 * The split API (Pdp.authorize then executeTool) is what makes the window
 * observable. Through EnforcementPoint.handle the decision and the execution
 * happen inside one ledger-exclusive call with no caller-visible gap, so the
 * window this file measures is one a caller of the lower-level API holds open.
 */
const SESSION = 'sess-analyst-delegated';   // read on corp/finance, expires at 5000
const principal = { type: 'Mcp::Session', id: SESSION };
const CALL = { tool: 'read_document', args: { path: 'corp/finance/q3-forecast.md' } };

function mintAt(pdp: Pdp, entities: EntityStore, now: number, requestId: string) {
  const r = resolveCall(CALL, { requestId, now, sourceTrust: 'user', entities });
  assert.ok(r.ok, r.ok ? '' : r.reason);
  const mediation = permitAllMediator().mediateOperation(principal, r.call.operation, r.call.operationSha256, now);
  const outcome = pdp.authorize({ ...r.call, principal, entities, mediation });
  assert.equal(outcome.decision.decision, 'allow', outcome.decision.explanation);
  assert.ok(outcome.grant);
  return { call: r.call, mediation, grant: outcome.grant };
}

function revokedCopy(base: EntityStore): EntityStore {
  const entities = JSON.parse(JSON.stringify(base.entities)) as typeof base.entities;
  const session = entities.find((e) => (e.uid as { id: string }).id === SESSION)!;
  (session.attrs as { revoked: boolean }).revoked = true;
  const byUid = new Map(base.byUid);
  for (const e of entities) { const u = e.uid as { type: string; id: string }; byUid.set(`${u.type}::"${u.id}"`, e); }
  return { entities, byUid, sha256: sha256(JSON.stringify(entities)) };
}

test('(1) policy deployed between mint and consume: the grant still executes (decision-time semantics)', () => {
  const { restore } = harness({ session: SESSION, clock: 2000 });
  try {
    const entities = loadEntities();
    const v1 = new Pdp(loadPolicy('v1'));
    const minted = mintAt(v1, entities, 2000, 'toctou-policy');

    // the world changes: v2 forbids this session outright
    const v2 = new Pdp(loadPolicy('v2', ['overlay-revocation']));
    const again = v2.authorize({ ...minted.call, principal, entities, mediation: minted.mediation });
    assert.equal(again.decision.decision, 'deny');
    assert.deepEqual(again.decision.determiningPolicies, ['revoke-session-analyst-delegated']);

    // the grant minted under v1 is consumed after v2 is in force
    let outcome: string;
    try { executeTool(minted.call.operation, minted.grant, minted.mediation); outcome = 'EXECUTED'; }
    catch (error) { outcome = `REFUSED: ${String(error)}`; }
    console.log(`toctou (1) policy change between mint and consume -> ${outcome}`);
    assert.equal(outcome, 'EXECUTED', 'observed 2026-09-10: consumeGrant does not re-check policy');
    assert.equal(minted.grant.policyVersionSha, v1['policy'].version.sha256, 'the grant names the version it was decided under');
    assert.notEqual(minted.grant.policyVersionSha, v2['policy'].version.sha256);
  } finally { restore(); }
});

test('(2) session revoked in the entity store between mint and consume: the grant still executes', () => {
  const { restore } = harness({ session: SESSION, clock: 2000 });
  try {
    const pdp = new Pdp(loadPolicy('v1'));
    const live = loadEntities();
    const minted = mintAt(pdp, live, 2000, 'toctou-revocation');

    const revoked = revokedCopy(live);
    assert.notEqual(revoked.sha256, live.sha256);
    const again = pdp.authorize({ ...minted.call, principal, entities: revoked, mediation: minted.mediation });
    assert.equal(again.decision.decision, 'deny');
    assert.deepEqual(again.decision.determiningPolicies, ['forbid-revoked-session']);

    let outcome: string;
    try { executeTool(minted.call.operation, minted.grant, minted.mediation); outcome = 'EXECUTED'; }
    catch (error) { outcome = `REFUSED: ${String(error)}`; }
    console.log(`toctou (2) session revocation between mint and consume -> ${outcome}`);
    assert.equal(outcome, 'EXECUTED', 'observed 2026-09-10: a grant carries no revocation check');
  } finally { restore(); }
});

test('(3) session expiry between mint and consume: the grant still executes', () => {
  const { restore } = harness({ session: SESSION, clock: 2000 });
  try {
    const pdp = new Pdp(loadPolicy('v1'));
    const entities = loadEntities();
    const minted = mintAt(pdp, entities, 4999, 'toctou-expiry');   // expiresAt = 5000

    const r = resolveCall(CALL, { requestId: 'toctou-expiry-late', now: 5000, sourceTrust: 'user', entities });
    assert.ok(r.ok);
    const late = pdp.authorize({ ...r.call, principal, entities, mediation: permitAllMediator().mediateOperation(principal, r.call.operation, r.call.operationSha256, 5000) });
    assert.equal(late.decision.decision, 'deny');
    assert.deepEqual(late.decision.determiningPolicies, ['forbid-outside-validity-window']);

    let outcome: string;
    try { executeTool(minted.call.operation, minted.grant, minted.mediation); outcome = 'EXECUTED'; }
    catch (error) { outcome = `REFUSED: ${String(error)}`; }
    console.log(`toctou (3) expiry between mint and consume -> ${outcome}`);
    assert.equal(outcome, 'EXECUTED', 'observed 2026-09-10: a grant carries no clock');
  } finally { restore(); }
});

test('through EnforcementPoint.handle there is no caller-visible window: decision and execution are one exclusive step', () => {
  // A second decision under a revoked store is denied and nothing executes;
  // there is no API on the enforcement point that returns a grant to hold.
  const h = harness({ session: SESSION, clock: 2000 });
  try {
    const first = h.pep.handle(CALL);
    assert.equal(first.entry.decision.decision, 'allow');
    assert.ok(first.result);
    const revoked = harness({ session: SESSION, clock: 2000 });
    try {
      const store = revokedCopy(loadEntities());
      (revoked.pep as unknown as { cfg: { entities: () => EntityStore } }).cfg.entities = () => store;
      const second = revoked.pep.handle(CALL);
      assert.equal(second.entry.decision.decision, 'deny');
      assert.equal(second.result, null);
      assert.deepEqual(second.entry.decision.determiningPolicies, ['forbid-revoked-session']);
      console.log('toctou (handle): revocation before the call -> deny, nothing executed; no grant object is ever returned to a caller');
    } finally { revoked.restore(); }
  } finally { h.restore(); }
});
