import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolveCall } from '../src/resolve.js';
import { Pdp } from '../src/pdp.js';
import { loadEntities, loadPolicy } from '../src/policy.js';
import { permitAllMediator, type EffectMediation } from '../src/mediation.js';
import { executeTool, snapshotDocuments } from '../src/tools.js';
import { Ledger, readLedger, sealPath } from '../src/ledger.js';
import { replay } from '../src/replay.js';
import { sha256Canonical } from '../src/canonical.js';
import { harness } from './helper.js';
import type { LedgerEntry, ResolvedOperation } from '../src/types.js';

/**
 * The grant is bound to the operation digest, and the digest is re-checked at
 * execution. This file turns that sentence from a comment (enforce.ts, the
 * pipeline diagram) into a measured property.
 *
 * Where the check lives, traced by reading the code path, not the comments:
 *
 *   enforce.ts   handleLocked -> executeTool(call.operation, outcome.grant, mediation)
 *   tools.ts     executeTool  -> consumeGrant(grant, op, mediation) before any effect
 *   mediation.ts consumeGrant -> digest = sha256Canonical(operation)          (computed)
 *                             -> mediation.operationSha256 !== digest -> throw (linkage)
 *                             -> grant.operationSha256     !== digest -> throw (binding)
 *   pdp.ts       authorize    -> mintGrant(requestId, operationSha256, mediation.hash, ...)
 *                               after re-resolving and re-digesting the operation
 *
 * Two refusals guard a mutated operation, in that order. The mediation-linkage
 * check fires first for an operation presented with the ORIGINAL mediation
 * record; the grant-binding check is what fires when the mediation record was
 * cleared for the presented operation but the grant was minted for another. The
 * test exercises both, so neither can be deleted without a red bar.
 */

const REQUEST = 'grant-binding';
const principal = { type: 'Mcp::Session', id: 'sess-writer-delegated' };
const entities = loadEntities();
const mediator = permitAllMediator();

function resolve(args: Record<string, unknown>) {
  const r = resolveCall({ tool: 'write_document', args }, {
    requestId: REQUEST, now: 2000, sourceTrust: 'user', entities,
  });
  assert.ok(r.ok, r.ok ? '' : r.reason);
  const call = r.call;
  const mediation = mediator.mediateOperation(principal, call.operation, call.operationSha256, 2000);
  return { call, mediation, input: { ...call, principal, entities, mediation } };
}

const CANONICAL = { path: 'corp/public/notes.md', content: 'ok' };

test('(a) a grant minted for the resolved operation executes that same operation', () => {
  const pdp = new Pdp(loadPolicy('v1'));
  const { call, mediation, input } = resolve(CANONICAL);
  const outcome = pdp.authorize(input);
  assert.equal(outcome.decision.decision, 'allow');
  assert.ok(outcome.grant);
  assert.equal(outcome.grant.operationSha256, call.operationSha256);
  assert.equal(outcome.grant.operationSha256, sha256Canonical(call.operation), 'grant digest is the digest of the frozen operation');
  const result = executeTool(call.operation, outcome.grant, mediation);
  assert.equal(result.ok, true);
  console.log(`grant-binding (a): same op -> executed; grant.operationSha256 ${call.operationSha256.slice(0, 16)}...`);
});

test('(b) one byte changed after minting is refused at execution, and the world does not move', () => {
  const pdp = new Pdp(loadPolicy('v1'));
  const before = snapshotDocuments();
  const original = resolve(CANONICAL);

  // The frozen operation cannot be edited in place - that is a TypeError - so
  // the mutated operation is a second, equally valid resolved operation whose
  // canonical form differs from the authorized one by one byte.
  assert.throws(() => { (original.call.operation as { content: string }).content = 'oj'; }, TypeError);

  const mutations: Array<[string, Record<string, unknown>]> = [
    ['content byte', { ...CANONICAL, content: 'oj' }],
    ['path byte', { ...CANONICAL, path: 'corp/public/roadmap.md' }],
  ];
  for (const [label, args] of mutations) {
    const mutated = resolve(args);
    assert.notEqual(mutated.call.operationSha256, original.call.operationSha256);

    // (b1) grant + mediation for the ORIGINAL operation, mutated operation presented.
    // The first refusal on the path is the mediation linkage (mediation.ts).
    const g1 = pdp.authorize(original.input);
    assert.ok(g1.grant);
    assert.throws(
      () => executeTool(mutated.call.operation, g1.grant, original.mediation),
      /mediation clears operation [0-9a-f]+, but the operation presented digests to/,
      `${label}: mediation linkage`,
    );

    // (b2) a grant minted for the ORIGINAL operation but bound to a mediation
    // record cleared for the MUTATED one. pdp.authorize does not cross-check
    // mediation.operationSha256 against the operation, so this grant can exist;
    // the linkage check passes, and the grant-binding digest check is what refuses.
    const g2 = pdp.authorize({ ...original.input, mediation: mutated.mediation });
    assert.ok(g2.grant, 'authorize mints for the original operation');
    assert.equal(g2.grant.operationSha256, original.call.operationSha256);
    assert.throws(
      () => executeTool(mutated.call.operation, g2.grant, mutated.mediation),
      /grant authorises operation [0-9a-f]+, but the operation presented digests to/,
      `${label}: grant binding`,
    );

    // and the grant is still valid for what it was minted for
    assert.equal(executeTool(original.call.operation, g1.grant, original.mediation).ok, true, `${label}: original still executes`);
    console.log(`grant-binding (b) ${label}: authorized ${original.call.operationSha256.slice(0, 12)} presented ${mutated.call.operationSha256.slice(0, 12)} -> REFUSED (linkage) and REFUSED (grant digest)`);
  }

  // Nothing but the authorized writes touched the world: notes.md holds 'ok',
  // never 'oj', and roadmap.md is untouched.
  const after = snapshotDocuments();
  assert.equal(after.documents.get('corp/public/notes.md'), 'ok');
  assert.equal(after.documents.get('corp/public/roadmap.md'), before.documents.get('corp/public/roadmap.md'));
  const { restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  restore(); // put the fixture world back for later test files
});

function unchained(e: LedgerEntry) {
  const { seq: _s, prevHash: _p, hash: _h, ...rest } = e;
  return rest;
}

test('(c) replay does not report ALL STAGES PASS for an execution that did not happen', () => {
  // Positive control: one honest execution, sealed, replays clean.
  const honest = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const r = honest.pep.handle({ tool: 'write_document', args: CANONICAL });
    assert.equal(r.entry.decision.decision, 'allow');
    assert.ok(r.result);
    new Ledger(honest.ledgerPath).seal();
    const v = replay(honest.ledgerPath);
    assert.equal(v.verdict, 'ALL STAGES PASS', JSON.stringify(v.findings));
    console.log(`grant-binding (c) honest ledger: ${v.verdict}`);
  } finally { honest.restore(); }

  // (c1) A record claiming the mutated operation executed, carrying the
  // ORIGINAL digest (what a runtime divergence would look like if the record
  // were written from the mutated op but the digest copied from the grant).
  // (c2) The same claim with a freshly computed digest for the mutated op.
  // Neither execution happened. Both must fail replay.
  const forgeries: Array<[string, (op: ResolvedOperation, digest: string) => string | null, RegExp]> = [
    ['c1 original digest', (_op, digest) => digest, /operation digest recomputes to/],
    ['c2 recomputed digest', (op) => sha256Canonical(op), /execution without prepared authorization/],
  ];
  for (const [label, digestOf, expected] of forgeries) {
    const h = harness({ session: 'sess-writer-delegated', clock: 2000 });
    try {
      h.pep.handle({ tool: 'write_document', args: CANONICAL });
      const real = readLedger(h.ledgerPath)[0]!;
      assert.ok(real.operation && real.operation.tool === 'write_document');
      const mutatedOp = { ...real.operation, content: 'oj' } as ResolvedOperation;
      const forged = {
        ...unchained(real),
        requestId: `${real.requestId}-forged`,
        operation: mutatedOp,
        operationSha256: digestOf(mutatedOp, real.operationSha256!),
        decision: { ...real.decision, requestId: `${real.requestId}-forged` },
        cedarRequest: { ...real.cedarRequest, context: { ...real.cedarRequest.context, requestId: `${real.requestId}-forged` } },
      };
      const ledger = new Ledger(h.ledgerPath);
      ledger.append(forged);
      // The honest sealer refuses: readiness reconciles the intent journal and
      // finds an execution record with no prepared authorization. An attacker
      // who can write the ledger writes the seal file by hand instead.
      assert.throws(() => ledger.seal(), /execution without prepared authorization/, `${label}: Ledger.seal refuses`);
      const entries = readLedger(h.ledgerPath);
      writeFileSync(sealPath(h.ledgerPath), JSON.stringify({ entries: entries.length, finalHash: entries.at(-1)!.hash }) + '\n');
      const v = replay(h.ledgerPath);
      assert.notEqual(v.verdict, 'ALL STAGES PASS', label);
      assert.equal(v.verdict, 'FAILED', label);
      assert.ok(v.findings.some((f) => expected.test(f.detail)), `${label}: ${JSON.stringify(v.findings)}`);
      console.log(`grant-binding (${label}): forged execution record -> ${v.verdict} (${v.findings.length} findings; first: ${v.findings[0]?.detail})`);
    } finally { h.restore(); }
  }
});

test('the digest check is source, not comment: consumeGrant computes and compares it', () => {
  const src = readFileSync(new URL('../../src/mediation.ts', import.meta.url), 'utf8');
  assert.match(src, /const digest = sha256Canonical\(operation\);/);
  assert.match(src, /grant\.operationSha256 !== digest/);
  assert.match(src, /mediation\.operationSha256 !== digest/);
  const tools = readFileSync(new URL('../../src/tools.ts', import.meta.url), 'utf8');
  assert.match(tools, /consumeGrant\(grant, op, mediation\);/);
});
