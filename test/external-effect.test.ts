import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256Canonical } from '../src/canonical.js';
import { loadEntities } from '../src/policy.js';
import { cedarRequestFromOperation, resolveCall } from '../src/resolve.js';
import {
  effectsMatch,
  expectedEffectOf,
  observeEffect,
  restoreDocuments,
  snapshotDocuments,
} from '../src/tools.js';
import type { ResolvedOperation } from '../src/types.js';
import { harness } from './helper.js';

/**
 * S24: the executable form of assumption A8.
 *
 * A8 says the artifact "demonstrates that a REQUEST was refused, not that a real
 * side effect was prevented". These tests make that sentence fail-able. They
 * assert two things at once, and the pairing is the point:
 *
 *   - claims A and B still hold on the S24 operation (green, and they should be);
 *   - the inference "therefore the external consequence is contained" does not
 *     follow, because the thing that denotes the consequence is not in the Cedar
 *     request and is not independently observed after execution.
 *
 * The underlying enforcement limitation is prior work: an effect the monitor can
 * neither observe nor control cannot be constrained by it (Basin et al. 2012;
 * Khoury and Halle 2015; Ray 2026). See "The boundary of the boundary" in
 * README.md. Nothing here is offered as a result about enforcement.
 *
 * NOTHING IN THIS FILE PERFORMS NETWORK ACCESS. `execute_shell` appends to an
 * in-process array (src/tools.ts) and returns `[simulated output]`. The command
 * strings below are data. The domain is a reserved `.example` name and is never
 * resolved.
 */

const BENIGN = 'systemctl restart api';
const DENOTES_EXTERNAL =
  'curl -sX POST https://api.forge.example/repos/acme/widgets/pulls -d @payload.json';

function shellOp(command: string): ResolvedOperation {
  const r = resolveCall(
    { tool: 'execute_shell', args: { host: 'build-01', command } },
    { requestId: 'test', now: 2000, sourceTrust: 'user', entities: loadEntities() },
  );
  assert.ok(r.ok, 'the shell call must resolve');
  return r.call.operation;
}

test('S24: the Cedar request is identical for a benign and an externally-consequential command', () => {
  const benign = cedarRequestFromOperation(shellOp(BENIGN));
  const external = cedarRequestFromOperation(shellOp(DENOTES_EXTERNAL));

  // Not "similar". The same object. The command is not a field Cedar receives,
  // so no policy in this set - present or future - can be written against it.
  assert.deepEqual(external, benign);
  assert.equal(external.resource.type, 'Mcp::Host');
  assert.equal(external.byteLen, 0);
  assert.equal(external.recipientDomain, '');
});

test('S24: authorization-execution binding still separates the two operations', () => {
  // The contrast that keeps claim B honest. The digest DOES distinguish them, so
  // a grant minted for one cannot be spent on the other. Binding is intact and
  // does not help: it binds execution to the authorized operation, and the
  // authorized operation is the one whose consequence is unrepresented.
  assert.notEqual(sha256Canonical(shellOp(BENIGN)), sha256Canonical(shellOp(DENOTES_EXTERNAL)));
});

test('S24: the real PDP returns the same verdict and determining policy for both', () => {
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    for (const command of [BENIGN, DENOTES_EXTERNAL]) {
      const { entry } = pep.handle({ tool: 'execute_shell', args: { host: 'build-01', command } });
      assert.equal(entry.decision.decision, 'allow');
      assert.deepEqual(entry.decision.determiningPolicies, ['permit-admin-tier']);
      // Claim A, on this operation: a result exists only because an allow did.
      assert.ok(entry.toolResult !== null);
    }
  } finally {
    restore();
  }
});

test('S24: forbid-shell-on-production-host is the only lever, and it is about the host', () => {
  // Completes the picture: the policy set CAN deny this command, but only by
  // denying every command on that host. There is no term that reaches the string.
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const { entry } = pep.handle({
      tool: 'execute_shell',
      args: { host: 'prod-db-01', command: DENOTES_EXTERNAL },
    });
    assert.equal(entry.decision.decision, 'deny');
    assert.deepEqual(entry.decision.determiningPolicies, ['forbid-shell-on-production-host']);
  } finally {
    restore();
  }
});

test('claim D: write_document IS independently observed - tampering with the world is detected', () => {
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const { entry } = pep.handle({
      tool: 'write_document',
      args: { path: 'corp/public/notes.md', content: 'hello' },
    });
    assert.equal(entry.decision.decision, 'allow');
    const op = entry.operation!;

    // Normal case: the read-back agrees.
    assert.ok(effectsMatch(expectedEffectOf(op), observeEffect(op)));

    // Now change the world behind the tool's back, as a tool that wrote
    // something other than what it was handed would have done.
    const tampered = snapshotDocuments();
    tampered.documents.set('corp/public/notes.md', 'something else entirely');
    restoreDocuments(tampered);

    // The check notices, because it re-reads the document rather than the record.
    assert.ok(
      !effectsMatch(expectedEffectOf(op), observeEffect(op)),
      'the write effect check must detect a document that does not match the authorized operation',
    );
  } finally {
    restore();
  }
});

test('claim D: execute_shell is NOT independently observed - the observation ignores its argument', () => {
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const { entry } = pep.handle({
      tool: 'execute_shell',
      args: { host: 'build-01', command: BENIGN },
    });
    assert.equal(entry.decision.decision, 'allow');
    const executed = entry.operation!;

    // Ask for the "observed effect" of an operation that was never executed.
    const neverExecuted = shellOp(DENOTES_EXTERNAL);
    assert.notEqual(sha256Canonical(neverExecuted), sha256Canonical(executed));

    // The answer describes the operation that WAS executed. observeEffect's shell
    // branch reads the tail of `shellLog`, and executeTool appended that entry
    // from the operation it was handed - so expected and observed are two
    // derivations of one object, not two views of a world. There is no channel
    // here for a real effect to disagree through, which is exactly why claim D
    // is scoped away from this tool in docs/LIMITATIONS.md L7.
    assert.deepEqual(observeEffect(neverExecuted), expectedEffectOf(executed));
  } finally {
    restore();
  }
});
