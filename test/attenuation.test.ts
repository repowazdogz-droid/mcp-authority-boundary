import { test } from 'node:test';
import assert from 'node:assert/strict';
import type * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { harness } from './helper.js';

const AGENT = { __entity: { type: 'Mcp::Agent', id: 'assistant' } };
const ALICE = { __entity: { type: 'Mcp::Human', id: 'alice' } };
const perm = (id: string) => ({ __entity: { type: 'Mcp::Permission', id } });
const scope = (id: string) => ({ __entity: { type: 'Mcp::Scope', id } });
const sess = (id: string) => ({ __entity: { type: 'Mcp::Session', id } });

/**
 * A child proposed by sess-writer-delegated
 * (write / corp/public / [1000,9000) / 4096 bytes / depth 1).
 *
 * The parent is deliberately NOT the root session: relative to an admin/org
 * parent, proposing `admin` or `org` is not a widening, so an admin parent
 * cannot demonstrate that widening is refused.
 */
const PARENT = 'sess-writer-delegated';

function child(overrides: Record<string, unknown> = {}): cedar.EntityJson {
  return {
    uid: { type: 'Mcp::Session', id: 'sess-under-test' },
    attrs: {
      agent: AGENT,
      delegator: ALICE,
      permission: perm('read'),
      scope: scope('corp/public'),
      notBefore: 1000,
      expiresAt: 4000,
      revoked: false,
      maxWriteBytes: 1024,
      depth: 2,
      delegatedFrom: sess(PARENT),
      ...overrides,
    } as never,
    parents: [{ type: 'Mcp::Agent', id: 'assistant' }],
  } as cedar.EntityJson;
}

function mint(overrides: Record<string, unknown> = {}, from = PARENT) {
  const { pep, restore } = harness({ session: from, clock: 2000 });
  try {
    return pep.handleDelegation(child(overrides)).decision;
  } finally {
    restore();
  }
}

test('a proposal that narrows every dimension is minted', () => {
  const d = mint();
  assert.equal(d.decision, 'allow');
  assert.deepEqual(d.determiningPolicies, ['permit-delegate-attenuated']);
});

test('a proposal may not widen any single dimension', () => {
  const widenings: Array<[string, Record<string, unknown>]> = [
    ['capability tier', { permission: perm('admin') }],
    ['resource scope', { scope: scope('org') }],
    ['expiry', { expiresAt: 99999 }],
    ['start of validity', { notBefore: 0 }],
    ['write budget', { maxWriteBytes: 99_999_999 }],
  ];
  for (const [what, override] of widenings) {
    const d = mint(override);
    assert.equal(d.decision, 'deny', `widening the ${what} was permitted`);
    assert.equal(d.denialKind, 'no-matching-permit', `widening the ${what}`);
  }
});

test('a proposal must record the parent it claims to descend from', () => {
  const noParent = child();
  delete (noParent.attrs as Record<string, unknown>)['delegatedFrom'];
  const { pep, restore } = harness({ session: PARENT, clock: 2000 });
  try {
    assert.equal(pep.handleDelegation(noParent).decision.decision, 'deny');
  } finally {
    restore();
  }

  // ...and it must name the session actually doing the delegating
  assert.equal(mint({ delegatedFrom: sess('sess-alice-root') }).decision, 'deny');
  // ...at exactly one hop deeper
  assert.equal(mint({ depth: 5 }).decision, 'deny');
  assert.equal(mint({ depth: 1 }).decision, 'deny');
});

test('an expired or revoked parent cannot delegate at all', () => {
  const { pep, restore } = harness({ session: 'sess-analyst-delegated', clock: 6000 });
  try {
    const d = pep.handleDelegation(
      child({ delegatedFrom: sess('sess-analyst-delegated'), depth: 2, expiresAt: 4000 }),
    ).decision;
    assert.equal(d.decision, 'deny');
    assert.deepEqual(d.determiningPolicies, ['forbid-outside-validity-window']);
  } finally {
    restore();
  }
});

test('an admin parent may legitimately mint an admin child - attenuation is not "always narrower"', () => {
  // the mirror of the widening test: what is refused above is refused because
  // it exceeds THIS parent, not because sub-grants must always shrink
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const d = pep.handleDelegation(
      child({ permission: perm('admin'), scope: scope('org'), delegatedFrom: sess('sess-alice-root'), depth: 1 }),
    ).decision;
    assert.equal(d.decision, 'allow');
  } finally {
    restore();
  }
});

test('a session that widened its grant is refused at every decision, not only at mint', () => {
  const { pep, restore } = harness({ session: 'sess-rogue-widened', clock: 2000 });
  try {
    for (const call of [
      { tool: 'read_document', args: { path: 'corp/public/roadmap.md' } },
      { tool: 'write_document', args: { path: 'corp/public/notes.md', content: 'x' } },
      { tool: 'delete_file', args: { path: 'corp/public/notes.md' } },
      { tool: 'query_database', args: { sql: 'SELECT * FROM analytics.metrics' } },
    ]) {
      const { entry } = pep.handle(call);
      assert.equal(entry.decision.decision, 'deny', JSON.stringify(call));
      assert.deepEqual(entry.decision.determiningPolicies, ['forbid-widening-delegation']);
    }
  } finally {
    restore();
  }
});
