import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { loadPolicy } from '../src/policy.js';
import { TOOL_NAMES } from '../src/resolve.js';
import { TOOL_SPECS } from '../src/tools.js';
import { harness } from './helper.js';

const POLICY_DIR = new URL('../../policies/', import.meta.url).pathname;

/**
 * Pinned defects.
 *
 * Each test here corresponds to a mistake that was actually made while building
 * this artifact, or to an invariant whose violation would be silent.
 */

test('action groups do not nest: a write-tier grant cannot delete or run shell', () => {
  // The first draft declared `dangerousGroup in [mutatingGroup]`, which made
  // permit-write-tier match delete_file and execute_shell. Tier inheritance
  // belongs in the Permission hierarchy only.
  const { pep, restore } = harness({ session: 'sess-writer-delegated', clock: 2000 });
  try {
    const del = pep.handle({ tool: 'delete_file', args: { path: 'corp/public/notes.md' } });
    assert.equal(del.entry.decision.decision, 'deny', 'a write grant must not confer delete');

    const sh = pep.handle({ tool: 'execute_shell', args: { host: 'build-01', command: 'ls' } });
    assert.equal(sh.entry.decision.decision, 'deny', 'a write grant must not confer shell');

    // ...while the capability ladder still works upward: admin covers read
    const { pep: root, restore: r2 } = harness({ session: 'sess-alice-root', clock: 2000 });
    try {
      assert.equal(
        root.handle({ tool: 'read_document', args: { path: 'corp/public/roadmap.md' } }).entry
          .decision.decision,
        'allow',
      );
    } finally {
      r2();
    }
  } finally {
    restore();
  }
});

test('an absolute forbid cannot be bought back by the highest grant', () => {
  const { pep, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    const d = pep.handle({ tool: 'execute_shell', args: { host: 'prod-db-01', command: 'whoami' } });
    assert.equal(d.entry.decision.decision, 'deny');
    assert.deepEqual(d.entry.decision.determiningPolicies, ['forbid-shell-on-production-host']);
  } finally {
    restore();
  }
});

test('there is no blanket permit anywhere in the policy set', () => {
  for (const f of readdirSync(POLICY_DIR).filter((f) => f.endsWith('.cedar'))) {
    const text = readFileSync(POLICY_DIR + f, 'utf8');
    const parts = cedar.policySetTextToParts(text);
    assert.equal(parts.type, 'success');
    if (parts.type !== 'success') return;
    for (const p of parts.policies) {
      if (!p.includes('permit')) continue;
      assert.ok(/\bwhen\b/.test(p), `unconditional permit found in ${f}:\n${p}`);
    }
  }
});

test('every policy carries an @id, so every decision can be cited', () => {
  const v = loadPolicy('v1');
  assert.equal(v.version.policyIds.length, 14);
  for (const id of v.version.policyIds) {
    assert.match(id, /^(permit|forbid|revoke)-/, `policy id ${id} does not state its effect`);
  }
});

test('the advertised tool set and the resolver agree', () => {
  assert.deepEqual(
    TOOL_SPECS.map((t) => t.name).sort(),
    [...TOOL_NAMES].sort(),
    'a tool advertised over MCP with no resolver mapping would be unauthorizable',
  );
});

test('the policy-set hash changes when any policy source changes', () => {
  const v1 = loadPolicy('v1');
  const again = loadPolicy('v1');
  assert.equal(v1.version.sha256, again.version.sha256, 'hashing must be deterministic');
  assert.notEqual(v1.version.sha256, loadPolicy('v2', ['overlay-revocation']).version.sha256);
});

test('the session bound to the transport is the only principal a decision uses', () => {
  const { pep, restore } = harness({ session: 'sess-analyst-delegated', clock: 2000 });
  try {
    const { entry } = pep.handle({
      tool: 'read_document',
      args: { path: 'corp/finance/q3-forecast.md', principal: 'Mcp::Session::"sess-alice-root"' },
    });
    assert.equal(entry.cedarRequest.principal.id, 'sess-analyst-delegated');
  } finally {
    restore();
  }
});
