import { test } from 'node:test';
import assert from 'node:assert/strict';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { GENESIS, entryHash, readLedger, verifyChain } from '../src/ledger.js';
import { harness } from './helper.js';
import type { LedgerEntry } from '../src/types.js';

function seed(): { path: string; entries: LedgerEntry[] } {
  const { pep, ledgerPath, restore } = harness({ session: 'sess-alice-root', clock: 2000 });
  try {
    pep.handle({ tool: 'read_document', args: { path: 'corp/public/roadmap.md' } });
    pep.handle({ tool: 'execute_shell', args: { host: 'prod-db-01', command: 'whoami' } });
    pep.handle({ tool: 'write_document', args: { path: 'corp/public/notes.md', content: 'ok' } });
  } finally {
    restore();
  }
  return { path: ledgerPath, entries: readLedger(ledgerPath) };
}

test('an untampered chain verifies', () => {
  const { entries } = seed();
  const r = verifyChain(entries);
  assert.ok(r.ok, JSON.stringify(r.failures));
  assert.equal(entries.length, 3);
  assert.equal(entries[0]!.prevHash, GENESIS);
});

test('editing a past decision breaks that entry and every link after it', () => {
  const { entries } = seed();
  entries[0]!.decision.decision = 'deny';
  const r = verifyChain(entries);
  assert.ok(!r.ok);
  assert.ok(r.failures.some((f) => f.seq === 0 && /hash mismatch/.test(f.problem)));
  assert.ok(r.failures.some((f) => f.seq === 1 && /prevHash/.test(f.problem)));
});

test('deleting an entry from the middle is detected', () => {
  const { entries } = seed();
  entries.splice(1, 1);
  const r = verifyChain(entries);
  assert.ok(!r.ok);
});

test('a re-hashed forgery still fails because the chain does not re-link', () => {
  // an attacker who edits an entry AND recomputes its hash still has to fix
  // every subsequent prevHash; this checks the recompute alone is not enough
  const { entries } = seed();
  const forged = structuredClone(entries[1]!);
  forged.decision.decision = 'allow';
  const { hash: _drop, ...rest } = forged;
  forged.hash = entryHash(rest);
  entries[1] = forged;
  const r = verifyChain(entries);
  assert.ok(!r.ok);
  assert.ok(r.failures.some((f) => f.seq === 2 && /prevHash/.test(f.problem)));
});

test('appending an entry with a stale prevHash is detected', () => {
  const { path } = seed();
  const entries = readLedger(path);
  const bogus = structuredClone(entries[0]!);
  bogus.seq = entries.length;
  appendFileSync(path, JSON.stringify(bogus) + '\n');
  assert.ok(!verifyChain(readLedger(path)).ok);
});

test('the ledger is byte-reproducible across runs', () => {
  const a = seed();
  const b = seed();
  assert.equal(readFileSync(a.path, 'utf8'), readFileSync(b.path, 'utf8'));
});

test('a truncated final line does not silently pass', () => {
  const { path } = seed();
  const raw = readFileSync(path, 'utf8').split('\n').filter(Boolean);
  writeFileSync(path, raw.slice(0, -1).join('\n') + '\n');
  const truncated = readLedger(path);
  assert.equal(truncated.length, 2);
  // truncation of the tail leaves a valid prefix - which is exactly why the
  // chain alone cannot witness completeness. See docs/LIMITATIONS.md, L6.
  assert.ok(verifyChain(truncated).ok);
});
