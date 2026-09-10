import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { REPO, V1_COMMIT, v1Build } from './v1-build.js';

/**
 * The independent-observer experiment exports v1's in-memory effect map to a
 * real file so a third party can hash it. That export is a claim: "the bytes on
 * disk are the bytes the SUT's executor produced". This test measures it.
 *
 * run-sut.mjs hashes the map value before writing and the file after writing;
 * this test hashes the file a third time, itself, and requires all three to
 * agree. The stimulus is the A1 witness (content: [<100,000 chars>]), so the
 * expected export is 100,000 bytes of 'x'.
 */
const EXPECTED_SHA256 = 'd69e68988157833272305aaf21f453c800346e8a3640db6578e260215542e5d4';

test('harness export of the v1 effect map is byte-identical to the in-memory value', () => {
  const v1 = v1Build();
  const work = mkdtempSync(join(tmpdir(), 'mab-export-'));
  const exp = join(REPO, 'experiments/independent-observer');
  const run = (args: string[]) => {
    const r = spawnSync(process.execPath, args, { encoding: 'utf8', cwd: work });
    assert.equal(r.status, 0, `${args[0]} failed: ${r.stderr}`);
    return r.stdout;
  };
  run([join(exp, 'make-stimulus.mjs'), join(work, 'stimulus.json')]);
  const effectDir = join(work, 'effect-v1');
  mkdirSync(effectDir);
  run([join(exp, 'run-sut.mjs'), 'v1', v1, effectDir, join(work, 'ledger-v1.jsonl'),
    join(work, 'stimulus.json'), join(work, 'sut-v1.json')]);

  const result = JSON.parse(readFileSync(join(work, 'sut-v1.json'), 'utf8'));
  assert.equal(result.commit, V1_COMMIT);
  assert.equal(result.decision, 'allow');
  assert.equal(result.cedarByteLen, 0, 'v1 authorizes the array as a zero-byte write');
  assert.ok(result.exported, 'v1 executed, so the harness must have exported');

  const file = join(effectDir, 'corp/public/notes.md');
  const independent = createHash('sha256').update(readFileSync(file)).digest('hex');
  assert.equal(statSync(file).size, 100_000);
  assert.equal(result.exported.memorySha256, result.exported.fileSha256);
  assert.equal(independent, result.exported.memorySha256);
  assert.equal(independent, EXPECTED_SHA256);
  assert.equal(result.exported.byteIdentical, true);

  console.log(`observer-export: in-memory sha256 ${result.exported.memorySha256}`);
  console.log(`observer-export: exported  sha256 ${independent} (${statSync(file).size} bytes, re-hashed by the test)`);
  console.log('observer-export: byte-identical YES');
});
