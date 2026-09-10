import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const toolchain = readFileSync('formal/lean-toolchain', 'utf8').trim();
const result = spawnSync('lean', [`+${toolchain}`, 'formal/Boundary.lean'], {
  encoding: 'utf8', timeout: 60000,
});
process.stdout.write(result.stdout ?? '');
process.stderr.write(result.stderr ?? '');
assert.equal(result.status, 0, String(result.error ?? 'Lean check failed'));
const output = result.stdout;
assert.doesNotMatch(output, /sorryAx/);
const allowed = new Set(['propext', 'Quot.sound']);
for (const [, axioms] of output.matchAll(/depends on axioms: \[([^\]]*)\]/g)) {
  for (const axiom of axioms.split(',').map(x => x.trim()).filter(Boolean)) {
    assert.ok(allowed.has(axiom), `unapproved proof axiom ${axiom}`);
  }
}
for (const name of ['execution_has_recorded_allow', 'grants_execute_at_most_once', 'reuse_mutant_has_bad_trace']) {
  assert.ok(output.includes(`'Boundary.${name}'`), `missing axiom audit for ${name}`);
}
