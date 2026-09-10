// Trace conformance: run src/ with MAB_TRACE=1, then have Lean check every
// emitted transition against the Boundary.lean transition system.
//
// NOT a refinement proof. See the header of formal/Conformance.lean.
//
//   node scripts/check-conformance.mjs              suite traces only (formal/traces/suite is wiped and regenerated)
//   node scripts/check-conformance.mjs --hardening  also regenerate formal/traces/hardening by running the campaign
//
// Every *.jsonl under formal/traces/ is checked, including committed traces from
// earlier collections (hardening/, observer/), so the checked set is visible in git.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';
import { resolve } from 'node:path';

const toolchain = readFileSync('formal/lean-toolchain', 'utf8').trim();
const ROOT = resolve('formal/traces');
const SUITE = resolve(ROOT, 'suite');
const HARDENING = resolve(ROOT, 'hardening');
const withHardening = process.argv.includes('--hardening');

function traced(dir, command, args) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const r = spawnSync(command, args, { stdio: 'inherit', env: { ...process.env, MAB_TRACE: '1', MAB_TRACE_DIR: dir } });
  assert.equal(r.status, 0, `${command} ${args.join(' ')} failed under MAB_TRACE=1`);
}

traced(SUITE, process.execPath, ['--test', '--test-concurrency=1', ...expand('dist/test/*.test.js'), ...expand('dist/containment/test/*.test.js')]);
if (withHardening) {
  traced(HARDENING, process.execPath, ['experiments/hardening/run.mjs']);
  // Record which trace came from which campaign case while the run directory
  // still exists. Cases with a `mutation` are EXECUTOR-COMPROMISE cases: the
  // executor is deliberately broken, so a divergence in their trace is the
  // planted fault being caught, not a defect. This sidecar is what lets the
  // check below tell those apart from an unexpected non-conformance.
  const cases = {};
  for (const f of readdirSync(HARDENING)) {
    const header = JSON.parse(readFileSync(resolve(HARDENING, f), 'utf8').split('\n')[0]);
    const caseFile = header.argv.find((a) => a.endsWith('/case.json'));
    if (!caseFile) continue;
    const spec = JSON.parse(readFileSync(caseFile, 'utf8'));
    cases[f] = { case: spec.name, mutation: spec.mutation ?? null, threatModel: spec.mutation ? 'executor-compromise' : 'caller-only' };
  }
  writeFileSync(resolve(HARDENING, 'CASES.json'), JSON.stringify(cases, null, 2) + '\n');
}
const cases = existsSync(resolve(HARDENING, 'CASES.json')) ? JSON.parse(readFileSync(resolve(HARDENING, 'CASES.json'), 'utf8')) : {};

const REPORT = 'formal/conformance-report.json';
if (existsSync(REPORT)) rmSync(REPORT);   // its reappearance proves Lean ran
const lean = spawnSync('lean', [`+${toolchain}`, 'formal/Conformance.lean'], {
  encoding: 'utf8', timeout: 300000, env: { ...process.env, MAB_TRACE_DIR: ROOT },
});
process.stdout.write(lean.stdout ?? '');
process.stderr.write(lean.stderr ?? '');
assert.equal(lean.status, 0, String(lean.error ?? 'Lean conformance check failed'));
assert.ok(existsSync(REPORT), `${REPORT} was not written by Lean`);
const report = JSON.parse(readFileSync(REPORT, 'utf8'));
assert.ok(report.traces > 0, 'no traces were collected');
assert.ok(report.events > 0, 'no events were emitted');

// Every non-conforming event is printed by Lean above. Here each one is either
// (a) inside a trace from an executor-compromise mutant, where the mutant's
//     divergence is the finding the observe world-check exists to catch, or
// (b) unexpected, and the check fails.
// Two mutants MUST stay red: `shadow` (write redirected) and `no-write` (write
// dropped). If either trace ever conforms, the observe check has gone blind.
const mustBeRed = new Set(['shadow', 'no-write']);
let expected = 0, unexpected = 0;
const redMutants = new Set();
for (const t of report.perTrace) {
  const meta = cases[basename(t.file)];
  for (const f of t.nonconform) {
    if (meta?.mutation) {
      expected += 1; redMutants.add(meta.mutation);
      console.log(`conformance: EXPECTED non-conformance in ${basename(t.file)} (executor-compromise mutant "${meta.mutation}"): ${f.reason}`);
    } else {
      unexpected += 1;
      console.log(`conformance: UNEXPECTED non-conformance in ${basename(t.file)}: ${f.reason}`);
    }
  }
  assert.equal(t.parseErrors.length, 0, `parse errors in ${t.file}`);
}
for (const m of mustBeRed) {
  if (Object.values(cases).some((c) => c.mutation === m)) {
    assert.ok(redMutants.has(m), `mutant "${m}" produced a CONFORMING trace: the observe world-check is blind`);
  }
}
assert.equal(unexpected, 0, `${unexpected} unexpected non-conforming events; see ${REPORT}`);
console.log(`conformance: OK — ${report.traces} traces, ${report.events} events, ${unexpected} unexpected non-conforming, ${expected} expected (executor-compromise mutants: ${[...redMutants].sort().join(', ')}); trace check, not a refinement proof`);

function expand(glob) {
  const [dir, pattern] = [glob.slice(0, glob.lastIndexOf('/')), glob.slice(glob.lastIndexOf('/') + 1)];
  const re = new RegExp('^' + pattern.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$');
  return readdirSync(dir).filter((f) => re.test(f)).sort().map((f) => `${dir}/${f}`);
}
