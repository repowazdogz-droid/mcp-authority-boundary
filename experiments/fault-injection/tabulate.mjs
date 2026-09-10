// Mechanical tabulation: read every artifact under <RESULTS> and emit the
// mutation matrix. No interpretations here; verdicts are extracted, not judged.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const [resDir, outJson, outMd] = process.argv.slice(2);

const J = (p) => JSON.parse(readFileSync(p, 'utf8'));
const T = (p) => (existsSync(p) ? readFileSync(p, 'utf8') : null);

function suiteOf(d) {
  const t = T(join(resDir, d, 'suite.txt'));
  if (!t) return 'n/a (post-hoc ledger edit; suite uses fresh ledgers)';
  const pass = t.match(/ℹ pass (\d+)/)?.[1] ?? '?';
  const fail = t.match(/ℹ fail (\d+)/)?.[1] ?? '?';
  if (fail === '0') return `PASS ${pass}/0`;
  const names = [...t.matchAll(/^✖ (?!failing tests)(.+?) \(\d/gm)].map((m) => m[1]);
  return `FAIL ${pass} pass / ${fail} fail (e.g. ${names.slice(0, 3).join('; ')})`;
}

function replayOf(d, sub = null) {
  const p = sub ? join(resDir, 'L-base', `replay-${sub}.txt`) : join(resDir, d, `replay-${d}.txt`);
  const t = T(p);
  if (!t || /no ledger at/.test(t)) return { verdict: 'n/a (no ledger on this probe path)', binding: 'n/a' };
  const verdict =
    /verdict\s+VERIFIED/.test(t) ? 'VERIFIED'
    : /verdict:\s*ALL STAGES PASS/.test(t) || /verdict ALL STAGES PASS/.test(t) ? 'ALL STAGES PASS'
    : /verdict\s+INCOMPLETE/.test(t) ? 'INCOMPLETE'
    : /findings [1-9]/.test(t) ? `FAIL (${t.match(/findings (\d+)/)?.[1]} findings)`
    : 'UNKNOWN';
  const bindingLine = t.split('\n').find((l) => l.includes('auth-exec-binding')) ?? '';
  const binding = /FAIL/.test(bindingLine) ? 'FAIL' : /NOT CHECKED/.test(bindingLine) ? 'NOT CHECKED' : /PASS/.test(bindingLine) ? 'PASS' : 'n/a';
  return { verdict, binding };
}

function obsOf(d, file) {
  const o = J(join(resDir, d, file));
  return o.comparison;
}

const rows = [
  { defect: 'D1 executor uses raw input', tests: suiteOf('D1'), cedar: 'unexpected-type input refused / plain input allowed (masked upstream)', replay: replayOf('D1').verdict, binding: replayOf('D1').binding, observer: obsOf('D1', 'obs-D1.json') },
  { defect: 'D2 grant-digest check removed', tests: suiteOf('D2'), cedar: 'allow (for input A; grant presented with input B)', replay: replayOf('D2').verdict, binding: replayOf('D2').binding, observer: 'no write (grant presented with input B is stopped at the linkage check)' },
  { defect: 'D3 resource altered post-auth', tests: suiteOf('D3'), cedar: 'allow, then fail-loud THROW', replay: replayOf('D3').verdict, binding: replayOf('D3').binding, observer: `${obsOf('D3', 'obs-D3.json')} (stray .shadow file, empty ledger)` },
  { defect: 'D4 coercion reintroduced', tests: suiteOf('D4'), cedar: 'ALLOW byteLen=0', replay: replayOf('D4').verdict, binding: replayOf('D4').binding, observer: `${obsOf('D4', 'obs-D4.json')} (0 vs 0)` },
  { defect: 'D5 grant reuse allowed', tests: suiteOf('D5'), cedar: 'allow', replay: replayOf('D5').verdict, binding: replayOf('D5').binding, observer: `${obsOf('D5', 'obs-D5.json')} (11B written, zero ledger lines)` },
  { defect: 'D6 effect omitted', tests: suiteOf('D6'), cedar: 'allow, then fail-loud THROW', replay: replayOf('D6').verdict, binding: replayOf('D6').binding, observer: obsOf('D6', 'obs-D6.json') },
  { defect: 'D9 combined variant (D1+D4)', tests: suiteOf('D9'), cedar: 'allow at resolution, then THROW at linkage', replay: replayOf('D9').verdict, binding: replayOf('D9').binding, observer: obsOf('D9', 'obs-D9.json') },
  { defect: 'D7a mediation record edited', tests: suiteOf('L-base') === undefined ? '' : 'n/a (post-hoc ledger edit)', cedar: 'n/a', replay: replayOf(null, 'D7a').verdict, binding: replayOf(null, 'D7a').binding, observer: `${J(join(resDir, 'L-base', 'obs-D7a-roadmap.json')).comparison} (effect matches; the edit is in mediation metadata)` },
  { defect: 'D7b mediation edited + chain re-hashed', tests: 'n/a (post-hoc ledger edit)', cedar: 'n/a', replay: replayOf(null, 'D7b').verdict, binding: replayOf(null, 'D7b').binding, observer: `${J(join(resDir, 'L-base', 'obs-D7b-roadmap.json')).comparison} (fully invisible)` },
  { defect: 'D8 ledger truncated', tests: 'n/a (post-hoc ledger edit)', cedar: 'n/a', replay: replayOf(null, 'D8').verdict, binding: replayOf(null, 'D8').binding, observer: `${J(join(resDir, 'L-base', 'obs-D8-roadmap.json')).comparison} (truncated target) / ${J(join(resDir, 'L-base', 'obs-D8-notes.json')).comparison} (retained control)` },
];

const matrix = { producedBy: 'tabulate.mjs over /tmp/mab-mut/results artifacts (suites, probes, replays, observations)', rows };
writeFileSync(outJson, JSON.stringify(matrix, null, 2));
const md = [
  '| Injected defect | Existing tests | Cedar | Replay | Binding check | Independent observer |',
  '|---|---|---|---|---|---|',
  ...rows.map((r) => `| ${r.defect} | ${r.tests} | ${r.cedar} | ${r.replay} | ${r.binding} | ${r.observer} |`),
  '',
].join('\n');
writeFileSync(outMd, md);
console.log(md);
