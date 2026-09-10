// Evidence role: combine the SUT results, the independent observations and
// each version's own replay output into one machine-generated evidence table.
//
// Usage:
//   node compare.mjs <RESULTS_DIR> <OUT_JSON> <OUT_MD>
//
// RESULTS_DIR must contain: sut-v1.json, sut-head.json, obs-v1.json,
// obs-head.json, replay-v1.txt, replay-head.txt
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [dir, outJson, outMd] = process.argv.slice(2);
const J = (f) => JSON.parse(readFileSync(join(dir, f), 'utf8'));
const T = (f) => readFileSync(join(dir, f), 'utf8');

const sutV1 = J('sut-v1.json');
const sutHead = J('sut-head.json');
const obsV1 = J('obs-v1.json');
const obsHead = J('obs-head.json');
const replayV1 = T('replay-v1.txt');
const replayHead = T('replay-head.txt');

const replayVerdict = (t) => {
  if (/verdict\s+VERIFIED/.test(t)) return 'VERIFIED';
  if (/verdict:\s*ALL STAGES PASS/.test(t)) return 'ALL STAGES PASS';
  if (/verdict\s+INCOMPLETE/.test(t)) return 'INCOMPLETE (nothing executed, nothing to check)';
  if (/FAILED/.test(t)) return 'FAILED';
  return 'UNKNOWN';
};

const row = (sut, obs, replayText) => ({
  version: sut.version,
  commit: sut.commit,
  cedar:
    sut.decision === 'allow'
      ? `ALLOW (byteLen=${sut.cedarByteLen})`
      : `REFUSE (${sut.denialKind ?? sut.decision}; never reached Cedar as an allow)`,
  ledgerReplay: `${replayVerdict(replayText)} (decision=${sut.decision}${sut.toolResult ? `, ${sut.toolResult}` : ''})`,
  observer:
    obs.comparison === 'DIVERGENCE'
      ? `${obs.fileBytes} bytes written (sha256 ${String(obs.fileSha256).slice(0, 16)}...) vs ${obs.ledgerCedarByteLen} authorized -> DIVERGENCE`
      : obs.comparison === 'NO_EXECUTION_NO_WRITE'
        ? `no write (refused: ${obs.ledgerDenialKind ?? obs.ledgerDecision})`
        : obs.comparison,
});

const table = {
  producedBy: 'compare.mjs from SUT results + independent observations + each version\'s own replay',
  stimulus: 'write_document corp/public/notes.md with content=[100000-char string] (array where a string is expected)',
  rows: [row(sutV1, obsV1, replayV1), row(sutHead, obsHead, replayHead)],
};
writeFileSync(outJson, JSON.stringify(table, null, 2));

const md = [
  '| Version | Cedar | Ledger / replay | Independent world observer |',
  '|---|---|---|---|',
  ...table.rows.map((r) => `| ${r.version} (${r.commit}) | ${r.cedar} | ${r.ledgerReplay} | ${r.observer} |`),
  '',
].join('\n');
writeFileSync(outMd, md);
console.log(md);
