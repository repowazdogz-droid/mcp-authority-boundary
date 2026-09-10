// Independent implementation: no imports from src/, dist/, or the file adapter.
// Compare the WHOLE final filesystem against a baseline plus completed effects.
import { readFileSync, readdirSync, lstatSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function snapshot(root) {
  const result = {};
  const walk = (relative = '') => {
    for (const name of readdirSync(join(root, relative)).sort()) {
      const key = relative ? `${relative}/${name}` : name;
      const path = join(root, key), st = lstatSync(path);
      if (st.isSymbolicLink()) throw new Error(`observer refuses symlink ${key}`);
      if (st.isDirectory()) walk(key);
      else if (st.isFile()) {
        const bytes = readFileSync(path);
        result[key] = { byteLen: bytes.length, sha256: hash(bytes) };
      } else throw new Error(`observer refuses special file ${key}`);
    }
  };
  walk();
  return result;
}

try {
  const [root, beforeFile, ledgerFile] = process.argv.slice(2);
  const actual = snapshot(root);
  if (!beforeFile) console.log(JSON.stringify(actual));
  else {
    const expected = JSON.parse(readFileSync(beforeFile, 'utf8'));
    const entries = readFileSync(ledgerFile, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
    const findings = [];
    for (const e of entries) {
      if (e.toolResult === null) continue;
      const op = e.operation;
      if (!op || e.decision.decision !== 'allow') { findings.push('execution lacks allow'); continue; }
      if (op.tool === 'write_document') {
        const bytes = Buffer.from(op.content, 'utf8');
        const fingerprint = { byteLen: bytes.length, sha256: hash(bytes) };
        if (fingerprint.byteLen !== e.cedarRequest.context.byteLen ||
            fingerprint.sha256 !== op.contentSha256 || e.cedarRequest.resource.id !== op.path) {
          findings.push(`record authorization mismatch ${op.path}`);
        }
        expected[op.path] = fingerprint;
      } else if (op.tool === 'delete_file') delete expected[op.path];
    }
    for (const key of [...new Set([...Object.keys(expected), ...Object.keys(actual)])].sort()) {
      if (JSON.stringify(expected[key]) !== JSON.stringify(actual[key])) findings.push(`world mismatch ${key}`);
    }
    console.log(JSON.stringify({ verdict: findings.length ? 'DIVERGENCE' : 'AGREE', findings, actual,
      scope: 'final file-state comparison, separate process on the same host; no event-completeness claim' }));
  }
} catch (error) {
  console.log(JSON.stringify({ verdict: 'ERROR', error: String(error) }));
  process.exitCode = 2;
}
