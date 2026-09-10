// Print ONE sha256 over the sorted (path, hash) pairs of the source manifest in
// experiments/hardening/RESULTS.json, so a slide can cite a single digest for
// the whole measured artifact. Also reports how many manifest entries differ
// from the working tree, and exits non-zero if any do: a digest over a stale
// manifest is not a digest of the code in front of you.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(fileURLToPath(new URL('..', import.meta.url)));
const results = JSON.parse(readFileSync(join(repo, 'experiments/hardening/RESULTS.json'), 'utf8'));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const pairs = Object.entries(results.sourceHashes).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
const digest = createHash('sha256');
for (const [path, hash] of pairs) digest.update(`${path}\0${hash}\n`);

let stale = 0;
for (const [path, hash] of pairs) {
  const file = join(repo, path);
  const current = existsSync(file) ? sha256(readFileSync(file)) : null;
  if (current !== hash) { stale += 1; console.error(`stale: ${path} (${current === null ? 'missing' : 'changed'} since RESULTS.json)`); }
}
console.log(`manifest-digest ${digest.digest('hex')}`);
console.log(`  ${pairs.length} files in experiments/hardening/RESULTS.json (gitHead ${String(results.gitHead).slice(0, 7)}, generated ${results.generatedAt}); ${stale} differ from the working tree`);
process.exitCode = stale === 0 ? 0 : 1;
