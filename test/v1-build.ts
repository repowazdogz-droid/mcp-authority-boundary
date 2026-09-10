import { existsSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

/**
 * Build the pristine v1 artifact (commit 631196d) from `git archive` into a
 * cache directory, so tests can measure the ORIGINAL defect against the same
 * bytes the talk cites, without depending on a worktree that happens to exist.
 *
 * The build reuses this repo's node_modules by symlink: v1 pins the same
 * cedar-wasm version and its package-lock.json is byte-identical to HEAD's
 * (git diff 631196d HEAD -- package-lock.json is empty), so no install is
 * needed and no network is touched.
 */
export const V1_COMMIT = '631196d';
export const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));

export function v1Build(): string {
  const dir = join(tmpdir(), `mab-v1-${V1_COMMIT}`);
  const built = join(dir, 'dist/src/enforce.js');
  if (existsSync(built) && existsSync(join(dir, 'BUILT_FROM'))) return dir;
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const archive = spawnSync('git', ['archive', V1_COMMIT], { cwd: REPO, maxBuffer: 64 * 1024 * 1024 });
  if (archive.status !== 0) throw new Error(`git archive ${V1_COMMIT} failed: ${archive.stderr}`);
  const untar = spawnSync('tar', ['-x', '-C', dir], { input: archive.stdout });
  if (untar.status !== 0) throw new Error(`tar failed: ${untar.stderr}`);
  symlinkSync(join(REPO, 'node_modules'), join(dir, 'node_modules'), 'dir');
  const tsc = spawnSync(process.execPath, [join(REPO, 'node_modules/typescript/bin/tsc'), '-p', dir], {
    encoding: 'utf8',
  });
  if (tsc.status !== 0) throw new Error(`tsc for ${V1_COMMIT} failed:\n${tsc.stdout}${tsc.stderr}`);
  writeFileSync(join(dir, 'BUILT_FROM'), `${V1_COMMIT}\n`);
  return dir;
}
