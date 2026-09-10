// Real-file adapter for controlled experiments. The parent process owns the
// directory topology; concurrent hostile directory replacement is out of scope.
import { constants, closeSync, existsSync, fstatSync, fsyncSync, lstatSync,
  openSync, readFileSync, realpathSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { randomUUID } from 'node:crypto';

export class FileBackend {
  constructor(root) { this.root = realpathSync(root); }
  path(key) {
    if (typeof key !== 'string' || key !== key.normalize('NFC') ||
        key.includes('\\') || key.includes('\0') || key.startsWith('/') ||
        key.split('/').some(p => !p || p === '.' || p === '..' || p.includes(':'))) {
      throw new Error('invalid canonical document key');
    }
    const parts = key.split('/');
    for (let i = 1; i <= parts.length; i++) {
      const path = join(this.root, ...parts.slice(0, i));
      try {
        const st = lstatSync(path);
        if (st.isSymbolicLink()) throw new Error('symlink in document path');
        if (i < parts.length && !st.isDirectory()) throw new Error('non-directory ancestor');
        if (i === parts.length && !st.isFile()) throw new Error('non-file document');
      } catch (error) {
        if (error.code === 'ENOENT' && i === parts.length) continue;
        throw error;
      }
    }
    return join(this.root, key);
  }
  get(key) {
    const path = this.path(key);
    let fd;
    try {
      fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      if (!fstatSync(fd).isFile()) throw new Error('non-file document');
      return readFileSync(fd, 'utf8');
    } catch (error) { if (error.code === 'ENOENT') return undefined; throw error; }
    finally { if (fd !== undefined) closeSync(fd); }
  }
  has(key) { return this.get(key) !== undefined; }
  set(key, content) {
    const path = this.path(key);
    const temp = join(dirname(path), `.${basename(path)}.${randomUUID()}.tmp`);
    const fd = openSync(temp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    try { writeFileSync(fd, content, 'utf8'); fsyncSync(fd); }
    finally { closeSync(fd); }
    try { this.path(key); renameSync(temp, path); }
    catch (error) { if (existsSync(temp)) unlinkSync(temp); throw error; }
  }
  delete(key) {
    const path = this.path(key);
    try { unlinkSync(path); return true; }
    catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  }
}
