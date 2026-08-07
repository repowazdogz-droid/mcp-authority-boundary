import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonicalJson, sha256 } from './canonical.js';
import type { LedgerEntry } from './types.js';

export const GENESIS = '0'.repeat(64);

/**
 * Append-only hash-chained decision log.
 *
 * What the chain gives you: any edit to a past entry, or any deletion from the
 * middle, changes that entry's hash and breaks every link after it, so
 * after-the-fact tampering is detectable by anyone holding the file.
 *
 * What it does not give you, and this artifact does not claim: evidence that the
 * log faithfully records what happened. Anything able to run code inside the
 * server process can write a perfectly consistent chain describing events that
 * never occurred. The chain proves internal consistency; it does not witness
 * itself. The check that carries real weight is in replay.ts, which re-decides
 * every entry with the Cedar engine against the pinned policy version instead of
 * trusting the recorded verdict. See docs/LIMITATIONS.md, L6.
 */
export function entryHash(entry: Omit<LedgerEntry, 'hash'>): string {
  return sha256(canonicalJson(entry));
}

export class Ledger {
  private prevHash = GENESIS;
  private seq = 0;

  constructor(private readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
      const last = lines.at(-1);
      if (last) {
        const e = JSON.parse(last) as LedgerEntry;
        this.prevHash = e.hash;
        this.seq = e.seq + 1;
      }
    }
  }

  /**
   * The sequence number the next append will take. Used to derive request ids
   * that are unique across the whole ledger rather than only within one server
   * process - see the note in EnforcementPoint.
   */
  nextSeq(): number {
    return this.seq;
  }

  append(entry: Omit<LedgerEntry, 'seq' | 'prevHash' | 'hash'>): LedgerEntry {
    const withChain = { ...entry, seq: this.seq, prevHash: this.prevHash };
    const hash = entryHash(withChain);
    const full: LedgerEntry = { ...withChain, hash };
    appendFileSync(this.path, JSON.stringify(full) + '\n', 'utf8');
    this.prevHash = hash;
    this.seq += 1;
    return full;
  }
}

export function readLedger(path: string): LedgerEntry[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as LedgerEntry);
}

export interface ChainCheck {
  ok: boolean;
  entries: number;
  failures: Array<{ seq: number; problem: string }>;
}

export function verifyChain(entries: LedgerEntry[]): ChainCheck {
  const failures: ChainCheck['failures'] = [];
  let prev = GENESIS;
  entries.forEach((e, i) => {
    if (e.seq !== i) failures.push({ seq: e.seq, problem: `sequence gap: expected ${i}` });
    if (e.prevHash !== prev) {
      failures.push({
        seq: e.seq,
        problem: `prevHash ${e.prevHash.slice(0, 12)} does not match the previous entry's recomputed hash ${prev.slice(0, 12)}`,
      });
    }
    const { hash, ...rest } = e;
    const recomputed = entryHash(rest);
    if (recomputed !== hash) {
      failures.push({
        seq: e.seq,
        problem: `hash mismatch: recorded ${hash.slice(0, 12)}, recomputed ${recomputed.slice(0, 12)}`,
      });
    }
    // Link on the RECOMPUTED hash, not the recorded one. Chaining on the
    // recorded field would let an edit to an entry's content fail only that
    // entry's own hash check while every subsequent link still lined up, so a
    // tampered entry would not cascade. Recomputing makes the break propagate,
    // which is the property the chain is supposed to have.
    prev = recomputed;
  });
  return { ok: failures.length === 0, entries: entries.length, failures };
}
