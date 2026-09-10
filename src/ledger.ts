import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonicalJson, sha256 } from './canonical.js';
import type { LedgerEntry } from './types.js';

export const GENESIS = '0'.repeat(64);
export type UnchainedEntry = Omit<LedgerEntry, 'seq' | 'prevHash' | 'hash'>;

/** fsync the file before an effect can begin. Directory durability is OS-dependent. */
function durableWrite(path: string, text: string, flags: 'a' | 'wx'): void {
  const fd = openSync(path, flags, 0o600);
  try { writeFileSync(fd, text, 'utf8'); fsyncSync(fd); }
  finally { closeSync(fd); }
}

export const intentPath = (path: string): string => `${path}.intents.jsonl`;

export function readIntents(path: string): UnchainedEntry[] {
  if (!existsSync(intentPath(path))) return [];
  return readFileSync(intentPath(path), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
}

function intentIdentity(e: UnchainedEntry): string {
  return canonicalJson({ requestId: e.requestId, operation: e.operation,
    operationSha256: e.operationSha256, cedarRequest: e.cedarRequest, decision: e.decision,
    mediation: e.mediation, authorizedEffect: e.authorizedEffect,
    policyVersion: e.policyVersion, entitiesSha256: e.entitiesSha256 });
}

/** Reconcile write-ahead authorizations with completed records in both directions. */
export function verifyIntents(path: string, entries: LedgerEntry[]): string[] {
  const failures: string[] = [];
  const intents = readIntents(path);
  const seen = new Set<string>();
  for (const intent of intents) {
    if (seen.has(intent.requestId)) failures.push(`duplicate intent ${intent.requestId}`);
    seen.add(intent.requestId);
    const matches = entries.filter(e => e.requestId === intent.requestId && e.toolResult !== null);
    if (matches.length !== 1) failures.push(`unresolved execution intent ${intent.requestId}: outcome unknown`);
    else if (intentIdentity(intent) !== intentIdentity(matches[0]!)) {
      failures.push(`execution record differs from prepared authorization ${intent.requestId}`);
    }
  }
  for (const e of entries) {
    if (e.toolResult !== null && !seen.has(e.requestId)) failures.push(`execution without prepared authorization ${e.requestId}`);
  }
  return failures;
}

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
  private locked = false;

  constructor(private readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
    const entries = readLedger(path);
    if (!verifyChain(entries).ok) throw new Error('cannot resume a corrupt ledger');
    this.prevHash = entries.at(-1)?.hash ?? GENESIS;
    this.seq = entries.length;
  }

  /**
   * The sequence number the next append will take. Used to derive request ids
   * that are unique across the whole ledger rather than only within one server
   * process - see the note in EnforcementPoint.
   */
  nextSeq(): number {
    return this.seq;
  }

  /** Serialize the whole prepare/effect/complete interval across host processes.
   * A process killed while holding this lock requires explicit recovery.
   */
  exclusive<T>(action: () => T): T {
    if (this.locked) return action();
    const lock = `${this.path}.lock`;
    const fd = openSync(lock, 'wx', 0o600);
    this.locked = true;
    try { return action(); }
    finally { this.locked = false; closeSync(fd); unlinkSync(lock); }
  }

  assertWritable(): void {
    if (existsSync(sealPath(this.path))) {
      throw new Error(`ledger is sealed: ${this.path}`);
    }
    const entries = readLedger(this.path);
    if (!verifyChain(entries).ok || entries.length !== this.seq ||
        (entries.at(-1)?.hash ?? GENESIS) !== this.prevHash) {
      throw new Error('ledger changed or is corrupt; refusing stale writer');
    }
  }

  assertReady(): void {
    this.assertWritable();
    const failures = verifyIntents(this.path, readLedger(this.path));
    if (failures.length) throw new Error(failures.join('; '));
  }

  prepare(entry: UnchainedEntry): void {
    this.assertReady();
    if (entry.decision.decision !== 'allow' || entry.operation === null) {
      throw new Error('only an authorized tool operation may be prepared');
    }
    durableWrite(intentPath(this.path), JSON.stringify(entry) + '\n', 'a');
  }

  append(entry: UnchainedEntry): LedgerEntry {
    this.assertWritable();
    // Hash the representation that actually reaches disk. Direct test callers
    // may supply boxed strings; JSON.stringify unboxes them before persistence.
    const persisted = JSON.parse(JSON.stringify(entry)) as UnchainedEntry;
    if (persisted.operation !== null) Object.freeze(persisted.operation);
    const withChain = { ...persisted, seq: this.seq, prevHash: this.prevHash };
    const hash = entryHash(withChain);
    const full: LedgerEntry = { ...withChain, hash };
    durableWrite(this.path, JSON.stringify(full) + '\n', 'a');
    this.prevHash = hash;
    this.seq += 1;
    return full;
  }

  /** Commit the expected end of the log so tail truncation is detectable. */
  seal(): LedgerSeal {
    return this.exclusive(() => {
      this.assertReady();
      const seal = { entries: this.seq, finalHash: this.prevHash };
      durableWrite(sealPath(this.path), JSON.stringify(seal) + '\n', 'wx');
      return seal;
    });
  }
}

export interface LedgerSeal {
  entries: number;
  finalHash: string;
}

export function sealPath(path: string): string {
  return `${path}.seal.json`;
}

export function readSeal(path: string, p = sealPath(path)): LedgerSeal | null {
  if (!existsSync(p)) return null;
  const value = JSON.parse(readFileSync(p, 'utf8'));
  if (!value || !Number.isSafeInteger(value.entries) || value.entries < 0 ||
      typeof value.finalHash !== 'string' || !/^[a-f0-9]{64}$/.test(value.finalHash)) {
    throw new Error('malformed ledger seal');
  }
  return value as LedgerSeal;
}

export function verifySeal(path: string, entries: LedgerEntry[], anchorPath?: string): { ok: boolean; problem?: string } {
  let seal: LedgerSeal | null;
  try { seal = readSeal(path, anchorPath); }
  catch (error) { return { ok: false, problem: String(error) }; }
  if (seal === null) return { ok: false, problem: `missing ledger seal ${anchorPath ?? sealPath(path)}` };
  const finalHash = entries.at(-1)?.hash ?? GENESIS;
  if (seal.entries !== entries.length || seal.finalHash !== finalHash) {
    return {
      ok: false,
      problem: `sealed end is ${seal.entries} entries/${seal.finalHash.slice(0, 12)}, file has ${entries.length} entries/${finalHash.slice(0, 12)}`,
    };
  }
  return { ok: true };
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
