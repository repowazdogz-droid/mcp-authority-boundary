import { closeSync, mkdirSync, openSync, appendFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import type { ResolvedOperation } from './types.js';

/**
 * TRANSITION TRACE EMITTER for formal/Conformance.lean.
 *
 * OFF unless the process environment has MAB_TRACE=1. When off, every function
 * here returns immediately and nothing is written, so the enforcement path is
 * behaviourally identical to the untraced build. When on, each real transition
 * of the grant state machine is appended as one JSON line to a per-process file
 * in MAB_TRACE_DIR (default evidence/traces/), carrying exactly the fields the
 * Lean transitions take:
 *
 *   authorize  operation view (digest, resource, byteLen), the request Cedar saw
 *              (resource, byteLen), the decision, and the grant id if minted
 *   execute    grant id and the digest of the operation actually executed
 *   refuse     a consumeGrant refusal, with its reason code
 *   observe    digests of the authorized and the observed effect fingerprint
 *   delegate   a delegation decision (no operation; outside the Lean model)
 *
 * The file is one trace: the Lean model's State is per process, because the
 * spent-set and mint counter in mediation.ts are module-global.
 *
 * This is a trace, not a proof. Conformance of a trace to the model says the
 * transitions THIS RUN took are transitions the model permits; it says nothing
 * about runs not taken and is not a refinement of src/ by formal/Boundary.lean.
 */
export const TRACE_ENABLED = process.env['MAB_TRACE'] === '1';

export interface OpView { digest: string; resource: string; byteLen: number }
export interface RequestView { resource: string; byteLen: number }

export type RefusalCode =
  | 'not-issued'
  | 'no-mediation'
  | 'mediation-binding'
  | 'mediation-hash'
  | 'mediation-linkage'
  | 'mediation-deny'
  | 'grant-binding'
  | 'spent';

export type TraceEvent =
  | {
      kind: 'authorize';
      requestId: string;
      decision: 'allow' | 'deny';
      denialKind: string | null;
      grantId: number | null;
      op: OpView;
      request: RequestView;
    }
  | { kind: 'delegate'; requestId: string; decision: 'allow' | 'deny' }
  | { kind: 'execute'; requestId: string; grantId: number; executedOpDigest: string }
  | {
      kind: 'refuse';
      requestId: string | null;
      grantId: number | null;
      executedOpDigest: string | null;
      reason: RefusalCode;
    }
  | {
      kind: 'observe';
      requestId: string;
      executedOpDigest: string;
      authorizedEffect: string;
      observedEffect: string;
      match: boolean;
    };

/**
 * The operation as the model sees it. Computed from the operation's own fields,
 * deliberately NOT via cedarRequestFromOperation, so that the request-side view
 * (what Cedar was handed) and this view reach Lean by different code.
 */
export function opView(op: ResolvedOperation, digest: string): OpView {
  const resource =
    op.tool === 'send_email' ? op.to
    : op.tool === 'execute_shell' ? op.host
    : op.tool === 'query_database' ? op.table
    : op.path;
  const byteLen = 'byteLen' in op ? op.byteLen : 0;
  return { digest, resource, byteLen };
}

let file: string | null = null;
let seq = 0;

function traceFile(): string {
  if (file !== null) return file;
  const dir = resolve(process.env['MAB_TRACE_DIR'] ?? 'evidence/traces');
  mkdirSync(dir, { recursive: true });
  const base = basename(process.argv[1] ?? 'node').replace(/\.(m?js|ts)$/, '');
  // One file per process. Deterministic name when the process is the only one
  // running that script; a pid suffix when it is not (the hardening file-worker).
  const plain = `${dir}/${base}.jsonl`;
  try {
    closeSync(openSync(plain, 'wx', 0o600));
    file = plain;
  } catch {
    file = `${dir}/${base}-${process.pid}.jsonl`;
    closeSync(openSync(file, 'wx', 0o600));
  }
  appendFileSync(
    file,
    JSON.stringify({ kind: 'header', argv: process.argv.slice(1), pid: process.pid, cwd: process.cwd(),
      startedAt: new Date().toISOString() }) + '\n',
  );
  return file;
}

export function traceEvent(e: TraceEvent): void {
  if (!TRACE_ENABLED) return;
  appendFileSync(traceFile(), JSON.stringify({ seq: seq++, ...e }) + '\n');
}
