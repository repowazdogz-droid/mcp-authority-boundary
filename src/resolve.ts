import { posix } from 'node:path';
import type { EntityStore } from './policy.js';
import { uidKey } from './policy.js';
import { sha256, sha256Canonical } from './canonical.js';
import type {
  CedarContext,
  EntityUid,
  ModelToolCall,
  ResolvedCall,
  ResolvedOperation,
  StatementClass,
  ToolName,
} from './types.js';

/**
 * The correspondence layer.
 *
 * Cedar can only be as correct as the request it is handed, and execution can
 * only be as authorized as the object it consumes. This module produces exactly
 * one such object - a frozen ResolvedOperation - and everything downstream is
 * derived from it: the Cedar request, the grant digest, the expected effect, and
 * the execution itself.
 *
 * Three rules govern it:
 *
 *   1. Nothing about authority is read from model output. Identity-shaped keys
 *      are stripped and recorded, never honoured.
 *   2. Every value is validated to its expected type and REJECTED if it is not.
 *      No coercion. The audit's A1 witness (`content: [<100k chars>]` measured as
 *      zero bytes, then String()-coerced into a 100KB write) died here.
 *   3. Resource identity is resolved from the effect, not from the label.
 *
 * Where resolution is uncertain the answer is refusal, never a guess.
 */

/** Keys the model must never be able to set. Supplying one is itself evidence. */
const IDENTITY_SHAPED_KEYS = new Set([
  'principal', 'session', 'session_id', 'sessionId', 'sessionid',
  'permission', 'permissions', 'scope', 'grant', 'role', 'roles',
  'user', 'as_user', 'on_behalf_of', 'delegator', 'agent',
  'expiresAt', 'notBefore', 'revoked', 'depth', 'delegatedFrom',
  'authorization', 'auth', 'token', 'capability', 'sudo', 'admin',
  'maxWriteBytes', 'policy', 'policies', 'cedar', 'override',
]);

export function stripIdentityFields(args: Record<string, unknown>): {
  clean: Record<string, unknown>;
  ignored: string[];
} {
  const clean: Record<string, unknown> = {};
  const ignored: string[] = [];
  for (const [k, v] of Object.entries(args)) {
    if (IDENTITY_SHAPED_KEYS.has(k) || k.startsWith('_')) ignored.push(k);
    else clean[k] = v;
  }
  return { clean, ignored };
}

/**
 * Accept a string and nothing else.
 *
 * The whole A1 class of bug is coercion, so there is exactly one place where a
 * value becomes a string and it is this function, which refuses rather than
 * converts. Numbers, booleans, arrays, objects, null and undefined are all
 * rejected: a caller that meant to send text can send text.
 */
function asString(v: unknown): string | null {
  return typeof v === 'string' ? v : null;
}

/** Reject control characters outright; they alias, truncate, and confuse logs. */
function hasControlChars(s: string): boolean {
  return /[\u0000-\u001f\u007f]/.test(s);
}

/**
 * Canonicalise a document path into the virtual document root.
 * Returns null when the path escapes the root, is absolute, or is not a string.
 *
 * Unicode is normalised to NFC so that two spellings of the same name cannot
 * address the same entity by different routes.
 */
export function canonicalisePath(raw: unknown): string | null {
  const s = asString(raw);
  if (s === null || s.length === 0) return null;
  if (hasControlChars(s)) return null;
  const nfc = s.normalize('NFC');
  if (nfc.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(nfc)) return null;
  const normalised = posix.normalize(nfc.replace(/\\/g, '/'));
  if (normalised.startsWith('..') || normalised === '.') return null;
  return normalised.replace(/^\.\//, '');
}

/**
 * Classify a SQL statement by its leading keyword.
 *
 * Recorded on the operation so the record shows what class of statement was
 * authorized. NOTE: the policy set does not currently gate on this - see audit
 * finding A6, which this change makes visible but does not close.
 */
export function classifyStatement(sql: string): StatementClass {
  const head = sql.replace(/^[\s(]*(?:\/\*[\s\S]*?\*\/|--[^\n]*\n)*[\s(]*/, '').trimStart();
  if (/^select\b/i.test(head) || /^with\b/i.test(head)) return 'select';
  if (/^(insert|update|delete|drop|alter|truncate|create|replace|merge|grant)\b/i.test(head)) {
    return 'mutating';
  }
  return 'unrecognised';
}

/**
 * Extract the single table a query touches. Deliberately strict: anything this
 * cannot resolve to exactly one known table is refused rather than allowed
 * through on a partial match. See docs/LIMITATIONS.md, L3 - a regex is not a SQL
 * parser, and the honest consequence is false denials, not false allows.
 */
export function resolveTable(sql: unknown): string | null {
  const s = asString(sql);
  if (s === null) return null;
  const froms = [...s.matchAll(/\bfrom\s+([a-zA-Z_][\w.]*)/gi)].map((m) => m[1]!);
  const joins = [...s.matchAll(/\bjoin\s+([a-zA-Z_][\w.]*)/gi)].map((m) => m[1]!);
  const into = [...s.matchAll(/\b(?:into|update)\s+([a-zA-Z_][\w.]*)/gi)].map((m) => m[1]!);
  const all = [...new Set([...froms, ...joins, ...into])];
  return all.length === 1 ? all[0]! : null;
}

const TOOL_ACTION: Record<ToolName, string> = {
  read_document: 'readDocument',
  write_document: 'writeDocument',
  send_email: 'sendEmail',
  execute_shell: 'executeShell',
  query_database: 'queryDatabase',
  delete_file: 'deleteFile',
};

export const TOOL_NAMES = Object.keys(TOOL_ACTION) as ToolName[];

export function isToolName(x: string): x is ToolName {
  return x in TOOL_ACTION;
}

/** Deep-freeze so a resolved operation cannot be edited after authorization. */
function freeze<T>(o: T): T {
  Object.freeze(o);
  return o;
}

/**
 * The Cedar request is DERIVED from the operation, never assembled alongside it.
 *
 * Exported because replay.ts re-runs this same derivation over the recorded
 * operation and compares the result to the recorded request. That is a
 * consistency check over the record, not an independent one - it shares this
 * function with the producer - and replay.ts says so where it reports the stage.
 */
export function cedarRequestFromOperation(
  op: ResolvedOperation,
): { action: EntityUid; resource: EntityUid; byteLen: number; recipientDomain: string } {
  const action: EntityUid = { type: 'Mcp::Action', id: TOOL_ACTION[op.tool] };
  switch (op.tool) {
    case 'read_document':
    case 'delete_file':
      return { action, resource: { type: 'Mcp::Document', id: op.path }, byteLen: 0, recipientDomain: '' };
    case 'write_document':
      return {
        action,
        resource: { type: 'Mcp::Document', id: op.path },
        byteLen: op.byteLen,
        recipientDomain: '',
      };
    case 'send_email':
      return {
        action,
        resource: { type: 'Mcp::Mailbox', id: op.to },
        byteLen: op.byteLen,
        recipientDomain: op.domain,
      };
    case 'execute_shell':
      return { action, resource: { type: 'Mcp::Host', id: op.host }, byteLen: 0, recipientDomain: '' };
    case 'query_database':
      return { action, resource: { type: 'Mcp::Table', id: op.table }, byteLen: 0, recipientDomain: '' };
  }
}

export type ResolveOutcome =
  | { ok: true; call: ResolvedCall }
  | { ok: false; reason: string; ignoredModelFields: string[]; tool: ToolName | null };

export interface ResolveEnv {
  requestId: string;
  now: number;
  sourceTrust: 'user' | 'tool_output';
  entities: EntityStore;
}

export function resolveCall(raw: ModelToolCall, env: ResolveEnv): ResolveOutcome {
  const { clean, ignored } = stripIdentityFields(raw.args ?? {});
  const fail = (reason: string, tool: ToolName | null): ResolveOutcome => ({
    ok: false,
    reason,
    ignoredModelFields: ignored,
    tool,
  });

  if (!isToolName(raw.tool)) return fail(`unknown tool "${raw.tool}"`, null);
  const tool = raw.tool;

  let operation: ResolvedOperation;

  switch (tool) {
    case 'read_document':
    case 'delete_file': {
      const path = canonicalisePath(clean['path']);
      if (path === null) {
        return fail(`path ${JSON.stringify(clean['path'])} is not a valid document path`, tool);
      }
      operation = freeze({ tool, path });
      break;
    }
    case 'write_document': {
      const path = canonicalisePath(clean['path']);
      if (path === null) {
        return fail(`path ${JSON.stringify(clean['path'])} is not a valid document path`, tool);
      }
      // Rejected, not coerced. This is the A1 fix.
      const content = asString(clean['content']);
      if (content === null) {
        return fail(
          `content must be a string; got ${describeType(clean['content'])}. ` +
            `Refusing rather than coercing, because a coerced value would be authorized at one ` +
            `size and written at another`,
          tool,
        );
      }
      operation = freeze({
        tool,
        path,
        content,
        byteLen: Buffer.byteLength(content, 'utf8'),
        contentSha256: sha256(content),
      });
      break;
    }
    case 'send_email': {
      const to = asString(clean['to']);
      if (to === null || hasControlChars(to)) return fail(`recipient must be a string`, tool);
      const canonicalTo = to.trim().toLowerCase().normalize('NFC');
      if (!canonicalTo.includes('@')) return fail(`recipient "${canonicalTo}" is not an address`, tool);
      // `?? ''` would have accepted an explicit null as an absent field and
      // coerced it to the empty string. That is the same reject-vs-coerce
      // mistake as A1, found by the post-repair falsification pass (F1), so
      // absence and wrong-type are distinguished explicitly.
      const body = asString('body' in clean ? clean['body'] : '');
      if (body === null) return fail(`body must be a string; got ${describeType(clean['body'])}`, tool);
      const subject = asString('subject' in clean ? clean['subject'] : '');
      if (subject === null) {
        return fail(`subject must be a string; got ${describeType(clean['subject'])}`, tool);
      }
      operation = freeze({
        tool,
        to: canonicalTo,
        domain: canonicalTo.split('@')[1] ?? '',
        subject,
        body,
        byteLen: Buffer.byteLength(body, 'utf8'),
        bodySha256: sha256(body),
      });
      break;
    }
    case 'execute_shell': {
      const host = asString(clean['host']);
      if (host === null || host.length === 0 || hasControlChars(host)) {
        return fail('host must be a non-empty string', tool);
      }
      const command = asString(clean['command']);
      if (command === null) {
        return fail(`command must be a string; got ${describeType(clean['command'])}`, tool);
      }
      operation = freeze({ tool, host: host.normalize('NFC'), command });
      break;
    }
    case 'query_database': {
      const sql = asString(clean['sql']);
      if (sql === null) return fail(`sql must be a string; got ${describeType(clean['sql'])}`, tool);
      const table = resolveTable(sql);
      if (table === null) {
        return fail(
          'could not resolve exactly one table from the query; refusing rather than ' +
            'authorising against a guessed resource',
          tool,
        );
      }
      operation = freeze({ tool, table, statementClass: classifyStatement(sql), sql });
      break;
    }
  }

  const derived = cedarRequestFromOperation(operation);

  // A resource the store does not know about is refused. Cedar would also deny
  // this, but refusing here gives an accurate explanation instead of an engine error.
  if (!env.entities.byUid.has(uidKey(derived.resource.type, derived.resource.id))) {
    return fail(`${derived.resource.type}::"${derived.resource.id}" is not a known resource`, tool);
  }

  const context: CedarContext = {
    now: env.now,
    sourceTrust: env.sourceTrust,
    byteLen: derived.byteLen,
    recipientDomain: derived.recipientDomain,
    requestId: env.requestId,
  };

  return {
    ok: true,
    call: freeze({
      requestId: env.requestId,
      operation,
      operationSha256: sha256Canonical(operation),
      action: derived.action,
      resource: derived.resource,
      context,
      ignoredModelFields: ignored,
    }),
  };
}

function describeType(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;
}
