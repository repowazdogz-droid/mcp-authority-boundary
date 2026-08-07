import { posix } from 'node:path';
import type { EntityStore } from './policy.js';
import { uidKey } from './policy.js';
import type { CedarContext, EntityUid, ModelToolCall, ResolvedCall, ToolName } from './types.js';

/**
 * The correspondence layer.
 *
 * Cedar can only be as correct as the request it is handed. This module turns a
 * tool call the model emitted into the (principal, action, resource, context)
 * that the tool would ACTUALLY have effect on. Two rules govern it:
 *
 *   1. Nothing about authority is read from model output. Identity-shaped keys
 *      are stripped and recorded, never honoured.
 *   2. Resource identity is resolved from the effect, not from the label. A path
 *      is canonicalised before lookup, so `../hr/salaries.csv` is authorised as
 *      the HR document it would actually open, not as the public-looking string
 *      the model wrote.
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
 * Canonicalise a document path into the virtual document root.
 * Returns null when the path escapes the root or is not relative.
 */
export function canonicalisePath(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  if (raw.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(raw)) return null;
  const normalised = posix.normalize(raw.replace(/\\/g, '/'));
  if (normalised.startsWith('..') || normalised === '.') return null;
  return normalised.replace(/^\.\//, '');
}

/**
 * Extract the single table a query reads. Deliberately strict: anything this
 * cannot resolve to exactly one known table is refused rather than allowed
 * through on a partial match. See docs/LIMITATIONS.md, L3 - a regex is not a SQL
 * parser, and the honest consequence is false denials, not false allows.
 */
export function resolveTable(sql: unknown): string | null {
  if (typeof sql !== 'string') return null;
  const froms = [...sql.matchAll(/\bfrom\s+([a-zA-Z_][\w.]*)/gi)].map((m) => m[1]!);
  const joins = [...sql.matchAll(/\bjoin\s+([a-zA-Z_][\w.]*)/gi)].map((m) => m[1]!);
  const all = [...new Set([...froms, ...joins])];
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

  if (!isToolName(raw.tool)) {
    return { ok: false, reason: `unknown tool "${raw.tool}"`, ignoredModelFields: ignored, tool: null };
  }
  const tool = raw.tool;
  const action: EntityUid = { type: 'Mcp::Action', id: TOOL_ACTION[tool] };

  let resource: EntityUid;
  let byteLen = 0;
  let recipientDomain = '';

  switch (tool) {
    case 'read_document':
    case 'delete_file': {
      const path = canonicalisePath(clean['path']);
      if (path === null) {
        return { ok: false, reason: `path "${String(clean['path'])}" is not a valid document path inside the document root`, ignoredModelFields: ignored, tool };
      }
      resource = { type: 'Mcp::Document', id: path };
      break;
    }
    case 'write_document': {
      const path = canonicalisePath(clean['path']);
      if (path === null) {
        return { ok: false, reason: `path "${String(clean['path'])}" is not a valid document path inside the document root`, ignoredModelFields: ignored, tool };
      }
      const content = typeof clean['content'] === 'string' ? clean['content'] : '';
      resource = { type: 'Mcp::Document', id: path };
      // The size Cedar sees is the size of the payload that would actually be
      // written, measured here. A `length` field in the model's arguments, if
      // one were present, would be a label and is not consulted.
      byteLen = Buffer.byteLength(content, 'utf8');
      break;
    }
    case 'send_email': {
      const to = clean['to'];
      if (typeof to !== 'string' || !to.includes('@')) {
        return { ok: false, reason: `recipient "${String(to)}" is not an address`, ignoredModelFields: ignored, tool };
      }
      resource = { type: 'Mcp::Mailbox', id: to.trim().toLowerCase() };
      recipientDomain = resource.id.split('@')[1] ?? '';
      byteLen = Buffer.byteLength(String(clean['body'] ?? ''), 'utf8');
      break;
    }
    case 'execute_shell': {
      const host = clean['host'];
      if (typeof host !== 'string' || host.length === 0) {
        return { ok: false, reason: 'no host named for shell execution', ignoredModelFields: ignored, tool };
      }
      resource = { type: 'Mcp::Host', id: host };
      break;
    }
    case 'query_database': {
      const table = resolveTable(clean['sql']);
      if (table === null) {
        return { ok: false, reason: `could not resolve exactly one table from the query; refusing rather than authorising against a guessed resource`, ignoredModelFields: ignored, tool };
      }
      resource = { type: 'Mcp::Table', id: table };
      break;
    }
  }

  // A resource the store does not know about is refused. Cedar would also deny
  // this (an unknown entity produces an evaluation error, which this artifact
  // maps to deny), but refusing here gives an accurate explanation instead of a
  // confusing engine error.
  if (!env.entities.byUid.has(uidKey(resource.type, resource.id))) {
    return {
      ok: false,
      reason: `${resource.type}::"${resource.id}" is not a known resource`,
      ignoredModelFields: ignored,
      tool,
    };
  }

  const context: CedarContext = {
    now: env.now,
    sourceTrust: env.sourceTrust,
    byteLen,
    recipientDomain,
    requestId: env.requestId,
  };

  return {
    ok: true,
    call: { requestId: env.requestId, tool, action, resource, args: clean, context, ignoredModelFields: ignored },
  };
}
