#!/usr/bin/env node
import { permitAllMediator } from './mediation.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { EnforcementPoint } from './enforce.js';
import { Ledger } from './ledger.js';
import { loadEntities, loadPolicy } from './policy.js';
import { TOOL_SPECS } from './tools.js';
import type { EntityUid } from './types.js';

/**
 * The MCP server, with authorization in front of tool dispatch.
 *
 * The gate lives here, in the server process, rather than in the client. That is
 * a deliberate departure from the obvious layering and the reason is in
 * docs/ARCHITECTURE.md: a check the calling process performs on itself is a
 * check the calling process can decline to perform. Since the agent chooses
 * which client code to run, a client-side gate governs only the clients that
 * agreed to be governed. Putting it behind the transport means every caller
 * traverses it, including one written specifically to avoid it - which is what
 * scenario 12 does.
 *
 * The session identity comes from the environment at spawn time, not from the
 * protocol and not from any tool argument. Real deployments would bind it during
 * an authenticated handshake; that is assumption A2 in docs/ASSUMPTIONS.md.
 */
/**
 * Session identity is REQUIRED and has no default.
 *
 * This used to read `process.env['MCP_SESSION_ID'] ?? 'sess-alice-root'`. That
 * default was a fail-open: `sess-alice-root` is the highest-authority session in
 * the entity store, so a launcher that omitted one environment variable got
 * admin rather than an error. An unknown session id already fails closed - Cedar
 * cannot evaluate the policies and the fail-closed mapping denies - so absence
 * was the single input routed to maximum privilege instead of to refusal.
 *
 * Refusing here does NOT authenticate the binding. Whoever spawns this process
 * still chooses the value, which is assumption A2 in docs/ASSUMPTIONS.md and is
 * unchanged. It removes one specific hazard: a missing identity silently
 * becoming the most privileged one.
 *
 * Exit code 2 is distinct from Node's generic 1 so a supervisor can tell
 * "misconfigured" from "crashed" without parsing the message.
 */
const rawSessionId = process.env['MCP_SESSION_ID'];
if (rawSessionId === undefined || rawSessionId.trim() === '') {
  process.stderr.write(
    'mcp-authority-boundary: refusing to start: MCP_SESSION_ID is required and must be ' +
      'non-empty. There is no default session; a missing identity is a configuration ' +
      'error, not an invitation to assume one.\n',
  );
  process.exit(2);
}
// Deliberately NOT trimmed. `" sess-alice-root "` is not silently normalised
// onto the admin session; it is an unknown id and takes the existing fail-closed
// path through Cedar. Only wholly-absent and wholly-blank are special-cased.
const sessionId = rawSessionId;
const session: EntityUid = { type: 'Mcp::Session', id: sessionId };
const clockBase = Number(process.env['MCP_CLOCK'] ?? '2000');
// Advance the logical clock by this much per decision. 0 keeps the demo
// byte-reproducible; a non-zero step lets a single running server cross an
// expiry boundary, which is what audit finding A3 showed was impossible before.
const clockStep = Number(process.env['MCP_CLOCK_STEP'] ?? '0');
let tick = 0;
const now = () => clockBase + clockStep * tick++;
const ledgerPath = process.env['MCP_LEDGER'] ?? 'evidence/ledger.jsonl';
const overlays = (process.env['MCP_POLICY_OVERLAYS'] ?? '').split(',').filter(Boolean);
const versionId = process.env['MCP_POLICY_VERSION'] ?? (overlays.length ? 'v2' : 'v1');
const wallClock = process.env['MCP_WALLCLOCK'] ?? '2026-08-07T00:00:00.000Z';

const policy = loadPolicy(versionId, overlays);
// Re-read per decision so revocation on disk reaches a running process (A4).
const entities = () => loadEntities();
const ledger = new Ledger(ledgerPath);
const pep = new EnforcementPoint({
  policy,
  entities,
  ledger,
  session,
  now,
  wallClock,
  mediator: permitAllMediator(),
});

const server = new Server(
  { name: 'mcp-authority-boundary', version: '1.0.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOL_SPECS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { entry, result } = pep.handle({
    tool: request.params.name,
    args: (request.params.arguments ?? {}) as Record<string, unknown>,
  });

  const envelope = {
    decision: entry.decision.decision,
    denialKind: entry.decision.denialKind,
    determiningPolicies: entry.decision.determiningPolicies,
    explanation: entry.decision.explanation,
    ignoredModelFields: entry.ignoredModelFields,
    policyVersion: entry.policyVersion.id,
    policySha256: entry.policyVersion.sha256.slice(0, 16),
    ledgerSeq: entry.seq,
    ledgerHash: entry.hash.slice(0, 16),
    toolResult: result ? result.summary : null,
    content: result ? result.content : null,
  };

  return {
    content: [{ type: 'text', text: JSON.stringify(envelope, null, 2) }],
    isError: entry.decision.decision === 'deny',
  };
});

await server.connect(new StdioServerTransport());
