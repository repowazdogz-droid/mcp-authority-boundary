#!/usr/bin/env node
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
 * an authenticated handshake; that is assumption A2 in docs/THREAT_MODEL.md.
 */
const sessionId = process.env['MCP_SESSION_ID'] ?? 'sess-alice-root';
const session: EntityUid = { type: 'Mcp::Session', id: sessionId };
const now = Number(process.env['MCP_CLOCK'] ?? '2000');
const ledgerPath = process.env['MCP_LEDGER'] ?? 'evidence/ledger.jsonl';
const overlays = (process.env['MCP_POLICY_OVERLAYS'] ?? '').split(',').filter(Boolean);
const versionId = process.env['MCP_POLICY_VERSION'] ?? (overlays.length ? 'v2' : 'v1');
const wallClock = process.env['MCP_WALLCLOCK'] ?? '2026-08-07T00:00:00.000Z';

const policy = loadPolicy(versionId, overlays);
const entities = loadEntities();
const ledger = new Ledger(ledgerPath);
const pep = new EnforcementPoint({ policy, entities, ledger, session, now, wallClock });

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
