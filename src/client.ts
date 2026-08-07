import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { ModelToolCall } from './types.js';

export interface SessionEnv {
  sessionId: string;
  clock: number;
  clockStep?: number;
  ledgerPath: string;
  overlays?: string[];
  policyVersion?: string;
  wallClock?: string;
}

export interface CallEnvelope {
  decision: 'allow' | 'deny';
  denialKind: string | null;
  determiningPolicies: string[];
  explanation: string;
  ignoredModelFields: string[];
  policyVersion: string;
  policySha256: string;
  ledgerSeq: number;
  ledgerHash: string;
  toolResult: string | null;
  content: string | null;
}

/**
 * A thin MCP client. It performs no authorization of its own, on purpose.
 *
 * If this file contained a policy check, the demonstration would be weaker
 * rather than stronger: a reviewer could reasonably ask whether the boundary
 * only holds because the client is well behaved. Every guarantee in this
 * artifact is meant to survive the client being replaced by an adversary, so the
 * client is kept deliberately dumb and scenario 12 replaces it with a hostile one.
 */
export class BoundaryClient {
  private client: Client | null = null;
  private transport: StdioClientTransport | null = null;

  constructor(private readonly env: SessionEnv) {}

  async connect(): Promise<void> {
    this.transport = new StdioClientTransport({
      command: process.execPath,
      args: [new URL('./server.js', import.meta.url).pathname],
      env: {
        ...(process.env as Record<string, string>),
        MCP_SESSION_ID: this.env.sessionId,
        MCP_CLOCK: String(this.env.clock),
        MCP_CLOCK_STEP: String(this.env.clockStep ?? 0),
        MCP_LEDGER: this.env.ledgerPath,
        MCP_POLICY_OVERLAYS: (this.env.overlays ?? []).join(','),
        MCP_POLICY_VERSION: this.env.policyVersion ?? (this.env.overlays?.length ? 'v2' : 'v1'),
        MCP_WALLCLOCK: this.env.wallClock ?? '2026-08-07T00:00:00.000Z',
      },
      stderr: 'inherit',
    });
    this.client = new Client({ name: 'boundary-client', version: '1.0.0' }, { capabilities: {} });
    await this.client.connect(this.transport);
  }

  async listTools(): Promise<string[]> {
    const r = await this.client!.listTools();
    return r.tools.map((t) => t.name);
  }

  /** Forward a model-emitted tool call verbatim. No filtering happens here. */
  async call(toolCall: ModelToolCall): Promise<CallEnvelope> {
    const r = await this.client!.callTool({
      name: toolCall.tool,
      arguments: toolCall.args as Record<string, unknown>,
    });
    const content = r.content as Array<{ type: string; text?: string }> | undefined;
    const text = content?.[0]?.text ?? '{}';
    return JSON.parse(text) as CallEnvelope;
  }

  async close(): Promise<void> {
    await this.client?.close();
    this.client = null;
    this.transport = null;
  }
}
