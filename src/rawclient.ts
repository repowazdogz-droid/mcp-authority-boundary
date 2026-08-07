import { spawn, type ChildProcess } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';
import type { CallEnvelope, SessionEnv } from './client.js';
import type { ModelToolCall } from './types.js';

/**
 * A hostile client.
 *
 * This deliberately imports nothing from client.ts. It spawns the same server
 * binary and speaks newline-delimited JSON-RPC at it directly, which is what an
 * attacker who has the transport but not our source would do. If the
 * authorization gate lived in the client, this file would walk straight past it.
 *
 * It exists to make the architectural claim falsifiable rather than assumed:
 * scenario S14 runs a denied call through this path and the decision must match
 * the one the cooperative client gets.
 */
export class HostileRawClient {
  private proc: (ChildProcess & { stdin: Writable; stdout: Readable }) | null = null;
  private buffer = '';
  private pending = new Map<number, (msg: Record<string, unknown>) => void>();
  private nextId = 1;

  constructor(private readonly env: SessionEnv) {}

  async connect(): Promise<void> {
    this.proc = spawn(process.execPath, [new URL('./server.js', import.meta.url).pathname], {
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
      stdio: ['pipe', 'pipe', 'inherit'],
    }) as ChildProcess & { stdin: Writable; stdout: Readable };

    this.proc.stdout.setEncoding('utf8');
    this.proc.stdout.on('data', (chunk: string) => this.onData(chunk));

    await this.request('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'hostile-raw-client', version: '0' },
    });
    this.notify('notifications/initialized');
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    let nl: number;
    while ((nl = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, nl).trim();
      this.buffer = this.buffer.slice(nl + 1);
      if (!line) continue;
      const msg = JSON.parse(line) as Record<string, unknown>;
      const id = msg['id'];
      if (typeof id === 'number') {
        this.pending.get(id)?.(msg);
        this.pending.delete(id);
      }
    }
  }

  private send(payload: Record<string, unknown>): void {
    this.proc!.stdin.write(JSON.stringify(payload) + '\n');
  }

  private notify(method: string, params: unknown = {}): void {
    this.send({ jsonrpc: '2.0', method, params });
  }

  private request(method: string, params: unknown): Promise<Record<string, unknown>> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`raw client timeout on ${method}`)), 15_000);
      this.pending.set(id, (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      this.send({ jsonrpc: '2.0', id, method, params });
    });
  }

  async call(toolCall: ModelToolCall): Promise<CallEnvelope> {
    const msg = await this.request('tools/call', {
      name: toolCall.tool,
      arguments: toolCall.args,
    });
    const result = msg['result'] as { content?: Array<{ text?: string }> } | undefined;
    return JSON.parse(result?.content?.[0]?.text ?? '{}') as CallEnvelope;
  }

  async close(): Promise<void> {
    this.proc?.stdin.end();
    this.proc?.kill();
    this.proc = null;
  }
}
