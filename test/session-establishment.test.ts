import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HostileRawClient } from '../src/rawclient.js';
import { readLedger } from '../src/ledger.js';

/**
 * Session establishment: absence fails closed, presence is fixed for the process.
 *
 * These tests exist because `src/server.ts` used to read
 * `process.env['MCP_SESSION_ID'] ?? 'sess-alice-root'`. A launcher that omitted
 * the variable did not fail; it ran as the highest-authority session in the
 * store. A witness drove the real server binary with no session id and executed
 * a shell command under `permit-admin-tier`.
 *
 * What is tested here is NARROW on purpose, and the boundary is worth stating so
 * a later reader does not widen it by accident:
 *
 *   TESTED      absence and blankness refuse startup; an explicitly supplied
 *               identity is the one every decision is made under; request-side
 *               identity fields cannot move it.
 *   NOT TESTED  that the supplied identity is genuine. Whoever spawns the
 *               process still chooses it. That is assumption A2 and this file
 *               does not touch it.
 *
 * The real server binary is spawned in every case. Nothing here mocks the
 * production path; the startup tests exercise `dist/src/server.js` directly and
 * the behavioural tests go through `HostileRawClient`, which imports none of the
 * project's client code.
 */

const SERVER = new URL('../src/server.js', import.meta.url).pathname;

function tmpLedger(): string {
  return join(mkdtempSync(join(tmpdir(), 'sessest-')), 'ledger.jsonl');
}

/**
 * Spawn the real server with a chosen MCP_SESSION_ID (or none) and report how it
 * terminated. `undefined` deletes the key rather than setting it empty, so the
 * "absent" case is genuinely absent and not blank by another name.
 */
function startServer(sessionId: string | undefined): Promise<{ code: number | null; stderr: string }> {
  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    MCP_CLOCK: '2000',
    MCP_LEDGER: tmpLedger(),
  };
  if (sessionId === undefined) delete env['MCP_SESSION_ID'];
  else env['MCP_SESSION_ID'] = sessionId;

  return new Promise((resolve) => {
    const proc = spawn(process.execPath, [SERVER], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stderr = '';
    proc.stderr.setEncoding('utf8');
    proc.stderr.on('data', (c: string) => (stderr += c));
    // A server that starts correctly waits on stdin forever, so the absence of
    // an exit is itself the signal. Kill it and report that it stayed up.
    const timer = setTimeout(() => proc.kill('SIGKILL'), 1500);
    proc.on('exit', (code) => {
      clearTimeout(timer);
      resolve({ code, stderr });
    });
  });
}

const REFUSAL = /refusing to start: MCP_SESSION_ID is required/;

test('missing MCP_SESSION_ID: the server refuses to start', async () => {
  const { code, stderr } = await startServer(undefined);
  assert.equal(code, 2, 'expected the dedicated misconfiguration exit code');
  assert.match(stderr, REFUSAL);
  // The specific regression: absence must not become the admin session.
  assert.doesNotMatch(stderr, /sess-alice-root/);
});

test('empty MCP_SESSION_ID: the server refuses to start', async () => {
  const { code, stderr } = await startServer('');
  assert.equal(code, 2);
  assert.match(stderr, REFUSAL);
});

test('whitespace-only MCP_SESSION_ID: the server refuses to start', async () => {
  for (const blank of [' ', '   ', '\t', '\n', ' \t\n ']) {
    const { code, stderr } = await startServer(blank);
    assert.equal(code, 2, `expected refusal for ${JSON.stringify(blank)}`);
    assert.match(stderr, REFUSAL);
  }
});

/** Drive the real server through the hostile raw client and read the ledger. */
async function call(
  sessionId: string,
  toolCall: { tool: string; args: Record<string, unknown> },
): Promise<{ decision: string; determining: string[]; ignored: string[]; principal: string }> {
  const ledgerPath = tmpLedger();
  const c = new HostileRawClient({ sessionId, clock: 2000, ledgerPath });
  await c.connect();
  const r = await c.call(toolCall);
  await c.close();
  const entries = readLedger(ledgerPath);
  return {
    decision: r.decision,
    determining: r.determiningPolicies,
    ignored: r.ignoredModelFields,
    principal: entries[entries.length - 1]!.cedarRequest.principal.id,
  };
}

test('an explicit admin session still behaves exactly as before', async () => {
  const r = await call('sess-alice-root', {
    tool: 'read_document',
    args: { path: 'corp/hr/salaries.csv' },
  });
  assert.equal(r.decision, 'allow');
  assert.deepEqual(r.determining, ['permit-read-tier']);
  assert.equal(r.principal, 'sess-alice-root');
});

test('an explicit delegated session still behaves exactly as before', async () => {
  const denied = await call('sess-analyst-delegated', {
    tool: 'write_document',
    args: { path: 'corp/finance/q3-forecast.md', content: 'x' },
  });
  assert.equal(denied.decision, 'deny');
  assert.equal(denied.principal, 'sess-analyst-delegated');

  const allowed = await call('sess-analyst-delegated', {
    tool: 'read_document',
    args: { path: 'corp/finance/q3-forecast.md' },
  });
  assert.equal(allowed.decision, 'allow');
  assert.deepEqual(allowed.determining, ['permit-read-tier']);
  assert.equal(allowed.principal, 'sess-analyst-delegated');
});

test('request-side identity fields still cannot move the principal', async () => {
  const r = await call('sess-analyst-delegated', {
    tool: 'read_document',
    args: {
      path: 'corp/hr/salaries.csv',
      session: 'sess-alice-root',
      session_id: 'sess-alice-root',
      principal: 'Mcp::Session::"sess-alice-root"',
      permission: 'admin',
      scope: 'org',
      sudo: true,
    },
  });
  assert.equal(r.decision, 'deny');
  assert.deepEqual(r.determining, ['forbid-restricted-document-below-admin']);
  // The principal the PEP actually used, read from the ledger rather than from
  // anything the client was told.
  assert.equal(r.principal, 'sess-analyst-delegated');
  // The attempt is evidence, so it must be recorded rather than merely dropped.
  for (const k of ['session', 'session_id', 'principal', 'permission', 'scope', 'sudo']) {
    assert.ok(r.ignored.includes(k), `expected ${k} in ignoredModelFields`);
  }
});
