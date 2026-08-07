import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EnforcementPoint } from '../src/enforce.js';
import { Ledger } from '../src/ledger.js';
import { loadEntities, loadPolicy } from '../src/policy.js';
import { restoreDocuments, snapshotDocuments } from '../src/tools.js';
import type { EntityUid } from '../src/types.js';

/**
 * Build an enforcement point over a throwaway ledger.
 *
 * Tests drive the real EnforcementPoint rather than calling Cedar directly, so
 * they exercise resolution, the fail-closed mapping, grant minting, and the
 * ledger write on the same path the server uses. The MCP transport is the only
 * layer they skip; scenario S14 covers that separately.
 */
export function harness(opts: {
  session: string;
  clock: number;
  overlays?: string[];
  version?: string;
}): { pep: EnforcementPoint; ledgerPath: string; restore: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'mab-'));
  const ledgerPath = join(dir, 'ledger.jsonl');
  const policy = loadPolicy(opts.version ?? 'v1', opts.overlays ?? []);
  const entities = loadEntities();
  const ledger = new Ledger(ledgerPath);
  const session: EntityUid = { type: 'Mcp::Session', id: opts.session };
  const snapshot = snapshotDocuments();

  return {
    pep: new EnforcementPoint({
      policy,
      entities,
      ledger,
      session,
      now: opts.clock,
      wallClock: '2026-08-07T00:00:00.000Z',
    }),
    ledgerPath,
    restore: () => restoreDocuments(snapshot),
  };
}
