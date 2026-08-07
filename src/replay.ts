import { writeFileSync } from 'node:fs';
import type * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { readLedger, verifyChain } from './ledger.js';
import { loadEntities, loadPolicy } from './policy.js';
import { Pdp } from './pdp.js';
import type { CedarContext, LedgerEntry } from './types.js';

/**
 * The replay verifier.
 *
 * It performs four independent checks over a ledger:
 *
 *   1. Chain integrity - every entry's hash recomputes, and every prevHash links.
 *   2. Policy pinning  - the policy-set hash recorded on each entry matches the
 *                        hash of the policy files on disk for that version.
 *   3. Re-decision     - each recorded request is put to Cedar again under the
 *                        pinned policy, and the decision and determining policy
 *                        ids must match what was recorded.
 *   4. Mediation       - no entry may show a tool result without an allow, and
 *                        no request id may appear twice.
 *
 * Check 3 is the one that carries weight. Checks 1 and 2 are self-referential in
 * the sense that matters: a hash chain proves the file has not been edited since
 * it was written, not that it describes what happened. Check 3 discards the
 * recorded verdict entirely and re-derives it from the request plus the policy
 * files, which the verifier holds independently of the log.
 *
 * The honest boundary: this re-derivation runs the SAME Cedar engine that made
 * the original decision. It therefore cannot detect a fault in Cedar itself -
 * agreement here is agreement between a thing and a rerun of that thing, which
 * establishes reproducibility, not correctness. See docs/LIMITATIONS.md, L6.
 */

interface Finding {
  seq: number;
  check: string;
  detail: string;
}

function overlaysOf(entry: LedgerEntry): string[] {
  return [
    ...new Set(
      entry.policyVersion.sourceFiles
        .filter((f) => f.includes('/'))
        .map((f) => f.slice(0, f.indexOf('/'))),
    ),
  ];
}

function main(): void {
  const path = process.argv[2] ?? 'evidence/ledger.jsonl';
  const entries = readLedger(path);
  const findings: Finding[] = [];

  if (entries.length === 0) {
    console.error(`no ledger at ${path} - run \`npm run demo\` first`);
    process.exitCode = 1;
    return;
  }

  // 1. chain integrity
  const chain = verifyChain(entries);
  for (const f of chain.failures) findings.push({ seq: f.seq, check: 'chain-integrity', detail: f.problem });

  // cache one PDP per (versionId + overlays) so we do not reload per entry
  const pdps = new Map<string, { pdp: Pdp; sha: string }>();
  const entities = loadEntities();

  let reDecided = 0;
  const seenRequestIds = new Set<string>();

  for (const e of entries) {
    // 2. policy pinning
    const key = `${e.policyVersion.id}|${overlaysOf(e).join(',')}`;
    if (!pdps.has(key)) {
      const policy = loadPolicy(e.policyVersion.id, overlaysOf(e));
      pdps.set(key, { pdp: new Pdp(policy, entities), sha: policy.version.sha256 });
    }
    const { pdp, sha } = pdps.get(key)!;
    if (sha !== e.policyVersion.sha256) {
      findings.push({
        seq: e.seq,
        check: 'policy-pinning',
        detail: `recorded policy hash ${e.policyVersion.sha256.slice(0, 16)} but policy files on disk hash to ${sha.slice(0, 16)}`,
      });
      continue;
    }
    if (entities.sha256 !== e.entitiesSha256) {
      findings.push({
        seq: e.seq,
        check: 'entity-pinning',
        detail: `recorded entity-store hash ${e.entitiesSha256.slice(0, 16)} but the store on disk hashes to ${entities.sha256.slice(0, 16)}`,
      });
      continue;
    }

    // 4a. mediation: an execution requires an allow
    if (e.toolResult !== null && e.decision.decision !== 'allow') {
      findings.push({
        seq: e.seq,
        check: 'mediation',
        detail: `entry records a tool result but the decision was ${e.decision.decision}`,
      });
    }
    // 4b. single-use: one decision, one request id
    if (seenRequestIds.has(e.requestId)) {
      findings.push({ seq: e.seq, check: 'mediation', detail: `duplicate request id ${e.requestId}` });
    }
    seenRequestIds.add(e.requestId);

    // requests the host refused before Cedar saw them have nothing to re-decide
    if (e.decision.denialKind === 'unresolvable-resource') continue;

    // 3. re-decision
    const fresh = pdp.decide({
      requestId: e.requestId,
      principal: e.cedarRequest.principal,
      action: e.cedarRequest.action,
      resource: e.cedarRequest.resource,
      context: e.cedarRequest.context as CedarContext,
      extraEntities: e.extraEntities as cedar.EntityJson[] | undefined,
    });
    reDecided += 1;

    if (fresh.decision !== e.decision.decision) {
      findings.push({
        seq: e.seq,
        check: 're-decision',
        detail: `recorded ${e.decision.decision}, re-decided ${fresh.decision}`,
      });
    }
    const a = [...fresh.determiningPolicies].sort().join(',');
    const b = [...e.decision.determiningPolicies].sort().join(',');
    if (a !== b) {
      findings.push({
        seq: e.seq,
        check: 're-decision',
        detail: `recorded determining policies [${b}], re-decided [${a}]`,
      });
    }
    if (fresh.denialKind !== e.decision.denialKind) {
      findings.push({
        seq: e.seq,
        check: 're-decision',
        detail: `recorded denialKind ${e.decision.denialKind}, re-decided ${fresh.denialKind}`,
      });
    }
  }

  const executions = entries.filter((e) => e.toolResult !== null).length;
  // Delegation allows mint a session rather than invoke a tool, so they are not
  // expected to carry a tool result.
  const allows = entries.filter(
    (e) => e.decision.decision === 'allow' && e.cedarRequest.action.id !== 'delegate',
  ).length;
  if (executions !== allows) {
    findings.push({
      seq: -1,
      check: 'mediation',
      detail: `${executions} executions against ${allows} tool-action allow decisions`,
    });
  }

  const result = {
    ledger: path,
    entries: entries.length,
    chainIntact: chain.ok,
    reDecided,
    executions,
    allowDecisions: allows,
    findings,
    verdict: findings.length === 0 ? 'VERIFIED' : 'FAILED',
    scope:
      'Re-derivation uses the same Cedar engine that produced the original decisions. ' +
      'A match establishes that the ledger is a faithful, reproducible record of what the ' +
      'engine decided - not that the engine is correct, and not that the recorded events occurred.',
  };

  writeFileSync('evidence/replay-report.json', JSON.stringify(result, null, 2));

  console.log(`replay ${path}`);
  console.log(`  entries            ${entries.length}`);
  console.log(`  chain integrity    ${chain.ok ? 'intact' : 'BROKEN'}`);
  console.log(`  re-decided         ${reDecided} requests against their pinned policy version`);
  console.log(`  mediation          ${executions} executions / ${allows} tool-action allow decisions`);
  if (findings.length) {
    console.log(`  findings           ${findings.length}`);
    for (const f of findings) console.log(`    #${f.seq} [${f.check}] ${f.detail}`);
    process.exitCode = 1;
  } else {
    console.log('  verdict            VERIFIED');
    console.log(`  scope              ${result.scope}`);
  }
}

main();
