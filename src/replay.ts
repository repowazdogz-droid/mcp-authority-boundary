import { writeFileSync } from 'node:fs';
import type * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { readLedger, verifyChain } from './ledger.js';
import { loadEntities, loadPolicy } from './policy.js';
import { Pdp } from './pdp.js';
import { cedarRequestFromOperation } from './resolve.js';
import { expectedEffectOf, effectsMatch } from './tools.js';
import { sha256Canonical } from './canonical.js';
import type { CedarContext, LedgerEntry } from './types.js';

/**
 * The replay verifier, in four separately-reported stages.
 *
 * They are reported separately because they establish different things and
 * share different amounts with the producer. Collapsing them into one VERIFIED
 * was the flaw the adversarial audit exposed: a ledger containing an
 * authorization/execution divergence replayed as VERIFIED, because the only
 * thing being checked was the decision step.
 *
 *   1. CHAIN INTEGRITY   - the file has not been edited or reordered.
 *   2. POLICY REPLAY     - the recorded verdict is discarded and re-derived from
 *                          the recorded request under the pinned policy version.
 *   3. AUTH-EXEC BINDING - the recorded Cedar request is re-derived from the
 *                          recorded canonical operation, and the operation digest
 *                          is recomputed.
 *   4. EFFECT CONSISTENCY- the effect the operation authorizes is recomputed and
 *                          compared to the effect that was observed in the world.
 *
 * Honest labelling of what each stage buys:
 *
 *   Stage 2 shares the Cedar build and the classifier with the producer, so it
 *   establishes reproducibility of the decision, not its correctness.
 *
 *   Stage 3 shares `cedarRequestFromOperation` with the producer. It is a
 *   CONSISTENCY check over the record: it catches a record whose request and
 *   operation disagree, which is what tampering or a runtime divergence would
 *   look like. It does not establish that the derivation itself is right.
 *
 *   Stage 4 is the only stage whose two sides CAN come from different places,
 *   and it does so for two of the six tools. For write_document and delete_file
 *   the observed side was produced at runtime by re-reading the fixture world
 *   after execution, so a tool that wrote elsewhere would be caught. For
 *   read_document, send_email, execute_shell and query_database the observed
 *   side is the tail of a log that executeTool appended FROM the operation, so
 *   the two sides are one object derived twice; that comparison still fires if
 *   the tool records something other than what it was authorized to do, but it
 *   cannot witness a real effect.
 *
 *   READ THE PER-TOOL MIX BEFORE READING THE COUNT. In the shipped ledger the
 *   two read-back tools are never executed - every write_document and
 *   delete_file entry is a denial - so all of stage 4's checks there are the
 *   record-consistency kind, and a green line establishes nothing about
 *   independent observation. See docs/LIMITATIONS.md L7.
 *
 *   The authorized side is recomputed here from the operation. The world
 *   observation cannot be repeated after the fact - the process is gone - so
 *   replay checks the recorded observation against a freshly derived
 *   expectation. The live differential runs inside EnforcementPoint.handle,
 *   which throws on mismatch.
 */

type StageName = 'chain-integrity' | 'policy-replay' | 'auth-exec-binding' | 'effect-consistency';

interface Finding {
  seq: number;
  stage: StageName;
  detail: string;
}

interface StageReport {
  stage: StageName;
  checked: number;
  notApplicable: number;
  failures: number;
  verdict: 'PASS' | 'FAIL' | 'NOT CHECKED';
  establishes: string;
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

  const counts: Record<StageName, { checked: number; na: number; fail: number }> = {
    'chain-integrity': { checked: 0, na: 0, fail: 0 },
    'policy-replay': { checked: 0, na: 0, fail: 0 },
    'auth-exec-binding': { checked: 0, na: 0, fail: 0 },
    'effect-consistency': { checked: 0, na: 0, fail: 0 },
  };
  const fail = (seq: number, stage: StageName, detail: string) => {
    findings.push({ seq, stage, detail });
    counts[stage].fail += 1;
  };

  // ---- stage 1: chain integrity -------------------------------------------
  const chain = verifyChain(entries);
  counts['chain-integrity'].checked = entries.length;
  for (const f of chain.failures) fail(f.seq, 'chain-integrity', f.problem);

  const pdps = new Map<string, { pdp: Pdp; sha: string }>();
  const seenRequestIds = new Set<string>();

  for (const e of entries) {
    // policy pinning is a precondition of stage 2
    const key = `${e.policyVersion.id}|${overlaysOf(e).join(',')}`;
    if (!pdps.has(key)) {
      const policy = loadPolicy(e.policyVersion.id, overlaysOf(e));
      pdps.set(key, { pdp: new Pdp(policy), sha: policy.version.sha256 });
    }
    const { pdp, sha } = pdps.get(key)!;
    const entities = loadEntities();

    if (sha !== e.policyVersion.sha256) {
      fail(
        e.seq,
        'policy-replay',
        `recorded policy hash ${e.policyVersion.sha256.slice(0, 16)} but policy files on disk hash to ${sha.slice(0, 16)}`,
      );
      continue;
    }
    if (entities.sha256 !== e.entitiesSha256) {
      fail(
        e.seq,
        'policy-replay',
        `recorded entity-store hash ${e.entitiesSha256.slice(0, 16)} but the store on disk hashes to ${entities.sha256.slice(0, 16)}`,
      );
      continue;
    }
    if (seenRequestIds.has(e.requestId)) {
      fail(e.seq, 'auth-exec-binding', `duplicate request id ${e.requestId}`);
    }
    seenRequestIds.add(e.requestId);

    // ---- stage 3: authorization <- operation ------------------------------
    if (e.operation === null) {
      counts['auth-exec-binding'].na += 1;
      // a record with no operation must not claim an execution
      if (e.toolResult !== null) {
        fail(e.seq, 'auth-exec-binding', 'entry records a tool result but carries no operation');
      }
    } else {
      counts['auth-exec-binding'].checked += 1;
      const digest = sha256Canonical(e.operation);
      if (digest !== e.operationSha256) {
        fail(
          e.seq,
          'auth-exec-binding',
          `operation digest recomputes to ${digest.slice(0, 12)}, record says ${String(e.operationSha256).slice(0, 12)}`,
        );
      }
      const derived = cedarRequestFromOperation(e.operation);
      const ctx = e.cedarRequest.context as CedarContext;
      if (derived.action.id !== e.cedarRequest.action.id) {
        fail(e.seq, 'auth-exec-binding', `action ${e.cedarRequest.action.id} is not what the operation derives (${derived.action.id})`);
      }
      if (derived.resource.id !== e.cedarRequest.resource.id || derived.resource.type !== e.cedarRequest.resource.type) {
        fail(e.seq, 'auth-exec-binding', `resource ${e.cedarRequest.resource.type}::"${e.cedarRequest.resource.id}" is not what the operation derives`);
      }
      if (derived.byteLen !== ctx.byteLen) {
        fail(e.seq, 'auth-exec-binding', `context byteLen ${ctx.byteLen} is not what the operation derives (${derived.byteLen})`);
      }
      if (derived.recipientDomain !== ctx.recipientDomain) {
        fail(e.seq, 'auth-exec-binding', `context recipientDomain "${ctx.recipientDomain}" is not what the operation derives ("${derived.recipientDomain}")`);
      }
      // execution requires an allow
      if (e.toolResult !== null && e.decision.decision !== 'allow') {
        fail(e.seq, 'auth-exec-binding', `entry records a tool result but the decision was ${e.decision.decision}`);
      }
    }

    // ---- stage 4: effect consistency --------------------------------------
    if (e.decision.decision === 'allow' && e.operation !== null && e.toolResult !== null) {
      counts['effect-consistency'].checked += 1;
      if (e.authorizedEffect === null || e.observedEffect === null) {
        fail(e.seq, 'effect-consistency', 'an executed entry recorded no effect fingerprints');
      } else {
        const recomputed = expectedEffectOf(e.operation);
        if (!effectsMatch(recomputed, e.authorizedEffect)) {
          fail(e.seq, 'effect-consistency', 'the recorded authorized effect is not what the operation derives');
        }
        if (!effectsMatch(recomputed, e.observedEffect)) {
          fail(
            e.seq,
            'effect-consistency',
            `observed effect ${JSON.stringify(e.observedEffect)} does not match the authorized operation`,
          );
        }
      }
    } else {
      counts['effect-consistency'].na += 1;
    }

    // ---- stage 2: policy replay -------------------------------------------
    if (e.decision.denialKind === 'unresolvable-resource') {
      // refused by the host before Cedar saw it; there is nothing to re-decide
      counts['policy-replay'].na += 1;
      continue;
    }
    counts['policy-replay'].checked += 1;
    const fresh = pdp.decide({
      requestId: e.requestId,
      principal: e.cedarRequest.principal,
      action: e.cedarRequest.action,
      resource: e.cedarRequest.resource,
      context: e.cedarRequest.context as CedarContext,
      entities,
      extraEntities: e.extraEntities as cedar.EntityJson[] | undefined,
    });
    if (fresh.decision !== e.decision.decision) {
      fail(e.seq, 'policy-replay', `recorded ${e.decision.decision}, re-decided ${fresh.decision}`);
    }
    const a = [...fresh.determiningPolicies].sort().join(',');
    const b = [...e.decision.determiningPolicies].sort().join(',');
    if (a !== b) {
      fail(e.seq, 'policy-replay', `recorded determining policies [${b}], re-decided [${a}]`);
    }
    if (fresh.denialKind !== e.decision.denialKind) {
      fail(e.seq, 'policy-replay', `recorded denialKind ${e.decision.denialKind}, re-decided ${fresh.denialKind}`);
    }
  }

  const ESTABLISHES: Record<StageName, string> = {
    'chain-integrity': 'the file has not been edited or reordered since it was written',
    'policy-replay':
      'the recorded decision is reproducible from the recorded request (shares the Cedar build and classifier with the producer)',
    'auth-exec-binding':
      'the recorded Cedar request is the one the recorded operation derives (shares the derivation function with the producer)',
    'effect-consistency':
      'the recorded effect matches the authorized operation. Independent world read-back exists only for write_document and delete_file; where this ledger executes neither, every check here is consistency of the record with itself (docs/LIMITATIONS.md L7)',
  };

  const stages: StageReport[] = (Object.keys(counts) as StageName[]).map((stage) => {
    const c = counts[stage];
    return {
      stage,
      checked: c.checked,
      notApplicable: c.na,
      failures: c.fail,
      verdict: c.checked === 0 ? 'NOT CHECKED' : c.fail === 0 ? 'PASS' : 'FAIL',
      establishes: ESTABLISHES[stage],
    };
  });

  const executions = entries.filter((e) => e.toolResult !== null).length;
  const allows = entries.filter(
    (e) => e.decision.decision === 'allow' && e.cedarRequest.action.id !== 'delegate',
  ).length;
  if (executions !== allows) {
    fail(-1, 'auth-exec-binding', `${executions} executions against ${allows} tool-action allow decisions`);
    const s = stages.find((x) => x.stage === 'auth-exec-binding')!;
    s.failures += 1;
    s.verdict = 'FAIL';
  }

  const allPass = stages.every((s) => s.verdict === 'PASS');
  const anyUnchecked = stages.some((s) => s.verdict === 'NOT CHECKED');

  const result = {
    ledger: path,
    entries: entries.length,
    stages,
    findings,
    verdict: allPass ? 'ALL STAGES PASS' : anyUnchecked && findings.length === 0 ? 'INCOMPLETE' : 'FAILED',
    scope:
      'Stages 1-3 compare records to other records or re-derive them with code shared with the producer; ' +
      'they establish integrity and reproducibility, not correctness. Stage 4 is the only stage whose two ' +
      'sides come from different places, and even it compares a recorded world observation against a fresh ' +
      'derivation rather than re-observing the world, which is impossible after the fact.',
  };

  writeFileSync('evidence/replay-report.json', JSON.stringify(result, null, 2));

  console.log(`replay ${path}`);
  console.log(`  entries ${entries.length}`);
  for (const s of stages) {
    const pad = s.stage.padEnd(20);
    console.log(
      `  ${pad} ${s.verdict.padEnd(11)} checked ${String(s.checked).padStart(3)}  n/a ${String(s.notApplicable).padStart(3)}  failures ${s.failures}`,
    );
    console.log(`  ${' '.repeat(20)} establishes: ${s.establishes}`);
  }
  if (findings.length) {
    console.log(`  findings ${findings.length}`);
    for (const f of findings) console.log(`    #${f.seq} [${f.stage}] ${f.detail}`);
    process.exitCode = 1;
  } else {
    console.log(`  verdict ${result.verdict}`);
  }
}

main();
