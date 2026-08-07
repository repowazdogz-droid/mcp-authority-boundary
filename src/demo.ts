import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { BoundaryClient, type CallEnvelope } from './client.js';
import { HostileRawClient } from './rawclient.js';
import { EnforcementPoint } from './enforce.js';
import { Ledger, readLedger } from './ledger.js';
import { loadEntities, loadPolicy } from './policy.js';
import { resolveCall } from './resolve.js';
import { ScriptedAdversary, type AgentTurn } from './agent.js';
import { computeMetrics } from './metrics.js';
import { ATTACK_SCENARIOS, SCENARIOS, type Expectation, type Scenario } from './scenarios.js';
import { resetEffects, effectLog, snapshotDocuments, restoreDocuments } from './tools.js';
import type { ModelToolCall } from './types.js';

const LEDGER = 'evidence/ledger.jsonl';
const WALLCLOCK = '2026-08-07T00:00:00.000Z';

const tty = process.stdout.isTTY;
const dim = (s: string) => (tty ? `\x1b[2m${s}\x1b[0m` : s);
const bold = (s: string) => (tty ? `\x1b[1m${s}\x1b[0m` : s);
const green = (s: string) => (tty ? `\x1b[32m${s}\x1b[0m` : s);
const red = (s: string) => (tty ? `\x1b[31m${s}\x1b[0m` : s);
const yellow = (s: string) => (tty ? `\x1b[33m${s}\x1b[0m` : s);

const report: string[] = [];
function say(line = ''): void {
  console.log(line);
  report.push(line.replace(/\x1b\[[0-9;]*m/g, ''));
}

interface StepOutcome {
  call: ModelToolCall;
  envelope: {
    decision: 'allow' | 'deny';
    denialKind: string | null;
    determiningPolicies: string[];
    explanation: string;
    ignoredModelFields: string[];
    policyVersion: string;
    ledgerSeq: number;
    ledgerHash: string;
  };
  observation: string | null;
}

/** Run the tool steps of a scenario through the real MCP transport. */
async function runOverMcp(s: Scenario): Promise<StepOutcome[]> {
  const env = {
    sessionId: s.session,
    clock: s.clock,
    ledgerPath: LEDGER,
    overlays: s.overlays,
    policyVersion: s.policyVersion,
    wallClock: WALLCLOCK,
  };
  const client = s.useRawClient ? new HostileRawClient(env) : new BoundaryClient(env);
  await client.connect();

  const calls = s.steps.flatMap((st) => (st.kind === 'tool' ? [st.call] : []));
  const model = new ScriptedAdversary(calls);
  const turn: AgentTurn = { userPrompt: s.userPrompt, observations: [] };
  const out: StepOutcome[] = [];

  for (;;) {
    const call = await model.nextToolCall(turn);
    if (!call) break;
    const env2: CallEnvelope = await client.call(call);
    if (env2.content) turn.observations.push(env2.content);
    out.push({ call, envelope: env2, observation: env2.content });
  }

  await client.close();
  return out;
}

/**
 * Run delegation steps in-process.
 *
 * Minting a session is a host action, not something the model can request, so
 * it does not travel over MCP. It is decided by the same engine against the
 * same policy set and lands in the same ledger.
 */
function runDelegations(s: Scenario): StepOutcome[] {
  const policy = loadPolicy(s.policyVersion ?? 'v1', s.overlays ?? []);
  const ledger = new Ledger(LEDGER);
  const pep = new EnforcementPoint({
    policy,
    entities: () => loadEntities(),
    ledger,
    session: { type: 'Mcp::Session', id: s.session },
    now: () => s.clock,
    wallClock: WALLCLOCK,
  });

  return s.steps.flatMap((st) => {
    if (st.kind !== 'delegate') return [];
    const entry = pep.handleDelegation(st.child);
    return [
      {
        call: entry.modelToolCall,
        envelope: {
          decision: entry.decision.decision,
          denialKind: entry.decision.denialKind,
          determiningPolicies: entry.decision.determiningPolicies,
          explanation: entry.decision.explanation,
          ignoredModelFields: entry.ignoredModelFields,
          policyVersion: entry.policyVersion.id,
          ledgerSeq: entry.seq,
          ledgerHash: entry.hash.slice(0, 16),
        },
        observation: null,
      },
    ];
  });
}

function checkExpectation(actual: StepOutcome, expected: Expectation | undefined): string[] {
  if (!expected) return ['no expectation declared for this step'];
  const problems: string[] = [];
  const e = actual.envelope;
  if (e.decision !== expected.decision) {
    problems.push(`expected ${expected.decision}, got ${e.decision}`);
  }
  if (expected.denialKind && e.denialKind !== expected.denialKind) {
    problems.push(`expected denialKind ${expected.denialKind}, got ${e.denialKind}`);
  }
  if (expected.policies) {
    const got = [...e.determiningPolicies].sort().join(',');
    const want = [...expected.policies].sort().join(',');
    if (got !== want) problems.push(`expected determining policies [${want}], got [${got}]`);
  }
  return problems;
}

/**
 * The unmediated baseline.
 *
 * The same attacker-chosen tool calls, executed with the authorization layer
 * removed. Without this the demo would only show that denied things were
 * denied; the contrast is what makes the denials mean anything.
 */
function runUnmediatedBaseline(): { executed: number; effects: string[] } {
  resetEffects();
  const entities = loadEntities();
  const pristine = snapshotDocuments();
  let executed = 0;
  const effects: string[] = [];
  for (const s of ATTACK_SCENARIOS) {
    restoreDocuments(pristine);
    for (const st of s.steps) {
      if (st.kind !== 'tool') continue;
      const r = resolveCall(st.call, {
        requestId: `baseline:${s.id}`,
        now: s.clock,
        sourceTrust: 'user',
        entities,
      });
      if (!r.ok) continue;
      executed += 1;
      effects.push(`${r.call.operation.tool} -> ${r.call.resource.id}`);
    }
  }
  restoreDocuments(pristine);
  resetEffects();
  return { executed, effects };
}

async function main(): Promise<void> {
  rmSync('evidence', { recursive: true, force: true });
  mkdirSync('evidence', { recursive: true });

  const basePolicy = loadPolicy('v1');
  say(bold('MCP authority boundary - scenario run'));
  say(dim(`cedar ${basePolicy.version.sha256.slice(0, 12)} | ${basePolicy.version.policyIds.length} policies | logical clock pinned | wall clock pinned at ${WALLCLOCK}`));
  say();

  let failures = 0;

  for (const s of SCENARIOS) {
    const hasDelegate = s.steps.some((st) => st.kind === 'delegate');
    const outcomes = hasDelegate ? runDelegations(s) : await runOverMcp(s);

    say(bold(`${s.id}  ${s.title}`));
    say(dim(`      family=${s.family}${s.mcpSecBench ? ` | ${s.mcpSecBench}` : ''}`));
    say(dim(`      session=${s.session} clock=${s.clock} policy=${s.policyVersion ?? 'v1'}${s.useRawClient ? ' transport=raw-hostile-client' : ''}`));
    say(`      ${dim('user:')} ${s.userPrompt.split('\n')[0]}`);

    outcomes.forEach((o, i) => {
      const problems = checkExpectation(o, s.expect[i]);
      if (problems.length) failures += 1;

      const verdict =
        o.envelope.decision === 'allow'
          ? s.negativeControl
            ? yellow('ALLOW')
            : green('ALLOW')
          : red('DENY ');
      say(`      ${dim('model ->')} ${o.call.tool}(${JSON.stringify(o.call.args).slice(0, 90)})`);
      say(`      ${verdict} ${o.envelope.determiningPolicies.join(', ') || dim('(no policy matched)')}${o.envelope.denialKind ? dim(`  [${o.envelope.denialKind}]`) : ''}`);
      say(`      ${dim('why:')}  ${o.envelope.explanation}`);
      if (o.envelope.ignoredModelFields.length) {
        say(`      ${dim('ignored model-supplied authority fields:')} ${o.envelope.ignoredModelFields.join(', ')}`);
      }
      say(`      ${dim(`ledger #${o.envelope.ledgerSeq} ${o.envelope.ledgerHash}`)}`);
      if (problems.length) say(`      ${red('EXPECTATION FAILED:')} ${problems.join('; ')}`);
    });

    if (s.commentary) say(`      ${yellow('note:')} ${s.commentary}`);
    say();
  }

  const baseline = runUnmediatedBaseline();
  const entries = readLedger(LEDGER);
  // the universe is every policy across every version the run exercised
  const allPolicyIds = [
    ...basePolicy.version.policyIds,
    ...loadPolicy('v2', ['overlay-revocation']).version.policyIds,
  ];
  const metrics = computeMetrics(entries, SCENARIOS, allPolicyIds, baseline.executed);

  say(bold('Unmediated baseline (authorization removed)'));
  say(dim('      the same attacker-chosen calls, resolved to canonical operations. Each of these'));
  say(dim('      would execute if the Cedar layer were taken out of the path. The tool layer no'));
  say(dim('      longer exposes a bypass to run them for real - see audit finding A9.'));
  for (const e of baseline.effects) say(`      WOULD EXECUTE  ${e}`);
  say();

  say(bold('Metrics'));
  say(`      scenarios ${metrics.scenarios} | ledger entries ${metrics.ledgerEntries} | allow ${metrics.decisions.allow} | deny ${metrics.decisions.deny}`);
  say(`      denials by kind: ${JSON.stringify(metrics.denialsByKind)}`);
  say(`      policy coverage (determining at least once): ${metrics.policyCoverage}`);
  say(`      forged authority fields stripped from model output: ${metrics.forgedIdentityFieldsIgnored}`);
  say(`      tool executions ${metrics.executions} vs tool-action allows ${metrics.toolAllows} -> mediation invariant ${metrics.mediationInvariantHolds ? green('HOLDS') : red('VIOLATED')}`);
  say(`      same calls with authorization removed: ${metrics.unmediatedBaselineExecutions} would execute`);
  say();

  writeFileSync('evidence/metrics.json', JSON.stringify(metrics, null, 2));
  writeFileSync('evidence/baseline.json', JSON.stringify(baseline, null, 2));
  writeFileSync('evidence/transcript.md', '```\n' + report.join('\n') + '\n```\n');
  writeFileSync('evidence/attack-matrix.md', renderAttackMatrix());

  if (failures > 0) {
    say(red(`${failures} expectation(s) failed.`));
    process.exitCode = 1;
  } else {
    say(green('All scenario expectations met.') + dim('  Now run `npm run replay` to re-decide every entry independently.'));
  }
}

function renderAttackMatrix(): string {
  const rows = SCENARIOS.map((s) => {
    const outcome = s.expect.map((e) => (e.decision === 'allow' ? 'ALLOW' : 'DENY')).join(' then ');
    const policies = [...new Set(s.expect.flatMap((e) => e.policies ?? []))].join(', ') || '(default deny)';
    return `| ${s.id} | ${s.title} | ${s.family} | ${s.mcpSecBench ?? '-'} | ${outcome} | ${policies} |`;
  });
  return [
    '# Attack matrix (generated by `npm run demo`)',
    '',
    'Outcome is per step, in order. "DENY" with no policy named is Cedar default-deny:',
    'no permit matched, which is a denial by absence of authority rather than by an explicit rule.',
    '',
    '| ID | Scenario | Family | MCPSecBench class | Outcome | Determining policies |',
    '|---|---|---|---|---|---|',
    ...rows,
    '',
    '## Out of scope',
    '',
    'This boundary mediates tool *requests*. Attacks that never become a tool request are',
    'structurally out of its reach and are not counted as caught: transport interception,',
    'host or OS compromise, DNS, supply-chain substitution of the server binary, and',
    'side channels in tool output. See docs/THREAT_MODEL.md.',
    '',
  ].join('\n');
}

await main();
