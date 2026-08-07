import type { LedgerEntry } from './types.js';
import type { Scenario } from './scenarios.js';

/**
 * Metrics over a completed run.
 *
 * Every number here is a count over the ledger this run produced. None of them
 * is a measurement of how often the technique works in the wild, how many real
 * attacks it stops, or how a real model behaves: the scenario set is authored,
 * small, and adversarially chosen by the same person who wrote the policies.
 * The honest reading is in docs/EVIDENCE.md - these count what the artifact
 * demonstrates, not what the approach achieves.
 */
export interface Metrics {
  scenarios: number;
  ledgerEntries: number;
  decisions: { allow: number; deny: number };
  denialsByKind: Record<string, number>;
  determiningPolicyFrequency: Record<string, number>;
  policyVersionsExercised: string[];
  /** Union of policy ids across every policy version the run exercised. */
  policiesInSet: number;
  policiesExercisedAsDetermining: number;
  policyCoverage: string;
  /** Named, not just counted: a coverage figure without these is not checkable. */
  policiesNeverDetermining: string[];
  /** Ledger entries whose tool ran. */
  executions: number;
  /** Allow decisions on a tool action. Delegation allows mint a session, not a call. */
  toolAllows: number;
  mediationInvariantHolds: boolean;
  forgedIdentityFieldsIgnored: number;
  unmediatedBaselineExecutions: number;
}

export function computeMetrics(
  entries: LedgerEntry[],
  scenarios: Scenario[],
  policyIds: string[],
  unmediatedBaselineExecutions: number,
): Metrics {
  const decisions = { allow: 0, deny: 0 };
  const denialsByKind: Record<string, number> = {};
  const determining: Record<string, number> = {};
  const versions = new Set<string>();
  let executions = 0;
  let toolAllows = 0;
  let forged = 0;
  let executionWithoutAllow = 0;

  for (const e of entries) {
    decisions[e.decision.decision] += 1;
    const isDelegation = e.cedarRequest.action.id === 'delegate';
    if (e.decision.decision === 'allow' && !isDelegation) toolAllows += 1;
    if (e.toolResult !== null && e.decision.decision !== 'allow') executionWithoutAllow += 1;
    if (e.decision.decision === 'deny') {
      const k = e.decision.denialKind ?? 'unknown';
      denialsByKind[k] = (denialsByKind[k] ?? 0) + 1;
    }
    for (const p of e.decision.determiningPolicies) {
      determining[p] = (determining[p] ?? 0) + 1;
    }
    versions.add(e.policyVersion.id);
    if (e.toolResult !== null) executions += 1;
    forged += e.ignoredModelFields.length;
  }

  // The denominator must be the union of policies across every version the run
  // exercised. Dividing by the base set alone counted an overlay policy in the
  // numerator that was not in the denominator, which inflated coverage.
  const universe = [...new Set(policyIds)].sort();
  const exercised = universe.filter((p) => p in determining).length;
  const never = universe.filter((p) => !(p in determining));

  return {
    scenarios: scenarios.length,
    ledgerEntries: entries.length,
    decisions,
    denialsByKind,
    determiningPolicyFrequency: determining,
    policyVersionsExercised: [...versions].sort(),
    policiesInSet: universe.length,
    policiesExercisedAsDetermining: exercised,
    policyCoverage: `${exercised}/${universe.length}`,
    policiesNeverDetermining: never,
    executions,
    toolAllows,
    // Two directions, both checked over the log rather than asserted in prose:
    // no tool ran without an allow, and every tool-action allow ran its tool.
    // Delegation allows are excluded because they mint a session rather than
    // invoke a tool - counting them here was a bug in the first draft of this
    // metric, and it reported a violation on a correct run.
    mediationInvariantHolds: executionWithoutAllow === 0 && executions === toolAllows,
    forgedIdentityFieldsIgnored: forged,
    unmediatedBaselineExecutions,
  };
}
