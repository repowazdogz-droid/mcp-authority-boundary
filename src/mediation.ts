import type { EntityUid, ToolName } from './types.js';

/**
 * Complete mediation, made structural.
 *
 * A tool in this artifact cannot be invoked with a plain argument list. It
 * requires an ExecutionGrant, and an ExecutionGrant can only be minted by the
 * policy decision point after Cedar returned `allow`. There is no code path from
 * "the model asked for a tool" to "the tool ran" that does not pass through
 * `mintGrant`, and `mintGrant` is not exported from the package entry point.
 *
 * This is a construction argument about this codebase, not a proof about MCP
 * servers in general. test/mediation.test.ts exercises the three ways one would
 * try to get around it: forging a grant, reusing a grant, and calling the tool
 * layer directly.
 */
const PDP_ONLY = Symbol('minted-by-pdp');

export class ExecutionGrant {
  readonly requestId: string;
  readonly tool: ToolName;
  readonly resource: EntityUid;
  readonly policyVersionSha: string;

  constructor(
    guard: symbol,
    requestId: string,
    tool: ToolName,
    resource: EntityUid,
    policyVersionSha: string,
  ) {
    if (guard !== PDP_ONLY) {
      throw new Error(
        'ExecutionGrant may only be minted by the policy decision point after an allow',
      );
    }
    this.requestId = requestId;
    this.tool = tool;
    this.resource = resource;
    this.policyVersionSha = policyVersionSha;
  }
}

/** Grants that this process actually issued. A forged object is not in here. */
const issued = new WeakSet<ExecutionGrant>();
/**
 * Grants already spent. One allow authorises exactly one execution.
 *
 * Keyed on the grant OBJECT, not on its request id. The first version used a
 * Set of id strings, which conflated two different things: request ids are for
 * correlating a decision with its ledger entry, and are only unique within one
 * ledger, so two independent enforcement points in the same process could
 * legitimately mint `sess-x@0#0` twice and the second execution would be
 * refused as a replay. Single use is a property of the capability, so the
 * capability is what gets tracked.
 */
const spent = new WeakSet<ExecutionGrant>();
let spentTotal = 0;

export function mintGrant(
  requestId: string,
  tool: ToolName,
  resource: EntityUid,
  policyVersionSha: string,
): ExecutionGrant {
  const g = new ExecutionGrant(PDP_ONLY, requestId, tool, resource, policyVersionSha);
  issued.add(g);
  return g;
}

/** Called by the tool layer before it does anything. Throws rather than returns. */
export function consumeGrant(grant: unknown, tool: ToolName): ExecutionGrant {
  if (!(grant instanceof ExecutionGrant) || !issued.has(grant)) {
    throw new Error('refusing to execute: no grant issued by the policy decision point');
  }
  if (grant.tool !== tool) {
    throw new Error(
      `refusing to execute: grant authorises ${grant.tool}, not ${tool}`,
    );
  }
  if (spent.has(grant)) {
    throw new Error(`refusing to execute: grant ${grant.requestId} already spent`);
  }
  spent.add(grant);
  spentTotal += 1;
  return grant;
}

/** Test/metrics hook. Not used to make decisions. */
export function spentCount(): number {
  return spentTotal;
}
