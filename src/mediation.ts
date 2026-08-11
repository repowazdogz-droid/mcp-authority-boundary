import { sha256Canonical } from './canonical.js';
import type { EntityUid, ResolvedOperation } from './types.js';

/**
 * Complete mediation, made structural.
 *
 * A tool in this artifact cannot be invoked with a plain argument list. It
 * requires an ExecutionGrant, and an ExecutionGrant is bound to the digest of
 * the exact canonical operation the PDP authorized. `consumeGrant` recomputes
 * that digest from the operation being executed and refuses on any mismatch, so
 * "the thing that runs is the thing that was authorized" is checked at the
 * moment of execution rather than assumed from the call site.
 *
 * Two weaknesses the adversarial audit exposed are closed here:
 *
 *   A5 - the grant carried a resource that nothing ever checked. The binding is
 *        now the operation digest, and it is verified on every execution.
 *   A9 - `executeTool` took an `unsafe_bypassAuthorization` flag, so complete
 *        mediation was a property of who called it. The flag is gone.
 *
 * A third weakness the audit did NOT catch: `mintGrant` used to be a plain
 * export, so any module could mint a grant and the guarantee rested on nobody
 * doing so. Minting is now a one-shot capability - the first caller of
 * `claimMinter()` takes it and every later caller throws - and pdp.ts claims it
 * at module load. There is no second minter to obtain.
 */
const PDP_ONLY = Symbol('minted-by-pdp');

/**
 * A mediator's verdict on the EFFECT of one operation.
 *
 * Declared here rather than where mediators are implemented, so that the
 * enforcement path can require one without knowing anything about how effects
 * are classified. `operationSha256` is part of the record on purpose: a verdict
 * that did not name the operation it was about could be replayed against a
 * different one, and `consumeGrant` would have no way to notice.
 */
export interface EffectMediation {
  readonly operationSha256: string;
  readonly verdict: 'allow' | 'deny';
  readonly reason: string;
  /** Digest over the record, bound into the grant. */
  readonly hash: string;
}

export interface EffectMediator {
  mediateOperation(
    principal: EntityUid,
    operation: ResolvedOperation,
    operationSha256: string,
    now: number,
  ): EffectMediation;
}

export const NO_MEDIATION_CONFIGURED =
  'permit-all: this deployment configured no effect mediation';

/**
 * A mediator that permits every effect, and says so in every record it issues.
 *
 * This is the analogue of a permissive policy set, not a hole. The MECHANISM is
 * unbypassable either way - `consumeGrant` refuses to execute without a
 * mediation record bound to the operation - and what a deployment chooses to put
 * behind that mechanism is a deployment decision, visible in the config and in
 * every ledger entry it produces. Compare docs/LIMITATIONS.md L2: a policy that
 * is wrong is enforced faithfully.
 *
 * It exists because mediation is mandatory, so every deployment must supply
 * something, including the ones whose subject is not effect containment at all.
 */
export function permitAllMediator(): EffectMediator {
  return {
    mediateOperation(_principal, _operation, operationSha256) {
      const body = {
        operationSha256,
        verdict: 'allow' as const,
        reason: NO_MEDIATION_CONFIGURED,
      };
      return { ...body, hash: sha256Canonical(body) };
    },
  };
}

export class ExecutionGrant {
  readonly requestId: string;
  readonly operationSha256: string;
  /** Digest of the mediation record that cleared this operation's effect. */
  readonly mediationSha256: string;
  readonly resource: EntityUid;
  readonly policyVersionSha: string;

  constructor(
    guard: symbol,
    requestId: string,
    operationSha256: string,
    mediationSha256: string,
    resource: EntityUid,
    policyVersionSha: string,
  ) {
    if (guard !== PDP_ONLY) {
      throw new Error(
        'ExecutionGrant may only be minted by the policy decision point after an allow',
      );
    }
    this.requestId = requestId;
    this.operationSha256 = operationSha256;
    this.mediationSha256 = mediationSha256;
    this.resource = resource;
    this.policyVersionSha = policyVersionSha;
  }
}

/** Grants this process actually issued. A forged object is not in here. */
const issued = new WeakSet<ExecutionGrant>();
/** Grants already spent, keyed on the capability object rather than on a name. */
const spent = new WeakSet<ExecutionGrant>();
let spentTotal = 0;

export type Minter = (
  requestId: string,
  operationSha256: string,
  mediationSha256: string,
  resource: EntityUid,
  policyVersionSha: string,
) => ExecutionGrant;

function mint(
  requestId: string,
  operationSha256: string,
  mediationSha256: string,
  resource: EntityUid,
  policyVersionSha: string,
): ExecutionGrant {
  const g = new ExecutionGrant(
    PDP_ONLY,
    requestId,
    operationSha256,
    mediationSha256,
    resource,
    policyVersionSha,
  );
  issued.add(g);
  return g;
}

let minterClaimed = false;

/**
 * Hand out the minting capability exactly once.
 *
 * pdp.ts calls this at module load. Anything else that tries gets an exception,
 * so a second minting path cannot be added by importing this module - it has to
 * be added by editing this file, which is a reviewable act rather than a silent one.
 */
export function claimMinter(): Minter {
  if (minterClaimed) {
    throw new Error('the grant-minting capability has already been claimed by the PDP');
  }
  minterClaimed = true;
  return mint;
}

/**
 * Called by the tool layer before it does anything. Throws rather than returns.
 *
 * The digest comparison is what makes the authorization binding real: an
 * operation that differs from the authorized one in any field - a byte of
 * content, a character of path, a recipient - produces a different digest and
 * is refused.
 */
export function consumeGrant(
  grant: unknown,
  operation: ResolvedOperation,
  mediation?: EffectMediation,
): ExecutionGrant {
  if (!(grant instanceof ExecutionGrant) || !issued.has(grant)) {
    throw new Error('refusing to execute: no grant issued by the policy decision point');
  }

  // MEDIATION IS MANDATORY. Three separate refusals, because there are three
  // separate ways to be handed something that looks like clearance and is not.
  if (mediation === undefined) {
    throw new Error(
      'refusing to execute: no effect mediation presented. Every operation must be ' +
        'mediated; a deployment that does not want effect containment configures ' +
        'permitAllMediator(), it does not omit the record',
    );
  }
  if (grant.mediationSha256 !== mediation.hash) {
    throw new Error(
      `refusing to execute: grant is bound to mediation ${grant.mediationSha256.slice(0, 12)}, ` +
        `but the record presented digests to ${mediation.hash.slice(0, 12)}`,
    );
  }

  const digest = sha256Canonical(operation);

  // The linkage check. Without it, a mediation record cleared for one operation
  // could be presented alongside a grant for another: both digests would match
  // their own bindings and neither would notice they were about different
  // things. The record names the operation it judged, and this is where that
  // name is made to matter.
  if (mediation.operationSha256 !== digest) {
    throw new Error(
      `refusing to execute: mediation clears operation ${mediation.operationSha256.slice(0, 12)}, ` +
        `but the operation presented digests to ${digest.slice(0, 12)}`,
    );
  }
  if (mediation.verdict !== 'allow') {
    throw new Error(
      `refusing to execute: the effect mediator returned ${mediation.verdict} (${mediation.reason})`,
    );
  }

  if (grant.operationSha256 !== digest) {
    throw new Error(
      `refusing to execute: grant authorises operation ${grant.operationSha256.slice(0, 12)}, ` +
        `but the operation presented digests to ${digest.slice(0, 12)}`,
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
