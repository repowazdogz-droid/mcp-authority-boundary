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

export class ExecutionGrant {
  readonly requestId: string;
  readonly operationSha256: string;
  readonly resource: EntityUid;
  readonly policyVersionSha: string;

  constructor(
    guard: symbol,
    requestId: string,
    operationSha256: string,
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
  resource: EntityUid,
  policyVersionSha: string,
) => ExecutionGrant;

function mint(
  requestId: string,
  operationSha256: string,
  resource: EntityUid,
  policyVersionSha: string,
): ExecutionGrant {
  const g = new ExecutionGrant(PDP_ONLY, requestId, operationSha256, resource, policyVersionSha);
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
export function consumeGrant(grant: unknown, operation: ResolvedOperation): ExecutionGrant {
  if (!(grant instanceof ExecutionGrant) || !issued.has(grant)) {
    throw new Error('refusing to execute: no grant issued by the policy decision point');
  }
  const digest = sha256Canonical(operation);
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
