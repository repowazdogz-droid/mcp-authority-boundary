import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import type { LoadedPolicy, EntityStore } from './policy.js';
import { claimMinter, type ExecutionGrant } from './mediation.js';

/** The PDP claims the sole minting capability at module load. See mediation.ts. */
const mintGrant = claimMinter();
import type { CedarContext, Decision, EntityUid, ResolvedOperation } from './types.js';

export interface DecideInput {
  requestId: string;
  principal: EntityUid;
  action: EntityUid;
  resource: EntityUid;
  /** Tool actions carry the full ToolContext; `delegate` carries only `now`. */
  context: CedarContext | { now: number };
  /** The entity store as read for THIS decision. Never cached by the PDP. */
  entities: EntityStore;
  /**
   * Entities that exist only for this decision - specifically, the child
   * session proposed by a `delegate` request, which must be evaluated before
   * it is admitted to the store. It is never persisted by the PDP.
   */
  extraEntities?: cedar.EntityJson[];
}

export interface AuthorizeInput extends DecideInput {
  context: CedarContext;
  /** The frozen operation the grant will be bound to. */
  operation: ResolvedOperation;
  operationSha256: string;
}

export type AuthorizeResult =
  | { decision: Decision & { decision: 'allow' }; grant: ExecutionGrant }
  | { decision: Decision & { decision: 'deny' }; grant: null };

/**
 * The policy decision point.
 *
 * Everything interesting here is in how a non-`allow` answer is classified.
 * Cedar returns `deny` in several structurally different situations, and
 * collapsing them would produce explanations that are confidently wrong:
 *
 *   - a forbid policy matched              -> explicit-forbid, ids reported
 *   - nothing matched                      -> no-matching-permit (default deny)
 *   - policies errored during evaluation   -> evaluation-error
 *   - the request did not typecheck        -> request-validation-failure
 *
 * The third case is the one that has to be got right. When a policy errors,
 * Cedar skips it and continues. A skipped policy might have been a forbid, so an
 * `allow` returned alongside evaluation errors is not a decision anyone should
 * act on. This PDP treats any evaluation error as a denial, including when Cedar
 * itself said allow. That is a deliberate fail-closed choice and it is the
 * subject of test/failclosed.test.ts.
 */
export class Pdp {
  constructor(private readonly policy: LoadedPolicy) {}

  /**
   * Evaluate a request and classify the answer. Used directly for decisions
   * that do not run a tool - minting a delegated session, for instance - and
   * wrapped by `authorize` for those that do.
   */
  decide(input: DecideInput): Decision {
    const answer = cedar.isAuthorized({
      principal: input.principal,
      action: input.action,
      resource: input.resource,
      context: input.context as unknown as cedar.Context,
      entities: input.extraEntities
        ? [...input.entities.entities, ...input.extraEntities]
        : input.entities.entities,
      policies: { staticPolicies: this.policy.staticPolicies },
      schema: this.policy.schema,
      // Ask Cedar to check the request itself against the schema. Without this a
      // request naming an action that does not exist would simply match nothing
      // and come back as a default deny, which reads identically to a policy
      // decision and hides a malformed request.
      validateRequest: true,
    });

    if (answer.type === 'failure') {
      return this.deny(input, 'request-validation-failure', [], answer.errors.map((e) => e.message));
    }

    const { decision, diagnostics } = answer.response;
    const errors = diagnostics.errors.map((e) => `${e.policyId}: ${e.error.message}`);

    if (errors.length > 0) {
      return this.deny(input, 'evaluation-error', diagnostics.reason, errors);
    }

    if (decision === 'deny') {
      const kind = diagnostics.reason.length > 0 ? 'explicit-forbid' : 'no-matching-permit';
      return this.deny(input, kind, diagnostics.reason, []);
    }

    return {
      requestId: input.requestId,
      decision: 'allow',
      determiningPolicies: diagnostics.reason,
      denialKind: null,
      errors: [],
      explanation:
        `allow: ${diagnostics.reason.join(', ')} permitted ` +
        `${input.action.type}::"${input.action.id}" on ${input.resource.type}::"${input.resource.id}" ` +
        `for ${input.principal.type}::"${input.principal.id}" at t=${input.context.now}`,
    };
  }

  /** Decide, and on allow mint the single-use grant the tool layer demands. */
  authorize(input: AuthorizeInput): AuthorizeResult {
    const decision = this.decide(input);
    if (decision.decision === 'deny') {
      return { decision: decision as Decision & { decision: 'deny' }, grant: null };
    }
    return {
      decision: decision as Decision & { decision: 'allow' },
      grant: mintGrant(
        input.requestId,
        input.operationSha256,
        input.resource,
        this.policy.version.sha256,
      ),
    };
  }

  private deny(
    input: DecideInput,
    kind: Decision['denialKind'],
    reason: string[],
    errors: string[],
  ): Decision & { decision: 'deny' } {
    return {
      requestId: input.requestId,
      decision: 'deny',
      determiningPolicies: reason,
      denialKind: kind,
      errors,
      explanation: explain(kind, reason, errors, input),
    };
  }
}

function explain(
  kind: Decision['denialKind'],
  reason: string[],
  errors: string[],
  input: DecideInput,
): string {
  const target =
    `${input.action.type}::"${input.action.id}" on ${input.resource.type}::"${input.resource.id}" ` +
    `for ${input.principal.type}::"${input.principal.id}" at t=${input.context.now}`;
  switch (kind) {
    case 'explicit-forbid':
      return `deny: forbid policy ${reason.join(', ')} matched ${target}`;
    case 'no-matching-permit':
      return `deny: no permit policy matched ${target}; Cedar is default-deny, so this is a denial by absence of authority rather than by an explicit rule`;
    case 'evaluation-error':
      return `deny (fail-closed): Cedar could not evaluate ${reason.length ? reason.join(', ') : 'one or more policies'} for ${target} - ${errors.join('; ')}. A policy that failed to evaluate may have been a forbid, so this is not treated as an allow`;
    case 'request-validation-failure':
      return `deny (fail-closed): the request did not typecheck against the schema for ${target} - ${errors.join('; ')}`;
    case 'unresolvable-resource':
      return `deny (fail-closed): ${target} could not be resolved to a known resource - ${errors.join('; ')}`;
    default:
      return `deny: ${target}`;
  }
}

/** Used by the resolver when a tool call names something that does not exist. */
export function denyUnresolvable(
  requestId: string,
  detail: string,
): Decision & { decision: 'deny' } {
  return {
    requestId,
    decision: 'deny',
    determiningPolicies: [],
    denialKind: 'unresolvable-resource',
    errors: [detail],
    explanation: `deny (fail-closed): ${detail}. The request never reached Cedar because the host could not bind it to a real resource; an unbindable request is refused rather than guessed at`,
  };
}
