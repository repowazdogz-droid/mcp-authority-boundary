import type * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { Pdp, denyMediated, denyUnresolvable } from './pdp.js';
import { resolveCall } from './resolve.js';
import { executeTool, expectedEffectOf, observeEffect, effectsMatch, type ToolResult } from './tools.js';
import type { EffectMediation, EffectMediator } from './mediation.js';
import type { EntityStore, LoadedPolicy } from './policy.js';
import { engineVersions } from './policy.js';
import type { Ledger } from './ledger.js';
import type {
  CedarContext,
  Decision,
  EffectFingerprint,
  EntityUid,
  LedgerEntry,
  ModelToolCall,
  ResolvedOperation,
} from './types.js';

/**
 * The enforcement point: the single place a tool call can become a tool
 * execution.
 *
 * The order is fixed and each step consumes only the output of the previous one:
 *
 *   raw call -> validate and canonicalise ONCE -> frozen ResolvedOperation
 *            -> Cedar request DERIVED from the operation -> decide
 *            -> grant bound to the operation's digest
 *            -> execute exactly that operation
 *            -> observe the world and compare against what was authorized
 *
 * The tool layer never sees the raw arguments. That is the structural answer to
 * audit finding A1, where the resolver measured one payload and the tool wrote
 * a different one because both read `call.args` independently.
 */
export interface EnforcementConfig {
  policy: LoadedPolicy;
  /**
   * Read afresh for every decision.
   *
   * Audit finding A4: the store used to be loaded once at server start, so
   * flipping `revoked` on disk never reached a running process while the
   * documentation claimed revocation was immediate. A function, called per
   * decision, makes the documented behaviour the actual behaviour.
   */
  entities: () => EntityStore;
  ledger: Ledger;
  session: EntityUid;
  /**
   * Read afresh for every decision.
   *
   * Audit finding A3: this used to be a fixed number captured at construction,
   * so expiry was evaluated against session-start time and never fired in a live
   * session. Deployments inject a real clock; the demo injects a deterministic
   * one so the ledger stays byte-reproducible.
   */
  now: () => number;
  wallClock: string;
  /**
   * Effect mediation, REQUIRED.
   *
   * Deliberately not optional and with no default. Mediation is mandatory for
   * every operation, so a deployment has to choose what sits behind it; a
   * deployment that does not want effect containment passes
   * `permitAllMediator()` and every ledger entry it writes says so. An optional
   * field would have made the guarantee depend on remembering to set it, which
   * is the class of weakness this change exists to remove.
   */
  mediator: EffectMediator;
}

interface RecordInput {
  requestId: string;
  raw: ModelToolCall;
  logicalTime: number;
  entitiesSha256: string;
  operation: ResolvedOperation | null;
  operationSha256: string | null;
  action: EntityUid;
  resource: EntityUid;
  context: CedarContext | { now: number };
  ignoredModelFields: string[];
  decision: Decision;
  mediation: EffectMediation | null;
  result: ToolResult | null;
  authorizedEffect: EffectFingerprint | null;
  observedEffect: EffectFingerprint | null;
  extraEntities?: unknown[];
}

const UNRESOLVED: EntityUid = { type: '<unresolved>', id: '<unresolved>' };

export class EnforcementPoint {
  private readonly pdp: Pdp;
  private counter = 0;
  private readonly origin: number;
  /** Turn-level taint. Coarse by design; see docs/LIMITATIONS.md, L4. */
  private sourceTrust: 'user' | 'tool_output' = 'user';

  constructor(private readonly cfg: EnforcementConfig) {
    this.pdp = new Pdp(cfg.policy);
    this.origin = cfg.ledger.nextSeq();
  }

  private newRequestId(): string {
    return `${this.cfg.session.id}@${this.origin}#${this.counter++}`;
  }

  /** Reset the taint flag at the start of a fresh user turn. */
  newTurn(): void {
    this.sourceTrust = 'user';
  }

  handle(raw: ModelToolCall): { entry: LedgerEntry; result: ToolResult | null } {
    const requestId = this.newRequestId();
    // both read once per decision, and recorded with the decision
    const now = this.cfg.now();
    const entities = this.cfg.entities();

    const resolution = resolveCall(raw, {
      requestId,
      now,
      sourceTrust: this.sourceTrust,
      entities,
    });

    if (!resolution.ok) {
      return {
        entry: this.record({
          requestId,
          raw,
          logicalTime: now,
          entitiesSha256: entities.sha256,
          operation: null,
          operationSha256: null,
          action: UNRESOLVED,
          resource: UNRESOLVED,
          context: {
            now,
            sourceTrust: this.sourceTrust,
            byteLen: 0,
            recipientDomain: '',
            requestId,
          },
          ignoredModelFields: resolution.ignoredModelFields,
          decision: denyUnresolvable(requestId, resolution.reason),
          mediation: null,
          result: null,
          authorizedEffect: null,
          observedEffect: null,
        }),
        result: null,
      };
    }

    const call = resolution.call;

    // EFFECT MEDIATION, before authorization and therefore before any grant
    // exists. A denial here means no grant is minted, so there is nothing the
    // tool layer could spend even if something tried.
    const mediation = this.cfg.mediator.mediateOperation(
      this.cfg.session,
      call.operation,
      call.operationSha256,
      now,
    );

    if (mediation.verdict === 'deny') {
      return {
        entry: this.record({
          ...{
            requestId,
            raw,
            logicalTime: now,
            entitiesSha256: entities.sha256,
            operation: call.operation,
            operationSha256: call.operationSha256,
            action: call.action,
            resource: call.resource,
            context: call.context,
            ignoredModelFields: call.ignoredModelFields,
          },
          decision: denyMediated(requestId, mediation.reason),
          mediation,
          result: null,
          authorizedEffect: null,
          observedEffect: null,
        }),
        result: null,
      };
    }

    const outcome = this.pdp.authorize({
      requestId,
      principal: this.cfg.session,
      action: call.action,
      resource: call.resource,
      context: call.context,
      entities,
      operation: call.operation,
      operationSha256: call.operationSha256,
      mediation,
    });

    const base = {
      requestId,
      raw,
      logicalTime: now,
      entitiesSha256: entities.sha256,
      operation: call.operation,
      operationSha256: call.operationSha256,
      action: call.action,
      resource: call.resource,
      context: call.context,
      ignoredModelFields: call.ignoredModelFields,
    };

    if (outcome.decision.decision === 'deny') {
      return {
        entry: this.record({
          ...base,
          decision: outcome.decision,
          mediation,
          result: null,
          authorizedEffect: null,
          observedEffect: null,
        }),
        result: null,
      };
    }

    // What the authorized operation says should happen, computed BEFORE the tool
    // runs and from the operation alone.
    const authorizedEffect = expectedEffectOf(call.operation);

    const result = executeTool(call.operation, outcome.grant, mediation);

    // What actually happened, read back out of the fixture world.
    const observedEffect = observeEffect(call.operation);

    if (!effectsMatch(authorizedEffect, observedEffect)) {
      // Not reachable by any input found so far. It is a throw rather than a
      // logged warning because an execution that diverged from its authorization
      // is precisely the condition this artifact exists to prevent, and
      // continuing would leave the world in a state nothing authorized.
      throw new Error(
        `execution diverged from authorization for ${requestId}: ` +
          `authorized ${JSON.stringify(authorizedEffect)}, observed ${JSON.stringify(observedEffect)}`,
      );
    }

    if (result.carriesResourceContent) this.sourceTrust = 'tool_output';

    return {
      entry: this.record({ ...base, decision: outcome.decision, mediation, result, authorizedEffect, observedEffect }),
      result,
    };
  }

  /**
   * Authorize the minting of a delegated session.
   *
   * The proposed child is passed to Cedar as a transient entity and is admitted
   * only if `permit-delegate-attenuated` allows it. Running this through the same
   * engine and the same ledger as tool calls is what makes the attenuation
   * argument inductive rather than a convention.
   */
  handleDelegation(child: cedar.EntityJson): LedgerEntry {
    const requestId = this.newRequestId();
    const now = this.cfg.now();
    const entities = this.cfg.entities();
    const uid = child.uid as { type: string; id: string };
    const resource: EntityUid = { type: uid.type, id: uid.id };
    const action: EntityUid = { type: 'Mcp::Action', id: 'delegate' };

    const decision = this.pdp.decide({
      requestId,
      principal: this.cfg.session,
      action,
      resource,
      context: { now },
      entities,
      extraEntities: [child],
    });

    return this.record({
      requestId,
      raw: { tool: 'delegate', args: { proposedSession: uid.id, attributes: child.attrs } },
      logicalTime: now,
      entitiesSha256: entities.sha256,
      operation: null,
      operationSha256: null,
      action,
      resource,
      context: { now },
      ignoredModelFields: [],
      decision,
      mediation: null,
      result: null,
      authorizedEffect: null,
      observedEffect: null,
      extraEntities: [child],
    });
  }

  private record(i: RecordInput): LedgerEntry {
    return this.cfg.ledger.append({
      requestId: i.requestId,
      logicalTime: i.logicalTime,
      wallClock: this.cfg.wallClock,
      engine: engineVersions(),
      policyVersion: this.cfg.policy.version,
      entitiesSha256: i.entitiesSha256,
      modelToolCall: i.raw,
      operation: i.operation,
      operationSha256: i.operationSha256,
      cedarRequest: {
        principal: this.cfg.session,
        action: i.action,
        resource: i.resource,
        context: i.context,
      },
      ...(i.extraEntities ? { extraEntities: i.extraEntities } : {}),
      ignoredModelFields: i.ignoredModelFields,
      decision: i.decision,
      mediation: i.mediation
        ? { verdict: i.mediation.verdict, reason: i.mediation.reason, hash: i.mediation.hash }
        : null,
      toolResult: i.result ? { ok: i.result.ok, summary: i.result.summary } : null,
      authorizedEffect: i.authorizedEffect,
      observedEffect: i.observedEffect,
    });
  }
}
