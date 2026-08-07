import type * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { Pdp, denyUnresolvable } from './pdp.js';
import { resolveCall } from './resolve.js';
import { executeTool, type ToolResult } from './tools.js';
import type { EntityStore, LoadedPolicy } from './policy.js';
import { engineVersions } from './policy.js';
import type { Ledger } from './ledger.js';
import type { CedarContext, Decision, EntityUid, LedgerEntry, ModelToolCall } from './types.js';

/**
 * The enforcement point: the single place a tool call can become a tool
 * execution.
 *
 * Order matters and is fixed: resolve the call against the real world, decide,
 * record, and only then - if and only if Cedar allowed it - execute. The ledger
 * entry is written for denials too, which is what makes the "no execution
 * without a matching allow" invariant checkable over the log rather than merely
 * asserted in prose.
 */
export interface EnforcementConfig {
  policy: LoadedPolicy;
  entities: EntityStore;
  ledger: Ledger;
  session: EntityUid;
  /** Logical clock. Injected by the host at session setup; not model-influenceable. */
  now: number;
  /** Pinned so the hash chain is byte-reproducible across runs. */
  wallClock: string;
}

interface RecordInput {
  requestId: string;
  raw: ModelToolCall;
  action: EntityUid;
  resource: EntityUid;
  context: CedarContext | { now: number };
  ignoredModelFields: string[];
  decision: Decision;
  result: ToolResult | null;
  extraEntities?: unknown[];
}

const UNRESOLVED: EntityUid = { type: '<unresolved>', id: '<unresolved>' };

export class EnforcementPoint {
  private readonly pdp: Pdp;
  private counter = 0;
  /**
   * Where this enforcement point started in the ledger.
   *
   * Request ids were originally `<session>#<counter>` with the counter local to
   * the process. Each scenario spawns a fresh server, so the counter restarted
   * and ids collided across scenarios - the in-process single-use grant check
   * could not see it, because the collisions were in different processes. The
   * replay verifier's duplicate-id check found it. Anchoring on the ledger
   * position makes ids unique across the whole log while staying deterministic,
   * so the hash chain remains byte-reproducible.
   */
  private readonly origin: number;
  /** Turn-level taint. Coarse by design; see docs/LIMITATIONS.md, L4. */
  private sourceTrust: 'user' | 'tool_output' = 'user';

  constructor(private readonly cfg: EnforcementConfig) {
    this.pdp = new Pdp(cfg.policy, cfg.entities);
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

    const resolution = resolveCall(raw, {
      requestId,
      now: this.cfg.now,
      sourceTrust: this.sourceTrust,
      entities: this.cfg.entities,
    });

    if (!resolution.ok) {
      const decision = denyUnresolvable(requestId, resolution.reason);
      return {
        entry: this.record({
          requestId,
          raw,
          action: UNRESOLVED,
          resource: UNRESOLVED,
          context: {
            now: this.cfg.now,
            sourceTrust: this.sourceTrust,
            byteLen: 0,
            recipientDomain: '',
            requestId,
          },
          ignoredModelFields: resolution.ignoredModelFields,
          decision,
          result: null,
        }),
        result: null,
      };
    }

    const call = resolution.call;
    const outcome = this.pdp.authorize({
      requestId,
      principal: this.cfg.session,
      action: call.action,
      resource: call.resource,
      context: call.context,
      tool: call.tool,
    });

    const base = {
      requestId,
      raw,
      action: call.action,
      resource: call.resource,
      context: call.context,
      ignoredModelFields: call.ignoredModelFields,
    };

    if (outcome.decision.decision === 'deny') {
      return { entry: this.record({ ...base, decision: outcome.decision, result: null }), result: null };
    }

    const result = executeTool(call, outcome.grant);
    if (result.carriesResourceContent) this.sourceTrust = 'tool_output';
    return { entry: this.record({ ...base, decision: outcome.decision, result }), result };
  }

  /**
   * Authorize the minting of a delegated session.
   *
   * The proposed child is passed to Cedar as a transient entity and is admitted
   * to the world only if `permit-delegate-attenuated` allows it. Running this
   * through the same engine and the same ledger as tool calls is what makes the
   * attenuation argument inductive: every link in a delegation chain was
   * checked by the policy set that the chain's final request is decided under.
   */
  handleDelegation(child: cedar.EntityJson): LedgerEntry {
    const requestId = this.newRequestId();
    const uid = child.uid as { type: string; id: string };
    const resource: EntityUid = { type: uid.type, id: uid.id };
    const action: EntityUid = { type: 'Mcp::Action', id: 'delegate' };
    const context = { now: this.cfg.now };

    const decision = this.pdp.decide({
      requestId,
      principal: this.cfg.session,
      action,
      resource,
      context,
      extraEntities: [child],
    });

    return this.record({
      requestId,
      raw: { tool: 'delegate', args: { proposedSession: uid.id, attributes: child.attrs } },
      action,
      resource,
      context,
      ignoredModelFields: [],
      decision,
      result: null,
      extraEntities: [child],
    });
  }

  private record(i: RecordInput): LedgerEntry {
    return this.cfg.ledger.append({
      requestId: i.requestId,
      logicalTime: this.cfg.now,
      wallClock: this.cfg.wallClock,
      engine: engineVersions(),
      policyVersion: this.cfg.policy.version,
      entitiesSha256: this.cfg.entities.sha256,
      modelToolCall: i.raw,
      cedarRequest: {
        principal: this.cfg.session,
        action: i.action,
        resource: i.resource,
        context: i.context,
      },
      ...(i.extraEntities ? { extraEntities: i.extraEntities } : {}),
      ignoredModelFields: i.ignoredModelFields,
      decision: i.decision,
      toolResult: i.result ? { ok: i.result.ok, summary: i.result.summary } : null,
    });
  }
}
