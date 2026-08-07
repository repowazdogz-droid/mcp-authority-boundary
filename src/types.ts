/** Shared types. Deliberately small: this file is the whole vocabulary. */

/** A Cedar entity reference, in the JSON form the engine expects. */
export interface EntityUid {
  type: string;
  id: string;
}

/** The six tools this artifact exposes over MCP. */
export type ToolName =
  | 'read_document'
  | 'write_document'
  | 'send_email'
  | 'execute_shell'
  | 'query_database'
  | 'delete_file';

/** A tool call exactly as the model emitted it. Untrusted in its entirety. */
export interface ModelToolCall {
  tool: string;
  args: Record<string, unknown>;
}

/** How a SQL statement was classified by the resolver. */
export type StatementClass = 'select' | 'mutating' | 'unrecognised';

/**
 * THE CANONICAL OPERATION.
 *
 * This is the single object that both the authorization request and the
 * execution are derived from. It is built once, validated, canonicalised, and
 * deep-frozen; after that nothing in the pipeline reads the model's raw
 * arguments again.
 *
 * The previous design let `resolve.ts` measure one thing and `tools.ts` execute
 * another, because both read `call.args` independently. That produced audit
 * finding A1: a non-string `content` measured as zero bytes and written as
 * 100,000. Carrying every security-relevant execution value here - the byte
 * length AND the exact string that produces it - makes that divergence
 * unrepresentable rather than merely checked for.
 */
export type ResolvedOperation =
  | { readonly tool: 'read_document'; readonly path: string }
  | {
      readonly tool: 'write_document';
      readonly path: string;
      readonly content: string;
      readonly byteLen: number;
      readonly contentSha256: string;
    }
  | { readonly tool: 'delete_file'; readonly path: string }
  | {
      readonly tool: 'send_email';
      readonly to: string;
      readonly domain: string;
      readonly subject: string;
      readonly body: string;
      readonly byteLen: number;
      readonly bodySha256: string;
    }
  | { readonly tool: 'execute_shell'; readonly host: string; readonly command: string }
  | {
      readonly tool: 'query_database';
      readonly table: string;
      readonly statementClass: StatementClass;
      readonly sql: string;
    };

/**
 * A fingerprint of a world state transition.
 *
 * Two of these are produced per execution, by deliberately different routes:
 * `expectedEffectOf(operation)` derives one from the authorized operation, and
 * `observeEffect(operation)` derives one by inspecting the fixture world after
 * the tool ran. Comparing them is the artifact's only genuinely differential
 * check - everything else in the evidence chain compares a record to another
 * record.
 */
export interface EffectFingerprint {
  kind: string;
  target: string;
  byteLen: number | null;
  sha256: string | null;
  detail: string;
}

export interface ResolvedCall {
  requestId: string;
  /** Frozen. The only thing execution is allowed to consume. */
  operation: ResolvedOperation;
  /** Digest over the canonical operation; the grant is bound to this value. */
  operationSha256: string;
  action: EntityUid;
  resource: EntityUid;
  context: CedarContext;
  /** Identity-shaped keys the model tried to supply, stripped before resolution. */
  ignoredModelFields: string[];
}

export interface CedarContext {
  now: number;
  sourceTrust: 'user' | 'tool_output';
  byteLen: number;
  recipientDomain: string;
  requestId: string;
}

/**
 * Why a request was denied. This distinction matters: Cedar returns `deny` both
 * when a policy said so and when it could not evaluate the request at all, and
 * reporting the second as the first would be a false explanation.
 */
export type DenialKind =
  | 'explicit-forbid' // a forbid policy matched; ids are in determiningPolicies
  | 'no-matching-permit' // Cedar's default deny; no policy matched at all
  | 'evaluation-error' // policies errored; treated as deny, fail-closed
  | 'request-validation-failure' // request did not typecheck against the schema
  | 'unresolvable-resource'; // the host could not build a canonical operation

export interface Decision {
  requestId: string;
  decision: 'allow' | 'deny';
  /** Policy ids Cedar reported as determining. Empty on a default deny. */
  determiningPolicies: string[];
  denialKind: DenialKind | null;
  /** Engine-level errors, verbatim. */
  errors: string[];
  /** Prose rendering of the decision, derived from the fields above. */
  explanation: string;
}

export interface PolicyVersion {
  id: string;
  sha256: string;
  policyIds: string[];
  sourceFiles: string[];
}

export interface LedgerEntry {
  seq: number;
  requestId: string;
  /** Logical clock the decision was made at; the value Cedar saw for THIS decision. */
  logicalTime: number;
  wallClock: string;
  engine: { cedar: string; cedarLang: string };
  policyVersion: PolicyVersion;
  /** Hash of the entity store as read for THIS decision, not at process start. */
  entitiesSha256: string;
  /** The model's raw output, retained so replay can show what was attempted. */
  modelToolCall: ModelToolCall;
  /** The canonical operation, or null when resolution failed before one existed. */
  operation: ResolvedOperation | null;
  operationSha256: string | null;
  /** The request as it was actually put to Cedar, verbatim. */
  cedarRequest: {
    principal: EntityUid;
    action: EntityUid;
    resource: EntityUid;
    /** Tool actions record a full ToolContext; `delegate` records only `now`. */
    context: CedarContext | { now: number };
  };
  /**
   * Entities that existed only for this decision (the proposed child session on
   * a `delegate` request). Recorded so replay can reconstruct the exact request.
   */
  extraEntities?: unknown[];
  ignoredModelFields: string[];
  decision: Decision;
  /** Present only when the decision was allow and the tool then ran. */
  toolResult: { ok: boolean; summary: string } | null;
  /** Derived from the authorized operation before execution. */
  authorizedEffect: EffectFingerprint | null;
  /** Derived by inspecting the fixture world after execution. */
  observedEffect: EffectFingerprint | null;
  prevHash: string;
  hash: string;
}
