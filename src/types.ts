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

/**
 * A tool call after the enforcement point has resolved it against the real world.
 * Every field here is computed by the host from the session and from the actual
 * effect the tool would have. None of it is taken from the model's output, apart
 * from `args`, which is data the tool operates on rather than a claim about
 * authority.
 */
export interface ResolvedCall {
  requestId: string;
  tool: ToolName;
  action: EntityUid;
  resource: EntityUid;
  args: Record<string, unknown>;
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
  | 'unresolvable-resource'; // the host could not map the call to a real resource

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
  /** Logical clock the decision was made at; this is the value Cedar saw. */
  logicalTime: number;
  wallClock: string;
  engine: { cedar: string; cedarLang: string };
  policyVersion: PolicyVersion;
  entitiesSha256: string;
  /** The model's raw output, retained so replay can show what was attempted. */
  modelToolCall: ModelToolCall;
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
  prevHash: string;
  hash: string;
}
