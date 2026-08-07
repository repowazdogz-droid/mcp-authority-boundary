import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import { sha256, sha256Canonical } from './canonical.js';
import type { PolicyVersion } from './types.js';

const POLICY_DIR = new URL('../../policies/', import.meta.url).pathname;
const ENTITY_FILE = new URL('../../entities/entities.json', import.meta.url).pathname;

export interface LoadedPolicy {
  schema: string;
  /** policy id -> policy source. Ids come from each policy's @id annotation. */
  staticPolicies: Record<string, string>;
  version: PolicyVersion;
}

/** Read the @id("...") annotation. A policy without one is a load-time error:
 *  an unnamed policy cannot be cited in an explanation or a replay log. */
function policyId(source: string, file: string): string {
  const m = source.match(/@id\("([^"]+)"\)/);
  if (!m?.[1]) {
    throw new Error(`policy in ${file} has no @id annotation:\n${source.slice(0, 120)}`);
  }
  return m[1];
}

/**
 * Load a policy set and pin it to a content hash.
 *
 * `overlays` names subdirectories of policies/ whose files are appended. The
 * revocation scenario uses this to produce a genuinely different policy version
 * rather than mutating one in place, so both versions stay replayable.
 */
export function loadPolicy(versionId: string, overlays: string[] = []): LoadedPolicy {
  const schema = readFileSync(join(POLICY_DIR, 'mcp.cedarschema'), 'utf8');

  const sources: Array<{ file: string; text: string }> = [];
  for (const f of readdirSync(POLICY_DIR).filter((f) => f.endsWith('.cedar')).sort()) {
    sources.push({ file: f, text: readFileSync(join(POLICY_DIR, f), 'utf8') });
  }
  for (const overlay of overlays) {
    const dir = join(POLICY_DIR, overlay);
    for (const f of readdirSync(dir).filter((f) => f.endsWith('.cedar')).sort()) {
      sources.push({ file: `${overlay}/${f}`, text: readFileSync(join(dir, f), 'utf8') });
    }
  }

  const staticPolicies: Record<string, string> = {};
  for (const { file, text } of sources) {
    const parts = cedar.policySetTextToParts(text);
    if (parts.type !== 'success') {
      throw new Error(`cedar failed to parse ${file}: ${JSON.stringify(parts.errors)}`);
    }
    for (const p of parts.policies) {
      const id = policyId(p, file);
      if (id in staticPolicies) throw new Error(`duplicate policy id ${id} (${file})`);
      staticPolicies[id] = p;
    }
  }

  // Strict validation is a load-time gate, not a warning. A policy set that does
  // not typecheck against the schema never reaches a decision.
  const validation = cedar.validate({
    schema,
    policies: { staticPolicies },
    validationSettings: { mode: 'strict' },
  });
  if (validation.type !== 'success') {
    throw new Error(`cedar validation failed: ${JSON.stringify(validation.errors)}`);
  }
  if (validation.validationErrors.length > 0) {
    throw new Error(
      `policy set does not typecheck: ${JSON.stringify(validation.validationErrors)}`,
    );
  }

  return {
    schema,
    staticPolicies,
    version: {
      id: versionId,
      // Hash covers the schema and every policy source, keyed by id, so a change
      // to any of them yields a different version.
      sha256: sha256Canonical({ schema, staticPolicies }),
      policyIds: Object.keys(staticPolicies).sort(),
      sourceFiles: sources.map((s) => s.file),
    },
  };
}

export interface EntityStore {
  entities: cedar.EntityJson[];
  sha256: string;
  byUid: Map<string, cedar.EntityJson>;
}

export function uidKey(type: string, id: string): string {
  return `${type}::"${id}"`;
}

export function loadEntities(extra: cedar.EntityJson[] = []): EntityStore {
  const base = JSON.parse(readFileSync(ENTITY_FILE, 'utf8')) as cedar.EntityJson[];
  const entities = [...base, ...extra];
  const byUid = new Map<string, cedar.EntityJson>();
  for (const e of entities) {
    const uid = e.uid as { type: string; id: string };
    byUid.set(uidKey(uid.type, uid.id), e);
  }
  return { entities, sha256: sha256(JSON.stringify(entities)), byUid };
}

export function engineVersions(): { cedar: string; cedarLang: string } {
  return { cedar: cedar.getCedarVersion(), cedarLang: cedar.getCedarLangVersion() };
}
