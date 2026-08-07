import { createHash } from 'node:crypto';

/**
 * Canonical JSON: object keys sorted, no incidental whitespace, arrays in order.
 *
 * The hash chain is only meaningful if two runs that produced the same content
 * serialise identically, so serialisation is pinned here rather than left to
 * JSON.stringify's insertion-order behaviour.
 *
 * Numbers are emitted by JSON.stringify. That is exact for the integers this
 * artifact uses (logical clocks, byte counts); it is not safe for floats, and
 * nothing here produces one.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return (
    '{' +
    keys
      .filter((k) => obj[k] !== undefined)
      .map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k]))
      .join(',') +
    '}'
  );
}

export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

export function sha256Canonical(value: unknown): string {
  return sha256(canonicalJson(value));
}
