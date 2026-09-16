import { C2spTlogParseError } from './errors.ts';
import { parseJsonNoDuplicateMembers as parseStrictJson } from '@dnsid-ai/protocol';

const textDecoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Serializes a JSON value to its RFC 8785 (JCS-style) canonical form:
 * lexicographically sorted object members, no whitespace, valid Unicode.
 *
 * @throws C2spTlogParseError for non-finite or negative-zero numbers, unpaired
 *   surrogates, `undefined` members, or non-JSON values.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
    if (typeof value === 'number' && (!Number.isFinite(value) || Object.is(value, -0))) {
      throw new C2spTlogParseError('non-canonical JSON number');
    }
    if (typeof value === 'string') assertValidUnicode(value);
    return JSON.stringify(value)!;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj).sort().map((k) => {
      assertValidUnicode(k);
      const v = obj[k];
      if (v === undefined) throw new C2spTlogParseError('undefined is not JSON');
      return `${JSON.stringify(k)}:${canonicalJson(v)}`;
    }).join(',')}}`;
  }
  throw new C2spTlogParseError(`unsupported JSON value: ${typeof value}`);
}

/** Rejects strings containing unpaired UTF-16 surrogates. */
function assertValidUnicode(value: string): void {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new C2spTlogParseError('JSON contains an unpaired surrogate');
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new C2spTlogParseError('JSON contains an unpaired surrogate');
    }
  }
}

/** UTF-8 encoding of {@link canonicalJson}. */
export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJson(value));
}

/**
 * Parses UTF-8 JSON bytes, rejecting duplicate object member names anywhere in
 * the document.
 *
 * @throws C2spTlogParseError on invalid UTF-8, malformed JSON, or duplicate members.
 */
export function parseJsonNoDuplicateMembers(bytes: Uint8Array): unknown {
  try {
    return parseStrictJson(bytes);
  } catch (cause) {
    if (cause instanceof C2spTlogParseError) throw cause;
    throw new C2spTlogParseError(`malformed UTF-8 JSON: ${cause instanceof Error ? cause.message : String(cause)}`, cause);
  }
}

/**
 * Asserts that `bytes` are exactly the canonical JSON serialization of `value`
 * (which defaults to the parsed content of `bytes`).
 *
 * @throws C2spTlogParseError when the bytes are not canonical.
 */
export function assertCanonicalJsonBytes(bytes: Uint8Array, value = parseJsonNoDuplicateMembers(bytes)): void {
  const got = textDecoder.decode(bytes);
  const want = canonicalJson(value);
  if (got !== want) throw new C2spTlogParseError('entry bytes are not canonical JCS');
}
