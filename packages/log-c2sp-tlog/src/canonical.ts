import { C2spTlogParseError, C2spTlogResourceLimitError } from './errors.ts';
import { parseJsonNoDuplicateMembers as parseStrictJson } from '@dnsid-ai/protocol';

// ignoreBOM keeps a leading U+FEFF, so BOM-prefixed entry bytes fail the canonical comparison.
const textDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

// Match Go jsonutil.decodeValue: root depth 0, every member/element value adds 1.
// Empty containers at depth 64 are allowed; any value at depth 65 is fatal.
const MAX_JSON_DEPTH = 64;

/** Iterative scan before parsing; brackets and escaped quotes inside strings do not count. */
function assertJsonDepth(bytes: Uint8Array): void {
  let depth = 0;
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte === 0x7d || byte === 0x5d) { depth--; continue; }
    if (byte === 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0d || byte === 0x2c || byte === 0x3a) continue;
    if (byte === 0x22) {
      while (++i < bytes.length && bytes[i] !== 0x22) {
        if (bytes[i] === 0x5c) i++;
      }
      let next = i + 1;
      while ([0x20, 0x09, 0x0a, 0x0d].includes(bytes[next]!)) next++;
      if (bytes[next] === 0x3a) continue; // Member names are not values.
    }
    if (depth > MAX_JSON_DEPTH) throw new C2spTlogResourceLimitError('JSON nesting limit exceeded (64)');
    if (byte === 0x7b || byte === 0x5b) depth++;
  }
}

/**
 * Serializes a JSON value to its RFC 8785 (JCS-style) canonical form:
 * lexicographically sorted object members, no whitespace, valid Unicode.
 *
 * @throws C2spTlogParseError for non-finite or negative-zero numbers, unpaired
 *   surrogates, `undefined` members, or non-JSON values.
 * @throws C2spTlogResourceLimitError for value depth above 64 (root depth 0).
 */
export function canonicalJson(value: unknown): string {
  const pending = [{ value, depth: 0 }];
  while (pending.length > 0) {
    const { value: current, depth } = pending.pop()!;
    if (depth > MAX_JSON_DEPTH) throw new C2spTlogResourceLimitError('JSON nesting limit exceeded (64)');
    if (current !== null && typeof current === 'object') {
      for (const child of Object.values(current)) pending.push({ value: child, depth: depth + 1 });
    }
  }
  return serializeJson(value);
}

function serializeJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
    if (typeof value === 'number' && (!Number.isFinite(value) || Object.is(value, -0))) {
      throw new C2spTlogParseError('non-canonical JSON number');
    }
    if (typeof value === 'string') assertValidUnicode(value);
    return JSON.stringify(value)!;
  }
  if (Array.isArray(value)) return `[${value.map(serializeJson).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj).sort().map((k) => {
      assertValidUnicode(k);
      const v = obj[k];
      if (v === undefined) throw new C2spTlogParseError('undefined is not JSON');
      return `${JSON.stringify(k)}:${serializeJson(v)}`;
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
 * @throws C2spTlogResourceLimitError for value depth above 64 (root depth 0).
 */
export function parseJsonNoDuplicateMembers(bytes: Uint8Array): unknown {
  assertJsonDepth(bytes);
  try {
    return parseStrictJson(bytes);
  } catch (cause) {
    if (cause instanceof RangeError) throw new C2spTlogResourceLimitError('JSON parser resource limit exceeded', cause);
    if (cause instanceof C2spTlogParseError || cause instanceof C2spTlogResourceLimitError) throw cause;
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
