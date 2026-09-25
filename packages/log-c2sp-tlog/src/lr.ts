import { C2spTlogParseError } from './errors.ts';
import { b64url } from './base64.ts';

/** Deployment scope of a c2sp-tlog reference; `public` additionally requires HTTPS and a non-zero witness quorum. All scopes require chaining; lifecycle reads require witnessed checkpoints. */
export type C2spTlogScope = 'public' | 'testnet' | `private-${string}`;

/** Components of a parsed `c2sp-tlog:<scope>:<logPrefix>#<streamId>[@index]` log reference. */
export interface ParsedC2spTlogLr {
  method: 'c2sp-tlog';
  scope: C2spTlogScope;
  logPrefix: string;
  streamId: string;
  origin: string;
  /** Canonical bound reference without an entry index. */
  lr: string;
  entryIndex?: number;
}

const METHOD = 'c2sp-tlog:';
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const STREAM_ID_BYTES = 16;

/**
 * Generates an opaque identity-instance stream ID using 128 bits of
 * cryptographically secure randomness, encoded as unpadded base64url.
 */
export function generateC2spTlogStreamId(): string {
  const bytes = new Uint8Array(STREAM_ID_BYTES);
  crypto.getRandomValues(bytes);
  return b64url(bytes);
}

/**
 * Parses and validates a `c2sp-tlog:` log reference as published in an
 * identity record's `lr` tag, requiring an already-canonical log prefix.
 *
 * @throws C2spTlogParseError when any component is missing or non-canonical.
 */
export function parseC2spTlogLr(lr: string): ParsedC2spTlogLr {
  if (!lr.startsWith(METHOD)) throw new C2spTlogParseError('lr must start with c2sp-tlog:');
  const rest = lr.slice(METHOD.length);
  const colon = rest.indexOf(':');
  if (colon <= 0) throw new C2spTlogParseError('missing c2sp-tlog scope');
  const scope = rest.slice(0, colon);
  validateScope(scope);
  const tail = rest.slice(colon + 1);
  const hash = tail.lastIndexOf('#');
  if (hash <= 0 || hash === tail.length - 1) throw new C2spTlogParseError('missing log prefix or stream id');
  const rawLogPrefix = tail.slice(0, hash);
  const logPrefix = canonicalLogPrefix(rawLogPrefix);
  if (rawLogPrefix !== logPrefix) throw new C2spTlogParseError('log prefix must already be canonical');
  const ref = tail.slice(hash + 1);
  const at = ref.lastIndexOf('@');
  const streamId = at === -1 ? ref : ref.slice(0, at);
  if (!/^(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})+$/.test(streamId)) throw new C2spTlogParseError('invalid stream id');
  const entryIndex = at === -1 ? undefined : parseIndex(ref.slice(at + 1));
  const origin = checkpointOrigin(logPrefix);
  validateSignedNoteName(origin);
  if (scope === 'public' && !logPrefix.startsWith('https://')) throw new C2spTlogParseError('public c2sp-tlog requires an https log prefix');
  const boundLr = `${METHOD}${scope}:${logPrefix}#${streamId}`;
  return { method: 'c2sp-tlog', scope: scope as C2spTlogScope, logPrefix, streamId, origin, lr: boundLr, entryIndex };
}

/**
 * Asserts that `scope` is a valid {@link C2spTlogScope}.
 *
 * @throws C2spTlogParseError otherwise.
 */
export function validateScope(scope: string): asserts scope is C2spTlogScope {
  if (scope !== 'public' && scope !== 'testnet' && !/^private-[A-Za-z0-9-]+$/.test(scope)) {
    throw new C2spTlogParseError(`invalid c2sp-tlog scope: ${scope}`);
  }
}

/**
 * Canonicalizes a log-prefix URL: lowercase scheme and host, default ports and
 * trailing slash removed, percent-encoding normalized.
 *
 * @throws C2spTlogParseError for userinfo, query/fragment, dot segments,
 *   encoded slashes, unsupported schemes, or TXT-delimiter characters.
 */
export function canonicalLogPrefix(raw: string): string {
  if (/[;\s]/.test(raw)) throw new C2spTlogParseError('log prefix must percent-encode DNS TXT tag delimiters');
  const rawPath = raw.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i, '') || '/';
  if (/(^|\/)\.\.?($|\/)/.test(rawPath)) throw new C2spTlogParseError('log prefix must not contain dot segments');
  let url: URL;
  try { url = new URL(raw); } catch (cause) { throw new C2spTlogParseError(`invalid log prefix URL: ${cause}`); }
  if (url.username || url.password) throw new C2spTlogParseError('log prefix must not contain userinfo');
  if (url.search || url.hash) throw new C2spTlogParseError('log prefix must not contain query or fragment');
  if (url.pathname !== '/' && url.pathname.endsWith('/')) throw new C2spTlogParseError('log prefix must not have trailing slash');
  if (/%2f|%5c/i.test(url.pathname)) throw new C2spTlogParseError('log prefix must not percent-encode slash or backslash');
  const scheme = url.protocol.toLowerCase();
  if (scheme !== 'https:' && scheme !== 'http:') throw new C2spTlogParseError('unsupported log prefix scheme');
  url.protocol = scheme;
  url.hostname = url.hostname.toLowerCase();
  if ((scheme === 'https:' && url.port === '443') || (scheme === 'http:' && url.port === '80')) url.port = '';
  url.pathname = normalizePercentPath(url.pathname);
  const out = url.toString();
  return out.endsWith('/') ? out.slice(0, -1) : out;
}

/** Derives the C2SP checkpoint origin (host plus path, no scheme) from a canonical log prefix. */
export function checkpointOrigin(logPrefix: string): string {
  const u = new URL(logPrefix);
  return `${u.host}${u.pathname}`.replace(/\/$/, '');
}

function parseIndex(s: string): number {
  if (!/^(0|[1-9][0-9]*)$/.test(s)) throw new C2spTlogParseError('invalid entry index');
  const n = Number(s);
  if (!Number.isSafeInteger(n) || n > MAX_SAFE) throw new C2spTlogParseError('entry index outside safe integer range');
  return n;
}

function normalizePercentPath(path: string): string {
  return path.replace(/%[0-9a-fA-F]{2}/g, (m) => {
    const byte = Number.parseInt(m.slice(1), 16);
    const ch = String.fromCharCode(byte);
    return /[A-Za-z0-9._~-]/.test(ch) ? ch : m.toUpperCase();
  });
}

function validateSignedNoteName(name: string): void {
  if (!/^[\x21-\x7e]+$/.test(name) || /[\s+]/.test(name)) {
    throw new C2spTlogParseError(`invalid signed-note key name: ${name}`);
  }
}
