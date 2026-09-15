import { importJWK } from 'jose';
import type { JWK } from 'jose';
import { ValidationError, ArgumentError } from './errors.ts';
import type { DnsIdJWK } from './types.ts';
import { jwkSignatureAlg } from './jwks.ts';

const MAX_FQDN_OCTETS = 253;
const MAX_AGENT_FQDN_OCTETS = 246;
const MAX_LABEL_OCTETS = 63;

/**
 * Converts IDNA U-labels to A-label punycode, lowercases ASCII, strips one trailing root dot,
 * and validates DNS label constraints.
 *
 * @throws ValidationError if the name is empty, contains empty labels, has any label over 63 octets,
 *         exceeds the 253-octet DNS limit, or (when agentFQDN=true) exceeds the 246-octet DNSid agent limit.
 */
export function normalizeFQDN(name: string, agentFQDN = false): string {
  if (!name) throw new ValidationError('FQDN cannot be empty');

  // UTS46 §4: all four label separators are equivalent to ASCII '.'. Map them
  // before any dot-based processing so the trailing-dot strip below handles them.
  name = name.replace(/[。．｡]/g, '.');

  // Strip exactly one trailing root dot before passing to the URL parser.
  const withoutTrailingDot = name.endsWith('.') ? name.slice(0, -1) : name;

  if (!withoutTrailingDot) throw new ValidationError('FQDN cannot be empty after normalization');

  // RFC 5890 §2.3.1 LDH: labels may not begin or end with a hyphen. Check the raw input
  // labels first — IDNA/punycode conversion masks this (e.g. "-é" → "xn--..." no longer
  // starts with a hyphen), so a post-normalization check alone misses malformed U-labels.
  // Split on all IDNA label separators: '.' (U+002E), '。' (U+3002), '．' (U+FF0E), '｡' (U+FF61).
  for (const label of withoutTrailingDot.split(/[.\u3002\uFF0E\uFF61]/)) {
    if (label.startsWith('-') || label.endsWith('-')) {
      throw new ValidationError(`DNS label may not begin or end with a hyphen: ${label}`);
    }
  }

  // Use the WHATWG URL parser to convert IDNA U-labels to A-label punycode and
  // lowercase the result. Available in Node.js 18+ and all modern browsers.
  // Example: münchen.DE → xn--mnchen-3ya.de
  let normalized: string;
  try {
    normalized = new URL(`https://${withoutTrailingDot}`).hostname;
  } catch {
    throw new ValidationError(`FQDN is not a valid domain name: ${name}`);
  }

  if (!normalized) throw new ValidationError('FQDN cannot be empty after normalization');

  const labels = normalized.split('.');
  for (const label of labels) {
    if (!label) throw new ValidationError(`FQDN contains empty label: ${name}`);
    // RFC 5890 §2.3.1 LDH: labels may not begin or end with a hyphen. The WHATWG
    // URL/IDNA parser does not enforce this, so check it explicitly.
    if (label.startsWith('-') || label.endsWith('-')) {
      throw new ValidationError(`DNS label may not begin or end with a hyphen: ${label}`);
    }
    if (new TextEncoder().encode(label).length > MAX_LABEL_OCTETS) {
      throw new ValidationError(`DNS label exceeds 63 octets: ${label}`);
    }
  }

  const fqdnBytes = new TextEncoder().encode(normalized).length;
  if (fqdnBytes > MAX_FQDN_OCTETS) {
    throw new ValidationError(`FQDN exceeds 253-octet DNS presentation limit: ${name}`);
  }
  if (agentFQDN && fqdnBytes > MAX_AGENT_FQDN_OCTETS) {
    throw new ValidationError(`Agent FQDN exceeds 246-octet DNSid limit: ${name}`);
  }

  return normalized;
}

/**
 * Checks whether a string is a valid domain name (for gi consistency checks).
 * Returns true if the value looks like a domain name (as opposed to a URI or other identifier).
 */
export function isDomainName(value: string): boolean {
  const v = value.endsWith('.') ? value.slice(0, -1) : value;
  // Domain names consist of labels of [a-z0-9] and hyphens, separated by dots.
  // A URI (e.g. "https://...") or a log ref (e.g. "algorand:ADDR") will not match.
  return /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/.test(v);
}

/**
 * Parses the DNSid SDK's cross-profile compound key ID convention: "{domain}#{kid}".
 *
 * This is an SDK/profile convention used by packages such as @identity-digital/dnsid-jose and
 * @identity-digital/dnsid-http-signatures to bind a profile-level key reference to a DNSid agent
 * FQDN plus a JWKS "kid". It is not a DNSid protocol wire-format requirement;
 * the protocol itself only requires JWKS keys to carry "kid" values.
 *
 * Splits on the first '#', normalizes the domain side with normalizeFQDN(),
 * and rejects if either side is empty or the kid side contains another '#'.
 *
 * @throws ArgumentError if the key ID is malformed.
 */
export function parseKeyId(keyId: string): { domain: string; kid: string } {
  const hashIdx = keyId.indexOf('#');
  if (hashIdx === -1) {
    throw new ArgumentError(`key ID must contain '#' separator: ${keyId}`);
  }
  const domainPart = keyId.slice(0, hashIdx);
  const kidPart = keyId.slice(hashIdx + 1);
  if (!domainPart) {
    throw new ArgumentError(`key ID domain part is empty: ${keyId}`);
  }
  if (!kidPart) {
    throw new ArgumentError(`key ID kid part is empty: ${keyId}`);
  }
  if (kidPart.includes('#')) {
    throw new ArgumentError(`key ID kid part must not contain '#': ${keyId}`);
  }
  let domain: string;
  try {
    domain = normalizeFQDN(domainPart);
  } catch (e) {
    throw new ArgumentError(`key ID domain part is not a valid FQDN: ${keyId} — ${(e as Error).message}`);
  }
  return { domain, kid: kidPart };
}

/**
 * Encodes a Uint8Array to unpadded base64url (RFC 7515 §2).
 */
export function toBase64Url(bytes: Uint8Array): string {
  // Use btoa for environments where Buffer is not available
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Decodes a base64url string (accepts both padded and unpadded forms) to Uint8Array.
 */
export function fromBase64Url(b64: string): Uint8Array {
  // Normalize to standard base64
  const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '=='.slice(0, (4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Parses a duration string (as used in the `ka` tag) to milliseconds.
 * Valid values: "24h", "7d", "30d", "90d".
 */
export function parseKaDuration(ka: string): number {
  switch (ka) {
    case '24h': return 24 * 60 * 60 * 1000;
    case '7d':  return  7 * 24 * 60 * 60 * 1000;
    case '30d': return 30 * 24 * 60 * 60 * 1000;
    case '90d': return 90 * 24 * 60 * 60 * 1000;
    default: throw new ArgumentError(`invalid ka value: ${ka}`);
  }
}

/**
 * Returns a Uint8Array<ArrayBuffer> view over the same memory — no copy.
 * Required because WebCrypto's BufferSource only accepts ArrayBuffer-backed views,
 * not the default Uint8Array<ArrayBufferLike> that TypeScript infers.
 */
export function toArrayBuffer(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes.buffer as ArrayBuffer, bytes.byteOffset, bytes.byteLength);
}

/** Maps a JOSE alg name to the WebCrypto verify algorithm params. */
function getVerifyAlgorithm(alg: string): object {
  switch (alg) {
    case 'ES256': return { name: 'ECDSA', hash: 'SHA-256' };
    case 'ES384': return { name: 'ECDSA', hash: 'SHA-384' };
    case 'ES512': return { name: 'ECDSA', hash: 'SHA-512' };
    case 'EdDSA': return { name: 'Ed25519' };
    case 'RS256': return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    case 'RS384': return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' };
    case 'RS512': return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' };
    case 'PS256': return { name: 'RSA-PSS', saltLength: 32 };
    case 'PS384': return { name: 'RSA-PSS', saltLength: 48 };
    case 'PS512': return { name: 'RSA-PSS', saltLength: 64 };
    default: throw new ArgumentError(`unsupported algorithm for verification: ${alg}`);
  }
}

/**
 * RFC 9525 §4 dNSName SAN matching.
 * Returns true when at least one SAN entry matches the given FQDN.
 * Supports case-insensitive comparison, trailing-dot normalisation, and
 * wildcard labels (only leftmost `*.` matching one or more labels at depth > 0).
 */
export function matchesDnsName(san: string[], fqdn: string): boolean {
  const target = fqdn.replace(/\.$/, '').toLowerCase();
  if (!target) return false;
  for (const entry of san) {
    const name = entry.replace(/\.$/, '').toLowerCase();
    if (name === target) return true;
    // Wildcard: RFC 9525 §4 — only leftmost label, must have at least one dot remaining
    if (name.startsWith('*.')) {
      const suffix = name.slice(2); // e.g. "example.com" from "*.example.com"
      const dotIdx = target.indexOf('.');
      if (dotIdx > 0 && target.slice(dotIdx + 1) === suffix) return true;
    }
  }
  return false;
}

/**
 * Verifies a signing input against a raw signature using a public JWK.
 * Returns true if the signature is valid, false otherwise.
 */
export async function verifyWithKey(signingInput: string | Uint8Array, signature: Uint8Array, key: DnsIdJWK, expectedAlg?: string): Promise<boolean> {
  try {
    const alg = jwkSignatureAlg(key);
    if (expectedAlg !== undefined && alg !== expectedAlg) return false;
    const cryptoKey = await importJWK(key as unknown as JWK, alg) as CryptoKey;
    const algorithm = getVerifyAlgorithm(alg);
    const message = typeof signingInput === 'string'
      ? new TextEncoder().encode(signingInput)
      : signingInput;
    return await crypto.subtle.verify(algorithm as AlgorithmIdentifier, cryptoKey, toArrayBuffer(signature), toArrayBuffer(message));
  } catch {
    return false;
  }
}
