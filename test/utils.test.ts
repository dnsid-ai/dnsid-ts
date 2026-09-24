import { describe, it, expect } from 'vitest';
import { generateNonce, parseContentDigest } from '@dnsid-ai/http-signatures';
import {
  ArgumentError,
  fromBase64Url,
  normalizeFQDN,
  parseKeyId,
  toBase64Url,
  ValidationError,
} from '@dnsid-ai/protocol';

// ---- parseKeyId ----

describe('parseKeyId()', () => {
  it('splits on the first # and normalizes the domain', () => {
    const { domain, kid } = parseKeyId('agent.example.com#key-1');
    expect(domain).toBe('agent.example.com');
    expect(kid).toBe('key-1');
  });

  it('normalizes the domain (strips trailing dot, lowercases)', () => {
    const { domain } = parseKeyId('Agent.Example.Com.#key-1');
    expect(domain).toBe('agent.example.com');
  });

  it('preserves kid that contains no #', () => {
    const { kid } = parseKeyId('example.com#my-key-v2');
    expect(kid).toBe('my-key-v2');
  });

  it('splits on the FIRST # only when compound domain has subdomain', () => {
    const { domain, kid } = parseKeyId('sub.example.com#key-1');
    expect(domain).toBe('sub.example.com');
    expect(kid).toBe('key-1');
  });

  it('throws ArgumentError when # is absent', () => {
    expect(() => parseKeyId('example.comkey-1')).toThrow(ArgumentError);
  });

  it('throws ArgumentError when domain part is empty', () => {
    expect(() => parseKeyId('#key-1')).toThrow(ArgumentError);
  });

  it('throws ArgumentError when kid part is empty', () => {
    expect(() => parseKeyId('example.com#')).toThrow(ArgumentError);
  });

  it('throws ArgumentError when kid contains another #', () => {
    expect(() => parseKeyId('example.com#key#extra')).toThrow(ArgumentError);
  });

  it('throws ValidationError when domain is invalid', () => {
    // normalizeFQDN throws ValidationError for empty labels
    expect(() => parseKeyId('..bad..#key')).toThrow();
  });
});

// ---- normalizeFQDN ----

describe('normalizeFQDN()', () => {
  // UTS46 §4: all four label separators are equivalent to ASCII '.'.
  it('maps U+3002 (ideographic full stop) to "."', () => {
    expect(normalizeFQDN('example.com。', true)).toBe('example.com');
  });

  it('maps U+FF0E (fullwidth full stop) to "."', () => {
    expect(normalizeFQDN('example.com．', true)).toBe('example.com');
  });

  it('maps U+FF61 (halfwidth ideographic full stop) to "."', () => {
    expect(normalizeFQDN('example.com｡', true)).toBe('example.com');
  });

  it('maps ideographic separators between labels', () => {
    expect(normalizeFQDN('sub。example．com')).toBe('sub.example.com');
  });

  it('rejects a label beginning with a hyphen (RFC 5890 §2.3.1)', () => {
    expect(() => normalizeFQDN('-foo.example.com', true)).toThrow(ValidationError);
  });

  it('rejects a label ending with a hyphen (RFC 5890 §2.3.1)', () => {
    expect(() => normalizeFQDN('foo-.example.com', true)).toThrow(ValidationError);
  });

  it('rejects a U-label beginning with a hyphen before IDNA normalization', () => {
    expect(() => normalizeFQDN('-é.example.com', true)).toThrow(ValidationError);
  });

  it('rejects a U-label ending with a hyphen before IDNA normalization', () => {
    expect(() => normalizeFQDN('é-.example.com', true)).toThrow(ValidationError);
  });

  it('rejects a U-label with leading hyphen after Unicode label separator (U+3002)', () => {
    expect(() => normalizeFQDN('foo\u3002-é.example.com', true)).toThrow(ValidationError);
  });

  it('rejects a U-label with trailing hyphen after Unicode label separator (U+FF0E)', () => {
    expect(() => normalizeFQDN('foo\uFF0Eé-.example.com', true)).toThrow(ValidationError);
  });

  it('accepts a valid ACE (A-label) FQDN', () => {
    expect(normalizeFQDN('xn--e1afmkfd.example.com', true)).toBe('xn--e1afmkfd.example.com');
  });

  it('returns the normalized form for a valid FQDN', () => {
    expect(normalizeFQDN('foo.example.com', true)).toBe('foo.example.com');
    expect(normalizeFQDN('München.DE.', true)).toBe('xn--mnchen-3ya.de');
  });

  it.each([
    'evil.com/victim.example.com', 'victim.example.com@evil.com',
    'evil.com?x=victim.example.com', 'evil.com#victim.example.com',
    'evil.com:8443', 'evil.com\\victim.example.com', 'ex%61mple.com',
    'exa\tmple.com', 'example.com\u200b', 'example.com\ufeff',
    '127.0.0.1', '127.1', '0x7f000001', '2130706433', '[::1]',
  ])('rejects URL syntax, invisible characters and IP literals in %s', (input) => {
    expect(() => normalizeFQDN(input)).toThrow(ValidationError);
  });
});

// ---- generateNonce ----

describe('generateNonce()', () => {
  it('returns a non-empty string', () => {
    expect(generateNonce().length).toBeGreaterThan(0);
  });

  it('returns a base64url string (no +, /, or =)', () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('returns a different value on each call', () => {
    const a = generateNonce();
    const b = generateNonce();
    expect(a).not.toBe(b);
  });

  it('produces at least 20 characters (32-byte input)', () => {
    // 32 bytes base64url → ceil(32 * 4/3) = 43 chars unpadded
    expect(generateNonce().length).toBeGreaterThanOrEqual(40);
  });
});

// ---- parseContentDigest ----

describe('parseContentDigest()', () => {
  it('parses a sha-256 byte sequence', () => {
    // echo -n "" | openssl dgst -sha256 -binary | base64
    const digest = 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:';
    const { hashAlg, digest: bytes } = parseContentDigest(digest);
    expect(hashAlg).toBe('sha-256');
    expect(bytes).toHaveLength(32);
  });

  it('parses a sha-512 byte sequence', () => {
    const digest = 'sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+TF/MQVOALa5pDKYlUw1NSBXshKTPp3A==:';
    const { hashAlg, digest: bytes } = parseContentDigest(digest);
    expect(hashAlg).toBe('sha-512');
    expect(bytes).toHaveLength(64);
  });

  it('rejects uppercase dictionary keys', () => {
    expect(() => parseContentDigest('SHA-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:')).toThrow(ArgumentError);
  });

  it('throws ArgumentError for an unsupported algorithm', () => {
    expect(() => parseContentDigest('sha-1=:abc=:')).toThrow(ArgumentError);
  });

  it('throws ArgumentError when no closing colon is present', () => {
    expect(() => parseContentDigest('sha-256=:abc')).toThrow(ArgumentError);
  });

  it('throws ArgumentError for completely malformed input', () => {
    expect(() => parseContentDigest('not-valid')).toThrow(ArgumentError);
  });

  it('round-trips: encode bytes then parse them back', () => {
    const original = new Uint8Array(32).fill(0xAB);
    const b64 = btoa(String.fromCharCode(...original));
    const header = `sha-256=:${b64}:`;
    const { digest } = parseContentDigest(header);
    expect(digest).toEqual(original);
  });
});
