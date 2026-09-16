import { describe, it, expect } from 'vitest';
import { jwkThumbprint, keySetsShareKeyMaterial, JWKS, ValidationError } from '@dnsid-ai/protocol';
import type { DnsIdJWK } from '@dnsid-ai/protocol';

// ---- Test vectors ----

// RFC 7638 §3.1 example key
const RFC7638_KEY: DnsIdJWK = {
  kty: 'RSA',
  kid: 'rfc7638-example',
  alg: 'RS256',
  e: 'AQAB',
  n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
  // RFC 7638 §3.1 expected thumbprint (SHA-256): NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
};

const EC_P256: DnsIdJWK = {
  kty: 'EC',
  kid: 'ec-p256',
  alg: 'ES256',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};

const ED25519: DnsIdJWK = {
  kty: 'OKP',
  kid: 'ed-1',
  alg: 'EdDSA',
  crv: 'Ed25519',
  x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
};

describe('jwkThumbprint()', () => {
  it('returns a string', async () => {
    const tp = await jwkThumbprint(EC_P256);
    expect(typeof tp).toBe('string');
  });

  it('returns an unpadded base64url string (no + / =)', async () => {
    const tp = await jwkThumbprint(EC_P256);
    expect(tp).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('returns the same thumbprint for the same key on repeated calls', async () => {
    const tp1 = await jwkThumbprint(EC_P256);
    const tp2 = await jwkThumbprint(EC_P256);
    expect(tp1).toBe(tp2);
  });

  it('returns different thumbprints for different keys', async () => {
    const tp1 = await jwkThumbprint(EC_P256);
    const tp2 = await jwkThumbprint(ED25519);
    expect(tp1).not.toBe(tp2);
  });

  it('ignores non-required JWK fields (kid, alg, use) when computing thumbprint', async () => {
    const keyWithExtras: DnsIdJWK = { ...EC_P256, kid: 'different-kid', alg: 'ES384', use: 'sig' };
    const tp1 = await jwkThumbprint(EC_P256);
    const tp2 = await jwkThumbprint(keyWithExtras);
    // RFC 7638 includes only the required members for the key type, so kid/alg/use are excluded
    expect(tp1).toBe(tp2);
  });

  it('returns the known RFC 7638 §3.1 thumbprint for the example RSA key', async () => {
    const tp = await jwkThumbprint(RFC7638_KEY);
    expect(tp).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  });

  it('computes an OKP Ed25519 thumbprint without throwing', async () => {
    await expect(jwkThumbprint(ED25519)).resolves.toBeTypeOf('string');
  });
});

describe('keySetsShareKeyMaterial()', () => {
  it('returns false for completely disjoint key sets', async () => {
    const a = new JWKS([EC_P256]);
    const b = new JWKS([ED25519]);
    await expect(keySetsShareKeyMaterial(a, b)).resolves.toBe(false);
  });

  it('returns true when a key appears in both sets', async () => {
    const a = new JWKS([EC_P256, RFC7638_KEY]);
    const b = new JWKS([ED25519, EC_P256]);
    await expect(keySetsShareKeyMaterial(a, b)).resolves.toBe(true);
  });

  it('detects a collision based on key material even if kid/alg/use differ', async () => {
    const a = new JWKS([EC_P256]);
    const relabeled: DnsIdJWK = { ...EC_P256, kid: 'different-kid', alg: 'ES384', use: 'sig' };
    const b = new JWKS([ED25519, relabeled]);
    await expect(keySetsShareKeyMaterial(a, b)).resolves.toBe(true);
  });

  it('returns false when the first set (ek) is empty', async () => {
    const a = new JWKS([]);
    const b = new JWKS([ED25519]);
    await expect(keySetsShareKeyMaterial(a, b)).resolves.toBe(false);
  });

  it('returns false when the second set (ku) is empty', async () => {
    const a = new JWKS([EC_P256]);
    const b = new JWKS([]);
    await expect(keySetsShareKeyMaterial(a, b)).resolves.toBe(false);
  });

  it('returns false when both sets are empty', async () => {
    await expect(keySetsShareKeyMaterial(new JWKS([]), new JWKS([]))).resolves.toBe(false);
  });

  it('throws a normalized ValidationError when a malformed key in ek cannot be thumbprinted', async () => {
    // EC key missing required crv/x/y — cannot compute RFC 7638 thumbprint
    const malformed = { kty: 'EC', kid: 'bad-ek', use: 'enc' } as DnsIdJWK;
    const a = new JWKS([EC_P256, malformed]);
    const b = new JWKS([ED25519]);
    await expect(keySetsShareKeyMaterial(a, b)).rejects.toThrow(ValidationError);
    const err = await keySetsShareKeyMaterial(a, b).catch(e => e);
    expect(err.message).toContain('malformed key in ek JWK Set');
    expect(err.message).toContain('bad-ek');
  });

  it('throws a normalized ValidationError when a malformed key in ku cannot be thumbprinted', async () => {
    const malformed = { kty: 'EC', kid: 'bad-ku', use: 'enc' } as DnsIdJWK;
    const a = new JWKS([EC_P256]);
    const b = new JWKS([ED25519, malformed]);
    await expect(keySetsShareKeyMaterial(a, b)).rejects.toThrow(ValidationError);
    const err = await keySetsShareKeyMaterial(a, b).catch(e => e);
    expect(err.message).toContain('malformed key in ku JWK Set');
    expect(err.message).toContain('bad-ku');
  });

  it('checks distinctness across non-current (non-signing) keys in both sets', async () => {
    // Simulates a scenario where the "current" signing keys are distinct, but a
    // rotated/non-current key still published in one set collides with a key in the other.
    // This exercises the full-set pairwise check against non-current key set entries.
    const currentEk = EC_P256;
    const currentKu = ED25519;
    // A rotated ek entry that shares material with the ku signing key
    const rotatedEkMatchingKu: DnsIdJWK = { ...ED25519, kid: 'rotated-ek', use: 'enc' };
    const a = new JWKS([currentEk, rotatedEkMatchingKu]);
    const b = new JWKS([currentKu]);
    // Even though current signing keys are distinct, the rotated entry causes a collision
    await expect(keySetsShareKeyMaterial(a, b)).resolves.toBe(true);
  });

  it('checks distinctness when non-current ku entry collides with an ek key', async () => {
    const currentEk = EC_P256;
    const currentKu = ED25519;
    // A deactivated ku entry that shares material with the ek signing key
    const deactivatedKuMatchingEk: DnsIdJWK = { ...EC_P256, kid: 'old-ku', use: 'enc' };
    const a = new JWKS([currentEk]);
    const b = new JWKS([currentKu, deactivatedKuMatchingEk]);
    await expect(keySetsShareKeyMaterial(a, b)).resolves.toBe(true);
  });
});
