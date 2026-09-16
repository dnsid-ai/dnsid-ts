import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest';
import { generateKeyPair, exportJWK } from 'jose';
import { JoseProfile } from '@dnsid-ai/jose';
import {
  ArgumentError,
  fromBase64Url,
  IdentityManager,
  toArrayBuffer,
  toBase64Url,
  VerificationCode,
  VerificationError,
} from '@dnsid-ai/protocol';
import type { IdentityConfig, DnsIdJWK, KeyProvider } from '@dnsid-ai/protocol';
import { currentProfileFixture } from './helpers/current-profile.ts';

const mockFetchJson = vi.hoisted(() => vi.fn());

vi.mock('../packages/transport/src/index.ts', () => ({
  fetchJson: mockFetchJson,
}));

// ---- shared key pair ----

let privateKey: CryptoKey;
let publicJwk: DnsIdJWK;

beforeAll(async () => {
  const kp = await generateKeyPair('ES256');
  privateKey = kp.privateKey;
  const raw = await exportJWK(kp.publicKey);
  publicJwk = { ...raw, kty: raw.kty!, alg: 'ES256', kid: 'key-1', use: 'sig' } as DnsIdJWK;
});

async function signWithKey(bytes: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, toArrayBuffer(bytes));
  return new Uint8Array(sig);
}

function makeKeyProvider(): KeyProvider {
  return {
    signingKey: vi.fn().mockImplementation(() => Promise.resolve(publicJwk)),
    jwk: vi.fn().mockResolvedValue(publicJwk),
    listKeyIds: vi.fn().mockResolvedValue(['key-1']),
    sign: vi.fn().mockImplementation((bytes: Uint8Array) => signWithKey(bytes)),
    signKey: vi.fn().mockImplementation((_kid: string, bytes: Uint8Array) => signWithKey(bytes)),
    generateKey: vi.fn(),
    activate: vi.fn(),
    supersede: vi.fn(),
    purge: vi.fn(),
  };
}

const ISSUER_DOMAIN = 'issuer.example.com';
const VERIFIER_CONFIG: IdentityConfig = {
  domain: 'verifier.example.com',
  governanceId: 'example.com',
  logRef: 'microledger:v',
  statusUrl: 'https://verifier.example.com/status',
};
const ISSUER_CONFIG: IdentityConfig = {
  domain: ISSUER_DOMAIN,
  governanceId: 'example.com',
  logRef: 'microledger:i',
  statusUrl: `https://${ISSUER_DOMAIN}/status`,
};

const resolverStub = { verifyDomain: vi.fn() };

beforeEach(() => { mockFetchJson.mockReset(); });

// ---- createJWT ----

describe('JoseProfile.createJWT()', () => {
  it('throws ArgumentError when audience is empty', async () => {
    const profile = new JoseProfile({ domain: ISSUER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    await expect(profile.createJWT({ audience: '' })).rejects.toThrow(ArgumentError);
  });

  it('returns a 3-part dot-delimited string', async () => {
    const profile = new JoseProfile({ domain: ISSUER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const jwt = await profile.createJWT({ audience: 'verifier.example.com' });
    expect(jwt.split('.')).toHaveLength(3);
  });

  it('sets iss and sub to config.domain', async () => {
    const profile = new JoseProfile({ domain: ISSUER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const jwt = await profile.createJWT({ audience: 'verifier.example.com' });
    const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(jwt.split('.')[1]!)));
    expect(payload.iss).toBe(ISSUER_DOMAIN);
    expect(payload.sub).toBe(ISSUER_DOMAIN);
  });

  it('sets aud to the normalized audience', async () => {
    const profile = new JoseProfile({ domain: ISSUER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const jwt = await profile.createJWT({ audience: 'Verifier.Example.Com' });
    const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(jwt.split('.')[1]!)));
    expect(payload.aud).toBe('verifier.example.com');
  });

  it('sets exp to iat + default 900 seconds when no expiry given', async () => {
    const before = Math.floor(Date.now() / 1000);
    const profile = new JoseProfile({ domain: ISSUER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const jwt = await profile.createJWT({ audience: 'verifier.example.com' });
    const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(jwt.split('.')[1]!)));
    expect(payload.exp - payload.iat).toBe(900);
    expect(payload.iat).toBeGreaterThanOrEqual(before);
  });

  it('sets exp to iat + custom expiry when provided', async () => {
    const profile = new JoseProfile({ domain: ISSUER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const jwt = await profile.createJWT({ audience: 'verifier.example.com', expiry: 60 });
    const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(jwt.split('.')[1]!)));
    expect(payload.exp - payload.iat).toBe(60);
  });

  it('throws ArgumentError when expiry exceeds configured maximum lifetime', async () => {
    const profile = new JoseProfile({ domain: ISSUER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub, jose: { maxLifetime: 60 } });
    await expect(profile.createJWT({ audience: 'verifier.example.com', expiry: 61 })).rejects.toThrow(ArgumentError);
  });

  it('generates a unique jti on each call', async () => {
    const profile = new JoseProfile({ domain: ISSUER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const j1 = await profile.createJWT({ audience: 'verifier.example.com' });
    const j2 = await profile.createJWT({ audience: 'verifier.example.com' });
    const p1 = JSON.parse(new TextDecoder().decode(fromBase64Url(j1.split('.')[1]!)));
    const p2 = JSON.parse(new TextDecoder().decode(fromBase64Url(j2.split('.')[1]!)));
    expect(p1.jti).not.toBe(p2.jti);
  });

  it('merges additionalClaims into the payload', async () => {
    const profile = new JoseProfile({ domain: ISSUER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const jwt = await profile.createJWT({ audience: 'verifier.example.com', additionalClaims: { role: 'admin' } });
    const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(jwt.split('.')[1]!)));
    expect(payload.role).toBe('admin');
  });

  it.each(['iss', 'sub', 'aud', 'iat', 'exp', 'jti'])('throws ArgumentError when additionalClaims contains reserved claim %s', async (reserved) => {
    const profile = new JoseProfile({ domain: ISSUER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    await expect(profile.createJWT({
      audience: 'verifier.example.com',
      additionalClaims: { [reserved]: 'bad' },
    })).rejects.toThrow(ArgumentError);
  });

  it('sets alg and kid in the JOSE header', async () => {
    const profile = new JoseProfile({ domain: ISSUER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const jwt = await profile.createJWT({ audience: 'verifier.example.com' });
    const header = JSON.parse(new TextDecoder().decode(fromBase64Url(jwt.split('.')[0]!)));
    expect(header.alg).toBe('ES256');
    expect(header.kid).toBe('key-1');
    expect(header.typ).toBe('JWT');
  });
});

// ---- verifyJWT (round-trip) ----

describe('JoseProfile.verifyJWT()', () => {
  async function setup() {
    const fixture = await currentProfileFixture(ISSUER_DOMAIN, publicJwk);
    mockFetchJson.mockImplementation(fixture.fetchJson);
    const kp = makeKeyProvider();
    const issuer = new JoseProfile({ domain: ISSUER_CONFIG.domain, keyProvider: kp, identityResolver: resolverStub });
    const verifierResolver = new IdentityManager({ identity: VERIFIER_CONFIG }, { keyProvider: makeKeyProvider(), logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson: mockFetchJson });
    const verifier = new JoseProfile({ domain: VERIFIER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: verifierResolver });
    return { issuer, verifier };
  }

  it('returns a VerifiedDomain on a valid JWT', async () => {
    const { issuer, verifier } = await setup();
    const jwt = await issuer.createJWT({ audience: 'verifier.example.com' });
    const vd = await verifier.verifyJWT(jwt);
    expect(vd.domain).toBe(ISSUER_DOMAIN);
  });

  it('throws VerificationError when iss is missing', async () => {
    const { verifier } = await setup();
    const header = toBase64Url(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', kid: 'key-1', typ: 'JWT' })));
    const payload = toBase64Url(new TextEncoder().encode(JSON.stringify({ sub: 'x', aud: 'verifier.example.com', iat: 0, exp: 9999999999, jti: 'j' })));
    const fakeSig = toBase64Url(new Uint8Array(64));
    await expect(verifier.verifyJWT(`${header}.${payload}.${fakeSig}`)).rejects.toThrow(VerificationError);
  });

  it('throws VerificationError when aud does not include verifier domain', async () => {
    const { issuer, verifier } = await setup();
    const jwt = await issuer.createJWT({ audience: 'other.example.com' });
    await expect(verifier.verifyJWT(jwt)).rejects.toThrow(VerificationError);
  });

  it('throws VerificationError for an expired JWT', async () => {
    const { verifier } = await setup();
    const kp = makeKeyProvider();
    const issuer2 = new JoseProfile({ domain: ISSUER_CONFIG.domain, keyProvider: kp, identityResolver: resolverStub });
    const clock = vi.spyOn(Date, 'now').mockReturnValue(Date.now() - 2000);
    const jwt = await issuer2.createJWT({ audience: 'verifier.example.com', expiry: 1 });
    clock.mockRestore();
    await expect(verifier.verifyJWT(jwt)).rejects.toThrow(VerificationError);
  });

  it('throws VerificationError when iat is missing', async () => {
    const { verifier } = await setup();
    const header = toBase64Url(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', kid: 'key-1', typ: 'JWT' })));
    const payload = toBase64Url(new TextEncoder().encode(JSON.stringify({
      iss: ISSUER_DOMAIN,
      sub: ISSUER_DOMAIN,
      aud: 'verifier.example.com',
      exp: Math.floor(Date.now() / 1000) + 60,
    })));
    const fakeSig = toBase64Url(new Uint8Array(64));
    const err = await verifier.verifyJWT(`${header}.${payload}.${fakeSig}`).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).message).toContain('iat');
  });

  it('throws VerificationError when iat is beyond configured clock skew', async () => {
    const { verifier } = await setup();
    const now = Math.floor(Date.now() / 1000);
    const header = toBase64Url(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', kid: 'key-1', typ: 'JWT' })));
    const payload = toBase64Url(new TextEncoder().encode(JSON.stringify({
      iss: ISSUER_DOMAIN,
      sub: ISSUER_DOMAIN,
      aud: 'verifier.example.com',
      iat: now + 61,
      exp: now + 120,
    })));
    const fakeSig = toBase64Url(new Uint8Array(64));
    const err = await verifier.verifyJWT(`${header}.${payload}.${fakeSig}`).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).message).toContain('issued-at');
  });

  it('throws VerificationError when exp is not after iat', async () => {
    const { verifier } = await setup();
    const now = Math.floor(Date.now() / 1000);
    const header = toBase64Url(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', kid: 'key-1', typ: 'JWT' })));
    const payload = toBase64Url(new TextEncoder().encode(JSON.stringify({
      iss: ISSUER_DOMAIN,
      sub: ISSUER_DOMAIN,
      aud: 'verifier.example.com',
      iat: now,
      exp: now,
    })));
    const fakeSig = toBase64Url(new Uint8Array(64));
    const err = await verifier.verifyJWT(`${header}.${payload}.${fakeSig}`).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).message).toContain('after iat');
  });

  it('throws VerificationError when JWT lifetime exceeds configured maximum', async () => {
    const fixture = await currentProfileFixture(ISSUER_DOMAIN, publicJwk);
    mockFetchJson.mockImplementation(fixture.fetchJson);
    const verifierResolver = new IdentityManager({ identity: VERIFIER_CONFIG }, { keyProvider: makeKeyProvider(), logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson: mockFetchJson });
    const verifier = new JoseProfile({ domain: VERIFIER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: verifierResolver, jose: { maxLifetime: 60 } });
    const now = Math.floor(Date.now() / 1000);
    const header = toBase64Url(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', kid: 'key-1', typ: 'JWT' })));
    const payload = toBase64Url(new TextEncoder().encode(JSON.stringify({
      iss: ISSUER_DOMAIN,
      sub: ISSUER_DOMAIN,
      aud: 'verifier.example.com',
      iat: now,
      exp: now + 61,
    })));
    const fakeSig = toBase64Url(new Uint8Array(64));
    const err = await verifier.verifyJWT(`${header}.${payload}.${fakeSig}`).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).message).toContain('lifetime');
  });

  it('throws VerificationError when nbf is beyond configured clock skew', async () => {
    const { verifier } = await setup();
    const now = Math.floor(Date.now() / 1000);
    const header = toBase64Url(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', kid: 'key-1', typ: 'JWT' })));
    const payload = toBase64Url(new TextEncoder().encode(JSON.stringify({
      iss: ISSUER_DOMAIN,
      sub: ISSUER_DOMAIN,
      aud: 'verifier.example.com',
      iat: now,
      exp: now + 120,
      nbf: now + 61,
    })));
    const fakeSig = toBase64Url(new Uint8Array(64));
    const err = await verifier.verifyJWT(`${header}.${payload}.${fakeSig}`).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).message).toContain('not yet valid');
  });

  it('throws VerificationError when signature is invalid', async () => {
    const { issuer, verifier } = await setup();
    const jwt = await issuer.createJWT({ audience: 'verifier.example.com' });
    const parts = jwt.split('.');
    // Corrupt the signature
    const corrupted = `${parts[0]}.${parts[1]}.${toBase64Url(new Uint8Array(64))}`;
    const err = await verifier.verifyJWT(corrupted).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).code).toBe(VerificationCode.SignatureInvalid);
  });

  it('throws VerificationError for a JWT with only 2 parts', async () => {
    const { verifier } = await setup();
    await expect(verifier.verifyJWT('header.payload')).rejects.toThrow(VerificationError);
  });

  it('throws VerificationError (not ValidationError) when iss is a URI, not a domain', async () => {
    const { verifier } = await setup();
    const header = toBase64Url(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', kid: 'key-1', typ: 'JWT' })));
    const payload = toBase64Url(new TextEncoder().encode(JSON.stringify({
      iss: 'https://issuer.example.com',
      sub: 'https://issuer.example.com',
      aud: 'verifier.example.com',
      iat: 0,
      exp: 9999999999,
    })));
    const fakeSig = toBase64Url(new Uint8Array(64));
    const err = await verifier.verifyJWT(`${header}.${payload}.${fakeSig}`).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
  });

  it('throws VerificationError (not ValidationError) when sub is a URI, not a domain', async () => {
    const { verifier } = await setup();
    const header = toBase64Url(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', kid: 'key-1', typ: 'JWT' })));
    const payload = toBase64Url(new TextEncoder().encode(JSON.stringify({
      iss: 'issuer.example.com',
      sub: 'https://issuer.example.com',
      aud: 'verifier.example.com',
      iat: 0,
      exp: 9999999999,
    })));
    const fakeSig = toBase64Url(new Uint8Array(64));
    const err = await verifier.verifyJWT(`${header}.${payload}.${fakeSig}`).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
  });
});
