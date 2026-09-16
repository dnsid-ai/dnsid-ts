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

const SIGNER_CONFIG: IdentityConfig = {
  domain: 'signer.example.com',
  governanceId: 'example.com',
  logRef: 'microledger:s',
  statusUrl: 'https://signer.example.com/status',
};
const VERIFIER_CONFIG: IdentityConfig = {
  domain: 'verifier.example.com',
  governanceId: 'example.com',
  logRef: 'microledger:v',
  statusUrl: 'https://verifier.example.com/status',
};

const PAYLOAD = new TextEncoder().encode('hello world');
const resolverStub = { verifyDomain: vi.fn() };

beforeEach(() => { mockFetchJson.mockReset(); });

// ---- createJWS ----

describe('JoseProfile.createJWS()', () => {
  it('returns a 3-part dot-delimited compact JWS', async () => {
    const profile = new JoseProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const jws = await profile.createJWS(PAYLOAD);
    expect(jws.split('.')).toHaveLength(3);
  });

  it('sets kid in the protected header to {domain}#{kid}', async () => {
    const profile = new JoseProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const jws = await profile.createJWS(PAYLOAD);
    const header = JSON.parse(new TextDecoder().decode(fromBase64Url(jws.split('.')[0]!)));
    expect(header.kid).toBe('signer.example.com#key-1');
  });

  it('sets typ=jose in the protected header', async () => {
    const profile = new JoseProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const jws = await profile.createJWS(PAYLOAD);
    const header = JSON.parse(new TextDecoder().decode(fromBase64Url(jws.split('.')[0]!)));
    expect(header.typ).toBe('jose');
  });

  it('encodes the payload as unpadded base64url', async () => {
    const profile = new JoseProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const jws = await profile.createJWS(PAYLOAD);
    const decoded = fromBase64Url(jws.split('.')[1]!);
    expect(decoded).toEqual(PAYLOAD);
  });

  it('throws ArgumentError when signing key kid contains #', async () => {
    const badKey: DnsIdJWK = { ...publicJwk, kid: 'bad#kid' };
    const kp: KeyProvider = { ...makeKeyProvider(), signingKey: vi.fn().mockResolvedValue(badKey) };
    const profile = new JoseProfile({ domain: SIGNER_CONFIG.domain, keyProvider: kp, identityResolver: resolverStub });
    await expect(profile.createJWS(PAYLOAD)).rejects.toThrow(ArgumentError);
  });
});

// ---- verifyJWS (round-trip) ----

describe('JoseProfile.verifyJWS()', () => {
  async function setup() {
    const fixture = await currentProfileFixture('signer.example.com', publicJwk);
    mockFetchJson.mockImplementation(fixture.fetchJson);
    const signer = new JoseProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const verifierResolver = new IdentityManager({ identity: VERIFIER_CONFIG }, { keyProvider: makeKeyProvider(), logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson: mockFetchJson });
    const verifier = new JoseProfile({ domain: VERIFIER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: verifierResolver });
    return { signer, verifier };
  }

  it('returns the payload and a VerifiedDomain on success', async () => {
    const { signer, verifier } = await setup();
    const jws = await signer.createJWS(PAYLOAD);
    const { payload, verifiedDomain } = await verifier.verifyJWS(jws);
    expect(payload).toEqual(PAYLOAD);
    expect(verifiedDomain.domain).toBe('signer.example.com');
  });

  it('throws VerificationError for a JWS with only 2 parts', async () => {
    const { verifier } = await setup();
    await expect(verifier.verifyJWS('header.payload')).rejects.toThrow(VerificationError);
  });

  it('throws VerificationError when kid header is absent', async () => {
    const { verifier } = await setup();
    const header = toBase64Url(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', typ: 'jose' })));
    const payload = toBase64Url(PAYLOAD);
    const sig = toBase64Url(new Uint8Array(64));
    await expect(verifier.verifyJWS(`${header}.${payload}.${sig}`)).rejects.toThrow(VerificationError);
  });

  it('throws VerificationError when kid does not contain #', async () => {
    const { verifier } = await setup();
    const header = toBase64Url(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', kid: 'nokid', typ: 'jose' })));
    const payload = toBase64Url(PAYLOAD);
    const sig = toBase64Url(new Uint8Array(64));
    await expect(verifier.verifyJWS(`${header}.${payload}.${sig}`)).rejects.toThrow();
  });

  it('throws VerificationError when the signature is corrupt', async () => {
    const { signer, verifier } = await setup();
    const jws = await signer.createJWS(PAYLOAD);
    const parts = jws.split('.');
    const corrupted = `${parts[0]}.${parts[1]}.${toBase64Url(new Uint8Array(64))}`;
    const err = await verifier.verifyJWS(corrupted).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).code).toBe(VerificationCode.SignatureInvalid);
  });

  it('throws VerificationError when alg is not in application-layer allowlist', async () => {
    const { signer, verifier } = await setup();
    const jws = await signer.createJWS(PAYLOAD);
    const parts = jws.split('.');
    // Swap alg to something disallowed
    const header = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[0]!)));
    header.alg = 'HS256';
    const newHeaderB64 = toBase64Url(new TextEncoder().encode(JSON.stringify(header)));
    const err = await verifier.verifyJWS(`${newHeaderB64}.${parts[1]}.${parts[2]}`).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
  });
});
