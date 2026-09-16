import { describe, it, expect, vi } from 'vitest';
import { IdentityManager, JWKS, ValidationError, jwkSignatureAlg } from '@dnsid-ai/protocol';
import type { IdentityConfig, DnsIdJWK, KeyProvider } from '@dnsid-ai/protocol';

// ---- fixtures ----

const EC_KEY: DnsIdJWK = {
  kty: 'EC',
  kid: 'key-1',
  alg: 'ES256',
  use: 'sig',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};

const EC_KEY_2: DnsIdJWK = {
  kty: 'EC',
  kid: 'key-2',
  alg: 'ES256',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};

const BASE_CONFIG: IdentityConfig = {
  domain: 'agent.example.com',
  governanceId: 'example.com',
  logRef: 'microledger:abc123',
  statusUrl: 'https://agent.example.com/status',
};

function makeMockKeyProvider(keys: DnsIdJWK[] = [EC_KEY]): KeyProvider {
  const byId = new Map(keys.map(k => [k.kid!, k]));
  return {
    signingKey:  vi.fn().mockResolvedValue(keys[0]),
    jwk:         vi.fn().mockImplementation((kid: string) => Promise.resolve(byId.get(kid)!)),
    listKeyIds:  vi.fn().mockResolvedValue(keys.map(k => k.kid!)),
    sign:        vi.fn().mockResolvedValue(new Uint8Array(64)),
    signKey:     vi.fn().mockResolvedValue(new Uint8Array(64)),
    generateKey: vi.fn().mockResolvedValue('new-key'),
    activate:    vi.fn().mockResolvedValue(undefined),
    supersede:   vi.fn().mockResolvedValue(undefined),
    purge:       vi.fn().mockResolvedValue(undefined),
  };
}

// ---- IdentityManager.getKeySet() ----

describe('IdentityManager.getKeySet()', () => {
  it('returns a JWKS instance', async () => {
    const manager = new IdentityManager({ identity: BASE_CONFIG }, { keyProvider: makeMockKeyProvider() });
    const result = await manager.getKeySet();
    expect(result).toBeInstanceOf(JWKS);
  });

  it('uses signingKey only for the live draft-01 ku JWKS', async () => {
    const kp = makeMockKeyProvider([EC_KEY, EC_KEY_2]);
    const manager = new IdentityManager({ identity: BASE_CONFIG }, { keyProvider: kp });
    await manager.getKeySet();
    expect(kp.signingKey).toHaveBeenCalledOnce();
    expect(kp.listKeyIds).not.toHaveBeenCalled();
    expect(kp.jwk).not.toHaveBeenCalled();
  });

  it('returns JWKS containing only the active signing key', async () => {
    const manager = new IdentityManager({ identity: BASE_CONFIG }, { keyProvider: makeMockKeyProvider([EC_KEY, EC_KEY_2]) });
    const jwks = await manager.getKeySet();
    expect(jwks.keys).toEqual([EC_KEY]);
  });

  it('returns JWKS with a single key when provider has one key', async () => {
    const manager = new IdentityManager({ identity: BASE_CONFIG }, { keyProvider: makeMockKeyProvider([EC_KEY]) });
    const jwks = await manager.getKeySet();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toEqual(EC_KEY);
  });

  it('returns the active key first and only', async () => {
    const manager = new IdentityManager({ identity: BASE_CONFIG }, { keyProvider: makeMockKeyProvider([EC_KEY, EC_KEY_2]) });
    const jwks = await manager.getKeySet();
    expect(jwks.keys[0]!.kid).toBe('key-1');
    expect(jwks.keys).toHaveLength(1);
  });

  it('rejects operational keys missing draft-01 alg', async () => {
    const manager = new IdentityManager({ identity: BASE_CONFIG }, { keyProvider: makeMockKeyProvider([{ ...EC_KEY, alg: undefined }]) });
    await expect(manager.getKeySet()).rejects.toThrow(/operational key missing alg/);
  });

  it('rejects unsupported draft-01 operational alg', async () => {
    const manager = new IdentityManager({ identity: BASE_CONFIG }, { keyProvider: makeMockKeyProvider([{ ...EC_KEY, kid: 'p384', alg: 'ES384', crv: 'P-384' }]) });
    await expect(manager.getKeySet()).rejects.toThrow(/unsupported draft-01 operational key alg/);
  });
});

// ---- IdentityManager.getEntityKeySet() ----

describe('IdentityManager.getEntityKeySet()', () => {
  it('returns a validated entity JWKS', async () => {
    const entity = makeMockKeyProvider([{ ...EC_KEY, kid: 'entity-key-1' }]);
    const manager = new IdentityManager({ identity: BASE_CONFIG }, { keyProvider: makeMockKeyProvider(), entityKeyProvider: entity });
    const jwks = await manager.getEntityKeySet();
    expect(jwks.keys[0]!.kid).toBe('entity-key-1');
  });

  it('rejects entity keys missing draft-01 alg', async () => {
    const entity = makeMockKeyProvider([{ ...EC_KEY, kid: 'entity-key-1', alg: undefined }]);
    const manager = new IdentityManager({ identity: BASE_CONFIG }, { keyProvider: makeMockKeyProvider(), entityKeyProvider: entity });
    await expect(manager.getEntityKeySet()).rejects.toThrow(/record-signing key missing alg/);
  });

  it('rejects unsupported draft-01 entity alg', async () => {
    const entity = makeMockKeyProvider([{ ...EC_KEY, kid: 'entity-key-1', alg: 'ES384', crv: 'P-384' }]);
    const manager = new IdentityManager({ identity: BASE_CONFIG }, { keyProvider: makeMockKeyProvider(), entityKeyProvider: entity });
    await expect(manager.getEntityKeySet()).rejects.toThrow(/unsupported draft-01 record-signing key alg/);
  });
});

// ---- JWKS.signingKeys() ----

describe('JWKS.signingKeys()', () => {
  it('returns keys with a signing alg', () => {
    const jwks = new JWKS([EC_KEY]);
    expect(jwks.signingKeys()).toEqual([EC_KEY]);
  });

  it('returns keys with use=sig when alg is absent but derivable', () => {
    const key: DnsIdJWK = { kty: 'EC', kid: 'k', crv: 'P-256', use: 'sig' };
    const jwks = new JWKS([key]);
    expect(jwks.signingKeys()).toEqual([key]);
  });

  it('returns all signing keys when multiple are present', () => {
    const jwks = new JWKS([EC_KEY, EC_KEY_2]);
    expect(jwks.signingKeys()).toHaveLength(2);
  });

  it('excludes keys whose alg is not a signing alg and have no use=sig', () => {
    const encKey: DnsIdJWK = { kty: 'EC', kid: 'enc', alg: 'ECDH-ES', use: 'enc' };
    const jwks = new JWKS([EC_KEY, encKey]);
    const result = jwks.signingKeys();
    expect(result).toContainEqual(EC_KEY);
    expect(result).not.toContainEqual(encKey);
  });

  it('throws ValidationError when no signing keys are present', () => {
    const encKey: DnsIdJWK = { kty: 'EC', kid: 'enc', alg: 'ECDH-ES', use: 'enc' };
    const jwks = new JWKS([encKey]);
    expect(() => jwks.signingKeys()).toThrow(ValidationError);
  });

  it('throws ValidationError for an empty key set', () => {
    const jwks = new JWKS([]);
    expect(() => jwks.signingKeys()).toThrow(ValidationError);
  });

  it('includes EdDSA keys', () => {
    const edKey: DnsIdJWK = { kty: 'OKP', kid: 'ed-1', alg: 'EdDSA', crv: 'Ed25519' };
    const jwks = new JWKS([edKey]);
    expect(jwks.signingKeys()).toEqual([edKey]);
  });

  it('derives EdDSA from OKP/Ed25519 when alg is absent', () => {
    const edKey: DnsIdJWK = { kty: 'OKP', kid: 'ed-1', crv: 'Ed25519' };
    const jwks = new JWKS([edKey]);
    expect(jwks.signingKeys()).toEqual([edKey]);
    expect(jwkSignatureAlg(edKey)).toBe('EdDSA');
  });

  it('excludes custom owner-use keys', () => {
    const ownerKey: DnsIdJWK = { kty: 'EC', kid: 'owner-1', crv: 'P-256', use: 'owner' };
    const jwks = new JWKS([ownerKey]);
    expect(() => jwks.signingKeys()).toThrow(/no signing keys/);
    expect(() => jwkSignatureAlg(ownerKey)).toThrow(/use is not valid for signing/);
  });
});

// ---- JWKS.keyById() ----

describe('JWKS.keyById()', () => {
  it('returns the matching key', () => {
    const jwks = new JWKS([EC_KEY, EC_KEY_2]);
    expect(jwks.keyById('key-1')).toEqual(EC_KEY);
    expect(jwks.keyById('key-2')).toEqual(EC_KEY_2);
  });

  it('returns null when kid is not found', () => {
    const jwks = new JWKS([EC_KEY]);
    expect(jwks.keyById('missing')).toBeNull();
  });

  it('returns null for an empty key set', () => {
    const jwks = new JWKS([]);
    expect(jwks.keyById('key-1')).toBeNull();
  });
});

// ---- JWKS.draft01RecordSigningKeyById() ----

describe('JWKS.draft01RecordSigningKeyById()', () => {
  const encKey: DnsIdJWK = { ...EC_KEY, use: 'enc' };
  const algLess: DnsIdJWK = { kty: 'EC', kid: 'key-1', crv: 'P-256', x: EC_KEY.x, y: EC_KEY.y };

  it('returns the matching draft-01 record-signing key', () => {
    expect(new JWKS([EC_KEY]).draft01RecordSigningKeyById('key-1')).toEqual(EC_KEY);
  });

  it('returns null when the kid resolves to a use=enc key', () => {
    expect(new JWKS([encKey]).draft01RecordSigningKeyById('key-1')).toBeNull();
  });

  it('returns null when the kid resolves to a key with no explicit alg', () => {
    expect(new JWKS([algLess]).draft01RecordSigningKeyById('key-1')).toBeNull();
  });
});

// ---- JWKS.validateRecordSigningKeyset() ----

describe('JWKS.validateRecordSigningKeyset()', () => {
  it('passes for a well-formed record-signing key set', async () => {
    await expect(new JWKS([EC_KEY]).validateRecordSigningKeyset()).resolves.toBeUndefined();
  });

  it('rejects product-layer use=owner for a draft-01 live record-signing key', async () => {
    await expect(new JWKS([{ ...EC_KEY, use: 'owner' }]).validateRecordSigningKeyset())
      .rejects.toThrow(/exactly one current signing key/);
  });

  it('rejects a selectable EC key missing its public coordinates', async () => {
    const malformed: DnsIdJWK = { ...EC_KEY, y: undefined } as DnsIdJWK;
    await expect(new JWKS([malformed]).validateRecordSigningKeyset()).rejects.toThrow(ValidationError);
  });

  it('rejects a selectable EC key with present-but-invalid coordinate text', async () => {
    // Non-empty but not a valid P-256 point: passes the shape check, fails to import.
    const malformed: DnsIdJWK = { ...EC_KEY, x: 'not-base64url!!', y: 'also-bad!!' };
    await expect(new JWKS([malformed]).validateRecordSigningKeyset()).rejects.toThrow(ValidationError);
  });

  it('rejects an ek JWKS whose sole signing key uses an unsupported algorithm', async () => {
    const es384: DnsIdJWK = { kty: 'EC', kid: 'p384', alg: 'ES384', crv: 'P-384', x: 'x', y: 'y' };
    await expect(new JWKS([es384]).validateRecordSigningKeyset())
      .rejects.toThrow(/unsupported draft-01 record-signing key alg: ES384/);
  });

  it('rejects multiple current signing keys even when only one uses a supported algorithm', async () => {
    const es384: DnsIdJWK = { kty: 'EC', kid: 'p384', alg: 'ES384', crv: 'P-384', x: 'x', y: 'y' };
    await expect(new JWKS([EC_KEY, es384]).validateRecordSigningKeyset())
      .rejects.toThrow(/exactly one current signing key/);
  });
});

// ---- JWKS.validate() ----

describe('JWKS.validate()', () => {
  it('passes for a valid key set', () => {
    const jwks = new JWKS([EC_KEY]);
    expect(() => jwks.validate()).not.toThrow();
  });

  it('passes for multiple valid keys', () => {
    const jwks = new JWKS([EC_KEY, EC_KEY_2]);
    expect(() => jwks.validate()).not.toThrow();
  });

  it('passes when alg is absent but derivable from kty/crv', () => {
    const noAlg: DnsIdJWK = { kty: 'EC', kid: 'k', crv: 'P-256' };
    const jwks = new JWKS([EC_KEY, noAlg]);
    expect(() => jwks.validate()).not.toThrow();
    expect(jwkSignatureAlg(noAlg)).toBe('ES256');
  });

  it('throws ValidationError when present alg is inconsistent with kty/crv', () => {
    const badAlg: DnsIdJWK = { kty: 'EC', kid: 'k', alg: 'EdDSA', crv: 'P-256' };
    const jwks = new JWKS([EC_KEY, badAlg]);
    expect(() => jwks.validate()).toThrow(ValidationError);
  });

  it('throws ValidationError when no signing key has a kid', () => {
    // @ts-expect-error (no kid breaks type)
    const noKid: DnsIdJWK = { kty: 'EC', alg: 'ES256', crv: 'P-256', x: 'x', y: 'y' };
    const jwks = new JWKS([noKid]);
    expect(() => jwks.validate()).toThrow(ValidationError);
  });

  it('throws ValidationError when there are no signing keys', () => {
    const encKey: DnsIdJWK = { kty: 'EC', kid: 'enc', alg: 'ECDH-ES', use: 'enc' };
    const jwks = new JWKS([encKey]);
    expect(() => jwks.validate()).toThrow(ValidationError);
  });

  it('throws ValidationError for an empty key set', () => {
    const jwks = new JWKS([]);
    expect(() => jwks.validate()).toThrow(ValidationError);
  });

  it('passes when only one signing key has a kid and others do not', () => {
    // @ts-expect-error (no kid breaks type)
    const noKid: DnsIdJWK = { kty: 'EC', alg: 'ES256', crv: 'P-256', x: 'x', y: 'y' };
    const jwks = new JWKS([EC_KEY, noKid]);
    expect(() => jwks.validate()).not.toThrow();
  });
});
