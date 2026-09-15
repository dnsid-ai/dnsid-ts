import { describe, it, expect, vi, beforeAll } from 'vitest';
import { DnsIdTxtRecord, fromBase64Url, IdentityManager, toBase64Url } from '@identity-digital/dnsid-protocol';
import type { IdentityConfig, DnsIdJWK, KeyProvider } from '@identity-digital/dnsid-protocol';

// ---- fixtures ----

const TEST_JWK: DnsIdJWK = {
  kty: 'EC',
  kid: 'test-key-1',
  alg: 'ES256',
  use: 'sig',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};

const ENTITY_JWK: DnsIdJWK = { ...TEST_JWK, kid: 'entity-key-1', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const FIXED_SIG_BYTES = new Uint8Array(64).fill(0xab);

function makeMockKeyProvider(jwk: DnsIdJWK = TEST_JWK, overrides: Partial<KeyProvider> = {}): KeyProvider {
  return {
    signingKey:  vi.fn().mockResolvedValue(jwk),
    jwk:         vi.fn().mockResolvedValue(jwk),
    listKeyIds:  vi.fn().mockResolvedValue(['test-key-1']),
    sign:        vi.fn().mockResolvedValue(FIXED_SIG_BYTES),
    signKey:     vi.fn().mockResolvedValue(FIXED_SIG_BYTES),
    generateKey: vi.fn().mockResolvedValue('test-key-2'),
    activate:    vi.fn().mockResolvedValue(undefined),
    supersede:   vi.fn().mockResolvedValue(undefined),
    purge:       vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

const BASE_CONFIG: IdentityConfig = {
  domain: 'agent.example.com',
  governanceId: 'example.com',
  logRef: 'microledger:abc123',
  statusUrl: 'https://agent.example.com/status',
  ekUrl: 'https://example.com/entity-jwks.json',
  kuUrl: 'https://agent.example.com/jwks.json',
};

function makeManager(config: IdentityConfig = BASE_CONFIG, keyProvider = makeMockKeyProvider(TEST_JWK), entityProvider = makeMockKeyProvider(ENTITY_JWK)): IdentityManager {
  return new IdentityManager({ identity: config }, { keyProvider, entityKeyProvider: entityProvider });
}

// ---- helpers ----

function parseTxtRecord(raw: string): Record<string, string> {
  return Object.fromEntries(
    raw.split(';').map(pair => {
      const eq = pair.indexOf('=');
      return [pair.slice(0, eq), pair.slice(eq + 1)] as [string, string];
    }),
  );
}

// ---- tests ----

describe('IdentityManager.createTxtRecord()', () => {
  it('rejects an empty local domain', () => {
    expect(() => makeManager({ ...BASE_CONFIG, domain: '' })).toThrow('config.identity.domain is required');
    expect(() => makeManager({ ...BASE_CONFIG, domain: '-bad-.example.com' })).toThrow('config.identity.domain is not a valid agent FQDN');
  });

  it('returns a non-empty string', async () => {
    const manager = makeManager();
    const result = await manager.createTxtRecord();
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
  });

  it('starts with v=dnsid-draft-01', async () => {
    const manager = makeManager();
    const result = await manager.createTxtRecord();
    expect(result).toMatch(/^v=dnsid-draft-01/);
  });

  it('includes all required tags', async () => {
    const manager = makeManager();
    const tags = parseTxtRecord(await manager.createTxtRecord());
    expect(tags['v']).toBe('dnsid-draft-01');
    expect(tags['ek']).toBe('https://example.com/entity-jwks.json');
    expect(tags['gi']).toBe('example.com');
    expect(tags['lr']).toBe('microledger:abc123');
    expect(tags['su']).toBe('https://agent.example.com/status');
    expect(tags['sg']).toBeTruthy();
  });

  it('uses configured kuUrl', async () => {
    const manager = makeManager();
    const tags = parseTxtRecord(await manager.createTxtRecord());
    expect(tags['ku']).toBe('https://agent.example.com/jwks.json');
  });

  it('uses provided kuUrl when set', async () => {
    const manager = makeManager({ ...BASE_CONFIG, kuUrl: 'https://agent.example.com/custom-jwks.json' });
    const tags = parseTxtRecord(await manager.createTxtRecord());
    expect(tags['ku']).toBe('https://agent.example.com/custom-jwks.json');
  });

  it('includes optional fl tag when policyFlags is set', async () => {
    const manager = makeManager({ ...BASE_CONFIG, policyFlags: 'mtls,logchk' });
    const tags = parseTxtRecord(await manager.createTxtRecord());
    expect(tags['fl']).toBe('mtls,logchk');
  });

  it('includes optional ka tag when maxKeyAge is set', async () => {
    const manager = makeManager({ ...BASE_CONFIG, maxKeyAge: '30d' });
    const tags = parseTxtRecord(await manager.createTxtRecord());
    expect(tags['ka']).toBe('30d');
  });

  it('includes optional cu tag when capabilitiesUrl is set', async () => {
    const manager = makeManager({ ...BASE_CONFIG, capabilitiesUrl: 'https://agent.example.com/agent.md' });
    const tags = parseTxtRecord(await manager.createTxtRecord());
    expect(tags['cu']).toBe('https://agent.example.com/agent.md');
  });

  it('omits optional tags when not set', async () => {
    const manager = makeManager();
    const result = await manager.createTxtRecord();
    expect(result).not.toContain('fl=');
    expect(result).not.toContain('ka=');
    expect(result).not.toContain('cu=');
  });

  it('sets sg to bare unpadded base64url signature bytes from entityKeyProvider', async () => {
    const kp = makeMockKeyProvider(ENTITY_JWK);
    const manager = makeManager(BASE_CONFIG, makeMockKeyProvider(TEST_JWK), kp);
    const tags = parseTxtRecord(await manager.createTxtRecord());

    expect(tags['sg']).toBe(toBase64Url(FIXED_SIG_BYTES));
    expect(fromBase64Url(tags['sg']!)).toEqual(FIXED_SIG_BYTES);
  });

  it('sg contains no base64 padding characters', async () => {
    const manager = makeManager();
    const tags = parseTxtRecord(await manager.createTxtRecord());
    expect(tags['sg']).not.toContain('=');
  });

  it('signs the draft-01 canonical bytes directly', async () => {
    const kp = makeMockKeyProvider(ENTITY_JWK);
    const manager = makeManager(BASE_CONFIG, makeMockKeyProvider(TEST_JWK), kp);
    await manager.createTxtRecord();

    const signMock = kp.sign as ReturnType<typeof vi.fn>;
    expect(signMock).toHaveBeenCalledOnce();

    const canonical = new TextDecoder().decode(signMock.mock.calls[0][0] as Uint8Array);
    expect(canonical).not.toContain('sg=');
    const tags = canonical.split(';').map(p => p.split('=')[0]!);
    expect(tags).toEqual([...tags].sort());
  });

  it('signed canonical payload includes v=dnsid-draft-01', async () => {
    const kp = makeMockKeyProvider(ENTITY_JWK);
    const manager = makeManager(BASE_CONFIG, makeMockKeyProvider(TEST_JWK), kp);
    await manager.createTxtRecord();

    const canonical = new TextDecoder().decode((kp.sign as ReturnType<typeof vi.fn>).mock.calls[0][0] as Uint8Array);
    expect(canonical).toContain('v=dnsid-draft-01');
  });

  it('validates entity and operational draft-01 JWKS requirements before signing', async () => {
    const entityProvider = makeMockKeyProvider({ ...ENTITY_JWK, alg: undefined });
    const manager = makeManager(BASE_CONFIG, makeMockKeyProvider(TEST_JWK), entityProvider);
    await expect(manager.createTxtRecord()).rejects.toThrow(/record-signing key missing alg/);
    expect(entityProvider.sign).not.toHaveBeenCalled();
  });

  it('normalizes domain to lowercase in constructor', () => {
    const manager = makeManager({ ...BASE_CONFIG, domain: 'Agent.EXAMPLE.COM' });
    expect(manager.config.identity!.domain).toBe('agent.example.com');
  });

  it('strips trailing dot from domain in constructor', () => {
    const manager = makeManager({ ...BASE_CONFIG, domain: 'agent.example.com.' });
    expect(manager.config.identity!.domain).toBe('agent.example.com');
  });

  it('normalizes governanceId when it is a domain name', () => {
    const manager = makeManager({ ...BASE_CONFIG, governanceId: 'EXAMPLE.COM' });
    expect(manager.config.identity!.governanceId).toBe('example.com');
  });

  it('preserves governanceId unchanged when it is not a domain name', () => {
    const manager = makeManager({ ...BASE_CONFIG, governanceId: 'algorand:SOMEADDR' });
    expect(manager.config.identity!.governanceId).toBe('algorand:SOMEADDR');
  });
});
