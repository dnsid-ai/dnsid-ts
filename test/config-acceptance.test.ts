import { beforeEach, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import {
  ArgumentError,
  DNSSECMode,
  DNSSECState,
  IdentityManager,
  InMemoryIdentityCache,
  VerificationCode,
  VerificationError,
  jwkThumbprint,
} from '@dnsid-ai/protocol';
import type { DnsIdJWK, DnsidConfig, IdentityConfig, JsonFetcher, KeyProvider } from '@dnsid-ai/protocol';
import { createNodeIdentityManager, createNodeIdentityVerifier } from '@dnsid-ai/sdk/node';
import { awaitRegistryManagedPublication, RegistryClient } from '@dnsid-ai/registry';
import { currentProfileFixture } from './helpers/current-profile.ts';

const transportSpies = vi.hoisted(() => ({ fetchJson: vi.fn(), createDefaultDnsResolver: vi.fn() }));
vi.mock('../packages/transport/src/index.ts', async importOriginal => {
  const actual = await importOriginal<typeof import('../packages/transport/src/index.ts')>();
  transportSpies.createDefaultDnsResolver.mockImplementation(actual.createDefaultDnsResolver);
  return { ...actual, ...transportSpies };
});

const identity: IdentityConfig = {
  domain: 'agent.example.com', governanceId: 'example.com',
  logRef: 'microledger:v', statusUrl: 'https://agent.example.com/status',
};
const keyProvider = { signingKey: vi.fn() } as unknown as KeyProvider;
const OTHER_PIN = 'A'.repeat(42) + 'A';

async function setup() {
  const pair = await generateKeyPair('ES256');
  const raw = await exportJWK(pair.publicKey);
  const operationalKey = { ...raw, kty: raw.kty!, kid: 'op', alg: 'ES256', use: 'sig' } as DnsIdJWK;
  const fixture = await currentProfileFixture('agent.example.com', operationalKey);
  const entityPin = await jwkThumbprint(fixture.entityKey);
  const manager = (config: DnsidConfig, fetchJson: JsonFetcher = fixture.fetchJson, cache?: InMemoryIdentityCache) =>
    new IdentityManager(config, { logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson, cache });
  return { fixture, entityPin, manager };
}

describe('DnsidConfig validation', () => {
  it('applies identical verification defaults with or without a local identity', async () => {
    const { manager } = await setup();
    const local = new IdentityManager({ identity }, { keyProvider });
    expect(local.config.verification).toEqual(manager({}).config.verification);
    expect(local.config.transport).toEqual({});
    expect(manager({}).config.identity).toBeUndefined();
  });

  it('snapshots configuration; later caller mutation has no effect', async () => {
    const { manager } = await setup();
    const trustedEntities = [{ governanceId: 'example.com' }];
    const config: DnsidConfig = { verification: { trustedEntities } };
    const idm = manager(config);
    trustedEntities.push({ governanceId: 'evil.example' });
    trustedEntities.length = 0;
    config.verification!.trustedEntities = undefined;
    expect(idm.config.verification.trustedEntities).toEqual([{ governanceId: 'example.com' }]);
    expect(Object.isFrozen(idm.config.verification.trustedEntities)).toBe(true);
  });

  it.each<[string, unknown]>([
    ['unknown top-level field', { bogus: 1 }],
    ['unknown identity field', { identity: { ...identity, dnssecMode: 'auto' } }],
    ['unknown verification field', { verification: { trusted: [] } }],
    ['unknown transport field', { transport: { proxy: 'x' } }],
    ['boolean statusCheckInterval', { verification: { statusCheckInterval: true } }],
    ['negative statusCheckInterval', { verification: { statusCheckInterval: -1 } }],
    ['invalid dnssecMode', { verification: { dnssecMode: 'strict' } }],
    ['trustedEntities not array', { verification: { trustedEntities: {} } }],
    ['invalid governanceId', { verification: { trustedEntities: [{ governanceId: '-bad-.example' }] } }],
    ['duplicate normalized governanceId', { verification: { trustedEntities: [{ governanceId: 'Example.COM' }, { governanceId: 'example.com.' }] } }],
    ['unknown entity field', { verification: { trustedEntities: [{ governanceId: 'example.com', pins: [] }] } }],
    ['empty pins', { verification: { trustedEntities: [{ governanceId: 'example.com', entityKeyThumbprints: [] }] } }],
    ['padded pin', { verification: { trustedEntities: [{ governanceId: 'example.com', entityKeyThumbprints: ['A'.repeat(43) + '='] }] } }],
    ['short pin', { verification: { trustedEntities: [{ governanceId: 'example.com', entityKeyThumbprints: ['abc'] }] } }],
    ['non-canonical pin trailing bits', { verification: { trustedEntities: [{ governanceId: 'example.com', entityKeyThumbprints: ['A'.repeat(42) + 'B'] }] } }],
    ['duplicate pins', { verification: { trustedEntities: [{ governanceId: 'example.com', entityKeyThumbprints: [OTHER_PIN, OTHER_PIN] }] } }],
  ])('rejects %s before network work', async (_name, config) => {
    const fetchTXT = vi.fn();
    expect(() => new IdentityManager(config as DnsidConfig, { dnsResolver: { fetchTXT }, fetchJson: vi.fn() })).toThrow(ArgumentError);
    expect(fetchTXT).not.toHaveBeenCalled();
  });

  it('normalizes configured governance IDs without rewriting signed record fields', async () => {
    const { manager } = await setup();
    const idm = manager({ verification: { trustedEntities: [{ governanceId: 'EXAMPLE.com.' }] } });
    expect(idm.config.verification.trustedEntities).toEqual([{ governanceId: 'example.com' }]);
    const vd = await idm.verifyDomain('agent.example.com');
    expect(vd.record.gi).toBe('example.com');
  });

  it('rejects explicit transport settings in the runtime-neutral core', () => {
    expect(() => new IdentityManager({ transport: { dnsServer: '1.1.1.1' } }, { dnsResolver: { fetchTXT: vi.fn() }, fetchJson: vi.fn() })).toThrow(/no SDK-managed consumer/);
    expect(() => new IdentityManager({ transport: { caBundlePath: '/ca.pem' } }, { dnsResolver: { fetchTXT: vi.fn() }, fetchJson: vi.fn() })).toThrow(/no SDK-managed consumer/);
  });
});

describe('Node transport conflict rules', () => {
  beforeEach(() => { transportSpies.fetchJson.mockClear(); transportSpies.createDefaultDnsResolver.mockClear(); });
  const fetchJson = vi.fn();
  const dnsResolver = { fetchTXT: vi.fn() };

  it('dnsServer with only the TXT resolver injected configures the default fetcher', async () => {
    const { fixture } = await setup();
    transportSpies.fetchJson.mockImplementation(fixture.fetchJson);
    const idm = await createNodeIdentityVerifier({ transport: { dnsServer: '127.0.0.1' } }, { dnsResolver: fixture.dnsResolver, logRegistry: fixture.logRegistry });
    expect(idm.config.transport).toEqual({});
    await idm.verifyDomain('agent.example.com');
    expect(transportSpies.fetchJson).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ dnsServer: '127.0.0.1' }));
    expect(transportSpies.createDefaultDnsResolver).not.toHaveBeenCalled();
  });

  it('dnsServer with only the HTTPS fetcher injected configures the default resolver', async () => {
    const idm = await createNodeIdentityVerifier({ transport: { dnsServer: '127.0.0.1' } }, { fetchJson });
    expect(idm.config.transport).toEqual({});
    expect(transportSpies.createDefaultDnsResolver).toHaveBeenCalledWith({ dnsServer: '127.0.0.1' });
    expect(fetchJson).not.toHaveBeenCalled();
  });

  it('rejects dnsServer when both consumers are injected', async () => {
    await expect(createNodeIdentityVerifier({ transport: { dnsServer: '127.0.0.1' } }, { dnsResolver, fetchJson })).rejects.toThrow(ArgumentError);
    expect(dnsResolver.fetchTXT).not.toHaveBeenCalled();
  });

  it('rejects caBundlePath when the HTTPS fetcher is injected', async () => {
    await expect(createNodeIdentityManager({ identity, transport: { caBundlePath: '/ca.pem' } }, { keyProvider, dnsResolver, fetchJson })).rejects.toThrow(ArgumentError);
  });

  it('validates configuration before loading transport or touching the network', async () => {
    await expect(createNodeIdentityVerifier({ verification: { dnssecMode: 'nope' as DNSSECMode } }, { dnsResolver, fetchJson })).rejects.toThrow(ArgumentError);
  });
});

describe('counterparty acceptance', () => {
  it('makes no decision when policy is omitted and denies all for []', async () => {
    const { manager } = await setup();
    await expect(manager({}).verifyDomain('agent.example.com')).resolves.toBeDefined();
    await expect(manager({ verification: { trustedEntities: [] } }).verifyDomain('agent.example.com')).rejects.toMatchObject({
      code: VerificationCode.CounterpartyNotAccepted, transient: false,
    });
  });

  it('accepts an exact gi match and rejects child, suffix, and lookalike names', async () => {
    const { manager } = await setup();
    await expect(manager({ verification: { trustedEntities: [{ governanceId: 'example.com' }] } }).verifyDomain('agent.example.com')).resolves.toBeDefined();
    for (const governanceId of ['agent.example.com', 'com', 'sub.example.com', 'example.co', 'xexample.com']) {
      await expect(manager({ verification: { trustedEntities: [{ governanceId }] } }).verifyDomain('agent.example.com'))
        .rejects.toMatchObject({ code: VerificationCode.CounterpartyNotAccepted });
    }
  });

  it('accepts an exact allowed gi for an unrelated (delegated) agent domain only with verified bilateral binding', async () => {
    const domain = 'agent.contractor.test';
    const pair = await generateKeyPair('ES256');
    const raw = await exportJWK(pair.publicKey);
    const fixture = await currentProfileFixture(domain, { ...raw, kty: raw.kty!, kid: 'op', alg: 'ES256', use: 'sig' } as DnsIdJWK);
    const binding = vi.spyOn(fixture.logReader, 'verifyBilateralBinding');
    const config: DnsidConfig = { verification: { trustedEntities: [{ governanceId: 'example.com' }] } };
    const deps = { dnsResolver: fixture.dnsResolver, fetchJson: fixture.fetchJson };
    await expect(new IdentityManager(config, { ...deps, logRegistry: fixture.logRegistry }).verifyDomain(domain)).resolves.toMatchObject({ domain });
    expect(binding).toHaveBeenCalledOnce();
    // Allowed name but no binding evidence: rejected before acceptance is ever consulted.
    await expect(new IdentityManager(config, deps).verifyDomain(domain)).rejects.toMatchObject({ code: VerificationCode.LogError });
  });

  it('pins constrain the current entity key; operational key thumbprint is not a pin', async () => {
    const { manager, entityPin, fixture } = await setup();
    const vd = await manager({ verification: { trustedEntities: [{ governanceId: 'example.com', entityKeyThumbprints: [OTHER_PIN, entityPin] }] } }).verifyDomain('agent.example.com');
    expect(vd.signingKeyThumbprint).toBe(entityPin);
    const opPin = await jwkThumbprint(vd.jwks.keys[0]!);
    await expect(manager({ verification: { trustedEntities: [{ governanceId: 'example.com', entityKeyThumbprints: [opPin] }] } }).verifyDomain('agent.example.com'))
      .rejects.toMatchObject({ code: VerificationCode.CounterpartyNotAccepted, verifiedGovernanceId: 'example.com', verifiedEntityKeyThumbprint: await jwkThumbprint(fixture.entityKey) });
  });

  it('denial discloses only observed values, never the configured allowlist or pins', async () => {
    const { manager, entityPin } = await setup();
    const configured = 'trusted.example.org';
    const err = await manager({ verification: { trustedEntities: [{ governanceId: configured, entityKeyThumbprints: [OTHER_PIN] }] } })
      .verifyDomain('agent.example.com').then(() => { throw new Error('expected denial'); }, e => e as VerificationError);
    expect(err).toBeInstanceOf(VerificationError);
    expect(err.verifiedGovernanceId).toBe('example.com');
    expect(err.verifiedEntityKeyThumbprint).toBe(entityPin);
    const serialized = JSON.stringify({ ...err, message: err.message, cause: String(err.cause) });
    expect(serialized).not.toContain(configured);
    expect(serialized).not.toContain(OTHER_PIN);
  });

  it('caches protocol evidence before denial and reevaluates acceptance on cache hits', async () => {
    const { manager, fixture } = await setup();
    const fetchTXT = vi.fn(fixture.dnsResolver.fetchTXT);
    const fetchJson = vi.fn(fixture.fetchJson);
    const idm = new IdentityManager(
      { verification: { statusCheckInterval: 60, trustedEntities: [] } },
      { logRegistry: fixture.logRegistry, dnsResolver: { fetchTXT }, fetchJson },
    );
    await expect(idm.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.CounterpartyNotAccepted });
    await expect(idm.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.CounterpartyNotAccepted });
    // Second call was a cache hit with no due status refresh: no new DNS lookup, still rejected.
    expect(fetchTXT).toHaveBeenCalledTimes(1);
    expect(fetchJson).toHaveBeenCalledTimes(3);
  });

  it('status refresh succeeds and is cached even when acceptance then denies', async () => {
    const { manager, fixture } = await setup();
    const fetchJson = vi.fn(fixture.fetchJson);
    const idm = new IdentityManager(
      { verification: { statusCheckInterval: 0, trustedEntities: [] } },
      { logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson },
    );
    await expect(idm.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.CounterpartyNotAccepted });
    const before = fetchJson.mock.calls.length;
    await expect(idm.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.CounterpartyNotAccepted });
    // Zero interval: exactly one status re-fetch, no JWKS re-fetch (identity evidence stayed cached).
    expect(fetchJson.mock.calls.slice(before).map(([url]) => url)).toEqual(['https://agent.example.com/status']);
  });

  it('coalesced concurrent invocations each reject independently', async () => {
    const { manager } = await setup();
    const idm = manager({ verification: { trustedEntities: [] } });
    const results = await Promise.allSettled([idm.verifyDomain('agent.example.com'), idm.verifyDomain('agent.example.com')]);
    expect(results.map(r => r.status)).toEqual(['rejected', 'rejected']);
  });

  it('different acceptance policies sharing a cache backend never share results', async () => {
    const { manager } = await setup();
    const cache = new InMemoryIdentityCache();
    const permissive = manager({}, undefined, cache);
    const strict = manager({ verification: { trustedEntities: [] } }, undefined, cache);
    await expect(permissive.verifyDomain('agent.example.com')).resolves.toBeDefined();
    await expect(strict.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.CounterpartyNotAccepted });
    await expect(permissive.verifyDomain('agent.example.com')).resolves.toBeDefined();
  });

  it('VerifiedDomain carries no acceptance flag', async () => {
    const { manager } = await setup();
    const vd = await manager({ verification: { trustedEntities: [{ governanceId: 'example.com' }] } }).verifyDomain('agent.example.com');
    expect(Object.keys(vd).some(key => /trust|accept/i.test(key))).toBe(false);
  });

  it('publication confirmation succeeds on protocol evidence while public verifyDomain(localDomain) still rejects', async () => {
    const { fixture } = await setup();
    const idm = new IdentityManager(
      { identity, verification: { trustedEntities: [] } },
      { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson: fixture.fetchJson },
    );
    const registryFetch = vi.fn(async () => new Response(JSON.stringify({
      id: 'agent-1', domain: 'agent.example.com', status: 'READY', managed: 'dnsid', dns_published: true,
    }))) as unknown as typeof fetch;
    await expect(awaitRegistryManagedPublication({
      domain: 'agent.example.com',
      registryClient: new RegistryClient({ baseUrl: 'https://registry.example', fetch: registryFetch }),
      identityManager: idm,
    })).resolves.toMatchObject({ ownerName: '_dnsid.agent.example.com' });
    await expect(idm.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.CounterpartyNotAccepted });
  });

  it('publication evidence is not a counterparty acceptance bypass', async () => {
    const { fixture } = await setup();
    const deps = { logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson: fixture.fetchJson };
    const local = new IdentityManager({ identity: { ...identity, domain: 'other.example.com' }, verification: { trustedEntities: [] } }, { keyProvider, ...deps });
    await expect(local.verifyPublicationEvidence('agent.example.com')).rejects.toThrow(ArgumentError);
    await expect(local.verifyPublicationEvidence('AGENT.example.com.')).rejects.toThrow(/only available for the local identity/);
    const verifierOnly = new IdentityManager({ verification: { trustedEntities: [] } }, deps);
    await expect(verifierOnly.verifyPublicationEvidence('agent.example.com')).rejects.toThrow(ArgumentError);
  });

  it('DNSSEC state is preserved through acceptance', async () => {
    const { manager } = await setup();
    const vd = await manager({ verification: { dnssecMode: DNSSECMode.auto, trustedEntities: [{ governanceId: 'example.com' }] } }).verifyDomain('agent.example.com');
    expect(vd.dnssecState).toBe(DNSSECState.UNSIGNED);
  });
});
