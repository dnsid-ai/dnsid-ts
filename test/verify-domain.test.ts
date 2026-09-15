import { beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import {
  ArgumentError,
  DNSID_DRAFT01_VERSION,
  DNSID_VERSION,
  DNSSECMode,
  DNSSECState,
  IdentityManager,
  InMemoryIdentityCache,
  JWKS_MAX_RESPONSE_BYTES,
  STATUS_MAX_RESPONSE_BYTES,
  VerificationCode,
  retryTransientVerification,
  toArrayBuffer,
  toBase64Url,
} from '@identity-digital/dnsid-protocol';
import type { IdentityConfig, DnsIdJWK, KeyProvider } from '@identity-digital/dnsid-protocol';
import { currentProfileFixture } from './helpers/current-profile.ts';

const selectors = [DNSID_DRAFT01_VERSION, DNSID_VERSION] as const;
let operationalKey: DnsIdJWK;
let operationalPrivateKey: CryptoKey;
beforeAll(async () => {
  const pair = await generateKeyPair('ES256');
  operationalPrivateKey = pair.privateKey;
  const raw = await exportJWK(pair.publicKey);
  operationalKey = { ...raw, kty: raw.kty!, kid: 'operational', alg: 'ES256', use: 'sig' } as DnsIdJWK;
});

const identity: IdentityConfig = {
  domain: 'verifier.example.com', governanceId: 'example.com',
  logRef: 'microledger:v', statusUrl: 'https://verifier.example.com/status',
};
const keyProvider = {
  signingKey: vi.fn(), jwk: vi.fn(), listKeyIds: vi.fn(), sign: vi.fn(), signKey: vi.fn(),
  generateKey: vi.fn(), activate: vi.fn(), supersede: vi.fn(), purge: vi.fn(),
} as unknown as KeyProvider;

async function setup(selector?: string) {
  const fixture = await currentProfileFixture('agent.example.com', operationalKey, undefined, selector);
  const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson: fixture.fetchJson });
  return { fixture, manager };
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

describe('IdentityManager.verifyDomain()', () => {
  it.each(selectors)('verifies %s with frozen draft-01 behavior', async selector => {
    const { manager } = await setup(selector);
    const vd = await manager.verifyDomain('agent.example.com');
    expect(vd.domain).toBe('agent.example.com');
    expect(vd.record.v).toBe(selector);
    expect(vd.signingKey.kid).toBe('entity-key');
    expect(vd.jwks.keys).toEqual([operationalKey]);
  });

  it('rejects unsupported and obsolete selectors as RecordInvalid', async () => {
    const { fixture, manager } = await setup();
    fixture.record.v = 'dnsid-draft-01-20260504';
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.RecordInvalid });
  });

  it('rejects algorithm-prefixed draft-01 signatures', async () => {
    const { fixture, manager } = await setup();
    fixture.record.sg = `ES256:${fixture.record.sg}`;
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.SignatureInvalid });
  });

  it.each(selectors)('rejects %s records signed by the operational key instead of the entity key', async selector => {
    const { fixture, manager } = await setup(selector);
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      operationalPrivateKey,
      toArrayBuffer(new TextEncoder().encode(fixture.record.canonical())),
    );
    fixture.record.sg = toBase64Url(new Uint8Array(signature));
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.SignatureInvalid });
  });

  it.each(selectors)('requires exactly one current entity key for %s', async selector => {
    const { fixture } = await setup(selector);
    const fetchJson = async (url: string, opts?: object) => {
      const result = await fixture.fetchJson(url, opts);
      return url === fixture.record.ek ? { ...result, data: { keys: [fixture.entityKey, operationalKey] } } : result;
    };
    const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson });
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.RecordInvalid });
  });

  it.each(selectors)('requires exactly one current operational key for %s', async selector => {
    const { fixture } = await setup(selector);
    const fetchJson = async (url: string, opts?: object) => {
      const result = await fixture.fetchJson(url, opts);
      return url === fixture.record.ku ? { ...result, data: { keys: [operationalKey, fixture.entityKey] } } : result;
    };
    const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson });
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.RecordInvalid });
  });

  it.each(selectors)('requires distinct entity and operational keys for %s', async selector => {
    const { fixture } = await setup(selector);
    const fetchJson = async (url: string, opts?: object) => {
      const result = await fixture.fetchJson(url, opts);
      return url === fixture.record.ku ? { ...result, data: { keys: [fixture.entityKey] } } : result;
    };
    const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson });
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.RecordInvalid });
  });

  it.each(selectors)('reports malformed current keys as RecordInvalid for %s', async selector => {
    const { fixture } = await setup(selector);
    const malformed = { kty: 'EC', kid: 'bad', alg: 'ES256', use: 'sig' };
    const fetchJson = async (url: string, opts?: object) => {
      const result = await fixture.fetchJson(url, opts);
      return url === fixture.record.ku ? { ...result, data: { keys: [malformed] } } : result;
    };
    const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson });
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.RecordInvalid });
  });

  it.each(selectors)('requires bilateral issuance and operational continuity for %s', async selector => {
    const { fixture, manager } = await setup(selector);
    const binding = vi.spyOn(fixture.logReader, 'verifyBilateralBinding');
    const continuity = vi.spyOn(fixture.logReader, 'verifyOperationalContinuity');
    await manager.verifyDomain('agent.example.com');
    expect(binding).toHaveBeenCalledOnce();
    expect(continuity).toHaveBeenCalledOnce();
  });

  it('accepts delegated cross-domain governance with verified ISSUANCE evidence', async () => {
    const domain = 'agent.contractor.test';
    const fixture = await currentProfileFixture(domain, operationalKey);
    const binding = vi.spyOn(fixture.logReader, 'verifyBilateralBinding');
    const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson: fixture.fetchJson });

    await expect(manager.verifyDomain(domain)).resolves.toMatchObject({ domain });
    expect(binding).toHaveBeenCalledOnce();
  });

  it('fails closed when delegated governance has no ISSUANCE verifier', async () => {
    const domain = 'agent.contractor.test';
    const fixture = await currentProfileFixture(domain, operationalKey);
    const manager = new IdentityManager({ identity }, { keyProvider, dnsResolver: fixture.dnsResolver, fetchJson: fixture.fetchJson });

    await expect(manager.verifyDomain(domain)).rejects.toMatchObject({
      code: VerificationCode.LogError,
      message: 'delegated governance relationship requires verified ISSUANCE evidence',
    });
  });

  it.each([DNSSECState.VALID, DNSSECState.UNSIGNED, DNSSECState.UNKNOWN])(
    'classifies absent TXT records as non-transient DNSResolution with DNSSEC %s', async dnssecState => {
      const dnsResolver = { fetchTXT: vi.fn().mockResolvedValue([[], dnssecState]) };
      const fetchJson = vi.fn();
      const manager = new IdentityManager({ identity }, { keyProvider, dnsResolver, fetchJson });
      await expect(retryTransientVerification(() => manager.verifyDomain('agent.example.com'))).rejects.toMatchObject({
        code: VerificationCode.DNSResolution,
        message: 'no _dnsid TXT record found for agent.example.com',
        transient: false,
      });
      expect(dnsResolver.fetchTXT).toHaveBeenCalledOnce();
      expect(fetchJson).not.toHaveBeenCalled();
    },
  );

  it.each([
    [DNSSECMode.auto, DNSSECState.FAILED],
    [DNSSECMode.validated, DNSSECState.UNKNOWN],
    [DNSSECMode.required, DNSSECState.UNSIGNED],
  ])('preserves DNSSEC rejection for empty answers in %s mode with %s', async (dnssecMode, dnssecState) => {
    const dnsResolver = { fetchTXT: vi.fn().mockResolvedValue([[], dnssecState]) };
    const manager = new IdentityManager({ identity, verification: { dnssecMode } }, { keyProvider, dnsResolver });
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.DNSSECFailed });
  });

  it('rejects multiple TXT records', async () => {
    const { fixture } = await setup();
    const dnsResolver = { fetchTXT: vi.fn().mockResolvedValue([[
      { strings: [fixture.record.serialize()], ttl: 300 },
      { strings: [fixture.record.serialize()], ttl: 300 },
    ], DNSSECState.UNSIGNED]) };
    const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver, fetchJson: fixture.fetchJson });
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.RecordInvalid });
  });

  it('rejects DNSSEC validation failures even when DNSSEC is not required', async () => {
    const { fixture } = await setup();
    const dnsResolver = { fetchTXT: vi.fn().mockResolvedValue([[{ strings: [fixture.record.serialize()], ttl: 300 }], DNSSECState.FAILED]) };
    const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver, fetchJson: fixture.fetchJson });
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.DNSSECFailed });
  });

  it('rejects an invalid runtime DNSSEC state before policy evaluation', async () => {
    const { fixture } = await setup();
    const dnsResolver = {
      fetchTXT: vi.fn().mockResolvedValue([
        [{ strings: [fixture.record.serialize()], ttl: 300 }],
        'BOGUS' as DNSSECState,
      ]),
    };
    const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver, fetchJson: fixture.fetchJson });
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({
      code: VerificationCode.DNSSECFailed,
      message: 'invalid DNSSEC state: BOGUS',
    });
  });

  it.each([DNSSECState.VALID, DNSSECState.UNSIGNED, DNSSECState.UNKNOWN])(
    'auto mode permits and preserves DNSSEC state %s',
    async dnssecState => {
      const { fixture } = await setup();
      const dnsResolver = {
        fetchTXT: vi.fn().mockResolvedValue([[{ strings: [fixture.record.serialize()], ttl: 300 }], dnssecState]),
      };
      const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver, fetchJson: fixture.fetchJson });
      await expect(manager.verifyDomain('agent.example.com')).resolves.toMatchObject({ dnssecState });
    },
  );

  it.each([DNSSECState.VALID, DNSSECState.UNSIGNED])(
    'validated mode permits DNSSEC state %s',
    async dnssecState => {
      const { fixture } = await setup();
      const dnsResolver = {
        fetchTXT: vi.fn().mockResolvedValue([[{ strings: [fixture.record.serialize()], ttl: 300 }], dnssecState]),
      };
      const manager = new IdentityManager({ identity, verification: { dnssecMode: DNSSECMode.validated } }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver, fetchJson: fixture.fetchJson });
      await expect(manager.verifyDomain('agent.example.com')).resolves.toMatchObject({ dnssecState });
    },
  );

  it('validated mode rejects an unknown DNSSEC state', async () => {
    const { fixture } = await setup();
    const dnsResolver = {
      fetchTXT: vi.fn().mockResolvedValue([[{ strings: [fixture.record.serialize()], ttl: 300 }], DNSSECState.UNKNOWN]),
    };
    const manager = new IdentityManager({ identity, verification: { dnssecMode: DNSSECMode.validated } }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver, fetchJson: fixture.fetchJson });
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.DNSSECFailed });
  });

  it.each(['disabled', 'typo'])('rejects invalid DNSSEC mode %s at construction, before any network work', async dnssecMode => {
    const { fixture } = await setup();
    const fetchTXT = vi.fn();
    expect(() => new IdentityManager({ identity, verification: { dnssecMode: dnssecMode as DNSSECMode } }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: { fetchTXT }, fetchJson: fixture.fetchJson }))
      .toThrow(ArgumentError);
    expect(fetchTXT).not.toHaveBeenCalled();
  });

  it('enforces DNSSEC required mode', async () => {
    const { fixture } = await setup();
    const manager = new IdentityManager({ identity, verification: { dnssecMode: DNSSECMode.required } }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson: fixture.fetchJson });
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.DNSSECFailed });
  });

  it('rejects non-ACTIVE status', async () => {
    const { fixture } = await setup();
    const fetchJson = async (url: string, opts?: object) => {
      const result = await fixture.fetchJson(url, opts);
      return url.includes('/status') ? { ...result, data: { state: 'REVOKED', lastTransitionAt: new Date().toISOString(), revocationReason: 'superseded' } } : result;
    };
    const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson });
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.StatusNotActive });
  });

  it('reports status transport failures as transient', async () => {
    const { fixture } = await setup();
    const fetchJson = async (url: string, opts?: object) => {
      if (url.includes('/status')) throw new Error('offline');
      return fixture.fetchJson(url, opts);
    };
    const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson });
    await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({
      code: VerificationCode.StatusUnavailable,
      transient: true,
    });
  });

  it('passes endpoint-specific response limits to the fetcher', async () => {
    const { fixture } = await setup();
    const fetchJson = vi.fn(fixture.fetchJson);
    const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson });
    await manager.verifyDomain('agent.example.com');
    expect(fetchJson).toHaveBeenCalledWith(fixture.record.ek, expect.objectContaining({ maxResponseBytes: JWKS_MAX_RESPONSE_BYTES }));
    expect(fetchJson).toHaveBeenCalledWith(fixture.record.ku, expect.objectContaining({ maxResponseBytes: JWKS_MAX_RESPONSE_BYTES }));
    expect(fetchJson).toHaveBeenCalledWith(fixture.record.su, expect.objectContaining({ maxResponseBytes: STATUS_MAX_RESPONSE_BYTES }));
  });

  it.each([[60, 3], [0, 4]])(
    'uses cached verification state at a %ss status interval without operation-level non-revocation',
    async (statusCheckInterval, expectedFetches) => {
      const { fixture } = await setup();
      const fetchJson = vi.fn(fixture.fetchJson);
      const fetchTXT = vi.spyOn(fixture.dnsResolver, 'fetchTXT');
      const nonRevocation = vi.spyOn(fixture.logReader, 'verifyNonRevocation');
      const manager = new IdentityManager({ identity, verification: { statusCheckInterval } }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson });
      await manager.verifyDomain('agent.example.com');
      await manager.verifyDomain('agent.example.com');
      expect(fetchTXT).toHaveBeenCalledOnce();
      expect(fetchJson).toHaveBeenCalledTimes(expectedFetches);
      expect(nonRevocation).not.toHaveBeenCalled();
    },
  );

  describe('in-flight coalescing', () => {
    it('runs cold reusable verification once for 32 same-domain callers', async () => {
      const { fixture } = await setup();
      const gate = deferred();
      const fetchTXT = vi.fn(async (name: string) => {
        await gate.promise;
        return fixture.dnsResolver.fetchTXT(name);
      });
      const fetchJson = vi.fn(fixture.fetchJson);
      const binding = vi.spyOn(fixture.logReader, 'verifyBilateralBinding');
      const continuity = vi.spyOn(fixture.logReader, 'verifyOperationalContinuity');
      const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: { fetchTXT }, fetchJson });

      const calls = Array.from({ length: 32 }, () => manager.verifyDomain('Agent.Example.COM.'));
      expect(fetchTXT).toHaveBeenCalledOnce();
      gate.resolve();
      const results = await Promise.all(calls);

      expect(new Set(results).size).toBe(1);
      expect(fetchJson.mock.calls.filter(([url]) => url === fixture.record.ek)).toHaveLength(1);
      expect(fetchJson.mock.calls.filter(([url]) => url === fixture.record.ku)).toHaveLength(1);
      expect(fetchJson.mock.calls.filter(([url]) => url === fixture.record.su)).toHaveLength(1);
      expect(binding).toHaveBeenCalledOnce();
      expect(continuity).toHaveBeenCalledOnce();
    });

    it('coalesces 32 stale-cache refreshes but refreshes again after interval-zero settlement', async () => {
      const { fixture } = await setup();
      let statusGate: ReturnType<typeof deferred> | undefined;
      const fetchJson = vi.fn(async (url: string, opts?: object) => {
        if (url === fixture.record.su && statusGate) await statusGate.promise;
        return fixture.fetchJson(url, opts);
      });
      const fetchTXT = vi.spyOn(fixture.dnsResolver, 'fetchTXT');
      const manager = new IdentityManager({ identity, verification: { statusCheckInterval: 0 } }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson });
      await manager.verifyDomain('agent.example.com');

      statusGate = deferred();
      const calls = Array.from({ length: 32 }, () => manager.verifyDomain('agent.example.com'));
      expect(fetchJson.mock.calls.filter(([url]) => url === fixture.record.su)).toHaveLength(2);
      statusGate.resolve();
      expect(new Set(await Promise.all(calls)).size).toBe(1);
      expect(fetchTXT).toHaveBeenCalledOnce();

      statusGate = undefined;
      await manager.verifyDomain('agent.example.com');
      expect(fetchJson.mock.calls.filter(([url]) => url === fixture.record.su)).toHaveLength(3);
    });

    it('shares a cold failure with current waiters and retries later', async () => {
      const { fixture } = await setup();
      const gate = deferred();
      let fail = true;
      const fetchTXT = vi.fn(async (name: string) => {
        if (fail) {
          await gate.promise;
          throw new Error('offline');
        }
        return fixture.dnsResolver.fetchTXT(name);
      });
      const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: { fetchTXT }, fetchJson: fixture.fetchJson });

      const calls = Array.from({ length: 32 }, () => manager.verifyDomain('agent.example.com'));
      expect(fetchTXT).toHaveBeenCalledOnce();
      gate.resolve();
      const settled = await Promise.allSettled(calls);
      const failures = settled.filter((result): result is PromiseRejectedResult => result.status === 'rejected');
      expect(failures).toHaveLength(32);
      expect(new Set(failures.map(result => result.reason)).size).toBe(1);
      expect(failures[0]!.reason).toMatchObject({ code: VerificationCode.DNSResolution });

      fail = false;
      await expect(manager.verifyDomain('agent.example.com')).resolves.toMatchObject({ domain: 'agent.example.com' });
      expect(fetchTXT).toHaveBeenCalledTimes(2);
    });

    it('never returns stale success when a shared status refresh fails and retries later', async () => {
      const { fixture } = await setup();
      let statusGate: ReturnType<typeof deferred> | undefined;
      let failStatus = false;
      const fetchJson = vi.fn(async (url: string, opts?: object) => {
        if (url === fixture.record.su && statusGate) {
          await statusGate.promise;
          if (failStatus) throw new Error('offline');
        }
        return fixture.fetchJson(url, opts);
      });
      const manager = new IdentityManager({ identity, verification: { statusCheckInterval: 0 } }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson });
      await manager.verifyDomain('agent.example.com');

      failStatus = true;
      statusGate = deferred();
      const calls = Array.from({ length: 32 }, () => manager.verifyDomain('agent.example.com'));
      expect(fetchJson.mock.calls.filter(([url]) => url === fixture.record.su)).toHaveLength(2);
      statusGate.resolve();
      const settled = await Promise.allSettled(calls);
      const failures = settled.filter((result): result is PromiseRejectedResult => result.status === 'rejected');
      expect(failures).toHaveLength(32);
      expect(new Set(failures.map(result => result.reason)).size).toBe(1);
      expect(failures[0]!.reason).toMatchObject({ code: VerificationCode.StatusUnavailable });

      failStatus = false;
      statusGate = undefined;
      await expect(manager.verifyDomain('agent.example.com')).resolves.toMatchObject({ domain: 'agent.example.com' });
      expect(fetchJson.mock.calls.filter(([url]) => url === fixture.record.su)).toHaveLength(3);
    });

    it('applies mTLS checks per caller after sharing reusable verification', async () => {
      const fixture = await currentProfileFixture('agent.example.com', operationalKey, 'mtls');
      const gate = deferred();
      const fetchTXT = vi.fn(async (name: string) => {
        await gate.promise;
        return fixture.dnsResolver.fetchTXT(name);
      });
      const fetchJson = vi.fn(fixture.fetchJson);
      const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: { fetchTXT }, fetchJson });
      const valid = { notAfter: new Date('2099-01-01'), san: ['agent.example.com'] };
      const mismatch = { notAfter: new Date('2099-01-01'), san: ['other.example.com'] };

      const calls = [
        manager.verifyDomain('agent.example.com', valid),
        manager.verifyDomain('agent.example.com'),
        manager.verifyDomain('agent.example.com', mismatch),
      ];
      expect(fetchTXT).toHaveBeenCalledOnce();
      gate.resolve();
      const [accepted, missing, mismatched] = await Promise.allSettled(calls);

      expect(accepted).toMatchObject({ status: 'fulfilled', value: { domain: 'agent.example.com' } });
      expect(missing).toMatchObject({ status: 'rejected', reason: { code: VerificationCode.TLSError } });
      expect(mismatched).toMatchObject({ status: 'rejected', reason: { code: VerificationCode.TLSError } });
      expect(fetchJson).toHaveBeenCalledTimes(3);
    });

    it('rejects invalid mTLS callers before refreshing cached status', async () => {
      const fixture = await currentProfileFixture('agent.example.com', operationalKey, 'mtls');
      const fetchJson = vi.fn(fixture.fetchJson);
      const manager = new IdentityManager({ identity, verification: { statusCheckInterval: 0 } }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson });
      const valid = { notAfter: new Date('2099-01-01'), san: ['agent.example.com'] };
      await manager.verifyDomain('agent.example.com', valid);

      await expect(manager.verifyDomain('agent.example.com')).rejects.toMatchObject({
        code: VerificationCode.TLSError,
      });
      expect(fetchJson).toHaveBeenCalledTimes(3);
      await expect(manager.verifyDomain('agent.example.com', valid)).resolves.toMatchObject({
        domain: 'agent.example.com',
      });
      expect(fetchJson).toHaveBeenCalledTimes(4);
    });

    it('starts new cold verification after explicit eviction and ignores old completion', async () => {
      const { fixture } = await setup();
      const first = deferred();
      const second = deferred();
      let lookup = 0;
      const fetchTXT = vi.fn(async (name: string) => {
        await (lookup++ === 0 ? first.promise : second.promise);
        return fixture.dnsResolver.fetchTXT(name);
      });
      const manager = new IdentityManager({ identity, verification: { statusCheckInterval: 60 } }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: { fetchTXT }, fetchJson: fixture.fetchJson });

      const oldCall = manager.verifyDomain('agent.example.com');
      manager.evictDomain('agent.example.com');
      const newCall = manager.verifyDomain('agent.example.com');
      expect(fetchTXT).toHaveBeenCalledTimes(2);

      second.resolve();
      const newResult = await newCall;
      first.resolve();
      await oldCall;

      await expect(manager.verifyDomain('agent.example.com')).resolves.toBe(newResult);
      expect(fetchTXT).toHaveBeenCalledTimes(2);
    });

    it('does not let an evicted status refresh remove newer verification', async () => {
      const { fixture } = await setup();
      const staleStatus = deferred();
      const cache = new InMemoryIdentityCache();
      let statusCalls = 0;
      const fetchJson = vi.fn(async (url: string, opts?: object) => {
        const result = await fixture.fetchJson(url, opts);
        if (url === fixture.record.su && ++statusCalls === 2) {
          await staleStatus.promise;
          return {
            ...result,
            data: {
              state: 'REVOKED',
              lastTransitionAt: new Date().toISOString(),
              revocationReason: 'superseded',
            },
          };
        }
        return result;
      });
      const manager = new IdentityManager({ identity, verification: { statusCheckInterval: 0 } }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, cache, fetchJson });
      await manager.verifyDomain('agent.example.com');

      const oldRefresh = manager.verifyDomain('agent.example.com');
      manager.evictDomain('agent.example.com');
      const newResult = await manager.verifyDomain('agent.example.com');
      staleStatus.resolve();
      await expect(oldRefresh).rejects.toMatchObject({ code: VerificationCode.StatusNotActive });

      expect((await manager.verifyDomain('agent.example.com')).verifiedAt).toEqual(newResult.verifiedAt);
      expect(cache.get('agent.example.com')).toBeNull(); // Domain-only keys cannot cross manager namespaces.
    });

    it('starts verification for different domains independently', async () => {
      const first = deferred();
      const second = deferred();
      const fetchTXT = vi.fn(async (name: string) => {
        await (name === '_dnsid.first.example.com' ? first.promise : second.promise);
        throw new Error('stop after barrier');
      });
      const manager = new IdentityManager({ identity }, { keyProvider, dnsResolver: { fetchTXT }, fetchJson: vi.fn() });

      const calls = [
        manager.verifyDomain('first.example.com'),
        manager.verifyDomain('second.example.com'),
      ];
      expect(fetchTXT).toHaveBeenCalledTimes(2);
      expect(fetchTXT).toHaveBeenNthCalledWith(1, '_dnsid.first.example.com', { signal: expect.any(AbortSignal) });
      expect(fetchTXT).toHaveBeenNthCalledWith(2, '_dnsid.second.example.com', { signal: expect.any(AbortSignal) });
      first.resolve();
      second.resolve();
      expect((await Promise.allSettled(calls)).every(result => result.status === 'rejected')).toBe(true);
    });
  });

  it('concatenates multi-string TXT records before parsing', async () => {
    const { fixture } = await setup();
    const raw = fixture.record.serialize();
    const midpoint = Math.floor(raw.length / 2);
    const dnsResolver = { fetchTXT: vi.fn().mockResolvedValue([[{
      strings: [raw.slice(0, midpoint), raw.slice(midpoint)], ttl: 300,
    }], DNSSECState.UNSIGNED]) };
    const manager = new IdentityManager({ identity }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver, fetchJson: fixture.fetchJson });
    await expect(manager.verifyDomain('agent.example.com')).resolves.toMatchObject({ domain: 'agent.example.com' });
  });

  it('evicts cached verification state', async () => {
    const { fixture, manager } = await setup();
    const fetchSpy = vi.spyOn(fixture.dnsResolver, 'fetchTXT');
    await manager.verifyDomain('agent.example.com');
    manager.evictDomain('agent.example.com');
    await manager.verifyDomain('agent.example.com');
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });
});
