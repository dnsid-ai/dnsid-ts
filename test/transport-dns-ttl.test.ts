import * as dns from 'node:dns/promises';
import { generateKeyPairSync } from 'node:crypto';
import { afterEach, expect, it, vi } from 'vitest';
import { DNSSECMode, DNSSECState, IdentityManager, InMemoryIdentityCache, VerificationCode, type DnsIdJWK } from '@dnsid-ai/protocol';
import { createDefaultDnsResolver, createDnsResolverFromServer } from '@dnsid-ai/transport';
import { currentProfileFixture } from './helpers/current-profile.ts';

vi.mock('node:dns/promises', async importOriginal => ({
  ...await importOriginal<typeof import('node:dns/promises')>(),
  resolveTxt: vi.fn(),
  lookup: vi.fn(),
  getServers: vi.fn().mockReturnValue([]),
}));
afterEach(() => vi.restoreAllMocks());

it.each(['ETIMEOUT', 'ECONNREFUSED', 'ENETUNREACH', 'ESERVFAIL'])('keeps system %s failures transient', async code => {
  const cause = Object.assign(new Error('upstream failed'), { code });
  vi.mocked(dns.resolveTxt).mockRejectedValue(cause);
  const resolver = createDefaultDnsResolver({});
  await expect(resolver.fetchTXT('_dnsid.example.com')).rejects.toBe(cause);
  const manager = new IdentityManager({}, { dnsResolver: resolver });
  await expect(manager.verifyDomain('example.com')).rejects.toMatchObject({ code: VerificationCode.DNSResolution, transient: true });
});

it.each(['empty', 'ENOTFOUND', 'ENODATA'])('normalizes system %s absence before DNSSEC policy', async outcome => {
  if (outcome === 'empty') vi.mocked(dns.resolveTxt).mockResolvedValue([]);
  else vi.mocked(dns.resolveTxt).mockRejectedValue(Object.assign(new Error('not found'), { code: outcome }));
  const resolver = createDefaultDnsResolver({});
  await expect(resolver.fetchTXT('_dnsid.example.com')).resolves.toEqual([[], DNSSECState.UNKNOWN]);
  for (const dnssecMode of Object.values(DNSSECMode)) {
    const manager = new IdentityManager({ verification: { dnssecMode } }, { dnsResolver: resolver });
    await expect(manager.verifyDomain('example.com')).rejects.toMatchObject({
      code: dnssecMode === DNSSECMode.auto ? VerificationCode.RecordNotFound : VerificationCode.DNSSECFailed, transient: false,
    });
  }
});

it.each([
  { label: 'multiple', records: [['first'], ['second']] },
  { label: 'malformed', records: [['not a DNSid record']] },
])('keeps $label system TXT records non-transient RecordInvalid', async ({ records }) => {
  vi.mocked(dns.resolveTxt).mockResolvedValue(records);
  const manager = new IdentityManager({}, { dnsResolver: createDefaultDnsResolver({}) });
  await expect(manager.verifyDomain('example.com')).rejects.toMatchObject({ code: VerificationCode.RecordInvalid, transient: false });
});

it('does not mistake a missing configured resolver hostname for an absent identity', async () => {
  vi.mocked(dns.lookup).mockRejectedValue(Object.assign(new Error('resolver not found'), { code: 'ENOTFOUND' }));
  const resolver = createDnsResolverFromServer('missing-resolver.example');
  await expect(resolver.fetchTXT('_dnsid.example.com')).rejects.toMatchObject({ code: VerificationCode.DNSResolution, transient: true });
  const manager = new IdentityManager({}, { dnsResolver: resolver });
  await expect(manager.verifyDomain('example.com')).rejects.toMatchObject({ code: VerificationCode.DNSResolution, transient: true });
});

it('falls back to TTL 0 when no system DNS servers are available', async () => {
  const domain = 'agent.example.com';
  const pair = generateKeyPairSync('ed25519');
  const key = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'op', alg: 'EdDSA' } as DnsIdJWK;
  const fixture = await currentProfileFixture(domain, key);
  const raw = fixture.record.serialize();
  const strings = [raw.slice(0, 100), raw.slice(100)];
  vi.mocked(dns.resolveTxt).mockResolvedValue([strings]);
  const resolver = createDefaultDnsResolver({});
  await expect(resolver.fetchTXT(`_dnsid.${domain}`)).resolves.toEqual([
    [{ strings, ttl: 0 }], DNSSECState.UNKNOWN,
  ]);
  const fetchTXT = vi.spyOn(resolver, 'fetchTXT');
  const cache = new InMemoryIdentityCache();
  const manager = new IdentityManager({}, { logRegistry: fixture.logRegistry, dnsResolver: resolver, cache, fetchJson: fixture.fetchJson });
  const first = await manager.verifyDomain(domain);
  const second = await manager.verifyDomain(domain);
  expect(first.dnsTTL).toBe(0);
  expect(first.expiry().getTime()).toBeLessThanOrEqual(Date.now());
  expect(second).not.toBe(first);
  expect(fetchTXT).toHaveBeenCalledTimes(2);
  expect(cache.get(domain)).toBeNull();
});
