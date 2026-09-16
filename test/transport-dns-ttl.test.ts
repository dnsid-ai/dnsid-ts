import * as dns from 'node:dns/promises';
import { generateKeyPairSync } from 'node:crypto';
import { afterEach, expect, it, vi } from 'vitest';
import { DNSSECState, IdentityManager, InMemoryIdentityCache, type DnsIdJWK } from '@dnsid-ai/protocol';
import { createDefaultDnsResolver } from '@dnsid-ai/transport';
import { currentProfileFixture } from './helpers/current-profile.ts';

vi.mock('node:dns/promises', async importOriginal => ({
  ...await importOriginal<typeof import('node:dns/promises')>(),
  resolveTxt: vi.fn(),
  lookup: vi.fn(),
}));
afterEach(() => vi.restoreAllMocks());

it.each([undefined, '127.0.0.1:5353', 'resolver.example:5353'])('does not cache unknown TXT TTLs via %s', async dnsServer => {
  const domain = 'agent.example.com';
  const pair = generateKeyPairSync('ed25519');
  const key = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'op', alg: 'EdDSA' } as DnsIdJWK;
  const fixture = await currentProfileFixture(domain, key);
  const raw = fixture.record.serialize();
  const strings = [raw.slice(0, 100), raw.slice(100)];
  vi.mocked(dns.resolveTxt).mockResolvedValue([strings]);
  vi.mocked(dns.lookup).mockResolvedValue({ address: '127.0.0.1', family: 4 });
  vi.spyOn(dns.Resolver.prototype, 'resolveTxt').mockResolvedValue([strings]);
  const resolver = createDefaultDnsResolver({ dnsServer });
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
