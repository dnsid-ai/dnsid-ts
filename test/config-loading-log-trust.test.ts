import { describe, expect, it, vi } from 'vitest';

import { DNSSECState, LogRegistry } from '@dnsid-ai/sdk';
import type { DNSResolver, JsonFetcher } from '@dnsid-ai/sdk';
import { createC2spTlogVerificationRegistry, createDnsidManagedVerificationRegistry } from '@dnsid-ai/log-c2sp-tlog';
import { constructIdentityManager, createNodeIdentityManagerFromEnvironment } from '@dnsid-ai/sdk/node';

vi.mock('@dnsid-ai/log-c2sp-tlog', async importOriginal => ({
  ...await importOriginal<typeof import('@dnsid-ai/log-c2sp-tlog')>(),
  createC2spTlogVerificationRegistry: vi.fn(async () => new LogRegistry()),
  createDnsidManagedVerificationRegistry: vi.fn(async () => new LogRegistry()),
}));

const deps = {
  dnsResolver: { fetchTXT: vi.fn().mockResolvedValue([[], DNSSECState.UNSIGNED]) } as DNSResolver,
  fetchJson: vi.fn() as JsonFetcher,
};

describe('constructIdentityManager() log trust wiring', () => {
  it('passes the loaded transport and the managed fixed defaults to the generic factory for policyUrl', async () => {
    await createNodeIdentityManagerFromEnvironment({
      DNSID_LOG_POLICY_URL: 'https://policy.test/p',
      DNSID_CA_BUNDLE: '/etc/dnsid/ca.pem',
      DNSID_PRIVATE_HOSTS: '.test',
    }); // no injected fetcher: transport settings need the SDK-managed default
    expect(createC2spTlogVerificationRegistry).toHaveBeenLastCalledWith({
      trustProfile: undefined,
      policyDocument: undefined,
      policyUrl: 'https://policy.test/p',
      transport: { caBundlePath: '/etc/dnsid/ca.pem', privateAddressHosts: ['.test'] },
      checkpointMaxAge: 600_000,
      maxBundleLifetimeMs: undefined,
      allowedClockSkew: 0,
    });
  });

  it('managed: true calls the managed factory with no options', async () => {
    await constructIdentityManager({ logTrust: { managed: true } }, deps);
    expect(createDnsidManagedVerificationRegistry).toHaveBeenLastCalledWith();
  });

  it('skips every factory when deps.logRegistry is supplied', async () => {
    vi.mocked(createC2spTlogVerificationRegistry).mockClear();
    vi.mocked(createDnsidManagedVerificationRegistry).mockClear();
    await constructIdentityManager({ logTrust: { managed: true } }, { ...deps, logRegistry: new LogRegistry() });
    expect(createC2spTlogVerificationRegistry).not.toHaveBeenCalled();
    expect(createDnsidManagedVerificationRegistry).not.toHaveBeenCalled();
  });
});
