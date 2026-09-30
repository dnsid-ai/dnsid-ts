import { afterEach, expect, it, vi } from 'vitest';
import { RegistryClient, type IdentityManager } from '@dnsid-ai/sdk';
import * as nodeSdk from '@dnsid-ai/sdk/node';
import * as transportSdk from '@dnsid-ai/transport';
import { EchoAgent } from '../examples/a2a/src/server.ts';
import { startEchoAgent } from '../examples/a2a/src/setup.ts';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

it('reuses loaded transport for A2A and registry clients after construction consumes it', async () => {
  vi.useFakeTimers();
  vi.stubEnv('DNSID_AGENT_PORT', '3002');
  vi.stubEnv('DNSID_PUBLIC_URL', 'https://bob.test');
  const transport = { dnsServer: '127.0.0.1:7753', caBundlePath: '/tmp/root-ca.pem', privateAddressHosts: ['.test'] };
  const identity = { domain: 'bob.test', kuUrl: 'https://bob.test/.well-known/jwks.json', logRef: 'c2sp-tlog:testnet:https://registry.test#bob.test' };
  const idm = { config: { identity, transport: {} }, verifyDomain: vi.fn().mockResolvedValue({}) } as unknown as IdentityManager;
  vi.spyOn(nodeSdk, 'loadEnvironment').mockResolvedValue({
    dnsid: { identity, transport },
    keySource: { cliDirectory: '/tmp/bob.test' },
    logTrust: { policyUrl: 'https://registry.test/dnsid-policy' },
  });
  vi.spyOn(nodeSdk, 'constructIdentityManager').mockResolvedValue(idm);
  const agent = { url: 'https://bob.test', start: vi.fn(), stop: vi.fn() } as unknown as EchoAgent;
  const createAgent = vi.spyOn(EchoAgent, 'create').mockResolvedValue(agent);
  const createFetch = vi.spyOn(transportSdk, 'createDnsidFetch').mockReturnValue(vi.fn());
  vi.spyOn(RegistryClient.prototype, 'getRegistration').mockResolvedValue({ registryStatus: 'READY' } as Awaited<ReturnType<RegistryClient['getRegistration']>>);

  const started = startEchoAgent();
  await vi.runAllTimersAsync();
  await started;

  expect(createAgent.mock.calls[0][3]?.transport).toEqual(transport);
  expect(createFetch).toHaveBeenCalledWith(transport);
});
