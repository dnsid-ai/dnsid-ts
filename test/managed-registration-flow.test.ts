import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const originalExitCode = process.exitCode;
beforeEach(() => {
  vi.resetModules();
  vi.stubEnv('DNSID_API_KEY', 'owner-token');
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  process.exitCode = originalExitCode;
});

async function run(directory?: string) {
  const argv = process.argv;
  process.argv = ['node', 'index.ts', ...(directory ? [directory] : [])];
  try { await import('../examples/managed-registration/src/index.ts'); }
  finally { process.argv = argv; }
}

it('delegates sandbox registration to the SDK with explicit dev trust and the env credential', async () => {
  const sdk = await import('@dnsid-ai/sdk/node');
  const setup = vi.spyOn(sdk, 'registerManagedIdentity').mockResolvedValue({
    registration: { domain: 'agent.sandbox.dev.dnsid.ai' },
    loggedStateEvidence: { loggedState: 'ACTIVE' },
  } as never);
  await run('/tmp/dnsid-example');
  expect(setup).toHaveBeenCalledExactlyOnceWith({
    name: 'example-agent',
    loaded: {
      registry: { registryUrl: 'https://api.dev.dnsid.ai' },
      registration: {
        governanceId: 'dev.dnsid.ai', entityKeyUrl: 'https://dnsid.dev.dnsid.ai/.well-known/dnsid-ek.json',
      },
      logTrust: { managed: true },
    },
    credential: 'owner-token',
    store: expect.any(sdk.FileRegistrationStore),
  });
  const namedStore = setup.mock.calls[0][0].store.forIdentity({
    registryUrl: 'https://api.dev.dnsid.ai', organizationId: 'org-1', name: 'example-agent',
  });
  expect(namedStore.keyStorePath).toMatch(/^\/tmp\/dnsid-example\/[0-9a-f]{64}\/operational-key\.json$/);
  expect(console.log).toHaveBeenCalledWith('Verified: agent.sandbox.dev.dnsid.ai status=ACTIVE');
});

it.each(['', 'invalid token'])('rejects invalid DNSID_API_KEY %j before setup', async token => {
  const sdk = await import('@dnsid-ai/sdk/node');
  const setup = vi.spyOn(sdk, 'registerManagedIdentity');
  vi.stubEnv('DNSID_API_KEY', token);
  await run('/tmp/dnsid-example');
  expect(setup).not.toHaveBeenCalled();
  expect(process.exitCode).toBe(1);
  expect(console.error).toHaveBeenCalledWith('set DNSID_API_KEY to one API token');
});

it('requires a recovery directory before setup', async () => {
  const sdk = await import('@dnsid-ai/sdk/node');
  const setup = vi.spyOn(sdk, 'registerManagedIdentity');
  await run();
  expect(setup).not.toHaveBeenCalled();
  expect(process.exitCode).toBe(1);
});

it('redacts credentials from failures and tells the user to retain recovery state', async () => {
  const sdk = await import('@dnsid-ai/sdk/node');
  vi.spyOn(sdk, 'registerManagedIdentity').mockRejectedValue(new Error('failed for owner-token'));
  await run('/tmp/dnsid-example');
  expect(process.exitCode).toBe(1);
  expect(console.error).toHaveBeenCalledWith('failed for [REDACTED]');
  expect(console.error).toHaveBeenCalledWith('Keep your recovery files and rerun with the same directory.');
});
