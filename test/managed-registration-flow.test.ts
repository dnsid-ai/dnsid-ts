import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import * as nodeSdk from '@dnsid-ai/sdk/node';
import { runRegistration } from '../examples/managed-registration/src/registration.ts';

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

it('delegates sandbox setup and recovery to the SDK with explicit dev trust', async () => {
  const setup = vi.spyOn(nodeSdk, 'registerManagedIdentity').mockResolvedValue({
    registration: { domain: 'agent.sandbox.dev.dnsid.ai' },
    loggedStateEvidence: { loggedState: 'ACTIVE' },
  } as never);
  const network = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json({ id: 'org-1' }));
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.stubEnv('DNSID_DOMAIN', 'old.example.com');
  await runRegistration('/tmp/dnsid-example', 'owner-token');
  const options = setup.mock.calls[0][0];
  expect(options.store).toBeInstanceOf(nodeSdk.FileRegistrationStore);
  expect(options.credential).toBe('owner-token');
  expect(options.input).toEqual({ environment: 'sandbox' });
  expect(options.loaded.dnsid?.identity).toBeUndefined();
  expect(options.loaded.keySource).toBeUndefined();
  expect(options.loaded.registry?.registryUrl).toBe('https://api.dev.dnsid.ai');
  expect(options.loaded.registration).toEqual({
    governanceId: 'dev.dnsid.ai', entityKeyUrl: 'https://dnsid.dev.dnsid.ai/.well-known/dnsid-ek.json',
  });
  expect(options.loaded.logTrust).toEqual({ managed: true });
  const signal = new AbortController().signal;
  await expect(options.adapter.resolveOrganization({} as never, signal)).resolves.toBe('org-1');
  expect(network).toHaveBeenCalledWith('https://api.dev.dnsid.ai/api/v1/org', {
    headers: { Authorization: 'Bearer owner-token' }, signal, redirect: 'error',
  });
  network.mockResolvedValueOnce(Response.json({ id: '' }));
  await expect(options.adapter.resolveOrganization({} as never, signal)).rejects.toThrow('missing organization ID');
  network.mockResolvedValueOnce(new Response(null, { status: 403 }));
  await expect(options.adapter.resolveOrganization({} as never, signal)).rejects.toThrow('HTTP 403');
  expect(() => options.fetch!('https://other.example/api/v1/agent')).toThrow('unexpected registry origin');
});

it('refuses legacy recovery files without generating a replacement identity', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dnsid-example-'));
  const network = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('unexpected network request'));
  try {
    await writeFile(join(directory, 'recovery.json'), '{}', { mode: 0o600 });
    await expect(runRegistration(directory, 'owner-token')).rejects.toMatchObject({ code: 'CORRUPT_STATE' });
    expect(network).not.toHaveBeenCalled();
    expect(await readdir(directory)).toEqual(['recovery.json']);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it('rejects a different deployment before setup and preserves SDK failures', async () => {
  const failure = new nodeSdk.ManagedRegistrationError('CORRUPT_STATE', 'storage', false);
  const setup = vi.spyOn(nodeSdk, 'registerManagedIdentity').mockRejectedValue(failure);
  vi.stubEnv('DNSID_REGISTRY_URL', 'https://other.example');
  await expect(runRegistration('/tmp/dnsid-example', 'owner-token')).rejects.toThrow('only the dev registry');
  expect(setup).not.toHaveBeenCalled();
  vi.stubEnv('DNSID_REGISTRY_URL', 'https://api.dev.dnsid.ai');
  await expect(runRegistration('/tmp/dnsid-example', 'owner-token')).rejects.toBe(failure);
});
