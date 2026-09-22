import type * as https from 'node:https';
import { afterEach, expect, it, vi } from 'vitest';
import { fetchJson } from '@dnsid-ai/transport';

const httpsGetMock = vi.hoisted(() => vi.fn());
vi.mock('node:https', async importOriginal => ({ ...await importOriginal<typeof import('node:https')>(), get: httpsGetMock }));
vi.mock('node:dns/promises', async importOriginal => ({
  ...await importOriginal<typeof import('node:dns/promises')>(),
  // Every name answers loopback, as dnsid local's DNS does for its zone.
  lookup: vi.fn(async () => [{ address: '127.0.0.1', family: 4 }]),
}));
afterEach(() => vi.restoreAllMocks());

// Names under the reserved .test TLD (RFC 2606) can never resolve publicly, so a
// loopback answer is deliberate local configuration and passes the SSRF guard
// without an allowedUnsafeHosts entry. Any other name is still rejected.
it('lets a .test name resolve to loopback, and no other name', async () => {
  httpsGetMock.mockImplementation(() => { throw new Error('stop'); });
  await fetchJson('https://agent.example/.well-known/jwks.json').catch(() => undefined);
  const [, requestOptions] = httpsGetMock.mock.calls[0] as [string, https.RequestOptions];
  const resolve = (host: string) =>
    new Promise<string>((res, rej) => requestOptions.lookup!(host, { family: 4 }, (err, address) => (err ? rej(err) : res(address as string))));

  await expect(resolve('alice.dev.dnsid.test')).resolves.toBe('127.0.0.1');
  await expect(resolve('registry.dev.dnsid.test.')).resolves.toBe('127.0.0.1');
  await expect(resolve('alice.dev.dnsid.testing')).rejects.toThrow('unsafe resolved IP address');
  await expect(resolve('agent.example')).rejects.toThrow('unsafe resolved IP address');
});
