import { afterEach, describe, expect, it } from 'vitest';
import * as http from 'node:http';
import { getGlobalDispatcher } from 'undici';
import { createDnsidFetch } from '@dnsid-ai/transport';
import type { TransportConfig } from '@dnsid-ai/transport';

const CONFIG: TransportConfig = {};

describe('createDnsidFetch()', () => {
  let server: http.Server | undefined;

  afterEach(async () => {
    if (server) {
      await new Promise<void>((resolve, reject) => server!.close(err => err ? reject(err) : resolve()));
      server = undefined;
    }
  });

  it('does not mutate global fetch or Undici global dispatcher', () => {
    const originalFetch = globalThis.fetch;
    const originalDispatcher = getGlobalDispatcher();
    createDnsidFetch({ ...CONFIG, dnsServer: '127.0.0.1:7753' });
    expect(globalThis.fetch).toBe(originalFetch);
    expect(getGlobalDispatcher()).toBe(originalDispatcher);
  });

  it('behaves like standard fetch when no DNS server or CA bundle is configured', async () => {
    server = http.createServer((_req, res) => res.end('ok'));
    await new Promise<void>(resolve => server!.listen(0, '127.0.0.1', () => resolve()));
    const port = (server.address() as import('node:net').AddressInfo).port;

    const dnsidFetch = createDnsidFetch(CONFIG);
    const resp = await dnsidFetch(`http://127.0.0.1:${port}/hello`);
    expect(await resp.text()).toBe('ok');
  });
});
