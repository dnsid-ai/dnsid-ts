import { createServer } from 'node:http';
import { gzipSync } from 'node:zlib';
import { afterAll, beforeAll, expect, it, vi } from 'vitest';
import { createSsrfSafeFetch } from '@dnsid-ai/transport';

vi.mock('node:dns/promises', async importOriginal => ({
  ...await importOriginal<typeof import('node:dns/promises')>(),
  lookup: vi.fn().mockResolvedValue([{ address: '127.0.0.1', family: 4 }]),
}));

const compressed = gzipSync('signed representation');
const server = createServer(async (req, res) => {
  if (req.url === '/redirect') { res.writeHead(302, { Location: '/encoded' }); res.end(); return; }
  if (req.url === '/pending') { res.writeHead(200); res.flushHeaders(); return; }
  if (req.url === '/echo') {
    for await (const chunk of req) res.write(chunk);
    res.end();
    return;
  }
  res.writeHead(200, { 'Content-Encoding': 'gzip', 'Content-Length': compressed.length });
  res.end(compressed);
});
let origin: string;
beforeAll(async () => {
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('missing server port');
  origin = `http://raw.test:${address.port}`;
});
afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>(resolve => server.close(() => resolve()));
});

it.each([true, false])('preserves default decoding and supports raw response bytes: decompress=%s', async decompress => {
  const fetch = createSsrfSafeFetch({}, { privateAddressHosts: ['raw.test'], decompress });
  const response = await fetch(`${origin}/encoded`);
  expect(response.headers.get('Content-Encoding')).toBe('gzip');
  expect(Buffer.from(await response.arrayBuffer())).toEqual(decompress ? Buffer.from('signed representation') : compressed);
});

it('keeps raw redirects manual and supports bodyless responses and request streams', async () => {
  const fetch = createSsrfSafeFetch({}, { privateAddressHosts: ['raw.test'], decompress: false });
  const redirect = await fetch(`${origin}/redirect`);
  expect(redirect.status).toBe(302);
  expect(redirect.headers.get('Location')).toBe('/encoded');
  await redirect.body?.cancel();
  expect((await fetch(`${origin}/encoded`, { method: 'HEAD' })).body).toBeNull();
  const echoed = await fetch(new Request(`${origin}/echo`, { method: 'POST', body: 'exact request bytes' }));
  expect(await echoed.text()).toBe('exact request bytes');
});

it('cancels raw response streams under the caller signal', async () => {
  const fetch = createSsrfSafeFetch({}, { privateAddressHosts: ['raw.test'], decompress: false });
  const controller = new AbortController();
  const response = await fetch(`${origin}/pending`, { signal: controller.signal });
  controller.abort();
  await expect(response.text()).rejects.toThrow();
});
