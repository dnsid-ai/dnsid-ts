import { createServer, type RequestListener, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import { HttpSignaturesProfile } from '@dnsid-ai/http-signatures';
import { IdentityManager, toArrayBuffer } from '@dnsid-ai/protocol';
import type { DnsIdJWK, KeyProvider } from '@dnsid-ai/protocol';
import { createResponseSigningMiddleware } from '@dnsid-ai/sdk/node';
import { currentProfileFixture } from './helpers/current-profile.ts';

const domain = 'service.example.com';
const policy = { expectedDomain: domain, additionalComponents: ['content-type'] };
let profile: HttpSignaturesProfile;
let server: Server | undefined;

beforeAll(async () => {
  const pair = await generateKeyPair('ES256');
  const key: DnsIdJWK = { ...await exportJWK(pair.publicKey), kty: 'EC', kid: 'current', alg: 'ES256', use: 'sig' };
  const provider = {
    signingKey: vi.fn(async () => key),
    sign: vi.fn(async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, toArrayBuffer(bytes)))),
    jwk: vi.fn(async () => key), listKeyIds: vi.fn(async () => [key.kid]),
    signKey: vi.fn(), generateKey: vi.fn(), activate: vi.fn(), supersede: vi.fn(), purge: vi.fn(),
  } as unknown as KeyProvider;
  const manager = new IdentityManager({}, { ...await currentProfileFixture(domain, key) });
  profile = new HttpSignaturesProfile({ domain, identityResolver: manager, keyProvider: provider });
});
afterEach(() => new Promise<void>(resolve => (server ? server.close(() => resolve()) : resolve())));

/** Serves handler behind the middleware and sends one request for https://service.example.com{path}. */
async function exchange(handler: RequestListener, init: { method?: string; negotiate?: boolean; path?: string } = {}) {
  const middleware = createResponseSigningMiddleware(profile, { origin: `https://${domain}` });
  server = createServer((req, res) => middleware(req, res, () => handler(req, res)));
  await new Promise<void>(resolve => server!.listen(0, '127.0.0.1', resolve));
  const path = init.path ?? '/op?x=1';
  let request = new Request(`https://${domain}${path}`, { method: init.method ?? 'GET' });
  if (init.negotiate !== false) request = await profile.createSignedHttpRequest(request, { responseSignature: policy });
  const { port } = server.address() as AddressInfo;
  const response = await fetch(`http://127.0.0.1:${port}${path}`, { method: request.method, headers: request.headers });
  return { request, response };
}
const verify = ({ request, response }: Awaited<ReturnType<typeof exchange>>) => profile.verifySignedHttpResponse(request, response, policy);

describe('createResponseSigningMiddleware', () => {
  it('signs content written through writeHead, write, and end', async () => {
    const result = await exchange((_req, res) => {
      res.writeHead(201, 'Made', { 'content-type': 'text/plain', 'x-multi': ['a', 'b'] });
      res.write('exact ');
      res.end(Buffer.from('content'));
    });
    expect(result.response.status).toBe(201);
    expect((await verify(result)).domain).toBe(domain);
    expect(await result.response.text()).toBe('exact content');
    expect(result.response.headers.get('x-multi')).toBe('a, b');
  });

  it.each([['HEAD', 200], ['GET', 204], ['GET', 304]])('signs %s with status %i and no content', async (method, status) => {
    const result = await exchange((_req, res) => {
      res.setHeader('content-type', 'text/plain');
      res.statusCode = status;
      res.end();
    }, { method });
    expect(result.response.status).toBe(status);
    expect((await verify(result)).domain).toBe(domain);
  });

  it('passes requests without Accept-Signature through unbuffered', async () => {
    const result = await exchange((_req, res) => {
      res.flushHeaders();
      res.end('plain');
    }, { negotiate: false });
    expect(result.response.headers.has('signature')).toBe(false);
    expect(await result.response.text()).toBe('plain');
  });

  it('sends an unsigned empty 500 when the handler streams', async () => {
    const result = await exchange((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.flushHeaders();
      res.write('data: x\n\n');
    });
    expect(result.response.status).toBe(500);
    expect(result.response.headers.has('signature')).toBe(false);
    expect(await result.response.text()).toBe('');
  });

  it('sends an unsigned empty 500 above 8 MiB', async () => {
    const result = await exchange((_req, res) => {
      res.write(Buffer.alloc(8 * 1024 * 1024));
      res.end('x');
    });
    expect(result.response.status).toBe(500);
    expect(result.response.headers.has('signature')).toBe(false);
  });

  it('sends an unsigned empty 500 when signing fails', async () => {
    const result = await exchange((_req, res) => {
      res.setHeader('signature', 'sig1=:AA==:'); // label collision
      res.end('content');
    });
    expect(result.response.status).toBe(500);
    expect(await result.response.text()).toBe('');
  });
});
