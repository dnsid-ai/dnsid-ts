import { createServer } from 'node:https';
import type { Server } from 'node:https';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { generateKeyPair, exportJWK } from 'jose';
import { HttpSignaturesProfile } from '@dnsid-ai/http-signatures';
import { createResponseSignatureTransport } from '@dnsid-ai/transport';
import { IdentityManager, toArrayBuffer } from '@dnsid-ai/protocol';
import type { KeyProvider, DnsIdJWK } from '@dnsid-ai/protocol';
import { currentProfileFixture } from './helpers/current-profile.ts';
import { generateSelfSignedCert } from './helpers/self-signed-cert.ts';

let server: Server, profile: HttpSignaturesProfile, origin: string;
let transport: ReturnType<typeof createResponseSignatureTransport>;
let directory: string;
const counts = new Map<string, number>();
const coded = gzipSync('exact representation');
const closed: string[] = [];
const sockets: unknown[] = [];
const framing: (string | undefined)[] = [];

beforeAll(async () => {
  const pair = await generateKeyPair('ES256');
  const key: DnsIdJWK = { ...await exportJWK(pair.publicKey), kty: 'EC', kid: 'current', alg: 'ES256' };
  const provider: KeyProvider = {
    signingKey: async () => key,
    sign: async bytes => new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, toArrayBuffer(bytes))),
    jwk: async () => key, listKeyIds: async () => [key.kid], signKey: vi.fn(), generateKey: vi.fn(), activate: vi.fn(), supersede: vi.fn(), purge: vi.fn(),
  };
  const fixture = await currentProfileFixture('localhost', key, 'mtls');
  const manager = new IdentityManager({}, { ...fixture });
  profile = new HttpSignaturesProfile({ domain: 'localhost', keyProvider: provider, identityResolver: manager });
  const tls = generateSelfSignedCert('localhost');
  directory = mkdtempSync(join(tmpdir(), 'dnsid-response-'));
  const caBundlePath = join(directory, 'ca.pem'); writeFileSync(caBundlePath, tls.cert);
  transport = createResponseSignatureTransport({ caBundlePath });
  server = createServer(tls, async (incoming, outgoing) => {
    const path = incoming.url!;
    counts.set(path, (counts.get(path) ?? 0) + 1);
    if (path === '/reuse') { sockets.push(incoming.socket); framing.push(incoming.headers['content-length'] ?? incoming.headers['transfer-encoding']); }
    outgoing.on('close', () => closed.push(path));
    if (path === '/reset') { incoming.socket.destroy(); return; }
    if (path === '/upgrade') { outgoing.writeHead(101, { Connection: 'Upgrade', Upgrade: 'test' }); outgoing.end(); return; }
    if (path === '/unsigned') { outgoing.writeHead(503); outgoing.flushHeaders(); return; }
    const chunks: Buffer[] = []; for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
    const body = Buffer.concat(chunks);
    const request = new Request(`${origin}${path}`, { method: incoming.method, headers: incoming.headers as Record<string, string>, ...(body.length ? { body } : {}) });
    const response = await profile.signRequestedHttpResponse(request, new Response(path === '/gzip' ? coded : 'intact', {
      status: path === '/redirect' ? 302 : path === '/error' ? 503 : 200,
      headers: path === '/redirect' ? { Location: '/final' } : path === '/gzip' ? { 'Content-Encoding': 'gzip' } : {},
    }));
    outgoing.writeHead(response.status, Object.fromEntries(response.headers));
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  });
  server.on('connect', (_request, socket) => {
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    socket.on('error', () => {});
    socket.on('end', () => socket.destroy());
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `https://localhost:${(server.address() as { port: number }).port}`;
});
afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>(resolve => server.close(() => resolve()));
  rmSync(directory, { recursive: true, force: true });
});

function client() {
  return profile.createSignedFetch({ fetch: vi.fn(), responseTransport: transport, signing: { responseSignature: { expectedDomain: 'localhost' } } });
}

describe('NR14/21 actual HTTPS current peer', () => {
  it('uses the actual peer on repeated requests', async () => {
    for (let i = 0; i < 2; i++) expect(await (await client()(`${origin}/success`)).text()).toBe('intact');
    expect(counts.get('/success')).toBe(2);
  });
  it('reuses keep-alive connections and sends buffered bodies with Content-Length', async () => {
    const fetch = client();
    for (let i = 0; i < 2; i++) expect(await (await fetch(`${origin}/reuse`, { method: 'POST', body: 'abc' })).text()).toBe('intact');
    expect(sockets).toHaveLength(2);
    expect(sockets[0]).toBe(sockets[1]);
    expect(framing).toEqual(['3', '3']);
  });
});

describe('NR10/11 exact encoded response bytes', () => {
  it('verifies content before decoding and returns intact coded bytes', async () => {
    const response = await client()(`${origin}/gzip`);
    expect(response.headers.get('Content-Encoding')).toBe('gzip');
    expect(Buffer.from(await response.arrayBuffer())).toEqual(coded);
  });
});

describe('NR22/23 actual transport redirects and retries', () => {
  it('returns a signed redirect without sending a second request', async () => {
    const response = await client()(`${origin}/redirect`, { redirect: 'follow' });
    expect(response.status).toBe(302); expect(await response.text()).toBe('intact');
    expect(counts.get('/redirect')).toBe(1); expect(counts.has('/final')).toBe(false);
  });
  it('returns a signed HTTP error after verification', async () => {
    const response = await client()(`${origin}/error`);
    expect(response.status).toBe(503); expect(await response.text()).toBe('intact');
  });
  it('does not replay when the server drops the connection', async () => {
    await expect(client()(`${origin}/reset`)).rejects.toMatchObject({ code: 'TLSError' });
    expect(counts.get('/reset')).toBe(1);
  });
});

describe('NR24 actual upgrade and tunnel rejection', () => {
  it('rejects HTTP protocol upgrades', async () => {
    await expect(client()(`${origin}/upgrade`)).rejects.toMatchObject({ code: 'SignatureInvalid', transient: false });
  });
  it('rejects tunnel establishment', async () => {
    const request = new Request(origin); Object.defineProperty(request, 'method', { value: 'CONNECT' });
    await expect(transport(request)).rejects.toMatchObject({ code: 'SignatureInvalid', transient: false });
  });
});

describe('NR25 actual transport cleanup', () => {
  it('keeps Web PKI certificate failures permanent', async () => {
    const untrusted = createResponseSignatureTransport();
    await expect(untrusted(new Request(origin))).rejects.toMatchObject({ code: 'TLSError', transient: false });
  });
  it('closes an unread rejected response connection', async () => {
    await expect(client()(`${origin}/unsigned`)).rejects.toMatchObject({ code: 'SignatureInvalid' });
    await vi.waitFor(() => expect(closed).toContain('/unsigned'));
  });
  it('rejects plaintext before transport work', async () => {
    await expect(transport(new Request('http://localhost/'))).rejects.toThrow('HTTPS');
  });
});
