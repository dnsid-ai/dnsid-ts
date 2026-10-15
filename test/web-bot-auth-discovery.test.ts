import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createServer } from 'node:https';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSelfSignedCert } from './helpers/self-signed-cert.ts';
const lookup = vi.hoisted(() => vi.fn());
vi.mock('node:dns/promises', () => ({ lookup }));
import { exportJWK, generateKeyPair } from 'jose';
import { WebBotAuthProfile } from '@dnsid-ai/web-bot-auth';
import { createSsrfSafeFetch } from '@dnsid-ai/transport';
import { toArrayBuffer, VerificationCode } from '@dnsid-ai/protocol';
import type { DnsIdJWK, KeyProvider } from '@dnsid-ai/protocol';

describe('WBA directory rejection over HTTPS', () => {
  let server: ReturnType<typeof createServer>;
  let origin: string;
  let directory: string;
  let keyProvider: KeyProvider;
  let caBundlePath: string;
  let closed = 0;
  beforeAll(async () => {
    const pair = await generateKeyPair('EdDSA');
    const key = { ...await exportJWK(pair.publicKey), kid: 'operational', alg: 'EdDSA' } as DnsIdJWK;
    keyProvider = {
      signingKey: async () => key,
      sign: async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey, toArrayBuffer(bytes))),
    } as KeyProvider;
    const signer = new WebBotAuthProfile({ domain: 'bot.example.com', keyProvider });
    const cert = generateSelfSignedCert('bot.example.com');
    directory = await mkdtemp(join(tmpdir(), 'dnsid-wba-tls-'));
    caBundlePath = join(directory, 'ca.pem');
    await writeFile(caBundlePath, cert.cert);
    server = createServer(cert, async (req, res) => {
      res.on('close', () => { closed++; });
      const response = await signer.serveHttpMessageSignaturesDirectory(new Request(origin + req.url));
      const headers = Object.fromEntries(response.headers);
      const mode = new URL(origin + req.url).searchParams.get('mode');
      if (mode === 'coded') headers['content-encoding'] = 'gzip';
      if (mode === 'expired') headers['signature-input'] = headers['signature-input']!.replace(/(created|expires)=(\d+)/g, (_, name, value) => `${name}=${Number(value) - 3600}`);
      res.writeHead(mode === '503' ? 503 : 200, headers);
      // Keep the raw body open so rejection must cancel the network stream.
      res.write(' ');
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    origin = `https://bot.example.com:${(server.address() as { port: number }).port}`;
  });
  afterAll(async () => {
    server?.closeAllConnections();
    if (server) await new Promise<void>(resolve => server.close(() => resolve()));
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  it.each(['503', 'coded', 'expired'])('returns a verification error and closes the raw body for %s', async mode => {
    lookup.mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
    const signer = new WebBotAuthProfile({ domain: 'bot.example.com', keyProvider,
      webBotAuth: { signatureAgent: { uri: `${origin}/directory?mode=${mode}`, type: 'jwks_uri' } } });
    const request = await signer.createWebBotAuthSignedRequest(new Request('https://target.example/'));
    const fetch = createSsrfSafeFetch({ caBundlePath }, { decompress: false, privateAddressHosts: ['bot.example.com'] });
    const resolver = { verifyDomain: vi.fn(), refreshDomain: vi.fn() };
    const verifier = new WebBotAuthProfile({ identityResolver: resolver, discoveryFetch: request => fetch(request) });
    const before = closed;
    await expect(verifier.verifyWebBotAuthSignedRequest(request, { signerDomain: 'bot.example.com' })).rejects.toMatchObject({
      code: mode === '503' ? VerificationCode.TLSError : VerificationCode.SignatureInvalid,
      transient: mode === '503',
    });
    await vi.waitFor(() => expect(closed).toBe(before + 1));
    expect(resolver.verifyDomain).not.toHaveBeenCalled();
  });
});

describe('WBA public-address transport', () => {
  it.each(['127.0.0.1', '10.0.0.1', '169.254.169.254', 'fc00::1', '224.0.0.1'])('rejects discovery resolving to %s', async address => {
    lookup.mockResolvedValue([{ address, family: address.includes(':') ? 6 : 4 }]);
    const pair = await generateKeyPair('EdDSA');
    const key = { ...await exportJWK(pair.publicKey), kid: 'operational', alg: 'EdDSA' } as DnsIdJWK;
    const keyProvider = {
      signingKey: async () => key,
      sign: async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey, toArrayBuffer(bytes))),
    } as KeyProvider;
    const signer = new WebBotAuthProfile({ domain: 'bot.example.com', keyProvider });
    const req = await signer.createWebBotAuthSignedRequest(new Request('https://target.example/'));
    const safeFetch = createSsrfSafeFetch({}, { decompress: false });
    const resolver = { verifyDomain: vi.fn(), refreshDomain: vi.fn() };
    const verifier = new WebBotAuthProfile({ identityResolver: resolver, discoveryFetch: request => safeFetch(request) });
    await expect(verifier.verifyWebBotAuthSignedRequest(req, { signerDomain: 'bot.example.com' })).rejects.toThrow();
    expect(lookup).toHaveBeenCalledWith('bot.example.com', expect.any(Object));
    expect(resolver.verifyDomain).not.toHaveBeenCalled();
  });
});
