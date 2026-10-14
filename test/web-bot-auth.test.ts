import { beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import { Response as UndiciResponse } from 'undici';
import {
  WEB_BOT_AUTH_TAG,
  HTTP_MESSAGE_SIGNATURES_DIRECTORY_MEDIA_TYPE,
  HTTP_MESSAGE_SIGNATURES_DIRECTORY_TAG,
  WebBotAuthProfile,
  wbaDirectoryJwkFromPublicKey,
} from '@dnsid-ai/web-bot-auth';
import { parseSignatureInput, signHttpMessage } from '@dnsid-ai/http-signatures';
import type { SignatureParams } from '@dnsid-ai/http-signatures';
import type { WebBotAuthVerificationOptions } from '@dnsid-ai/web-bot-auth';
import { JWKS, VerificationError, VerificationCode } from '@dnsid-ai/protocol';
import type { VerifiedDomain } from '@dnsid-ai/protocol';
import { ArgumentError, jwkThumbprint, toArrayBuffer } from '@dnsid-ai/protocol';
import type { DnsIdJWK, KeyProvider } from '@dnsid-ai/protocol';

let privateKey: CryptoKey;
let publicJwk: DnsIdJWK;

beforeAll(async () => {
  const kp = await generateKeyPair('EdDSA');
  privateKey = kp.privateKey;
  const raw = await exportJWK(kp.publicKey);
  publicJwk = { ...raw, kty: raw.kty!, alg: 'EdDSA', kid: 'ed-key', use: 'sig' } as DnsIdJWK;
});

function makeKeyProvider(key = publicJwk): KeyProvider {
  return {
    signingKey: vi.fn().mockResolvedValue(key),
    jwk: vi.fn().mockResolvedValue(key),
    listKeyIds: vi.fn().mockResolvedValue([key.kid]),
    sign: vi.fn().mockImplementation(async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, toArrayBuffer(bytes)))),
    signKey: vi.fn().mockImplementation(async (_kid: string, bytes: Uint8Array) => new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, toArrayBuffer(bytes)))),
    generateKey: vi.fn(),
    activate: vi.fn(),
    supersede: vi.fn(),
    purge: vi.fn(),
  };
}

describe('WebBotAuthProfile verification', () => {
  const domain = 'bot.example.com';
  const policy = { signerDomain: domain };

  async function setup(options: WebBotAuthVerificationOptions = policy) {
    const signer = new WebBotAuthProfile({ domain, keyProvider: makeKeyProvider() });
    const req = await signer.createWebBotAuthSignedRequest(new Request('https://target.example/path', { method: 'POST', body: 'hello', headers: { Authorization: 'Bearer existing' } }));
    const evidence = { domain, jwks: new JWKS([publicJwk]), expiry: () => new Date(Date.now() + 60_000) } as VerifiedDomain;
    const resolver = { verifyDomain: vi.fn().mockResolvedValue(evidence) };
    const fetch = vi.fn().mockImplementation((request: Request) => signer.serveHttpMessageSignaturesDirectory(request));
    const verifier = new WebBotAuthProfile({ identityResolver: resolver, discoveryFetch: fetch });
    return { signer, req, evidence, resolver, fetch, verifier, verify: (request = req) => verifier.verifyWebBotAuthSignedRequest(request, options) };
  }

  async function resignRequest(req: Request, change: (params: SignatureParams) => void) {
    const params = parseSignatureInput(req.headers.get('Signature-Input')!).get('sig1')!;
    delete params.parameters;
    change(params);
    return signHttpMessage(req, params, makeKeyProvider());
  }

  it('verifies request/directory and forwards the current peer and cancellation', async () => {
    const peerCert = { san: [domain], notAfter: new Date(Date.now() + 60_000) };
    const s = await setup({ ...policy, peerCert });
    expect(s.req.headers.get('Authorization')).toBe('Bearer existing');
    await expect(s.verify()).resolves.toBe(s.evidence);
    expect(s.resolver.verifyDomain).toHaveBeenCalledWith(domain, peerCert, { signal: expect.any(AbortSignal) });
    expect(s.fetch.mock.calls[0][0].url).toBe(`https://${domain}/.well-known/http-message-signatures-directory`);
    expect(s.fetch.mock.calls[0][0].redirect).toBe('manual');
  });

  it('verifies signed directories returned as Undici responses', async () => {
    const s = await setup();
    s.fetch.mockImplementation(async (request: Request) => {
      const response = await s.signer.serveHttpMessageSignaturesDirectory(request);
      const fetched = new UndiciResponse(await response.arrayBuffer(), { status: response.status, headers: [...response.headers] });
      expect(fetched).not.toBeInstanceOf(Response);
      return fetched;
    });
    await expect(s.verify()).resolves.toBe(s.evidence);
  });

  it('rejects unchecked transport redirects before normalizing responses', async () => {
    const s = await setup();
    const response = new UndiciResponse(null);
    Object.defineProperty(response, 'redirected', { value: true });
    s.fetch.mockResolvedValue(response);
    await expect(s.verify()).rejects.toThrow('unchecked redirect');
    expect(s.resolver.verifyDomain).not.toHaveBeenCalled();
  });

  it.each([null, 'malformed'])('rejects invalid Content-Digest %s without cloning the request body', async value => {
    const s = await setup();
    const headers = new Headers(s.req.headers);
    if (value === null) headers.delete('Content-Digest');
    else headers.set('Content-Digest', value);
    const req = new Request(s.req, { headers });
    const clone = vi.spyOn(req, 'clone');
    await expect(s.verify(req)).rejects.toThrow('Content-Digest');
    expect(clone).not.toHaveBeenCalled();
    expect(req.bodyUsed).toBe(false);
    expect(s.fetch).not.toHaveBeenCalled();
  });

  it('requires explicit permission to infer the signer domain', async () => {
    const s = await setup({});
    await expect(s.verify()).rejects.toThrow('trusted signer domain');
    await expect(s.verifier.verifyWebBotAuthSignedRequest(s.req, { allowSignatureAgentDomain: true })).resolves.toBe(s.evidence);
  });

  it('accepts non-default labels and default directory discovery, discarding paths', async () => {
    const s = await setup();
    const headers = new Headers(s.req.headers);
    headers.set('Signature-Agent', `member="https://${domain}/ignored?query#fragment"`);
    const input = new Request(s.req, { headers });
    const params = parseSignatureInput(s.req.headers.get('Signature-Input')!).get('sig1')!;
    delete params.parameters;
    params.label = 'bot';
    params.components = ['@authority', 'content-digest', { name: 'signature-agent', params: { key: 'member' } }];
    headers.delete('Signature');
    headers.delete('Signature-Input');
    const req = await signHttpMessage(new Request(input, { headers }), params, makeKeyProvider());
    s.fetch.mockImplementation(async (request: Request) => {
      const response = await s.signer.serveHttpMessageSignaturesDirectory(request);
      const h = new Headers(response.headers);
      for (const name of ['Signature', 'Signature-Input']) h.set(name, h.get(name)!.replace(/^sig1=/, 'directory='));
      return new Response(await response.arrayBuffer(), { headers: h });
    });
    await expect(s.verify(req)).resolves.toBe(s.evidence);
    expect(s.fetch.mock.calls[0][0].url).toBe(`https://${domain}/.well-known/http-message-signatures-directory`);
  });

  it('supports trusted discovery without Signature-Agent and direct jwks_uri', async () => {
    const s = await setup({ ...policy, discovery: { uri: `https://${domain}/keys.json`, type: 'jwks_uri' } });
    const req = await s.signer.createWebBotAuthSignedRequest(new Request('https://target.example/'), { signatureAgent: false });
    await expect(s.verify(req)).resolves.toBe(s.evidence);
    expect(s.fetch.mock.calls[0][0].url).toBe(`https://${domain}/keys.json`);
  });

  it.each([
    ['wrong tag', (p: SignatureParams) => { p.tag = 'other'; }],
    ['wrong keyid', (p: SignatureParams) => { p.keyId = 'a'.repeat(43); }],
    ['missing authority', (p: SignatureParams) => { p.components = p.components.filter(c => c !== '@authority'); }],
    ['missing digest', (p: SignatureParams) => { p.components = p.components.filter(c => c !== 'content-digest'); }],
    ['missing agent coverage', (p: SignatureParams) => { p.components = ['@authority', 'content-digest']; }],
    ['wrong algorithm', (p: SignatureParams) => { p.alg = 'EdDSA'; }],
    ['expired', (p: SignatureParams) => { p.created! -= 600; p.expires! -= 600; }],
    ['long lifetime', (p: SignatureParams) => { p.expires = p.created! + 301; }],
    ['missing expires', (p: SignatureParams) => { delete p.expires; }],
  ])('rejects request %s', async (_name, change) => {
    const s = await setup();
    await expect(s.verify(await resignRequest(s.req, change))).rejects.toThrow();
  });

  it.each(['request signature', 'request content', 'directory signature', 'directory content', 'directory tag', 'directory coverage', 'directory expiry', 'directory thumbprint'])('rejects modified %s', async kind => {
    const s = await setup();
    let req = s.req;
    if (kind === 'request content') req = new Request(req, { body: 'changed' });
    if (kind === 'request signature') {
      const headers = new Headers(req.headers);
      headers.set('Signature', `sig1=:${btoa('x'.repeat(64))}:`);
      req = new Request(req, { headers });
    }
    if (kind.startsWith('directory')) s.fetch.mockImplementation(async (request: Request) => {
      const res = await s.signer.serveHttpMessageSignaturesDirectory(request);
      const headers = new Headers(res.headers);
      if (kind === 'directory signature') headers.set('Signature', `sig1=:${btoa('x'.repeat(64))}:`);
      let body = await res.text();
      if (kind === 'directory content') body += ' ';
      if (kind === 'directory thumbprint') {
        const document = JSON.parse(body);
        document.keys[0].kid = 'a'.repeat(43);
        body = JSON.stringify(document);
        headers.set('Content-Digest', `sha-256=:${btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)))))}:`);
      }
      const changed = new Response(body, { headers });
      if (['directory tag', 'directory coverage', 'directory expiry'].includes(kind)) {
        const params = parseSignatureInput(headers.get('Signature-Input')!).get('sig1')!;
        delete params.parameters;
        if (kind === 'directory tag') params.tag = WEB_BOT_AUTH_TAG;
        if (kind === 'directory coverage') params.components = ['content-digest'];
        if (kind === 'directory expiry') { params.created! -= 600; params.expires! -= 600; }
        return signHttpMessage({ message: changed, request }, params, makeKeyProvider());
      }
      return changed;
    });
    await expect(s.verify(req)).rejects.toThrow();
  });

  it.each(['missing identity', 'acceptance denial', 'missing mtls peer'])('never falls back after %s', async reason => {
    const s = await setup();
    s.resolver.verifyDomain.mockRejectedValue(new VerificationError(reason, { code: VerificationCode.TLSError }));
    await expect(s.verify()).rejects.toThrow(reason);
  });

  it('reevaluates acceptance and current keys on repeated directory use', async () => {
    const s = await setup();
    const cached = await s.signer.serveHttpMessageSignaturesDirectory(new Request(`https://${domain}/.well-known/http-message-signatures-directory`));
    s.fetch.mockImplementation(async () => cached.clone());
    await expect(s.verify()).resolves.toBe(s.evidence);
    s.resolver.verifyDomain.mockRejectedValueOnce(new Error('denied'));
    await expect(s.verify()).rejects.toThrow('denied');
    s.resolver.verifyDomain.mockResolvedValue({ ...s.evidence, jwks: new JWKS([]) });
    await expect(s.verify()).rejects.toThrow('current DNSid ku');
    expect(s.resolver.verifyDomain).toHaveBeenCalledTimes(3);
  });

  it.each(['https://127.0.0.1/', 'https://10.0.0.1/', 'https://[::1]/', 'https://localhost/', 'http://bot.example.com/', 'https://other.example/'])('rejects unapproved discovery %s', async uri => {
    const s = await setup();
    const headers = new Headers(s.req.headers);
    headers.set('Signature-Agent', `sig1="${uri}";type=directory`);
    const req = await resignRequest(new Request(s.req, { headers }), () => {});
    await expect(s.verify(req)).rejects.toThrow();
    expect(s.fetch).not.toHaveBeenCalled();
  });

  it.each(['https://127.0.0.1/', 'https://other.example/', 'http://bot.example.com/'])('rejects unsafe redirect %s', async location => {
    const s = await setup();
    s.fetch.mockResolvedValue(new Response(null, { status: 302, headers: { Location: location } }));
    await expect(s.verify()).rejects.toThrow();
    expect(s.fetch).toHaveBeenCalledTimes(1);
  });

  it('rejects ambiguous signatures', async () => {
    const s = await setup();
    const headers = new Headers(s.req.headers);
    for (const name of ['Signature', 'Signature-Input']) headers.set(name, `${headers.get(name)}, ${headers.get(name)!.replace(/^sig1=/, 'other=')}`);
    await expect(s.verify(new Request(s.req, { headers }))).rejects.toThrow('exactly one');
  });

  it('rechecks evidence freshness after discovery and nonce storage', async () => {
    const s = await setup({ ...policy, consumeNonce: async () => { s.evidence.expiry = () => new Date(0); return true; } });
    await expect(s.verify()).rejects.toThrow('evidence expired');
  });

  it('atomically rejects replay and fails closed on store errors', async () => {
    const consumeNonce = vi.fn().mockResolvedValueOnce(true).mockResolvedValueOnce(false).mockRejectedValueOnce(new Error('store down'));
    const s = await setup({ ...policy, consumeNonce });
    await expect(s.verify()).resolves.toBe(s.evidence);
    await expect(s.verify()).rejects.toThrow('replayed');
    await expect(s.verify()).rejects.toThrow('store down');
    expect(consumeNonce.mock.calls[0][0]).toMatchObject({ signerDomain: domain, keyid: await jwkThumbprint(publicJwk), nonce: expect.any(String), retainUntil: expect.any(Date) });
    await expect(s.verify(await resignRequest(s.req, p => { delete p.nonce; }))).rejects.toThrow('non-empty nonce');
  });

  it('bounds the complete operation including non-cooperative fetch and resolver', async () => {
    const s = await setup({ ...policy, timeoutMs: 10 });
    s.fetch.mockImplementationOnce(() => new Promise(() => {}));
    await expect(s.verify()).rejects.toThrow('deadline');
    s.resolver.verifyDomain.mockImplementation(() => new Promise(() => {}));
    await expect(s.verify()).rejects.toThrow('deadline');
    const controller = new AbortController();
    controller.abort();
    await expect(s.verifier.verifyWebBotAuthSignedRequest(s.req, { ...policy, signal: controller.signal })).rejects.toThrow('canceled');
  });

  it('rejects duplicate digest members and malformed discovery types', async () => {
    const s = await setup();
    for (const [name, value] of [
      ['Content-Digest', `${s.req.headers.get('Content-Digest')}, ${s.req.headers.get('Content-Digest')}`],
      ['Signature-Agent', `sig1="https://${domain}";type="directory"`],
      ['Signature-Agent', `sig1="https://${domain}";type=unsupported`],
      ['Signature-Agent', `sig1="https://${domain}", sig1="https://${domain}"`],
    ]) {
      const headers = new Headers(s.req.headers);
      headers.set(name, value);
      await expect(s.verify(new Request(s.req.clone(), { headers }))).rejects.toThrow();
    }
  });

  it.each(['size', 'depth', 'key count', 'private key'])('bounds directory %s', async kind => {
    const s = await setup();
    s.fetch.mockImplementation(async (request: Request) => {
      const res = await s.signer.serveHttpMessageSignaturesDirectory(request);
      const document = await res.json();
      if (kind === 'size') document.extra = 'x'.repeat(256 * 1024);
      if (kind === 'depth') {
        let nested = document;
        for (let i = 0; i < 20; i++) nested = nested.extra = {};
      }
      if (kind === 'key count') document.keys = Array(65).fill(document.keys[0]);
      if (kind === 'private key') document.keys[0].d = 'secret';
      const body = JSON.stringify(document);
      const headers = new Headers(res.headers);
      headers.set('Content-Digest', `sha-256=:${btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)))))}:`);
      return new Response(body, { headers });
    });
    await expect(s.verify()).rejects.toThrow();
  });

  it.each(['301', '-1', 'invalid'])('rejects stale or malformed HTTP cache Age %s', async age => {
    const s = await setup();
    s.fetch.mockImplementation(async (request: Request) => {
      const response = await s.signer.serveHttpMessageSignaturesDirectory(request);
      const headers = new Headers(response.headers);
      headers.set('Age', age);
      return new Response(await response.arrayBuffer(), { headers });
    });
    await expect(s.verify()).rejects.toThrow();
  });

  it('rejects excessive message headers and URLs', async () => {
    const s = await setup();
    const headers = new Headers(s.req.headers);
    headers.set('X-Large', 'x'.repeat(64 * 1024));
    await expect(s.verify(new Request(s.req.clone(), { headers }))).rejects.toThrow('headers exceed');
    const req = new Request(`https://target.example/${'x'.repeat(16 * 1024)}`, { headers: s.req.headers });
    await expect(s.verify(req)).rejects.toThrow('URL exceeds');
  });

  it('rejects directory evidence that expires while DNSid verification is running', async () => {
    const s = await setup();
    const expiry = new Date(Date.now() + 60_000);
    s.evidence.expiry = () => expiry;
    s.resolver.verifyDomain.mockImplementation(async () => {
      vi.spyOn(Date, 'now').mockReturnValue(expiry.getTime() + 600_000);
      return s.evidence;
    });
    try { await expect(s.verify()).rejects.toThrow('currently valid'); }
    finally { vi.restoreAllMocks(); }
  });

  it('requires verifier dependencies and rejects signing-only operations without a local key', async () => {
    const s = await setup();
    await expect(s.signer.verifyWebBotAuthSignedRequest(s.req, policy)).rejects.toThrow(ArgumentError);
    await expect(s.verifier.createWebBotAuthSignedRequest(s.req)).rejects.toThrow(ArgumentError);
  });
});

describe('WebBotAuthProfile', () => {
  it('signs requests with WBA defaults', async () => {
    const profile = new WebBotAuthProfile({ domain: 'bot.example.com', keyProvider: makeKeyProvider() });
    const signed = await profile.createWebBotAuthSignedRequest(new Request('https://target.example/path'));
    const params = parseSignatureInput(signed.headers.get('Signature-Input')!).get('sig1')!;

    expect(signed.headers.get('Signature-Agent')).toBe('sig1="https://bot.example.com";type=directory');
    expect(params.keyId).toBe(await jwkThumbprint(publicJwk));
    expect(params.alg).toBe('ed25519');
    expect(params.tag).toBe(WEB_BOT_AUTH_TAG);
    expect(params.expires! - params.created!).toBe(60);
    expect(params.nonce).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(params.components).toContain('@authority');
    expect(params.components).toContainEqual({ name: 'signature-agent', params: { key: 'sig1' } });
  });

  it('preserves other Signature-Agent dictionary members', async () => {
    const profile = new WebBotAuthProfile({ domain: 'bot.example.com', keyProvider: makeKeyProvider() });
    const signed = await profile.createWebBotAuthSignedRequest(new Request('https://target.example/path', {
      headers: { 'Signature-Agent': 'other="https://other.example/directory"' },
    }));

    expect(signed.headers.get('Signature-Agent')).toContain('other="https://other.example/directory"');
    expect(signed.headers.get('Signature-Agent')).toContain('sig1="https://bot.example.com";type=directory');
  });

  it('preserves request metadata while signing', async () => {
    const profile = new WebBotAuthProfile({ domain: 'bot.example.com', keyProvider: makeKeyProvider() });
    const controller = new AbortController();
    const signed = await profile.createWebBotAuthSignedRequest(new Request('https://target.example/path', {
      cache: 'no-store',
      credentials: 'include',
      redirect: 'manual',
      signal: controller.signal,
    }));

    expect(signed.cache).toBe('no-store');
    expect(signed.credentials).toBe('include');
    expect(signed.redirect).toBe('manual');
    controller.abort();
    expect(signed.signal.aborted).toBe(true);
  });

  it('serves and signs the HTTP Message Signatures Directory', async () => {
    const profile = new WebBotAuthProfile({ domain: 'bot.example.com', keyProvider: makeKeyProvider() });
    const res = await profile.serveHttpMessageSignaturesDirectory(new Request('https://bot.example.com/.well-known/http-message-signatures-directory'));
    const body = await res.json() as { keys: DnsIdJWK[] };
    const params = parseSignatureInput(res.headers.get('Signature-Input')!).get('sig1')!;

    expect(res.headers.get('Content-Type')).toBe(HTTP_MESSAGE_SIGNATURES_DIRECTORY_MEDIA_TYPE);
    expect(res.headers.get('Cache-Control')).toBe('max-age=300');
    expect(res.headers.get('Content-Digest')).toMatch(/^sha-256=:/);
    expect(body.keys[0]).toMatchObject({ kid: await jwkThumbprint(publicJwk), alg: 'ed25519', use: 'sig' });
    expect(params.tag).toBe(HTTP_MESSAGE_SIGNATURES_DIRECTORY_TAG);
    expect(params.components).toEqual([{ name: '@authority', params: { req: true } }, 'content-type', 'cache-control', 'content-digest']);
  });

  it('rejects non-Ed25519 signing keys', async () => {
    const profile = new WebBotAuthProfile({
      domain: 'bot.example.com',
      keyProvider: makeKeyProvider({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', kid: 'p256', alg: 'ES256' }),
    });

    await expect(profile.createWebBotAuthSignedRequest(new Request('https://target.example/'))).rejects.toThrow(ArgumentError);
  });

  it('emits an explicit jwks_uri token for direct discovery', async () => {
    const profile = new WebBotAuthProfile({
      domain: 'bot.example.com',
      keyProvider: makeKeyProvider(),
      webBotAuth: { signatureAgent: { uri: 'https://keys.example/jwks.json', type: 'jwks_uri' } },
    });
    const signed = await profile.createWebBotAuthSignedRequest(new Request('https://target.example/'));
    expect(signed.headers.get('Signature-Agent')).toBe('sig1="https://keys.example/jwks.json";type=jwks_uri');
  });

  it('rejects unsupported Signature-Agent discovery types at runtime', () => {
    expect(() => new WebBotAuthProfile({
      domain: 'bot.example.com',
      keyProvider: makeKeyProvider(),
      webBotAuth: { signatureAgent: { type: 'unsupported' } },
    } as any)).toThrow(ArgumentError);
  });

  it.each([0, -1, 301])('rejects invalid request TTL %s', async ttl => {
    const profile = new WebBotAuthProfile({ domain: 'bot.example.com', keyProvider: makeKeyProvider() });
    await expect(profile.createWebBotAuthSignedRequest(new Request('https://target.example/'), { ttl })).rejects.toThrow(ArgumentError);
  });

  it('converts directory JWKs to WBA wire shape without extra material', async () => {
    const jwk = await wbaDirectoryJwkFromPublicKey({ ...publicJwk, d: 'secret', extra: 'nope' } as DnsIdJWK);
    expect(jwk).toEqual({ kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, kid: await jwkThumbprint(publicJwk), alg: 'ed25519', use: 'sig' });
  });
});
