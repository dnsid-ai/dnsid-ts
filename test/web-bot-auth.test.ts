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
import { JWKS, VerificationError, VerificationCode, VerifiedDomain, DnsIdTxtRecord, DNSSECState, NoopLogReader, IdentityManager } from '@dnsid-ai/protocol';
import { currentProfileFixture } from './helpers/current-profile.ts';
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
    const evidence = new VerifiedDomain({
      domain, jwks: new JWKS([publicJwk]), record: new DnsIdTxtRecord(), signingKey: publicJwk,
      signingKeyThumbprint: await jwkThumbprint(publicJwk), tlsCert: { san: [domain], notAfter: new Date(Date.now() + 60_000) },
      recordSigningTlsCert: { san: [domain], notAfter: new Date(Date.now() + 60_000) },
      registryStatus: { state: 'ACTIVE', lastTransitionAt: new Date() }, verifiedAt: new Date(), dnsTTL: 60,
      keyBoundAt: new Date(0), lastStatusCheckAt: new Date(), dnssecState: DNSSECState.UNKNOWN, logReader: new NoopLogReader('test'),
    });
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

  function rewriteDirectory(s: Awaited<ReturnType<typeof setup>>, change: (document: { keys: DnsIdJWK[] }, headers: Headers, params: SignatureParams) => void) {
    s.fetch.mockImplementation(async (request: Request) => {
      const response = await s.signer.serveHttpMessageSignaturesDirectory(request);
      const document = await response.json();
      const headers = new Headers(response.headers);
      const params = parseSignatureInput(headers.get('Signature-Input')!).get('sig1')!;
      delete params.parameters;
      change(document, headers, params);
      const body = JSON.stringify(document);
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)));
      headers.set('Content-Digest', `sha-256=:${btoa(String.fromCharCode(...digest))}:`);
      return signHttpMessage({ message: new Response(body, { headers }), request }, params, makeKeyProvider());
    });
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

  it('reevaluates acceptance and current keys on repeated fresh discovery', async () => {
    const s = await setup();
    await expect(s.verify()).resolves.toBe(s.evidence);
    s.resolver.verifyDomain.mockRejectedValueOnce(new Error('denied'));
    await expect(s.verify()).rejects.toThrow('denied');
    s.resolver.verifyDomain.mockResolvedValue({ ...s.evidence, jwks: new JWKS([]) });
    await expect(s.verify()).rejects.toThrow('operational');
    expect(s.resolver.verifyDomain).toHaveBeenCalledTimes(3);
    expect(s.fetch).toHaveBeenCalledTimes(3);
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
    const s = await setup({ ...policy, consumeNonce: async () => { s.evidence.tlsCert.notAfter = new Date(0); return true; } });
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

  it.each([false, true])('uses a fresh no-store, max-age=0 directory with Date metadata: %s', async metadata => {
    const s = await setup();
    rewriteDirectory(s, (_document, headers, params) => {
      headers.set('Cache-Control', 'no-store, max-age=0');
      if (metadata) { headers.set('Date', new Date().toUTCString()); headers.set('Age', '0'); }
      params.created! -= 60;
      params.expires! -= 60;
    });
    await expect(s.verify()).resolves.toBe(s.evidence);
    expect(s.fetch.mock.calls[0][0].cache).toBe('no-store');
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
    s.evidence.tlsCert.notAfter = expiry;
    s.resolver.verifyDomain.mockImplementation(async () => {
      vi.spyOn(Date, 'now').mockReturnValue(expiry.getTime() + 600_000);
      return s.evidence;
    });
    try { await expect(s.verify()).rejects.toThrow('currently valid'); }
    finally { vi.restoreAllMocks(); }
  });

  it('rejects an auxiliary non-signing ku key even when it signs valid WBA evidence', async () => {
    const s = await setup();
    const pair = await generateKeyPair('EdDSA');
    const raw = await exportJWK(pair.publicKey);
    const current = { ...raw, kty: raw.kty!, kid: 'current', alg: 'EdDSA', use: 'sig' } as DnsIdJWK;
    const fixture = await currentProfileFixture(domain, current);
    const resolver = new IdentityManager({}, {
      dnsResolver: fixture.dnsResolver, logRegistry: fixture.logRegistry,
      fetchJson: async (url, options) => {
        const result = await fixture.fetchJson(url, options);
        if (url === fixture.record.ku) result.data = { keys: [current, { ...publicJwk, use: 'enc' }] };
        return result;
      },
    });
    const verifier = new WebBotAuthProfile({ identityResolver: resolver, discoveryFetch: s.fetch });
    await expect(verifier.verifyWebBotAuthSignedRequest(s.req, policy)).rejects.toThrow('current DNSid operational');
  });

  it.each(['missing identity', 'acceptance denial', 'missing mtls peer'])('rejects %s with the real configured identity manager', async kind => {
    const s = await setup();
    const fixture = await currentProfileFixture(domain, publicJwk, kind === 'missing mtls peer' ? 'mtls' : undefined);
    const resolver = new IdentityManager({ verification: { trustedEntities: kind === 'acceptance denial' ? [] : [{ governanceId: 'example.com' }] } }, {
      dnsResolver: kind === 'missing identity' ? { fetchTXT: async () => [[], DNSSECState.UNKNOWN] } : fixture.dnsResolver,
      logRegistry: fixture.logRegistry, fetchJson: fixture.fetchJson,
    });
    const verifier = new WebBotAuthProfile({ identityResolver: resolver, discoveryFetch: s.fetch });
    await expect(verifier.verifyWebBotAuthSignedRequest(s.req, policy)).rejects.toBeInstanceOf(VerificationError);
    if (kind === 'missing mtls peer') await expect(verifier.verifyWebBotAuthSignedRequest(s.req, {
      ...policy, peerCert: { san: [domain], notAfter: new Date(Date.now() + 60_000) },
    })).resolves.toBeInstanceOf(VerifiedDomain);
  });

  it('uses fresh zero-TTL evidence only within each acquiring invocation', async () => {
    const s = await setup();
    const fixture = await currentProfileFixture(domain, publicJwk);
    const fetchTXT = vi.fn().mockImplementation(async () => {
      const [records, state] = await fixture.dnsResolver.fetchTXT('');
      return [records.map(record => ({ ...record, ttl: 0 })), state];
    });
    const resolver = new IdentityManager({}, { dnsResolver: { fetchTXT }, logRegistry: fixture.logRegistry, fetchJson: fixture.fetchJson });
    const verifier = new WebBotAuthProfile({ identityResolver: resolver, discoveryFetch: s.fetch });
    for (let i = 0; i < 2; i++) {
      const evidence = await verifier.verifyWebBotAuthSignedRequest(s.req, policy);
      expect(evidence.dnsTTL).toBe(0);
      expect(evidence.expiry().getTime()).toBeLessThanOrEqual(Date.now());
    }
    expect(fetchTXT).toHaveBeenCalledTimes(2);
  });

  it.each(['runtime certificate', 'entity certificate', 'key age', 'positive DNS TTL'])('rejects expired %s after replay storage, including zero-TTL evidence', async kind => {
    const s = await setup({ ...policy, consumeNonce: async () => {
      if (kind === 'runtime certificate') s.evidence.tlsCert.notAfter = new Date(0);
      if (kind === 'entity certificate') s.evidence.recordSigningTlsCert.notAfter = new Date(0);
      if (kind === 'key age') s.evidence.record.ka = '24h';
      if (kind === 'positive DNS TTL') s.evidence.dnsExpiresAt.setTime(0);
      return true;
    } });
    if (kind !== 'positive DNS TTL') Object.defineProperty(s.evidence, 'dnsTTL', { value: 0 });
    await expect(s.verify()).rejects.toThrow('evidence expired');
  });

  it('requires exact application component coverage before discovery', async () => {
    const s = await setup({ ...policy, requiredComponents: ['@method', '@path', { name: '@query-param', params: { name: 'operation' } }] });
    await expect(s.verify()).rejects.toThrow('coverage');
    expect(s.fetch).not.toHaveBeenCalled();
    const req = await s.signer.createWebBotAuthSignedRequest(new Request('https://target.example/path?operation=create'), {
      additionalComponents: ['@method', '@path', { name: '@query-param', params: { name: 'operation' } }],
    });
    await expect(s.verify(req)).resolves.toBe(s.evidence);
    await expect(s.verifier.verifyWebBotAuthSignedRequest(req, { ...policy, requiredComponents: [{ name: '@query-param', params: { name: 'other' } }] })).rejects.toThrow('coverage');
  });

  it.each([null, 'invalid', [null], [42], [{}], [{ name: '@unknown' }], [{ name: '@method', params: { req: false } }], [{ name: '@method', params: [] }]].map(requiredComponents => ({ requiredComponents })))('rejects malformed coverage policy $requiredComponents before discovery', async ({ requiredComponents }) => {
    const s = await setup({ ...policy, requiredComponents } as WebBotAuthVerificationOptions);
    await expect(s.verify()).rejects.toThrow(ArgumentError);
    expect(s.fetch).not.toHaveBeenCalled();
  });

  it.each([null, 'verify', [], ['sign'], ['encrypt'], ['verify', 'verify'], ['verify', 1], ['verify', 'encrypt']].map(operations => ({ operations })))('rejects directory key_ops $operations', async ({ operations }) => {
    const s = await setup();
    rewriteDirectory(s, document => { document.keys[0]!.key_ops = operations; });
    await expect(s.verify()).rejects.toThrow('key_ops');
  });

  it.each([['verify'], ['sign', 'verify']].map(operations => ({ operations })))('accepts directory key_ops $operations', async ({ operations }) => {
    const s = await setup();
    rewriteDirectory(s, document => { document.keys[0]!.key_ops = operations; });
    await expect(s.verify()).resolves.toBe(s.evidence);
  });

  it('accepts valid directory signatures covering the actual response status', async () => {
    const s = await setup();
    rewriteDirectory(s, (_document, _headers, params) => { params.components.push('@status'); });
    await expect(s.verify()).resolves.toBe(s.evidence);
    expect(s.fetch.mock.calls[0][0].headers.get('Accept-Encoding')).toBe('identity');
    expect(s.fetch.mock.calls[0][0].cache).toBe('no-store');
  });

  it.each(['gzip', 'identity', ''])('rejects any directory Content-Encoding %j without reading the body', async encoding => {
    const s = await setup();
    const response = new Response('not a directory', { headers: { 'Content-Encoding': encoding } });
    const reader = vi.spyOn(response.body!, 'getReader');
    s.fetch.mockResolvedValue(response);
    await expect(s.verify()).rejects.toThrow('coded');
    expect(reader).not.toHaveBeenCalled();
  });

  it.each(['request', 'directory'])('rejects one valid plus one invalid complete %s candidate', async kind => {
    const s = await setup();
    const duplicate = (headers: Headers) => {
      headers.append('Signature-Input', headers.get('Signature-Input')!.replace(/^sig1=/, 'other='));
      headers.append('Signature', `other=:${btoa('x'.repeat(64))}:`);
    };
    if (kind === 'directory') s.fetch.mockImplementation(async (request: Request) => {
      const response = await s.signer.serveHttpMessageSignaturesDirectory(request);
      const headers = new Headers(response.headers);
      duplicate(headers);
      return new Response(response.body, { headers });
    });
    const headers = new Headers(s.req.headers);
    if (kind === 'request') duplicate(headers);
    await expect(s.verify(new Request(s.req, { headers }))).rejects.toThrow('exactly one');
  });

  it.each([false, true])('propagates cache transport freshness enforcement with Date metadata: %s', async metadata => {
    const s = await setup();
    const acquiredAt = Date.now();
    rewriteDirectory(s, (_document, headers) => {
      headers.set('Cache-Control', 'max-age=60');
      if (metadata) { headers.set('Date', new Date(acquiredAt).toUTCString()); headers.set('Age', '0'); }
    });
    const cached = await s.fetch(new Request(`https://${domain}/.well-known/http-message-signatures-directory`));
    s.fetch.mockImplementation(async () => {
      // An injected cache owns the acquisition metadata and must not reset age on delivery.
      if (Date.now() >= acquiredAt + 60_000) throw new VerificationError('directory HTTP cache freshness expired', { code: VerificationCode.SignatureInvalid });
      return cached.clone();
    });
    await expect(s.verify()).resolves.toBe(s.evidence);
    const req = await resignRequest(s.req, params => { params.expires = params.created! + 300; });
    const now = vi.spyOn(Date, 'now').mockReturnValue(acquiredAt + 61_000);
    try { await expect(s.verify(req)).rejects.toThrow('cache freshness'); }
    finally { now.mockRestore(); }
  });

  it.each([503, 408, 429])('classifies HTTP %s directory availability failures as transient', async status => {
    const s = await setup();
    s.fetch.mockResolvedValue(new Response(null, { status }));
    await expect(s.verify()).rejects.toMatchObject({ code: VerificationCode.TLSError, transient: true });
    expect(s.resolver.verifyDomain).not.toHaveBeenCalled();
  });

  it.each([['ETIMEDOUT', true], ['ECONNRESET', true], ['CERT_HAS_EXPIRED', false], ['ERR_TLS_CERT_ALTNAME_INVALID', false], ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', false]])('classifies transport %s as transient: %s', async (code, transient) => {
    const s = await setup();
    s.fetch.mockRejectedValue(new TypeError('fetch failed', { cause: Object.assign(new Error('transport failure'), { code }) }));
    await expect(s.verify()).rejects.toMatchObject({ code: VerificationCode.TLSError, transient });
  });

  it('classifies interrupted directory reads as transient', async () => {
    const s = await setup();
    s.fetch.mockImplementation(async (request: Request) => {
      const response = await s.signer.serveHttpMessageSignaturesDirectory(request);
      const body = new ReadableStream({ start(controller) { controller.error(Object.assign(new Error('socket reset'), { code: 'ECONNRESET' })); } });
      return new Response(body, { headers: response.headers });
    });
    await expect(s.verify()).rejects.toMatchObject({ code: VerificationCode.TLSError, transient: true });
  });

  it('does not infer HTTP freshness from signed creation when Date and Age are absent', async () => {
    const s = await setup();
    rewriteDirectory(s, (_document, headers, params) => {
      headers.set('Cache-Control', 'max-age=1');
      headers.delete('Date');
      headers.delete('Age');
      params.created! -= 60;
      params.expires! -= 60;
    });
    await expect(s.verify()).resolves.toBe(s.evidence);
  });

  it('preserves permanent unsafe-destination failures nested by fetch', async () => {
    const s = await setup();
    const cause = new VerificationError('unsafe destination', { code: VerificationCode.TLSError });
    s.fetch.mockRejectedValue(new TypeError('fetch failed', { cause }));
    await expect(s.verify()).rejects.toBe(cause);
  });

  it('ignores unrelated, incomplete, and other-key directory signatures', async () => {
    const s = await setup();
    s.fetch.mockImplementation(async (request: Request) => {
      const response = await s.signer.serveHttpMessageSignaturesDirectory(request);
      const headers = new Headers(response.headers);
      headers.append('Signature-Input', headers.get('Signature-Input')!.replace(/^sig1=/, 'other=').replace(/keyid="[^"]+"/, `keyid="${'a'.repeat(43)}"`));
      headers.append('Signature', `other=:${btoa('x'.repeat(64))}:`);
      return new Response(response.body, { headers });
    });
    const headers = new Headers(s.req.headers);
    headers.append('Signature-Input', headers.get('Signature-Input')!.replace(/^sig1=/, 'incomplete='));
    headers.append('Signature-Input', headers.get('Signature-Input')!.split(',')[0]!.replace(/^sig1=/, 'unrelated=').replace('web-bot-auth', 'other-profile'));
    headers.append('Signature', `unrelated=:${btoa('x'.repeat(64))}:`);
    await expect(s.verify(new Request(s.req, { headers }))).resolves.toBe(s.evidence);
  });

  it.each([';extension=@1', ';extension=%"display"'])('rejects RFC 9651-only Signature-Agent parameters %s', async extension => {
    const s = await setup();
    const headers = new Headers(s.req.headers);
    headers.set('Signature-Agent', headers.get('Signature-Agent')! + extension);
    await expect(s.verify(new Request(s.req, { headers }))).rejects.toThrow('structured field');
    expect(s.fetch).not.toHaveBeenCalled();
  });

  it.each([NaN, Infinity, -Infinity, true, false, null, 0, -1, 301, 1.5])('rejects invalid signature durations %j', async value => {
    const s = await setup();
    for (const field of ['signatureTTL', 'directorySignatureTTL']) {
      expect(() => new WebBotAuthProfile({ webBotAuth: { [field]: value } })).toThrow(ArgumentError);
    }
    await expect(s.signer.createWebBotAuthSignedRequest(s.req, { ttl: value } as never)).rejects.toThrow(ArgumentError);
  });

  it.each([NaN, Infinity, -Infinity, true, false, null, -1])('rejects invalid clock skew %j before network work', value => {
    expect(() => new WebBotAuthProfile({ webBotAuth: { clockSkew: value } as never })).toThrow(ArgumentError);
  });

  it('rejects mutable URI objects instead of retaining a configuration reference', () => {
    const uri = new URL(`https://${domain}/keys`);
    expect(() => new WebBotAuthProfile({ webBotAuth: { signatureAgent: { uri, type: 'jwks_uri' } } as never })).toThrow(ArgumentError);
    expect(() => new WebBotAuthProfile({ webBotAuth: { directoryURL: uri } as never })).toThrow(ArgumentError);
  });

  it('snapshots configuration, including nested discovery, and still rejects expired requests', async () => {
    const s = await setup();
    const config = { signatureTTL: 30, directorySignatureTTL: 40, clockSkew: 0, includeSignatureAgent: true,
      signatureAgent: { uri: `https://${domain}/keys`, type: 'jwks_uri' as 'jwks_uri' | 'directory' } };
    const profile = new WebBotAuthProfile({ domain, keyProvider: makeKeyProvider(), identityResolver: s.resolver, discoveryFetch: s.fetch, webBotAuth: config });
    config.signatureTTL = 300;
    config.directorySignatureTTL = 300;
    config.clockSkew = Infinity;
    config.includeSignatureAgent = false;
    config.signatureAgent.uri = 'http://127.0.0.1';
    config.signatureAgent.type = 'directory';
    const signed = await profile.createWebBotAuthSignedRequest(new Request('https://target.example/path'));
    const params = parseSignatureInput(signed.headers.get('Signature-Input')!).get('sig1')!;
    expect(params.expires! - params.created!).toBe(30);
    expect(signed.headers.get('Signature-Agent')).toBe(`sig1="https://${domain}/keys";type=jwks_uri`);
    const directory = await profile.serveHttpMessageSignaturesDirectory(new Request(`https://${domain}/keys`));
    expect(directory.headers.get('Cache-Control')).toBe('max-age=40');
    const directoryParams = parseSignatureInput(directory.headers.get('Signature-Input')!).get('sig1')!;
    expect(directoryParams.expires! - directoryParams.created!).toBe(40);
    await expect(profile.verifyWebBotAuthSignedRequest(signed, policy)).resolves.toBe(s.evidence);
    s.fetch.mockClear();
    const now = vi.spyOn(Date, 'now').mockReturnValue((params.expires! + 1) * 1000);
    try { await expect(profile.verifyWebBotAuthSignedRequest(signed, policy)).rejects.toThrow('currently valid'); }
    finally { now.mockRestore(); }
    expect(s.fetch).not.toHaveBeenCalled();
  });

  it.each(['request', 'directory'])('checks every keyed Content-Digest component on the %s', async kind => {
    for (const key of ['sha-256', 'foo']) {
      const s = await setup();
      const component = { name: 'content-digest', params: { key } };
      let req = s.req;
      if (kind === 'request') {
        const headers = new Headers(req.headers);
        headers.append('Content-Digest', 'foo=:AA==:');
        req = await resignRequest(new Request(req, { headers }), params => { params.components.push(component); });
      } else s.fetch.mockImplementation(async (request: Request) => {
        const response = await s.signer.serveHttpMessageSignaturesDirectory(request);
        const headers = new Headers(response.headers);
        headers.append('Content-Digest', 'foo=:AA==:');
        const params = parseSignatureInput(headers.get('Signature-Input')!).get('sig1')!;
        delete params.parameters;
        params.components.push(component);
        return signHttpMessage({ message: new Response(await response.arrayBuffer(), { headers }), request }, params, makeKeyProvider());
      });
      if (key === 'sha-256') await expect(s.verify(req)).resolves.toBe(s.evidence);
      else await expect(s.verify(req)).rejects.toThrow('unsupported covered Content-Digest');
    }
  });

  it('rejects keyed digest coverage without supplied content', async () => {
    const s = await setup();
    const req = await s.signer.createWebBotAuthSignedRequest(new Request('https://target.example/path', {
      headers: { 'Content-Digest': 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:' },
    }), { additionalComponents: [{ name: 'content-digest', params: { key: 'sha-256' } }] });
    await expect(s.verify(req)).rejects.toThrow('without supplied content');
    expect(s.fetch).not.toHaveBeenCalled();
  });

  it('retains exact minimum digest coverage for supplied content', async () => {
    const s = await setup();
    const req = await resignRequest(s.req, params => {
      params.components = params.components.filter(c => c !== 'content-digest');
      params.components.push({ name: 'content-digest', params: { key: 'sha-256' } });
    });
    await expect(s.verify(req)).rejects.toThrow('missing required WBA component');
    expect(s.fetch).not.toHaveBeenCalled();
  });

  it('honors explicit zero clock skew', async () => {
    const s = await setup();
    const req = await resignRequest(s.req, params => { params.created! += 1; params.expires! += 1; });
    const now = vi.spyOn(Date, 'now').mockReturnValue(parseSignatureInput(s.req.headers.get('Signature-Input')!).get('sig1')!.created! * 1000);
    const verifier = new WebBotAuthProfile({ identityResolver: s.resolver, discoveryFetch: s.fetch, webBotAuth: { clockSkew: 0 } });
    try { await expect(verifier.verifyWebBotAuthSignedRequest(req, policy)).rejects.toThrow('currently valid'); }
    finally { now.mockRestore(); }
    expect(s.fetch).not.toHaveBeenCalled();
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
