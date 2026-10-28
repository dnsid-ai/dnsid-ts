import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import {
  buildSignatureInput, HttpSignaturesProfile, parseDictionaryField, parseSignature,
  parseSignatureInput, sameComponent, signHttpMessage,
} from '@dnsid-ai/http-signatures';
import type { ComponentIdentifier, ResponseSignatureOptions, SignatureParams } from '@dnsid-ai/http-signatures';
import {
  ArgumentError, IdentityManager, JWKS, toArrayBuffer, VerificationCode, VerificationError, verifyWithKey,
} from '@dnsid-ai/protocol';
import type { DnsIdJWK, IdentityResolver, KeyProvider } from '@dnsid-ai/protocol';
import { currentProfileFixture } from './helpers/current-profile.ts';

const domain = 'service.example.com';
const policy: ResponseSignatureOptions = { expectedDomain: domain };
let key: DnsIdJWK;
let privateKey: CryptoKey;
let provider: KeyProvider;
let manager: IdentityManager;
let client: HttpSignaturesProfile;
let server: HttpSignaturesProfile;
let fixture: Awaited<ReturnType<typeof currentProfileFixture>>;

beforeAll(async () => {
  const pair = await generateKeyPair('ES256');
  privateKey = pair.privateKey;
  key = { ...await exportJWK(pair.publicKey), kty: 'EC', kid: 'current', alg: 'ES256', use: 'sig' };
});
beforeEach(async () => {
  provider = {
    signingKey: vi.fn(async () => key),
    sign: vi.fn(async bytes => new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, toArrayBuffer(bytes)))),
    jwk: vi.fn(async () => key), listKeyIds: vi.fn(async () => [key.kid]),
    signKey: vi.fn(), generateKey: vi.fn(), activate: vi.fn(), supersede: vi.fn(), purge: vi.fn(),
  };
  fixture = await currentProfileFixture(domain, key);
  manager = new IdentityManager({}, { ...fixture });
  client = profile();
  server = profile();
});
afterEach(() => vi.restoreAllMocks());

function profile(resolver: IdentityResolver = manager, signing = true, signerDomain = domain): HttpSignaturesProfile {
  return new HttpSignaturesProfile({ domain: signerDomain, identityResolver: resolver, keyProvider: signing ? provider : undefined });
}
async function prepare(options = policy, request = new Request(`https://${domain}/operation?x=1`)): Promise<Request> {
  return client.createSignedHttpRequest(request, { responseSignature: options });
}
async function exchange(options = policy, response = new Response('exact content')) {
  const request = await prepare(options);
  return { request, response: await server.signRequestedHttpResponse(request, response) };
}
function params(response: Response): SignatureParams {
  return parseSignatureInput(response.headers.get('Signature-Input')!).get('sig1')!;
}
async function resign(request: Request, response: Response, change: Partial<SignatureParams> = {}): Promise<Response> {
  return signHttpMessage({ message: response, request }, { ...params(response), parameters: undefined, ...change }, provider, key);
}
async function expectValidCrypto(request: Request, response: Response, label = 'sig1') {
  const input = parseSignatureInput(response.headers.get('Signature-Input')!).get(label)!;
  expect(await verifyWithKey(buildSignatureInput({ message: response, request }, input), parseSignature(response.headers.get('Signature')!).get(label)!, key, 'ES256')).toBe(true);
}
function withHeaders(response: Response, mutate: (h: Headers) => void, status = response.status): Response {
  const headers = new Headers(response.headers);
  mutate(headers);
  return new Response(response.body, { status, headers });
}

describe('NR01 request-only default', () => {
  it('does not negotiate or verify an unsigned response', async () => {
    const response = new Response('unsigned', { status: 503 });
    const fetch = vi.fn(async (input: RequestInfo | URL) => {
      expect((input as Request).headers.has('Accept-Signature')).toBe(false);
      return response;
    });
    const verify = vi.spyOn(manager, 'verifyDomain');
    expect(await client.createSignedFetch({ fetch })(`https://${domain}`)).toBe(response);
    expect(verify).not.toHaveBeenCalled();
  });
});

describe('NR02 request negotiation', () => {
  it('emits exact ordered coverage, true flags, canonical fresh challenge, and signs the field', async () => {
    const request = await prepare({ expectedDomain: 'SERVICE.Example.com.', additionalComponents: ['content-type'] });
    const header = request.headers.get('Accept-Signature')!;
    expect(header).toMatch(/^sig1=\("@status" "@method";req "@authority";req "@target-uri";req "accept-signature";req "signature-input";req;key="sig1" "signature";req;key="sig1" "content-digest" "cache-control" "content-type"\);created;expires;nonce="[A-Za-z0-9_-]{43}"$/);
    const member = parseDictionaryField(header).get('sig1')!;
    expect(member[1].get('created')).toBe(true);
    expect(member[1].get('expires')).toBe(true);
    const nonce = member[1].get('nonce') as string;
    expect(Buffer.from(nonce, 'base64url').length).toBe(32);
    expect(Buffer.from(nonce, 'base64url').toString('base64url')).toBe(nonce);
    const input = parseSignatureInput(request.headers.get('Signature-Input')!).get('sig1')!;
    expect(input.components).toContain('accept-signature');
    expect(input.nonce).not.toBe(nonce);
    await expect(client.verifySignedHttpRequest(request)).resolves.toMatchObject({ domain });
  });
});

describe('NR03 local validation before dependencies', () => {
  it.each(['', 'https://evil.example', 'a..example', '127.0.0.1'])('rejects domain %s', async expectedDomain => {
    const fetch = vi.fn();
    const transport = vi.fn();
    await expect(client.createSignedFetch({ fetch, responseTransport: transport, signing: { responseSignature: { expectedDomain } } })(`https://${domain}`)).rejects.toBeInstanceOf(ArgumentError);
    expect(fetch).not.toHaveBeenCalled(); expect(transport).not.toHaveBeenCalled(); expect(provider.signingKey).not.toHaveBeenCalled();
  });
  it.each(['http', 'existing'])('rejects %s before key/network work', async kind => {
    const request = new Request(`${kind === 'http' ? 'http' : 'https'}://${domain}`, { headers: kind === 'existing' ? { 'Accept-Signature': '' } : {} });
    await expect(prepare(policy, request)).rejects.toBeInstanceOf(ArgumentError);
    expect(provider.signingKey).not.toHaveBeenCalled();
  });
  it.each<ComponentIdentifier[]>([['@method'], ['cache-control'], [{ name: 'x', params: { sf: true } }], [{ name: '@status', params: { req: true } }]])('rejects invalid additional coverage %j', async component => {
    await expect(prepare({ expectedDomain: domain, additionalComponents: [component] })).rejects.toBeInstanceOf(ArgumentError);
    expect(provider.signingKey).not.toHaveBeenCalled();
  });
});

describe('NR04 fresh explicit attempts', () => {
  it('prepares each repeated send from the unsigned original', async () => {
    const headers: string[] = [], signatures: string[] = [];
    const responseTransport = vi.fn(async (request: Request) => {
      headers.push(request.headers.get('Accept-Signature')!); signatures.push(request.headers.get('Signature')!);
      return { response: await server.signRequestedHttpResponse(request, new Response('ok')) };
    });
    const fetch = client.createSignedFetch({ fetch: vi.fn(), responseTransport, signing: { responseSignature: policy } });
    const original = new Request(`https://${domain}`);
    for (let i = 0; i < 2; i++) expect(await (await fetch(original)).text()).toBe('ok');
    expect(new Set(headers).size).toBe(2); expect(new Set(signatures).size).toBe(2);
    expect(original.headers.has('Accept-Signature')).toBe(false);
  });
});

describe('NR05 invocation snapshots', () => {
  it('retains domain, nested coverage, challenge, and request fields across caller mutation', async () => {
    const options = { expectedDomain: domain, additionalComponents: [{ name: 'content-type', params: {} }] };
    const original = new Request(`https://${domain}`);
    const responseTransport = vi.fn(async (request: Request) => {
      options.expectedDomain = 'attacker.example'; options.additionalComponents[0]!.name = 'location';
      original.headers.set('Accept-Signature', 'invalid'); original.headers.set('Signature', 'invalid');
      return { response: await server.signRequestedHttpResponse(request, new Response('ok', { headers: { 'Content-Type': 'text/plain' } })) };
    });
    const fetch = client.createSignedFetch({ fetch: vi.fn(), responseTransport, signing: { responseSignature: options } });
    expect(await (await fetch(original)).text()).toBe('ok');
  });
});

describe('NR06 server no negotiation', () => {
  it('returns the identical response without accessing keys, also in verification-only mode', async () => {
    const response = new Response('unchanged');
    const request = new Request(`https://${domain}`);
    expect(await server.signRequestedHttpResponse(request, response)).toBe(response);
    expect(await profile(manager, false).signRequestedHttpResponse(request, response)).toBe(response);
    expect(provider.signingKey).not.toHaveBeenCalled(); expect(provider.sign).not.toHaveBeenCalled();
  });
});

describe('NR07 server fulfills parsed negotiation', () => {
  it('preserves a non-default label, reordered full coverage, added fields, and equivalent true spellings', async () => {
    let request = await prepare({ expectedDomain: domain, additionalComponents: ['content-type'] });
    const header = request.headers.get('Accept-Signature')!.replace('sig1=', 'custom=').replace('"@status" ', '').replace('("@method"', '("@method"').replace('"content-type")', '"content-type" "@status")').replaceAll(';req', ';req=?1').replace(';created;', ';created=?1;').replace(';expires;', ';expires=?1;');
    const headers = new Headers(request.headers); headers.set('Accept-Signature', header);
    request = new Request(request, { headers });
    const response = await server.signRequestedHttpResponse(request, new Response('body', { headers: { 'Content-Type': 'text/plain' } }));
    const parsed = parseSignatureInput(response.headers.get('Signature-Input')!).get('custom')!;
    expect(parsed.components[0]).toEqual({ name: '@method', params: { req: true } });
    expect(parsed.components.at(-1)).toBe('@status');
    expect(parsed.created).toBeTypeOf('number'); expect(parsed.expires! - parsed.created!).toBe(60);
    expect(parsed.nonce).toBe(parseDictionaryField(header).get('custom')![1].get('nonce'));
    await expect(client.verifySignedHttpResponse(request, response, policy)).resolves.toMatchObject({ domain });
  });
});

describe('NR08 additional metadata coverage', () => {
  const options = { expectedDomain: domain, additionalComponents: ['content-type'] };
  it('fails signing when requested metadata is absent without changing original headers', async () => {
    const request = await prepare(options);
    const response = new Response(new Uint8Array([1]));
    await expect(server.signRequestedHttpResponse(request, response)).rejects.toBeInstanceOf(ArgumentError);
    expect(response.headers.has('Content-Digest')).toBe(false);
  });
  it.each(['changed', 'omitted', 'coverage'])('rejects %s metadata', async kind => {
    const { request, response } = await exchange(options, new Response('body', { headers: { 'Content-Type': 'text/plain' } }));
    const changed = kind === 'coverage'
      ? await resign(request, response, { components: params(response).components.filter(c => !sameComponent(c, 'content-type')) })
      : withHeaders(response, h => kind === 'changed' ? h.set('Content-Type', 'text/html') : h.delete('Content-Type'));
    await expect(client.verifySignedHttpResponse(request, changed, options)).rejects.toBeInstanceOf(VerificationError);
  });
});

describe('NR09 strict complete negotiation', () => {
  const corruptions: [string, (h: string) => string][] = [
    ['malformed', () => 'sig1=('], ['duplicate label', h => `${h}, ${h}`], ['two members', h => `${h}, other=()`],
    ['item instead of list', () => 'sig1="item"'], ['duplicate time', h => h.replace(';created;', ';created;created;')],
    ['duplicate nonce', h => h + ';nonce="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"'],
    ['duplicate component parameter', h => h.replace(';req', ';req;req=?1')],
    ['duplicate component', h => h.replace('("@status"', '("@status" "@status"')],
    ['wrong flag type', h => h.replace(';created;', ';created=1;')], ['false flag', h => h.replace(';expires;', ';expires=?0;')],
    ['missing flag', h => h.replace(';created', '')], ['constraint', h => h + ';keyid="policy"'],
    ['unsupported component', h => h.replace('"@status"', '"@unknown"')], ['unsupported parameter', h => h.replace('"@status"', '"@status";sf')],
    ['missing required', h => h.replace('"signature-input";req;key="sig1" ', '')],
    ['unkeyed request signature', h => h.replace('"signature";req;key="sig1"', '"signature";req')],
    ['mismatched member keys', h => h.replace('"signature";req;key="sig1"', '"signature";req;key="other"')], ['wrong req type', h => h.replace(';req', ';req=1')],
    ['short nonce', h => h.replace(/nonce="[^"]+"/, 'nonce="short"')],
    ['padded nonce', h => h.replace(/(nonce="[^"]+)/, '$1=')],
    ['noncanonical nonce', h => h.replace(/nonce="[^"]+"/, 'nonce="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"')],
    ['nonce type', h => h.replace(/nonce="[^"]+"/, 'nonce=123')],
    ['date value', h => h.replace(';created;', ';created=@1;')], ['display string', h => h.replace(/nonce="[^"]+"/, 'nonce=%"value"')],
  ];
  it.each(corruptions)('rejects %s without signing or partial changes', async (_name, corrupt) => {
    const request = await prepare();
    request.headers.set('Accept-Signature', corrupt(request.headers.get('Accept-Signature')!));
    vi.mocked(provider.sign).mockClear(); vi.mocked(provider.signingKey).mockClear();
    const response = new Response('body');
    await expect(server.signRequestedHttpResponse(request, response)).rejects.toBeInstanceOf(VerificationError);
    expect(provider.signingKey).not.toHaveBeenCalled(); expect(provider.sign).not.toHaveBeenCalled();
    expect(response.headers.has('Signature')).toBe(false); expect(response.headers.has('Content-Digest')).toBe(false);
  });
});

describe('NR10 content semantics and intact replay', () => {
  it.each(['ordinary', 'empty', 'HEAD', '204', '205', '304'])('digests %s exact bytes and preserves content', async kind => {
    const status = /^\d/.test(kind) ? Number(kind) : 200;
    const request = await prepare(policy, new Request(`https://${domain}`, { method: kind === 'HEAD' ? 'HEAD' : 'GET' }));
    const body = kind === 'ordinary' ? new Uint8Array([0, 255, 128, 10]) : new Uint8Array();
    const bodyless = status !== 200 || kind === 'HEAD';
    const original = new Response(bodyless ? null : body, { status, headers: { 'Cache-Control': 'private, max-age=10' } });
    const response = await server.signRequestedHttpResponse(request, original);
    expect(response.headers.get('Cache-Control')).toBe('private, max-age=10, no-store');
    expect(response.headers.get('Content-Digest')).toBe(`sha-256=:${Buffer.from(await crypto.subtle.digest('SHA-256', body)).toString('base64')}:`);
    await client.verifySignedHttpResponse(request, response, policy);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(body);
    expect(new Uint8Array(await original.arrayBuffer())).toEqual(body);
  });
});

describe('NR11 unavailable or decoded content', () => {
  it('does not expose supplied bytes as authenticated on a semantically empty HEAD response', async () => {
    const request = await prepare(policy, new Request(`https://${domain}`, { method: 'HEAD' }));
    const signed = await server.signRequestedHttpResponse(request, new Response(null));
    const response = new Response('not HTTP content', { headers: signed.headers });
    await expectValidCrypto(request, response);
    await expect(client.verifySignedHttpResponse(request, response, policy)).rejects.toThrow('no-content');
  });
  it('normalizes a failed content stream to a verification rejection', async () => {
    const { request, response } = await exchange();
    const failed = new Response(new ReadableStream({ start(c) { c.error(new Error('broken stream')); } }), { headers: response.headers });
    await expect(client.verifySignedHttpResponse(request, failed, policy)).rejects.toBeInstanceOf(VerificationError);
  });
  it('never substitutes empty bytes for an unavailable ordinary body', async () => {
    const request = await prepare();
    await expect(server.signRequestedHttpResponse(request, new Response(null))).rejects.toBeInstanceOf(VerificationError);
    const signed = await server.signRequestedHttpResponse(request, new Response('content'));
    const unavailable = new Response(null, { headers: signed.headers });
    await expectValidCrypto(request, unavailable);
    await expect(client.verifySignedHttpResponse(request, unavailable, policy)).rejects.toThrow('unavailable');
  });
  it('rejects transparent content decoding rather than authenticate changed representation bytes', async () => {
    const { gzipSync } = await import('node:zlib');
    const { request, response } = await exchange(policy, new Response(gzipSync('content'), { headers: { 'Content-Encoding': 'gzip' } }));
    const decoded = new Response('content', { headers: response.headers });
    await expectValidCrypto(request, decoded);
    await expect(client.verifySignedHttpResponse(request, decoded, policy)).rejects.toThrow('Digest');
  });
});

describe('NR12 signature label collisions', () => {
  it('ignores an unrelated complete valid profile signature without ambiguity or substitution', async () => {
    const { request, response } = await exchange();
    const both = await signHttpMessage({ message: response, request }, { ...params(response), label: 'other' }, provider, key);
    await expectValidCrypto(request, both, 'other');
    await expect(client.verifySignedHttpResponse(request, both.clone(), policy)).resolves.toMatchObject({ domain });
    both.headers.set('Signature', `other=:${Buffer.from(parseSignature(both.headers.get('Signature')!).get('other')!).toString('base64')}:`);
    await expect(client.verifySignedHttpResponse(request, both, policy)).rejects.toThrow('missing requested');
  });
  it.each(['Signature', 'Signature-Input'])('rejects collision in %s', async header => {
    const { request, response } = await exchange();
    response.headers.delete(header === 'Signature' ? 'Signature-Input' : 'Signature');
    const before = [...response.headers];
    await expect(server.signRequestedHttpResponse(request, response)).rejects.toThrow('already exists');
    expect([...response.headers]).toEqual(before);
  });
  it('preserves unrelated signature labels and verifies only the requested label', async () => {
    const request = await prepare();
    const unrelated = await signHttpMessage(new Response('body'), { label: 'other', components: ['@status'], created: 1 }, provider, key);
    const otherSignature = parseSignature(unrelated.headers.get('Signature')!).get('other');
    const signed = await server.signRequestedHttpResponse(request, unrelated);
    expect(parseSignature(signed.headers.get('Signature')!).get('other')).toEqual(otherSignature);
    await expect(client.verifySignedHttpResponse(request, signed, policy)).resolves.toMatchObject({ domain });
  });
});

describe('NR13 atomic signing failures', () => {
  it.each(['signature', 'signature-input'])('rejects coverage of the response %s field', async field => {
    await expect(prepare({ expectedDomain: domain, additionalComponents: [field] })).rejects.toBeInstanceOf(ArgumentError);
    const prepared = await prepare();
    const headers = new Headers(prepared.headers);
    headers.set('Accept-Signature', headers.get('Accept-Signature')!.replace(')', ` "${field}")`));
    const response = new Response('body');
    await expect(server.signRequestedHttpResponse(new Request(prepared, { headers }), response)).rejects.toBeInstanceOf(VerificationError);
    expect([...response.headers]).toEqual([['content-type', 'text/plain;charset=UTF-8']]);
  });
  it.each(['provider', 'changed key', 'bounds', 'missing provider'])('does not commit headers on %s failure', async kind => {
    const request = await prepare();
    if (kind === 'provider') vi.mocked(provider.sign).mockRejectedValue(new Error('provider failed'));
    if (kind === 'changed key') {
      const replacement = await generateKeyPair('ES256');
      vi.mocked(provider.sign).mockImplementation(async input => new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, replacement.privateKey, toArrayBuffer(input))));
    }
    const response = new Response(kind === 'bounds' ? new Uint8Array(8 * 1024 * 1024 + 1) : 'body');
    await expect((kind === 'missing provider' ? profile(manager, false) : server).signRequestedHttpResponse(request, response)).rejects.toThrow();
    expect(response.headers.has('Content-Digest')).toBe(false); expect(response.headers.has('Cache-Control')).toBe(false); expect(response.headers.has('Signature')).toBe(false);
  });
});

describe('NR14 expected-domain success', () => {
  it('supports Ed25519 operational keys', async () => {
    const pair = await generateKeyPair('EdDSA');
    const operational: DnsIdJWK = { ...await exportJWK(pair.publicKey), kty: 'OKP', kid: 'ed25519', alg: 'EdDSA' };
    const edProvider = { ...provider, signingKey: async () => operational, sign: async (input: Uint8Array) => new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey, toArrayBuffer(input))) };
    const fixture = await currentProfileFixture(domain, operational);
    const manager = new IdentityManager({}, { ...fixture });
    const ed = new HttpSignaturesProfile({ domain, keyProvider: edProvider, identityResolver: manager });
    const request = await ed.createSignedHttpRequest(new Request(`https://${domain}`), { responseSignature: policy });
    const response = await ed.signRequestedHttpResponse(request, new Response('ed content'));
    await expect(ed.verifySignedHttpResponse(request, response, policy)).resolves.toMatchObject({ domain });
    expect(await response.text()).toBe('ed content');
  });
  it('preserves bytes through repeated standalone verification without retaining cleanup wrapper chains', async () => {
    const { request, response } = await exchange();
    for (let i = 0; i < 4; i++) await expect(client.verifySignedHttpResponse(request, response, policy)).resolves.toMatchObject({ domain });
    expect(await response.text()).toBe('exact content');
  });
  it('returns verified identity and does not release the client response until verification finishes', async () => {
    const { request, response } = await exchange();
    await expect(client.verifySignedHttpResponse(request, response, { expectedDomain: 'SERVICE.EXAMPLE.COM.' })).resolves.toMatchObject({ domain });
    expect(await response.text()).toBe('exact content');
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    let resolving!: () => void;
    const reached = new Promise<void>(resolve => { resolving = resolve; });
    const resolver = { verifyDomain: vi.fn(async (...args: Parameters<IdentityManager['verifyDomain']>) => { resolving(); await gate; return manager.verifyDomain(...args); }) };
    const signedFetch = profile(resolver).createSignedFetch({ fetch: vi.fn(), responseTransport: async req => ({ response: await server.signRequestedHttpResponse(req, new Response('intact')) }), signing: { responseSignature: policy } });
    let returned = false;
    const pending = signedFetch(`https://${domain}`).then(value => { returned = true; return value; });
    await reached; expect(returned).toBe(false); release();
    expect(await (await pending).text()).toBe('intact');
  });
});

describe('NR15 requested label, exact ordered coverage, and challenge', () => {
  it.each(['unsigned', 'missing label', 'wrong label', 'missing coverage', 'reordered', 'wrong nonce'])('rejects %s, including otherwise valid signatures', async kind => {
    const { request, response } = await exchange();
    let changed: Response;
    if (kind === 'unsigned') changed = withHeaders(response, h => { h.delete('Signature'); h.delete('Signature-Input'); });
    else if (kind === 'missing label') changed = withHeaders(response, h => h.delete('Signature'));
    else if (kind === 'wrong label') changed = withHeaders(response, h => { h.set('Signature', h.get('Signature')!.replace('sig1=', 'other=')); h.set('Signature-Input', h.get('Signature-Input')!.replace('sig1=', 'other=')); });
    else {
      const components = [...params(response).components];
      if (kind === 'missing coverage') components.pop();
      if (kind === 'reordered') [components[0], components[1]] = [components[1]!, components[0]!];
      changed = await resign(request, response, kind === 'wrong nonce' ? { nonce: 'A'.repeat(43) } : { components });
      await expectValidCrypto(request, changed);
    }
    await expect(client.verifySignedHttpResponse(request, changed, policy)).rejects.toBeInstanceOf(VerificationError);
  });
});

describe('NR16 response and retained request tampering', () => {
  it.each(['status', 'content', 'cache', 'method', 'authority', 'target', 'negotiation', 'signature-input', 'signature'])('rejects modified %s', async kind => {
    let { request, response } = await exchange();
    if (kind === 'status') response = withHeaders(response, () => {}, 201);
    else if (kind === 'content') response = new Response('changed', { headers: response.headers });
    else if (kind === 'cache') response = withHeaders(response, h => h.set('Cache-Control', 'no-store, public'));
    else if (kind === 'method') request = new Request(request, { method: 'POST' });
    else if (kind === 'authority') request = new Request('https://gateway.example/operation?x=1', { headers: request.headers });
    else if (kind === 'target') request = new Request(`https://${domain}/other?x=1`, { headers: request.headers });
    else if (kind === 'negotiation') request.headers.set('Accept-Signature', request.headers.get('Accept-Signature')!.replace('"@status" ', '"@status"  '));
    else if (kind === 'signature-input') request.headers.set(kind, request.headers.get(kind)! + ';tag="changed"');
    else request.headers.set(kind, 'sig1=:AQ==:');
    await expect(client.verifySignedHttpResponse(request, response, policy)).rejects.toBeInstanceOf(VerificationError);
  });
  it('rejects a response lifetime above 60 seconds and ignores verifier maxAge for lifetime', async () => {
    const { request, response } = await exchange();
    const strict = new HttpSignaturesProfile({ domain, identityResolver: manager, httpMessageSignatures: { maxAge: 30 } });
    await expect(strict.verifySignedHttpResponse(request, response.clone(), policy)).resolves.toMatchObject({ domain });
    const p = params(response);
    const long = await resign(request, response, { expires: p.created! + 61 });
    await expect(client.verifySignedHttpResponse(request, long, policy)).rejects.toThrow('lifetime');
  });
  it('ignores unrelated response members with profile-invalid parameters', async () => {
    const { request, response } = await exchange();
    const mixed = withHeaders(response, h => {
      h.set('Signature-Input', `${h.get('Signature-Input')}, other=("@status");created=1.0, gone=("@status");alg="rsa-pss-sha512"`);
      h.set('Signature', `${h.get('Signature')}, other=:AQ==:, gone=:AQ==:`);
    });
    await expect(client.verifySignedHttpResponse(request, mixed, policy)).resolves.toMatchObject({ domain });
  });
  it.each([['HEAD', 200], ['GET', 205]])('signs %s %i over empty content and ignores a supplied body', async (method, status) => {
    const request = await prepare(policy, new Request(`https://${domain}/operation?x=1`, { method }));
    const signed = await server.signRequestedHttpResponse(request, new Response(status === 205 ? null : 'ignored', { status }));
    expect(signed.body).toBeNull();
    expect(signed.headers.get('Content-Digest')).toBe('sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:');
    await expect(client.verifySignedHttpResponse(request, signed, policy)).resolves.toMatchObject({ domain });
  });
  it('verifies when an intermediary adds its own request signature member', async () => {
    const request = await prepare();
    const received = new Request(request);
    received.headers.set('Signature-Input', `${request.headers.get('Signature-Input')}, gateway=("@method");created=1`);
    received.headers.set('Signature', `${request.headers.get('Signature')}, gateway=:AQ==:`);
    const response = await server.signRequestedHttpResponse(received, new Response('body'));
    await expect(client.verifySignedHttpResponse(request, response, policy)).resolves.toMatchObject({ domain });
  });
});

describe('NR17 gateway re-signing attack', () => {
  it.each(['changed content', 'different caller'])('rejects a relayed valid service response after %s', async kind => {
    const original = await prepare(policy, new Request(`https://${domain}/operation`, { method: 'POST', body: 'original' }));
    const headers = new Headers(original.headers);
    headers.delete('Signature'); headers.delete('Signature-Input'); headers.delete('Content-Digest');
    const gateway = profile(manager, true, kind === 'different caller' ? 'gateway.example.com' : domain);
    const forwarded = await gateway.createSignedHttpRequest(new Request(original.url, { method: 'POST', headers, body: kind === 'changed content' ? 'changed' : 'original' }));
    const response = await server.signRequestedHttpResponse(forwarded, new Response('service response'));
    await expectValidCrypto(forwarded, response);
    await expect(client.verifySignedHttpResponse(original, response, policy)).rejects.toThrow('signature');
  });
});

describe('NR18 freshness, algorithms, and current key policy', () => {
  it('rejects an old operational key after a fresh resolver invocation learns rotation', async () => {
    const { request, response } = await exchange();
    await expectValidCrypto(request, response);
    const pair = await generateKeyPair('ES256');
    const replacement: DnsIdJWK = { ...await exportJWK(pair.publicKey), kty: 'EC', kid: 'replacement', alg: 'ES256' };
    const current = await currentProfileFixture(domain, replacement);
    const rotatedManager = new IdentityManager({}, { ...current });
    await expect(profile(rotatedManager).verifySignedHttpResponse(request, response, policy)).rejects.toMatchObject({ code: 'KeyNotFound' });
  });
  it.each(['missing created', 'missing expires', 'missing alg', 'invalid alg', 'expired', 'future', 'zero lifetime', 'long lifetime', 'non-current key'])('rejects cryptographically signed %s', async kind => {
    const { request, response } = await exchange();
    const now = Math.floor(Date.now() / 1000);
    const changes: Record<string, Partial<SignatureParams>> = {
      'missing created': { created: undefined }, 'missing expires': { expires: undefined }, 'missing alg': { alg: undefined }, 'invalid alg': { alg: 'unsupported' },
      expired: { created: now - 301, expires: now - 1 }, future: { created: now + 6, expires: now + 60 },
      'zero lifetime': { created: now, expires: now }, 'long lifetime': { created: now, expires: now + 301 },
      'non-current key': { keyId: `${domain}#retired` },
    };
    const changed = await resign(request, response, changes[kind]);
    await expectValidCrypto(request, changed);
    await expect(client.verifySignedHttpResponse(request, changed, policy)).rejects.toBeInstanceOf(VerificationError);
  });
  it.each(['timestamp type', 'timestamp decimal', 'expires decimal', 'algorithm type', 'mismatched metadata'])('rejects %s', async kind => {
    const { request, response } = await exchange();
    if (kind === 'mismatched metadata') {
      const vd = await manager.verifyDomain(domain);
      vi.spyOn(manager, 'verifyDomain').mockResolvedValue(Object.assign(Object.create(Object.getPrototypeOf(vd)), vd, { jwks: new JWKS([{ ...key, alg: 'EdDSA' }]) }));
    } else {
      const field = response.headers.get('Signature-Input')!;
      const alter = (input: string) => kind === 'timestamp decimal' ? input.replace(/created=(\d+)/, 'created=$1.0')
        : kind === 'expires decimal' ? input.replace(/expires=(\d+)/, 'expires=$1.0')
        : input.replace(kind === 'timestamp type' ? /created=\d+/ : /alg="[^"]+"/, kind === 'timestamp type' ? 'created' : 'alg=1');
      const base = alter(new TextDecoder().decode(buildSignatureInput({ message: response, request }, params(response))));
      const signature = await provider.sign(new TextEncoder().encode(base));
      expect(await verifyWithKey(new TextEncoder().encode(base), signature, key, 'ES256')).toBe(true);
      response.headers.set('Signature-Input', alter(field));
      response.headers.set('Signature', `sig1=:${Buffer.from(signature).toString('base64')}:`);
    }
    await expect(client.verifySignedHttpResponse(request, response, policy)).rejects.toBeInstanceOf(VerificationError);
  });
  it('uses the injected clock and rejects after the configured deadline of the signature', async () => {
    const { request, response } = await exchange();
    const now = Date.now(); vi.spyOn(Date, 'now').mockReturnValue(now + 306_000);
    await expect(client.verifySignedHttpResponse(request, response, policy)).rejects.toBeInstanceOf(VerificationError);
  });
});

describe('NR19 reject untrusted keyid domain before lookup', () => {
  it('rejects another domain even when the signature is cryptographically valid', async () => {
    const { request, response } = await exchange();
    const changed = await resign(request, response, { keyId: 'other.example.com#current' });
    await expectValidCrypto(request, changed);
    const resolver = vi.spyOn(manager, 'verifyDomain');
    await expect(client.verifySignedHttpResponse(request, changed, policy)).rejects.toThrow('unexpected');
    expect(resolver).not.toHaveBeenCalled();
  });
});

describe('NR20 DNSid policy and acquisition failures', () => {
  it.each(['status', 'lifecycle', 'acceptance', 'transient', 'cache denial'])('preserves %s failure classification', async kind => {
    const { request, response } = await exchange();
    if (kind === 'cache denial') {
      const lookup = vi.spyOn(fixture.dnsResolver, 'fetchTXT');
      manager = new IdentityManager({ verification: { trustedEntities: [] } }, { ...fixture });
      for (let i = 0; i < 2; i++) await expect(profile().verifySignedHttpResponse(request, response.clone(), policy)).rejects.toMatchObject({ code: 'CounterpartyNotAccepted', transient: false });
      expect(lookup).toHaveBeenCalledTimes(1);
      return;
    }
    if (kind === 'status') {
      const fetchJson = fixture.fetchJson;
      manager = new IdentityManager({}, { ...fixture, fetchJson: async (url, options) => url === fixture.record.su ? { data: { state: 'REVOKED', revocationReason: 'keyCompromise', lastTransitionAt: new Date().toISOString() }, tlsCert: { notAfter: new Date('2099-01-01'), san: [domain] } } : fetchJson(url, options) });
    } else if (kind === 'lifecycle') fixture.logReader.verifyBilateralBinding = async () => { throw new VerificationError('bad lifecycle', { code: VerificationCode.LogError, transient: false }); };
    else if (kind === 'acceptance') manager = new IdentityManager({ verification: { trustedEntities: [] } }, { ...fixture });
    else vi.spyOn(manager, 'verifyDomain').mockRejectedValue(new VerificationError('DNS unavailable', { code: VerificationCode.DNSResolution, transient: true }));
    await expect(profile().verifySignedHttpResponse(request, response, policy)).rejects.toMatchObject({ transient: kind === 'transient' });
  });
});

describe('NR21 current-peer mTLS, including cache hits', () => {
  it('requires the current connection peer on every invocation and preserves transient acquisition errors', async () => {
    fixture = await currentProfileFixture(domain, key, 'mtls');
    manager = new IdentityManager({ verification: { statusCheckInterval: 60 } }, { ...fixture });
    const verifier = profile();
    const { request, response } = await exchange();
    const peer = { notAfter: new Date('2099-01-01'), san: [domain] };
    await expect(verifier.verifySignedHttpResponse(request, response.clone(), policy, peer)).resolves.toMatchObject({ domain });
    for (const wrong of [undefined, { ...peer, san: ['wrong.example.com'] }]) await expect(verifier.verifySignedHttpResponse(request, response.clone(), policy, wrong)).rejects.toMatchObject({ code: 'TLSError' });
    const transport = async (req: Request) => ({ response: await server.signRequestedHttpResponse(req, new Response('ok')) });
    await expect(verifier.createSignedFetch({ fetch: vi.fn(), responseTransport: transport, signing: { responseSignature: policy } })(`https://${domain}`)).rejects.toMatchObject({ code: 'TLSError' });
    await expect(verifier.createSignedFetch({ fetch: vi.fn(), responseTransport: async req => ({ ...await transport(req), peerCert: peer }), signing: { responseSignature: policy } })(`https://${domain}`)).resolves.toBeInstanceOf(Response);
  });
});

describe('NR22 signed errors and redirects', () => {
  it.each([400, 503, 302])('verifies status %s without status filtering or following Location', async status => {
    const responseTransport = vi.fn(async (request: Request) => ({ response: await server.signRequestedHttpResponse(request, new Response('body', { status, headers: { Location: 'https://other.example/' } })) }));
    const fetch = client.createSignedFetch({ fetch: vi.fn(), responseTransport, signing: { responseSignature: policy } });
    const response = await fetch(`https://${domain}`, { redirect: 'follow' });
    expect(response.status).toBe(status); expect(await response.text()).toBe('body');
    expect(responseTransport).toHaveBeenCalledTimes(1);
    expect(responseTransport.mock.calls[0]![0].redirect).toBe('manual');
  });
  it.each([400, 503, 302])('rejects unsigned status %s before returning', async status => {
    const fetch = client.createSignedFetch({ fetch: vi.fn(), responseTransport: async () => ({ response: new Response('unsigned', { status }) }), signing: { responseSignature: policy } });
    await expect(fetch(`https://${domain}`)).rejects.toBeInstanceOf(VerificationError);
  });
});

describe('NR23 no implicit transport replay', () => {
  it('rejects generic fetch transports that cannot disable hidden retry/replay', async () => {
    const fetch = vi.fn();
    await expect(client.createSignedFetch({ fetch, signing: { responseSignature: policy } })(`https://${domain}`)).rejects.toBeInstanceOf(ArgumentError);
    expect(fetch).not.toHaveBeenCalled();
  });
  it('never retries a failed operation; explicit caller attempts get a fresh challenge', async () => {
    const challenges: string[] = [];
    const transport = vi.fn(async (request: Request) => { challenges.push(request.headers.get('Accept-Signature')!); throw new Error('ambiguous network failure'); });
    const fetch = client.createSignedFetch({ fetch: vi.fn(), responseTransport: transport, signing: { responseSignature: policy } });
    for (let i = 0; i < 2; i++) { await expect(fetch(`https://${domain}`)).rejects.toThrow('network'); expect(transport).toHaveBeenCalledTimes(i + 1); }
    expect(new Set(challenges).size).toBe(2);
  });
});

describe('NR24 unsupported response modes', () => {
  it.each([101, 103, 0])('rejects non-final status %s', async status => {
    const request = await prepare();
    const response = new Response('body'); Object.defineProperty(response, 'status', { value: status });
    await expect(server.signRequestedHttpResponse(request, response)).rejects.toBeInstanceOf(VerificationError);
    await expect(client.verifySignedHttpResponse(request, response, policy)).rejects.toBeInstanceOf(VerificationError);
  });
  it('rejects tunnel establishment', async () => {
    const request = await prepare(); Object.defineProperty(request, 'method', { value: 'CONNECT' });
    await expect(server.signRequestedHttpResponse(request, new Response('tunnel'))).rejects.toBeInstanceOf(VerificationError);
  });
});

describe('NR25 finite resource bounds and cleanup', () => {
  it('bounds request content before sending and never falls back to unsigned transport', async () => {
    const transport = vi.fn();
    const fetch = client.createSignedFetch({ fetch: vi.fn(), responseTransport: transport, signing: { responseSignature: policy } });
    await expect(fetch(`https://${domain}`, { method: 'POST', body: new Uint8Array(8 * 1024 * 1024 + 1) })).rejects.toThrow('size limit');
    expect(transport).not.toHaveBeenCalled();
  });
  it('bounds standalone response signing and cancels its owned read on cancellation', async () => {
    const controller = new AbortController();
    const request = await prepare(policy, new Request(`https://${domain}`, { signal: controller.signal }));
    const cancel = vi.fn();
    const response = new Response(new ReadableStream({ cancel }));
    const pending = server.signRequestedHttpResponse(request, response);
    controller.abort();
    await expect(pending).rejects.toMatchObject({ transient: true });
    await new Promise(resolve => setImmediate(resolve)); expect(cancel).toHaveBeenCalled();
  });
  it.each(['negotiation', 'nonce', 'signature', 'components'])('rejects oversized %s before DNS lookup', async kind => {
    const { request, response } = await exchange();
    if (kind === 'negotiation') request.headers.set('Accept-Signature', 'a'.repeat(16 * 1024 + 1));
    if (kind === 'nonce') request.headers.set('Accept-Signature', request.headers.get('Accept-Signature')!.replace(/nonce="[^"]+"/, `nonce="${'A'.repeat(1025)}"`));
    if (kind === 'signature') response.headers.set('Signature', 'a'.repeat(16 * 1024 + 1));
    if (kind === 'components') request.headers.set('Accept-Signature', request.headers.get('Accept-Signature')!.replace('("@status"', `(${Array.from({ length: 65 }, (_, i) => `"x-${i}"`).join(' ')} "@status"`));
    const resolver = vi.spyOn(manager, 'verifyDomain');
    await expect(client.verifySignedHttpResponse(request, response, policy)).rejects.toBeInstanceOf(VerificationError);
    expect(resolver).not.toHaveBeenCalled();
  });
  it('bounds signed response bytes while reading and cancels the underlying stream', async () => {
    const { request, response } = await exchange();
    const cancel = vi.fn(); let sent = 0;
    const oversized = new Response(new ReadableStream({ pull(c) { if (++sent <= 130) c.enqueue(new Uint8Array(64 * 1024)); }, cancel }), { headers: response.headers });
    await expect(client.verifySignedHttpResponse(request, oversized, policy)).rejects.toThrow('size limit');
    await new Promise(resolve => setImmediate(resolve)); expect(cancel).toHaveBeenCalled();
  });
  it.each(['deadline', 'cancel'])('closes a stalled body after %s', async kind => {
    const cancel = vi.fn();
    const controller = new AbortController();
    const fetch = client.createSignedFetch({ fetch: vi.fn(), timeoutMs: kind === 'deadline' ? 20 : 1000,
      responseTransport: async request => {
        const signed = await server.signRequestedHttpResponse(request, new Response('body'));
        const response = new Response(new ReadableStream({ cancel }), { headers: signed.headers });
        if (kind === 'cancel') setTimeout(() => controller.abort(), 5);
        return { response };
      }, signing: { responseSignature: policy } });
    await expect(fetch(`https://${domain}`, { signal: controller.signal })).rejects.toMatchObject({ transient: true });
    await new Promise(resolve => setImmediate(resolve)); expect(cancel).toHaveBeenCalled();
  });
  it('disposes responses arriving after cancellation of a non-cooperative transport', async () => {
    const cancel = vi.fn(); let finish!: () => void;
    const fetch = client.createSignedFetch({ fetch: vi.fn(), timeoutMs: 10, responseTransport: () => new Promise(resolve => { finish = () => resolve({ response: new Response(new ReadableStream({ cancel })) }); }), signing: { responseSignature: policy } });
    await expect(fetch(`https://${domain}`)).rejects.toMatchObject({ transient: true });
    finish(); await new Promise(resolve => setImmediate(resolve)); expect(cancel).toHaveBeenCalled();
  });
});

describe('NR26 non-cacheable per-challenge responses', () => {
  it.each(['', ', private,,', 'private, No-Store'])('preserves existing valid cache directives %s', async cache => {
    const { request, response } = await exchange(policy, new Response('body', { headers: { 'Cache-Control': cache } }));
    await expect(client.verifySignedHttpResponse(request, response, policy)).resolves.toMatchObject({ domain });
    expect(response.headers.get('Cache-Control')).toContain(cache);
  });
  it('does not publish an unverifiable response when an existing cache directive is malformed', async () => {
    const request = await prepare();
    const original = new Response('body', { headers: { 'Cache-Control': 'x="unterminated' } });
    await expect(server.signRequestedHttpResponse(request, original)).rejects.toBeInstanceOf(ArgumentError);
    expect(original.headers.has('Signature')).toBe(false);
  });
  it.each(['public', 'x="foo,no-store,bar"', 'no-store=1'])('rejects cryptographically valid cache policy %s', async cache => {
    const { request, response } = await exchange();
    const changed = await resign(request, withHeaders(response, h => h.set('Cache-Control', cache)));
    await expectValidCrypto(request, changed);
    await expect(client.verifySignedHttpResponse(request, changed, policy)).rejects.toBeInstanceOf(VerificationError);
  });
  it('never accepts a prior response for a new challenge, and sends cache=no-store', async () => {
    let cached: Response | undefined;
    const transport = vi.fn(async (request: Request) => {
      expect(request.cache).toBe('no-store');
      cached ??= await server.signRequestedHttpResponse(request, new Response('first'));
      return { response: cached.clone() };
    });
    const fetch = client.createSignedFetch({ fetch: vi.fn(), responseTransport: transport, signing: { responseSignature: policy } });
    await expect(fetch(`https://${domain}`)).resolves.toBeInstanceOf(Response);
    await expect(fetch(`https://${domain}`)).rejects.toThrow('nonce');
    expect(transport).toHaveBeenCalledTimes(2);
  });
});
