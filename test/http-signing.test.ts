import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest';
import { generateKeyPair, exportJWK } from 'jose';
import {
  buildSignatureInput,
  hasComponentNamed,
  HttpSignaturesProfile,
  joseAlgToHttpSigAlg,
  JOSE_TO_HTTP_SIG_ALG,
  parseSignature,
  parseSignatureInput,
  sameComponent,
  serializeComponentIdentifier,
  setDictionaryMember,
  signHttpMessage,
} from '@identity-digital/dnsid-http-signatures';
import { currentProfileFixture } from './helpers/current-profile.ts';
import {
  ArgumentError,
  IdentityManager,
  toArrayBuffer,
  verifyWithKey,
  VerificationCode,
  VerificationError,
} from '@identity-digital/dnsid-protocol';
import type { IdentityConfig, DnsIdJWK, KeyProvider } from '@identity-digital/dnsid-protocol';

const mockFetchJson = vi.hoisted(() => vi.fn());

vi.mock('../packages/transport/src/index.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../packages/transport/src/index.ts')>()),
  fetchJson: mockFetchJson,
}));

// ---- shared key pair ----

let privateKey: CryptoKey;
let publicJwk: DnsIdJWK;

beforeAll(async () => {
  const kp = await generateKeyPair('ES256');
  privateKey = kp.privateKey;
  const raw = await exportJWK(kp.publicKey);
  publicJwk = { ...raw, kty: raw.kty!, alg: 'ES256', kid: 'key-1', use: 'sig' } as DnsIdJWK;
});

async function signWithKey(bytes: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, toArrayBuffer(bytes));
  return new Uint8Array(sig);
}

function makeKeyProvider(): KeyProvider {
  return {
    signingKey: vi.fn().mockImplementation(() => Promise.resolve(publicJwk)),
    jwk: vi.fn().mockResolvedValue(publicJwk),
    listKeyIds: vi.fn().mockResolvedValue(['key-1']),
    sign: vi.fn().mockImplementation((bytes: Uint8Array) => signWithKey(bytes)),
    signKey: vi.fn().mockImplementation((_kid: string, bytes: Uint8Array) => signWithKey(bytes)),
    generateKey: vi.fn(),
    activate: vi.fn(),
    supersede: vi.fn(),
    purge: vi.fn(),
  };
}

const SIGNER_CONFIG: IdentityConfig = {
  domain: 'signer.example.com',
  governanceId: 'example.com',
  logRef: 'microledger:s',
  statusUrl: 'https://signer.example.com/status',
};
const VERIFIER_CONFIG: IdentityConfig = {
  domain: 'verifier.example.com',
  governanceId: 'example.com',
  logRef: 'microledger:v',
  statusUrl: 'https://verifier.example.com/status',
};

const resolverStub = { verifyDomain: vi.fn() };

beforeEach(() => { mockFetchJson.mockReset(); });

function makeGetRequest(): Request {
  return new Request('https://api.example.com/resource?foo=bar', { method: 'GET' });
}

function makePostRequest(body = '{"hello":"world"}'): Request {
  return new Request('https://api.example.com/resource', {
    method: 'POST',
    body,
    headers: { 'Content-Type': 'application/json' },
  });
}

// ---- reusable RFC 9421 primitives ----

describe('RFC 9421 Appendix B.2 vectors', () => {
  it('reconstructs the B.2.2 selective-components signature base', () => {
    const request = new Request('https://example.com/foo?param=Value&Pet=dog', {
      method: 'POST',
      headers: {
        'Content-Digest': 'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
      },
    });
    const params = parseSignatureInput(
      'sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
    ).get('sig-b22')!;

    expect(new TextDecoder().decode(buildSignatureInput(request, params))).toBe([
      '"@authority": example.com',
      '"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
      '"@query-param";name="Pet": dog',
      '"@signature-params": ("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
    ].join('\n'));
  });

  it('reconstructs and verifies the B.2.4 P-256 response vector', async () => {
    const response = new Response('{"message": "good dog"}', {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Digest': 'sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:',
        'Content-Length': '23',
      },
    });
    const params = parseSignatureInput(
      'sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"',
    ).get('sig-b24')!;
    const base = buildSignatureInput(response, params);

    expect(new TextDecoder().decode(base)).toBe([
      '"@status": 200',
      '"content-type": application/json',
      '"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:',
      '"content-length": 23',
      '"@signature-params": ("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"',
    ].join('\n'));
    const signature = parseSignature('sig-b24=:wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==:').get('sig-b24')!;
    const key = { kty: 'EC', crv: 'P-256', x: 'qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA', y: 'Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0', kid: 'test-key-ecc-p256', alg: 'ES256', use: 'sig' };
    expect(await verifyWithKey(base, signature, key, 'ES256')).toBe(true);
  });

  it('reconstructs and verifies the B.2.6 Ed25519 request vector', async () => {
    const request = new Request('https://example.com/foo?param=Value&Pet=dog', {
      method: 'POST',
      body: '{"hello": "world"}',
      headers: {
        Date: 'Tue, 20 Apr 2021 02:07:55 GMT',
        'Content-Type': 'application/json',
        'Content-Length': '18',
      },
    });
    const params = parseSignatureInput(
      'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
    ).get('sig-b26')!;
    const base = buildSignatureInput(request, params);

    expect(new TextDecoder().decode(base)).toBe([
      '"date": Tue, 20 Apr 2021 02:07:55 GMT',
      '"@method": POST',
      '"@path": /foo',
      '"@authority": example.com',
      '"content-type": application/json',
      '"content-length": 18',
      '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
    ].join('\n'));
    const signature = parseSignature('sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:').get('sig-b26')!;
    const key = { kty: 'OKP', crv: 'Ed25519', x: 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs', kid: 'test-key-ed25519', alg: 'EdDSA', use: 'sig' };
    expect(await verifyWithKey(base, signature, key, 'EdDSA')).toBe(true);
  });
});

describe('HTTP Message Signature reusable primitives', () => {
  it('parses full Signature-Input and Signature dictionaries by label', () => {
    const inputs = parseSignatureInput(
      'sig1=("@method");created=1;unknown="kept", sig2=("@authority");keyid="k";tag="t"',
    );
    const sigs = parseSignature('sig1=:AQI=:, sig2=:AwQ=:');

    expect(inputs.get('sig1')?.created).toBe(1);
    expect(inputs.get('sig1')?.parameters).toEqual([['created', 1], ['unknown', 'kept']]);
    expect(inputs.get('sig2')?.keyId).toBe('k');
    expect(sigs.get('sig1')).toEqual(new Uint8Array([1, 2]));
    expect(sigs.get('sig2')).toEqual(new Uint8Array([3, 4]));
  });

  it('parses supported parameterized components', () => {
    const params = parseSignatureInput('sig1=("@query-param";name="foo" "signature-agent";key="sig1");created=1').get('sig1')!;
    expect(params.components).toEqual([
      { name: '@query-param', params: { name: 'foo' } },
      { name: 'signature-agent', params: { key: 'sig1' } },
    ]);
  });

  it('rejects duplicate dictionary labels', () => {
    expect(() => parseSignatureInput('sig1=("@method"), sig1=("@path")')).toThrow(VerificationError);
    expect(() => parseSignature('sig1=:AA==:, sig1=:AQ==:')).toThrow(VerificationError);
  });

  it('treats ;req and ;req=?1 as equivalent component identifiers', () => {
    const shorthand = parseSignatureInput('sig1=("@method";req);created=1').get('sig1')!.components[0]!;
    const explicit = parseSignatureInput('sig1=("@method";req=?1);created=1').get('sig1')!.components[0]!;
    expect(sameComponent(shorthand, explicit)).toBe(true);
  });

  it('parses quoted parens inside Signature-Input component params', () => {
    const params = parseSignatureInput('sig1=("@query-param";name="x)y");created=1').get('sig1')!;
    expect(params.components).toEqual([{ name: '@query-param', params: { name: 'x)y' } }]);
  });

  it('builds signature input for parameterized components', () => {
    const req = new Request('https://api.example.com/search?foo=one%20two&bar=three');
    const base = new TextDecoder().decode(buildSignatureInput(req, {
      label: 'sig1',
      components: [{ name: '@query-param', params: { name: 'foo' } }],
      created: 1,
    }));

    expect(base).toBe([
      '"@query-param";name="foo": one%20two',
      '"@signature-params": ("@query-param";name="foo");created=1',
    ].join('\n'));
  });

  it('rejects absent query-param components', () => {
    expect(() => buildSignatureInput(new Request('https://api.example.com/search'), {
      label: 'sig1',
      components: [{ name: '@query-param', params: { name: 'foo' } }],
      created: 1,
    })).toThrow(ArgumentError);
  });

  it('rejects duplicate query-param components by decoded name', () => {
    expect(() => buildSignatureInput(new Request('https://api.example.com/search?foo=one&f%6fo=two'), {
      label: 'sig1',
      components: [{ name: '@query-param', params: { name: 'foo' } }],
      created: 1,
    })).toThrow(ArgumentError);
  });

  it('matches query-param components by RFC-encoded name', () => {
    for (const query of ['na+me=value', 'na%20me=value']) {
      const base = new TextDecoder().decode(buildSignatureInput(new Request(`https://api.example.com/search?${query}`), {
        label: 'sig1',
        components: [{ name: '@query-param', params: { name: 'na%20me' } }],
        created: 1,
      }));

      expect(base).toContain('"@query-param";name="na%20me": value');
    }
  });

  it('strictly form-encodes query-param names and values', () => {
    const base = new TextDecoder().decode(buildSignatureInput(new Request('https://api.example.com/search?a!=v!'), {
      label: 'sig1',
      components: [{ name: '@query-param', params: { name: 'a%21' } }],
      created: 1,
    }));

    expect(base).toContain('"@query-param";name="a%21": v%21');
  });

  it('matches parameterized components without caring about parameter order', () => {
    expect(sameComponent(
      { name: '@query-param', params: { name: 'foo', req: true } },
      { name: '@query-param', params: { req: true, name: 'foo' } },
    )).toBe(true);
  });

  it('canonicalizes unknown signature parameters in @signature-params', () => {
    const params = parseSignatureInput('sig1=("@method");created=1;extension=?1').get('sig1')!;
    const base = new TextDecoder().decode(buildSignatureInput(new Request('https://api.example/'), params));
    expect(base).toBe('"@method": GET\n"@signature-params": ("@method");created=1;extension');
  });

  it('retains duplicate unknown signature parameters in occurrence order', () => {
    const params = parseSignatureInput(
      'sig1=("@method");created=1;extension="first";other=2;extension=?1',
    ).get('sig1')!;
    expect(params.parameters).toEqual([
      ['created', 1],
      ['extension', 'first'],
      ['other', 2],
      ['extension', true],
    ]);
    const base = new TextDecoder().decode(buildSignatureInput(new Request('https://api.example/'), params));
    expect(base).toBe(
      '"@method": GET\n"@signature-params": ("@method");created=1;extension="first";other=2;extension',
    );
  });

  it('rejects duplicate known signature parameters', () => {
    expect(() => parseSignatureInput('sig1=("@method");created=1;extension;created=2')).toThrow(VerificationError);
  });

  it.each([
    'sig1=("@method";unknown);created=1',
    'sig1=("example-dict";sf);created=1',
  ])('rejects unsupported component parameters: %s', value => {
    expect(() => parseSignatureInput(value)).toThrow(VerificationError);
  });

  it('rejects duplicate equivalent covered components', () => {
    expect(() => parseSignatureInput('sig1=("@method" "@method");created=1')).toThrow(VerificationError);
  });

  it('rejects req components without response request context', () => {
    const params = parseSignatureInput('sig1=("@authority";req);created=1').get('sig1')!;
    expect(() => buildSignatureInput(new Request('https://api.example/'), params)).toThrow(ArgumentError);
  });

  it('exports component inspection and serialization primitives', () => {
    const components = [{ name: '@query-param', params: { name: 'Pet', req: true } }];
    expect(hasComponentNamed(components, '@query-param')).toBe(true);
    expect(hasComponentNamed(components, '@method')).toBe(false);
    expect(serializeComponentIdentifier(components[0]!)).toBe('"@query-param";name="Pet";req');
  });

  it('canonicalizes derived request components', () => {
    const req = new Request('https://Example.COM:443/path?x=1', { method: 'custom' });
    const base = new TextDecoder().decode(buildSignatureInput(req, {
      label: 'sig1',
      components: ['@method', '@authority', '@target-uri'],
      created: 1,
    }));

    expect(base).toContain('"@method": custom');
    expect(base).toContain('"@authority": example.com');
    expect(base).toContain('"@target-uri": https://example.com/path?x=1');
  });

  it('maps only DNSid HTTP signature algorithms', () => {
    expect(JOSE_TO_HTTP_SIG_ALG).toEqual({ EdDSA: 'ed25519', ES256: 'ecdsa-p256-sha256' });
    expect(joseAlgToHttpSigAlg('EdDSA')).toBe('ed25519');
    expect(joseAlgToHttpSigAlg('ES256')).toBe('ecdsa-p256-sha256');
    for (const unsupported of ['ES384', 'RS256', 'PS256', 'PS512']) {
      expect(() => joseAlgToHttpSigAlg(unsupported)).toThrow(ArgumentError);
    }
  });

  it('rejects unsupported structured field values', () => {
    expect(() => parseSignatureInput('sig1=("@method");created=:bad:')).toThrow(VerificationError);
    expect(() => parseSignatureInput('sig1=("@method");created=?2')).toThrow(VerificationError);
    expect(() => parseSignatureInput('sig1=("@method");created="unterminated')).toThrow(VerificationError);
  });

  it.each([
    'sig1=("@method");created=@1618884473',
    'sig1=("@method");tag=%"display string"',
    'sig1=("@method");unknown=@1618884473',
    'sig1=("@method");unknown=%"display string"',
  ])('rejects RFC 9651-only values: %s', (value) => {
    expect(() => parseSignatureInput(value)).toThrow(VerificationError);
  });

  it('builds signature input for header dictionary members', () => {
    const req = new Request('https://api.example.com/', { headers: { 'signature-agent': 'sig1="https://bot.example", other="x"' } });
    const base = new TextDecoder().decode(buildSignatureInput(req, {
      label: 'sig1',
      components: [{ name: 'signature-agent', params: { key: 'sig1' } }],
      created: 1,
    }));

    expect(base).toContain('"signature-agent";key="sig1": "https://bot.example"');
  });

  it('adds or replaces only the selected dictionary member when signing', async () => {
    const req = new Request('https://api.example.com/', {
      headers: {
        'Signature-Input': 'old=("@method");created=1',
        Signature: 'old=:AA==:',
      },
    });
    const signed = await signHttpMessage(req, {
      label: 'sig1',
      components: ['@method'],
      created: 2,
    }, makeKeyProvider());

    expect(signed.headers.get('Signature-Input')).toContain('old=("@method");created=1');
    expect(signed.headers.get('Signature-Input')).toContain('sig1=("@method");created=2');
    expect(signed.headers.get('Signature')).toContain('old=:AA==:');
    expect(signed.headers.get('Signature')).toContain('sig1=:');
  });

  it('byte-preserves unrelated dictionary members when replacing one label', () => {
    const headers = new Headers({
      'Signature-Input': 'old=("@method");created=1;extension="first";other=2;extension',
    });

    setDictionaryMember(headers, 'Signature-Input', 'sig1', '("@method");created=2');

    expect(headers.get('Signature-Input')).toBe(
      'old=("@method");created=1;extension="first";other=2;extension, sig1=("@method");created=2',
    );
  });
});

// ---- createSignedHttpRequest ----

describe('HttpSignaturesProfile.createSignedHttpRequest()', () => {
  it('adds Signature-Input and Signature headers to a GET request', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const signed = await manager.createSignedHttpRequest(makeGetRequest());
    expect(signed.headers.get('Signature-Input')).toBeTruthy();
    expect(signed.headers.get('Signature')).toBeTruthy();
  });

  it('Signature-Input contains the default label and required components', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const signed = await manager.createSignedHttpRequest(makeGetRequest());
    const si = signed.headers.get('Signature-Input')!;
    expect(si).toContain('sig1=');
    expect(si).toContain('@method');
    expect(si).toContain('@authority');
    expect(si).toContain('@target-uri');
    expect(si).not.toContain('expires=');
    expect(si).not.toContain('tag=');
  });

  it('honors explicit label, expires, and tag options', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const signed = await manager.createSignedHttpRequest(makeGetRequest(), { label: 'a2a', expiresInSeconds: 300, tag: 'a2a-dnsid-http-sig-v1' });
    const si = signed.headers.get('Signature-Input')!;
    expect(si).toContain('a2a=');
    expect(si).toContain('expires=');
    expect(si).toContain('tag="a2a-dnsid-http-sig-v1"');
  });

  it('Signature-Input includes keyid as {domain}#{kid}', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const signed = await manager.createSignedHttpRequest(makeGetRequest());
    const si = signed.headers.get('Signature-Input')!;
    expect(si).toContain('signer.example.com#key-1');
  });

  it('adds Content-Digest header and includes content-digest component for POST with body', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const signed = await manager.createSignedHttpRequest(makePostRequest());
    expect(signed.headers.get('Content-Digest')).toMatch(/^sha-256=:/);
    expect(signed.headers.get('Signature-Input')).toContain('content-digest');
  });

  it('preserves request metadata and leaves the original body readable', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const request = new Request('https://api.example.com/resource', {
      method: 'POST',
      body: 'hello',
      credentials: 'include',
      redirect: 'manual',
      referrer: 'https://client.example/source',
      referrerPolicy: 'origin',
    });

    const signed = await manager.createSignedHttpRequest(request);

    expect(signed.credentials).toBe('include');
    expect(signed.redirect).toBe('manual');
    expect(signed.referrer).toBe(request.referrer);
    expect(signed.referrerPolicy).toBe('origin');
    expect(await request.text()).toBe('hello');
    expect(await signed.text()).toBe('hello');
  });

  it('does not add Content-Digest for a GET with no body', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const signed = await manager.createSignedHttpRequest(makeGetRequest());
    expect(signed.headers.get('Content-Digest')).toBeNull();
    expect(signed.headers.get('Signature-Input')).not.toContain('content-digest');
  });

  it('hashes and covers explicitly supplied empty content', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const signed = await manager.createSignedHttpRequest(new Request('https://api.example.com/resource', {
      method: 'POST',
      body: '',
    }));
    expect(signed.body).not.toBeNull();
    expect(signed.headers.get('Content-Digest')).toBe('sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:');
    expect(parseSignatureInput(signed.headers.get('Signature-Input')!).get('sig1')!.components).toContain('content-digest');
  });

  it('does not infer supplied content from Content-Length', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const signed = await manager.createSignedHttpRequest(new Request('https://api.example.com/resource', {
      method: 'POST',
      headers: { 'Content-Length': '0' },
    }));
    expect(signed.body).toBeNull();
    expect(signed.headers.get('Content-Digest')).toBeNull();
    expect(parseSignatureInput(signed.headers.get('Signature-Input')!).get('sig1')!.components).not.toContain('content-digest');
  });

  it('includes additional components when specified', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const req = new Request('https://api.example.com/resource', {
      method: 'GET',
      headers: { 'x-request-id': 'abc' },
    });
    const signed = await manager.createSignedHttpRequest(req, { additionalComponents: ['x-request-id'] });
    expect(signed.headers.get('Signature-Input')).toContain('x-request-id');
  });

  it('throws ArgumentError for an unknown component name', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    await expect(
      manager.createSignedHttpRequest(makeGetRequest(), { additionalComponents: ['UPPERCASE-INVALID'] }),
    ).rejects.toThrow(ArgumentError);
  });

  it('throws ArgumentError when signing key kid contains #', async () => {
    const badKey: DnsIdJWK = { ...publicJwk, kid: 'bad#kid' };
    const kp: KeyProvider = { ...makeKeyProvider(), signingKey: vi.fn().mockResolvedValue(badKey) };
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: kp, identityResolver: resolverStub });
    await expect(manager.createSignedHttpRequest(makeGetRequest())).rejects.toThrow(ArgumentError);
  });
});

// ---- createSignedFetch ----

describe('HttpSignaturesProfile.createSignedFetch()', () => {
  it('signs GET requests and uses an injected fetch', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const calls: Request[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      calls.push(input as Request);
      return new Response('ok');
    });

    const signedFetch = manager.createSignedFetch({ fetch: fetchImpl });
    const resp = await signedFetch('https://api.example.com/resource');

    expect(await resp.text()).toBe('ok');
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(calls[0]!.headers.get('Signature')).toBeTruthy();
    expect(calls[0]!.headers.get('Signature-Input')).toBeTruthy();
  });

  it('adds Content-Digest for requests with a body', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    let sent!: Request;
    const signedFetch = manager.createSignedFetch({
      fetch: vi.fn(async (input: RequestInfo | URL) => {
        sent = input as Request;
        return new Response('ok');
      }),
    });

    await signedFetch('https://api.example.com/resource', { method: 'POST', body: 'hello' });

    expect(sent.headers.get('Content-Digest')).toMatch(/^sha-256=:/);
    expect(sent.headers.get('Signature-Input')).toContain('content-digest');
  });

  it('signs pre-built Request inputs with replayable bodies', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    let sent!: Request;
    const signedFetch = manager.createSignedFetch({
      fetch: vi.fn(async (input: RequestInfo | URL) => {
        sent = input as Request;
        return new Response('ok');
      }),
    });
    const req = new Request('https://api.example.com/resource', { method: 'POST', body: 'hello' });

    await signedFetch(req);

    expect(sent.headers.get('Content-Digest')).toMatch(/^sha-256=:/);
    expect(sent.headers.get('Signature-Input')).toContain('content-digest');
    expect(req.bodyUsed).toBe(false);
    expect(await req.text()).toBe('hello');
  });

  it('rejects non-replayable ReadableStream bodies before sending', async () => {
    const manager = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const fetchImpl = vi.fn(async () => new Response('should not send'));
    const signedFetch = manager.createSignedFetch({ fetch: fetchImpl });
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('hello'));
        controller.close();
      },
    });

    await expect(signedFetch('https://api.example.com/resource', {
      method: 'POST',
      body: stream,
      // Required by Node fetch for stream request bodies.
      duplex: 'half',
    } as RequestInit)).rejects.toThrow(ArgumentError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

// ---- verifySignedHttpRequest (round-trip) ----

describe('HttpSignaturesProfile.verifySignedHttpRequest()', () => {
  async function makeMinimalSignedGetRequest(): Promise<Request> {
    const req = makeGetRequest();
    const created = Math.floor(Date.now() / 1000);
    const signatureInput =
      `a2a=("@method" "@authority" "@target-uri");keyid="signer.example.com#key-1";alg="ecdsa-p256-sha256";created=${created}`;
    const signatureBase = [
      '"@method": GET',
      '"@authority": api.example.com',
      '"@target-uri": https://api.example.com/resource?foo=bar',
      `"@signature-params": ${signatureInput.slice('a2a='.length)}`,
    ].join('\n');
    const sig = await signWithKey(new TextEncoder().encode(signatureBase));
    const headers = new Headers(req.headers);
    headers.set('Signature-Input', signatureInput);
    headers.set('Signature', `a2a=:${btoa(String.fromCharCode(...sig))}:`);
    return new Request(req.url, { method: req.method, headers });
  }

  async function setup() {
    const fixture = await currentProfileFixture('signer.example.com', publicJwk);
    mockFetchJson.mockImplementation(fixture.fetchJson);
    const signer = new HttpSignaturesProfile({ domain: SIGNER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: resolverStub });
    const verifierResolver = new IdentityManager({ identity: VERIFIER_CONFIG }, { keyProvider: makeKeyProvider(), logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson: mockFetchJson });
    const verifier = new HttpSignaturesProfile({ domain: VERIFIER_CONFIG.domain, keyProvider: makeKeyProvider(), identityResolver: verifierResolver });
    return { signer, verifier };
  }

  it('returns a VerifiedDomain for a valid signed GET request', async () => {
    const { signer, verifier } = await setup();
    const signed = await signer.createSignedHttpRequest(makeGetRequest());
    const vd = await verifier.verifySignedHttpRequest(signed);
    expect(vd.domain).toBe('signer.example.com');
  });

  it('returns a VerifiedDomain for a valid signed POST request', async () => {
    const { signer, verifier } = await setup();
    const signed = await signer.createSignedHttpRequest(makePostRequest());
    const vd = await verifier.verifySignedHttpRequest(signed);
    expect(vd.domain).toBe('signer.example.com');
  });

  it('verifies a covered SHA-256 digest for explicitly supplied empty content', async () => {
    const { signer, verifier } = await setup();
    const signed = await signer.createSignedHttpRequest(new Request('https://api.example.com/resource', {
      method: 'POST',
      body: '',
    }));
    await expect(verifier.verifySignedHttpRequest(signed)).resolves.toMatchObject({ domain: 'signer.example.com' });

    const headers = new Headers(signed.headers);
    headers.set('Content-Digest', 'sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:');
    const tampered = new Request(signed, { headers, body: await signed.clone().arrayBuffer() });
    await expect(verifier.verifySignedHttpRequest(tampered)).rejects.toThrow(VerificationError);
  });

  it('verifies absent content without requiring a digest despite Content-Length', async () => {
    const { signer, verifier } = await setup();
    const signed = await signer.createSignedHttpRequest(new Request('https://api.example.com/resource', {
      method: 'POST',
      headers: { 'Content-Length': '0' },
    }));
    expect(signed.body).toBeNull();
    await expect(verifier.verifySignedHttpRequest(signed)).resolves.toMatchObject({ domain: 'signer.example.com' });
  });

  it('accepts a valid signature without optional expires, nonce, or tag parameters', async () => {
    const { verifier } = await setup();
    const signed = await makeMinimalSignedGetRequest();
    const vd = await verifier.verifySignedHttpRequest(signed);
    expect(vd.domain).toBe('signer.example.com');
    expect(signed.headers.get('Signature-Input')).not.toContain('expires=');
    expect(signed.headers.get('Signature-Input')).not.toContain('nonce=');
    expect(signed.headers.get('Signature-Input')).not.toContain('tag=');
  });

  it('enforces a required tag only when caller policy requests one', async () => {
    const { verifier } = await setup();
    const signed = await makeMinimalSignedGetRequest();
    await expect(
      verifier.verifySignedHttpRequest(signed, { requiredTag: 'a2a-dnsid-http-sig-v1' }),
    ).rejects.toThrow(VerificationError);
  });

  it('uses requiredTag to select one signature from multiple signatures', async () => {
    const { signer, verifier } = await setup();
    const signedOther = await signer.createSignedHttpRequest(makeGetRequest(), { label: 'other', tag: 'other' });
    const signedWba = await signer.createSignedHttpRequest(signedOther, { label: 'sig1', tag: 'web-bot-auth' });

    await expect(verifier.verifySignedHttpRequest(signedWba, { requiredTag: 'web-bot-auth' })).resolves.toBeTruthy();
    await expect(verifier.verifySignedHttpRequest(signedWba)).rejects.toThrow(VerificationError);
  });

  it('ignores an invalid coexisting signature', async () => {
    const { signer, verifier } = await setup();
    const signed = await signer.createSignedHttpRequest(makeGetRequest());
    const headers = new Headers(signed.headers);
    headers.set('Signature-Input', `proxy=${headers.get('Signature-Input')!.slice('sig1='.length)}, ${headers.get('Signature-Input')}`);
    headers.set('Signature', `proxy=:Ym9ndXM=:, ${headers.get('Signature')}`);
    const withProxy = new Request(signed, { headers });

    await expect(verifier.verifySignedHttpRequest(withProxy)).resolves.toMatchObject({ domain: 'signer.example.com' });
  });

  it('matches required parameterized components by full identity', async () => {
    const { signer, verifier } = await setup();
    const signed = await signer.createSignedHttpRequest(makeGetRequest(), {
      additionalComponents: [{ name: '@query-param', params: { name: 'foo' } }],
    });

    await expect(verifier.verifySignedHttpRequest(signed, {
      requiredComponents: ['@method', '@authority', '@target-uri', { name: '@query-param', params: { name: 'bar' } }],
    })).rejects.toThrow(VerificationError);
  });

  it('does not treat keyed content-digest as body digest coverage', async () => {
    const { verifier } = await setup();
    const body = 'hello';
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body));
    const req = new Request('https://api.example.com/resource', {
      method: 'POST',
      body,
      headers: { 'Content-Digest': `sha-256=:${btoa(String.fromCharCode(...new Uint8Array(digest)))}:, foo=:AA==:` },
    });
    const signed = await signHttpMessage(req, {
      label: 'sig1',
      keyId: 'signer.example.com#key-1',
      alg: 'ecdsa-p256-sha256',
      created: Math.floor(Date.now() / 1000),
      components: ['@method', '@authority', '@target-uri', { name: 'content-digest', params: { key: 'foo' } }],
    }, makeKeyProvider());

    await expect(verifier.verifySignedHttpRequest(signed)).rejects.toThrow(VerificationError);
  });

  it('throws VerificationError when Signature-Input header is absent', async () => {
    const { verifier } = await setup();
    const req = new Request('https://api.example.com/', { headers: { Signature: 'a2a=:abc:' } });
    await expect(verifier.verifySignedHttpRequest(req)).rejects.toThrow(VerificationError);
  });

  it('throws VerificationError when Signature header is absent', async () => {
    const { verifier } = await setup();
    const req = new Request('https://api.example.com/', { headers: { 'Signature-Input': 'a2a=()' } });
    await expect(verifier.verifySignedHttpRequest(req)).rejects.toThrow(VerificationError);
  });

  it('throws VerificationError when signature is expired (created too old)', async () => {
    const { signer, verifier } = await setup();
    const signed = await signer.createSignedHttpRequest(makeGetRequest());
    // Tamper the created timestamp to be very old
    const si = signed.headers.get('Signature-Input')!;
    const oldSI = si.replace(/created=\d+/, `created=${Math.floor(Date.now() / 1000) - 9999}`);
    const newHeaders = new Headers(signed.headers);
    newHeaders.set('Signature-Input', oldSI);
    const tampered = new Request(signed.url, { method: signed.method, headers: newHeaders });
    const err = await verifier.verifySignedHttpRequest(tampered).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).code).toBe(VerificationCode.SignatureInvalid);
  });

  it('throws VerificationError when created is too far in the future', async () => {
    const { signer, verifier } = await setup();
    const signed = await signer.createSignedHttpRequest(makeGetRequest());
    const si = signed.headers.get('Signature-Input')!;
    const futureSI = si.replace(/created=\d+/, `created=${Math.floor(Date.now() / 1000) + 9999}`);
    const newHeaders = new Headers(signed.headers);
    newHeaders.set('Signature-Input', futureSI);
    const tampered = new Request(signed.url, { method: signed.method, headers: newHeaders });
    const err = await verifier.verifySignedHttpRequest(tampered).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).code).toBe(VerificationCode.SignatureInvalid);
  });

  it('throws VerificationError when a required covered component is omitted', async () => {
    const { signer, verifier } = await setup();
    const signed = await signer.createSignedHttpRequest(makeGetRequest());
    const si = signed.headers.get('Signature-Input')!;
    const missingTargetUri = si.replace(' "@target-uri"', '');
    const newHeaders = new Headers(signed.headers);
    newHeaders.set('Signature-Input', missingTargetUri);
    const tampered = new Request(signed.url, { method: signed.method, headers: newHeaders });
    const err = await verifier.verifySignedHttpRequest(tampered).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).code).toBe(VerificationCode.SignatureInvalid);
    expect((err as VerificationError).message).toContain('@target-uri');
  });

  it('throws VerificationError when @authority is omitted from default covered components', async () => {
    const { signer, verifier } = await setup();
    const signed = await signer.createSignedHttpRequest(makeGetRequest());
    const si = signed.headers.get('Signature-Input')!;
    const missingAuthority = si.replace(' "@authority"', '');
    const newHeaders = new Headers(signed.headers);
    newHeaders.set('Signature-Input', missingAuthority);
    const tampered = new Request(signed.url, { method: signed.method, headers: newHeaders });
    const err = await verifier.verifySignedHttpRequest(tampered).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).code).toBe(VerificationCode.SignatureInvalid);
    expect((err as VerificationError).message).toContain('@authority');
  });

  it('throws VerificationError when the body has been tampered with (Content-Digest mismatch)', async () => {
    const { signer, verifier } = await setup();
    const signed = await signer.createSignedHttpRequest(makePostRequest('original body'));
    // Replace body with tampered content but keep same headers
    const tampered = new Request(signed.url, {
      method: signed.method,
      headers: signed.headers,
      body: 'tampered body',
    });
    const err = await verifier.verifySignedHttpRequest(tampered).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).code).toBe(VerificationCode.SignatureInvalid);
  });

  it('throws VerificationError when the signature bytes are corrupted', async () => {
    const { signer, verifier } = await setup();
    const signed = await signer.createSignedHttpRequest(makeGetRequest());
    const newHeaders = new Headers(signed.headers);
    // 64 zero bytes as standard base64 = valid-length but cryptographically wrong ES256 signature
    const zeroSig = btoa(String.fromCharCode(...new Uint8Array(64)));
    newHeaders.set('Signature', `sig1=:${zeroSig}:`);
    const tampered = new Request(signed.url, { method: signed.method, headers: newHeaders });
    const err = await verifier.verifySignedHttpRequest(tampered).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).code).toBe(VerificationCode.SignatureInvalid);
  });
});
