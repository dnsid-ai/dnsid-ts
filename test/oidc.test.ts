const dnsLookupMock = vi.hoisted(() => vi.fn(async () => [{ address: '93.184.216.34', family: 4 }]));
vi.mock('node:dns/promises', () => ({ lookup: dnsLookupMock }));

import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { CompactSign, SignJWT, exportJWK, generateKeyPair, importJWK, jwtVerify } from 'jose';

import {
  OIDCProfile,
  OIDCTokenMinter,
  createOIDCKeyProviderFromJWK,
  createOIDCTokenMinter,
  decodeOIDCClaims,
  mintOIDCToken,
  validateExactOIDCIssuer,
} from '@identity-digital/dnsid-oidc';
import { ArgumentError, VerificationError, fromBase64Url, jwkThumbprint, toArrayBuffer, toBase64Url } from '@identity-digital/dnsid-protocol';
import type { DnsIdJWK, KeyProvider, VerifiedDomain } from '@identity-digital/dnsid-protocol';

let privateKey: CryptoKey;
let publicJwk: DnsIdJWK;

beforeAll(async () => {
  const kp = await generateKeyPair('ES256');
  privateKey = kp.privateKey;
  const raw = await exportJWK(kp.publicKey);
  publicJwk = { ...raw, kty: raw.kty!, alg: 'ES256', kid: 'key-1', use: 'sig' } as DnsIdJWK;
});

beforeEach(() => {
  dnsLookupMock.mockReset();
  dnsLookupMock.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
});

function keyProvider(): KeyProvider {
  return {
    signingKey: vi.fn().mockResolvedValue(publicJwk),
    jwk: vi.fn().mockResolvedValue(publicJwk),
    listKeyIds: vi.fn().mockResolvedValue(['key-1']),
    sign: vi.fn().mockImplementation(async (bytes: Uint8Array) => new Uint8Array(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, toArrayBuffer(bytes)),
    )),
    signKey: vi.fn().mockImplementation(async (_kid: string, bytes: Uint8Array) => new Uint8Array(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, toArrayBuffer(bytes)),
    )),
    generateKey: vi.fn(),
    activate: vi.fn(),
    supersede: vi.fn(),
    purge: vi.fn(),
  };
}

function profile(fetch = vi.fn(), oidc = {}): OIDCProfile {
  return new OIDCProfile({
    domain: 'agent.example.com',
    keyProvider: keyProvider(),
    identityResolver: { verifyDomain: vi.fn() },
    fetch: fetch as unknown as typeof globalThis.fetch,
    oidc: { allowedIssuers: ['https://issuer.example.com'], ...oidc },
  });
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });
}

function signRawJWT(payload: Record<string, unknown>, key: CryptoKey): Promise<string> {
  return new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'RS256', kid: 'issuer-key' })
    .sign(key);
}

function jwtPart(token: string, index: number): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(fromBase64Url(token.split('.')[index]!))) as Record<string, unknown>;
}

async function exportPrivateJwk(alg: 'ES256' | 'RS256') {
  const keys = await generateKeyPair(alg, { extractable: true });
  const privateJwk = await exportJWK(keys.privateKey);
  if (typeof privateJwk.d !== 'string') throw new Error('expected exportable private JWK');
  return { keys, privateJwk };
}

const discovery = {
  issuer: 'https://issuer.example.com',
  token_endpoint: 'https://issuer.example.com/token',
  jwks_uri: 'https://issuer.example.com/jwks',
};

describe('OIDCProfile', () => {
  it('uses fractional dates and forwards the current peer before rechecking expiration', async () => {
    const clock = vi.spyOn(Date, 'now').mockReturnValue(1500);
    try {
      const peerCert = { san: ['agent.example.com'], notAfter: new Date('2099-01-01') };
      const verified = { domain: 'agent.example.com' } as VerifiedDomain;
      const verifyDomain = vi.fn(async () => verified);
      const fetch = vi.fn(async (url: string | URL | Request) => json(String(url).endsWith('/jwks') ? { keys: [publicJwk] } : discovery));
      const p = new OIDCProfile({ domain: 'agent.example.com', identityResolver: { verifyDomain }, fetch: fetch as typeof globalThis.fetch, oidc: { allowedIssuers: [discovery.issuer], allowedTokenAlgorithms: ['ES256'], clockSkew: 0 } });
      const token = await new CompactSign(new TextEncoder().encode(JSON.stringify({ iss: discovery.issuer, sub: 'agent.example.com', aud: 'rp.example.com', iat: 0, nbf: 1.25, exp: 1.75 }))).setProtectedHeader({ alg: 'ES256', kid: publicJwk.kid }).sign(privateKey);
      const options = { issuer: discovery.issuer, audience: 'rp.example.com', peerCert };
      await expect(p.verifyOIDCToken(token, options)).resolves.toMatchObject({ verifiedDomain: verified });
      expect(verifyDomain).toHaveBeenCalledWith('agent.example.com', peerCert, { signal: expect.any(AbortSignal) });
      verifyDomain.mockImplementation(async () => { clock.mockReturnValue(1750); return verified; });
      await expect(p.verifyOIDCToken(token, options)).rejects.toThrow('expired');
      clock.mockReturnValue(1000);
      await expect(p.verifyOIDCToken(token, options)).rejects.toThrow('not yet valid');
    } finally { clock.mockRestore(); }
  });
  it('creates DNSid JWT bearer assertions', async () => {
    const jwt = await profile().createOIDCAssertion({ issuer: 'https://issuer.example.com' });
    const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(jwt.split('.')[1]!)));
    expect(payload.iss).toBe('agent.example.com');
    expect(payload.sub).toBe('agent.example.com');
    expect(payload.aud).toEqual(['https://issuer.example.com']);
    expect(payload.fqdn).toBe('agent.example.com');
  });

  it('rejects reserved assertion claim overrides', async () => {
    await expect(profile().createOIDCAssertion({
      issuer: 'https://issuer.example.com',
      additionalClaims: { iss: 'evil.example.com' },
    })).rejects.toThrow(ArgumentError);
  });

  it('validates exact issuer URLs', () => {
    expect(validateExactOIDCIssuer('https://issuer.example.com')).toBe('https://issuer.example.com');
    expect(validateExactOIDCIssuer('https://issuer.example.com/issuer1')).toBe('https://issuer.example.com/issuer1');
    expect(validateExactOIDCIssuer('http://localhost/issuer1', true)).toBe('http://localhost/issuer1');
    expect(validateExactOIDCIssuer('http://127.0.0.1/issuer1', true)).toBe('http://127.0.0.1/issuer1');
    expect(validateExactOIDCIssuer('http://[::1]/issuer1', true)).toBe('http://[::1]/issuer1');
    expect(() => validateExactOIDCIssuer('https://issuer.example.com/')).toThrow(ArgumentError);
    expect(() => validateExactOIDCIssuer('https://issuer.example.com/issuer1/')).toThrow(ArgumentError);
    expect(() => validateExactOIDCIssuer('https://issuer.example.com/issuer1?x=1')).toThrow(ArgumentError);
    expect(() => validateExactOIDCIssuer('http://issuer.example.com')).toThrow(ArgumentError);
    expect(() => validateExactOIDCIssuer('http://localhost')).toThrow(ArgumentError);
    expect(() => validateExactOIDCIssuer('http://127.evil.com/issuer', true)).toThrow(ArgumentError);
    expect(() => validateExactOIDCIssuer('http://127.0.0.1.evil.com/issuer', true)).toThrow(ArgumentError);
  });

  it('validates discovery documents', async () => {
    const fetch = vi.fn().mockResolvedValue(json(discovery));
    await expect(profile(fetch).discoverOIDCIssuer('https://issuer.example.com')).resolves.toMatchObject(discovery);
    expect(fetch).toHaveBeenCalledWith('https://issuer.example.com/.well-known/openid-configuration', expect.objectContaining({ redirect: 'manual' }));
  });

  it('allows loopback HTTP discovery only with explicit opt-in', async () => {
    const localDiscovery = {
      issuer: 'http://localhost:9999/issuer1',
      token_endpoint: 'http://localhost:9999/issuer1/token',
      jwks_uri: 'http://localhost:9999/issuer1/jwks',
    };
    const fetch = vi.fn().mockResolvedValue(json(localDiscovery));
    await expect(profile(fetch, { allowHttpLoopbackIssuer: true }).discoverOIDCIssuer(localDiscovery.issuer)).resolves.toMatchObject(localDiscovery);
    expect(fetch).toHaveBeenCalledWith(`${localDiscovery.issuer}/.well-known/openid-configuration`, expect.objectContaining({ redirect: 'manual' }));
    await expect(profile(fetch).discoverOIDCIssuer(localDiscovery.issuer)).rejects.toThrow(ArgumentError);
  });

  it('blocks unsafe OIDC targets before fetch', async () => {
    for (const issuer of ['https://127.0.0.1', 'https://169.254.169.254', 'https://10.0.0.1', 'https://[fe80::1]']) {
      const fetch = vi.fn();
      await expect(profile(fetch).discoverOIDCIssuer(issuer)).rejects.toThrow(VerificationError);
      expect(fetch).not.toHaveBeenCalled();
    }
  });

  it('blocks hostnames resolving to unsafe OIDC targets before fetch', async () => {
    dnsLookupMock.mockResolvedValueOnce([{ address: '10.0.0.1', family: 4 }]);
    const fetch = vi.fn();
    await expect(profile(fetch).discoverOIDCIssuer('https://issuer.example.com')).rejects.toThrow(VerificationError);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('discovers path-based issuers', async () => {
    const pathDiscovery = {
      issuer: 'https://issuer.example.com/issuer1',
      token_endpoint: 'https://issuer.example.com/issuer1/token',
      jwks_uri: 'https://issuer.example.com/issuer1/jwks',
    };
    const fetch = vi.fn().mockResolvedValue(json(pathDiscovery));
    await expect(profile(fetch).discoverOIDCIssuer('https://issuer.example.com/issuer1')).resolves.toMatchObject(pathDiscovery);
    expect(fetch).toHaveBeenCalledWith('https://issuer.example.com/issuer1/.well-known/openid-configuration', expect.objectContaining({ redirect: 'manual' }));
  });

  it('rejects malformed discovery documents', async () => {
    for (const body of [null, { ...discovery, issuer: 'https://other.example.com' }]) {
      const fetch = vi.fn().mockResolvedValue(json(body));
      await expect(profile(fetch).discoverOIDCIssuer('https://issuer.example.com')).rejects.toThrow(VerificationError);
    }
  });

  it('exchanges assertions for bearer tokens', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(json(discovery))
      .mockResolvedValueOnce(json({ access_token: 'token', token_type: 'Bearer', expires_in: 60, scope: 'openid' }));
    const got = await profile(fetch).exchangeOIDCToken({ issuer: 'https://issuer.example.com', audience: 'rp.example.com' });
    expect(got.accessToken).toBe('token');
    const form = await (fetch.mock.calls[1]![1]!.body as URLSearchParams);
    expect(form.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer');
    expect(form.get('audience')).toBe('rp.example.com');
  });

  it('mints tokens in server mode using discovered issuer but server token endpoint', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(json({
        issuer: 'https://issuer.example.com',
        token_endpoint: 'https://issuer.example.com/not-used',
        jwks_uri: 'https://issuer.example.com/jwks',
      }))
      .mockResolvedValueOnce(json({ access_token: 'minted-token', token_type: 'Bearer', expires_in: 60, scope: 'openid' }));
    const minter = new OIDCTokenMinter({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: fetch as unknown as typeof globalThis.fetch,
      serverUrl: 'https://api.example.com',
    });

    const got = await minter.mintToken({ audience: 'https://gateway.example.com' });

    expect(got).toMatchObject({
      accessToken: 'minted-token',
      tokenType: 'Bearer',
      issuer: 'https://issuer.example.com',
      tokenEndpoint: 'https://api.example.com/token',
      scope: 'openid',
    });
    expect(fetch.mock.calls[0]![0]).toBe('https://api.example.com/.well-known/openid-configuration');
    expect(fetch.mock.calls[1]![0]).toBe('https://api.example.com/token');
    const form = fetch.mock.calls[1]![1]!.body as URLSearchParams;
    expect(form.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer');
    expect(form.get('audience')).toBe('https://gateway.example.com');
    expect(form.get('scope')).toBe('openid');
    const assertion = form.get('assertion')!;
    expect(jwtPart(assertion, 0)).toMatchObject({ alg: 'ES256', kid: 'key-1', typ: 'JWT' });
    expect(jwtPart(assertion, 1)).toMatchObject({
      iss: 'agent.example.com',
      sub: 'agent.example.com',
      aud: ['https://issuer.example.com'],
      fqdn: 'agent.example.com',
    });
    expect(jwtPart(assertion, 1).iat).toBeTypeOf('number');
    expect(jwtPart(assertion, 1).exp).toBeTypeOf('number');
    expect(jwtPart(assertion, 1).jti).toBeTypeOf('string');
    expect((jwtPart(assertion, 1).exp as number) - (jwtPart(assertion, 1).iat as number)).toBe(300);
    await expect(jwtVerify(assertion, await importJWK(publicJwk, 'ES256'), {
      issuer: 'agent.example.com',
      subject: 'agent.example.com',
      audience: 'https://issuer.example.com',
    })).resolves.toMatchObject({
      payload: expect.objectContaining({ fqdn: 'agent.example.com' }),
    });
  });

  it('mints tokens in explicit issuer mode using the discovered token endpoint', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(json({
        issuer: 'https://issuer.example.com',
        token_endpoint: 'https://issuer.example.com/oauth/token',
        jwks_uri: 'https://issuer.example.com/jwks',
      }))
      .mockResolvedValueOnce(json({ access_token: 'token', token_type: 'Bearer' }));
    const minter = await createOIDCTokenMinter({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: fetch as unknown as typeof globalThis.fetch,
      issuer: 'https://issuer.example.com',
    });

    await minter.mintToken({ audience: 'rp.example.com' });

    expect(fetch.mock.calls[0]![0]).toBe('https://issuer.example.com/.well-known/openid-configuration');
    expect(fetch.mock.calls[1]![0]).toBe('https://issuer.example.com/oauth/token');
  });

  it('uses configured discovery URL overrides', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(json({
        issuer: 'https://issuer.example.com',
        token_endpoint: 'https://issuer.example.com/oauth/token',
        jwks_uri: 'https://issuer.example.com/jwks',
      }))
      .mockResolvedValueOnce(json({ access_token: 'token', token_type: 'Bearer' }));

    await mintOIDCToken({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: fetch as unknown as typeof globalThis.fetch,
      issuer: 'https://issuer.example.com',
      discoveryUrl: 'https://metadata.example.net/custom-issuer.json',
      audience: 'rp.example.com',
    });

    expect(fetch.mock.calls[0]![0]).toBe('https://metadata.example.net/custom-issuer.json');
    expect(fetch.mock.calls[1]![0]).toBe('https://issuer.example.com/oauth/token');
  });

  it('supports direct issuer and token endpoint override without discovery', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json({ access_token: 'token', token_type: 'Bearer' }));

    await mintOIDCToken({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: fetch as unknown as typeof globalThis.fetch,
      issuer: 'https://custom-issuer.example.org',
      tokenEndpoint: 'https://custom-issuer.example.org/custom/token',
      audience: 'rp.example.com',
    });

    expect(fetch).toHaveBeenCalledOnce();
    expect(fetch.mock.calls[0]![0]).toBe('https://custom-issuer.example.org/custom/token');
    const form = fetch.mock.calls[0]![1]!.body as URLSearchParams;
    expect(jwtPart(form.get('assertion')!, 1).aud).toEqual(['https://custom-issuer.example.org']);
  });

  it('inherits the constructor issuer for per-call token endpoint overrides', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json({ access_token: 'token', token_type: 'Bearer' }));
    const minter = new OIDCTokenMinter({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: fetch as unknown as typeof globalThis.fetch,
      issuer: 'https://issuer.example.com',
      discoveryUrl: 'https://metadata.example.net/custom-issuer.json',
    });

    const token = await minter.mintToken({
      audience: 'rp.example.com',
      tokenEndpoint: 'https://issuer.example.com/custom-token',
    });

    expect(fetch).toHaveBeenCalledOnce();
    expect(fetch.mock.calls[0]![0]).toBe('https://issuer.example.com/custom-token');
    expect(token.issuer).toBe('https://issuer.example.com');
    expect(token.tokenEndpoint).toBe('https://issuer.example.com/custom-token');
    const form = fetch.mock.calls[0]![1]!.body as URLSearchParams;
    expect(jwtPart(form.get('assertion')!, 1).aud).toEqual(['https://issuer.example.com']);
  });

  it('uses a per-call server URL endpoint mode override without carrying constructor issuer fields', async () => {
    const serverFetch = vi.fn()
      .mockResolvedValueOnce(json({
        issuer: 'https://server-issuer.example.com',
        token_endpoint: 'https://server-issuer.example.com/not-used',
        jwks_uri: 'https://server-issuer.example.com/jwks',
      }))
      .mockResolvedValueOnce(json({ access_token: 'server-token', token_type: 'Bearer' }));
    const issuerDefaultMinter = new OIDCTokenMinter({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: serverFetch as unknown as typeof globalThis.fetch,
      issuer: 'https://default-issuer.example.com',
    });
    const serverToken = await issuerDefaultMinter.mintToken({
      audience: 'rp.example.com',
      serverUrl: 'https://api.example.com',
    });
    expect(serverFetch.mock.calls[0]![0]).toBe('https://api.example.com/.well-known/openid-configuration');
    expect(serverFetch.mock.calls[1]![0]).toBe('https://api.example.com/token');
    expect(serverToken.issuer).toBe('https://server-issuer.example.com');
    expect(serverToken.tokenEndpoint).toBe('https://api.example.com/token');
    const serverForm = serverFetch.mock.calls[1]![1]!.body as URLSearchParams;
    expect(jwtPart(serverForm.get('assertion')!, 1).aud).toEqual(['https://server-issuer.example.com']);
  });

  it('uses a per-call issuer endpoint mode override without carrying constructor token endpoint fields', async () => {
    const issuerFetch = vi.fn()
      .mockResolvedValueOnce(json({
        issuer: 'https://issuer.example.com',
        token_endpoint: 'https://issuer.example.com/discovered-token',
        jwks_uri: 'https://issuer.example.com/jwks',
      }))
      .mockResolvedValueOnce(json({ access_token: 'issuer-token', token_type: 'Bearer' }));
    const directDefaultMinter = new OIDCTokenMinter({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: issuerFetch as unknown as typeof globalThis.fetch,
      issuer: 'https://default-issuer.example.com',
      tokenEndpoint: 'https://default-issuer.example.com/token',
    });
    const issuerToken = await directDefaultMinter.mintToken({
      audience: 'rp.example.com',
      issuer: 'https://issuer.example.com',
    });
    expect(issuerFetch.mock.calls[0]![0]).toBe('https://issuer.example.com/.well-known/openid-configuration');
    expect(issuerFetch.mock.calls[1]![0]).toBe('https://issuer.example.com/discovered-token');
    expect(issuerToken.issuer).toBe('https://issuer.example.com');
    expect(issuerToken.tokenEndpoint).toBe('https://issuer.example.com/discovered-token');
    const issuerForm = issuerFetch.mock.calls[1]![1]!.body as URLSearchParams;
    expect(jwtPart(issuerForm.get('assertion')!, 1).aud).toEqual(['https://issuer.example.com']);
  });

  it('rejects mixed constructor endpoint modes instead of silently choosing one', async () => {
    expect(() => new OIDCTokenMinter({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      issuer: 'https://issuer.example.com',
      serverUrl: 'https://api.example.com',
    })).toThrow(ArgumentError);
    expect(() => new OIDCTokenMinter({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      issuer: 'https://issuer.example.com',
      tokenEndpoint: 'https://issuer.example.com/token',
      discoveryUrl: 'https://issuer.example.com/.well-known/openid-configuration',
    })).toThrow(ArgumentError);
  });

  it('rejects mixed per-call endpoint modes instead of silently choosing one', async () => {
    const minter = new OIDCTokenMinter({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      serverUrl: 'https://api.example.com',
    });
    await expect(minter.mintToken({
      audience: 'rp.example.com',
      issuer: 'https://issuer.example.com',
      serverUrl: 'https://api.example.com',
    })).rejects.toThrow(ArgumentError);
    await expect(minter.mintToken({
      audience: 'rp.example.com',
      issuer: 'https://issuer.example.com',
      tokenEndpoint: 'https://issuer.example.com/token',
      discoveryUrl: 'https://issuer.example.com/.well-known/openid-configuration',
    })).rejects.toThrow(ArgumentError);
  });

  it('rejects an explicitly empty per-call token endpoint', async () => {
    const minter = new OIDCTokenMinter({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      serverUrl: 'https://api.example.com',
    });
    await expect(minter.mintToken({
      audience: 'rp.example.com',
      issuer: 'https://issuer.example.com',
      tokenEndpoint: '',
    })).rejects.toThrow('tokenEndpoint must not be empty');
  });

  it('requires CLI-compatible issuer roots for token minting', async () => {
    for (const issuer of ['https://issuer.example.com/path', 'https://issuer.example.com/', 'https://api.dnsid.dev', 'https://api.dnsid.ai']) {
      await expect(mintOIDCToken({
        domain: 'agent.example.com',
        keyProvider: keyProvider(),
        fetch: vi.fn() as unknown as typeof globalThis.fetch,
        issuer,
        tokenEndpoint: `${issuer.replace(/\/$/, '')}/token`,
        audience: 'rp.example.com',
      })).rejects.toThrow(ArgumentError);
    }
  });

  it('rejects invalid token endpoints while minting', async () => {
    for (const tokenEndpoint of [
      'https://other.example.com/token',
      'https://issuer.example.com',
      'https://issuer.example.com/token?x=1',
      'https://issuer.example.com/token#frag',
    ]) {
      await expect(mintOIDCToken({
        domain: 'agent.example.com',
        keyProvider: keyProvider(),
        fetch: vi.fn() as unknown as typeof globalThis.fetch,
        issuer: 'https://issuer.example.com',
        tokenEndpoint,
        audience: 'rp.example.com',
      })).rejects.toThrow(VerificationError);
    }
  });

  it('rejects invalid discovered token endpoints and redirects while minting', async () => {
    const invalidEndpointFetch = vi.fn().mockResolvedValueOnce(json({
      issuer: 'https://issuer.example.com',
      token_endpoint: 'https://other.example.com/token',
    }));
    await expect(mintOIDCToken({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: invalidEndpointFetch as unknown as typeof globalThis.fetch,
      issuer: 'https://issuer.example.com',
      audience: 'rp.example.com',
    })).rejects.toThrow(VerificationError);

    const discoveryRedirectFetch = vi.fn().mockResolvedValueOnce(new Response(null, {
      status: 302,
      headers: { location: 'https://issuer.example.com/elsewhere' },
    }));
    await expect(mintOIDCToken({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: discoveryRedirectFetch as unknown as typeof globalThis.fetch,
      issuer: 'https://issuer.example.com',
      audience: 'rp.example.com',
    })).rejects.toThrow('OIDC discovery redirects are not allowed');

    const tokenRedirectFetch = vi.fn().mockResolvedValueOnce(new Response(null, {
      status: 302,
      headers: { location: 'https://issuer.example.com/elsewhere' },
    }));
    await expect(mintOIDCToken({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: tokenRedirectFetch as unknown as typeof globalThis.fetch,
      issuer: 'https://issuer.example.com',
      tokenEndpoint: 'https://issuer.example.com/token',
      audience: 'rp.example.com',
    })).rejects.toThrow('OIDC token endpoint redirects are not allowed');
  });

  it('passes requested scopes and omits empty scope values', async () => {
    const scopedFetch = vi.fn()
      .mockResolvedValueOnce(json({ access_token: 'token', token_type: 'Bearer' }));
    await mintOIDCToken({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: scopedFetch as unknown as typeof globalThis.fetch,
      issuer: 'https://issuer.example.com',
      tokenEndpoint: 'https://issuer.example.com/token',
      audience: 'rp.example.com',
      scopes: ['openid', 'dnsid'],
    });
    expect((scopedFetch.mock.calls[0]![1]!.body as URLSearchParams).get('scope')).toBe('openid dnsid');

    const scopeStringFetch = vi.fn()
      .mockResolvedValueOnce(json({ access_token: 'token', token_type: 'Bearer' }));
    await mintOIDCToken({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: scopeStringFetch as unknown as typeof globalThis.fetch,
      issuer: 'https://issuer.example.com',
      tokenEndpoint: 'https://issuer.example.com/token',
      audience: 'rp.example.com',
      scope: 'openid dnsid',
    });
    expect((scopeStringFetch.mock.calls[0]![1]!.body as URLSearchParams).get('scope')).toBe('openid dnsid');

    const emptyScopeFetch = vi.fn()
      .mockResolvedValueOnce(json({ access_token: 'token', token_type: 'Bearer' }));
    await mintOIDCToken({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: emptyScopeFetch as unknown as typeof globalThis.fetch,
      issuer: 'https://issuer.example.com',
      tokenEndpoint: 'https://issuer.example.com/token',
      audience: 'rp.example.com',
      scope: '',
    });
    expect((emptyScopeFetch.mock.calls[0]![1]!.body as URLSearchParams).has('scope')).toBe(false);
  });

  it('surfaces discovery and token endpoint errors cleanly while minting', async () => {
    const discoveryFetch = vi.fn().mockResolvedValueOnce(json({ error: 'down' }, 500));
    await expect(mintOIDCToken({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: discoveryFetch as unknown as typeof globalThis.fetch,
      issuer: 'https://issuer.example.com',
      audience: 'rp.example.com',
    })).rejects.toThrow(VerificationError);

    const tokenFetch = vi.fn().mockResolvedValueOnce(json({ error: 'invalid_scope', error_description: 'scope "admin" is not permitted' }, 400));
    await expect(mintOIDCToken({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: tokenFetch as unknown as typeof globalThis.fetch,
      issuer: 'https://issuer.example.com',
      tokenEndpoint: 'https://issuer.example.com/token',
      audience: 'rp.example.com',
      scope: 'admin',
    })).rejects.toThrow('invalid_scope: scope "admin" is not permitted');
  });

  it('rejects unexpected successful token endpoint statuses clearly', async () => {
    for (const response of [
      json({ access_token: 'token', token_type: 'Bearer' }, 201),
      new Response(null, { status: 204 }),
    ]) {
      const fetch = vi.fn().mockResolvedValueOnce(response);
      await expect(mintOIDCToken({
        domain: 'agent.example.com',
        keyProvider: keyProvider(),
        fetch: fetch as unknown as typeof globalThis.fetch,
        issuer: 'https://issuer.example.com',
        tokenEndpoint: 'https://issuer.example.com/token',
        audience: 'rp.example.com',
      })).rejects.toThrow(`OIDC token endpoint returned unexpected successful status ${response.status}`);
    }
  });

  it('uses configured fetch timeout signals', async () => {
    const signal = new AbortController().signal;
    const timeout = vi.spyOn(AbortSignal, 'timeout').mockReturnValue(signal);
    const fetch = vi.fn()
      .mockResolvedValueOnce(json({
        issuer: 'https://issuer.example.com',
        token_endpoint: 'https://issuer.example.com/token',
        jwks_uri: 'https://issuer.example.com/jwks',
      }))
      .mockResolvedValueOnce(json({ access_token: 'token', token_type: 'Bearer' }));
    try {
      await mintOIDCToken({
        domain: 'agent.example.com',
        keyProvider: keyProvider(),
        fetch: fetch as unknown as typeof globalThis.fetch,
        issuer: 'https://issuer.example.com',
        audience: 'rp.example.com',
        timeoutMs: 1234,
      });
      expect(timeout).toHaveBeenCalledTimes(2);
      expect(timeout).toHaveBeenNthCalledWith(1, 1234);
      expect(timeout).toHaveBeenNthCalledWith(2, 1234);
      expect(fetch.mock.calls[0]![1]!.signal).toBe(signal);
      expect(fetch.mock.calls[1]![1]!.signal).toBe(signal);
    } finally {
      timeout.mockRestore();
    }
  });

  it('applies configured timeout to DNS preflight before fetch', async () => {
    dnsLookupMock.mockReturnValueOnce(new Promise(() => undefined));
    const fetch = vi.fn();
    await expect(mintOIDCToken({
      domain: 'agent.example.com',
      keyProvider: keyProvider(),
      fetch: fetch as unknown as typeof globalThis.fetch,
      issuer: 'https://slow-issuer.example.com',
      tokenEndpoint: 'https://slow-issuer.example.com/token',
      audience: 'rp.example.com',
      timeoutMs: 1,
    })).rejects.toThrow(/deadline|DNS lookup timed out/);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('supports direct private JWK signing for token minting', async () => {
    const { privateJwk: exportedPrivateJwk } = await exportPrivateJwk('ES256');
    const privateJwk = {
      ...exportedPrivateJwk,
      kty: exportedPrivateJwk.kty!,
      crv: exportedPrivateJwk.crv!,
      d: exportedPrivateJwk.d!,
      kid: 'private-key-1',
      alg: 'ES256',
      use: 'sig',
    };
    const provider = await createOIDCKeyProviderFromJWK(privateJwk);
    expect((await provider.signingKey()).kid).toBe('private-key-1');
    const { kid: _kid, ...privateJwkWithoutKid } = privateJwk;
    const derivedProvider = await createOIDCKeyProviderFromJWK(privateJwkWithoutKid);
    const { d: _d, ...publicWithoutKid } = privateJwkWithoutKid;
    expect((await derivedProvider.signingKey()).kid).toBe(await jwkThumbprint(publicWithoutKid as DnsIdJWK));

    const fetch = vi.fn().mockResolvedValueOnce(json({ access_token: 'token', token_type: 'Bearer' }));
    await mintOIDCToken({
      domain: 'agent.example.com',
      privateJwk,
      fetch: fetch as unknown as typeof globalThis.fetch,
      issuer: 'https://issuer.example.com',
      tokenEndpoint: 'https://issuer.example.com/token',
      audience: 'rp.example.com',
    });

    const form = fetch.mock.calls[0]![1]!.body as URLSearchParams;
    const assertion = form.get('assertion')!;
    expect(jwtPart(assertion, 0)).toMatchObject({ alg: 'ES256', kid: 'private-key-1', typ: 'JWT' });
    await expect(jwtVerify(assertion, await importJWK(await provider.signingKey(), 'ES256'))).resolves.toMatchObject({
      payload: expect.objectContaining({
        iss: 'agent.example.com',
        aud: ['https://issuer.example.com'],
      }),
    });
  });

  it('does not expose private RSA JWK fields from direct private JWK key providers', async () => {
    const { privateJwk: exportedPrivateJwk } = await exportPrivateJwk('RS256');
    const privateJwk = {
      ...exportedPrivateJwk,
      kty: exportedPrivateJwk.kty!,
      d: exportedPrivateJwk.d!,
      kid: 'rsa-private-key-1',
      alg: 'RS256',
      use: 'sig',
    };

    const provider = await createOIDCKeyProviderFromJWK(privateJwk);
    const publicJwk = await provider.signingKey();

    expect(publicJwk).toMatchObject({ kty: 'RSA', kid: 'rsa-private-key-1', alg: 'RS256', use: 'sig' });
    expect(publicJwk.n).toBeTypeOf('string');
    expect(publicJwk.e).toBeTypeOf('string');
    for (const privateField of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
      expect(publicJwk).not.toHaveProperty(privateField);
      expect(await provider.jwk('rsa-private-key-1')).not.toHaveProperty(privateField);
    }
  });

  it('fails closed when a key provider signs with a different key than the assertion header names', async () => {
    const other = await generateKeyPair('ES256');
    const rotatingProvider = keyProvider();
    vi.mocked(rotatingProvider.sign).mockImplementation(async (bytes: Uint8Array) => new Uint8Array(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, other.privateKey, toArrayBuffer(bytes)),
    ));

    await expect(mintOIDCToken({
      domain: 'agent.example.com',
      keyProvider: rotatingProvider,
      fetch: vi.fn() as unknown as typeof globalThis.fetch,
      issuer: 'https://issuer.example.com',
      tokenEndpoint: 'https://issuer.example.com/token',
      audience: 'rp.example.com',
    })).rejects.toThrow('OIDC assertion signature does not match active signing key');
  });

  it('does not log token, assertion, or key material while minting', async () => {
    const { privateJwk: exportedPrivateJwk } = await exportPrivateJwk('ES256');
    const privateJwk = {
      ...exportedPrivateJwk,
      kty: exportedPrivateJwk.kty!,
      crv: exportedPrivateJwk.crv!,
      d: exportedPrivateJwk.d!,
      kid: 'private-key-1',
      alg: 'ES256',
      use: 'sig',
    };
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const info = vi.spyOn(console, 'info').mockImplementation(() => undefined);
    const debug = vi.spyOn(console, 'debug').mockImplementation(() => undefined);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const fetch = vi.fn().mockResolvedValueOnce(json({ access_token: 'opaque-log-regression-value', token_type: 'Bearer' }));
    try {
      await expect(mintOIDCToken({
        domain: 'agent.example.com',
        privateJwk,
        fetch: fetch as unknown as typeof globalThis.fetch,
        issuer: 'https://issuer.example.com',
        tokenEndpoint: 'https://issuer.example.com/token',
        audience: 'rp.example.com',
      })).resolves.toMatchObject({ accessToken: 'opaque-log-regression-value' });
      expect(log).not.toHaveBeenCalled();
      expect(info).not.toHaveBeenCalled();
      expect(debug).not.toHaveBeenCalled();
      expect(warn).not.toHaveBeenCalled();
      expect(error).not.toHaveBeenCalled();
    } finally {
      log.mockRestore();
      info.mockRestore();
      debug.mockRestore();
      warn.mockRestore();
      error.mockRestore();
    }
  });

  it('rejects malformed prebuilt assertions as argument errors', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json(discovery));
    await expect(profile(fetch).exchangeOIDCToken({
      issuer: 'https://issuer.example.com',
      audience: 'rp.example.com',
      assertion: 'not-a-jwt',
    })).rejects.toThrow(ArgumentError);
  });

  it('rejects prebuilt assertions with non-exact audiences', async () => {
    const assertion = `${toBase64Url(new TextEncoder().encode(JSON.stringify({ alg: 'none' })))}.${toBase64Url(new TextEncoder().encode(JSON.stringify({ aud: ['https://issuer.example.com', 0] })))}.sig`;
    const fetch = vi.fn().mockResolvedValueOnce(json(discovery));
    await expect(profile(fetch).exchangeOIDCToken({
      issuer: 'https://issuer.example.com',
      audience: 'rp.example.com',
      assertion,
    })).rejects.toThrow(ArgumentError);
  });

  it('requires an issuer allowlist to verify tokens', async () => {
    const p = new OIDCProfile({ domain: 'agent.example.com', keyProvider: keyProvider(), identityResolver: { verifyDomain: vi.fn() } });
    await expect(p.verifyOIDCToken('x.y.z', { issuer: 'https://issuer.example.com', audience: 'rp.example.com' }))
      .rejects.toThrow(VerificationError);
  });

  it('wraps malformed provider JWTs as verification errors', async () => {
    await expect(profile().verifyOIDCToken('not-a-jwt', {
      issuer: 'https://issuer.example.com',
      audience: 'rp.example.com',
      verifyDnsidSubject: false,
    })).rejects.toThrow('malformed JWT');
  });

  it('rejects non-object decoded OIDC claims', () => {
    for (const payload of [null, [], 'str']) {
      const token = `x.${toBase64Url(new TextEncoder().encode(JSON.stringify(payload)))}.y`;
      expect(() => decodeOIDCClaims(token)).toThrow('malformed JWT');
    }
  });

  it('rejects provider JWTs with extra audiences or unsupported headers', async () => {
    const now = Math.floor(Date.now() / 1000);
    const cases = [
      {
        header: { alg: 'RS256', kid: 'issuer-key' },
        payload: { iss: 'https://issuer.example.com', aud: ['rp.example.com', 'other.example.com'], sub: 'subject.example.com', iat: now, exp: now + 120 },
        error: 'OIDC audience mismatch',
      },
      {
        header: { alg: 'RS256', kid: 'issuer-key' },
        payload: { iss: 'https://issuer.example.com', aud: ['rp.example.com', 0], sub: 'subject.example.com', iat: now, exp: now + 120 },
        error: 'OIDC audience mismatch',
      },
      {
        header: { alg: 'RS256', kid: 'issuer-key', jku: 'https://evil.example.com/jwks' },
        payload: { iss: 'https://issuer.example.com', aud: 'rp.example.com', sub: 'subject.example.com', iat: now, exp: now + 120 },
        error: 'unsupported OIDC token header',
      },
    ];
    for (const c of cases) {
      const token = `${toBase64Url(new TextEncoder().encode(JSON.stringify(c.header)))}.${toBase64Url(new TextEncoder().encode(JSON.stringify(c.payload)))}.sig`;
      await expect(profile().verifyOIDCToken(token, {
        issuer: 'https://issuer.example.com',
        audience: 'rp.example.com',
        verifyDnsidSubject: false,
      })).rejects.toThrow(c.error);
    }
  });

  it('verifies provider JWTs and optionally skips DNSid subject verification', async () => {
    const issuerKeys = await generateKeyPair('RS256');
    const jwk = { ...await exportJWK(issuerKeys.publicKey), kid: 'issuer-key', alg: 'RS256', use: 'sig' };
    const token = await new SignJWT({ sub: 'subject.example.com' })
      .setProtectedHeader({ alg: 'RS256', kid: 'issuer-key' })
      .setIssuer('https://issuer.example.com')
      .setAudience('rp.example.com')
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(issuerKeys.privateKey);
    const fetch = vi.fn()
      .mockResolvedValueOnce(json(discovery))
      .mockResolvedValueOnce(json({ keys: [jwk] }));
    const got = await profile(fetch).verifyOIDCToken(token, {
      issuer: 'https://issuer.example.com',
      audience: 'rp.example.com',
      verifyDnsidSubject: false,
    });
    expect(got.subject).toBe('subject.example.com');
  });

  it('verifies tokens from path-based issuers', async () => {
    const issuer = 'https://issuer.example.com/issuer1';
    const issuerKeys = await generateKeyPair('RS256');
    const jwk = { ...await exportJWK(issuerKeys.publicKey), kid: 'issuer-key', alg: 'RS256', use: 'sig' };
    const token = await new SignJWT({ sub: 'subject.example.com' })
      .setProtectedHeader({ alg: 'RS256', kid: 'issuer-key' })
      .setIssuer(issuer)
      .setAudience('rp.example.com')
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(issuerKeys.privateKey);
    const fetch = vi.fn()
      .mockResolvedValueOnce(json({ issuer, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` }))
      .mockResolvedValueOnce(json({ keys: [jwk] }));
    const got = await profile(fetch, { allowedIssuers: [issuer] }).verifyOIDCToken(token, {
      issuer,
      audience: 'rp.example.com',
      verifyDnsidSubject: false,
    });
    expect(got.subject).toBe('subject.example.com');
    expect(fetch).toHaveBeenCalledWith(`${issuer}/.well-known/openid-configuration`, expect.objectContaining({ redirect: 'manual' }));
  });

  it('requires provider JWT exp', async () => {
    const issuerKeys = await generateKeyPair('RS256');
    const jwk = { ...await exportJWK(issuerKeys.publicKey), kid: 'issuer-key', alg: 'RS256', use: 'sig' };
    const token = await new SignJWT({ sub: 'subject.example.com' })
      .setProtectedHeader({ alg: 'RS256', kid: 'issuer-key' })
      .setIssuer('https://issuer.example.com')
      .setAudience('rp.example.com')
      .setIssuedAt()
      .sign(issuerKeys.privateKey);
    const fetch = vi.fn()
      .mockResolvedValueOnce(json(discovery))
      .mockResolvedValueOnce(json({ keys: [jwk] }));
    await expect(profile(fetch).verifyOIDCToken(token, {
      issuer: 'https://issuer.example.com',
      audience: 'rp.example.com',
      verifyDnsidSubject: false,
    })).rejects.toThrow('OIDC token missing exp');
  });

  it('requires provider JWT iat', async () => {
    const issuerKeys = await generateKeyPair('RS256');
    const jwk = { ...await exportJWK(issuerKeys.publicKey), kid: 'issuer-key', alg: 'RS256', use: 'sig' };
    const token = await new SignJWT({ sub: 'subject.example.com' })
      .setProtectedHeader({ alg: 'RS256', kid: 'issuer-key' })
      .setIssuer('https://issuer.example.com')
      .setAudience('rp.example.com')
      .setExpirationTime('2m')
      .sign(issuerKeys.privateKey);
    const fetch = vi.fn()
      .mockResolvedValueOnce(json(discovery))
      .mockResolvedValueOnce(json({ keys: [jwk] }));
    await expect(profile(fetch).verifyOIDCToken(token, {
      issuer: 'https://issuer.example.com',
      audience: 'rp.example.com',
      verifyDnsidSubject: false,
    })).rejects.toThrow('OIDC token missing iat');
  });

  it('rejects provider JWT future iat, invalid nbf, and exp before iat', async () => {
    const issuerKeys = await generateKeyPair('RS256');
    const jwk = { ...await exportJWK(issuerKeys.publicKey), kid: 'issuer-key', alg: 'RS256', use: 'sig' };
    const now = Math.floor(Date.now() / 1000);
    const cases = [
      {
        token: new SignJWT({ sub: 'subject.example.com' })
          .setProtectedHeader({ alg: 'RS256', kid: 'issuer-key' })
          .setIssuer('https://issuer.example.com')
          .setAudience('rp.example.com')
          .setIssuedAt(now + 3600)
          .setExpirationTime(now + 7200)
          .sign(issuerKeys.privateKey),
        error: 'OIDC token not yet valid',
      },
      {
        token: signRawJWT({ iss: 'https://issuer.example.com', aud: 'rp.example.com', sub: 'subject.example.com', iat: now, exp: now + 120, nbf: 'nope' }, issuerKeys.privateKey),
        error: 'OIDC token invalid nbf',
      },
      {
        token: new SignJWT({ sub: 'subject.example.com' })
          .setProtectedHeader({ alg: 'RS256', kid: 'issuer-key' })
          .setIssuer('https://issuer.example.com')
          .setAudience('rp.example.com')
          .setIssuedAt(now)
          .setExpirationTime(now)
          .sign(issuerKeys.privateKey),
        error: 'OIDC token exp must be after iat',
      },
    ];
    for (const c of cases) {
      const token = await c.token;
      const fetch = vi.fn()
        .mockResolvedValueOnce(json(discovery))
        .mockResolvedValueOnce(json({ keys: [jwk] }));
      await expect(profile(fetch).verifyOIDCToken(token, {
        issuer: 'https://issuer.example.com',
        audience: 'rp.example.com',
        verifyDnsidSubject: false,
      })).rejects.toThrow(c.error);
    }
  });

  it('rejects null token responses cleanly', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(json(discovery))
      .mockResolvedValueOnce(json(null));
    await expect(profile(fetch).exchangeOIDCToken({
      issuer: 'https://issuer.example.com',
      audience: 'rp.example.com',
    })).rejects.toThrow(VerificationError);
  });

  it('rejects malformed JWKS responses cleanly', async () => {
    const issuerKeys = await generateKeyPair('RS256');
    const token = await new SignJWT({ sub: 'subject.example.com' })
      .setProtectedHeader({ alg: 'RS256', kid: 'issuer-key' })
      .setIssuer('https://issuer.example.com')
      .setAudience('rp.example.com')
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(issuerKeys.privateKey);

    for (const jwks of [null, { keys: { kid: 'issuer-key' } }, { keys: [null] }]) {
      const fetch = vi.fn()
        .mockResolvedValueOnce(json(discovery))
        .mockResolvedValueOnce(json(jwks));
      await expect(profile(fetch).verifyOIDCToken(token, {
        issuer: 'https://issuer.example.com',
        audience: 'rp.example.com',
        verifyDnsidSubject: false,
      })).rejects.toThrow(VerificationError);
    }
  });

  it('rejects disallowed token algorithms before key matching', async () => {
    const issuerKeys = await generateKeyPair('ES256');
    const token = await new SignJWT({ sub: 'subject.example.com' })
      .setProtectedHeader({ alg: 'ES256', kid: 'missing-key' })
      .setIssuer('https://issuer.example.com')
      .setAudience('rp.example.com')
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(issuerKeys.privateKey);
    const fetch = vi.fn()
      .mockResolvedValueOnce(json(discovery))
      .mockResolvedValueOnce(json({ keys: [] }));
    await expect(profile(fetch).verifyOIDCToken(token, {
      issuer: 'https://issuer.example.com',
      audience: 'rp.example.com',
      verifyDnsidSubject: false,
    })).rejects.toThrow('OIDC token algorithm is not allowed');
  });

  it('fails closed for unsupported configured token algorithms', async () => {
    const issuerKeys = await generateKeyPair('RS256');
    const jwk = { ...await exportJWK(issuerKeys.publicKey), kid: 'issuer-key', alg: 'RS256', use: 'sig' };
    const token = await new SignJWT({ sub: 'subject.example.com' })
      .setProtectedHeader({ alg: 'RS256', kid: 'issuer-key' })
      .setIssuer('https://issuer.example.com')
      .setAudience('rp.example.com')
      .setExpirationTime('2m')
      .sign(issuerKeys.privateKey);
    const fetch = vi.fn()
      .mockResolvedValueOnce(json(discovery))
      .mockResolvedValueOnce(json({ keys: [jwk] }));
    await expect(profile(fetch, { allowedTokenAlgorithms: ['RS256', 'NOPE'] }).verifyOIDCToken(token, {
      issuer: 'https://issuer.example.com',
      audience: 'rp.example.com',
      verifyDnsidSubject: false,
    })).rejects.toThrow('unsupported OIDC token algorithm');
  });

  it('wraps provider JWT verification failures', async () => {
    const goodKeys = await generateKeyPair('RS256');
    const badKeys = await generateKeyPair('RS256');
    const jwk = { ...await exportJWK(goodKeys.publicKey), kid: 'issuer-key', alg: 'RS256', use: 'sig' };
    const token = await new SignJWT({ sub: 'subject.example.com' })
      .setProtectedHeader({ alg: 'RS256', kid: 'issuer-key' })
      .setIssuer('https://issuer.example.com')
      .setAudience('rp.example.com')
      .setExpirationTime('2m')
      .sign(badKeys.privateKey);
    const fetch = vi.fn()
      .mockResolvedValueOnce(json(discovery))
      .mockResolvedValueOnce(json({ keys: [jwk] }));
    await expect(profile(fetch).verifyOIDCToken(token, {
      issuer: 'https://issuer.example.com',
      audience: 'rp.example.com',
      verifyDnsidSubject: false,
    })).rejects.toThrow(VerificationError);
  });
});
