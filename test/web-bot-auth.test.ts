import { beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import {
  WEB_BOT_AUTH_TAG,
  HTTP_MESSAGE_SIGNATURES_DIRECTORY_MEDIA_TYPE,
  HTTP_MESSAGE_SIGNATURES_DIRECTORY_TAG,
  WebBotAuthProfile,
  wbaDirectoryJwkFromPublicKey,
} from '@dnsid-ai/web-bot-auth';
import { parseSignatureInput } from '@dnsid-ai/http-signatures';
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
