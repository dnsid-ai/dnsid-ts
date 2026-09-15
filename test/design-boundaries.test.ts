import { generateKeyPairSync, sign } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ArgumentError, DNSSECMode, DNSSECState, IdentityManager, InMemoryIdentityCache, JWKS, type DnsIdJWK, type KeyProvider, type VerifiedDomain } from '@identity-digital/dnsid-protocol';
import { JoseProfile } from '@identity-digital/dnsid-jose';
import { HttpSignaturesProfile, parseSignatureInput } from '@identity-digital/dnsid-http-signatures';
import { OIDCProfile } from '@identity-digital/dnsid-oidc';
import { currentProfileFixture } from './helpers/current-profile.ts';

const pair = generateKeyPairSync('ed25519');
const key = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'op', alg: 'EdDSA' } as DnsIdJWK;
const domain = 'agent.example.com';
const peerCert = { san: [domain], notAfter: new Date('2099-01-01') };
const provider = { signingKey: async () => key, sign: async (bytes: Uint8Array) => new Uint8Array(sign(null, bytes, pair.privateKey)) } as KeyProvider;
function compact(header: object | string, claims: object | string): string {
  const input = [header, claims].map(value => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url')).join('.');
  return `${input}.${sign(null, Buffer.from(input), pair.privateKey).toString('base64url')}`;
}
const header = { alg: 'EdDSA', kid: 'op', typ: 'JWT' };
const claims = (now = Date.now() / 1000) => ({ iss: domain, sub: domain, aud: domain, iat: now, exp: now + 60 });
afterEach(() => vi.restoreAllMocks());

describe('corrected JOSE boundaries', () => {
  const result = { domain, jwks: new JWKS([key]) } as VerifiedDomain;
  it('rejects malformed signed headers and claims before discovery', async () => {
    const verifyDomain = vi.fn(async () => result);
    const profile = new JoseProfile({ identityResolver: { verifyDomain }, domain });
    for (const bad of [{ ...header, crit: [] }, { ...header, b64: false }, { ...header, b64: 'true' }, { ...header, alg: 'none' }, { ...header, kid: 7 }, { ...header, typ: null }, '{"alg":"EdDSA","kid":"op","k\\u0069d":"op"}']) {
      await expect(profile.verifyJWT(compact(bad, claims()))).rejects.toBeDefined();
    }
    for (const bad of ['null', '[]', JSON.stringify(claims()).replace('"iat":', '"iat":0,"iat":'), { ...claims(), aud: [domain, 7] }, { ...claims(), aud: [] }, ...['0', null, true, Infinity].map(iat => ({ ...claims(), iat }))]) {
      await expect(profile.verifyJWT(compact(header, bad))).rejects.toBeDefined();
    }
    expect(verifyDomain).not.toHaveBeenCalled();
    await expect(profile.verifyJWS(compact({ ...header, kid: `${domain}#op`, crit: ['future'] }, 'opaque'))).rejects.toBeDefined();
    expect(verifyDomain).not.toHaveBeenCalled();
  });

  it('honors zero skew, fractional/zero NumericDates, explicit audience and exact expiration', async () => {
    let now = 0;
    vi.spyOn(Date, 'now').mockImplementation(() => now * 1000);
    const verifyDomain = vi.fn(async () => result);
    const profile = new JoseProfile({ identityResolver: { verifyDomain }, jose: { clockSkew: 0 } });
    const token = compact(header, { ...claims(0), exp: 0.75 });
    await expect(profile.verifyJWT(token)).rejects.toBeInstanceOf(ArgumentError);
    now = 0.5;
    await expect(profile.verifyJWT(token, { expectedAudience: domain, peerCert })).resolves.toBe(result);
    expect(verifyDomain).toHaveBeenCalledWith(domain, peerCert, { signal: expect.any(AbortSignal) });
    await expect(profile.verifyJWT(compact(header, { ...claims(0), nbf: 0.51 }), { expectedAudience: domain })).rejects.toThrow('not yet valid');
    await expect(profile.verifyJWT(compact(header, claims(0.51)), { expectedAudience: domain })).rejects.toThrow('future');
    now = 0.75;
    await expect(profile.verifyJWT(token, { expectedAudience: domain })).rejects.toThrow('expired');
    now = 0.5;
    verifyDomain.mockImplementation(async () => { now = 0.75; return result; });
    await expect(profile.verifyJWT(token, { expectedAudience: domain })).rejects.toThrow('expired during');
  });

  it('rejects explicit invalid configuration and expiry, defaults only when omitted', async () => {
    for (const value of [0, -1, Infinity, NaN, null, '60']) {
      expect(() => new JoseProfile({ identityResolver: { verifyDomain: vi.fn() }, jose: { maxLifetime: value as number } })).toThrow(ArgumentError);
      expect(() => new OIDCProfile({ domain, oidc: { maxAssertionLifetime: value as number } })).toThrow(ArgumentError);
      const profile = new JoseProfile({ domain, keyProvider: provider, identityResolver: { verifyDomain: vi.fn() } });
      await expect(profile.createJWT({ audience: domain, expiry: value as number })).rejects.toThrow(ArgumentError);
    }
  });

  it('bounds discovery time and headers without accepting partial verification', async () => {
    const verifyDomain = vi.fn(() => new Promise<VerifiedDomain>(() => {}));
    const profile = new JoseProfile({ domain, identityResolver: { verifyDomain } });
    await expect(profile.verifyJWT(compact(header, claims()), { timeoutMs: 5 })).rejects.toThrow('deadline');
    expect(verifyDomain.mock.calls).toHaveLength(1);
    expect(() => parseSignatureInput('a'.repeat(16385))).toThrow('16 KiB');
    await expect(profile.verifyJWS('a'.repeat(1024 * 1024 + 1))).rejects.toThrow('malformed');
  });
});

describe('absolute identity evidence and manager-private contexts', () => {
  it('isolates shared backends across DNSSEC and log trust contexts', async () => {
    const fixture = await currentProfileFixture(domain, key);
    const cache = new InMemoryIdentityCache();
    const fetchTXT = vi.fn(async () => [[{ strings: [fixture.record.serialize()], ttl: 30 }], DNSSECState.UNKNOWN] as Awaited<ReturnType<typeof fixture.dnsResolver.fetchTXT>>);
    const manager = new IdentityManager({ verification: { dnssecMode: DNSSECMode.auto } }, { logRegistry: fixture.logRegistry, dnsResolver: { fetchTXT }, cache, fetchJson: fixture.fetchJson });
    await manager.verifyDomain(domain);
    const strict = new IdentityManager({ verification: { dnssecMode: DNSSECMode.required } }, { logRegistry: fixture.logRegistry, dnsResolver: { fetchTXT }, cache, fetchJson: fixture.fetchJson });
    await expect(strict.verifyDomain(domain)).rejects.toMatchObject({ code: 'DNSSECFailed' });
    const untrusted = new IdentityManager({}, { dnsResolver: { fetchTXT }, cache, fetchJson: fixture.fetchJson });
    await expect(untrusted.verifyDomain(domain)).rejects.toMatchObject({ code: 'LogError' });
    expect(fetchTXT).toHaveBeenCalledTimes(3);
  });

  it('does not restart DNS TTL after slow verification or cache status refresh', async () => {
    let now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const fixture = await currentProfileFixture(domain, key);
    const fetchTXT = vi.fn(async () => [[{ strings: [fixture.record.serialize()], ttl: 30 }], DNSSECState.UNKNOWN] as Awaited<ReturnType<typeof fixture.dnsResolver.fetchTXT>>);
    let delayStatus = false;
    const fetchJson: typeof fixture.fetchJson = async (url, options) => {
      const response = await fixture.fetchJson(url, options);
      if (delayStatus && url === fixture.record.su) now += 35000;
      return response;
    };
    const manager = new IdentityManager({}, { logRegistry: fixture.logRegistry, dnsResolver: { fetchTXT }, fetchJson });
    const first = await manager.verifyDomain(domain);
    expect(first.dnsExpiresAt.getTime()).toBe(now + 30000);
    delayStatus = true;
    await expect(manager.verifyDomain(domain)).rejects.toMatchObject({ code: 'DNSResolution', transient: true });
    await expect(manager.verifyDomain(domain)).rejects.toMatchObject({ code: 'DNSResolution' });
    expect(fetchTXT).toHaveBeenCalledTimes(2);
  });

  it('never reuses zero-TTL answers and still rechecks TLS at completion', async () => {
    let now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const fixture = await currentProfileFixture(domain, key);
    const fetchTXT = vi.fn(async () => [[{ strings: [fixture.record.serialize()], ttl: 0 }], DNSSECState.UNKNOWN] as Awaited<ReturnType<typeof fixture.dnsResolver.fetchTXT>>);
    let expire = false;
    const manager = new IdentityManager({}, { logRegistry: fixture.logRegistry, dnsResolver: { fetchTXT }, fetchJson: async (url, options) => {
      const response = await fixture.fetchJson(url, options);
      if (expire && url === fixture.record.su) now += 2000;
      return { ...response, tlsCert: { ...response.tlsCert, notAfter: new Date(now + (expire && url === fixture.record.su ? 0 : 1000)) } };
    } });
    await Promise.all([manager.verifyDomain(domain), manager.verifyDomain(domain)]);
    await manager.verifyDomain(domain);
    expect(fetchTXT).toHaveBeenCalledTimes(3);
    expire = true;
    await expect(manager.verifyDomain(domain)).rejects.toMatchObject({ code: 'TLSError' });
  });

  it('rejects a key-age bound that expires during a zero-TTL operation', async () => {
    let now = Date.now();
    const introduced = new Date(now - 24 * 60 * 60 * 1000 + 1000);
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const fixture = await currentProfileFixture(domain, key, undefined, undefined, '24h');
    fixture.logReader.keyTimestamp = async () => introduced;
    const manager = new IdentityManager({}, { logRegistry: fixture.logRegistry, dnsResolver: {
      fetchTXT: async () => [[{ strings: [fixture.record.serialize()], ttl: 0 }], DNSSECState.UNKNOWN],
    }, fetchJson: async (url, options) => {
      const response = await fixture.fetchJson(url, options);
      if (url === fixture.record.su) now += 2000;
      return response;
    } });
    await expect(manager.verifyDomain(domain)).rejects.toMatchObject({ code: 'KeyAgeExceeded' });
  });

  it('preserves each coalesced deadline and cancels work when the last caller leaves', async () => {
    const fixture = await currentProfileFixture(domain, key);
    let finish!: () => void;
    let sharedSignal!: AbortSignal;
    const fetchTXT = vi.fn(async (_name: string, options?: { signal?: AbortSignal }) => {
      sharedSignal = options!.signal!;
      await new Promise<void>(resolve => { finish = resolve; });
      return fixture.dnsResolver.fetchTXT(_name);
    });
    const manager = new IdentityManager({}, { logRegistry: fixture.logRegistry, dnsResolver: { fetchTXT }, fetchJson: fixture.fetchJson });
    const canceled = new AbortController();
    const first = manager.verifyDomain(domain, undefined, { signal: canceled.signal });
    const second = manager.verifyDomain(domain);
    canceled.abort();
    await expect(first).rejects.toThrow('canceled');
    expect(sharedSignal.aborted).toBe(false);
    finish();
    await expect(second).resolves.toMatchObject({ domain });
    expect(fetchTXT).toHaveBeenCalledTimes(1);
    manager.evictDomain(domain);
    await expect(manager.verifyDomain(domain, undefined, { timeoutMs: 5 })).rejects.toThrow('deadline');
    expect(sharedSignal.aborted).toBe(true);
  });

  it('passes current peer evidence through JWT, JWS and HTTP, including cached identities', async () => {
    const fixture = await currentProfileFixture(domain, key, 'mtls');
    const manager = new IdentityManager({ verification: { statusCheckInterval: 60 } }, { logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson: fixture.fetchJson });
    const jose = new JoseProfile({ domain, keyProvider: provider, identityResolver: manager });
    const jwt = await jose.createJWT({ audience: domain });
    const jws = await jose.createJWS(new Uint8Array([1]));
    const http = new HttpSignaturesProfile({ domain, keyProvider: provider, identityResolver: manager });
    const request = await http.createSignedHttpRequest(new Request(`https://${domain}`));
    for (const verify of [() => jose.verifyJWT(jwt, { peerCert }), () => jose.verifyJWS(jws, { peerCert }), () => http.verifySignedHttpRequest(request, { peerCert })]) await expect(verify()).resolves.toBeDefined();
    for (const verify of [() => jose.verifyJWT(jwt), () => jose.verifyJWS(jws), () => http.verifySignedHttpRequest(request)]) await expect(verify()).rejects.toMatchObject({ code: 'TLSError' });
  });
});
