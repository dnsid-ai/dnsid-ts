import { EventEmitter } from 'node:events';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type * as https from 'node:https';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createSsrfSafeFetch, fetchJson, isUnsafeIp } from '@dnsid-ai/transport';
import { ArgumentError, VerificationCode, VerificationError } from '@dnsid-ai/protocol';

const httpsGetMock = vi.hoisted(() => vi.fn());
const dnsLookupMock = vi.hoisted(() => vi.fn());
vi.mock('node:dns/promises', async importOriginal => ({
  ...await importOriginal<typeof import('node:dns/promises')>(),
  lookup: dnsLookupMock,
}));

vi.mock('node:https', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:https')>();
  return {
    ...actual,
    get: httpsGetMock,
  };
});

describe('transport SSRF protections', () => {
  afterEach(() => {
    httpsGetMock.mockReset();
  });

  it('classifies unsafe IP ranges', () => {
    for (const ip of [
      '127.0.0.1',
      '10.0.0.1',
      '172.16.0.1',
      '192.168.0.1',
      '169.254.169.254',
      '100.64.0.1',
      '224.0.0.1',
      '[::1]',
      'fc00::1',
      'fe80::1',
      'ff02::1',
      '::ffff:127.0.0.1',
      '[::127.0.0.1]',
      '::10.0.0.1',
      '::169.254.169.254',
      '64:ff9b::7f00:1', // NAT64 + 127.0.0.1
      '64:ff9b::a00:5', // NAT64 + 10.0.0.5
      '64:ff9b::169.254.169.254', // NAT64 + cloud metadata
      '64:ff9b::6440:1', // NAT64 + 100.64.0.1 (CGNAT)
      '64:ff9b::1', // NAT64 + 0.0.0.1
      '64:ff9b:1::808:808', // RFC 8215 local-use NAT64 prefix
      '64:ff9b::1:808:808', // outside the /96: not a NAT64 address
    ]) {
      expect(isUnsafeIp(ip), ip).toBe(true);
    }

    expect(isUnsafeIp('8.8.8.8')).toBe(false);
    expect(isUnsafeIp('::8.8.8.8')).toBe(false);
    expect(isUnsafeIp('2001:4860:4860::8888')).toBe(false);
    expect(isUnsafeIp('64:ff9b::808:808')).toBe(false); // NAT64 + 8.8.8.8 (DNS64 network)
    expect(isUnsafeIp('[64:ff9b::8.8.8.8]')).toBe(false);
  });

  it('sends a stable SDK User-Agent when fetching JSON', async () => {
    mockHttpsStatus(403);

    const err = await fetchJson('https://agent.example/.well-known/jwks.json').catch(e => e);

    expect(err).toBeInstanceOf(VerificationError);
    expect(httpsGetMock).toHaveBeenCalledOnce();
    const [, requestOptions] = httpsGetMock.mock.calls[0] as [string, https.RequestOptions, (res: IncomingMessage) => void];
    expect(requestOptions.headers).toMatchObject({
      'User-Agent': 'dnsid-ts',
    });
  });

  it('sends upstream revalidation on explicit evidence refresh', async () => {
    mockHttpsStatus(403);
    await fetchJson('https://agent.example/keys', { revalidate: true }).catch(() => {});
    expect(httpsGetMock.mock.calls[0]![1].headers).toMatchObject({ 'Cache-Control': 'no-cache' });
  });

  it('blocks direct private HTTPS targets before connecting', async () => {
    const err = await fetchJson('https://127.0.0.1/.well-known/jwks.json').catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).code).toBe(VerificationCode.TLSError);
    expect((err as Error).message).toContain('unsafe HTTPS target IP address');

    const safeFetchError = await createSsrfSafeFetch()('https://127.0.0.1/resource').catch(e => e);
    expect(safeFetchError).toBeInstanceOf(VerificationError);
    expect((safeFetchError as VerificationError).code).toBe(VerificationCode.TLSError);
    expect((safeFetchError as Error).message).toContain('unsafe target IP address');
  });

  it('never exempts IP-literal URLs, whatever the list says', async () => {
    for (const hosts of [['localhost'], ['.test']]) {
      const safeFetch = createSsrfSafeFetch({}, { privateAddressHosts: hosts });
      for (const url of ['https://169.254.169.254/latest/meta-data', 'https://127.0.0.1/resource']) {
        const err = await safeFetch(url).catch(e => e);
        expect(err, url).toBeInstanceOf(VerificationError);
        expect((err as VerificationError).transient).toBe(false);
        expect((err as Error).message).toContain('unsafe target IP address');
      }
    }
  });

  // Exercises the lookup fetchJson hands to https.get, with DNS answers controlled per case.
  describe('privateAddressHosts matching', () => {
    const lookupFor = async (privateAddressHosts?: string[]) => {
      mockHttpsStatus(403);
      httpsGetMock.mockClear();
      await fetchJson('https://agent.example/.well-known/jwks.json', { privateAddressHosts }).catch(() => undefined);
      const [, requestOptions] = httpsGetMock.mock.calls[0] as [string, https.RequestOptions];
      return requestOptions.lookup!;
    };
    const resolve = (lookup: NonNullable<https.RequestOptions['lookup']>, host: string, answers = ['127.0.0.1']) => {
      dnsLookupMock.mockResolvedValue(answers.map(address => ({ address, family: 4 })));
      return new Promise<string>((res, rej) => lookup(host, { family: 4 }, (err, address) => (err ? rej(err) : res(address as string))));
    };

    it('rejects .test names with no configuration', async () => {
      const lookup = await lookupFor();
      await expect(resolve(lookup, 'alice.dev.dnsid.test')).rejects.toThrow('unsafe resolved IP address');
      await expect(resolve(lookup, 'localhost')).rejects.toThrow('unsafe resolved IP address');
    });

    it('matches a suffix entry on DNS-label boundaries, case-insensitively, ignoring a trailing dot', async () => {
      const lookup = await lookupFor(['.Test']);
      await expect(resolve(lookup, 'test')).resolves.toBe('127.0.0.1');
      await expect(resolve(lookup, 'alice.dev.dnsid.test')).resolves.toBe('127.0.0.1');
      await expect(resolve(lookup, 'Registry.DNSID.TEST.')).resolves.toBe('127.0.0.1');
      await expect(resolve(lookup, 'evil-test')).rejects.toThrow('unsafe resolved IP address');
      await expect(resolve(lookup, 'a.test.example')).rejects.toThrow('unsafe resolved IP address');
      await expect(resolve(lookup, 'a.testing')).rejects.toThrow('unsafe resolved IP address');
    });

    it('matches an exact entry only, not its subdomains', async () => {
      const lookup = await lookupFor(['agent.example']);
      await expect(resolve(lookup, 'agent.example')).resolves.toBe('127.0.0.1');
      await expect(resolve(lookup, 'sub.agent.example')).rejects.toThrow('unsafe resolved IP address');
    });

    it('accepts only private-or-loopback answers for a matching host', async () => {
      const lookup = await lookupFor(['.test']);
      await expect(resolve(lookup, 'a.test', ['10.0.0.5'])).resolves.toBe('10.0.0.5');
      await expect(resolve(lookup, 'a.test', ['169.254.169.254'])).rejects.toThrow('unsafe resolved IP address');
      await expect(resolve(lookup, 'a.test', ['8.8.8.8', '127.0.0.1'])).rejects.toThrow('unsafe resolved IP address');
      // A NAT64-wrapped private address never counts as private for the list.
      await expect(resolve(lookup, 'a.test', ['64:ff9b::a00:5'])).rejects.toThrow('unsafe resolved IP address');
    });

    it('rejects malformed entries with ArgumentError before connecting', async () => {
      for (const entry of ['', '.', 'agent.example:8443', 'https://agent.example', 'agent.example/path', 'user@agent.example', '127.0.0.1', '.127.0.0.1', '[::1]', '..test']) {
        const err = await fetchJson('https://agent.example/.well-known/jwks.json', { privateAddressHosts: [entry] }).catch(e => e);
        expect(err, JSON.stringify(entry)).toBeInstanceOf(ArgumentError);
        expect(() => createSsrfSafeFetch({}, { privateAddressHosts: [entry] }), JSON.stringify(entry)).toThrow(ArgumentError);
      }
      expect(httpsGetMock).not.toHaveBeenCalled();
    });
  });

  it('rejects initial URLs that do not match allowedHost', async () => {
    const err = await fetchJson('https://evil.example/.well-known/jwks.json', { allowedHost: 'agent.example' }).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as Error).message).toContain('URL host not permitted');
  });

  it('allows only DNS-label subdomains when domainBoundary is enabled', async () => {
    mockHttpsStatus(403);
    await fetchJson('https://keys.example.com/jwks.json', {
      allowedHost: 'example.com', domainBoundary: true,
    }).catch(() => undefined);
    expect(httpsGetMock).toHaveBeenCalledOnce();

    httpsGetMock.mockClear();
    const err = await fetchJson('https://notexample.test/jwks.json', {
      allowedHost: 'example.com', domainBoundary: true,
    }).catch(e => e);
    expect((err as Error).message).toContain('URL host not permitted');
    expect(httpsGetMock).not.toHaveBeenCalled();
  });
});

function mockHttpsStatus(statusCode: number): void {
  httpsGetMock.mockImplementation((_url: string, _options: https.RequestOptions, callback: (res: IncomingMessage) => void): ClientRequest => {
    const req = new EventEmitter() as ClientRequest;
    req.setTimeout = vi.fn(() => req) as unknown as ClientRequest['setTimeout'];
    req.destroy = vi.fn(() => req) as unknown as ClientRequest['destroy'];

    queueMicrotask(() => {
      const res = new EventEmitter() as IncomingMessage;
      res.statusCode = statusCode;
      res.headers = {};
      res.resume = vi.fn(() => res) as unknown as IncomingMessage['resume'];
      callback(res);
    });

    return req;
  });
}

// Hosts are compared in normalizeFQDN form on both sides (the initial URL, every
// redirect hop, and allowedHost itself), matching the other DNSid SDKs. U+0130
// is the probe: a simple case fold maps it to ASCII "i", but UTS 46 punycode-
// encodes the label into a different registrable domain, which must never pass
// the boundary. IP literals match only an allowedHost spelled exactly as the URL
// parser serializes them, and never on a domain boundary.
describe('transport allowedHost canonical comparison', () => {
  afterEach(() => {
    httpsGetMock.mockReset();
  });

  async function permitted(url: string, allowedHost: string, domainBoundary: boolean): Promise<boolean> {
    httpsGetMock.mockReset();
    mockHttpsStatus(403);
    const err = await fetchJson(url, { allowedHost, domainBoundary }).catch(e => e);
    if ((err as Error).message.includes('URL host not permitted')) {
      expect(httpsGetMock).not.toHaveBeenCalled();
      return false;
    }
    expect(httpsGetMock).toHaveBeenCalledOnce();
    return true;
  }

  it.each([
    ['https://keys.example.com/j', 'example.com', true, true],
    ['https://keys.example.com/j', 'example.com', false, false],
    ['https://KEYS.Example.COM/j', 'example.com', true, true],
    ['https://keys.example.com/j', 'Example.COM', true, true],
    ['https://xn--mnchen-3ya.de/j', 'münchen.de', false, true],
    ['https://münchen.de/j', 'xn--mnchen-3ya.de', false, true],
    ['https://keys.example.com./j', 'example.com', true, false],
    ['https://keys.example.com/j', 'example.com.', true, false],
    ['https://agent.example.com./j', 'agent.example.com.', false, true],
    ['https://keys.example.com./j', 'example.com.', true, true],
    ['https://keys.bİgcorp.com/j', 'bigcorp.com', true, false],
    ['https://keys.b%C4%B0gcorp.com/j', 'keys.bigcorp.com', false, false],
    ['https://example.com.attacker.test/j', 'example.com', true, false],
    ['https://EXAMPLE.COM.attacker.test/j', 'example.com', true, false],
    ['https://8.8.8.8/j', '8.8.8.8', false, true],
    ['https://8.8.8.8/j', '8.8.8.8', true, true],
    ['https://[2001:4860:4860::8888]/j', '[2001:4860:4860::8888]', false, true],
    ['https://[2001:4860:4860:0::8888]/j', '[2001:4860:4860::8888]', false, true],
    ['https://[2001:4860:4860::8888]/j', '2001:4860:4860::8888', false, false],
    ['https://[::ffff:808:808]/j', '8.8.8.8', false, false],
    ['https://8.8.8.8/j', '8.8.4.4', true, false],
    ['https://4.3.2.1/j', '3.2.1', true, false],
    ['https://keys.example.com/j', '8.8.8.8', true, false],
    ['https://-keys.example.com/j', 'example.com', true, false],
    [`https://${'a'.repeat(64)}.example.com/j`, 'example.com', true, false],
  ])('fetchJson(%s, allowedHost=%s, domainBoundary=%s) permitted=%s', async (url, allowedHost, domainBoundary, want) => {
    expect(await permitted(url, allowedHost, domainBoundary)).toBe(want);
  });

  it.each([
    ['https://keys.bigcorp.com/ek.json', true],
    ['https://KEYS.BigCorp.COM/ek.json', true],
    ['https://keys.bigcorp.com./ek.json', false],
    ['https://keys.b%C4%B0gcorp.com/ek.json', false],
    ['https://keys.bİgcorp.com/ek.json', false],
    ['https://bigcorp.com.attacker.example/ek.json', false],
    ['https://notbigcorp.com/ek.json', false],
  ])('redirect to %s permitted=%s', async (location, want) => {
    let calls = 0;
    httpsGetMock.mockImplementation((_url: string, _options: https.RequestOptions, callback: (res: IncomingMessage) => void): ClientRequest => {
      const req = new EventEmitter() as ClientRequest;
      req.setTimeout = vi.fn(() => req) as unknown as ClientRequest['setTimeout'];
      req.destroy = vi.fn(() => req) as unknown as ClientRequest['destroy'];
      const first = calls++ === 0;
      queueMicrotask(() => {
        const res = new EventEmitter() as IncomingMessage;
        res.statusCode = first ? 302 : 403;
        res.headers = first ? { location } : {};
        res.resume = vi.fn(() => res) as unknown as IncomingMessage['resume'];
        callback(res);
      });
      return req;
    });
    const err = await fetchJson('https://www.bigcorp.com/go', { allowedHost: 'bigcorp.com', domainBoundary: true }).catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    if (want) {
      expect((err as Error).message).toContain('unexpected HTTP status 403');
      expect(httpsGetMock).toHaveBeenCalledTimes(2);
    } else {
      expect((err as Error).message).toContain('redirect changes host');
      expect(httpsGetMock).toHaveBeenCalledOnce();
    }
  });
});
