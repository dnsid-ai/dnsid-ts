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
    ]) {
      expect(isUnsafeIp(ip), ip).toBe(true);
    }

    expect(isUnsafeIp('8.8.8.8')).toBe(false);
    expect(isUnsafeIp('::8.8.8.8')).toBe(false);
    expect(isUnsafeIp('2001:4860:4860::8888')).toBe(false);
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
