import { EventEmitter } from 'node:events';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type * as https from 'node:https';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createSsrfSafeFetch, fetchJson, isUnsafeIp } from '@dnsid-ai/transport';
import { VerificationCode, VerificationError } from '@dnsid-ai/protocol';

const httpsGetMock = vi.hoisted(() => vi.fn());

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

  it('keeps link-local destinations blocked under hostname-scoped testnet exceptions', async () => {
    const safeFetch = createSsrfSafeFetch({}, { allowedUnsafeHosts: ['169.254.169.254'] });
    const err = await safeFetch('https://169.254.169.254/latest/meta-data').catch(e => e);
    expect(err).toBeInstanceOf(VerificationError);
    expect((err as VerificationError).transient).toBe(false);
    expect((err as Error).message).toContain('unsafe target IP address');
  });

  // `localhost` resolves to loopback through the system resolver, which is the
  // testnet case: a real hostname whose address is private.
  it('lets an allowed host resolve to loopback, and no other host', async () => {
    mockHttpsStatus(403);
    const lookupFor = async (allowedUnsafeHosts?: string[]) => {
      httpsGetMock.mockClear();
      await fetchJson('https://agent.example/.well-known/jwks.json', { allowedUnsafeHosts }).catch(() => undefined);
      const [, requestOptions] = httpsGetMock.mock.calls[0] as [string, https.RequestOptions];
      return requestOptions.lookup!;
    };
    const resolve = (lookup: NonNullable<https.RequestOptions['lookup']>, host: string) =>
      new Promise<string>((res, rej) => lookup(host, { family: 4 }, (err, address) => (err ? rej(err) : res(address as string))));

    await expect(resolve(await lookupFor(['localhost']), 'localhost')).resolves.toBe('127.0.0.1');
    await expect(resolve(await lookupFor(), 'localhost')).rejects.toThrow('unsafe resolved IP address');
  });

  it('rejects a malformed allowedUnsafeHosts entry before connecting', async () => {
    const err = await fetchJson('https://agent.example/.well-known/jwks.json', {
      allowedUnsafeHosts: ['agent.example:8443'],
    }).catch(e => e);
    expect(err).toBeInstanceOf(TypeError);
    expect(httpsGetMock).not.toHaveBeenCalled();
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
    const err = await fetchJson('https://notexample.com/jwks.json', {
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
