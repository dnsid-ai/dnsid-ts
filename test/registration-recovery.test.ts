import { expect, it, vi } from 'vitest';
import { RegistrationError, RegistryClient } from '@identity-digital/dnsid-registry';

const domain = 'assigned.example.com';
const idempotencyKey = 'persisted-registration-1';
const methods = ['registerAgent', 'registerManagedAgent', 'registerSelfManagedAgent', 'registerInZone'] as const;

it.each(methods)('%s rejects invalid replay keys before fetch', async method => {
  const fetchMock = vi.fn();
  const registry = new RegistryClient({ fetch: fetchMock });
  for (const key of [undefined, null, 123, '', ' ', ' padded', 'a\nb', 'a\u0000b', 'x'.repeat(201), 'é'.repeat(101)]) {
    await expect(registry[method]({
      idempotencyKey: key,
      ...(method === 'registerSelfManagedAgent' ? { domain, environment: 'production' } : {}),
      ...(method === 'registerInZone' ? { zoneId: 'zone-1' } : {}),
    } as never)).rejects.toThrow('idempotencyKey');
  }
  expect(fetchMock).not.toHaveBeenCalled();
});

it.each(['lost POST response', 'invalid POST body', 'GET network error', 'GET 503', 'GET 404', 'invalid GET body'])('recovers with the same request after %s', async failure => {
  let fail = true;
  const posts: { key: string | null; body: string }[] = [];
  const networkError = new Error('connection lost');
  const fetchMock = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
    if (init?.method === 'POST') {
      posts.push({ key: new Headers(init.headers).get('Idempotency-Key'), body: String(init.body) });
      if (fail && failure === 'lost POST response') throw networkError;
      return new Response(fail && failure === 'invalid POST body' ? '{' : JSON.stringify({ domain }), { status: 201 });
    }
    if (fail) {
      if (failure === 'GET network error') throw networkError;
      if (failure === 'GET 503') return new Response('unavailable', { status: 503 });
      if (failure === 'GET 404') return new Response(null, { status: 404 });
      if (failure === 'invalid GET body') return new Response('{}');
    }
    return new Response(JSON.stringify({ id: 'agent-1', domain, status: 'PENDING', managed: 'dnsid' }));
  });
  const registry = new RegistryClient({ fetch: fetchMock });
  const input = { name: 'My agent', idempotencyKey };
  const error = await registry.registerManagedAgent(input).catch(error => error);
  expect(error).toBeInstanceOf(RegistrationError);
  expect(error.idempotencyKey).toBe(idempotencyKey);
  expect(error.domain).toBe(failure.startsWith('GET') || failure === 'invalid GET body' ? domain : undefined);
  expect(error.cause).toBeInstanceOf(Error);
  if (failure === 'lost POST response' || failure === 'GET network error') expect(error.cause).toBe(networkError);
  expect(posts).toHaveLength(1); // No automatic replay.
  fail = false;
  if (error.domain) {
    await expect(registry.getRegistration(error.domain)).resolves.toMatchObject({ domain });
    expect(posts).toHaveLength(1);
  }
  await expect(registry.registerManagedAgent(input)).resolves.toMatchObject({ domain });
  expect(posts).toHaveLength(2);
  expect(posts[0].key).toBe(idempotencyKey);
  expect(posts[1]).toEqual(posts[0]);
});
