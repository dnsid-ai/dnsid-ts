import { expect, it, vi } from 'vitest';
import { RegistrationError, RegistryClient } from '@dnsid-ai/registry';
import type { AgentRegistrationInput } from '@dnsid-ai/registry';
import { creation } from './helpers/registration.ts';

const domain = 'assigned.example.com';
const publicKeyJwk = { kid: 'key-1', kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };

it.each([
  [{ publicKeyJwk }, { public_key: publicKeyJwk }],
  [{ domain: 'ASSIGNED.EXAMPLE.COM.' }, { domain }],
  [{ rootDomain: 'EXAMPLE.COM.', publicKeyJwk }, { root_domain: 'example.com', public_key: publicKeyJwk }],
  [{ governanceDomain: 'EXAMPLE.COM.', publicKeyJwk }, { governance_domain: 'example.com', public_key: publicKeyJwk }],
  [{ rootDomain: 'example.com', governanceDomain: 'example.com', publicKeyJwk }, { root_domain: 'example.com', governance_domain: 'example.com', public_key: publicKeyJwk }],
])('serializes unified selectors without legacy defaults: %j', async (input, wire) => {
  const snapshot = { ...creation(domain), oidc_issuer_url: 'https://issuer.example.com' };
  const fetchMock = vi.fn(async (_url, init) => {
    expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer owner');
    if (init?.method === 'POST') {
      expect(JSON.parse(String(init.body))).toEqual(wire);
      expect(new Headers(init.headers).has('Idempotency-Key')).toBe(false);
      return Response.json(snapshot, { status: 201 });
    }
    // Hosting and later defaults must not override the creation snapshot.
    return Response.json({ id: snapshot.id, domain, managed: 'dnsid', status: 'PENDING', publication_config: { ...snapshot.publication_config, max_key_age: '90d' } });
  });
  const result = await new RegistryClient({ token: 'owner', fetch: fetchMock }).registerAgent(input);
  expect(result.publicationAuthority).toBe('registry');
  expect(result.publicationConfig?.maxKeyAge).toBeUndefined();
  expect(result.publicationConfig?.capabilitiesUrl).toBeUndefined();
  expect(result.oidcIssuerUrl).toBe(snapshot.oidc_issuer_url);
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it.each([
  { domain, rootDomain: 'example.com' },
  { rootDomain: 'bad/domain', publicKeyJwk },
  { governanceDomain: 'https://example.com', publicKeyJwk },
  { publicKeyJwk, capabilitiesUrl: 'http://example.com' },
  { publicKeyJwk, capabilitiesUrl: 'https://user:pass@example.com' },
  { publicKeyJwk: { ...publicKeyJwk, d: 'private' } },
  { publicKeyJwk: { ...publicKeyJwk, keys: [{ ...publicKeyJwk, d: 'private' }] } },
  { rootDomain: 'example.com' },
  { publicKeyJwk, name: 'x'.repeat(256) },
])('rejects invalid input before fetch: %j', async input => {
  const fetchMock = vi.fn();
  await expect(new RegistryClient({ fetch: fetchMock }).registerAgent(input as AgentRegistrationInput)).rejects.toThrow();
  expect(fetchMock).not.toHaveBeenCalled();
});

it.each([
  { domain: 'example.com' },
  { domain: 'assigned.badexample.com' },
  { id: undefined },
  { publication_config: undefined },
  { publication_config: { ...creation(domain).publication_config, publish_profile: 'unknown' } },
  { publication_config: { ...creation(domain).publication_config, governance_id: 'other.com' } },
  { publication_config: { ...creation(domain).publication_config, ku_url: 'https://other.com/jwks' } },
  { publication_config: { ...creation(domain).publication_config, ek_url: 'https://other.com/entity.jwks' } },
  { publication_config: { ...creation(domain).publication_config, status_url: 'http://example.com' } },
  { publication_config: { ...creation(domain).publication_config, log_ref: 'invalid' } },
  { publication_config: { ...creation(domain).publication_config, max_key_age: '' } },
  { publication_config: { ...creation(domain).publication_config, capabilities_url: 123 } },
])('retains creation facts on invalid response: %j', async changes => {
  const snapshot = { ...creation(domain), oidc_issuer_url: 'https://issuer.example.com', ...changes };
  const fetchMock = vi.fn(async () => Response.json(snapshot, { status: 201 }));
  const input = { publicKeyJwk, rootDomain: 'example.com', governanceDomain: 'example.com' };
  const error = await new RegistryClient({ fetch: fetchMock }).registerAgent(input, 'persisted-key').catch(e => e);
  expect(error).toBeInstanceOf(RegistrationError);
  expect(error).toMatchObject({ idempotencyKey: 'persisted-key', input, creation: JSON.parse(JSON.stringify(snapshot)), httpStatus: 201 });
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

it.each([
  [409, 'AMBIGUOUS_ROOT'], [400, 'BAD_REQUEST'], [403, 'GOVERNANCE_NOT_AUTHORIZED'],
  [503, 'SERVICE_UNAVAILABLE'], [409, 'MANAGED_GOVERNANCE_UNAVAILABLE'], [422, 'IDEMPOTENCY_MISMATCH'],
])('preserves HTTP %i %s without fallback or replay', async (status, code) => {
  const fetchMock = vi.fn(async () => Response.json({ error: code, message: 'rejected' }, { status }));
  const input = { publicKeyJwk, rootDomain: 'example.com', environment: 'sandbox' as const, managed: true };
  const error = await new RegistryClient({ fetch: fetchMock }).registerAgent(input, 'original-key').catch(e => e);
  expect(error).toMatchObject({ httpStatus: status, code, input, idempotencyKey: 'original-key' });
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

it.each(['unknown authority', 'detail identity mismatch', 'unauthorized', 'timeout'])('keeps the creation snapshot after %s', async failure => {
  const snapshot = { ...creation(domain), oidc_issuer_url: 'https://issuer.example.com' };
  const fetchMock = vi.fn(async (_url, init) => {
    if (init?.method === 'POST') return Response.json(snapshot, { status: 201 });
    if (failure === 'timeout') throw new Error('timeout');
    if (failure === 'unauthorized') return Response.json({ error: 'UNAUTHORIZED' }, { status: 401 });
    return Response.json({ id: failure === 'detail identity mismatch' ? 'other' : snapshot.id, domain, managed: failure === 'unknown authority' ? 'unknown' : 'self', status: 'PENDING' });
  });
  const error = await new RegistryClient({ fetch: fetchMock }).registerAgent({ publicKeyJwk }, 'original-key').catch(e => e);
  expect(error).toMatchObject({ creation: snapshot, domain, idempotencyKey: 'original-key' });
  if (failure === 'unauthorized') expect(error).toMatchObject({ httpStatus: 401, code: 'UNAUTHORIZED' });
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it('does not retry an unknown outcome without an idempotency key', async () => {
  const fetchMock = vi.fn(async () => { throw new Error('timeout'); });
  const error = await new RegistryClient({ fetch: fetchMock }).registerAgent({ publicKeyJwk }).catch(e => e);
  expect(error).toBeInstanceOf(RegistrationError);
  expect(error.idempotencyKey).toBeUndefined();
  expect(error.input).toEqual({ publicKeyJwk });
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

it('rejects an exact-domain response mismatch without reading detail', async () => {
  const fetchMock = vi.fn(async () => Response.json(creation('other.example.com'), { status: 201 }));
  await expect(new RegistryClient({ fetch: fetchMock }).registerAgent({ domain })).rejects.toThrow('requested domain/rootDomain');
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

it('retains the original key and complete request on replay after governance changes', async () => {
  let replay = false;
  const posts: { body: string; key: string | null }[] = [];
  const fetchMock = vi.fn(async (_url, init) => {
    if (init?.method === 'POST') {
      posts.push({ body: String(init.body), key: new Headers(init.headers).get('Idempotency-Key') });
      if (replay) return Response.json({ error: 'MANAGED_GOVERNANCE_UNAVAILABLE' }, { status: 409 });
      return Response.json(creation(domain), { status: 201 });
    }
    return Response.json({ id: 'agent-1', domain, managed: 'dnsid', status: 'PENDING' });
  });
  const client = new RegistryClient({ fetch: fetchMock });
  const input = { publicKeyJwk, rootDomain: 'example.com', governanceDomain: 'example.com', environment: 'production' as const, managed: true, idempotencyKey: 'saved-key' };
  const saved = await client.registerAgent(input);
  const savedConfig = structuredClone(saved.publicationConfig);
  replay = true;
  const error = await client.registerAgent(input).catch(e => e);
  expect(error).toMatchObject({ httpStatus: 409, code: 'MANAGED_GOVERNANCE_UNAVAILABLE', input, idempotencyKey: 'saved-key' });
  expect(posts).toHaveLength(2);
  expect(posts[1]).toEqual(posts[0]);
  expect(saved).toMatchObject({ id: 'agent-1', domain, publicationConfig: savedConfig });
});

it.each(['domain', 'zoneId', 'rootDomain', 'governanceDomain', 'managed', 'tier'])('rejects a Live %s override before fetch', async field => {
  const fetchMock = vi.fn();
  await expect(new RegistryClient({ fetch: fetchMock }).registerLiveAgent({ publicKeyJwk, [field]: 'override' }, 'live-key')).rejects.toThrow('forbids');
  expect(fetchMock).not.toHaveBeenCalled();
});
