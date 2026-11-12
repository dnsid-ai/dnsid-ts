import { afterEach, describe, expect, it, vi } from 'vitest';
import { create, SigningPaused } from '@dnsid-ai/foundry';
import { RegistryClient } from '@dnsid-ai/registry';
import { DOMAIN, ORG, GI, foundryFixture, publication } from './helpers/foundry.ts';
import { withTemp } from './helpers/cli-directory.ts';

const wirePublication = Object.fromEntries(Object.entries(publication).map(([name, value]) => [name.replace(/[A-Z]/g, char => '_' + char.toLowerCase()), value]));

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

describe('Foundry registry adapters', () => {
  it.each(['PROVISIONING', 'READY'])('decodes HTTP 201 Live create/replay without a detail read: %s', async status => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      const send = vi.fn(async () => Response.json({ id: 'agent-1', domain: DOMAIN, status,
        publication_config: wirePublication, oidc_issuer_url: 'https://issuer.example/exact' },
        { status: 201, headers: { 'Idempotency-Key': 'key' } }));
      const response = await new RegistryClient({ fetch: send }).registerLiveAgent({ publicKeyJwk: f.operationalKey }, 'key');
      expect(response).toMatchObject({ id: 'agent-1', domain: DOMAIN, registryStatus: status, publicationConfig: publication });
      expect(send).toHaveBeenCalledOnce();
    });
  });

  it.each(['domain', 'id', 'status', 'publication_config', 'oidc_issuer_url', 'header', '202'])('retains creation facts for invalid Live response: %s', async missing => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      const raw: Record<string, unknown> = { id: 'agent-1', domain: DOMAIN, status: 'PROVISIONING',
        publication_config: wirePublication, oidc_issuer_url: 'https://issuer.example/exact' };
      delete raw[missing];
      const registry = new RegistryClient({ fetch: async () => Response.json(raw, {
        status: missing === '202' ? 202 : 201, headers: missing === 'header' ? {} : { 'Idempotency-Key': 'key' },
      }) });
      await expect(registry.registerLiveAgent({ publicKeyJwk: f.operationalKey }, 'key')).rejects.toMatchObject({ idempotencyKey: 'key', creation: raw });
    });
  });

  it.each([undefined, null, 'true', 1])('rejects unsupported managed publication progress with known facts: %s', async dnsPublished => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      const id = await create('agent', f.options);
      const read = vi.mocked(f.registry.getRegistration).getMockImplementation()!;
      vi.mocked(f.registry.getRegistration).mockImplementation(async (...args) => ({ ...(await read(...args))!, dnsPublished: dnsPublished as never }));
      await expect(id.active()).rejects.toMatchObject({ category: 'UnsupportedRegistry', identityId: 'agent-1', domain: DOMAIN });
      expect(f.registry.prepareIssuance).not.toHaveBeenCalled();
      expect(f.registry.registerLiveAgent).toHaveBeenCalledOnce();
      await expect(id.sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
    });
  });

  it('uses the loaded endpoint and registry-only credential while DNS, HTTPS, and log checks stay public', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      const registryUrl = 'http://127.0.0.1:7755';
      vi.stubEnv('DNSID_REGISTRY_URL', 'https://must-not-be-read.example');
      vi.stubEnv('DNSID_API_KEY', 'must-not-be-read');
      const wirePublication = Object.fromEntries(Object.entries(publication).map(([name, value]) => [name.replace(/[A-Z]/g, char => '_' + char.toLowerCase()), value]));
      const send = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input);
        expect(url.startsWith(registryUrl + '/api/v1/')).toBe(true);
        expect(new Headers(init?.headers).get('authorization')).toBe('Bearer registry-only-secret');
        expect(init?.redirect).toBe('manual');
        expect(init?.signal).toBeInstanceOf(AbortSignal);
        if (url.endsWith('/onboarding')) return Response.json({ org_id: ORG, governance_domain: GI,
          gi: { domain: GI, state: 'verified', gate_authorized: true }, ek: { status: 'verified' } });
        if (url.endsWith('/status')) return Response.json({ id: 'agent-1', domain: DOMAIN, status: f.registryStatus, managed: 'dnsid', dns_published: true, publication_config: wirePublication });
        const idempotencyKey = new Headers(init?.headers).get('Idempotency-Key')!;
        if (url.endsWith('/issuance/prepare')) {
          const prepared = await f.registry.prepareIssuance(DOMAIN, idempotencyKey);
          return new Response(Buffer.from(prepared.entryBytes));
        }
        if (url.endsWith('/tlog/events')) {
          const result = await f.registry.submitPreparedEvent(DOMAIN, new Uint8Array(init!.body as ArrayBuffer), idempotencyKey);
          return Response.json({ state: result.state, entry_hash: result.entryHash, index: result.index, lr: result.logRef });
        }
        expect(JSON.parse(String(init?.body))).toMatchObject({ tier: 'live', managed: true, name: 'agent', public_key: f.operationalKey });
        return Response.json({ id: 'agent-1', status: f.registryStatus, domain: DOMAIN, publication_config: wirePublication, oidc_issuer_url: 'https://issuer.example/exact' }, { status: 201, headers: { 'Idempotency-Key': idempotencyKey } });
      });
      vi.stubGlobal('fetch', send);
      const id = await create('agent', { ...f.options, registryClient: undefined, credential: 'registry-only-secret',
        config: { ...f.options.config, registry: { registryUrl } } });
      await id.active();
      expect(send).toHaveBeenCalled();
      for (const [, options] of vi.mocked(f.options.fetchJson!).mock.calls) {
        expect(options).not.toHaveProperty('headers'); expect(options).not.toHaveProperty('credentials');
        expect(JSON.stringify(options)).not.toContain('secret');
      }
      expect(f.reader.verifyNonRevocation).toHaveBeenCalled();
    });
  });

  it('rejects authenticated redirects without forwarding credentials', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      const send = vi.fn(async () => new Response(null, { status: 307, headers: { location: 'https://attacker.example/collect' } }));
      vi.stubGlobal('fetch', send);
      await expect(create('agent', { ...f.options, registryClient: undefined, credential: 'secret',
        config: { registry: { registryUrl: 'http://127.0.0.1:7755' } } })).rejects.toMatchObject({ category: 'unsupported-contract', httpStatus: 307 });
      expect(send).toHaveBeenCalledOnce();
    });
  });

  it.each(['not json', '[]', '{}'])('reports an incompatible onboarding response as UnsupportedRegistry: %s', async body => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      vi.stubGlobal('fetch', vi.fn(async () => new Response(body)));
      await expect(create('agent', { ...f.options, registryClient: undefined,
        config: { registry: { registryUrl: 'http://127.0.0.1:7755' } } })).rejects.toMatchObject({ category: 'UnsupportedRegistry', resumable: false });
      expect(f.registry.registerLiveAgent).not.toHaveBeenCalled();
    });
  });

  it.each([['gi'], ['governance_domain'], ['gi', 'governance_domain']])('treats absent governance onboarding as resumable before comparing configured bindings: %j', async (...missing) => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      const body: Record<string, unknown> = { org_id: 'not-the-configured-org', governance_domain: GI,
        gi: { domain: GI, state: 'pending', gate_authorized: false }, ek: { status: 'pending' } };
      for (const member of missing) delete body[member];
      const send = vi.fn<typeof fetch>(async () => Response.json(body));
      const registry = new RegistryClient({ fetch: send as typeof fetch });
      await expect(create('agent', { ...f.options, registryClient: registry })).rejects.toMatchObject({
        category: 'workflow-outcome', message: 'organization onboarding is not ready', resumable: true,
      });
      expect(send).toHaveBeenCalledOnce();
      expect(String(send.mock.calls[0]![0])).toContain('/org/onboarding');
    });
  });

  it.each(['org_id', 'ek', 'domain', 'state', 'gate_authorized'])('rejects an onboarding contract missing required field %s', async missing => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      const gi: Record<string, unknown> = { domain: GI, state: 'verified', gate_authorized: true };
      const body: Record<string, unknown> = { org_id: ORG, governance_domain: GI, gi, ek: { status: 'verified' } };
      if (missing in gi) delete gi[missing]; else delete body[missing];
      const send = vi.fn<typeof fetch>(async () => Response.json(body));
      const registry = new RegistryClient({ fetch: send as typeof fetch });
      await expect(create('agent', { ...f.options, registryClient: registry })).rejects.toMatchObject({ category: 'UnsupportedRegistry', resumable: false });
      expect(send).toHaveBeenCalledOnce();
    });
  });

  it('keeps the local-registry connection diagnostic resumable', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('fetch failed', { cause: Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }) }); }));
      await expect(create('agent', { ...f.options, registryClient: undefined,
        config: { registry: { registryUrl: 'http://127.0.0.1:7755' } } })).rejects.toMatchObject({ category: 'resumable', resumable: true, message: expect.stringContaining('no registry at') });
      expect(f.registry.registerLiveAgent).not.toHaveBeenCalled();
    });
  });

  it('rejects an oversized registry body during the stream read', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      vi.stubGlobal('fetch', vi.fn(async () => new Response(new Uint8Array(1024 * 1024 + 1))));
      await expect(create('agent', { ...f.options, registryClient: undefined,
        config: { registry: { registryUrl: 'http://127.0.0.1:7755' } } })).rejects.toMatchObject({ category: 'resumable', resumable: true, message: 'registry response exceeds 1 MiB' });
      expect(f.registry.registerLiveAgent).not.toHaveBeenCalled();
    });
  });
});
