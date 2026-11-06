import { afterEach, describe, expect, it, vi } from 'vitest';
import { create, SigningPaused } from '@dnsid-ai/foundry';
import { RegistryClient } from '@dnsid-ai/registry';
import { DOMAIN, ORG, GI, foundryFixture, publication } from './helpers/foundry.ts';
import { withTemp } from './helpers/cli-directory.ts';

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

describe('Foundry registry adapters', () => {
  it.each([undefined, null, '', DOMAIN.toUpperCase() + '.'])('reads the optional challenge-free replay domain: %s', async domain => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      const registry = new RegistryClient({ fetch: vi.fn(async () => new Response(JSON.stringify({
        request_id: 'key', agent_id: 'agent-1', status: 'VERIFIED', challenge: '', challenge_message: '', ...(domain !== undefined ? { domain } : {}),
      }), { status: 202 })) as typeof fetch });
      const response = await registry.registerLiveAgent({ publicKeyJwk: f.operationalKey }, 'key');
      expect(response.domain).toBe(domain ? DOMAIN : undefined);
    });
  });

  it('rejects disagreement between the wire domain and challenge domain', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.proofRequired = true;
      const response = await f.registry.registerLiveAgent({ publicKeyJwk: f.operationalKey }, 'key');
      const registry = new RegistryClient({ fetch: vi.fn(async () => new Response(JSON.stringify({
        request_id: 'key', agent_id: 'agent-1', status: 'challenge_pending', challenge: response.challenge,
        challenge_message: response.challengeMessage, domain: 'different.example.com',
      }), { status: 202 })) as typeof fetch });
      await expect(registry.registerLiveAgent({ publicKeyJwk: f.operationalKey }, 'key')).rejects.toThrow('domain does not match challenge');
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
        if (url.endsWith('/status')) return Response.json({ id: 'agent-1', domain: DOMAIN, status: f.registryStatus, managed: 'dnsid', publication_config: wirePublication });
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
        return Response.json({ request_id: idempotencyKey, agent_id: 'agent-1', status: 'VERIFIED', domain: DOMAIN, challenge: '', challenge_message: '' }, { status: 202 });
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

  it('rejects an oversized registry body during the stream read', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      vi.stubGlobal('fetch', vi.fn(async () => new Response(new Uint8Array(1024 * 1024 + 1))));
      await expect(create('agent', { ...f.options, registryClient: undefined,
        config: { registry: { registryUrl: 'http://127.0.0.1:7755' } } })).rejects.toThrow('onboarding contract');
      expect(f.registry.registerLiveAgent).not.toHaveBeenCalled();
    });
  });
});
