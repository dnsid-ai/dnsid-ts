import assert from 'node:assert/strict';
import {
  FileRegistrationStore, loadEnvironment, mergeLoadedConfig, registerManagedIdentity,
} from '@dnsid-ai/sdk/node';
import { createDnsidFetch } from '@dnsid-ai/transport';

const REGISTRY_URL = 'https://api.dev.dnsid.ai';

export async function runRegistration(directory: string, token: string): Promise<void> {
  const loaded = await loadEnvironment(process.env);
  assert(!loaded.registry?.registryUrl || loaded.registry.registryUrl === REGISTRY_URL,
    'this example supports only the dev registry');
  // Setup owns the identity and operational key; keep SDK transport/verification settings.
  delete loaded.dnsid?.identity;
  delete loaded.keySource;
  const network = createDnsidFetch(loaded.dnsid?.transport ?? {});
  const devFetch: typeof fetch = (url, init) => {
    assert.equal(new URL(String(url)).origin, REGISTRY_URL, 'unexpected registry origin');
    return network(url, { ...init, redirect: 'error' });
  };
  const { registration, loggedStateEvidence } = await registerManagedIdentity({
    loaded: mergeLoadedConfig(loaded, {
      registry: { registryUrl: REGISTRY_URL },
      registration: {
        governanceId: 'dev.dnsid.ai',
        entityKeyUrl: 'https://dnsid.dev.dnsid.ai/.well-known/dnsid-ek.json',
      },
      logTrust: { managed: true },
    }),
    credential: token,
    store: new FileRegistrationStore(directory),
    input: { environment: 'sandbox' },
    fetch: devFetch,
    adapter: {
      resolveOrganization: async (_client, signal) => {
        const response = await devFetch(`${REGISTRY_URL}/api/v1/org`, {
          headers: { Authorization: `Bearer ${token}` }, signal,
        });
        assert(response.ok, `organization lookup failed: HTTP ${response.status}`);
        const organization = await response.json();
        assert(typeof organization?.id === 'string' && organization.id.trim(), 'missing organization ID');
        return organization.id;
      },
      // Dev server: internal/db/pgstore/idempotency.go, organization/key scope, 24h TTL.
      creationReplay: {
        policy: 'dev registry: organization/request-key; 24h from storage (at least first request)',
        minimumRetentionMs: 86_400_000,
        clockUncertaintyMs: 1000,
      },
    },
  });
  console.log(`Registered: ${registration.domain}`);
  console.log(`Verified: ${registration.domain} status=${loggedStateEvidence.loggedState}`);
}
