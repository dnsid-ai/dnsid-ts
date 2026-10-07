import assert from 'node:assert/strict';
import {
  FileRegistrationStore, loadEnvironment, mergeLoadedConfig, registerManagedIdentity,
} from '@dnsid-ai/sdk/node';

const REGISTRY_URL = 'https://api.dev.dnsid.ai';

export async function runRegistration(directory: string, token: string): Promise<void> {
  const loaded = await loadEnvironment(process.env);
  assert(!loaded.registry?.registryUrl || loaded.registry.registryUrl === REGISTRY_URL,
    'this example supports only the dev registry');
  // Setup owns the identity and operational key; keep SDK transport/verification settings.
  delete loaded.dnsid?.identity;
  delete loaded.keySource;
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
  });
  console.log(`Registered: ${registration.domain}`);
  console.log(`Verified: ${registration.domain} status=${loggedStateEvidence.loggedState}`);
}
