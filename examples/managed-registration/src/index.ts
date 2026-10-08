import assert from 'node:assert/strict';
import { FileRegistrationStore, registerManagedIdentity } from '@dnsid-ai/sdk/node';

const token = (process.env.DNSID_API_KEY ?? '').trim();
const directory = process.argv[2];

try {
  assert(token && !/\s/.test(token), 'set DNSID_API_KEY to one API token');
  assert(directory && process.argv.length === 3, 'usage: npm run start -- <state-directory>');

  // Requires permanent server-side registration idempotency; see README.md.
  const { registration, loggedStateEvidence } = await registerManagedIdentity({
    loaded: {
      registry: { registryUrl: 'https://api.dev.dnsid.ai' },
      registration: {
        governanceId: 'dev.dnsid.ai',
        entityKeyUrl: 'https://dnsid.dev.dnsid.ai/.well-known/dnsid-ek.json',
      },
      logTrust: { managed: true },
    },
    credential: token,
    store: new FileRegistrationStore(directory),
    input: { environment: 'sandbox' },
  });
  console.log(`Registered: ${registration.domain}`);
  console.log(`Verified: ${registration.domain} status=${loggedStateEvidence.loggedState}`);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(token ? message.replaceAll(token, '[REDACTED]') : message);
  console.error('Keep your recovery files and rerun with the same directory.');
  process.exitCode = 1;
}
