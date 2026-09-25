import { constructIdentityManager, loadEnvironment, mergeLoadedConfig } from '@dnsid-ai/sdk/node';

// Trust is explicit configuration, never discovered from an identity record's log reference.
// The example's fallback is DNSid's public test log; `dnsid local env` exports DNSID_LOG_POLICY_URL
// plus DNSID_DNS_SERVER, DNSID_CA_BUNDLE, and DNSID_PRIVATE_HOSTS=.test for the local registry, and
// production sets its own independently trusted DNSID_LOG_POLICY_URL / _FILE / DNSID_LOG_TRUST_PROFILE_FILE.
const FALLBACK = { logTrust: { policyUrl: 'https://log.dev.dnsid.ai/dnsid-policy' } };

export async function validateDomain(domain: string): Promise<void> {
  const idm = await constructIdentityManager(mergeLoadedConfig(FALLBACK, await loadEnvironment()));

  const verified = await idm.verifyDomain(domain);
  console.log(verified);
}

const domain = process.argv[2];
if (!domain) {
  console.error(`usage: ${process.argv[1]} <dnsid-domain>`);
  process.exit(2);
}
void validateDomain(domain);
