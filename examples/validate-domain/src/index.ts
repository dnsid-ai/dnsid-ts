import { createC2spTlogVerificationRegistry } from '@dnsid-ai/log-c2sp-tlog';
import { createNodeIdentityVerifier } from '@dnsid-ai/sdk/node';

// Independently trusted configuration for DNSid's public test log.
// Production applications should select their own trusted policy URL or bytes.
// `dnsid local env` exports DNSID_LOG_POLICY_URL for the local registry.
const policyUrl = process.env.DNSID_LOG_POLICY_URL ?? 'https://log.dnsid.dev/dnsid-policy';

export async function validateDomain(domain: string): Promise<void> {
  // Local registry only (`eval "$(dnsid local env)"`): route DNS to its CoreDNS and trust its CA.
  // Its `.test` hosts resolve to loopback, so DNSID_PRIVATE_HOSTS=.test is needed too. All undefined in production.
  const privateHosts = process.env.DNSID_PRIVATE_HOSTS?.split(',').map(h => h.trim()).filter(Boolean);
  const transport = {
    dnsServer: process.env.DNSID_DNS_SERVER,
    caBundlePath: process.env.DNSID_CA_BUNDLE,
    ...(privateHosts?.length ? { privateAddressHosts: privateHosts } : {}),
  };

  const logRegistry = await createC2spTlogVerificationRegistry({
    policyUrl,
    checkpointMaxAge: 24 * 60 * 60 * 1000,
    transport,
  });
  const idm = await createNodeIdentityVerifier({ transport }, { logRegistry });

  const verified = await idm.verifyDomain(domain);
  console.log(verified);
}

const domain = process.argv[2];
if (!domain) {
  console.error(`usage: ${process.argv[1]} <dnsid-domain>`);
  process.exit(2);
}
void validateDomain(domain);
