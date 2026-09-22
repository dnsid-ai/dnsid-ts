import { createC2spTlogVerificationRegistry } from '@dnsid-ai/log-c2sp-tlog';
import { createNodeIdentityVerifier } from '@dnsid-ai/sdk/node';

// Independently trusted configuration for DNSid's public test log.
// Production applications should select their own trusted policy URL or bytes.
// `dnsid local env` exports DNSID_LOG_POLICY_URL for the local registry.
const policyUrl = process.env.DNSID_LOG_POLICY_URL ?? 'https://log.dnsid.dev/dnsid-policy';

export async function validateDomain(domain: string): Promise<void> {
  // Local registry only (`eval "$(dnsid local env)"`): route DNS to its CoreDNS and trust its CA.
  // Its `.test` hosts may resolve to loopback without an allowlist. Both undefined in production.
  const transport = { dnsServer: process.env.DNSID_DNS_SERVER, caBundlePath: process.env.DNSID_CA_BUNDLE };

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
