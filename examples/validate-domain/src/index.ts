import {
  createC2spTlogVerificationRegistry,
  createFetchBackedC2spResourceFetcher,
  requiredC2spResourceFetchGuarantees,
} from '@dnsid-ai/log-c2sp-tlog';
import { createNodeIdentityVerifier } from '@dnsid-ai/sdk/node';
import { createSsrfSafeFetch } from '@dnsid-ai/transport';

// Independently trusted configuration for DNSid's public test log.
// Production applications should select their own trusted policy URL or bytes.
// `dnsid local env` exports DNSID_LOG_POLICY_URL for the local registry.
const policyUrl = process.env.DNSID_LOG_POLICY_URL ?? 'https://log.dnsid.dev/dnsid-policy';

export async function validateDomain(domain: string): Promise<void> {
  // Local registry only (`eval "$(dnsid local env)"`): route DNS to its CoreDNS, trust its CA,
  // and allow the loopback hosts it serves. All undefined in production.
  const { DNSID_DNS_SERVER: dnsServer, DNSID_CA_BUNDLE: caBundlePath, DNSID_GOVERNANCE_ID: governanceId } = process.env;
  const allowedUnsafeHosts = dnsServer ? [domain, new URL(policyUrl).hostname, `dnsid.${governanceId}`] : undefined;
  const transport = { dnsServer, caBundlePath, allowedUnsafeHosts };

  const logRegistry = await createC2spTlogVerificationRegistry({
    policyUrl,
    checkpointMaxAge: 24 * 60 * 60 * 1000,
    resourceFetcher: createFetchBackedC2spResourceFetcher(
      createSsrfSafeFetch(transport, { allowedUnsafeHosts }),
      requiredC2spResourceFetchGuarantees(),
    ),
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
