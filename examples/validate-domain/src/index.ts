import { createC2spTlogVerificationRegistry } from '@dnsid-ai/log-c2sp-tlog';
import { createNodeIdentityVerifier } from '@dnsid-ai/sdk/node';

// Independently trusted configuration for DNSid's public test log.
// Production applications should select their own trusted policy URL or bytes.
const policyUrl = 'https://log.dnsid.dev/dnsid-policy';

export async function validateDomain(domain: string): Promise<void> {
  const logRegistry = await createC2spTlogVerificationRegistry({
    policyUrl,
    checkpointMaxAge: 24 * 60 * 60 * 1000,
  });
  const idm = await createNodeIdentityVerifier({}, { logRegistry });

  const verified = await idm.verifyDomain(domain);
  console.log(verified);
}

const domain = process.argv[2];
if (!domain) {
  console.error(`usage: ${process.argv[1]} <dnsid-domain>`);
  process.exit(2);
}
void validateDomain(domain);
