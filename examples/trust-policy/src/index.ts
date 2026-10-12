import { readFile } from 'node:fs/promises';
import { createC2spTlogVerificationRegistry, parseC2spTlogTrustProfile } from '@dnsid-ai/log-c2sp-tlog';
import { createNodeIdentityVerifier } from '@dnsid-ai/sdk/node';

async function main(): Promise<void> {
  const [domain, profilePath, governanceId, thumbprint] = process.argv.slice(2);
  if (process.argv.length !== 6) {
    throw new Error('usage: trust-policy <domain> <trusted-profile.json> <gi> <ek-thumbprint>');
  }
  const trustProfile = parseC2spTlogTrustProfile(await readFile(profilePath!));
  const registry = await createC2spTlogVerificationRegistry({
    trustProfile,
    checkpointMaxAge: 10 * 60_000,
    maxBundleLifetimeMs: 5 * 60_000,
  });
  const verifier = await createNodeIdentityVerifier({
    verification: {
      statusCheckInterval: 30, // seconds, not milliseconds
      trustedEntities: [{ governanceId: governanceId!, entityKeyThumbprints: [thumbprint!] }],
    },
  }, { logRegistry: registry });
  const vd = await verifier.verifyDomain(domain!);
  console.log(vd.domain, vd.cachedState());
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
