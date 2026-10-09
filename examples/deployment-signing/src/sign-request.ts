import { HttpSignaturesProfile } from '@dnsid-ai/sdk';
import { constructIdentityManager, loadFile } from '@dnsid-ai/sdk/node';

export async function signDeploymentRequest(file: string): Promise<Request> {
  const loaded = await loadFile(file);
  const domain = loaded.dnsid?.identity?.domain;
  if (!domain || !loaded.keySource?.keyRef) {
    throw new Error('deployment must specify dnsid.identity.domain and keySource.keyRef');
  }

  // No injected provider: construction checks kid, algorithm, and public material against publication.
  const idm = await constructIdentityManager(loaded);
  await idm.verifyDomain(domain);

  return HttpSignaturesProfile.fromIdentityManager(idm).createSignedHttpRequest(
    new Request('https://api.example/resource', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'deployment signing example' }),
    }),
  );
}
