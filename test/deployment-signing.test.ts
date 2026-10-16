import { fileURLToPath } from 'node:url';
import { afterEach, expect, it, vi } from 'vitest';
import { HttpSignaturesProfile, JWKS, type VerifiedDomain } from '@dnsid-ai/sdk';
import * as nodeSdk from '@dnsid-ai/sdk/node';
import { signDeploymentRequest } from '../examples/deployment-signing/src/sign-request.ts';

const deployment = (provider: string) => fileURLToPath(new URL(
  `../examples/deployment-signing/deployment.${provider}.json`, import.meta.url,
));

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it('requires an identity and existing key reference before construction', async () => {
  vi.spyOn(nodeSdk, 'loadFile').mockResolvedValue({});
  const construct = vi.spyOn(nodeSdk, 'constructIdentityManager');
  await expect(signDeploymentRequest('incomplete.json')).rejects.toThrow('deployment must specify');
  expect(construct).not.toHaveBeenCalled();
});

it.each(['aws-kms', 'file'])('loads the %s template, verifies self, and signs without sending', async provider => {
  const keyProvider = await nodeSdk.LocalKeyProvider.generate('ES256');
  const loaded = await nodeSdk.loadFile(deployment(provider));
  expect(loaded.keySource?.provider).toBe(provider);
  expect(loaded.dnsid?.identity?.ekUrl).toBe('https://example.com/.well-known/dnsid/jwks.json');
  expect(loaded.dnsid?.identity?.kuUrl).toBe('https://agent.example/.well-known/dnsid/jwks.json');
  const idm = await nodeSdk.createNodeIdentityManager({ identity: {
    ...loaded.dnsid!.identity!, logRef: 'noop:0',
  } } as Parameters<typeof nodeSdk.createNodeIdentityManager>[0], { keyProvider });
  const verified = { domain: 'agent.example', jwks: new JWKS([await keyProvider.signingKey()]) } as VerifiedDomain;
  const verifySelf = vi.spyOn(idm, 'verifyDomain').mockResolvedValue(verified);
  const construct = vi.spyOn(nodeSdk, 'constructIdentityManager').mockResolvedValue(idm);
  const sign = vi.spyOn(keyProvider, 'sign');
  const fetch = vi.fn(() => { throw new Error('request must not be sent'); });
  vi.stubGlobal('fetch', fetch);

  const signed = await signDeploymentRequest(deployment(provider));
  expect(construct).toHaveBeenCalledExactlyOnceWith(loaded); // No injected provider bypassing binding checks.
  expect(verifySelf).toHaveBeenCalledExactlyOnceWith('agent.example');
  expect(verifySelf.mock.invocationCallOrder[0]).toBeLessThan(sign.mock.invocationCallOrder[0]!);
  expect(signed.method).toBe('POST');
  expect(signed.headers.has('Content-Digest')).toBe(true);
  await expect(HttpSignaturesProfile.fromIdentityManager(idm).verifySignedHttpRequest(signed)).resolves.toBe(verified);
  expect(fetch).not.toHaveBeenCalled();

  sign.mockClear();
  verifySelf.mockRejectedValue(new Error('self verification failed'));
  await expect(signDeploymentRequest(deployment(provider))).rejects.toThrow('self verification failed');
  expect(sign).not.toHaveBeenCalled();
  construct.mockRejectedValue(new Error('configured operational key does not match'));
  await expect(signDeploymentRequest(deployment(provider))).rejects.toThrow('configured operational key does not match');
  expect(sign).not.toHaveBeenCalled();
});
