import { describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';

import { ArgumentError, DNSSECState, IdentityManager } from '@identity-digital/dnsid-protocol';
import { createIdentityVerifier } from '@identity-digital/dnsid';
import { createNodeIdentityVerifier } from '@identity-digital/dnsid/node';
import { createJoseProfile } from '@identity-digital/dnsid-jose';
import { createHttpSignaturesProfile } from '@identity-digital/dnsid-http-signatures';
import { createOIDCProfile } from '@identity-digital/dnsid-oidc';
import { currentProfileFixture } from './helpers/current-profile.ts';

describe('verification-only IdentityManager construction', () => {
  it('verifies without local identity configuration or a KeyProvider', async () => {
    const pair = await generateKeyPair('ES256');
    const raw = await exportJWK(pair.publicKey);
    const operationalKey = { ...raw, kty: raw.kty!, kid: 'operational', alg: 'ES256', use: 'sig' };
    const fixture = await currentProfileFixture('agent.example.com', operationalKey);
    const verifier = createIdentityVerifier({}, {
      dnsResolver: fixture.dnsResolver,
      fetchJson: fixture.fetchJson,
      logRegistry: fixture.logRegistry,
    });

    await expect(verifier.verifyDomain('agent.example.com')).resolves.toMatchObject({
      domain: 'agent.example.com',
      dnssecState: DNSSECState.UNSIGNED,
    });
  });

  it('rejects local signing and mutation methods with ArgumentError', async () => {
    const verifier = createIdentityVerifier({}, {
      dnsResolver: { fetchTXT: vi.fn() },
      fetchJson: vi.fn(),
    });

    expect(() => verifier.getKeyProvider()).toThrow(ArgumentError);
    await expect(verifier.getKeySet()).rejects.toBeInstanceOf(ArgumentError);
    await expect(verifier.createTxtRecord()).rejects.toBeInstanceOf(ArgumentError);
    await expect(verifier.rotateOperationalKey({ publishKeySet: vi.fn() })).rejects.toBeInstanceOf(ArgumentError);
  });

  it('rejects local identity configuration without a KeyProvider', () => {
    expect(() => new IdentityManager(
      { identity: { domain: 'local.example.com', governanceId: 'example.com', logRef: 'noop:0', statusUrl: 'https://local.example.com/status' } },
      { dnsResolver: { fetchTXT: vi.fn() }, fetchJson: vi.fn() },
    )).toThrow(ArgumentError);
  });

  it('rejects key providers without a local identity', () => {
    const keyProvider = { signingKey: vi.fn() } as never;
    expect(() => new IdentityManager({}, { keyProvider, dnsResolver: { fetchTXT: vi.fn() }, fetchJson: vi.fn() })).toThrow(ArgumentError);
    expect(() => new IdentityManager({}, { entityKeyProvider: keyProvider, dnsResolver: { fetchTXT: vi.fn() }, fetchJson: vi.fn() })).toThrow(ArgumentError);
  });

  it('provides the same verify-only path through the Node entrypoint', async () => {
    const verifier = await createNodeIdentityVerifier({}, {
      dnsResolver: { fetchTXT: vi.fn() },
      fetchJson: vi.fn(),
    });
    expect(() => verifier.getKeyProvider()).toThrow(ArgumentError);
  });

  it('constructs verification profiles without a dummy signer', async () => {
    const verifier = createIdentityVerifier({}, {
      dnsResolver: { fetchTXT: vi.fn() },
      fetchJson: vi.fn(),
    });
    const jose = createJoseProfile({ domain: 'verifier.example.com', identityResolver: verifier });
    const http = createHttpSignaturesProfile({ domain: 'verifier.example.com', identityResolver: verifier });
    const oidcFetch = vi.fn();
    const oidc = createOIDCProfile({
      domain: 'verifier.example.com',
      identityResolver: verifier,
      fetch: oidcFetch,
    });

    await expect(jose.createJWS(new Uint8Array())).rejects.toBeInstanceOf(ArgumentError);
    await expect(http.createSignedHttpRequest(new Request('https://peer.example.com/')))
      .rejects.toBeInstanceOf(ArgumentError);
    await expect(oidc.createOIDCAssertion({ issuer: 'https://issuer.example.com' }))
      .rejects.toBeInstanceOf(ArgumentError);
    await expect(oidc.getOIDCToken({
      issuer: 'https://issuer.example.com',
      audience: 'https://api.example.com',
    })).rejects.toBeInstanceOf(ArgumentError);
    expect(oidcFetch).not.toHaveBeenCalled();
  });
});
