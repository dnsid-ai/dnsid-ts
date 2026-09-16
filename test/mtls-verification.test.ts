import { beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import { IdentityManager, matchesDnsName, VerificationCode } from '@dnsid-ai/protocol';
import type { IdentityConfig, DnsIdJWK, KeyProvider } from '@dnsid-ai/protocol';
import { currentProfileFixture } from './helpers/current-profile.ts';

let operationalKey: DnsIdJWK;
beforeAll(async () => {
  const pair = await generateKeyPair('ES256');
  const raw = await exportJWK(pair.publicKey);
  operationalKey = { ...raw, kty: raw.kty!, kid: 'op', alg: 'ES256', use: 'sig' } as DnsIdJWK;
});

const config: IdentityConfig = {
  domain: 'verifier.example.com', governanceId: 'example.com',
  logRef: 'microledger:v', statusUrl: 'https://verifier.example.com/status',
};
const keyProvider = {
  signingKey: vi.fn(), jwk: vi.fn(), listKeyIds: vi.fn(), sign: vi.fn(), signKey: vi.fn(),
  generateKey: vi.fn(), activate: vi.fn(), supersede: vi.fn(), purge: vi.fn(),
} as unknown as KeyProvider;

async function manager(flags?: string): Promise<IdentityManager> {
  const fixture = await currentProfileFixture('agent.example.com', operationalKey, flags);
  return new IdentityManager({ identity: config }, { keyProvider, logRegistry: fixture.logRegistry, dnsResolver: fixture.dnsResolver, fetchJson: fixture.fetchJson });
}

describe('fl=mtls peer certificate validation', () => {
  it('accepts a certificate matching the identity FQDN', async () => {
    const vd = await (await manager('mtls')).verifyDomain('agent.example.com', {
      notAfter: new Date('2099-01-01'), san: ['agent.example.com'],
    });
    expect(vd.domain).toBe('agent.example.com');
  });

  it('rejects a missing or mismatched peer certificate', async () => {
    const missing = await manager('mtls');
    await expect(missing.verifyDomain('agent.example.com')).rejects.toMatchObject({ code: VerificationCode.TLSError });
    const mismatch = await manager('mtls');
    await expect(mismatch.verifyDomain('agent.example.com', {
      notAfter: new Date('2099-01-01'), san: ['other.example.com'],
    })).rejects.toMatchObject({ code: VerificationCode.TLSError });
  });

  it('does not require a peer certificate without fl=mtls', async () => {
    await expect((await manager()).verifyDomain('agent.example.com')).resolves.toMatchObject({ domain: 'agent.example.com' });
  });
});

describe('matchesDnsName', () => {
  it('supports normalized exact names and one-label wildcards', () => {
    expect(matchesDnsName(['Agent.Example.COM.'], 'agent.example.com')).toBe(true);
    expect(matchesDnsName(['*.example.com'], 'agent.example.com')).toBe(true);
    expect(matchesDnsName(['*.example.com'], 'deep.agent.example.com')).toBe(false);
  });
});
