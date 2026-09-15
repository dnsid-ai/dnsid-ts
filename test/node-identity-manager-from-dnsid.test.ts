import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it, vi } from 'vitest';

import { DNSSECState } from '@identity-digital/dnsid';
import { createNodeIdentityManager, createNodeIdentityManagerFromDnsid } from '@identity-digital/dnsid/node';
import type { DNSResolver, JsonFetcher } from '@identity-digital/dnsid';

const dnsResolver: DNSResolver = {
  fetchTXT: vi.fn().mockResolvedValue([[], DNSSECState.UNSIGNED]),
};
const fetchJson: JsonFetcher = vi.fn();
const options = (dnsidDir: string) => [{ dnsidDir }, { dnsResolver, fetchJson }] as const;

async function withTemp(fn: (root: string) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), 'dnsid-manager-'));
  try { await fn(root); } finally { await rm(root, { recursive: true, force: true }); }
}

async function writeKeyPair(dir: string, kid: string, filename = 'private.jwk') {
  const pair = await crypto.subtle.generateKey(
    { name: 'Ed25519' } as AlgorithmIdentifier,
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;
  await writeFile(join(dir, filename), JSON.stringify({
    ...(await crypto.subtle.exportKey('jwk', pair.privateKey)),
    kid,
    alg: 'EdDSA',
    use: 'sig',
  }));
}

async function writePemKey(dir: string, algorithm: 'EdDSA' | 'ES256' = 'EdDSA') {
  const generationAlgorithm = algorithm === 'EdDSA'
    ? { name: 'Ed25519' } as AlgorithmIdentifier
    : { name: 'ECDSA', namedCurve: 'P-256' } as EcKeyGenParams;
  const pair = await crypto.subtle.generateKey(generationAlgorithm as AlgorithmIdentifier, true, ['sign', 'verify']) as CryptoKeyPair;
  const bytes = Buffer.from(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const body = bytes.toString('base64').match(/.{1,64}/g)!.join('\n');
  await writeFile(join(dir, 'private.pem'), `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`);
}

describe('createNodeIdentityManagerFromDnsid', () => {
  it('accepts zero arguments and uses the default DNSid directory', () => withTemp(async root => {
    vi.stubEnv('DNSID_CONFIG_DIR', join(root, 'missing'));
    try {
      await expect(createNodeIdentityManagerFromDnsid())
        .rejects.toThrow('run the DNSid CLI to register your domain first');
    } finally {
      vi.unstubAllEnvs();
    }
  }));

  it('uses the Node default resolver when callers omit a DNS resolver', async () => {
    await expect(createNodeIdentityManager({
      identity: {
        domain: 'verifier.example.com',
        governanceId: 'example.com',
        logRef: 'noop:0',
        statusUrl: 'https://verifier.example.com/status',
      },
    }, { keyProvider: {} as never, fetchJson })).resolves.toBeDefined();
  });

  it('rejects missing config with a helpful error', () => withTemp(async root => {
    await expect(createNodeIdentityManagerFromDnsid(...options(join(root, 'missing'))))
      .rejects.toThrow('run the DNSid CLI to register your domain first');
  }));

  it.each([
    ['without domain', { governance_id: 'example.com' }, 'must include domain'],
    ['without governanceId', { domain: 'agent.example.com' }, 'must include governanceId or governance_id'],
    ['with invalid maxKeyAge', { domain: 'agent.example.com', governance_id: 'example.com', max_key_age: 'forever' }, 'invalid maxKeyAge'],
  ])('rejects config %s', (_name, config, message) => withTemp(async root => {
    await writeFile(join(root, 'config.json'), JSON.stringify(config));
    await expect(createNodeIdentityManagerFromDnsid(...options(root))).rejects.toThrow(message);
  }));

  it('loads config and keys from a DNSid root directory', () => withTemp(async root => {
    const dir = join(root, 'agent.example.com');
    await mkdir(dir, { recursive: true });
    await writeFile(join(root, 'config.json'), JSON.stringify({
      domain: 'agent.example.com',
      governance_id: 'example.com',
      server_url: 'https://registry.example.com',
    }));
    await writeKeyPair(dir, 'registry-key');

    const idm = await createNodeIdentityManagerFromDnsid({ dnsidDir: root }, { fetchJson });

    expect(idm.config.identity).toMatchObject({
      domain: 'agent.example.com',
      governanceId: 'example.com',
      statusUrl: 'https://registry.example.com/v1/status/agent.example.com',
    });
    await expect(idm.getKeyProvider().listKeyIds()).resolves.toEqual(['registry-key']);
  }));

  it('uses DNSID_CONFIG_DIR and resolves the root pointer to per-identity config', () => withTemp(async root => {
    const dir = join(root, 'agent.example.com');
    await mkdir(dir, { recursive: true });
    await writeFile(join(root, 'config.json'), JSON.stringify({ domain: 'agent.example.com' }));
    await writeFile(join(dir, 'config.json'), JSON.stringify({
      domain: 'agent.example.com',
      governance_id: 'example.com',
      status_url: 'https://agent.example.com/status',
    }));
    await writeKeyPair(dir, 'pointer-key');

    const idm = await createNodeIdentityManagerFromDnsid({ env: { DNSID_CONFIG_DIR: root } }, { dnsResolver, fetchJson });

    expect(idm.config.identity!.statusUrl).toBe('https://agent.example.com/status');
    await expect(idm.getKeyProvider().listKeyIds()).resolves.toEqual(['pointer-key']);
  }));

  it('loads authoritative publication config and entity key from an exported per-domain config', () => withTemp(async root => {
    const dir = join(root, 'agent.example.com');
    await mkdir(dir, { recursive: true });
    await writeFile(join(root, 'config.json'), JSON.stringify({
      domain: 'agent.example.com',
      entity_key_path: 'agent.example.com/entity.jwk',
    }));
    await writeFile(join(dir, 'config.json'), JSON.stringify({
      domain: 'agent.example.com',
      governance_id: 'example.com',
      publish_profile: 'dnsid-draft-01',
      log_ref: 'c2sp-tlog:custom-log-ref',
      status_url: 'https://registry.example/status/agent.example.com',
      ku_url: 'https://agent.example.com/operational.jwks',
      ek_url: 'https://example.com/entity.jwks',
      capabilities_url: 'https://agent.example.com/capabilities.json',
      max_key_age: '30d',
      entity_key_path: 'entity.jwk',
    }));
    await writeKeyPair(dir, 'operational-key');
    await writeKeyPair(dir, 'entity-key', 'entity.jwk');

    const idm = await createNodeIdentityManagerFromDnsid(...options(root));

    expect(idm.config.identity).toMatchObject({
      domain: 'agent.example.com',
      governanceId: 'example.com',
      publishProfile: 'dnsid-draft-01',
      logRef: 'c2sp-tlog:custom-log-ref',
      statusUrl: 'https://registry.example/status/agent.example.com',
      kuUrl: 'https://agent.example.com/operational.jwks',
      ekUrl: 'https://example.com/entity.jwks',
      capabilitiesUrl: 'https://agent.example.com/capabilities.json',
      maxKeyAge: '30d',
    });
    await expect(idm.getEntityKeySet()).resolves.toMatchObject({ keys: [expect.objectContaining({ kid: 'entity-key' })] });
    await expect(idm.createTxtRecord()).resolves.toContain('ka=30d');
  }));

  it('resolves a root config entity_key_path relative to that config file', () => withTemp(async root => {
    const dir = join(root, 'agent.example.com');
    await mkdir(dir, { recursive: true });
    await writeFile(join(root, 'config.json'), JSON.stringify({
      domain: 'agent.example.com',
      governance_id: 'example.com',
      log_ref: 'c2sp-tlog:root-config',
      status_url: 'https://registry.example/status/agent.example.com',
      ku_url: 'https://agent.example.com/jwks.json',
      ek_url: 'https://example.com/entity.jwks',
      entity_key_path: 'agent.example.com/entity.jwk',
    }));
    await writeKeyPair(dir, 'operational-key');
    await writeKeyPair(dir, 'root-entity-key', 'entity.jwk');

    const idm = await createNodeIdentityManagerFromDnsid(...options(root));

    await expect(idm.getEntityKeySet()).resolves.toMatchObject({ keys: [expect.objectContaining({ kid: 'root-entity-key' })] });
  }));

  it('loads PKCS#8 Ed25519 private.pem when private.jwk is absent', () => withTemp(async root => {
    await writeFile(join(root, 'config.json'), JSON.stringify({
      domain: 'agent.example.com',
      governance_id: 'example.com',
    }));
    await writePemKey(root);

    const idm = await createNodeIdentityManagerFromDnsid(...options(root));

    await expect(idm.getKeyProvider().signingKey()).resolves.toMatchObject({
      kty: 'OKP',
      crv: 'Ed25519',
      alg: 'EdDSA',
      use: 'sig',
    });
  }));

  it('loads PKCS#8 ECDSA P-256 private.pem when private.jwk is absent', () => withTemp(async root => {
    await writeFile(join(root, 'config.json'), JSON.stringify({
      domain: 'agent.example.com',
      governance_id: 'example.com',
    }));
    await writePemKey(root, 'ES256');

    const idm = await createNodeIdentityManagerFromDnsid(...options(root));

    await expect(idm.getKeyProvider().signingKey()).resolves.toMatchObject({
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      use: 'sig',
    });
  }));

  it('loads config and keys from an identity directory directly', () => withTemp(async root => {
    const dir = join(root, 'agent.example.com');
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'config.json'), JSON.stringify({
      domain: 'agent.example.com',
      governance_id: 'example.com',
      server_url: 'https://registry.example.com',
    }));
    await writeKeyPair(dir, 'direct-key');

    const idm = await createNodeIdentityManagerFromDnsid(...options(dir));

    await expect(idm.getKeyProvider().listKeyIds()).resolves.toEqual(['direct-key']);
  }));
});
