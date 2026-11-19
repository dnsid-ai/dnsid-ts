import { expect, it, vi } from 'vitest';
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';
import {
  GcpCloudKmsKeyProvider,
  type GcpCloudKmsClient,
  type GcpCloudKmsConfig,
} from '@dnsid-ai/key-gcp';
import type { DnsIdJWK } from '@dnsid-ai/protocol';
import type { protos } from '@google-cloud/kms';

type Kms = protos.google.cloud.kms.v1.IPublicKey;
type SignRequest = protos.google.cloud.kms.v1.IAsymmetricSignRequest;
type SignResponse = protos.google.cloud.kms.v1.IAsymmetricSignResponse;
type Version = protos.google.cloud.kms.v1.ICryptoKeyVersion;
type CreateRequest = Parameters<NonNullable<GcpCloudKmsClient['createCryptoKeyVersion']>>[0];

const parent = 'projects/boundary-fixture/locations/us-central1/keyRings/fixture/cryptoKeys/signing';
const activeVersion = `${parent}/cryptoKeyVersions/7`;

// Independent reflected Castagnoli CRC32C, not an SDK helper or IEEE CRC32.
function crc32c(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function freshKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const exported = publicKey.export({ format: 'jwk' });
  if (exported.kty !== 'OKP' || exported.crv !== 'Ed25519' || typeof exported.x !== 'string') {
    throw new Error('Node did not generate an Ed25519 public JWK');
  }
  const publicJwk = { crv: 'Ed25519', kty: 'OKP', x: exported.x };
  const kid = createHash('sha256').update(JSON.stringify(publicJwk)).digest('base64url');
  const pem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
  return { privateKey, publicKey, publicJwk, kid, pem };
}
type FixtureKey = ReturnType<typeof freshKey>;

function assertPublicJwk(jwk: DnsIdJWK, key: FixtureKey): void {
  expect({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }).toEqual(key.publicJwk);
  expect(jwk.kid).toBe(key.kid);
  // Recompute RFC 7638 from the consumer-visible public members as well.
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  expect(createHash('sha256').update(canonical).digest('base64url')).toBe(jwk.kid);
}

function diagnosticTraps() {
  const trap = () => vi.fn(async (..._args: unknown[]) => {
    throw new Error('Unexpected operation on the injected diagnostic object');
  });
  return {
    getCryptoKey: trap(),
    getCryptoKeyVersion: trap(),
    createCryptoKey: trap(),
    createCryptoKeyVersion: trap(),
    createKeyRing: trap(),
    createLocation: trap(),
    createProject: trap(),
    updateCryptoKey: trap(),
    updateCryptoKeyVersion: trap(),
    destroyCryptoKeyVersion: trap(),
    asymmetricSign: trap(),
  };
}

it('ordinary load propagates native NOT_FOUND without fallback or configuration mutation', async () => {
  // Given: an immutable configured version and a native transport error.
  const config: GcpCloudKmsConfig = {
    activeKeyVersion: activeVersion,
    retainedKeyVersions: [],
    algorithm: 'EC_SIGN_ED25519',
  };
  const before = structuredClone(config);
  const missing = Object.assign(new Error('fixture immutable version is missing'), { code: 5 });
  const diagnostics = diagnosticTraps();
  const getPublicKey = vi.fn(async (request: protos.google.cloud.kms.v1.IGetPublicKeyRequest) => {
    expect(request.name).toBe(activeVersion);
    throw missing;
  });
  const client = { ...diagnostics, getPublicKey } satisfies GcpCloudKmsClient;

  // When/Then: failure reaches the consumer as the same Error, never a provider.
  await expect(GcpCloudKmsKeyProvider.load(client, config)).rejects.toBe(missing);
  expect(missing.code).toBe(5);
  expect(config).toEqual(before);
  expect(getPublicKey).toHaveBeenCalled();

  // Supplementary injected-object diagnostics only: not a global SDK-call claim.
  for (const spy of Object.values(diagnostics)) expect(spy).not.toHaveBeenCalled();
});

it('two explicit generations expose independent pending keys while preserving the active signer and configuration', async () => {
  // Given: independently generated active Ed25519 material and an offline KMS seam.
  expect(crc32c(Buffer.from('123456789'))).toBe(0xe3069283);
  const active = freshKey();
  const keys = new Map<string, FixtureKey>([[activeVersion, active]]);
  const allocations: Array<{ name: string; key: FixtureKey }> = [];
  const config: GcpCloudKmsConfig = {
    activeKeyVersion: activeVersion,
    retainedKeyVersions: [],
    algorithm: 'EC_SIGN_ED25519',
  };
  const before = structuredClone(config);
  const traps = diagnosticTraps();
  const client = {
    ...traps,
    getPublicKey: vi.fn(async (request: protos.google.cloud.kms.v1.IGetPublicKeyRequest) => {
      const key = keys.get(request.name ?? '');
      if (!key) throw new Error(`Unallocated public-key version: ${request.name}`);
      const response: Kms = {
        name: request.name,
        algorithm: 'EC_SIGN_ED25519',
        protectionLevel: 'SOFTWARE',
        pem: key.pem,
        pemCrc32c: { value: crc32c(Buffer.from(key.pem, 'utf8')) },
      };
      return [response, undefined, undefined] as const;
    }),
    createCryptoKeyVersion: vi.fn(async (request: CreateRequest) => {
      expect(request.parent).toBe(parent);
      expect(request.cryptoKeyVersion.state).toBe('ENABLED');
      const name = `${parent}/cryptoKeyVersions/${101 + allocations.length}`;
      const key = freshKey();
      keys.set(name, key);
      allocations.push({ name, key });
      const response: Version = {
        name, state: 'ENABLED', algorithm: 'EC_SIGN_ED25519', protectionLevel: 'SOFTWARE',
      };
      return [response, undefined, undefined] as const;
    }),
    asymmetricSign: vi.fn(async (request: SignRequest) => {
      const key = keys.get(request.name ?? '');
      if (!key) throw new Error(`Unallocated signing version: ${request.name}`);
      if (!(request.data instanceof Uint8Array)) throw new Error('Expected raw signing data');
      expect(request.dataCrc32c).toEqual({ value: crc32c(request.data) });
      const signature = nodeSign(null, request.data, key.privateKey);
      const response: SignResponse = {
        name: request.name,
        signature,
        signatureCrc32c: { value: crc32c(signature) },
        verifiedDataCrc32c: true,
        protectionLevel: 'SOFTWARE',
      };
      return [response, undefined, undefined] as const;
    }),
  } satisfies GcpCloudKmsClient;
  const provider = await GcpCloudKmsKeyProvider.load(client, config);
  expect(allocations).toHaveLength(0);
  expect(client.createCryptoKeyVersion).not.toHaveBeenCalled();
  const payload = Buffer.from('known62 independent pending signing boundary', 'utf8');

  async function assertActiveUnchanged(): Promise<void> {
    assertPublicJwk(await provider.signingKey(), active);
    expect(await provider.listKeyIds()).toEqual([active.kid]);
    const signature = await provider.sign(payload);
    expect(nodeVerify(null, payload, active.publicKey, signature)).toBe(true);
    for (const pending of allocations) {
      expect(nodeVerify(null, payload, pending.key.publicKey, signature)).toBe(false);
    }
    expect(config).toEqual(before);
  }

  async function assertPendingUsable(kid: string, key: FixtureKey): Promise<void> {
    const jwk = await provider.jwk(kid);
    assertPublicJwk(jwk, key);
    const signature = await provider.signKey(kid, payload);
    const consumerPublicKey = createPublicKey({ key: key.publicJwk, format: 'jwk' });
    expect(nodeVerify(null, payload, consumerPublicKey, signature)).toBe(true);
    expect(nodeVerify(null, payload, active.publicKey, signature)).toBe(false);
    for (const other of allocations) {
      if (other.key !== key) expect(nodeVerify(null, payload, other.key.publicKey, signature)).toBe(false);
    }
  }

  await assertActiveUnchanged();
  expect(allocations).toHaveLength(0);
  expect(client.createCryptoKeyVersion).not.toHaveBeenCalled();
  // When: generation is explicit; no activation is requested.
  const firstKid = await provider.generateKey();
  expect(allocations).toHaveLength(1);
  expect(firstKid).toBe(allocations[0]!.key.kid);
  await assertPendingUsable(firstKid, allocations[0]!.key);
  await assertActiveUnchanged();

  const secondKid = await provider.generateKey();
  // Then: both generations are fresh under the same parent and remain pending.
  expect(allocations).toHaveLength(2);
  expect(allocations.map(({ name }) => name)).toEqual([
    `${parent}/cryptoKeyVersions/101`, `${parent}/cryptoKeyVersions/102`,
  ]);
  expect(new Set([active.kid, firstKid, secondKid]).size).toBe(3);
  expect(secondKid).toBe(allocations[1]!.key.kid);
  await assertPendingUsable(secondKid, allocations[1]!.key);
  await assertPendingUsable(firstKid, allocations[0]!.key);
  await assertActiveUnchanged();

  // Supplementary traps only; the public signer/configuration checks are primary.
  for (const [name, spy] of Object.entries(traps)) {
    if (name !== 'createCryptoKeyVersion' && name !== 'asymmetricSign') {
      expect(spy).not.toHaveBeenCalled();
    }
  }
});
