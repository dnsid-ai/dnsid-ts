import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { GcpCloudKmsKeyProvider } from '@dnsid-ai/key-gcp';

/**
 * #56 runtime slice. Authority: dnsid-sdk-compliance@939d241,
 * docs/sdk-design/{README,01-core-identity-manager,12-configuration-loading}.md
 * and docs/key-provider-packages.md. GCP transport details: Cloud KMS v1
 * GetPublicKey / AsymmetricSign, EC_SIGN_ED25519 (SOFTWARE), data not digest.
 * No generation, rotation, retained-key, activation, supersession or purge claims.
 * Every TC below is fake-only for the GCP dependency (response fault injection
 * and transport inspection). No credentials, network, or production key material.
 */
const VERSION = 'projects/test-project/locations/global/keyRings/agents/cryptoKeys/signer/cryptoKeyVersions/7';
const OTHER_VERSION = VERSION.replace(/7$/, '8');
const ALGORITHM = 'EC_SIGN_ED25519';
// RFC 8032 section 7.1 TEST 1; independent of every DNSid provider implementation.
const PUBLIC_HEX = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const SEED_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const EMPTY_SIGNATURE = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f'
  + 'b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';
const privateKey = createPrivateKey({
  key: Buffer.from('302e020100300506032b657004220420' + SEED_HEX, 'hex'),
  format: 'der', type: 'pkcs8',
});
const publicKey = createPublicKey({
  key: Buffer.from('302a300506032b6570032100' + PUBLIC_HEX, 'hex'),
  format: 'der', type: 'spki',
});
const PEM = publicKey.export({ format: 'pem', type: 'spki' }).toString();

// Standalone reflected Castagnoli CRC; not imported from the implementation.
function crc32c(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

type Request = { name?: string; data?: Uint8Array; dataCrc32c?: { value?: number | string }; digest?: unknown };
function cloud() {
  const getPublicKey = vi.fn(async (_request: { name: string }) => [{
    name: VERSION, pem: PEM, algorithm: ALGORITHM, protectionLevel: 'SOFTWARE',
    pemCrc32c: { value: crc32c(Buffer.from(PEM)) },
  }]);
  const asymmetricSign = vi.fn(async (request: Request) => {
    const signature = sign(null, request.data ?? new Uint8Array(), privateKey);
    return [{ name: VERSION, signature, signatureCrc32c: { value: crc32c(signature) }, verifiedDataCrc32c: true }];
  });
  // Structural seam mirrors the official @google-cloud/kms KeyManagementServiceClient.
  // Forbidden methods are traps and are also explicitly asserted untouched.
  const client = {
    getPublicKey, asymmetricSign,
    createCryptoKey: vi.fn(), createCryptoKeyVersion: vi.fn(),
    importCryptoKeyVersion: vi.fn(), updateCryptoKeyPrimaryVersion: vi.fn(),
    destroyCryptoKeyVersion: vi.fn(),
  };
  return client;
}
async function open(client = cloud(), version = VERSION, algorithm = ALGORITHM) {
  const result = await GcpCloudKmsKeyProvider.load(client, { activeKeyVersion: version, algorithm })
    .then(provider => ({ ok: true as const, provider }), error => ({ ok: false as const, error }));
  // A deliberate behavioral assertion: a valid pre-existing software Ed25519
  // version must open. A placeholder rejection is not an uncaught setup failure.
  expect(result, 'Given an existing Ed25519 version, When loaded, Then opening succeeds').toMatchObject({ ok: true });
  if (!result.ok) throw new Error('unreachable after opening assertion');
  return result.provider;
}
function expectNoMutation(client: ReturnType<typeof cloud>) {
  for (const method of ['createCryptoKey', 'createCryptoKeyVersion', 'importCryptoKeyVersion',
    'updateCryptoKeyPrimaryVersion', 'destroyCryptoKeyVersion'] as const) expect(client[method]).not.toHaveBeenCalled();
}

describe('GCP existing-version Ed25519 runtime (#56; Mode: fake-only)', () => {
  it('Given independent RFC fixtures, When checked, Then the oracle matches RFC 8032 and CRC32C', () => {
    expect(crc32c(Buffer.from('123456789'))).toBe(0xe3069283);
    expect(sign(null, Buffer.alloc(0), privateKey).toString('hex')).toBe(EMPTY_SIGNATURE);
    expect(verify(null, Buffer.alloc(0), publicKey, Buffer.from(EMPTY_SIGNATURE, 'hex'))).toBe(true);
  });

  it('Given one immutable version, When reopened, Then the same public-only JWK and safe kid are exposed', async () => {
    const client = cloud();
    const first = await open(client);
    const second = await open(client);
    const jwk = await first.signingKey();
    expect(jwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', x: Buffer.from(PUBLIC_HEX, 'hex').toString('base64url') });
    expect(jwk).not.toHaveProperty('d');
    expect(jwk.kid).toEqual(expect.any(String));
    expect(jwk.kid.length).toBeGreaterThan(0);
    expect(jwk.kid).not.toContain('#');
    expect(await second.signingKey()).toEqual(jwk);
    expect(await first.listKeyIds()).toEqual([jwk.kid]);
    expect(await first.jwk(jwk.kid)).toEqual(jwk);
    expect(client.getPublicKey).toHaveBeenCalledWith(expect.objectContaining({ name: VERSION }));
    expect(client.asymmetricSign).not.toHaveBeenCalled();
    expectNoMutation(client);
  });

  for (const [label, payload] of [
    ['empty', new Uint8Array()],
    ['binary', new Uint8Array([0, 255, 128, 13, 10, 0, 35, 254])],
    ['text', new TextEncoder().encode('DNSid GCP raw Ed25519')],
  ] as const) {
    it(`Given ${label} bytes, When sign and signKey run, Then raw independent signatures bind the exact data`, async () => {
      const client = cloud();
      const provider = await open(client);
      const jwk = await provider.signingKey();
      for (const signature of [await provider.sign(payload), await provider.signKey(jwk.kid, payload)]) {
        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.byteLength).toBe(64);
        expect(Buffer.from(signature)).toEqual(sign(null, payload, privateKey));
        expect(verify(null, payload, publicKey, signature)).toBe(true);
        expect(verify(null, Buffer.concat([payload, Buffer.from([1])]), publicKey, signature)).toBe(false);
      }
      expect(client.asymmetricSign).toHaveBeenCalledTimes(2);
      for (const [request] of client.asymmetricSign.mock.calls) {
        expect(request.name).toBe(VERSION);
        expect(Buffer.from(request.data!)).toEqual(Buffer.from(payload));
        expect(request.digest).toBeUndefined();
        expect(Number(request.dataCrc32c?.value)).toBe(crc32c(payload));
      }
      expectNoMutation(client);
    });
  }

  it('Given an unknown kid, When explicitly signing or looking up, Then no active-key fallback occurs', async () => {
    const client = cloud();
    const provider = await open(client);
    await expect(provider.jwk('unknown-key')).rejects.toThrow();
    await expect(provider.signKey('unknown-key', new Uint8Array([1]))).rejects.toThrow();
    expect(client.asymmetricSign).not.toHaveBeenCalled();
    expectNoMutation(client);
  });

  for (const version of [VERSION.split('/cryptoKeyVersions/')[0], VERSION.replace(/7$/, 'primary'), OTHER_VERSION + '#fragment']) {
    it(`Given non-immutable reference ${version}, When opening, Then reject before cloud work`, async () => {
      const client = cloud();
      await expect(GcpCloudKmsKeyProvider.load(client, { activeKeyVersion: version, algorithm: ALGORITHM })).rejects.toThrow();
      expect(client.getPublicKey).not.toHaveBeenCalled();
      expectNoMutation(client);
    });
  }

  for (const fault of ['algorithm', 'version', 'pem-checksum', 'missing-pem-checksum', 'public-material'] as const) {
    it(`Given ${fault} mismatch, When opening, Then reject the unbound public key`, async () => {
      const client = cloud();
      const [response] = await client.getPublicKey({ name: VERSION });
      client.getPublicKey.mockClear();
      if (fault === 'algorithm') response.algorithm = 'EC_SIGN_P256_SHA256';
      if (fault === 'version') response.name = OTHER_VERSION;
      if (fault === 'pem-checksum') response.pemCrc32c.value ^= 1;
      if (fault === 'missing-pem-checksum') delete (response as Partial<typeof response>).pemCrc32c;
      if (fault === 'public-material') {
        response.pem = 'not a public key';
        response.pemCrc32c = { value: crc32c(Buffer.from(response.pem)) };
      }
      client.getPublicKey.mockResolvedValue([response]);
      await expect(GcpCloudKmsKeyProvider.load(client, { activeKeyVersion: VERSION, algorithm: ALGORITHM }))
        .rejects.toThrow(/algorithm|version|name|crc|checksum|public|pem|key/i);
      expect(client.asymmetricSign).not.toHaveBeenCalled();
      expectNoMutation(client);
    });
  }

  for (const fault of ['version', 'signature-checksum', 'missing-signature-checksum', 'unverified-data', 'short-signature'] as const) {
    it(`Given ${fault} from KMS, When signing, Then no signature is returned`, async () => {
      const client = cloud();
      const provider = await open(client);
      const [response] = await client.asymmetricSign({ name: VERSION, data: new Uint8Array([42]) });
      client.asymmetricSign.mockClear();
      if (fault === 'version') response.name = OTHER_VERSION;
      if (fault === 'signature-checksum') response.signatureCrc32c.value ^= 1;
      if (fault === 'missing-signature-checksum') delete (response as Partial<typeof response>).signatureCrc32c;
      if (fault === 'unverified-data') response.verifiedDataCrc32c = false;
      if (fault === 'short-signature') {
        response.signature = Buffer.alloc(63);
        response.signatureCrc32c = { value: crc32c(response.signature) };
      }
      client.asymmetricSign.mockResolvedValue([response]);
      await expect(provider.sign(new Uint8Array([42]))).rejects.toThrow();
      expectNoMutation(client);
    });
  }

  it('Given KMS permission denial, When signing, Then the failure propagates without a local signer', async () => {
    const client = cloud();
    const provider = await open(client);
    client.asymmetricSign.mockRejectedValue(Object.assign(new Error('permission denied'), { code: 7 }));
    await expect(provider.sign(new Uint8Array([42]))).rejects.toThrow(/permission denied/i);
    expectNoMutation(client);
  });
});
