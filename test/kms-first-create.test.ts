import crypto, { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import { syncBuiltinESMExports } from 'node:module';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { IdentityManager, LogRegistry } from '@dnsid-ai/protocol';
import type { DnsIdJWK } from '@dnsid-ai/protocol';
import { AwsKmsKeyProvider, AwsSdkKmsFacade } from '@dnsid-ai/key-aws';
import type { AwsSdkKmsClient } from '@dnsid-ai/key-aws';
import { GcpCloudKmsKeyProvider } from '@dnsid-ai/key-gcp';

// #58: compliance@df23a7cdd2e5acfe0c23ca832acbe35225496936,
// docs/sdk-design/01 (KMS-first creation), 12 (parent validation/open-only).
// All service dependencies are fake; crypto identity checks use independent fixtures.
const ARN = 'arn:aws:kms:us-east-1:111122223333:key/11111111-1111-4111-8111-111111111111';
const OTHER_ARN = ARN.replace('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222');
const PARENT = 'projects/first/locations/global/keyRings/agents/cryptoKeys/operational';
const VERSION = `${PARENT}/cryptoKeyVersions/1`;
const MESSAGE = new Uint8Array([0, 255, 128, 42, 10, 0, 13]);
const AWS_CONFIG = { algorithm: 'ED25519_SHA_512', keySpec: 'ECC_NIST_EDWARDS25519' } as const;
const GCP_CONFIG = { parent: PARENT, algorithm: 'EC_SIGN_ED25519' } as const;

// Independent RFC8032 test1 seed; private key remains in fake-service closure.
// Production crypto/JWK/thumbprint helpers are not expected-value oracles.
function fixture(seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60') {
  const privateKey = createPrivateKey({ key: Buffer.from('302e020100300506032b657004220420' + seed, 'hex'), format: 'der', type: 'pkcs8' });
  const publicKey = createPublicKey(privateKey);
  const jwk = { crv: 'Ed25519', kty: 'OKP', x: publicKey.export({ format: 'jwk' }).x! };
  return { publicKey, jwk, kid: createHash('sha256').update(JSON.stringify(jwk)).digest('base64url'),
    der: new Uint8Array(publicKey.export({ format: 'der', type: 'spki' })),
    pem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    remoteSign: (data: Uint8Array) => new Uint8Array(sign(null, data, privateKey)) };
}
function crc(bytes: Uint8Array) {
  let c = 0xffffffff;
  for (const b of bytes) { c ^= b; for (let i = 0; i < 8; i++) c = (c >>> 1) ^ ((c & 1) ? 0x82f63b78 : 0); }
  return (c ^ 0xffffffff) >>> 0;
}
function awsCloud() {
  const f = fixture(); let exists = false;
  const client = {
    createSigningKey: vi.fn(async (_input: unknown) => { exists = true; return { keyId: ARN }; }),
    getPublicKey: vi.fn(async ({ keyId }: { keyId: string }) => {
      if (!exists || keyId !== ARN) throw new Error('no such remote key');
      return { keyId: ARN, publicKey: f.der, keySpec: 'ECC_NIST_EDWARDS25519', keyUsage: 'SIGN_VERIFY', signingAlgorithms: ['ED25519_SHA_512'] };
    }),
    sign: vi.fn(async (input: { keyId: string; message: Uint8Array; messageType: string; signingAlgorithm: string }) => {
      expect(input.keyId).toBe(ARN); expect(input.messageType).toBe('RAW'); expect(input.signingAlgorithm).toBe('ED25519_SHA_512');
      return { keyId: ARN, signingAlgorithm: 'ED25519_SHA_512', signature: f.remoteSign(input.message) };
    }),
    scheduleKeyDeletion: vi.fn(async () => { throw new Error('remote deletion forbidden'); }),
    importKeyMaterial: vi.fn(), destroy: vi.fn(),
  };
  return { client, f };
}
function gcpCloud() {
  const f = fixture(); let exists = false;
  const metadata = { name: VERSION, state: 'ENABLED', algorithm: 'EC_SIGN_ED25519', protectionLevel: 'SOFTWARE' };
  const client = {
    // Native parent metadata is validated before creating the first version.
    getCryptoKey: vi.fn(async ({ name }: { name: string }) => {
      expect(name).toBe(PARENT);
      return [{ name: PARENT, purpose: 'ASYMMETRIC_SIGN', versionTemplate: { algorithm: 'EC_SIGN_ED25519', protectionLevel: 'SOFTWARE' } }];
    }),
    createCryptoKeyVersion: vi.fn(async ({ parent }: { parent: string; cryptoKeyVersion: { state: 'ENABLED' } }) => {
      expect(parent).toBe(PARENT); exists = true; return [{ ...metadata }];
    }),
    getCryptoKeyVersion: vi.fn(async ({ name }: { name: string }) => {
      if (!exists || name !== VERSION) throw new Error('no prior version exists');
      return [{ ...metadata }];
    }),
    getPublicKey: vi.fn(async ({ name }: { name: string }) => {
      if (!exists || name !== VERSION) throw new Error('no prior version exists');
      return [{ name: VERSION, algorithm: 'EC_SIGN_ED25519', protectionLevel: 'SOFTWARE', pem: f.pem, pemCrc32c: { value: crc(Buffer.from(f.pem)) } }];
    }),
    asymmetricSign: vi.fn(async ({ name, data, dataCrc32c }: { name: string; data: Uint8Array; dataCrc32c: { value: number } }) => {
      expect(name).toBe(VERSION); expect(dataCrc32c.value).toBe(crc(data));
      const signature = f.remoteSign(data);
      return [{ name: VERSION, signature, signatureCrc32c: { value: crc(signature) }, verifiedDataCrc32c: true }];
    }),
    createCryptoKey: vi.fn(), importCryptoKeyVersion: vi.fn(), destroyCryptoKeyVersion: vi.fn(), close: vi.fn(),
  };
  return { client, f };
}
function publicIdentity(actual: DnsIdJWK, f: ReturnType<typeof fixture>, kid: string, expectedKid = f.kid) {
  // AWS preserves canonical KMS-reference kids; GCP uses RFC7638 kids. Neither
  // substitutes kid equality for independently checking public-key identity.
  expect(kid).toBe(expectedKid); expect(kid).not.toContain('#');
  expect(actual).toMatchObject({ ...f.jwk, kid, alg: 'EdDSA' }); expect(actual).not.toHaveProperty('d');
  const thumbprint = createHash('sha256').update(JSON.stringify({ crv: actual.crv, kty: actual.kty, x: actual.x })).digest('base64url');
  expect(thumbprint).toBe(f.kid);
}
function verified(signature: Uint8Array, f: ReturnType<typeof fixture>) {
  expect(signature).toHaveLength(64); expect(verify(null, MESSAGE, f.publicKey, signature)).toBe(true);
  expect(verify(null, new Uint8Array([1, ...MESSAGE]), f.publicKey, signature)).toBe(false);
}
function noAwsMutation(c: ReturnType<typeof awsCloud>['client']) {
  expect(c.scheduleKeyDeletion).not.toHaveBeenCalled(); expect(c.importKeyMaterial).not.toHaveBeenCalled(); expect(c.destroy).not.toHaveBeenCalled();
}
function noGcpMutation(c: ReturnType<typeof gcpCloud>['client']) {
  expect(c.createCryptoKey).not.toHaveBeenCalled(); expect(c.importCryptoKeyVersion).not.toHaveBeenCalled(); expect(c.destroyCryptoKeyVersion).not.toHaveBeenCalled(); expect(c.close).not.toHaveBeenCalled();
}

describe('#58 AWS native first key', () => {
  it('Given zero keys, When create then activate and reopen, Then immutable identity and independently verified raw signatures persist [Mode: real-capable]', async () => {
    const { client, f } = awsCloud(); const config = { ...AWS_CONFIG };
    const { provider, kid, keyRef } = await AwsKmsKeyProvider.create(client, config);
    expect(provider).toBeInstanceOf(AwsKmsKeyProvider); expect(keyRef).toBe(ARN);
    expect(client.createSigningKey).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ keySpec: 'ECC_NIST_EDWARDS25519' }));
    expect(await provider.listKeyIds()).toEqual([]);
    await expect(provider.sign(MESSAGE)).rejects.toThrow(); await expect(provider.signingKey()).rejects.toThrow();
    publicIdentity(await provider.jwk(kid), f, kid, ARN); verified(await provider.signKey(kid, MESSAGE), f);
    expect(provider.stateSnapshot()).toMatchObject({ pendingKeyIds: [keyRef] }); expect(provider.stateSnapshot().activeKeyId).toBeFalsy();
    await provider.activate(kid); expect(await provider.listKeyIds()).toEqual([kid]);
    publicIdentity(await provider.signingKey(), f, kid, ARN); verified(await provider.sign(MESSAGE), f);
    expect(provider.stateSnapshot().activeKeyId).toBe(keyRef);
    const reopened = await AwsKmsKeyProvider.load(client, { ...AWS_CONFIG, activeKeyId: keyRef });
    publicIdentity(await reopened.signingKey(), f, kid, ARN); verified(await reopened.sign(MESSAGE), f);
    expect(client.createSigningKey).toHaveBeenCalledTimes(1); expect(config).toEqual(AWS_CONFIG); noAwsMutation(client);
    expect(client.getPublicKey.mock.calls.every(([input]) => input.keyId === ARN)).toBe(true);
  });
  for (const fault of ['denied', 'service', 'missing-ref', 'mutable-ref', 'public-denied', 'wrong-binding', 'wrong-spec', 'wrong-usage', 'wrong-algorithm', 'bad-public', 'wrong-key-type'] as const) {
    it(`Given ${fault}, When first create fails, Then no result, recreation, import, deletion or caller disposal [Mode: fake-only]`, async () => {
      const create = AwsKmsKeyProvider.create; const { client } = awsCloud();
      if (fault === 'denied' || fault === 'service') client.createSigningKey.mockRejectedValueOnce(new Error(fault));
      if (fault === 'missing-ref') client.createSigningKey.mockResolvedValueOnce({ keyId: '' });
      if (fault === 'mutable-ref') client.createSigningKey.mockResolvedValueOnce({ keyId: 'alias/first' });
      if (fault === 'public-denied') client.getPublicKey.mockRejectedValueOnce(new Error('access denied'));
      const get = client.getPublicKey.getMockImplementation()!;
      if (['wrong-binding', 'wrong-spec', 'wrong-usage', 'wrong-algorithm', 'bad-public', 'wrong-key-type'].includes(fault)) client.getPublicKey.mockImplementationOnce(async input => {
        const result = await get(input);
        if (fault === 'wrong-binding') result.keyId = OTHER_ARN;
        if (fault === 'wrong-spec') result.keySpec = 'ECC_NIST_P256';
        if (fault === 'wrong-usage') result.keyUsage = 'ENCRYPT_DECRYPT';
        if (fault === 'wrong-algorithm') result.signingAlgorithms = ['ECDSA_SHA_256'];
        if (fault === 'bad-public') result.publicKey = new Uint8Array([1, 2, 3]);
        if (fault === 'wrong-key-type') result.publicKey = new Uint8Array(crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'der' }));
        return result;
      });
      await expect(create(client, { ...AWS_CONFIG })).rejects.toThrow();
      expect(client.createSigningKey).toHaveBeenCalledTimes(1); noAwsMutation(client);
    });
  }
  for (const fault of ['wrong-key', 'wrong-algorithm'] as const) {
    it(`Given ${fault} sign response, When pending proof signs, Then reject without activation [Mode: fake-only]`, async () => {
      const { client } = awsCloud(); const { provider, kid } = await AwsKmsKeyProvider.create(client, { ...AWS_CONFIG });
      const original = client.sign.getMockImplementation()!;
      client.sign.mockImplementationOnce(async input => ({ ...await original(input), ...(fault === 'wrong-key' ? { keyId: OTHER_ARN } : { signingAlgorithm: 'ECDSA_SHA_256' }) }));
      await expect(provider.signKey(kid, MESSAGE)).rejects.toThrow(); expect(await provider.listKeyIds()).toEqual([]);
      await expect(provider.sign(MESSAGE)).rejects.toThrow(); expect(client.createSigningKey).toHaveBeenCalledTimes(1); noAwsMutation(client);
    });
  }
});

// F1/F2: native public creation binding, derived from shared 01 and independent
// externally observed response cases, not provider implementation details.
describe('#58 AWS initial creation resource binding', () => {
  it('F1 Given omitted public-response keyId, When creating, Then reject despite valid Ed25519 public material [Mode: fake-only]', async () => {
    const { client } = awsCloud();
    const unbound = {
      ...client,
      getPublicKey: vi.fn(async (input: { keyId: string }) => {
        const { keyId: _omitted, ...publicMaterial } = await client.getPublicKey(input);
        return publicMaterial;
      }),
    };
    await expect(AwsKmsKeyProvider.create(unbound, { ...AWS_CONFIG })).rejects.toThrow();
    expect(client.createSigningKey).toHaveBeenCalledTimes(1);
    expect(unbound.getPublicKey).toHaveBeenCalledExactlyOnceWith({ keyId: ARN });
    expect(client.sign).not.toHaveBeenCalled(); noAwsMutation(client);
  });

  // Real AwsSdkKmsFacade, fake SDK transport: no AWS network or credentials.
  // CreateKey supplies only its immutable UUID; GetPublicKey supplies the ARN.
  function nativeUuidCloud(publicArn: string) {
    const f = fixture(); const uuid = '11111111-1111-4111-8111-111111111111';
    let created = false;
    const send = vi.fn(async (command: { constructor: { name: string }; input: Record<string, unknown> }) => {
      switch (command.constructor.name) {
        case 'CreateKeyCommand':
          expect(created).toBe(false); created = true;
          expect(command.input).toMatchObject({ KeySpec: 'ECC_NIST_EDWARDS25519', KeyUsage: 'SIGN_VERIFY' });
          return { KeyMetadata: { KeyId: uuid } }; // Arn deliberately absent.
        case 'GetPublicKeyCommand':
          expect(created).toBe(true); expect([uuid, ARN]).toContain(command.input.KeyId);
          return { KeyId: publicArn, PublicKey: f.der, KeySpec: 'ECC_NIST_EDWARDS25519', KeyUsage: 'SIGN_VERIFY', SigningAlgorithms: ['ED25519_SHA_512'] };
        case 'SignCommand':
          expect(created).toBe(true);
          expect(command.input).toMatchObject({ KeyId: ARN, MessageType: 'RAW', SigningAlgorithm: 'ED25519_SHA_512' });
          return { KeyId: ARN, SigningAlgorithm: 'ED25519_SHA_512', Signature: f.remoteSign(command.input.Message as Uint8Array) };
        default: throw new Error(`unexpected SDK command: ${command.constructor.name}`);
      }
    });
    const destroy = vi.fn();
    const facade = new AwsSdkKmsFacade({ send, destroy } as unknown as AwsSdkKmsClient);
    const commands = () => send.mock.calls.map(([command]) => command.constructor.name);
    return { f, facade, send, destroy, commands, uuid };
  }

  it('F2 Given native CreateKey bare UUID fallback, When public response has matching ARN, Then succeed with canonical ARN kid and immutable reopen [Mode: fake-only]', async () => {
    const { f, facade, send, destroy, commands, uuid } = nativeUuidCloud(ARN);
    const creation = AwsKmsKeyProvider.create(facade, { ...AWS_CONFIG });
    await expect(creation).resolves.toMatchObject({ kid: ARN, keyRef: ARN });
    const { provider, kid, keyRef } = await creation;
    expect(commands().slice(0, 2)).toEqual(['CreateKeyCommand', 'GetPublicKeyCommand']);
    expect(send.mock.calls[1]![0].input).toEqual({ KeyId: uuid });
    expect(provider.stateSnapshot()).toMatchObject({ pendingKeyIds: [ARN] });
    expect(provider.stateSnapshot().activeKeyId).toBeFalsy();
    expect(await provider.listKeyIds()).toEqual([]);
    await expect(provider.sign(MESSAGE)).rejects.toThrow();
    publicIdentity(await provider.jwk(kid), f, kid, ARN); verified(await provider.signKey(kid, MESSAGE), f);
    await provider.activate(kid);
    publicIdentity(await provider.signingKey(), f, kid, ARN); verified(await provider.sign(MESSAGE), f);
    const reopened = await AwsKmsKeyProvider.load(facade, { ...AWS_CONFIG, activeKeyId: keyRef });
    publicIdentity(await reopened.signingKey(), f, kid, ARN); verified(await reopened.sign(MESSAGE), f);
    expect(commands().filter(name => name === 'CreateKeyCommand')).toHaveLength(1);
    expect(commands().every(name => ['CreateKeyCommand', 'GetPublicKeyCommand', 'SignCommand'].includes(name))).toBe(true);
    expect(destroy).not.toHaveBeenCalled();
  });

  it('F2 Given native CreateKey bare UUID fallback, When public response ARN has unrelated UUID, Then reject without signing or recreation [Mode: fake-only]', async () => {
    const { facade, destroy, commands } = nativeUuidCloud(OTHER_ARN);
    await expect(AwsKmsKeyProvider.create(facade, { ...AWS_CONFIG })).rejects.toThrow();
    expect(commands()).toEqual(['CreateKeyCommand', 'GetPublicKeyCommand']);
    expect(destroy).not.toHaveBeenCalled();
  });
});

describe('#58 GCP native first version', () => {
  it('Given parent but zero versions, When create then activate and reopen, Then exact version identity and raw signatures persist [Mode: real-capable]', async () => {
    const { client, f } = gcpCloud(); const config = { ...GCP_CONFIG };
    const { provider, kid, keyRef } = await GcpCloudKmsKeyProvider.create(client, config);
    expect(provider).toBeInstanceOf(GcpCloudKmsKeyProvider); expect(keyRef).toBe(VERSION);
    expect(client.getCryptoKey).toHaveBeenCalledWith(expect.objectContaining({ name: PARENT }));
    expect(client.createCryptoKeyVersion).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ parent: PARENT }));
    expect(await provider.listKeyIds()).toEqual([]); await expect(provider.sign(MESSAGE)).rejects.toThrow(); await expect(provider.signingKey()).rejects.toThrow();
    publicIdentity(await provider.jwk(kid), f, kid); verified(await provider.signKey(kid, MESSAGE), f);
    await provider.activate(kid); publicIdentity(await provider.signingKey(), f, kid);
    expect(await provider.listKeyIds()).toEqual([kid]); verified(await provider.sign(MESSAGE), f);
    const reopened = await GcpCloudKmsKeyProvider.load(client, { activeKeyVersion: keyRef, algorithm: GCP_CONFIG.algorithm });
    publicIdentity(await reopened.signingKey(), f, kid); verified(await reopened.sign(MESSAGE), f);
    expect(client.createCryptoKeyVersion).toHaveBeenCalledTimes(1);
    expect(client.getPublicKey.mock.calls.every(([request]) => request.name === VERSION)).toBe(true);
    expect(client.getCryptoKeyVersion.mock.calls.every(([request]) => request.name === VERSION)).toBe(true);
    expect(config).toEqual(GCP_CONFIG); noGcpMutation(client);
  });
  for (const fault of ['create-denied', 'service', 'parent-denied', 'wrong-purpose', 'wrong-template', 'wrong-parent-binding', 'missing-ref', 'foreign-parent', 'parent-only', 'wrong-algorithm', 'disabled', 'destroyed', 'public-denied', 'wrong-binding', 'bad-pem', 'pem-integrity', 'wrong-key-type'] as const) {
    it(`Given ${fault}, When first version create fails, Then no fallback, recreation or caller disposal [Mode: fake-only]`, async () => {
      const create = GcpCloudKmsKeyProvider.create; const { client } = gcpCloud();
      if (fault === 'parent-denied') client.getCryptoKey.mockRejectedValueOnce(new Error('parent denied'));
      if (fault === 'wrong-purpose' || fault === 'wrong-template' || fault === 'wrong-parent-binding') {
        const get = client.getCryptoKey.getMockImplementation()!;
        client.getCryptoKey.mockImplementationOnce(async input => {
          const [parent] = await get(input);
          if (fault === 'wrong-parent-binding') parent.name = PARENT + '-other';
          if (fault === 'wrong-purpose') parent.purpose = 'ENCRYPT_DECRYPT'; else if (fault === 'wrong-template') parent.versionTemplate.algorithm = 'RSA_SIGN_PKCS1_2048_SHA256';
          return [parent];
        });
      }
      if (fault === 'create-denied' || fault === 'service') client.createCryptoKeyVersion.mockRejectedValueOnce(new Error(fault));
      const generate = client.createCryptoKeyVersion.getMockImplementation()!;
      if (['missing-ref', 'foreign-parent', 'parent-only', 'wrong-algorithm', 'disabled', 'destroyed'].includes(fault)) client.createCryptoKeyVersion.mockImplementationOnce(async input => {
        const [version] = await generate(input);
        if (fault === 'missing-ref') version.name = '';
        if (fault === 'foreign-parent') version.name = VERSION.replace('/cryptoKeys/operational/', '/cryptoKeys/other/');
        if (fault === 'parent-only') version.name = PARENT;
        if (fault === 'wrong-algorithm') version.algorithm = 'RSA_SIGN_PKCS1_2048_SHA256';
        if (fault === 'disabled') version.state = 'DISABLED'; if (fault === 'destroyed') version.state = 'DESTROYED';
        return [version];
      });
      if (fault === 'public-denied') client.getPublicKey.mockRejectedValueOnce(new Error('public denied'));
      const get = client.getPublicKey.getMockImplementation()!;
      if (['wrong-binding', 'bad-pem', 'pem-integrity', 'wrong-key-type'].includes(fault)) client.getPublicKey.mockImplementationOnce(async input => {
        const [pub] = await get(input);
        if (fault === 'wrong-binding') pub.name = VERSION.replace('/1', '/2');
        if (fault === 'bad-pem') { pub.pem = 'not a public key'; pub.pemCrc32c.value = crc(Buffer.from(pub.pem)); }
        if (fault === 'pem-integrity') pub.pemCrc32c.value ^= 1;
        if (fault === 'wrong-key-type') { pub.pem = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'pem' }).toString(); pub.pemCrc32c.value = crc(Buffer.from(pub.pem)); }
        return [pub];
      });
      await expect(create(client, { ...GCP_CONFIG })).rejects.toThrow();
      if (['parent-denied', 'wrong-purpose', 'wrong-template', 'wrong-parent-binding'].includes(fault)) expect(client.createCryptoKeyVersion).not.toHaveBeenCalled();
      else expect(client.createCryptoKeyVersion).toHaveBeenCalledTimes(1);
      noGcpMutation(client);
    });
  }
  it('Given PENDING_GENERATION, When same version becomes ready, Then poll without recreation and remain locally pending [Mode: fake-only]', async () => {
    const { client } = gcpCloud(); const generate = client.createCryptoKeyVersion.getMockImplementation()!;
    client.createCryptoKeyVersion.mockImplementationOnce(async input => { const [v] = await generate(input); return [{ ...v, state: 'PENDING_GENERATION' }]; });
    const { provider, keyRef, kid } = await GcpCloudKmsKeyProvider.create(client, { ...GCP_CONFIG });
    expect(keyRef).toBe(VERSION); expect(client.getCryptoKeyVersion).toHaveBeenCalledWith(expect.objectContaining({ name: VERSION }));
    expect(client.createCryptoKeyVersion).toHaveBeenCalledTimes(1); expect(await provider.listKeyIds()).toEqual([]);
    await expect(provider.sign(MESSAGE)).rejects.toThrow(); expect(await provider.jwk(kid)).toHaveProperty('kid', kid); noGcpMutation(client);
  });
  // QA F1: shared 01 KMS-first creation and 12 Google Cloud KMS Ed25519;
  // public declaration requires SOFTWARE protection and caller-owned lifetime.
  // Characterizes unchanged behavior: valid initial pending metadata does not
  // authorize accepting a later invalid readiness observation.
  for (const fault of ['wrong-version', 'wrong-algorithm', 'wrong-protection', 'disabled', 'destroyed',
    'missing-name', 'missing-state', 'missing-algorithm', 'missing-protection', 'missing-metadata',
    'permission-denied', 'service-unavailable'] as const) {
    it(`Given valid pending creation then polling ${fault}, When public create awaits readiness, Then reject without public read, signing, fallback or cleanup [Mode: fake-only]`, async () => {
      const { client } = gcpCloud();
      const generate = client.createCryptoKeyVersion.getMockImplementation()!;
      client.createCryptoKeyVersion.mockImplementationOnce(async input => {
        const [version] = await generate(input);
        return [{ ...version, state: 'PENDING_GENERATION' }];
      });
      const metadata: Record<string, unknown> = {
        name: VERSION, state: 'ENABLED', algorithm: 'EC_SIGN_ED25519', protectionLevel: 'SOFTWARE',
      };
      if (fault === 'wrong-version') metadata.name = `${PARENT}/cryptoKeyVersions/2`;
      if (fault === 'wrong-algorithm') metadata.algorithm = 'RSA_SIGN_PKCS1_2048_SHA256';
      if (fault === 'wrong-protection') metadata.protectionLevel = 'HSM';
      if (fault === 'disabled') metadata.state = 'DISABLED';
      if (fault === 'destroyed') metadata.state = 'DESTROYED';
      if (fault === 'missing-name') delete metadata.name;
      if (fault === 'missing-state') delete metadata.state;
      if (fault === 'missing-algorithm') delete metadata.algorithm;
      if (fault === 'missing-protection') delete metadata.protectionLevel;
      const poll = vi.fn(async (_request: { name: string }): Promise<readonly unknown[]> => {
        if (fault === 'permission-denied' || fault === 'service-unavailable') throw new Error(fault);
        return fault === 'missing-metadata' ? [] : [metadata];
      });
      const nativeClient = { ...client, getCryptoKeyVersion: poll };
      // Same narrow custody instrumentation as the existing success/failure
      // guards. Build fake-service private material before installing traps.
      const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'dnsid58-'));
      const cwd = process.cwd(); const traps: ReturnType<typeof vi.spyOn>[] = [];
      const forbidden = () => { throw new Error('forbidden local custody operation'); };
      const importKey = crypto.subtle.importKey.bind(crypto.subtle);
      let privateImports = 0;
      vi.useFakeTimers();
      try {
        process.chdir(directory);
        traps.push(vi.spyOn(crypto, 'generateKeyPair').mockImplementation(forbidden), vi.spyOn(crypto, 'generateKeyPairSync').mockImplementation(forbidden));
        traps.push(vi.spyOn(crypto.subtle, 'generateKey').mockImplementation(forbidden), vi.spyOn(crypto, 'createPrivateKey').mockImplementation(forbidden));
        traps.push(vi.spyOn(fs, 'writeFileSync').mockImplementation(forbidden), vi.spyOn(fs, 'writeFile').mockImplementation(forbidden), vi.spyOn(fsp, 'writeFile').mockImplementation(forbidden));
        traps.push(vi.spyOn(fs, 'mkdirSync').mockImplementation(forbidden), vi.spyOn(fsp, 'mkdir').mockImplementation(forbidden));
        const importTrap = vi.spyOn(crypto.subtle, 'importKey').mockImplementation((...args: Parameters<typeof crypto.subtle.importKey>) => {
          const format: string = args[0]; const data: unknown = args[1];
          if (format === 'pkcs8' || (format === 'jwk' && data !== null && typeof data === 'object' && 'd' in data)) {
            privateImports++; return Promise.reject(new Error('private-key import forbidden'));
          }
          return importKey(...args);
        });
        traps.push({ mockRestore: importTrap.mockRestore.bind(importTrap) } as ReturnType<typeof vi.spyOn>);
        syncBuiltinESMExports();
        // Attach rejection handling before advancing existing fake timer controls.
        const rejection = expect(GcpCloudKmsKeyProvider.create(nativeClient, { ...GCP_CONFIG })).rejects.toThrow();
        await vi.runAllTimersAsync(); await rejection;
        expect(client.createCryptoKeyVersion).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ parent: PARENT }));
        expect(poll).toHaveBeenCalledExactlyOnceWith({ name: VERSION });
        expect(client.getPublicKey).not.toHaveBeenCalled(); expect(client.asymmetricSign).not.toHaveBeenCalled();
        noGcpMutation(client);
        expect(privateImports).toBe(0);
        for (const trap of traps) if ('mock' in trap) expect(trap).not.toHaveBeenCalled();
        expect(await fsp.readdir(directory)).toEqual([]);
        expect(vi.getTimerCount()).toBe(0);
      } finally {
        for (const trap of traps.reverse()) trap.mockRestore();
        syncBuiltinESMExports();
        vi.useRealTimers(); process.chdir(cwd);
        await fsp.rm(directory, { recursive: true, force: true });
        expect(fs.existsSync(directory)).toBe(false);
      }
    });
  }
  it('Given permanently pending version, When readiness budget expires, Then fail boundedly without recreation [Mode: fake-only]', async () => {
    const create = GcpCloudKmsKeyProvider.create; const { client } = gcpCloud(); const generate = client.createCryptoKeyVersion.getMockImplementation()!;
    client.createCryptoKeyVersion.mockImplementationOnce(async input => { const [v] = await generate(input); return [{ ...v, state: 'PENDING_GENERATION' }]; });
    client.getCryptoKeyVersion.mockResolvedValue([{ name: VERSION, state: 'PENDING_GENERATION', algorithm: 'EC_SIGN_ED25519', protectionLevel: 'SOFTWARE' }]);
    vi.useFakeTimers();
    try {
      const result = create(client, { ...GCP_CONFIG }).then(value => ({ ok: true, value }), error => ({ ok: false, error }));
      await vi.runAllTimersAsync(); expect(await result).toMatchObject({ ok: false });
      expect(client.createCryptoKeyVersion).toHaveBeenCalledTimes(1); noGcpMutation(client);
    } finally { vi.useRealTimers(); }
  });
  for (const fault of ['wrong-name', 'unverified-data', 'signature-integrity'] as const) {
    it(`Given ${fault}, When pending proof receives corrupt response, Then fail with no partial activation [Mode: fake-only]`, async () => {
      const { client } = gcpCloud(); const { provider, kid } = await GcpCloudKmsKeyProvider.create(client, { ...GCP_CONFIG });
      const original = client.asymmetricSign.getMockImplementation()!;
      client.asymmetricSign.mockImplementationOnce(async input => {
        const [result] = await original(input);
        if (fault === 'wrong-name') result.name = VERSION.replace('/1', '/2');
        if (fault === 'unverified-data') result.verifiedDataCrc32c = false;
        if (fault === 'signature-integrity') result.signatureCrc32c.value ^= 1;
        return [result];
      });
      await expect(provider.signKey(kid, MESSAGE)).rejects.toThrow(); expect(await provider.listKeyIds()).toEqual([]);
      await expect(provider.sign(MESSAGE)).rejects.toThrow(); expect(client.createCryptoKeyVersion).toHaveBeenCalledTimes(1); noGcpMutation(client);
    });
  }
});

// Invalid native configuration must reject before remote mutation; ordinary load
// semantics are separately pre-characterized by the existing regression suites.
for (const parent of ['', 'alias/current', VERSION]) {
  it(`Given invalid GCP parent ${JSON.stringify(parent)}, When create is requested, Then reject before version creation [Mode: fake-only]`, async () => {
    const create = GcpCloudKmsKeyProvider.create; const { client } = gcpCloud();
    await expect(create(client, { ...GCP_CONFIG, parent })).rejects.toThrow();
    expect(client.createCryptoKeyVersion).not.toHaveBeenCalled(); noGcpMutation(client);
  });
}
it('Given incompatible GCP algorithm, When create is requested, Then reject before metadata or mutation [Mode: fake-only]', async () => {
  const create = GcpCloudKmsKeyProvider.create; const { client } = gcpCloud();
  await expect(create(client, { ...GCP_CONFIG, algorithm: 'RSA_SIGN_PKCS1_2048_SHA256' })).rejects.toThrow();
  expect(client.getCryptoKey).not.toHaveBeenCalled(); expect(client.createCryptoKeyVersion).not.toHaveBeenCalled(); noGcpMutation(client);
});
it('Given incompatible AWS spec and algorithm, When create is requested, Then reject before creation [Mode: fake-only]', async () => {
  const create = AwsKmsKeyProvider.create; const { client } = awsCloud();
  await expect(create(client, { algorithm: 'ED25519_SHA_512', keySpec: 'ECC_NIST_P256' })).rejects.toThrow();
  expect(client.createSigningKey).not.toHaveBeenCalled(); noAwsMutation(client);
});

// Separate custody invariants; public-key import is allowed. Fixture creation
// precedes traps, and all traps are restored before isolated directory cleanup.
for (const vendor of ['AWS', 'GCP'] as const) for (const fail of [false, true]) {
  it(`Given ${vendor} ${fail ? 'failure' : 'success'} and empty setup directory, When creating, Then no local generation or key-file fallback [Mode: fake-only]`, async () => {
    const aws = awsCloud(); const gcp = gcpCloud();
    if (fail) { aws.client.createSigningKey.mockRejectedValueOnce(new Error('denied')); gcp.client.createCryptoKeyVersion.mockRejectedValueOnce(new Error('denied')); }
    const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'dnsid58-')); const cwd = process.cwd();
    const traps: ReturnType<typeof vi.spyOn>[] = [];
    const forbidden = () => { throw new Error('forbidden local custody operation'); };
    try {
      process.chdir(directory);
      traps.push(vi.spyOn(crypto, 'generateKeyPair').mockImplementation(forbidden), vi.spyOn(crypto, 'generateKeyPairSync').mockImplementation(forbidden));
      traps.push(vi.spyOn(crypto.subtle, 'generateKey').mockImplementation(forbidden));
      traps.push(vi.spyOn(crypto, 'createPrivateKey').mockImplementation(forbidden));
      const importKey = crypto.subtle.importKey.bind(crypto.subtle);
      let privateImports = 0;
      const importTrap = vi.spyOn(crypto.subtle, 'importKey').mockImplementation((...args: Parameters<typeof crypto.subtle.importKey>) => {
        const format: string = args[0]; const data: unknown = args[1];
        if (format === 'pkcs8' || (format === 'jwk' && data !== null && typeof data === 'object' && 'd' in data)) { privateImports++; return Promise.reject(new Error('private-key import forbidden')); }
        return importKey(...args);
      });
      // Public SPKI/JWK import is legitimate; restore separately, not a no-call assertion.
      const restoreImport = importTrap.mockRestore.bind(importTrap);
      traps.push({ mockRestore: restoreImport } as ReturnType<typeof vi.spyOn>);
      traps.push(vi.spyOn(fs, 'writeFileSync').mockImplementation(forbidden), vi.spyOn(fs, 'writeFile').mockImplementation(forbidden), vi.spyOn(fsp, 'writeFile').mockImplementation(forbidden));
      traps.push(vi.spyOn(fs, 'mkdirSync').mockImplementation(forbidden), vi.spyOn(fsp, 'mkdir').mockImplementation(forbidden));
      syncBuiltinESMExports();
      const operation = vendor === 'AWS'
        ? AwsKmsKeyProvider.create(aws.client, { ...AWS_CONFIG })
        : GcpCloudKmsKeyProvider.create(gcp.client, { ...GCP_CONFIG });
      if (fail) await expect(operation).rejects.toThrow('denied');
      else {
        const result = await operation;
        expect(JSON.stringify({ kid: result.kid, keyRef: result.keyRef, jwk: await result.provider.jwk(result.kid) })).not.toMatch(/PRIVATE KEY|\"d\":/);
        expect(await result.provider.listKeyIds()).toEqual([]);
      }
      expect(privateImports).toBe(0);
      for (const trap of traps) if ('mock' in trap) expect(trap).not.toHaveBeenCalled();
      expect(await fsp.readdir(directory)).toEqual([]); noAwsMutation(aws.client); noGcpMutation(gcp.client);
    } finally {
      for (const trap of traps.reverse()) trap.mockRestore();
      syncBuiltinESMExports();
      process.chdir(cwd);
      await fsp.rm(directory, { recursive: true, force: true });
      expect(fs.existsSync(directory)).toBe(false);
    }
  });
}

// Executable consumer of docs/kms-first-setup.md: real manager composition and
// public getKeySet only. No DNS publication, issuance, status ACTIVE, or live
// cloud interoperability is simulated or claimed. All service dependencies fake.
for (const vendor of ['AWS', 'GCP'] as const) {
  it(`Given new ${vendor} native key, When pending proof then activate and inject into manager then immutable reopen, Then manager JWKS preserves operational identity [Mode: real-capable]`, async () => {
    const aws = awsCloud(); const gcp = gcpCloud();
    // Distinct RFC8032 TEST2 entity key; never sourced from the operational SDK.
    const entity = fixture('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb');
    const f = vendor === 'AWS' ? aws.f : gcp.f;
    const created = vendor === 'AWS'
      ? await AwsKmsKeyProvider.create(aws.client, { ...AWS_CONFIG })
      : await GcpCloudKmsKeyProvider.create(gcp.client, { ...GCP_CONFIG });
    const expectedKid = vendor === 'AWS' ? ARN : f.kid;
    const expectedRef = vendor === 'AWS' ? ARN : VERSION;
    expect(created.keyRef).toBe(expectedRef);
    publicIdentity(await created.provider.jwk(created.kid), f, created.kid, expectedKid);
    expect(await created.provider.listKeyIds()).toEqual([]);
    verified(await created.provider.signKey(created.kid, MESSAGE), f);
    await expect(created.provider.sign(MESSAGE)).rejects.toThrow();
    // App-owned in-memory handoff; no implicit file persistence.
    const saved = { keyRef: created.keyRef, jwk: await created.provider.jwk(created.kid) };
    await created.provider.activate(created.kid);
    const entityJwk: DnsIdJWK = { ...entity.jwk, kid: entity.kid, alg: 'EdDSA', use: 'sig' };
    expect(entity.kid).not.toBe(f.kid);
    const entityKeyProvider = {
      signingKey: async () => entityJwk, jwk: async () => entityJwk,
      listKeyIds: async () => [entity.kid], sign: async (data: Uint8Array) => entity.remoteSign(data),
      signKey: async (_kid: string, data: Uint8Array) => entity.remoteSign(data),
      generateKey: async () => { throw new Error('entity generation forbidden'); },
      activate: async () => { throw new Error('entity activation forbidden'); },
      supersede: async () => { throw new Error('entity supersession forbidden'); },
    };
    const fetchJson = vi.fn(async () => { throw new Error('no publication/network expected'); });
    const fetchTXT = vi.fn(async () => { throw new Error('no DNS expected'); });
    const config = { identity: {
      domain: 'agent.example.com', governanceId: 'example.com',
      logRef: 'microledger:first-setup', statusUrl: 'https://agent.example.com/status',
      ekUrl: 'https://example.com/entity-jwks.json', kuUrl: 'https://agent.example.com/jwks.json',
    } };
    const deps = { entityKeyProvider, logRegistry: new LogRegistry(), fetchJson, dnsResolver: { fetchTXT } };
    const manager = new IdentityManager(config, { ...deps, keyProvider: created.provider });
    expect(manager.getKeyProvider()).toBe(created.provider);
    const published = await manager.getKeySet();
    expect(published.keys).toHaveLength(1);
    publicIdentity(published.keys[0]!, f, created.kid, expectedKid);
    expect((await manager.getEntityKeySet()).keys).toEqual([entityJwk]);
    verified(await manager.getKeyProvider().sign(MESSAGE), f);
    const reopened = vendor === 'AWS'
      ? await AwsKmsKeyProvider.load(aws.client, { ...AWS_CONFIG, activeKeyId: saved.keyRef })
      : await GcpCloudKmsKeyProvider.load(gcp.client, { algorithm: GCP_CONFIG.algorithm, activeKeyVersion: saved.keyRef });
    expect(await reopened.signingKey()).toEqual(saved.jwk);
    const restartConsumer = new IdentityManager(config, { ...deps, keyProvider: reopened });
    expect(await restartConsumer.getKeySet()).toEqual(published);
    verified(await restartConsumer.getKeyProvider().sign(MESSAGE), f);
    expect(fetchJson).not.toHaveBeenCalled(); expect(fetchTXT).not.toHaveBeenCalled();
    expect(aws.client.createSigningKey).toHaveBeenCalledTimes(vendor === 'AWS' ? 1 : 0);
    expect(gcp.client.createCryptoKeyVersion).toHaveBeenCalledTimes(vendor === 'GCP' ? 1 : 0);
    noAwsMutation(aws.client); noGcpMutation(gcp.client);
  });
}

// Shared 01/12: an operator must be able to reconcile the known remote version
// after validation fails; error recovery must not perform another provisioning.
describe('GCP post-create recovery reference', () => {
  for (const fault of ['readiness-permission', 'readiness-timeout', 'public-permission', 'public-binding', 'public-crc'] as const) {
    it(`Given known first version then ${fault}, When public create rejects, Then error retains recovery reference and cause [Mode: fake-only]`, async () => {
      const { client } = gcpCloud();
      const denied = Object.assign(new Error('fixture permission denied'), { code: 7 });
      const create = client.createCryptoKeyVersion.getMockImplementation()!;
      if (fault.startsWith('readiness-')) {
        client.createCryptoKeyVersion.mockImplementationOnce(async input => {
          const [version] = await create(input);
          return [{ ...version, state: 'PENDING_GENERATION' }];
        });
        if (fault === 'readiness-permission') client.getCryptoKeyVersion.mockRejectedValue(denied);
        else client.getCryptoKeyVersion.mockResolvedValue([{ name: VERSION, state: 'PENDING_GENERATION', algorithm: 'EC_SIGN_ED25519', protectionLevel: 'SOFTWARE' }]);
      }
      if (fault === 'public-permission') client.getPublicKey.mockRejectedValue(denied);
      const get = client.getPublicKey.getMockImplementation()!;
      if (fault === 'public-binding' || fault === 'public-crc') client.getPublicKey.mockImplementationOnce(async input => {
        const [pub] = await get(input);
        if (fault === 'public-binding') pub.name = `${PARENT}/cryptoKeyVersions/2`;
        else pub.pemCrc32c.value ^= 1;
        return [pub];
      });
      // Prepare fake private material before installing local-custody traps.
      const forbidden = () => { throw new Error('forbidden local custody'); };
      const traps = [vi.spyOn(crypto, 'generateKeyPair').mockImplementation(forbidden),
        vi.spyOn(crypto, 'generateKeyPairSync').mockImplementation(forbidden),
        vi.spyOn(crypto.subtle, 'generateKey').mockImplementation(forbidden),
        vi.spyOn(crypto, 'createPrivateKey').mockImplementation(forbidden)];
      const updateCryptoKeyVersion = vi.fn();
      vi.useFakeTimers();
      try {
        syncBuiltinESMExports();
        const recoveryClient = { ...client, updateCryptoKeyVersion };
        const outcome = GcpCloudKmsKeyProvider.create(recoveryClient, { ...GCP_CONFIG })
          .then(value => ({ value, error: undefined }), (error: unknown) => ({ value: undefined, error }));
        await vi.runAllTimersAsync();
        const result = await outcome;
        expect(result.value).toBeUndefined(); expect(result.error).toBeInstanceOf(Error);
        expect(client.createCryptoKeyVersion).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ parent: PARENT }));
        expect(client.asymmetricSign).not.toHaveBeenCalled(); expect(updateCryptoKeyVersion).not.toHaveBeenCalled();
        noGcpMutation(client);
        if (fault.startsWith('readiness-')) expect(client.getPublicKey).not.toHaveBeenCalled();
        for (const trap of traps) expect(trap).not.toHaveBeenCalled();
        expect(vi.getTimerCount()).toBe(0);
        const error = result.error as Error;
        if (fault.endsWith('permission')) {
          // Wrapping is allowed, but the original native error/code must survive.
          const chain: unknown[] = []; let next: unknown = error;
          while (next instanceof Error && !chain.includes(next)) { chain.push(next); next = next.cause; }
          expect(chain).toContain(denied); expect(denied.code).toBe(7);
        }
        expect(error.message, 'caller needs exact immutable version for operator-owned reconciliation').toContain(VERSION);
      } finally {
        for (const trap of traps.reverse()) trap.mockRestore();
        syncBuiltinESMExports();
        vi.useRealTimers();
      }
    });
  }
});

it('Given named builtin imports through Vite, When custody guard is installed, Then generation and writes are intercepted [Mode: fake-only]', async () => {
  const { namedGeneration, namedWrite, namedAsyncWrite } = await import('./kms-first-custody-canary.js');
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'dnsid58-canary-'));
  const forbidden = () => { throw new Error('forbidden local custody operation'); };
  const traps = [vi.spyOn(crypto, 'generateKeyPairSync').mockImplementation(forbidden),
    vi.spyOn(fs, 'writeFileSync').mockImplementation(forbidden),
    vi.spyOn(fsp, 'writeFile').mockImplementation(forbidden)];
  syncBuiltinESMExports();
  try {
    expect(namedGeneration).toThrow('forbidden local custody operation');
    expect(() => namedWrite(path.join(directory, 'sync'))).toThrow('forbidden local custody operation');
    await expect(async () => namedAsyncWrite(path.join(directory, 'async'))).rejects.toThrow('forbidden local custody operation');
    for (const trap of traps) expect(trap).toHaveBeenCalledTimes(1);
    expect(await fsp.readdir(directory)).toEqual([]);
  } finally {
    for (const trap of traps.reverse()) trap.mockRestore();
    syncBuiltinESMExports();
    await fsp.rm(directory, { recursive: true, force: true });
    expect(fs.existsSync(directory)).toBe(false);
  }
});
