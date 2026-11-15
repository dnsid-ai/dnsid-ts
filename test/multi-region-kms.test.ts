import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { expect, it } from 'vitest';
import { AwsKmsKeyProvider, type AwsKmsFacade } from '@dnsid-ai/key-aws';
import { GcpCloudKmsKeyProvider } from '@dnsid-ai/key-gcp';

// Regional public binding and cross-signatures. Mode: real-capable, AWS/GCP=fake.
// Synthetic topology is not proof of real replication/location availability.
// Public RFC 8032 section 7.1 TEST 1 seed; never use this fixture for credentials.
const privateKey = createPrivateKey({ key: Buffer.from('302e020100300506032b657004220420'
  + '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex'), format: 'der', type: 'pkcs8' });
const publicBytes = Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex');
const publicKey = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), publicBytes]), format: 'der', type: 'spki' });
const x = publicBytes.toString('base64url');
const thumbprint = (value: string) => createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: value })).digest('base64url');
const thumb = thumbprint(x);
const wrong = createPublicKey(createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32)]), format: 'der', type: 'pkcs8' }));
function crc32c(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) { crc ^= byte; for (let n = 0; n < 8; n++) crc = (crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0); }
  return (crc ^ 0xffffffff) >>> 0;
}
// Synthetic resource identifiers; no cloud account or resource is used.
const arns = ['us-east-1', 'us-west-2'].map(region => `arn:aws:kms:${region}:123456789012:key/mrk-0123456789abcdef0123456789abcdef`);
const version = (location: string) => `projects/fixture/locations/${location}/keyRings/agents/cryptoKeys/signer/cryptoKeyVersions/7`;
function aws(ref: string) {
  const calls: string[] = [];
  const client: AwsKmsFacade = {
    async createSigningKey() { throw new Error('open/sign must not provision'); },
    async scheduleKeyDeletion() { throw new Error('unexpected mutation'); },
    async getPublicKey(input) {
      expect(input.keyId).toBe(ref); calls.push('get');
      return { keyId: ref, publicKey: publicKey.export({ format: 'der', type: 'spki' }), keySpec: 'ECC_NIST_EDWARDS25519', keyUsage: 'SIGN_VERIFY', signingAlgorithms: ['ED25519_SHA_512'] };
    },
    async sign(input) {
      expect(input.keyId).toBe(ref); expect(input.messageType).toBe('RAW'); expect(input.signingAlgorithm).toBe('ED25519_SHA_512'); calls.push('sign');
      return { keyId: ref, signature: sign(null, input.message, privateKey), signingAlgorithm: 'ED25519_SHA_512' };
    },
  };
  return { client, calls };
}
function google(ref: string) {
  const calls: string[] = [];
  const pem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const client = {
    async getPublicKey(input: { name: string }) { expect(input.name).toBe(ref); calls.push('get'); return [{ name: ref, pem, pemCrc32c: { value: crc32c(Buffer.from(pem)) }, algorithm: 'EC_SIGN_ED25519', protectionLevel: 'SOFTWARE' }]; },
    async asymmetricSign(input: { name: string; data: Uint8Array; dataCrc32c: { value: number } }) {
      expect(input.name).toBe(ref); expect(input).not.toHaveProperty('digest'); expect(input.dataCrc32c.value).toBe(crc32c(input.data)); calls.push('sign');
      const signature = sign(null, input.data, privateKey);
      return [{ name: ref, signature, signatureCrc32c: { value: crc32c(signature) }, verifiedDataCrc32c: true }];
    },
    async createCryptoKeyVersion(): Promise<readonly unknown[]> { throw new Error('open/sign must not generate'); },
  };
  return { client, calls };
}
it('Given independent RFC 8032/CRC oracles, When checked, Then they validate and reject unrelated key material', () => {
  const signature = Buffer.from('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b', 'hex');
  expect(verify(null, Buffer.alloc(0), publicKey, signature)).toBe(true);
  expect(sign(null, Buffer.alloc(0), privateKey)).toEqual(signature);
  expect(crc32c(Buffer.from('123456789'))).toBe(0xe3069283);
  expect(thumbprint(wrong.export({ format: 'jwk' }).x!)).not.toBe(thumb);
});
for (const topology of ['aws', 'us', 'global']) {
  it(`Given ${topology} same-key clients, When independently opened and freshly reopened, Then native kids and cross-signatures remain bound`, async () => {
    // Given exact regional ARNs, or ONE identical numeric version per location.
    const refs = topology === 'aws' ? arns : [version(topology), version(topology)];
    const signatures: Uint8Array[] = [];
    const publics: ReturnType<typeof createPublicKey>[] = [];
    const payload = Buffer.from('bounded RAW cross-region payload');
    for (let reopen = 0; reopen < 2; reopen++) for (const ref of refs) {
      // When each provider uses a separate fresh client; no saved application state.
      const fixture = topology === 'aws' ? aws(ref) : google(ref);
      const provider = topology === 'aws'
        ? await AwsKmsKeyProvider.load(fixture.client as AwsKmsFacade, { activeKeyId: ref, algorithm: 'ED25519_SHA_512' })
        : await GcpCloudKmsKeyProvider.load(fixture.client as ReturnType<typeof google>['client'], { activeKeyVersion: ref, algorithm: 'EC_SIGN_ED25519' });
      const key = await provider.signingKey();
      expect(key).toMatchObject({ kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', x }); expect(key).not.toHaveProperty('d');
      expect(thumbprint(key.x!)).toBe(thumb);
      const kid = topology === 'aws' ? ref : thumb;
      expect(key.kid).toBe(kid); expect(await provider.listKeyIds()).toEqual([kid]);
      expect(await provider.jwk(kid)).toMatchObject({ kid, x });
      publics.push(createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key.x }, format: 'jwk' }));
      signatures.push(await provider.sign(payload));
      signatures.push(await provider.signKey(kid, payload));
      expect(fixture.calls).toEqual(['get', 'sign', 'sign']);
    }
    // Then every independent signature verifies against the other clients' keys.
    for (const signature of signatures) {
      for (const key of publics) expect(verify(null, payload, key, signature)).toBe(true);
      expect(verify(null, Buffer.concat([payload, Buffer.from('tampered')]), publicKey, signature)).toBe(false);
      expect(verify(null, payload, wrong, signature)).toBe(false);
    }
  });
}

// Regional configuration binding. Mode: real-capable (AWS=fake); fake-only wrong response binding.
it('Given explicit regional ARN/region/EdDSA config, When freshly opened, Then own endpoint binding is retained without provisioning', async () => {
  const { vi } = await import('vitest');
  const { KMSClient, GetPublicKeyCommand, SignCommand } = await import('@aws-sdk/client-kms');
  const { createAwsKmsKeyProvider } = await import('@dnsid-ai/key-aws');
  const seen: string[] = [];
  let wrongBinding = false;
  const rpc = vi.spyOn(KMSClient.prototype, 'send').mockImplementation(async function (this: InstanceType<typeof KMSClient>, command) {
    const region = await this.config.region();
    const ref = arns.find(value => value.includes(`:${region}:`))!;
    seen.push(command.constructor.name);
    if (command instanceof GetPublicKeyCommand || command instanceof SignCommand) {
      expect(command.input.KeyId).toBe(ref);
    }
    if (command instanceof GetPublicKeyCommand) return { KeyId: wrongBinding ? arns.find(value => value !== ref)! : ref,
      PublicKey: publicKey.export({ format: 'der', type: 'spki' }), KeySpec: 'ECC_NIST_EDWARDS25519', KeyUsage: 'SIGN_VERIFY', SigningAlgorithms: ['ED25519_SHA_512'] };
    if (command instanceof SignCommand) {
      expect(command.input.MessageType).toBe('RAW'); expect(command.input.SigningAlgorithm).toBe('ED25519_SHA_512');
      return { KeyId: ref, SigningAlgorithm: 'ED25519_SHA_512', Signature: sign(null, command.input.Message!, privateKey) };
    }
    throw new Error('unexpected provisioning/fallback RPC');
  });
  try {
    for (let reopen = 0; reopen < 2; reopen++) for (const ref of arns) {
      const provider = await createAwsKmsKeyProvider(ref, { region: ref.split(':')[3], algorithm: 'EdDSA' });
      expect(await provider.signingKey()).toMatchObject({ kid: ref, x });
      expect(verify(null, Buffer.from('config'), publicKey, await provider.sign(Buffer.from('config')))).toBe(true);
    }
    expect(seen).toEqual(Array.from({ length: 4 }, () => ['GetPublicKeyCommand', 'SignCommand']).flat());
    wrongBinding = true;
    await expect(createAwsKmsKeyProvider(arns[0], { region: 'us-east-1', algorithm: 'EdDSA' })).rejects.toThrow();
    expect(seen.at(-1)).toBe('GetPublicKeyCommand');
  } finally { rpc.mockRestore(); }
});

// Mode: fake-only (native AWS responses and fixed verified-publication evidence).
// Real identity-bound configuration path: do not inject an operational provider.
it('Given region A publication, When configuration selects region B with the same public material, Then reject the different regional kid', async () => {
  const { vi } = await import('vitest');
  const { KMSClient, GetPublicKeyCommand } = await import('@aws-sdk/client-kms');
  const { IdentityManager, JWKS } = await import('@dnsid-ai/sdk');
  const { constructIdentityManager, loadEnvironment, mergeLoadedConfig } = await import('@dnsid-ai/sdk/node');
  const seen: string[] = [];
  const rpc = vi.spyOn(KMSClient.prototype, 'send').mockImplementation(async function (this: InstanceType<typeof KMSClient>, command) {
    const region = await this.config.region();
    const ref = arns.find(value => value.includes(`:${region}:`))!;
    if (!(command instanceof GetPublicKeyCommand)) throw new Error('no generation, signing fallback or other RPC permitted');
    expect(command.input.KeyId).toBe(ref);
    seen.push(ref);
    return { KeyId: ref, PublicKey: publicKey.export({ format: 'der', type: 'spki' }),
      KeySpec: 'ECC_NIST_EDWARDS25519', KeyUsage: 'SIGN_VERIFY', SigningAlgorithms: ['ED25519_SHA_512'] };
  });
  // Independently fixed publication: never derive this evidence from the manager
  // under construction (which would hide a region-B/region-A mismatch).
  const published = { kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', kid: arns[0], x };
  const publication = vi.spyOn(IdentityManager.prototype, 'verifyPublicationEvidence')
    .mockResolvedValue({ jwks: new JWKS([published]) } as never);
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
  try {
    const base = await loadEnvironment({ DNSID_DOMAIN: 'alice.example.com', DNSID_GOVERNANCE_ID: 'example.com',
      DNSID_LOG_REF: 'noop:0', DNSID_STATUS_URL: 'https://status.example.com/alice' });
    const configured = (ref: string) => mergeLoadedConfig(base, {
      keySource: { provider: 'aws-kms', keyRef: ref, settings: { region: ref.split(':')[3], algorithm: 'EdDSA' } },
    });
    // Given region A's fixed publication, its matching constructor succeeds.
    const manager = await constructIdentityManager(configured(arns[0]));
    const selectedA = await manager.getKeyProvider().signingKey();
    expect(selectedA).toMatchObject(published);
    expect(thumbprint(selectedA.x!)).toBe(thumb);
    // When only the selected regional ARN/region changes, public material and
    // algorithm still match, but the published kid does not: binding must fail.
    await expect(constructIdentityManager(configured(arns[1]))).rejects.toThrow(/authorized key rotation/);
    expect(publication).toHaveBeenCalledTimes(2);
    expect(publication).toHaveBeenNthCalledWith(1, 'alice.example.com', { refresh: true });
    expect(publication).toHaveBeenNthCalledWith(2, 'alice.example.com', { refresh: true });
    expect(seen).toEqual(arns);
    expect(warn).not.toHaveBeenCalled();
  } finally { rpc.mockRestore(); publication.mockRestore(); warn.mockRestore(); }
});

// Mode: fake-only (AWS call accounting), inclusive RAW bound.
for (const size of [4096, 4097]) it(`AWS RAW size boundary: Given ${size} bytes, When signing, Then enforce the bound before native Sign`, async () => {
  const fixture = aws(arns[0]);
  let creates = 0;
  fixture.client.createSigningKey = async () => { creates++; throw new Error('unexpected generation'); };
  const provider = await AwsKmsKeyProvider.load(fixture.client, { activeKeyId: arns[0], algorithm: 'ED25519_SHA_512' });
  const payload = Buffer.alloc(size, 0x61);
  // The fake signs either size, so rejection must come before native Sign.
  for (const action of [() => provider.sign(payload), () => provider.signKey(arns[0], payload)]) {
    const before = fixture.calls.filter(call => call === 'sign').length;
    const result = await action().then(signature => ({ signature, error: undefined }), error => ({ signature: undefined, error }));
    const nativeCalls = fixture.calls.filter(call => call === 'sign').length - before;
    if (size === 4096) {
      expect(result.error).toBeUndefined(); expect(result.signature).toBeDefined();
      expect(nativeCalls).toBe(1);
      expect(verify(null, payload, publicKey, result.signature!)).toBe(true);
    } else {
      expect.soft(result.error, '4097 bytes must return an error, no substitute signature').toBeDefined();
      expect.soft(result.signature).toBeUndefined();
      expect.soft(nativeCalls, '4097 bytes must fail before native Sign').toBe(0);
    }
  }
  expect(creates).toBe(0);
});

// Alias and omitted-KeyId compatibility. Mode: real-capable (AWS=fake native SDK seam).
for (const referenceMode of ['omitted-KeyId', 'alias-name', 'alias-ARN'] as const) {
  it(`AWS reference compatibility: Given ${referenceMode}, When opened through official facade, Then canonical public binding signs without provisioning`, async () => {
    const { AwsSdkKmsFacade } = await import('@dnsid-ai/key-aws');
    const { GetPublicKeyCommand, SignCommand } = await import('@aws-sdk/client-kms');
    const canonical = arns[0];
    const requested = referenceMode === 'alias-name' ? 'alias/dnsid-current'
      : referenceMode === 'alias-ARN' ? 'arn:aws:kms:us-east-1:123456789012:alias/dnsid-current' : canonical;
    const calls: string[] = [];
    // Only service responses are synthetic; native facade and provider are real.
    const client = {
      async send(command: { input: unknown; constructor: { name: string } }) {
        calls.push(command.constructor.name);
        if (command instanceof GetPublicKeyCommand) {
          expect(command.input).toEqual({ KeyId: requested });
          return { ...(referenceMode === 'omitted-KeyId' ? {} : { KeyId: canonical }),
            PublicKey: publicKey.export({ format: 'der', type: 'spki' }),
            KeySpec: 'ECC_NIST_EDWARDS25519', KeyUsage: 'SIGN_VERIFY', SigningAlgorithms: ['ED25519_SHA_512'] };
        }
        if (command instanceof SignCommand) {
          expect(command.input.KeyId).toBe(canonical);
          expect(command.input.MessageType).toBe('RAW');
          expect(command.input.SigningAlgorithm).toBe('ED25519_SHA_512');
          expect(Buffer.from(command.input.Message!)).toEqual(Buffer.from('COV-1 unchanged compatibility'));
          return { KeyId: canonical, Signature: sign(null, command.input.Message!, privateKey), SigningAlgorithm: 'ED25519_SHA_512' };
        }
        throw new Error('no provisioning, fallback or other native operation permitted');
      },
    };
    const provider = await AwsKmsKeyProvider.load(new AwsSdkKmsFacade(client), { activeKeyId: requested, algorithm: 'ED25519_SHA_512' });
    const key = await provider.signingKey();
    expect(key).toMatchObject({ kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', kid: canonical, x });
    expect(key).not.toHaveProperty('d'); expect(thumbprint(key.x!)).toBe(thumb);
    expect(await provider.listKeyIds()).toEqual([canonical]);
    expect(await provider.jwk(canonical)).toMatchObject({ kid: canonical, x });
    const payload = Buffer.from('COV-1 unchanged compatibility');
    expect(verify(null, payload, publicKey, await provider.sign(payload))).toBe(true);
    expect(calls).toEqual(['GetPublicKeyCommand', 'SignCommand']);
  });
}
