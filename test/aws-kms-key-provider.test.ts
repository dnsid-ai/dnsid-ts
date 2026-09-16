import { describe, expect, it } from 'vitest';

import { verifyWithKey } from '@dnsid-ai/protocol';
import { AwsKmsKeyProvider, AwsSdkKmsFacade } from '@dnsid-ai/key-aws';
import type {
  AwsKmsCreateSigningKeyInput,
  AwsKmsFacade,
  AwsKmsGetPublicKeyInput,
  AwsKmsKeyState,
  AwsKmsSignInput,
  AwsSdkKmsClient,
} from '@dnsid-ai/key-aws';

class FakeAwsKms implements AwsKmsFacade {
  readonly createInputs: AwsKmsCreateSigningKeyInput[] = [];
  readonly signInputs: AwsKmsSignInput[] = [];
  readonly publicKeyInputs: AwsKmsGetPublicKeyInput[] = [];
  readonly deletedKeyIds: string[] = [];
  private readonly keys = new Map<string, CryptoKeyPair>();
  private readonly algorithms = new Map<string, 'ECDSA_SHA_256' | 'ED25519_SHA_512'>();
  private readonly aliases = new Map<string, string>();
  private nextId = 1;

  async addP256Key(keyId: string): Promise<void> {
    this.keys.set(keyId, await generateP256KeyPair());
    this.algorithms.set(keyId, 'ECDSA_SHA_256');
  }

  async addEd25519Key(keyId: string): Promise<void> {
    this.keys.set(keyId, await generateEd25519KeyPair());
    this.algorithms.set(keyId, 'ED25519_SHA_512');
  }

  addAlias(alias: string, keyId: string): void {
    this.aliases.set(alias, keyId);
  }

  async createSigningKey(input: AwsKmsCreateSigningKeyInput): Promise<{ keyId: string }> {
    this.createInputs.push(input);
    const keyId = `arn:aws:kms:us-east-1:111122223333:key/generated-${this.nextId++}`;
    if (input.keySpec === 'ECC_NIST_EDWARDS25519') await this.addEd25519Key(keyId);
    else await this.addP256Key(keyId);
    return { keyId };
  }

  async getPublicKey(input: AwsKmsGetPublicKeyInput): Promise<{
    keyId: string;
    publicKey: Uint8Array;
    keySpec: string;
    keyUsage: string;
    signingAlgorithms: string[];
  }> {
    this.publicKeyInputs.push(input);
    const keyId = this.resolve(input.keyId);
    const pair = this.key(input.keyId);
    return {
      keyId,
      publicKey: new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)),
      keySpec: this.algorithm(input.keyId) === 'ED25519_SHA_512' ? 'ECC_NIST_EDWARDS25519' : 'ECC_NIST_P256',
      keyUsage: 'SIGN_VERIFY',
      signingAlgorithms: [this.algorithm(input.keyId)],
    };
  }

  async sign(input: AwsKmsSignInput): Promise<{ keyId: string; signature: Uint8Array; signingAlgorithm: string }> {
    this.signInputs.push(input);
    const pair = this.key(input.keyId);
    const algorithm = this.algorithm(input.keyId);
    const raw = new Uint8Array(await crypto.subtle.sign(
      algorithm === 'ED25519_SHA_512'
        ? { name: 'Ed25519' } as AlgorithmIdentifier
        : { name: 'ECDSA', hash: 'SHA-256' },
      pair.privateKey,
      toArrayBuffer(input.message),
    ));
    return {
      keyId: this.resolve(input.keyId),
      signature: algorithm === 'ED25519_SHA_512' ? raw : joseEcdsaSignatureToDer(raw, 32),
      signingAlgorithm: input.signingAlgorithm,
    };
  }

  async scheduleKeyDeletion(input: { keyId: string }): Promise<void> {
    this.deletedKeyIds.push(input.keyId);
  }

  private key(keyId: string): CryptoKeyPair {
    const resolved = this.resolve(keyId);
    const pair = this.keys.get(resolved);
    if (!pair) throw new Error(`missing fake KMS key ${keyId}`);
    return pair;
  }

  private algorithm(keyId: string): 'ECDSA_SHA_256' | 'ED25519_SHA_512' {
    const resolved = this.resolve(keyId);
    const algorithm = this.algorithms.get(resolved);
    if (!algorithm) throw new Error(`missing fake KMS algorithm ${keyId}`);
    return algorithm;
  }

  private resolve(keyId: string): string {
    return this.aliases.get(keyId) ?? keyId;
  }
}

describe('AwsKmsKeyProvider', () => {
  it('loads active and retained public keys as JWKs, with active first', async () => {
    const kms = new FakeAwsKms();
    await kms.addP256Key('active-key');
    await kms.addP256Key('retained-key');

    const provider = await AwsKmsKeyProvider.load(kms, {
      activeKeyId: 'active-key',
      retainedKeyIds: ['retained-key'],
      algorithm: 'ECDSA_SHA_256',
    });

    await expect(provider.listKeyIds()).resolves.toEqual(['active-key', 'retained-key']);
    await expect(provider.signingKey()).resolves.toMatchObject({
      kid: 'active-key',
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      use: 'sig',
    });
    await expect(provider.jwk('retained-key')).resolves.toMatchObject({
      kid: 'retained-key',
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      use: 'sig',
    });
  });

  it('resolves aliases to canonical key IDs before publishing or signing', async () => {
    const kms = new FakeAwsKms();
    await kms.addP256Key('canonical-key');
    await kms.addP256Key('pending-key');
    kms.addAlias('alias/current', 'canonical-key');
    kms.addAlias('alias/pending', 'pending-key');
    const state: AwsKmsKeyState = { activeKeyId: 'alias/current', retainedKeyIds: [], pendingKeyIds: ['alias/pending'] };

    const provider = await AwsKmsKeyProvider.load(kms, {
      state,
      algorithm: 'ECDSA_SHA_256',
    });

    expect(state.activeKeyId).toBe('canonical-key');
    expect(state.pendingKeyIds).toEqual(['pending-key']);
    expect(await provider.listKeyIds()).toEqual(['canonical-key']);
    expect(await provider.signingKey()).toMatchObject({ kid: 'canonical-key' });
    await provider.sign(new TextEncoder().encode('payload'));
    expect(kms.signInputs[0]!.keyId).toBe('canonical-key');
    await provider.activate('pending-key');
    expect(await provider.listKeyIds()).toEqual(['pending-key', 'canonical-key']);
  });

  it('signs with the active KMS key and converts AWS DER ECDSA signatures to JOSE raw signatures', async () => {
    const kms = new FakeAwsKms();
    await kms.addP256Key('active-key');
    const provider = await AwsKmsKeyProvider.load(kms, {
      activeKeyId: 'active-key',
      algorithm: 'ECDSA_SHA_256',
    });

    const payload = new TextEncoder().encode('payload to sign');
    const signature = await provider.sign(payload);
    const explicitSignature = await provider.signKey('active-key', payload);
    const signingKey = await provider.signingKey();

    expect(signature).toHaveLength(64);
    expect(explicitSignature).toHaveLength(64);
    expect(await verifyWithKey(payload, signature, signingKey, 'ES256')).toBe(true);
    expect(kms.signInputs[0]).toMatchObject({
      keyId: 'active-key',
      signingAlgorithm: 'ECDSA_SHA_256',
      messageType: 'RAW',
    });

    await provider.sign(new Uint8Array(4097));
    expect(kms.signInputs[2]).toMatchObject({
      keyId: 'active-key',
      signingAlgorithm: 'ECDSA_SHA_256',
      messageType: 'DIGEST',
      message: new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(4097))),
    });
  });

  it('supports AWS KMS Ed25519 keys and returns raw EdDSA signatures', async () => {
    const kms = new FakeAwsKms();
    await kms.addEd25519Key('ed-key');
    const provider = await AwsKmsKeyProvider.load(kms, {
      activeKeyId: 'ed-key',
      algorithm: 'ED25519_SHA_512',
    });

    const generatedKid = await provider.generateKey();
    expect(kms.createInputs[0]).toMatchObject({ keySpec: 'ECC_NIST_EDWARDS25519' });
    await provider.activate(generatedKid);

    const payload = new TextEncoder().encode('payload to sign with Ed25519');
    const signature = await provider.sign(payload);
    const signingKey = await provider.signingKey();

    expect(signature).toHaveLength(64);
    expect(signingKey).toMatchObject({
      kid: generatedKid,
      kty: 'OKP',
      crv: 'Ed25519',
      alg: 'EdDSA',
      use: 'sig',
    });
    expect(await verifyWithKey(payload, signature, signingKey, 'EdDSA')).toBe(true);
    expect(kms.signInputs[0]).toMatchObject({
      keyId: generatedKid,
      signingAlgorithm: 'ED25519_SHA_512',
      messageType: 'RAW',
    });
  });

  it('keeps generated keys pending until activation, then retains the previous active key', async () => {
    const kms = new FakeAwsKms();
    await kms.addP256Key('active-key');
    const state: AwsKmsKeyState = { activeKeyId: 'active-key', retainedKeyIds: [], pendingKeyIds: [] };
    const provider = await AwsKmsKeyProvider.load(kms, {
      state,
      algorithm: 'ECDSA_SHA_256',
      description: 'DNSid signing key',
      tags: { service: 'dnsid' },
    });

    const newKid = await provider.generateKey();
    expect(await provider.listKeyIds()).toEqual(['active-key']);
    await expect(provider.jwk(newKid)).resolves.toMatchObject({ kid: newKid });
    expect(state.pendingKeyIds).toEqual([newKid]);
    expect(kms.createInputs[0]).toEqual({
      keySpec: 'ECC_NIST_P256',
      description: 'DNSid signing key',
      tags: { service: 'dnsid' },
    });

    await provider.activate(newKid);
    expect(await provider.listKeyIds()).toEqual([newKid, 'active-key']);
    expect(state.activeKeyId).toBe(newKid);
    expect(state.retainedKeyIds).toEqual(['active-key']);
    expect(state.pendingKeyIds).toEqual([]);
    expect(provider.stateSnapshot()).toEqual(state);
  });

  it('supersedes only rotated-out keys and can optionally schedule KMS deletion', async () => {
    const kms = new FakeAwsKms();
    await kms.addP256Key('active-key');
    await kms.addP256Key('old-key');
    const provider = await AwsKmsKeyProvider.load(kms, {
      activeKeyId: 'active-key',
      retainedKeyIds: ['old-key'],
      algorithm: 'ECDSA_SHA_256',
      scheduleKeyDeletionOnPurge: true,
      deletionWindowInDays: 7,
    });

    await expect(provider.supersede('active-key')).rejects.toThrow('cannot supersede the active key');
    await provider.supersede('old-key');
    expect(await provider.listKeyIds()).toEqual(['active-key']);
    expect(kms.deletedKeyIds).toEqual(['old-key']);
  });

  it('rejects active key IDs that cannot be used as DNSid kids', async () => {
    const kms = new FakeAwsKms();
    await expect(AwsKmsKeyProvider.load(kms, {
      activeKeyId: 'bad#kid',
      algorithm: 'ECDSA_SHA_256',
    })).rejects.toThrow("must not contain '#'");
  });
});

describe('AwsSdkKmsFacade', () => {
  it('translates facade calls into AWS SDK v3 KMS commands', async () => {
    const client = new FakeAwsSdkClient();
    const facade = new AwsSdkKmsFacade(client as unknown as AwsSdkKmsClient);
    const publicKey = new Uint8Array([1, 2, 3]);
    const signature = new Uint8Array([4, 5, 6]);

    client.outputs.push(
      { KeyMetadata: { Arn: 'arn:aws:kms:us-east-1:111122223333:key/new-key', KeyId: 'new-key' } },
      {
        KeyId: 'key-1',
        PublicKey: publicKey,
        KeySpec: 'ECC_NIST_P256',
        KeyUsage: 'SIGN_VERIFY',
        SigningAlgorithms: ['ECDSA_SHA_256'],
      },
      {
        KeyId: 'key-1',
        Signature: signature,
        SigningAlgorithm: 'ECDSA_SHA_256',
      },
      {},
    );

    await expect(facade.createSigningKey({
      keySpec: 'ECC_NIST_P256',
      description: 'DNSid signing key',
      tags: { service: 'dnsid', env: 'test' },
    })).resolves.toEqual({ keyId: 'arn:aws:kms:us-east-1:111122223333:key/new-key' });
    await expect(facade.getPublicKey({ keyId: 'key-1' })).resolves.toEqual({
      keyId: 'key-1',
      publicKey,
      keySpec: 'ECC_NIST_P256',
      keyUsage: 'SIGN_VERIFY',
      signingAlgorithms: ['ECDSA_SHA_256'],
    });
    await expect(facade.sign({
      keyId: 'key-1',
      message: new Uint8Array([7, 8, 9]),
      signingAlgorithm: 'ECDSA_SHA_256',
      messageType: 'RAW',
    })).resolves.toEqual({
      keyId: 'key-1',
      signature,
      signingAlgorithm: 'ECDSA_SHA_256',
    });
    await expect(facade.scheduleKeyDeletion({
      keyId: 'old-key',
      pendingWindowInDays: 7,
    })).resolves.toBeUndefined();

    expect(client.commands.map(c => c.name)).toEqual([
      'CreateKeyCommand',
      'GetPublicKeyCommand',
      'SignCommand',
      'ScheduleKeyDeletionCommand',
    ]);
    expect(client.commands[0]!.input).toEqual({
      KeyUsage: 'SIGN_VERIFY',
      KeySpec: 'ECC_NIST_P256',
      Description: 'DNSid signing key',
      Tags: [
        { TagKey: 'service', TagValue: 'dnsid' },
        { TagKey: 'env', TagValue: 'test' },
      ],
    });
    expect(client.commands[1]!.input).toEqual({ KeyId: 'key-1' });
    expect(client.commands[2]!.input).toEqual({
      KeyId: 'key-1',
      Message: new Uint8Array([7, 8, 9]),
      MessageType: 'RAW',
      SigningAlgorithm: 'ECDSA_SHA_256',
    });
    expect(client.commands[3]!.input).toEqual({
      KeyId: 'old-key',
      PendingWindowInDays: 7,
    });
  });
});

async function generateP256KeyPair(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;
}

async function generateEd25519KeyPair(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    { name: 'Ed25519' } as AlgorithmIdentifier,
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;
}

function joseEcdsaSignatureToDer(raw: Uint8Array, partLength: number): Uint8Array {
  const r = derInteger(raw.slice(0, partLength));
  const s = derInteger(raw.slice(partLength));
  const body = new Uint8Array(r.length + s.length);
  body.set(r, 0);
  body.set(s, r.length);
  return derSequence(body);
}

function derSequence(body: Uint8Array): Uint8Array {
  return new Uint8Array([0x30, ...derLength(body.length), ...body]);
}

function derInteger(raw: Uint8Array): Uint8Array {
  let value = raw;
  while (value.length > 0 && value[0] === 0) value = value.slice(1);
  if (value.length === 0) value = new Uint8Array([0]);
  if ((value[0]! & 0x80) !== 0) value = new Uint8Array([0, ...value]);
  return new Uint8Array([0x02, ...derLength(value.length), ...value]);
}

function derLength(length: number): number[] {
  if (length < 0x80) return [length];
  return [0x81, length];
}

function toArrayBuffer(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  if (bytes.buffer instanceof ArrayBuffer && bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
    return bytes as Uint8Array<ArrayBuffer>;
  }
  return new Uint8Array(bytes);
}

class FakeAwsSdkClient {
  readonly commands: Array<{ name: string; input: unknown }> = [];
  readonly outputs: unknown[] = [];

  async send(command: { input: unknown; constructor: { name: string } }): Promise<unknown> {
    this.commands.push({ name: command.constructor.name, input: command.input });
    return this.outputs.shift();
  }
}
