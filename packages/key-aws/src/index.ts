/**
 * AWS KMS-backed key provider for DNSid.
 *
 * `@identity-digital/dnsid-key-aws` implements the `KeyProvider` contract from
 * `@identity-digital/dnsid-protocol` on top of AWS KMS: private key material never
 * leaves KMS, while `AwsKmsKeyProvider` exposes public keys as DNSid JWKs, signs
 * through KMS, and manages the active/pending/retained key lifecycle. Callers persist
 * `stateSnapshot()` after lifecycle changes. `AwsSdkKmsFacade` adapts AWS SDK v3's
 * `KMSClient` to the narrow `AwsKmsFacade` interface this package depends on.
 *
 * @packageDocumentation
 */
import {
  CreateKeyCommand,
  GetPublicKeyCommand,
  MessageType,
  ScheduleKeyDeletionCommand,
  SignCommand,
} from '@aws-sdk/client-kms';
import type { KMSClient } from '@aws-sdk/client-kms';
import type { DnsIdJWK, KeyProvider } from '@identity-digital/dnsid-protocol';
import { ArgumentError } from '@identity-digital/dnsid-protocol';

export type AwsKmsSigningAlgorithm = 'ECDSA_SHA_256' | 'ED25519_SHA_512';

export type AwsKmsKeySpec = 'ECC_NIST_P256' | 'ECC_NIST_EDWARDS25519';

const AWS_KMS_RAW_SIGN_LIMIT_BYTES = 4096;

export interface AwsKmsKeyState {
  /** ARN, key ID, alias, or alias ARN of the currently active signing key. Aliases are resolved to canonical key IDs on load. */
  activeKeyId: string;
  /** KMS key IDs retained for verification of previous signatures. */
  retainedKeyIds?: string[];
  /** KMS key IDs generated but not yet active. */
  pendingKeyIds?: string[];
}

export interface AwsKmsConfig extends Partial<AwsKmsKeyState> {
  /**
   * Mutable state object for provider lifecycle. Prefer this over the legacy
   * top-level active/retained/pending fields when state must persist.
   */
  state?: AwsKmsKeyState;
  /** Legacy alias for activeKeyId kept for existing callers. */
  activeKeyArn?: string;
  /** Legacy alias for retainedKeyIds kept for existing callers. */
  retainedKeyArns?: string[];
  /** Legacy alias for pendingKeyIds kept for existing callers. */
  pendingKeyArns?: string[];
  /** KMS signing algorithm to request. Must match the key spec. */
  algorithm: AwsKmsSigningAlgorithm;
  /** KMS key spec to use when generateKey creates a new key. */
  keySpec?: AwsKmsKeySpec;
  /** Optional description passed to generated KMS keys. */
  description?: string;
  /** Optional tags passed to generated KMS keys. */
  tags?: Record<string, string>;
  /** Schedule deletion of retained KMS keys on purge. Default: false. */
  scheduleKeyDeletionOnPurge?: boolean;
  /** Waiting period for ScheduleKeyDeletion. AWS allows 7-30 days. Default: 30. */
  deletionWindowInDays?: number;
}

export interface AwsKmsCreateSigningKeyInput {
  keySpec: AwsKmsKeySpec;
  description?: string;
  tags?: Record<string, string>;
}

export interface AwsKmsGetPublicKeyInput {
  keyId: string;
}

export interface AwsKmsSignInput {
  keyId: string;
  message: Uint8Array;
  signingAlgorithm: AwsKmsSigningAlgorithm;
  messageType: 'RAW' | 'DIGEST';
}

export interface AwsKmsScheduleKeyDeletionInput {
  keyId: string;
  pendingWindowInDays: number;
}

export interface AwsKmsFacade {
  createSigningKey(input: AwsKmsCreateSigningKeyInput): Promise<{ keyId: string }>;
  getPublicKey(input: AwsKmsGetPublicKeyInput): Promise<{
    keyId?: string;
    publicKey: Uint8Array;
    keySpec?: AwsKmsKeySpec | string;
    keyUsage?: string;
    signingAlgorithms?: string[];
  }>;
  sign(input: AwsKmsSignInput): Promise<{
    keyId?: string;
    signature: Uint8Array;
    signingAlgorithm?: AwsKmsSigningAlgorithm | string;
  }>;
  scheduleKeyDeletion?(input: AwsKmsScheduleKeyDeletionInput): Promise<void>;
}

export type AwsSdkKmsClient = Pick<KMSClient, 'send'>;

/** Adapter from AWS SDK v3's KMSClient to the narrow facade used by AwsKmsKeyProvider. */
export class AwsSdkKmsFacade implements AwsKmsFacade {
  constructor(private readonly client: AwsSdkKmsClient) {}

  async createSigningKey(input: AwsKmsCreateSigningKeyInput): Promise<{ keyId: string }> {
    const output = await this.client.send(new CreateKeyCommand({
      KeyUsage: 'SIGN_VERIFY',
      KeySpec: input.keySpec,
      Description: input.description,
      Tags: input.tags ? Object.entries(input.tags).map(([TagKey, TagValue]) => ({ TagKey, TagValue })) : undefined,
    }));
    const keyId = output.KeyMetadata?.Arn ?? output.KeyMetadata?.KeyId;
    if (!keyId) throw new ArgumentError('AWS KMS CreateKey response did not include KeyMetadata.Arn or KeyMetadata.KeyId');
    return { keyId };
  }

  async getPublicKey(input: AwsKmsGetPublicKeyInput): Promise<{
    keyId?: string;
    publicKey: Uint8Array;
    keySpec?: string;
    keyUsage?: string;
    signingAlgorithms?: string[];
  }> {
    const output = await this.client.send(new GetPublicKeyCommand({ KeyId: input.keyId }));
    if (!output.PublicKey) throw new ArgumentError(`AWS KMS GetPublicKey response did not include PublicKey for ${input.keyId}`);
    return {
      keyId: output.KeyId,
      publicKey: output.PublicKey,
      keySpec: output.KeySpec,
      keyUsage: output.KeyUsage,
      signingAlgorithms: output.SigningAlgorithms,
    };
  }

  async sign(input: AwsKmsSignInput): Promise<{
    keyId?: string;
    signature: Uint8Array;
    signingAlgorithm?: string;
  }> {
    const output = await this.client.send(new SignCommand({
      KeyId: input.keyId,
      Message: input.message,
      MessageType: input.messageType === 'DIGEST' ? MessageType.DIGEST : MessageType.RAW,
      SigningAlgorithm: input.signingAlgorithm,
    }));
    if (!output.Signature) throw new ArgumentError(`AWS KMS Sign response did not include Signature for ${input.keyId}`);
    return {
      keyId: output.KeyId,
      signature: output.Signature,
      signingAlgorithm: output.SigningAlgorithm,
    };
  }

  async scheduleKeyDeletion(input: AwsKmsScheduleKeyDeletionInput): Promise<void> {
    await this.client.send(new ScheduleKeyDeletionCommand({
      KeyId: input.keyId,
      PendingWindowInDays: input.pendingWindowInDays,
    }));
  }
}

/**
 * AWS KMS-backed DNSid KeyProvider.
 *
 * AWS KMS owns private key material and signing. This provider owns DNSid's
 * active/pending/retained lifecycle state and exposes public keys as JWKs.
 */
export class AwsKmsKeyProvider implements KeyProvider {
  private readonly jwkCache = new Map<string, DnsIdJWK>();
  private readonly client: AwsKmsFacade;
  private readonly state: Required<AwsKmsKeyState>;
  private readonly config: Required<Pick<AwsKmsConfig, 'algorithm' | 'keySpec' | 'scheduleKeyDeletionOnPurge' | 'deletionWindowInDays'>>
    & Pick<AwsKmsConfig, 'description' | 'tags'>;

  private constructor(client: AwsKmsFacade, config: AwsKmsConfig) {
    const state = stateFromConfig(config);
    this.client = client;
    this.state = state;
    this.config = {
      algorithm: config.algorithm,
      keySpec: config.keySpec ?? defaultKeySpecForAlgorithm(config.algorithm),
      description: config.description,
      tags: config.tags,
      scheduleKeyDeletionOnPurge: config.scheduleKeyDeletionOnPurge ?? false,
      deletionWindowInDays: config.deletionWindowInDays ?? 30,
    };

    validateKid(this.state.activeKeyId);
    for (const kid of [...this.state.retainedKeyIds, ...this.state.pendingKeyIds]) validateKid(kid);
  }

  static async load(client: AwsKmsFacade, config: AwsKmsConfig): Promise<AwsKmsKeyProvider> {
    const provider = new AwsKmsKeyProvider(client, config);
    provider.state.activeKeyId = (await provider.publicJwk(provider.state.activeKeyId)).kid;
    provider.state.retainedKeyIds = await Promise.all(
      provider.state.retainedKeyIds.map(async kid => (await provider.publicJwk(kid)).kid),
    );
    provider.state.pendingKeyIds = await Promise.all(
      provider.state.pendingKeyIds.map(async kid => (await provider.publicJwk(kid)).kid),
    );
    return provider;
  }

  async signingKey(): Promise<DnsIdJWK> {
    return this.jwk(this.state.activeKeyId);
  }

  async jwk(kid: string): Promise<DnsIdJWK> {
    if (kid !== this.state.activeKeyId && !this.state.retainedKeyIds.includes(kid) && !this.state.pendingKeyIds.includes(kid)) {
      throw new ArgumentError(`key not found: ${kid}`);
    }
    return this.publicJwk(kid);
  }

  async listKeyIds(): Promise<string[]> {
    return [this.state.activeKeyId, ...this.state.retainedKeyIds];
  }

  stateSnapshot(): AwsKmsKeyState {
    return {
      activeKeyId: this.state.activeKeyId,
      retainedKeyIds: [...this.state.retainedKeyIds],
      pendingKeyIds: [...this.state.pendingKeyIds],
    };
  }

  async sign(payload: Uint8Array): Promise<Uint8Array> {
    return this.signKey(this.state.activeKeyId, payload);
  }

  async signKey(kid: string, payload: Uint8Array): Promise<Uint8Array> {
    if (kid !== this.state.activeKeyId && !this.state.pendingKeyIds.includes(kid)) throw new ArgumentError(`key is not active or pending for signing: ${kid}`);
    const useDigest = payload.byteLength > AWS_KMS_RAW_SIGN_LIMIT_BYTES && this.config.algorithm === 'ECDSA_SHA_256';
    if (payload.byteLength > AWS_KMS_RAW_SIGN_LIMIT_BYTES && !useDigest) {
      throw new ArgumentError(`AWS KMS RAW signing payload exceeds ${AWS_KMS_RAW_SIGN_LIMIT_BYTES} bytes`);
    }
    const result = await this.client.sign({
      keyId: kid,
      message: useDigest ? new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(payload))) : payload,
      signingAlgorithm: this.config.algorithm,
      messageType: useDigest ? 'DIGEST' : 'RAW',
    });
    if (!result.signature) throw new ArgumentError('AWS KMS sign response did not include a signature');
    if (result.signingAlgorithm && result.signingAlgorithm !== this.config.algorithm) {
      throw new ArgumentError(
        `AWS KMS signing algorithm mismatch: expected ${this.config.algorithm}, got ${result.signingAlgorithm}`,
      );
    }
    if (result.keyId && result.keyId !== kid) {
      const signedKid = (await this.publicJwk(result.keyId)).kid;
      if (signedKid !== kid) {
        throw new ArgumentError(`AWS KMS signed with unexpected key: expected ${kid}, got ${result.keyId}`);
      }
    }
    return signatureBytesForJose(this.config.algorithm, result.signature);
  }

  async generateKey(): Promise<string> {
    const result = await this.client.createSigningKey({
      keySpec: this.config.keySpec,
      description: this.config.description,
      tags: this.config.tags,
    });
    if (!result.keyId) throw new ArgumentError('AWS KMS create key response did not include a key ID');
    try {
      const kid = (await this.publicJwk(result.keyId)).kid;
      this.state.pendingKeyIds.push(kid);
      return kid;
    } catch (e) {
      throw new ArgumentError(`created AWS KMS key ${result.keyId} but failed to load its public key: ${(e as Error).message}`);
    }
  }

  async activate(kid: string): Promise<void> {
    const canonicalKid = (await this.publicJwk(kid)).kid;
    const idx = this.state.pendingKeyIds.indexOf(canonicalKid);
    if (idx === -1) throw new ArgumentError(`no pending key with kid "${kid}"`);
    this.state.pendingKeyIds.splice(idx, 1);
    this.state.retainedKeyIds.push(this.state.activeKeyId);
    this.state.activeKeyId = canonicalKid;
  }

  async supersede(kid: string): Promise<void> {
    if (this.state.activeKeyId === kid) {
      throw new ArgumentError('cannot supersede the active key; activate a replacement first');
    }
    const idx = this.state.retainedKeyIds.indexOf(kid);
    if (idx === -1) throw new ArgumentError(`no retained key with kid "${kid}"`);

    if (this.config.scheduleKeyDeletionOnPurge) {
      if (!this.client.scheduleKeyDeletion) {
        throw new ArgumentError('scheduleKeyDeletionOnPurge requires an AWS KMS facade with scheduleKeyDeletion');
      }
      await this.client.scheduleKeyDeletion({
        keyId: kid,
        pendingWindowInDays: this.config.deletionWindowInDays,
      });
    }

    this.state.retainedKeyIds.splice(idx, 1);
    this.jwkCache.delete(kid);
  }

  /** @deprecated Use supersede(). */
  async purge(kid: string): Promise<void> {
    await this.supersede(kid);
  }

  private async publicJwk(kid: string): Promise<DnsIdJWK> {
    const cached = this.jwkCache.get(kid);
    if (cached) return cached;

    const result = await this.client.getPublicKey({ keyId: kid });
    if (!result.publicKey) throw new ArgumentError(`AWS KMS public key response did not include PublicKey for ${kid}`);
    if (result.keyUsage !== 'SIGN_VERIFY') throw new ArgumentError(`AWS KMS key ${kid} is not a SIGN_VERIFY key`);
    if (result.keySpec !== this.config.keySpec) {
      throw new ArgumentError(`AWS KMS key ${kid} spec mismatch: expected ${this.config.keySpec}, got ${result.keySpec ?? 'unknown'}`);
    }
    if (!result.signingAlgorithms?.includes(this.config.algorithm)) {
      throw new ArgumentError(`AWS KMS key ${kid} does not support ${this.config.algorithm}`);
    }

    const canonicalKid = result.keyId ?? kid;
    validateKid(canonicalKid);
    const jwk = await spkiToJwk(result.publicKey, this.config.algorithm, canonicalKid);
    this.jwkCache.set(kid, jwk);
    this.jwkCache.set(canonicalKid, jwk);
    return jwk;
  }
}

function stateFromConfig(config: AwsKmsConfig): Required<AwsKmsKeyState> {
  const source = config.state ?? {
    activeKeyId: config.activeKeyId ?? config.activeKeyArn,
    retainedKeyIds: config.retainedKeyIds ?? config.retainedKeyArns,
    pendingKeyIds: config.pendingKeyIds ?? config.pendingKeyArns,
  };
  if (!source.activeKeyId) throw new ArgumentError('AWS KMS key provider requires an active key ID');
  source.retainedKeyIds ??= [];
  source.pendingKeyIds ??= [];
  return source as Required<AwsKmsKeyState>;
}

function validateKid(kid: string): void {
  if (!kid) throw new ArgumentError('AWS KMS key ID must be non-empty');
  if (kid.includes('#')) throw new ArgumentError("AWS KMS key ID must not contain '#'");
}

function defaultKeySpecForAlgorithm(algorithm: AwsKmsSigningAlgorithm): AwsKmsKeySpec {
  switch (algorithm) {
    case 'ECDSA_SHA_256': return 'ECC_NIST_P256';
    case 'ED25519_SHA_512': return 'ECC_NIST_EDWARDS25519';
  }
}

function joseAlgForAws(algorithm: AwsKmsSigningAlgorithm): string {
  switch (algorithm) {
    case 'ECDSA_SHA_256': return 'ES256';
    case 'ED25519_SHA_512': return 'EdDSA';
  }
}

function spkiImportAlgorithm(algorithm: AwsKmsSigningAlgorithm): AlgorithmIdentifier | EcKeyImportParams {
  switch (algorithm) {
    case 'ECDSA_SHA_256': return { name: 'ECDSA', namedCurve: 'P-256' };
    case 'ED25519_SHA_512': return { name: 'Ed25519' } as AlgorithmIdentifier;
  }
}

async function spkiToJwk(spki: Uint8Array, algorithm: AwsKmsSigningAlgorithm, kid: string): Promise<DnsIdJWK> {
  try {
    const cryptoKey = await crypto.subtle.importKey(
      'spki',
      toArrayBuffer(spki),
      spkiImportAlgorithm(algorithm),
      true,
      ['verify'],
    );
    const raw = await crypto.subtle.exportKey('jwk', cryptoKey);
    return { ...raw, kid, alg: joseAlgForAws(algorithm), use: 'sig' } as DnsIdJWK;
  } catch (e) {
    throw new ArgumentError(`failed to import AWS KMS public key for ${kid}: ${(e as Error).message}`);
  }
}

function toArrayBuffer(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  if (bytes.buffer instanceof ArrayBuffer && bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
    return bytes as Uint8Array<ArrayBuffer>;
  }
  return new Uint8Array(bytes);
}

function signatureBytesForJose(algorithm: AwsKmsSigningAlgorithm, signature: Uint8Array): Uint8Array {
  switch (algorithm) {
    case 'ECDSA_SHA_256': return derEcdsaSignatureToJose(signature, 32);
    case 'ED25519_SHA_512': return signature;
  }
}

function derEcdsaSignatureToJose(der: Uint8Array, partLength: number): Uint8Array {
  let offset = 0;
  if (der[offset++] !== 0x30) throw new ArgumentError('invalid ECDSA signature DER: expected sequence');
  const seqLength = readDerLength(der, offset);
  offset = seqLength.nextOffset;
  if (seqLength.length !== der.length - offset) throw new ArgumentError('invalid ECDSA signature DER: bad sequence length');
  const r = readDerInteger(der, offset);
  offset = r.nextOffset;
  const s = readDerInteger(der, offset);
  offset = s.nextOffset;
  if (offset !== der.length) throw new ArgumentError('invalid ECDSA signature DER: trailing bytes');

  const out = new Uint8Array(partLength * 2);
  out.set(integerToFixedUnsigned(r.value, partLength), 0);
  out.set(integerToFixedUnsigned(s.value, partLength), partLength);
  return out;
}

function readDerLength(der: Uint8Array, offset: number): { length: number; nextOffset: number } {
  const first = der[offset++];
  if (first === undefined) throw new ArgumentError('invalid DER: missing length');
  if ((first & 0x80) === 0) return { length: first, nextOffset: offset };
  const lenBytes = first & 0x7f;
  if (lenBytes === 0 || lenBytes > 2) throw new ArgumentError('invalid DER: unsupported length encoding');
  let length = 0;
  for (let i = 0; i < lenBytes; i++) {
    const b = der[offset++];
    if (b === undefined) throw new ArgumentError('invalid DER: truncated length');
    length = (length << 8) | b;
  }
  return { length, nextOffset: offset };
}

function readDerInteger(der: Uint8Array, offset: number): { value: Uint8Array; nextOffset: number } {
  if (der[offset++] !== 0x02) throw new ArgumentError('invalid ECDSA signature DER: expected integer');
  const len = readDerLength(der, offset);
  offset = len.nextOffset;
  const end = offset + len.length;
  if (end > der.length) throw new ArgumentError('invalid ECDSA signature DER: truncated integer');
  return { value: der.slice(offset, end), nextOffset: end };
}

function integerToFixedUnsigned(bytes: Uint8Array, length: number): Uint8Array {
  let value = bytes;
  while (value.length > 0 && value[0] === 0) value = value.slice(1);
  if (value.length > length) throw new ArgumentError('invalid ECDSA signature DER: integer too large');
  const out = new Uint8Array(length);
  out.set(value, length - value.length);
  return out;
}
