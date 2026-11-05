/** Existing-version Google Cloud KMS Ed25519 signing. Private keys never leave KMS.
 * @packageDocumentation
 */
import { createPublicKey } from 'node:crypto';
import type { DnsIdJWK, KeyProvider } from '@dnsid-ai/protocol';
import { ArgumentError, jwkThumbprint } from '@dnsid-ai/protocol';

export interface GcpCloudKmsConfig {
  /** Fully qualified immutable CryptoKeyVersion resource name. */
  activeKeyVersion: string;
  /** Retained-key loading is not supported by this runtime slice. */
  retainedKeyVersions?: string[];
  /** Must be EC_SIGN_ED25519. */
  algorithm: string;
}

/** Structural seam implemented by the official KeyManagementServiceClient. */
export interface GcpCloudKmsClient {
  createCryptoKeyVersion?(request: { parent: string; cryptoKeyVersion: { state: 'ENABLED' } }): Promise<readonly unknown[]>;
  getPublicKey(request: { name: string }): Promise<readonly unknown[]>;
  asymmetricSign(request: { name: string; data: Uint8Array; dataCrc32c: { value: number } }): Promise<readonly unknown[]>;
}

type Checksum = { value?: unknown } | null | undefined;
type PublicResponse = {
  name?: string; pem?: string; algorithm?: string | number;
  protectionLevel?: string | number; pemCrc32c?: Checksum;
};
type SignResponse = {
  name?: string; signature?: Uint8Array | string;
  signatureCrc32c?: Checksum; verifiedDataCrc32c?: boolean;
};

/** Opens one existing software Ed25519 version without cloud mutation or fallback. */
export class GcpCloudKmsKeyProvider implements KeyProvider {
  private readonly keys = new Map<string, { version: string; jwk: Readonly<DnsIdJWK>; state: 'active' | 'pending' | 'superseded' }>();
  private activeKid: string | undefined;
  private readonly signing = new Set<Promise<Uint8Array>>();
  private activating = false;
  private constructor(
    private readonly client: GcpCloudKmsClient,
    private readonly version: string,
    private readonly publicKey: Readonly<DnsIdJWK>,
  ) {
    this.activeKid = publicKey.kid;
    this.keys.set(publicKey.kid, { version, jwk: publicKey, state: 'active' });
  }

  static async load(client: GcpCloudKmsClient | undefined, config: GcpCloudKmsConfig): Promise<GcpCloudKmsKeyProvider> {
    const version = config.activeKeyVersion;
    if (typeof version !== 'string' || !/^projects\/[A-Za-z0-9._:-]+\/locations\/[A-Za-z0-9_-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+\/cryptoKeyVersions\/[1-9][0-9]*$/.test(version)) {
      throw new ArgumentError('Google Cloud KMS requires an immutable CryptoKeyVersion name');
    }
    if (config.algorithm !== 'EC_SIGN_ED25519') throw new ArgumentError('Google Cloud KMS algorithm must be EC_SIGN_ED25519');
    if (config.retainedKeyVersions?.length) throw new ArgumentError('Google Cloud KMS retained key loading is not supported');
    if (!client) {
      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      client = new KeyManagementServiceClient();
    }
    const [raw] = await client.getPublicKey({ name: version });
    const response = raw as PublicResponse | undefined;
    if (response?.name !== version) throw new ArgumentError('Google Cloud KMS public key version mismatch');
    // Official protobuf clients return numeric enums; REST and injected clients may use names.
    if (response.algorithm !== 'EC_SIGN_ED25519' && response.algorithm !== 40) throw new ArgumentError('Google Cloud KMS public key algorithm mismatch');
    if (response.protectionLevel !== 'SOFTWARE' && response.protectionLevel !== 1) throw new ArgumentError('Google Cloud KMS public key must use SOFTWARE protection');
    if (typeof response.pem !== 'string' || !checksumMatches(Buffer.from(response.pem), response.pemCrc32c)) {
      throw new ArgumentError('Google Cloud KMS public PEM checksum mismatch');
    }
    let publicKey: DnsIdJWK;
    try {
      if (!response.pem.startsWith('-----BEGIN PUBLIC KEY-----')) throw new Error();
      const key = createPublicKey({ key: response.pem, format: 'pem', type: 'spki' });
      if (key.asymmetricKeyType !== 'ed25519') throw new Error();
      const exported = key.export({ format: 'jwk' });
      publicKey = { kty: 'OKP', crv: 'Ed25519', x: exported.x!, kid: '', alg: 'EdDSA', use: 'sig' };
    } catch {
      // Do not include the response or parser error in diagnostics.
      throw new ArgumentError('Google Cloud KMS returned invalid Ed25519 public SPKI');
    }
    publicKey.kid = await jwkThumbprint(publicKey);
    return new GcpCloudKmsKeyProvider(client, version, Object.freeze(publicKey));
  }

  async signingKey(): Promise<DnsIdJWK> {
    if (!this.activeKid) throw new ArgumentError('Google Cloud KMS has no active key');
    return this.jwk(this.activeKid);
  }
  async jwk(kid: string): Promise<DnsIdJWK> {
    const key = this.keys.get(kid);
    if (!key) throw new ArgumentError('Google Cloud KMS key not found');
    return { ...key.jwk };
  }
  async listKeyIds(): Promise<string[]> { return this.activeKid ? [this.activeKid] : []; }
  async sign(payload: Uint8Array): Promise<Uint8Array> {
    if (!this.activeKid) throw new ArgumentError('Google Cloud KMS has no active key');
    return this.signKey(this.activeKid, payload);
  }
  async signKey(kid: string, payload: Uint8Array): Promise<Uint8Array> {
    if (this.activating) throw new ArgumentError('Google Cloud KMS activation is in progress');
    const key = this.keys.get(kid);
    if (!key || key.state === 'superseded') throw new ArgumentError('Google Cloud KMS key is not active or pending');
    const operation = this.signVersion(key.version, payload);
    this.signing.add(operation);
    try { return await operation; }
    finally { this.signing.delete(operation); }
  }
  private async signVersion(version: string, payload: Uint8Array): Promise<Uint8Array> {
    // Snapshot caller-owned bytes before crossing the asynchronous transport boundary.
    const data = new Uint8Array(payload);
    const [raw] = await this.client.asymmetricSign({ name: version, data, dataCrc32c: { value: crc32c(data) } });
    const response = raw as SignResponse | undefined;
    if (response?.name !== version) throw new ArgumentError('Google Cloud KMS signature version mismatch');
    if (response.verifiedDataCrc32c !== true) throw new ArgumentError('Google Cloud KMS did not verify data checksum');
    const signature = typeof response.signature === 'string'
      ? Buffer.from(response.signature, 'base64') : response.signature;
    if (!(signature instanceof Uint8Array) || signature.byteLength !== 64) throw new ArgumentError('Google Cloud KMS returned invalid Ed25519 signature');
    if (!checksumMatches(signature, response.signatureCrc32c)) throw new ArgumentError('Google Cloud KMS signature checksum mismatch');
    return new Uint8Array(signature);
  }
  /** Explicit operator generation only; never called by configuration opening. */
  async generateKey(): Promise<string> {
    if (!this.client.createCryptoKeyVersion) throw new ArgumentError('Google Cloud KMS client does not support version creation');
    const parent = this.version.slice(0, this.version.lastIndexOf('/cryptoKeyVersions/'));
    const [raw] = await this.client.createCryptoKeyVersion({ parent, cryptoKeyVersion: { state: 'ENABLED' } });
    const created = raw as { name?: string; algorithm?: string | number; protectionLevel?: string | number; state?: string | number } | undefined;
    if (!created?.name?.startsWith(parent + '/cryptoKeyVersions/')
      || (created.algorithm !== 'EC_SIGN_ED25519' && created.algorithm !== 40)
      || (created.protectionLevel !== 'SOFTWARE' && created.protectionLevel !== 1)
      || (created.state !== 'ENABLED' && created.state !== 1)) {
      throw new ArgumentError('Google Cloud KMS created an unexpected key version');
    }
    // Reuse the same integrity and immutable-version validation as existing-key opening.
    const pending = await GcpCloudKmsKeyProvider.load(this.client, { activeKeyVersion: created.name, algorithm: 'EC_SIGN_ED25519' });
    const jwk = await pending.signingKey();
    if (this.keys.has(jwk.kid)) throw new ArgumentError('Google Cloud KMS generated duplicate public key');
    this.keys.set(jwk.kid, { version: created.name, jwk: Object.freeze(jwk), state: 'pending' });
    return jwk.kid;
  }
  async activate(kid: string): Promise<void> {
    if (this.activating) throw new ArgumentError('Google Cloud KMS activation is already in progress');
    const key = this.keys.get(kid);
    if (!key || key.state !== 'pending') throw new ArgumentError('Google Cloud KMS key is not pending');
    this.activating = true;
    try {
      await Promise.allSettled(this.signing);
      if (this.activeKid) this.keys.get(this.activeKid)!.state = 'superseded';
      key.state = 'active';
      this.activeKid = kid;
    } finally { this.activating = false; }
  }
  /**
   * Removes local signing eligibility from an active, pending, or already
   * superseded key. Superseding the active key leaves no active signer and an
   * empty live key list; superseding another key does not clear its successor.
   * The public JWK remains available through `jwk` for historical verification.
   * Never disables, destroys, or otherwise mutates the remote CryptoKeyVersion.
   */
  async supersede(kid: string): Promise<void> {
    if (this.activating) throw new ArgumentError('Google Cloud KMS activation is in progress');
    const key = this.keys.get(kid);
    if (!key) throw new ArgumentError('Google Cloud KMS key not found');
    key.state = 'superseded';
    if (this.activeKid === kid) this.activeKid = undefined;
  }
  /** Alias for local supersession; never disables or destroys a cloud version. */
  async purge(kid: string): Promise<void> { return this.supersede(kid); }

}

function checksumMatches(bytes: Uint8Array, checksum: Checksum): boolean {
  const raw = checksum?.value;
  if (raw === undefined || raw === null) return false;
  // google-gax can decode int64 wrappers as numbers, decimal strings or Long objects.
  const text = String(raw);
  if (!/^[0-9]+$/.test(text)) return false;
  const value = Number(text);
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff && value === crc32c(bytes);
}

function crc32c(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
