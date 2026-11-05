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
  private constructor(
    private readonly client: GcpCloudKmsClient,
    private readonly version: string,
    private readonly publicKey: Readonly<DnsIdJWK>,
  ) {}

  static async load(client: GcpCloudKmsClient, config: GcpCloudKmsConfig): Promise<GcpCloudKmsKeyProvider> {
    const version = config.activeKeyVersion;
    if (typeof version !== 'string' || !/^projects\/[A-Za-z0-9._:-]+\/locations\/[A-Za-z0-9_-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+\/cryptoKeyVersions\/[1-9][0-9]*$/.test(version)) {
      throw new ArgumentError('Google Cloud KMS requires an immutable CryptoKeyVersion name');
    }
    if (config.algorithm !== 'EC_SIGN_ED25519') throw new ArgumentError('Google Cloud KMS algorithm must be EC_SIGN_ED25519');
    if (config.retainedKeyVersions?.length) throw new ArgumentError('Google Cloud KMS retained key loading is not supported');
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

  async signingKey(): Promise<DnsIdJWK> { return { ...this.publicKey }; }
  async jwk(kid: string): Promise<DnsIdJWK> {
    this.requireKey(kid);
    return { ...this.publicKey };
  }
  async listKeyIds(): Promise<string[]> { return [this.publicKey.kid]; }
  async sign(payload: Uint8Array): Promise<Uint8Array> { return this.signKey(this.publicKey.kid, payload); }
  async signKey(kid: string, payload: Uint8Array): Promise<Uint8Array> {
    this.requireKey(kid);
    // Snapshot caller-owned bytes before crossing the asynchronous transport boundary.
    const data = new Uint8Array(payload);
    const [raw] = await this.client.asymmetricSign({ name: this.version, data, dataCrc32c: { value: crc32c(data) } });
    const response = raw as SignResponse | undefined;
    if (response?.name !== this.version) throw new ArgumentError('Google Cloud KMS signature version mismatch');
    if (response.verifiedDataCrc32c !== true) throw new ArgumentError('Google Cloud KMS did not verify data checksum');
    const signature = typeof response.signature === 'string'
      ? Buffer.from(response.signature, 'base64') : response.signature;
    if (!(signature instanceof Uint8Array) || signature.byteLength !== 64) throw new ArgumentError('Google Cloud KMS returned invalid Ed25519 signature');
    if (!checksumMatches(signature, response.signatureCrc32c)) throw new ArgumentError('Google Cloud KMS signature checksum mismatch');
    return new Uint8Array(signature);
  }
  private requireKey(kid: string): void {
    if (kid !== this.publicKey.kid) throw new ArgumentError('Google Cloud KMS key not found');
  }

  // Lifecycle implementation awaits separately authored red proof (#56).
  async generateKey(): Promise<string> { throw new ArgumentError('Google Cloud KMS generation is not implemented'); }
  async activate(_kid: string): Promise<void> { throw new ArgumentError('Google Cloud KMS activation is not implemented'); }
  async supersede(_kid: string): Promise<void> { throw new ArgumentError('Google Cloud KMS supersession is not implemented'); }
  async purge(_kid: string): Promise<void> { throw new ArgumentError('Google Cloud KMS supersession is not implemented'); }
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
