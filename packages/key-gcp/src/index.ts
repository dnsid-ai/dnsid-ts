/**
 * Google Cloud KMS key provider placeholder for DNSid.
 *
 * `@dnsid-ai/key-gcp` is a private, unpublished placeholder for a
 * GCP Cloud KMS-backed implementation of the `KeyProvider` contract from
 * `@dnsid-ai/protocol`. Every method of `GcpCloudKmsKeyProvider`
 * currently throws; install `@google-cloud/kms` and complete the implementation
 * before use. See `@dnsid-ai/key-aws` for the working KMS pattern.
 *
 * @packageDocumentation
 */
import type { DnsIdJWK, KeyProvider } from '@dnsid-ai/protocol';
import { ArgumentError } from '@dnsid-ai/protocol';

export interface GcpCloudKmsConfig {
  /** Full resource name of the active CryptoKeyVersion. */
  activeKeyVersion: string;
  /** Full resource names of retained CryptoKeyVersions to include in the JWKS. */
  retainedKeyVersions?: string[];
  /** Cloud KMS algorithm name. Must match the key version. */
  algorithm: string;
}

/**
 * Google Cloud KMS KeyProvider stub.
 *
 * This concrete key-provider package intentionally lives outside `@dnsid-ai/protocol`.
 * Install `@google-cloud/kms` and complete this implementation before use.
 */
export class GcpCloudKmsKeyProvider implements KeyProvider {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private constructor(_client: any, _config: GcpCloudKmsConfig) {
    throw new ArgumentError(
      'GcpCloudKmsKeyProvider is a stub. ' +
      'Install @google-cloud/kms and implement this class before use.',
    );
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static async load(_client: any, _config: GcpCloudKmsConfig): Promise<GcpCloudKmsKeyProvider> {
    throw new ArgumentError(
      'GcpCloudKmsKeyProvider is a stub. ' +
      'Install @google-cloud/kms and implement this class before use.',
    );
  }

  async signingKey(): Promise<DnsIdJWK> { throw new ArgumentError('stub'); }
  async jwk(_kid: string): Promise<DnsIdJWK> { throw new ArgumentError('stub'); }
  async listKeyIds(): Promise<string[]> { throw new ArgumentError('stub'); }
  async sign(_payload: Uint8Array): Promise<Uint8Array> { throw new ArgumentError('stub'); }
  async signKey(_kid: string, _payload: Uint8Array): Promise<Uint8Array> { throw new ArgumentError('stub'); }
  async generateKey(): Promise<string> { throw new ArgumentError('stub'); }
  async activate(_kid: string): Promise<void> { throw new ArgumentError('stub'); }
  async supersede(_kid: string): Promise<void> { throw new ArgumentError('stub'); }
  async purge(_kid: string): Promise<void> { throw new ArgumentError('stub'); }
}
