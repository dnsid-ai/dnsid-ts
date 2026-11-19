import { describe, expect, it, vi } from 'vitest';
import {
  createOrReuseGcpCloudKmsKeyProvider,
  type GcpCloudKmsBootstrapClient,
} from '@dnsid-ai/key-gcp';

const validParent = 'projects/test-project/locations/us-central1/keyRings/operational';
const validCryptoKeyId = 'dnsid-acme-research';

const terminators = [
  { label: 'LF', suffix: '\n' },
  { label: 'CR', suffix: '\r' },
  { label: 'CRLF', suffix: '\r\n' },
  { label: 'U+2028', suffix: '\u2028' },
  { label: 'U+2029', suffix: '\u2029' },
] as const;

function unexpectedCloudClient() {
  const unexpectedCall = new Error('KNOWN62_UNEXPECTED_CLOUD_CALL');
  const client = {
    getCryptoKey: vi.fn<GcpCloudKmsBootstrapClient['getCryptoKey']>()
      .mockRejectedValue(unexpectedCall),
    createCryptoKey: vi.fn<GcpCloudKmsBootstrapClient['createCryptoKey']>()
      .mockRejectedValue(unexpectedCall),
    getCryptoKeyVersion: vi.fn<GcpCloudKmsBootstrapClient['getCryptoKeyVersion']>()
      .mockRejectedValue(unexpectedCall),
    getPublicKey: vi.fn<GcpCloudKmsBootstrapClient['getPublicKey']>()
      .mockRejectedValue(unexpectedCall),
    asymmetricSign: vi.fn<GcpCloudKmsBootstrapClient['asymmetricSign']>()
      .mockRejectedValue(unexpectedCall),
  } satisfies GcpCloudKmsBootstrapClient;
  return client;
}

describe('GCP bootstrap rejects line terminators before cloud access (#62)', () => {
  for (const field of ['cryptoKeyId', 'parent'] as const) {
    for (const { label, suffix } of terminators) {
      it(`rejects ${field} suffixed with ${label} as invalid configuration without cloud calls`, async () => {
        // Given: exactly one otherwise-valid configuration field has a suffix.
        const client = unexpectedCloudClient();
        const config = { parent: validParent, cryptoKeyId: validCryptoKeyId };
        config[field] += suffix;

        // When/Then: a service rejection is not an acceptable validation result.
        // In particular, the cryptoKeyId/LF case must reject as ArgumentError,
        // not merely reject with the fake's unexpected-cloud-call error.
        try {
          await expect(createOrReuseGcpCloudKmsKeyProvider(client, config))
            .rejects.toHaveProperty('name', 'ArgumentError');
        } finally {
          // All five public seam methods must remain untouched, even on failure.
          expect(client.getCryptoKey).not.toHaveBeenCalled();
          expect(client.createCryptoKey).not.toHaveBeenCalled();
          expect(client.getCryptoKeyVersion).not.toHaveBeenCalled();
          expect(client.getPublicKey).not.toHaveBeenCalled();
          expect(client.asymmetricSign).not.toHaveBeenCalled();
        }
      });
    }
  }
});
