import { describe, expect, it } from 'vitest';
import { KMSClient } from '@aws-sdk/client-kms';

import { verifyWithKey } from '@dnsid-ai/protocol';
import { AwsKmsKeyProvider, AwsSdkKmsFacade } from '@dnsid-ai/key-aws';

const runLocalStack = process.env['DNSID_AWS_KMS_LOCALSTACK'] === '1';

describe.skipIf(!runLocalStack)('AwsKmsKeyProvider LocalStack smoke', () => {
  it('creates a KMS signing key, signs through AWS SDK wiring, and verifies locally', async () => {
    const client = new KMSClient({
      region: process.env['AWS_REGION'] ?? 'us-east-1',
      endpoint: process.env['AWS_ENDPOINT_URL'] ?? 'http://localhost:4566',
      credentials: {
        accessKeyId: process.env['AWS_ACCESS_KEY_ID'] ?? 'test',
        secretAccessKey: process.env['AWS_SECRET_ACCESS_KEY'] ?? 'test',
      },
    });
    const state = { activeKeyId: 'placeholder-active', retainedKeyIds: [], pendingKeyIds: [] };
    const facade = new AwsSdkKmsFacade(client);
    let provider: AwsKmsKeyProvider;
    try {
      provider = await AwsKmsKeyProvider.load(facade, {
        state,
        algorithm: 'ECDSA_SHA_256',
        keySpec: 'ECC_NIST_P256',
        description: 'DNSid LocalStack smoke test key',
      });
    } catch (e) {
      if ((e as { name?: string }).name !== 'NotFoundException') throw e;
      const created = await facade.createSigningKey({
        keySpec: 'ECC_NIST_P256',
        description: 'DNSid LocalStack smoke test initial key',
      });
      state.activeKeyId = created.keyId;
      provider = await AwsKmsKeyProvider.load(facade, {
        state,
        algorithm: 'ECDSA_SHA_256',
        keySpec: 'ECC_NIST_P256',
        description: 'DNSid LocalStack smoke test key',
      });
    }

    const newKid = await provider.generateKey();
    await provider.activate(newKid);

    const payload = new TextEncoder().encode('localstack smoke payload');
    const signature = await provider.sign(payload);
    const signingKey = await provider.signingKey();

    expect(signature).toHaveLength(64);
    expect(await verifyWithKey(payload, signature, signingKey, 'ES256')).toBe(true);
  });
});
