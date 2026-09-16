# @dnsid-ai/key-gcp

**Private placeholder — not published to npm.**

Reserved workspace package for a future Google Cloud KMS-backed DNSid key provider. It is marked `"private": true` and is excluded from releases.

The current source is a stub: `GcpCloudKmsKeyProvider` implements the `KeyProvider` interface shape from `@dnsid-ai/protocol`, but every method throws `ArgumentError`. Do not depend on this package.

For a working cloud KMS key provider, use `@dnsid-ai/key-aws` (AWS KMS). For local file-backed keys, use `LocalKeyProvider` from `@dnsid-ai/sdk/node`.

## Intended shape

When implemented, the provider will wrap Cloud KMS `CryptoKeyVersion` resources:

```ts
import { GcpCloudKmsKeyProvider } from '@dnsid-ai/key-gcp';

const keyProvider = await GcpCloudKmsKeyProvider.load(kmsClient, {
  activeKeyVersion: 'projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
  algorithm: 'EC_SIGN_P256_SHA256',
});
```

Completing the implementation requires adding `@google-cloud/kms` and filling in the stubbed methods.
