# @dnsid-ai/key-gcp

Optional Node.js Google Cloud KMS provider for an existing **software
EC_SIGN_ED25519** key version. Install this package separately from the base SDK;
its Google dependency is not required by base SDK consumers.

```ts
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { GcpCloudKmsKeyProvider } from '@dnsid-ai/key-gcp';

const keyProvider = await GcpCloudKmsKeyProvider.load(new KeyManagementServiceClient(), {
  activeKeyVersion: 'projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
  algorithm: 'EC_SIGN_ED25519',
});
```

Use ambient Google credentials with permission to read the public key and sign.
The reference must name a numeric immutable version, not a parent or alias. The
provider exports only the public Ed25519 JWK, with an RFC 7638 thumbprint as `kid`.
It sends raw data (never a digest) and verifies request/response CRC32C integrity
and returned version bindings. Google transport and permission errors propagate;
there is no local signing fallback, key import, or generation during opening.

This runtime slice supports `signingKey`, `jwk`, `listKeyIds`, `sign`, and
`signKey`. Configuration-factory selection and management methods (`generateKey`,
`activate`, `supersede`, `purge`) are not implemented yet. Retained-key loading
is rejected. No remote version is disabled or destroyed by this package.
