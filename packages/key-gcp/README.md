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

Configuration selects this optional package with `provider: "google-kms"`, the
immutable version as `keyRef`, and optional `settings.algorithm: "EC_SIGN_ED25519"`.
Only the selected package is imported; injected providers bypass selection.

An explicit `generateKey()` creates a pending software Ed25519 version under the
same CryptoKey. It does not change deployment configuration or the active signer.
Pending keys support `jwk` and `signKey`; `activate` drains in-flight signatures
and blocks new signing while promoting the pending key. `listKeyIds` contains
only the active ID, or is empty after local supersession. `supersede` and its
`purge` alias change local eligibility only; no cloud version is disabled or
destroyed. Historical public keys remain available through `jwk`.

Lifecycle state is in memory. Applications own durable recovery and publication
orchestration; reopening the configured version does not recover pending state.
Retained-key configuration loading is rejected. Lifecycle behavior implements
the provisional shared #56 clarification, not a claim of contract acceptance.
