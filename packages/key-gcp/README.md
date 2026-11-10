# @dnsid-ai/key-gcp

Optional Node.js Google Cloud KMS provider that opens existing **software
EC_SIGN_ED25519** key versions or explicitly creates a pending first version
through `create()` under an existing compatible CryptoKey. Install this package
separately from the base SDK; its Google dependency is not required by base SDK
consumers.

```ts
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { GcpCloudKmsKeyProvider } from '@dnsid-ai/key-gcp';

const keyProvider = await GcpCloudKmsKeyProvider.load(new KeyManagementServiceClient(), {
  activeKeyVersion: 'projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
  algorithm: 'EC_SIGN_ED25519',
});
```

Use ambient Google credentials with `cloudkms.cryptoKeyVersions.viewPublicKey`
and `cloudkms.cryptoKeyVersions.useToSign` permissions. Both initial `create()`
and rotation through `generateKey()` also require
`cloudkms.cryptoKeyVersions.create` and `cloudkms.cryptoKeyVersions.get` for
version creation and readiness metadata reads. Initial `create()` additionally
requires `cloudkms.cryptoKeys.get` to validate the existing parent. Grant the
version metadata-read permission before either operation: a readiness read can
fail after the remote version has already been created.
The reference must name a numeric immutable version, not a parent or alias. The
provider exports only the public Ed25519 JWK, with an RFC 7638 thumbprint as `kid`.
It sends raw data (never a digest) and verifies request/response CRC32C integrity
and returned version bindings. Google transport and permission errors propagate;
there is no local signing fallback, key import, or generation during opening.

For first-key creation, explicitly call `GcpCloudKmsKeyProvider.create` with an
existing `ASYMMETRIC_SIGN` CryptoKey parent whose version template is
`EC_SIGN_ED25519` / `SOFTWARE`; no prior version is required. See the
[KMS-first setup guide](https://github.com/dnsid-ai/dnsid-ts/blob/main/docs/kms-first-setup.md) for pending-key activation,
reference handoff, publication boundaries, and failure recovery. Subsequent
startup must reopen the saved immutable version with `load`, never recreate it;
normal configuration remains open-only.

Configuration selects this optional package with `provider: "google-kms"`, the
immutable version as `keyRef`, and optional `settings.algorithm: "EdDSA"` (the
only supported deployment algorithm). SDK composition translates `EdDSA` to the
Cloud KMS `EC_SIGN_ED25519` algorithm; direct `GcpCloudKmsConfig.algorithm` remains
`EC_SIGN_ED25519`, as in the example above.
Only the selected package is imported; injected providers bypass selection.

```ts
const keySource = {
  provider: 'google-kms',
  keyRef: 'projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
  settings: { algorithm: 'EdDSA' },
};
```

An explicit `generateKey()` or `generateKey('EdDSA')` creates a pending software
Ed25519 version under the same CryptoKey. Other requested algorithms are rejected
before creation. `validateKeyGeneration('EdDSA')` checks algorithm support without
creating a version. Like first-key creation, generation waits for the exact created
version to become enabled, polling pending generation at most 20 times, 250ms apart.
Transport call deadlines remain caller-owned. Post-create failures retain the known
version reference and cause; service/integrity failures are not caller-argument
errors. There is no automatic recreation or deletion on failure.
Generation does not change deployment configuration or the active signer.
Pending keys support `jwk` and `signKey`; `activate` drains in-flight signatures
and blocks new signing while promoting the pending key. `listKeyIds` contains
only the active ID, or is empty after local supersession. `supersede` and its
`purge` alias change local eligibility only; no cloud version is disabled or
destroyed. Historical public keys remain available through `jwk`.

Lifecycle state is in memory. Applications own durable recovery and publication
orchestration. For recovery, pass the application's saved immutable A reference
as `activeKeyVersion` and saved B reference as optional `pendingKeyVersion` to
`load`. Both versions and public bindings are validated; duplicate versions or
public-key identities are rejected. B is inserted directly as pending: `jwk` and
rotation `signKey` are available, while `signingKey`, `sign`, and `listKeyIds`
continue to select only A. Existing `activate` performs the local transition.
This input is saved application state, not key discovery or permission to activate;
managed recovery still validates the saved rotation's exact bindings. Ordinary
A-only loading is unchanged and does not discover pending state.
Retained-key configuration loading is rejected. Lifecycle behavior implements
the provisional shared #56 clarification, not a claim of contract acceptance.
