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
creating a version. Generation does not change deployment configuration or the active signer.
Pending keys support `jwk` and `signKey`; `activate` drains in-flight signatures
and blocks new signing while promoting the pending key. `listKeyIds` contains
only the active ID, or is empty after local supersession. `supersede` and its
`purge` alias change local eligibility only; no cloud version is disabled or
destroyed. Historical public keys remain available through `jwk`.

Lifecycle state is in memory. Applications own durable recovery and publication
orchestration; reopening the configured version does not recover pending state.
Retained-key configuration loading is rejected. Lifecycle behavior implements
the provisional shared #56 clarification, not a claim of contract acceptance.

## Opt-in initial key bootstrap

`createOrReuseGcpCloudKmsKeyProvider(client, config)` explicitly creates or reuses
one named software Ed25519 CryptoKey. Pass the official
`KeyManagementServiceClient`, a compatible five-method `GcpCloudKmsBootstrapClient`,
or `undefined` to use the official client with ambient Google credentials.
Bootstrap needs named-key read/create, version read, public-key read and signing
permissions. Credentials do not belong in configuration.

```ts
import { createOrReuseGcpCloudKmsKeyProvider } from '@dnsid-ai/key-gcp';

const { keyRef, keyProvider } = await createOrReuseGcpCloudKmsKeyProvider(undefined, {
  parent: 'projects/my-project/locations/us-central1/keyRings/operational',
  cryptoKeyId: 'dnsid-acme-research',
});
const publicJwk = await keyProvider.signingKey();
```

The project, location and keyRing must already exist; bootstrap creates no
ancestors. Allocate a stable, collision-free ID for each organization/name pair.
CryptoKey IDs contain 1–63 ASCII letters, digits, underscores or hyphens. The SDK
neither normalizes names nor invents an organization-to-name mapping. The full
(project, location, keyRing, ID) scope identifies this cloud identity.

Only numeric Google service `NOT_FOUND` (5) from the named-key lookup permits
creation. Creation includes the initial version. Numeric `ALREADY_EXISTS` (6)
from creation causes exactly one winner read, so concurrent replicas converge on
the authoritative key. Other native service errors propagate, including a timeout
after a possibly committed create. There is no automatic retry: a later explicit
call with the same scope can recover a committed key. Failed winner reads remain
failures. No replacement key, extra version, fallback signer or rotation is
attempted. Invalid names fail before cloud mutation; incompatible or missing
resource fields, disabled versions and invalid public-key integrity fail closed.

The returned `keyRef` always names immutable initial numeric version **1**;
bootstrap validates that version as enabled software `EC_SIGN_ED25519`, then
uses the existing provider's public-key and signing integrity checks. It never
selects `primary` or `latest`. Missing, disabled or incompatible initial versions
are errors, not permission to generate another version. For an established or
rotated identity, persist and authorize the chosen immutable reference and use
ordinary `load`, rather than bootstrap to choose a successor. Ordinary `load`
and SDK key-source configuration remain open-only: neither creates cloud keys.
Explicit `generateKey` retains its separate pending-rotation behavior above.

Application sequencing is two explicit operations (conceptual, not a registry
API example):

1. Await this SDK key bootstrap and obtain `keyRef`, `keyProvider` and its public JWK.
2. Only after success, separately invoke the application's existing explicit
   agent-ID create/reuse operation with that identity.

Bootstrap itself creates or registers no agent ID and calls no registry API.
On key failure, do not attempt the second operation. The server never creates
keys; applications own key provisioning and agent-ID orchestration. Use one
identity per cloud, not a shared multi-cloud private key.
