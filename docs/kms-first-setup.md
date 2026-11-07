# KMS-first initial setup

Install `@dnsid-ai/key-aws` or `@dnsid-ai/key-gcp` alongside the SDK. Cloud
packages are optional; normal configuration opening never generates keys.
These snippets illustrate application composition, not an executable live smoke
or a complete issuance implementation. Use only for a new identity, never to
replace an established signer (use authorized rotation instead).

With a caller-owned AWS client and ambient credentials:

```ts
import { KMSClient } from '@aws-sdk/client-kms';
import { AwsKmsKeyProvider, AwsSdkKmsFacade } from '@dnsid-ai/key-aws';

const client = new AwsSdkKmsFacade(new KMSClient({ region: 'us-east-1' }));
const created = await AwsKmsKeyProvider.create(client, {
  algorithm: 'ED25519_SHA_512',
  keySpec: 'ECC_NIST_EDWARDS25519',
});
```

Or with an existing Google CryptoKey parent, whose purpose is
`ASYMMETRIC_SIGN` and version template is `EC_SIGN_ED25519` / `SOFTWARE`:

```ts
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { GcpCloudKmsKeyProvider } from '@dnsid-ai/key-gcp';

const client = new KeyManagementServiceClient();
const created = await GcpCloudKmsKeyProvider.create(client, {
  parent: 'projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY',
  algorithm: 'EC_SIGN_ED25519',
});
```

No prior version is required. The SDK validates the parent, creates only a
version, and checks its readiness and public key. It does not create projects,
key rings, or CryptoKeys. Pending generation has a finite polling budget; set
transport deadlines on the supplied client as well. Grant least-privilege
create/public-key/sign permissions (and Google parent/version metadata reads).
AWS Ed25519 availability depends on the service/region; errors do not select a
different algorithm.

Both results contain `{ provider, kid, keyRef }`. `keyRef` is an immutable cloud
reference, not necessarily the same as the binding's `kid`. Private material is
generated and retained inside KMS. The SDK writes no key/state files, performs
no private-key import, and never falls back to a local signer.

## Initial manager injection and publication

The application supplies `config` with its real identity URLs/log reference,
`entityKeyProvider` with a **distinct** accountable-entity key, and `logRegistry`
with independently configured trust. Publication and durable issuance storage
below are application-owned operations, not SDK helpers:

```ts
import { IdentityManager } from '@dnsid-ai/protocol';

// Save the public reference/binding in application-owned durable configuration.
// No SDK file persistence is implicit. This is not protocol activation.
await saveOperationalReference(created.keyRef, await created.provider.jwk(created.kid));
await created.provider.activate(created.kid);
const manager = new IdentityManager(config, {
  keyProvider: created.provider, entityKeyProvider, logRegistry,
});
await publishEntityJwks(await manager.getEntityKeySet()); // configured ek
await publishOperationalJwks(await manager.getKeySet()); // configured ku
await publishNonActiveStatus();                         // configured su
await publishDnsTxt(await manager.createTxtRecord());   // _dnsid.{domain}
```

Do not mark status ACTIVE here. Independently verify externally served DNS,
`ek`, `ku`, and `su`, then prepare, entity-sign and operationally countersign
one ISSUANCE. Persist the exact signed bytes before submission; verify the
accepted entry/hash/reference before converging status to ACTIVE. Recover with
the same issuance, not a second event. See the
[initial setup contract](https://github.com/dnsid-ai/dnsid-sdk-compliance/blob/main/docs/sdk-design/01-core-identity-manager.md#initial-setup-of-local-identity).
The example does not simulate acceptance or claim publication/issuance succeeded.

## Subsequent startup: reopen, never recreate

Use the saved immutable reference, check its public binding against the saved
public key, and preserve normal authenticated startup/publication verification:

```ts
// AWS; use its own caller-owned facade and saved keyRef.
const provider = await AwsKmsKeyProvider.load(client, {
  activeKeyId: savedKeyRef, algorithm: 'ED25519_SHA_512',
});
// Google alternative; use its own caller-owned native client.
const provider = await GcpCloudKmsKeyProvider.load(client, {
  activeKeyVersion: savedKeyRef, algorithm: 'EC_SIGN_ED25519',
});
```

These are alternatives, not two declarations in one program. Loading reads
existing public keys and never creates a replacement. Cloud ENABLED or local
activation does not establish protocol identity status. Keep caller-owned
clients alive until signing completes and close them in application cleanup.

A failed or ambiguous create may leave a billable remote key/version. Do not
blindly retry, recreate, or delete it: the operator owns discovery, reference
recovery and explicit cleanup. No multi-node/idempotent provisioning is promised.
No live cloud execution is required or implied by this example.
