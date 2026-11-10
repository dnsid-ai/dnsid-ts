# @dnsid-ai/key-aws

AWS KMS-backed DNSid `KeyProvider`.

Private keys stay in AWS KMS. This package fetches public keys, exposes them as DNSid JWKs, signs through KMS, and manages active/pending/retained key state.

## Install

```sh
npm install @dnsid-ai/key-aws @dnsid-ai/protocol @aws-sdk/client-kms
```

## Usage

```ts
import { KMSClient } from '@aws-sdk/client-kms';
import { AwsKmsKeyProvider, AwsSdkKmsFacade } from '@dnsid-ai/key-aws';

const state = {
  activeKeyId: 'alias/dnsid-current',
  retainedKeyIds: [],
  pendingKeyIds: [],
};

const provider = await AwsKmsKeyProvider.load(
  new AwsSdkKmsFacade(new KMSClient({ region: 'us-east-1' })),
  {
    state,
    algorithm: 'ECDSA_SHA_256',
    keySpec: 'ECC_NIST_P256',
  },
);

const signature = await provider.sign(new TextEncoder().encode('payload'));
const jwk = await provider.signingKey();
```

For an existing active provider, persist `provider.stateSnapshot()` after
`generateKey()`, `activate()`, or `supersede()`. The package mutates the supplied
`state` object, but persistence is the caller's job.

First-key `create()` is different: persist the returned immutable `keyRef` and
public-key binding in application-owned durable storage before activation. Its
pending-only snapshot has no active key ID and cannot be reopened with
`load({ state })`. If restarting with only the handed-off reference, deliberately
select it with `load({ activeKeyId: savedKeyRef, ... })`; prior local activation
is not required, and the reopened key is locally active. Do not discard saved
provider or managed-rotation state to use this reference-only path. Local
signing eligibility does not establish publication or protocol identity status.

For first-key creation, explicitly call `AwsKmsKeyProvider.create`; no existing
key is required. See the
[KMS-first setup guide](https://github.com/dnsid-ai/dnsid-ts/blob/main/docs/kms-first-setup.md)
for pending-key activation, canonical ARN handoff, publication boundaries, and
failure recovery. Subsequent startup must reopen the saved key with `load`,
never recreate it; normal configuration remains open-only.

## SDK configuration

The Node SDK lazily selects this optional package for `keySource.provider: "aws-kms"`.
Use an existing `keyRef` and non-secret `settings` with optional `region` and
`algorithm` (`EdDSA`, the default, or `ES256`). Authentication uses ambient AWS credentials;
raw secrets are rejected. `createAwsKmsKeyProvider(keyRef, settings)` provides the same factory
for explicit composition.

Configuration-driven cloud generation is not supported: use an existing stable reference
because KMS creation lacks atomic named create-or-recover. The SDK configuration constructor
checks the resolved key against verified publication before returning a signing manager.
Changing an alias to another key requires authorized rotation and updated publication.
The standalone factory only opens the key; its caller owns identity binding checks.

### AWS Ed25519 multi-Region keys

[AWS documents asymmetric multi-Region keys](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html)
and [Ed25519 signing](https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html).
This is a vendor-documented setup pattern, not live-service verification or a
promise that every account/region supports the combination. Check current service
availability, CLI support and organization policies before provisioning; stop on
an unsupported combination rather than substituting another algorithm.

Provision outside application startup, using a separately authorized operator.
For example, in one account and AWS partition (shell variables below are operator
inputs/output, not SDK environment settings):

```sh
set -eu
primary_region=us-east-1
replica_region=us-west-2
primary_arn=$(aws kms create-key --region "$primary_region" \
  --multi-region --key-spec ECC_NIST_EDWARDS25519 --key-usage SIGN_VERIFY \
  --query KeyMetadata.Arn --output text)
replica_arn=$(aws kms replicate-key --region "$primary_region" \
  --key-id "$primary_arn" --replica-region "$replica_region" \
  --query ReplicaKeyMetadata.Arn --output text)
aws kms describe-key --region "$primary_region" --key-id "$primary_arn"
aws kms describe-key --region "$replica_region" --key-id "$replica_arn"
```

Save the exact returned ARNs. Confirm `MultiRegionConfiguration` links the two
keys, `KeySpec` is `ECC_NIST_EDWARDS25519`, `KeyUsage` is `SIGN_VERIFY`, and both
keys are enabled before use. Set a finite readiness deadline and RPC timeouts;
if a key is still creating, recheck within that budget, not in an endless loop.
Do not blindly repeat creation after a lost response. Runtime principals need
`kms:GetPublicKey` and `kms:Sign` on each regional key; replication/provisioning
permissions belong to the operator, not ordinary startup.

Configure two independent clients with **different immutable regional key ARNs
and matching regions**, explicitly selecting `EdDSA`. These are deployment JSON
fragments; replace the illustrative account/key IDs with the returned ARNs:

```json
{"keySource":{"provider":"aws-kms","keyRef":"arn:aws:kms:us-east-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef","settings":{"region":"us-east-1","algorithm":"EdDSA"}}}
```

```json
{"keySource":{"provider":"aws-kms","keyRef":"arn:aws:kms:us-west-2:123456789012:key/mrk-0123456789abcdef0123456789abcdef","settings":{"region":"us-west-2","algorithm":"EdDSA"}}}
```

Use ambient AWS credentials. Do not send the primary ARN to the replica region
and rely on redirection. Related MRKs share key material and a key ID, not one
global ARN: policies, grants, aliases and enabled state are regional. An `mrk-`
prefix alone proves neither relationship nor public-key equality.

Opening configuration never generates or replicates keys and has no automatic
regional failover or local-signer fallback. Explicit provider creation/rotation
is not automatic MRK replication or fleet coordination. Preserve existing
publication/signing-key binding checks; changing configuration does not authorize
replacing an established signer.

`EdDSA` uses `ED25519_SHA_512` with **RAW data, at most 4096 bytes**. Oversized
payloads fail. Do not hash them and substitute Ed25519ph/DIGEST: that is not the
same signature scheme. See [AWS Sign limits](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html).

Go and TypeScript AWS providers retain canonical native KMS identifiers as
JWK `kid` values, so related regional keys can have different kids. Python AWS
uses public-key thumbprint kids while retaining native references separately.

For cryptographic equality, require public JWK `kty=OKP`, `crv=Ed25519`,
`alg=EdDSA`, equal `x`, and no private `d`. Independently compute RFC 7638 SHA-256
thumbprints over canonical JSON containing only `crv`, `kty`, `x`; compare those,
not entire serialized JWKs or native references. Sign the same bounded raw payload through
each client and independently verify both signatures with the common public key
(and the other client's public key). Reopen the exact saved references and repeat;
signature-byte equality is not the acceptance criterion. Unrelated keys cannot
satisfy this check; the SDK does not discover cross-region misconfiguration.

Plan cleanup before allocation. For owned disposable fixtures,
[schedule replica deletion before deleting the primary](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html#deleting-mrks)
and verify each key's disposition. Scheduled deletion is delayed, not completed
removal; retain an owner/follow-up for outstanding resources. Never delete shared
keys as test cleanup.

## Supported KMS keys

| DNSid/JWS alg | AWS signing algorithm | AWS key spec |
| --- | --- | --- |
| `ES256` | `ECDSA_SHA_256` | `ECC_NIST_P256` |
| `EdDSA` | `ED25519_SHA_512` | `ECC_NIST_EDWARDS25519` |

Loaded keys must have:

- `KeyUsage: SIGN_VERIFY`
- matching `KeySpec`
- `SigningAlgorithms` containing the configured algorithm

Aliases, alias ARNs, key IDs, and key ARNs are accepted. They are resolved to canonical KMS key IDs on load.

## IAM permissions

Minimum runtime permissions:

- `kms:GetPublicKey`
- `kms:Sign`

First-key creation permission:

- `kms:CreateKey` for `AwsKmsKeyProvider.create()`
- `kms:TagResource` only when `tags` are supplied

Rotation permissions, if used:

- `kms:CreateKey` for `generateKey()`
- `kms:TagResource` only when `tags` are supplied
- `kms:ScheduleKeyDeletion` for `supersede()` when `scheduleKeyDeletionOnPurge` is enabled

## Rotation

Like first-key `create()`, `generateKey()` requires the `getPublicKey` response
for the newly created key to include a nonempty immutable `keyId` matching the
created reference. A bare key UUID may resolve to its matching canonical key ARN.
An omitted or unrelated response ID rejects generation before adding a pending
key, even though the remote key has already been created; the operator owns
reconciliation and cleanup. Response `keyId` remains optional when opening an
existing key with `load()`.

```ts
const nextKid = await provider.generateKey();
await provider.activate(nextKid);
await provider.supersede('old-key-id');

await saveState(provider.stateSnapshot());
```

Pending keys are not published by `listKeyIds()` or `jwk()`. Activating a pending key moves the previous active key to retained.

## Large payloads

AWS KMS RAW signing is limited to 4096 bytes. For `ECDSA_SHA_256`, larger payloads are SHA-256 hashed locally and signed with KMS `DIGEST` mode. `ED25519_SHA_512` remains RAW-only.

## LocalStack smoke test

From the repo root:

```sh
DNSID_AWS_KMS_LOCALSTACK=1 npm run test:aws-kms:localstack
```
