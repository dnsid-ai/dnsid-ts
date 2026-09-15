# @identity-digital/dnsid-key-aws

AWS KMS-backed DNSid `KeyProvider`.

Private keys stay in AWS KMS. This package fetches public keys, exposes them as DNSid JWKs, signs through KMS, and manages active/pending/retained key state.

## Install

```sh
npm install @identity-digital/dnsid-key-aws @identity-digital/dnsid-protocol @aws-sdk/client-kms
```

## Usage

```ts
import { KMSClient } from '@aws-sdk/client-kms';
import { AwsKmsKeyProvider, AwsSdkKmsFacade } from '@identity-digital/dnsid-key-aws';

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

Persist `provider.stateSnapshot()` after `generateKey()`, `activate()`, or `supersede()`. The package mutates the supplied `state` object, but persistence is the caller's job.

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

Rotation permissions, if used:

- `kms:CreateKey` for `generateKey()`
- `kms:ScheduleKeyDeletion` for `supersede()` when `scheduleKeyDeletionOnPurge` is enabled

## Rotation

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
