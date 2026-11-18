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

Persist `provider.stateSnapshot()` after `generateKey()`, `activate()`, or `supersede()`. The package mutates the supplied `state` object, but persistence is the caller's job.

## SDK configuration

The Node SDK lazily selects this optional package for `keySource.provider: "aws-kms"`.
Use an existing `keyRef` and non-secret `settings` with optional `region` and
`algorithm` (`EdDSA`, the default, or `ES256`). Authentication uses ambient AWS credentials;
raw secrets are rejected. `createAwsKmsKeyProvider(keyRef, settings)` provides the same factory
for explicit composition.

Configuration-driven cloud generation is not supported: use an existing stable reference.
Explicit alias bootstrap is a separate key action, not a configuration side effect.
The SDK configuration constructor checks the resolved key against verified publication before returning a signing manager.
Changing an alias to another key requires authorized rotation and updated publication.
The standalone factory only opens the key; its caller owns identity binding checks.

## Explicit create or reuse

```ts
import { KMSClient } from '@aws-sdk/client-kms';
import { AwsSdkKmsFacade, createOrReuseAwsKmsKeyProvider } from '@dnsid-ai/key-aws';

const { keyRef, keyProvider } = await createOrReuseAwsKmsKeyProvider(
  new AwsSdkKmsFacade(new KMSClient({ region: 'us-east-1' })),
  { aliasName: 'alias/my-operational-key', algorithm: 'ECDSA_SHA_256' },
);
// Persist keyRef and keyProvider.stateSnapshot() in caller-owned storage.
```

The exact caller-selected alias is scoped to the injected client's account and region.
There is no name allocation or cross-region sharing. Existing winners are validated for
canonical ID, signing metadata and public material before returning a standalone signer.
Only an initial `NotFoundException` permits creating a candidate. `CreateAlias` acquires
an unused alias; only `AlreadyExistsException` permits one winner reread. Other native
errors propagate unchanged, including an unreadable winner or ambiguous acquisition.
There is no polling: a later explicit invocation may resolve an alias after response loss.

Bootstrap never retargets an alias, disables a key or schedules deletion. Losing-candidate
lifecycle disposition is deferred; this non-destructive partial operation does not establish
permanent retention policy. Candidates can remain after conflicts or ambiguous failures;
plan for their cost and a separately authorized lifecycle resolution. Do not use ordinary
rotation deletion settings as bootstrap cleanup policy.

The returned winner is active only within the standalone provider. This action does not
register an agent, publish registry/DNS/log state, verify published identity binding, or
authorize rotation. Agent-ID creation is a separate explicit action. Ordinary opening
remains existing-only; rotation generation remains fresh and pending.

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

Explicit bootstrap additionally needs:

- `kms:CreateKey` for a missing alias candidate
- `kms:CreateAlias` to acquire the caller-selected alias (authorize both the alias and target key as required by AWS IAM)

Scope permissions to the intended account, region and resources. Bootstrap does not need
alias update/delete, key disable or key deletion permissions.

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
