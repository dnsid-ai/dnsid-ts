# @dnsid-ai/sdk

Ergonomic aggregate package for DNSid TypeScript consumers.

The root `@dnsid-ai/sdk` entrypoint is runtime-neutral: callers inject DNS resolution, JSON fetching, key-provider, cache, and log implementations. Node.js defaults live behind the `@dnsid-ai/sdk/node` subpath and optional `@dnsid-ai/transport` peer.

## Package layout

- **Root export (`@dnsid-ai/sdk`)** — runtime-neutral. No Node built-ins, `Buffer`, filesystem, or `undici` imports; you inject `dnsResolver`, `fetchJson`, and key providers. Safe to bundle for browsers and other non-Node runtimes. Its managed C2SP workflows use the portable writer-only binding entrypoint.
- **`@dnsid-ai/sdk/node` subpath** — Node conveniences: `LocalKeyProvider`, configuration loaders (`loadEnvironment`, `loadFile`, `loadCliDirectory`, `mergeLoadedConfig`, `constructIdentityManager`), `createNodeIdentityManager`, and the one-call `createNodeIdentityManagerFromEnvironment` / `FromDnsid` / `FromFile`, plus durable managed registration with `registerManagedIdentity` and `FileRegistrationStore`. Loads the optional `@dnsid-ai/transport` peer when HTTPS defaults are needed.
- **OIDC lives in `@dnsid-ai/oidc`** — deliberately not re-exported from the root because its default transport is Node-bound, and private-key token minting belongs server-side. Import it directly.

## Install

```sh
npm install @dnsid-ai/sdk
```

For Node defaults:

```sh
npm install @dnsid-ai/sdk @dnsid-ai/transport
```

## Runtime-neutral usage

```ts
import { createIdentityManager } from '@dnsid-ai/sdk';

const idm = createIdentityManager({ identity, verification }, {
  keyProvider,       // operational ku key
  entityKeyProvider, // accountable-entity ek key
  dnsResolver,
  fetchJson,
});
```

For verification-only use, no local identity configuration or key provider is needed:

```ts
import { createIdentityVerifier } from '@dnsid-ai/sdk';

const verifier = createIdentityVerifier(
  { verification: { trustedEntities: [{ governanceId: 'agent.example' }] } },
  { dnsResolver, fetchJson, logRegistry },
);
const verified = await verifier.verifyDomain('agent.example');
```

JOSE, HTTP Message Signature, and OIDC profiles may use this verifier as their
`identityResolver` while omitting `keyProvider`. Their signing or minting methods
then fail with `ArgumentError`.

### Registry-managed C2SP key rotation

`rotateManagedOperationalKey()` composes the registry client, C2SP prepared-event
binding, and operational `KeyProvider`. It validates and signs the registry's
prepared bytes, then activates the pending key only after the registry accepts
those exact bytes. This does not change the generic/self-managed
`IdentityManager.rotateOperationalKey()` workflow.

If the result is pending, or `ManagedKeyRotationSubmissionError` reports
`retryWithSameBytes`, persist its rotation state, pause new application signing,
and call `resumeManagedOperationalKeyRotation()` with that exact state. Do not
generate a replacement event or idempotency key.

If `ManagedKeyRotationActivationError` is raised, registry acceptance succeeded
but local key-state reconciliation is incomplete. Resume with the error's exact
rotation state; already-completed activation or supersession is not repeated.

## Node.js convenience usage

```ts
import { createNodeIdentityManagerFromEnvironment } from '@dnsid-ai/sdk/node';

// Loaders parse; constructors default. Identity from DNSID_*, keys from DNSID_CONFIG_DIR or
// DNSID_KEY_STORE, log trust from DNSID_LOG_POLICY_URL / _FILE / DNSID_LOG_TRUST_PROFILE_FILE.
// Without DNSID_DOMAIN the result is a verification-only manager.
const idm = await createNodeIdentityManagerFromEnvironment();
```

`createNodeIdentityManagerFromEnvironment(env?, overlay?, deps?)` is exactly
`constructIdentityManager(mergeLoadedConfig(await loadEnvironment(env), { dnsid: overlay }), deps)`;
`createNodeIdentityManagerFromDnsid(dir?)` and `createNodeIdentityManagerFromFile(path)` are the same
shape over `loadCliDirectory` and `loadFile`. Compose sources yourself with `mergeLoadedConfig`
(field-wise, presence wins, lists replace, `logTrust` atomic). Supplied `deps` always win over loaded
`logTrust` and `keySource`. The environment schema is in the repository README.

```ts
import { createNodeIdentityManager, LocalKeyProvider } from '@dnsid-ai/sdk/node';

const keyProvider = await LocalKeyProvider.load('.dnsid/keys.json', true);
const entityKeyProvider = await LocalKeyProvider.load('.dnsid/entity.keys.json', true);
const idm = await createNodeIdentityManager({ identity, verification }, { keyProvider, entityKeyProvider });
```

`config.transport.dnsServer`/`caBundlePath` configure only the SDK-managed default resolver and
fetcher; a setting is rejected when every dependency it would configure is injected.

`LocalKeyProvider.load(path)` loads an existing store; pass `true` to create one when missing.
Use only one provider instance/process per store; mutations within that instance are serialized.
Persistence uses flushed, mode-0600 sibling files and atomic replacement, keeping the previous
successful generation at `<path>.bak`. Existing symlinks are resolved at load time; mutations and
backups use the resolved target path without replacing the link. The filesystem must support atomic rename, hard links,
and directory fsync. Protect and exclude the store, backup, and sibling `*.tmp` files from source
control; backups and crash-leftover temp files contain private keys. This is not an off-host backup.
If a mutation fails before replacement, the live store and in-memory keys are unchanged. A directory
fsync failure after replacement is reported, but memory follows the now-visible file; inspect it
before retrying. Recovery is manual: stop all users of the store, preserve both files, and validate
the backup against the registry/log state before restoring it. A backup can predate key activation
or contain a superseded key; it is never automatically loaded.
For `dnsid-draft-01` publishing, set `DNSID_EK_URL` to the accountable-entity JWKS URL and `DNSID_KU_URL` to the operational JWKS URL.
The Node helper uses the system or configured DNS resolver by default. It reports `UNKNOWN`, which the default `auto` policy permits and preserves. Inject a DNSSEC-aware resolver for `validated` or `required` policy.

If the registry CLI has already written `~/.dnsid/config.json` and `~/.dnsid/<fqdn>/private.jwk`:

```ts
import { createNodeIdentityManagerFromDnsid } from '@dnsid-ai/sdk/node';

const idm = await createNodeIdentityManagerFromDnsid(); // ~/.dnsid by default; never reads DNSID_CONFIG_DIR
```

The CLI loader maps persisted fields as written: a missing `status_url` or `log_ref` fails construction with `ArgumentError` unless the overlay supplies it.

DNSSEC modes are: `auto` (default), which rejects `FAILED` and permits `VALID`, `UNSIGNED`, or `UNKNOWN`; `validated`, which permits `VALID` or `UNSIGNED`; and `required`, which permits only `VALID`.

## Durable managed registration

`registerManagedIdentity()` creates or resumes a named registry-managed identity. The SDK owns
account discovery, key selection, durable recovery, managed C2SP issuance, publication, and
independent public verification. Live proof and client-controlled publication are separate flows.
Setup does not change application counterparty acceptance.

```ts
import { FileRegistrationStore, loadFile, registerManagedIdentity } from '@dnsid-ai/sdk/node';

const result = await registerManagedIdentity({
  name: 'billing-agent',
  loaded: await loadFile('deployment.json'),
  credential: registryCredential,
  store: new FileRegistrationStore('.dnsid/setup'),
  input: { governanceDomain: 'acme.example' },
});
```

Names are trimmed, case-sensitive display handles with 1–255 Unicode code points, not domains
or paths. Explicit `input.name` must match. The store selects a safe directory by a digest of
the normalized registry URL, organization ID, and name; the same root can hold multiple identities.

Configure explicit `logTrust` and `registration.entityKeyUrl`, an independently selected HTTPS
entity-JWKS endpoint. Organization ID and expected GI come from `registration.organizationId` /
`governanceId`, matching named state, or authenticated `GET /api/v1/org/onboarding`.
Organization ID must be resolved before state selection. Discovery requires verified GI proof,
gate authorization, and verified entity-key delegation, and compares configured/saved bindings.
It cannot supply the entity endpoint. Fully configured accounts require no discovery call.

Expected GI does not select a registry root: supply selectors through `input` explicitly.
Omitted input sends only the name and public key. `registry.registryUrl` and `dnsid.transport`
configure SDK-owned networking. Merge sources explicitly; setup never rereads the environment.

### Replay and server prerequisites

The SDK derives registration and issuance keys using JCS, SHA-256, and unpadded base64url.
The registration key binds organization ID, normalized name, and the initial public key's
RFC 7638 thumbprint; provider aliases, credentials, clocks, and generation counters do not enter it.
Matching replicas must also share the same key and complete creation input.

**Named recovery requires server work; these client changes do not establish deployed support.**
The server must validate derived bindings before allocation, atomically claim the organization/name
and complete request, and permanently retain organization-scoped replay claims through deletion
and retirement. Identical low-level key strings in different organizations are independent.
A credential from the wrong organization must not use a derived key to create or disclose an
identity in either organization. Old replay returns the old identity or a terminal error, never
a replacement. Verify these guarantees with real server persistence/integration tests, not an
acknowledgement flag. Expiring idempotency stores are insufficient.

Unknown creation outcomes reuse the frozen input and derived key. Once immutable identity facts
are known, recovery reads that identity instead of issuing another creation request. Validated
creation facts atomically replace creation-only inputs. Pending issuance retains exact bytes;
after verified inclusion, recovery retains the accepted hash/index/reference and retrieves the
historical entry rather than preparing or appending again. Failed retrieval does not authorize
reissuance. Current key-specific URLs come from registry publication configuration and signed TXT;
the SDK never synthesizes them or falls back to an old endpoint.

Completed calls obtain fresh public evidence, including verified key/URL rotations without the
original private key. Pending rotations require the rotation coordinator. Conflicting inputs,
unexplained keys, and terminal identities stop. Explicit `replace: true` requires confirmed
revocation/retirement and a fresh key, preserves earlier state/key history, and requires a fresh
immutable ID, domain, and log stream. The server must reject every previously used key.

### Key providers

Deployment files support `keySource`, including `provider`, `keyRef`, `generation`, and
non-secret `settings`. Injected `deps.keyProvider` wins and requires a stable `providerReference`;
displaced provider settings/packages are not loaded. An injected `logRegistry` requires an
independently selected `logTrustReference` and C2SP readers with `readIssuance()` for exact-byte,
verified historical recovery; the shipped `C2spTlogReader` provides it.

Default/explicit file custody emits a production-safety warning. File generation supports
EdDSA and ES256. An explicit generation locator is suffixed with the named-scope digest;
persisted locators are recovered, not replaced after ambiguous initialization.

AWS KMS existing keys are selected lazily through the optional `@dnsid-ai/key-aws` package:

```json
{
  "keySource": {
    "provider": "aws-kms",
    "keyRef": "arn:aws:kms:us-east-1:111122223333:key/11111111-1111-4111-8111-111111111111",
    "settings": { "region": "us-east-1", "algorithm": "EdDSA" }
  }
}
```

AWS settings accept region and EdDSA/ES256; authentication uses ambient AWS credential chains,
not secrets in deployment/recovery files. Cloud generation without atomic discovery is rejected:
supply an existing key reference. Google KMS and Azure factories are unavailable in this binding.
Unavailable packages, invalid settings, and conflicting selection fail before account discovery
or mutations, with no file fallback. Ordinary manager construction opens existing keys only.
Configuration-selected AWS keys must match the current operational key of the verified published
identity, including key ID, algorithm, and public material. Missing publication or unavailable
verification fails construction. Managed setup injects its provider and owns these binding checks.
Moving an established signer to another provider requires authorized, publicly verified rotation;
configuration alone cannot import or replace its private key.

### Errors and storage

The finite overall deadline defaults to five minutes; use `timeoutMs` / `signal` to change it.
Injected networking must honor cancellation. In-flight durable writes must settle before the
store lock is released, even after cancellation. Errors preserve structured causes, failed phase,
resumability, known ID/domain, registry status, historical setup completion and issuance state.
Registry READY is not success: public protocol ACTIVE and fresh complete log evidence are required.
The returned manager retains the application's allowlist even when it excludes the setup entity.

`FileRegistrationStore` requires a local POSIX filesystem supporting atomic rename, hard links
(for key creation), and directory fsync throughout the directory's ancestor chain. Named directories/files are owner-only. Competing calls
receive `STORE_BUSY`; locks are never stolen automatically. After an interruption, stop all writers,
back up the root and private-key files, then remove the affected named directory's `setup.lock`.
Keys, backups, and temp files are private material, separate from `setup.json`. Ephemeral
container storage is not an off-host backup.

Recovery uses version 3. Earlier single-operation state is refused without migration or replacement
generation; preserve it and finish with the previous implementation. Missing/corrupt state or keys,
timeouts, and failed evidence do not authorize a fresh identity.

## Included surfaces

`@dnsid-ai/sdk` re-exports the common core and profile surfaces and namespaces:

- `@dnsid-ai/protocol`
- `@dnsid-ai/jose`
- `@dnsid-ai/http-signatures`
- `@dnsid-ai/registry`

Use DNSid OIDC token minting and verification through `@dnsid-ai/oidc`. It is intentionally not re-exported here because its default transport is Node-bound; private-key token minting belongs in server-side code, not browser/client code.

Use lower-level packages directly when you need narrower dependencies or custom composition.
