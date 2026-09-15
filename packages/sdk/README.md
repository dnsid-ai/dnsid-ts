# @identity-digital/dnsid

Ergonomic aggregate package for DNSid TypeScript consumers.

The root `@identity-digital/dnsid` entrypoint is runtime-neutral: callers inject DNS resolution, JSON fetching, key-provider, cache, and log implementations. Node.js defaults live behind the `@identity-digital/dnsid/node` subpath and optional `@identity-digital/dnsid-transport` peer.

## Package layout

- **Root export (`@identity-digital/dnsid`)** — runtime-neutral. No Node built-ins, `Buffer`, filesystem, or `undici` imports; you inject `dnsResolver`, `fetchJson`, and key providers. Safe to bundle for browsers and other non-Node runtimes. Its managed C2SP workflows use the portable writer-only binding entrypoint.
- **`@identity-digital/dnsid/node` subpath** — Node conveniences: `LocalKeyProvider`, `configFromEnvironment`, `createNodeIdentityManager`, `createNodeIdentityManagerFromDnsid`. Loads the optional `@identity-digital/dnsid-transport` peer when HTTPS defaults are needed.
- **OIDC lives in `@identity-digital/dnsid-oidc`** — deliberately not re-exported from the root because its default transport is Node-bound, and private-key token minting belongs server-side. Import it directly.

## Install

```sh
npm install @identity-digital/dnsid
```

For Node defaults:

```sh
npm install @identity-digital/dnsid @identity-digital/dnsid-transport
```

## Runtime-neutral usage

```ts
import { createIdentityManager } from '@identity-digital/dnsid';

const idm = createIdentityManager({ identity, verification }, {
  keyProvider,       // operational ku key
  entityKeyProvider, // accountable-entity ek key
  dnsResolver,
  fetchJson,
});
```

For verification-only use, no local identity configuration or key provider is needed:

```ts
import { createIdentityVerifier } from '@identity-digital/dnsid';

const verifier = createIdentityVerifier(
  { verification: { trustedEntities: [{ governanceId: 'acme.example' }] } },
  { dnsResolver, fetchJson, logRegistry },
);
const verified = await verifier.verifyDomain('agent.example.com');
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
import { configFromEnvironment, createNodeIdentityManager, LocalKeyProvider } from '@identity-digital/dnsid/node';

const { config, keyStorePath } = configFromEnvironment();
const keyProvider = await LocalKeyProvider.load(keyStorePath ?? '.dnsid/keys.json', true);
const entityKeyProvider = await LocalKeyProvider.load('.dnsid/entity.keys.json', true);
const idm = await createNodeIdentityManager(config, { keyProvider, entityKeyProvider });
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
import { createNodeIdentityManagerFromDnsid } from '@identity-digital/dnsid/node';

const idm = await createNodeIdentityManagerFromDnsid();
```

DNSSEC modes are: `auto` (default), which rejects `FAILED` and permits `VALID`, `UNSIGNED`, or `UNKNOWN`; `validated`, which permits `VALID` or `UNSIGNED`; and `required`, which permits only `VALID`.

## Included surfaces

`@identity-digital/dnsid` re-exports the common core and profile surfaces and namespaces:

- `@identity-digital/dnsid-protocol`
- `@identity-digital/dnsid-jose`
- `@identity-digital/dnsid-http-signatures`
- `@identity-digital/dnsid-registry`

Use DNSid OIDC token minting and verification through `@identity-digital/dnsid-oidc`. It is intentionally not re-exported here because its default transport is Node-bound; private-key token minting belongs in server-side code, not browser/client code.

Use lower-level packages directly when you need narrower dependencies or custom composition.
