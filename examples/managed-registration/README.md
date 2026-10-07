# Managed registration

Register one hosted **dev sandbox** identity, complete bilateral ISSUANCE, wait for registry-managed publication, and verify it independently through public DNS. No challenge server or DNS hosting is needed.

## Run

Requires Node.js 22+, public DNS/HTTPS access, and a dev organization API key. From the repository root:

```sh
npm install
npm run build
npm run start --workspace @dnsid-ai/example-managed-registration -- \
  --api-key-file "$HOME/.dev-dnsid-api-key" \
  --state-dir "$HOME/.dnsid-examples/managed-registration-ts"
```

Alternatively, omit `--api-key-file` and set `DNSID_API_KEY`. The credential file must contain one token; protect it with mode `600`. Credentials are not saved or printed.

**This creates a real sandbox identity and a permanent dev transparency-log entry.** It leaves the identity active. Use a dedicated directory outside the repository, and keep the private key backed up. Do not share recovery directories between SDKs.

## Common setup flow

1. Generate and persist an Ed25519 operational key through `LocalKeyProvider`.
2. Save the complete sandbox registration request and replay key before registration. Retain the creation-time publication configuration; wait for automatic ownership verification.
3. Fetch and validate the entity JWKS from the configured dev HTTPS endpoint. `issueManagedIdentity()` validates the prepared identity/key bindings and entity signature, countersigns, saves exact bytes before submission, and persists the outcome.
4. Use `awaitRegistryManagedPublication()` to confirm registry publication and verify public evidence. Do not append separately to the log.
5. Use a fresh, credential-free verifier with the configured governance ID and entity-key thumbprint. Check `ACTIVE` status, the assigned log reference, and fresh lifecycle evidence with `verifyNonRevocation()`.

Success prints:

```text
Registered: <assigned-domain>.sandbox.dev.dnsid.ai
Verified: <assigned-domain>.sandbox.dev.dnsid.ai status=ACTIVE DNSSEC=UNKNOWN
```

`UNKNOWN` is not authenticated DNSSEC. Configure a DNSSEC-aware resolver and the appropriate verification policy when required.

## Configuration

The example uses `loadEnvironment()`, `mergeLoadedConfig()`, `constructIdentityManager()`, and `createRegistryClientFromEnvironment()`. SDK environment settings such as `DNSID_DNS_SERVER`, `DNSID_DNSSEC_MODE`, and `DNSID_CA_BUNDLE` are read by the SDK rather than duplicated here.

The dev registry is the explicit default. A different `DNSID_REGISTRY_URL` is rejected: this example's governance ID, entity-key endpoint, and log prefix are dev-specific. Managed log trust is explicitly selected with `logTrust.managed`; trust is never taken from an unverified record. Setup owns the new identity and key, so existing `DNSID_DOMAIN` and key-source settings are not used. The assigned publication snapshot is overlaid after registration.

## Recovery

Fresh runs create only:

- `keys.json`: private operational key; keep secret and backed up.
- `recovery.json`: original request, replay keys, creation snapshot, trusted entity key, exact signed bytes, and issuance outcome.

The directory is restricted to `700`; recovery files use `600`. Writes sync the temporary file, atomically rename it, and sync the directory. Use a local filesystem that supports these operations.

Rerun with the **same directory** after interruption. Do not delete recovery state, replace the key, edit signed bytes, or run concurrent processes against the directory. Accepted issuance is not resubmitted; rejected outcomes stop. Pending or unknown outcomes retain the same bytes and idempotency key. Only transient public-read failures and publication-DNS failures are retried; integrity and policy failures stop immediately.

The original example's separate request, registration, entity-key, and issuance files are imported into `recovery.json` on first resume. Old files are left intact as backups; subsequent runs use `recovery.json`.

Cleanup is explicit: retire the immutable identity through the registry before discarding its key. Production, Live challenges, and self-managed publication are outside this example.

## Offline checks

```sh
npm run typecheck --workspace @dnsid-ai/example-managed-registration
npm test -- test/managed-registration-state.test.ts test/managed-registration-flow.test.ts test/managed-issuance.test.ts test/config-loading.test.ts
```
