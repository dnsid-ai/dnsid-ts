# Managed registration

Create one hosted dev sandbox identity, complete bilateral ISSUANCE, and verify public ACTIVE status and fresh lifecycle evidence. No challenge server or DNS hosting is needed.

## Run

Requires Node.js 22+, public DNS/HTTPS access, a dev organization API key, and a local POSIX filesystem.

**Do not run until the deployment's permanent registration-idempotency contract has been verified with server integration tests.** The revised SDK requires atomic, registry-wide keys that survive retirement and deletion and reject cross-organization reuse. Hosted dev support is not established here; the previous 24-hour, organization-scoped contract is insufficient. `--server-contract-verified` confirms this prerequisite; it does not test the server.

After verification, from the repository root:

```sh
npm install
npm run build
npm run start --workspace @dnsid-ai/example-managed-registration -- \
  --server-contract-verified \
  --api-key-file "$HOME/.dev-dnsid-api-key" \
  --state-dir "$HOME/.dnsid-examples/managed-registration-ts"
```

Alternatively, omit `--api-key-file` and set `DNSID_API_KEY`. Protect the credential file with mode `600`. Credentials are not saved or printed.

**This creates a real sandbox identity and a permanent dev transparency-log entry.** It leaves the identity active. Keep its private key backed up.

## Implementation

`src/registration.ts` loads SDK environment settings and calls `registerManagedIdentity()` with a `FileRegistrationStore`. The SDK owns transport, key generation, durable replay, issuance, publication polling, and independent credential-free verification. The example only selects dev trust and requests a sandbox identity.

The registry authenticates the organization and permanently binds the registration key to the original request and immutable identity. There is no organization lookup, consumer adapter, or replay-expiration policy. Unknown creation outcomes reuse the same request/key, even after long interruptions or clock changes; the invocation still has a finite deadline.

SDK transport and verification settings such as `DNSID_DNS_SERVER`, `DNSID_DNSSEC_MODE`, and `DNSID_CA_BUNDLE` still apply. The example rejects a different `DNSID_REGISTRY_URL`, ignores existing identity/key-source settings, and explicitly selects managed log trust. System DNS does not provide authenticated DNSSEC; configure a DNSSEC-aware resolver and policy if required.

Success prints:

```text
Registered: <assigned-domain>.sandbox.dev.dnsid.ai
Verified: <assigned-domain>.sandbox.dev.dnsid.ai status=ACTIVE
```

## Recovery

Use the **same directory** to resume. The SDK saves `setup.json` and the private `operational-key.json` with owner-only permissions and atomic, synced writes. Back up both. Do not edit recovery state, replace missing keys, or share the directory between SDKs.

The SDK locks the directory with `setup.lock`. After a process interruption, stop all writers, back up the directory, then remove that lock before resuming. Completed setup rechecks public evidence without creating another identity or resubmitting accepted issuance. Integrity, policy, and terminal-status failures stop.

Old version-1 `setup.json`, `recovery.json`, or separate request/issuance files are **not migrated**. The SDK refuses those directories instead of silently allocating a replacement identity. Preserve them and use the previous example version to finish the old operation. Use an empty directory only for an intentionally new identity.

Retire the identity through the registry before discarding its key. Production, Live challenges, and self-managed publication are outside this example.

## Offline checks

```sh
npm run typecheck --workspace @dnsid-ai/example-managed-registration
npm test -- test/managed-registration-flow.test.ts test/managed-registration.test.ts
```
