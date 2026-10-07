# Managed registration

Create one hosted dev sandbox identity, complete bilateral ISSUANCE, and verify public ACTIVE status and fresh lifecycle evidence. No challenge server or DNS hosting is needed.

## Run

Requires Node.js 22+, public DNS/HTTPS access, a dev organization API key, and a local POSIX filesystem. From the repository root:

```sh
npm install
npm run build
npm run start --workspace @dnsid-ai/example-managed-registration -- \
  --api-key-file "$HOME/.dev-dnsid-api-key" \
  --state-dir "$HOME/.dnsid-examples/managed-registration-ts"
```

Alternatively, omit `--api-key-file` and set `DNSID_API_KEY`. Protect the credential file with mode `600`. Credentials are not saved or printed.

**This creates a real sandbox identity and a permanent dev transparency-log entry.** It leaves the identity active. Keep its private key backed up.

## Implementation

`src/registration.ts` loads SDK environment settings and calls `registerManagedIdentity()` with a `FileRegistrationStore`. The SDK owns key generation, durable replay, issuance, publication polling, and independent credential-free verification. The example only selects dev trust, requests a sandbox identity, and supplies the dev-specific adapter:

- `GET /api/v1/org` returns the authenticated credential's owning organization ID.
- Creation replay is scoped to organization/request key. The dev server's PostgreSQL idempotency store retains claims for 24 hours from storage, conservatively measured here from the first request. See the server's `internal/db/pgstore/idempotency.go`.
- The replay clock uncertainty is one second. Run only where clock error across restarts stays within this bound; expired or uncertain creation outcomes require reconciliation, not a new request.

SDK transport and verification settings such as `DNSID_DNS_SERVER`, `DNSID_DNSSEC_MODE`, and `DNSID_CA_BUNDLE` still apply. The example rejects a different `DNSID_REGISTRY_URL`, ignores existing identity/key-source settings, and explicitly selects managed log trust. System DNS does not provide authenticated DNSSEC; configure a DNSSEC-aware resolver and policy if required.

Success prints:

```text
Registered: <assigned-domain>.sandbox.dev.dnsid.ai
Verified: <assigned-domain>.sandbox.dev.dnsid.ai status=ACTIVE
```

## Recovery

Use the **same directory** to resume. The SDK saves `setup.json` and the private `operational-key.json` with owner-only permissions and atomic, synced writes. Back up both. Do not edit recovery state, replace missing keys, or share the directory between SDKs.

The SDK locks the directory with `setup.lock`. After a process interruption, stop all writers, back up the directory, then remove that lock before resuming. Completed setup rechecks public evidence without creating another identity or resubmitting accepted issuance. Integrity, policy, and terminal-status failures stop.

Old `recovery.json` or separate request/issuance files are **not migrated**. The SDK refuses those directories instead of silently allocating a replacement identity. Preserve them and use the previous example version to finish the old operation. Use an empty directory only for an intentionally new identity.

Retire the identity through the registry before discarding its key. Production, Live challenges, and self-managed publication are outside this example.

## Offline checks

```sh
npm run typecheck --workspace @dnsid-ai/example-managed-registration
npm test -- test/managed-registration-flow.test.ts test/managed-registration.test.ts
```
