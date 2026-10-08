# Managed registration

`src/index.ts` creates one dev sandbox identity and verifies its public ACTIVE status. The SDK handles keys, recovery, issuance, publication, and verification.

## Run

Requires Node.js 22+, public DNS/HTTPS access, a dev organization API key, and a local POSIX filesystem.

**Before running, verify that the deployment supports permanent registration idempotency.** Keys must be atomic, registry-wide, retained after deletion, and reject cross-organization reuse. Hosted dev support is not established here; the previous 24-hour contract is insufficient.

From the repository root:

```sh
npm install
npm run build
export DNSID_API_KEY='<dev organization API key>'
npm run start --workspace @dnsid-ai/example-managed-registration -- \
  "$HOME/.dnsid-examples/managed-registration-ts"
```

The only argument is the recovery directory. The example uses fixed dev settings and reads only `DNSID_API_KEY`, not other SDK environment settings. Credentials are not saved or printed.

**This creates a real sandbox identity and a permanent transparency-log entry.** It leaves the identity active.

## Recovery

Rerun with the **same directory**. Back up `setup.json` and the private `operational-key.json`. Do not edit state, replace missing keys, or share the directory between SDKs. Completed setup rechecks public evidence without creating another identity.

After a process interruption, stop all writers and back up the directory before removing `setup.lock` and resuming.

Old version-1 state and legacy recovery files are refused, not migrated. Preserve them and use the previous implementation to finish the operation. Use an empty directory only for an intentionally new identity. Retire an identity before discarding its key.

## Checks

```sh
npm run typecheck --workspace @dnsid-ai/example-managed-registration
npm test -- test/managed-registration-flow.test.ts test/managed-registration.test.ts
```
