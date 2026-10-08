# Managed registration

`src/index.ts` creates or resumes the named `example-agent` dev sandbox identity and verifies its public ACTIVE status. The SDK handles account discovery, keys, recovery, issuance, publication, and verification.

## Run

Requires Node.js 22+, public DNS/HTTPS access, a verified dev organization API key matching the configured dev governance/entity bindings, and a local POSIX filesystem with directory-fsync support throughout the ancestor chain.

**Before running, verify server support for named registration and permanent organization-scoped replay claims.** The server must validate derived organization/name/key bindings, atomically open one identity per name, and retain claims after deletion. Hosted dev support is not established here; the previous 24-hour contract is insufficient. An acknowledgement flag cannot establish support.

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

Rerun with the **same directory, organization, and name**. Credentials can be replaced within that organization. The SDK resolves the organization through authenticated onboarding and selects a digest-named subdirectory for the registry/organization/name tuple. Back up the whole directory, including each `setup.json` and private `operational-key.json`. Do not edit state, replace missing keys, or share the directory between SDKs. Completed setup rechecks public evidence without creating another identity.

After a process interruption, stop all writers and back up the directory before removing the affected named subdirectory's `setup.lock` and resuming.

Old single-operation version-1/version-2 state and legacy recovery files are refused, not migrated. Preserve them and use the previous implementation to finish the operation. A new directory does not authorize replacing an existing name or recovering a lost key. Retire an identity before discarding its key.

## Checks

```sh
npm run typecheck --workspace @dnsid-ai/example-managed-registration
npm test -- test/managed-registration-flow.test.ts test/managed-registration.test.ts
```
