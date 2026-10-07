# Managed registration

Creates one registry-managed identity on the **dev sandbox**, then verifies its published DNSid with the SDK. This is the complete hosted setup flow, not a local testnet simulation.

## What it does

1. Generate and save an Ed25519 operational key. Save the complete registration input and an idempotency key before calling `registerAgent()`.
2. Wait for automatic sandbox ownership verification. Fetch the accountable-entity public key from the configured HTTPS endpoint. Ask the registry to prepare ISSUANCE, validate its entity signature and bindings, and add the operational countersignature with `issueManagedIdentity()`.
3. Submit the exact signed bytes through the registry. After log acceptance, wait for `READY` and DNS publication with `awaitRegistryManagedPublication()`. Verify the publication evidence; do not append a second event directly to the log.
4. Use a fresh, verification-only manager to call `verifyDomain()`. This resolves public DNS and checks record signatures, entity and operational keys, TLS, lifecycle evidence, and public protocol status. It does not use the owner API key or the registration response as verification evidence.

Sandbox ownership verification is automatic. Production, self-managed, and Live challenge flows are not included.

## Run

Requirements: Node.js 22 or later, network access to the dev services, and a dev owner API key that can register sandbox identities. From the repository root:

```sh
npm install
npm run build

DNSID_API_KEY_FILE="$HOME/.dev-dnsid-api-key" \
  npm run start --workspace @dnsid-ai/example-managed-registration -- \
  "$HOME/.dnsid-examples/managed-registration"
```

The API key file must contain one token. Protect it with mode `600`. Its contents are never written to the recovery files or printed.

**This command creates a real sandbox identity and adds a permanent ISSUANCE entry to the dev transparency log.** There is no automatic revocation or cleanup. Use a dedicated state directory outside the repository. The example restricts that directory to mode `700` and its state files to mode `600`; it contains the private operational key.

A successful run prints the assigned domain, protocol state `ACTIVE`, publish profile, governance ID, log reference, and verification time. The system resolver reports DNSSEC state `UNKNOWN`; this is not evidence of DNSSEC validation. Inject a DNSSEC-aware resolver for stricter verification policy.

## Resume after a failure

Run the same command with the **same state directory**. Do not delete state, edit the signed bytes, or run two processes against the directory.

- Before registration completes, the same input and registration idempotency key are replayed. An unknown creation outcome is not grounds to generate a new key. If the registry no longer retains that idempotency key, reconcile the original operation before continuing.
- After registration is saved, the example reads current status without allocating another identity. The creation-time publication configuration remains the setup snapshot.
- ISSUANCE intent is saved before preparation. Exact countersigned bytes are saved before submission. Pending or indeterminate submissions resume with those same bytes and the same idempotency key.
- Accepted ISSUANCE resumes publication without another log submission. The example retries read-only publication checks for DNS propagation and transient verification failures. Integrity and trust-policy failures stop the run.
- A completed operation performs fresh public verification again when rerun.

A rejected operation is not silently replaced. Inspect the saved state and registry error before deciding what to do. Restore the original key from backup if it is missing; do not generate a replacement key to resume an existing operation.

| File | Purpose |
| --- | --- |
| `keys.json` | Private operational key; keep it backed up and secret |
| `request.json` | Original registration input, registry URL, and replay key |
| `registration.json` | Assigned identity and creation-time publication snapshot |
| `registration-error.json` | Creation facts and HTTP/code information, if registration fails |
| `entity-key.json` | Trusted public entity key fetched over HTTPS, retained for resume |
| `issuance.json` | Durable intent, exact signed bytes (base64url), and acceptance state |
| `publication.json` | Published TXT record and registry/publication evidence |
| `verification.json` | Latest independent verification result |

Writes use a temporary file, file sync, atomic rename, and directory sync. Run this on a local filesystem that supports those operations. Recovery state is trusted local input, not a portable untrusted import format.

## Code layout and trust

- [`src/index.ts`](src/index.ts): command-line arguments, credential loading, and errors.
- [`src/registration.ts`](src/registration.ts): the four setup steps, using SDK lifecycle helpers.
- [`src/state.ts`](src/state.ts): restricted, atomic JSON storage, including exact byte-array recovery.

The dev registry, governance ID, entity-key endpoint, and expected log prefix are explicit application configuration in `registration.ts`. Log verification uses the SDK's bundled managed public trust profiles, not keys advertised by an unverified identity. The final verifier accepts only the configured dev governance ID and the entity-key thumbprint established through the configured HTTPS endpoint. Changing deployment is a deliberate configuration change, not something inferred from registry or DNS responses.

## Offline checks

These commands do not contact the registry or create identities:

```sh
npm run typecheck --workspace @dnsid-ai/example-managed-registration
npm test -- test/managed-registration-state.test.ts test/managed-issuance.test.ts
```
