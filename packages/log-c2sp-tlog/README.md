# @dnsid-ai/log-c2sp-tlog

DNSid binding for C2SP tiled logs, including verified reads and split-signature
prepared writes.

## Breaking pre-1.0 logical-chain correction

This implementation follows DNSid method revision
`d5a65d06f76eff4db81e50f8767a600d2ca7fc2a` (exported as
`DNSID_C2SP_METHOD_REVISION`). The method, envelope `v:1`, and bundle `@v1`
labels are unchanged. Every scope requires signed binding context and a logical
predecessor chain. `C2spChain.previousEventId` replaces `previousIndex` and
`previousLeafHash`; the corresponding wire field is `prev_event_id`.
`prepared.eventId` is SHA-256 of `"dnsid-c2sp-event-v1"`, one zero byte, and
canonical signed payload bytes excluding top-level `sigs`. State hashing is
unchanged. Old index/leaf chain fields and signed `event_id` are prohibited.
The old `unchained` option no longer bypasses verification.

Deploy corrected readers, writers, monitors and bundle producers together.
Preserve conforming histories (including conforming public ISSUANCE-only streams)
and terminal state. Inventory nonconforming histories and outstanding submissions;
retain old evidence and use fresh streams where necessary. Never rewrite bytes
that may already have been submitted, even when the logical event ID is unchanged.
Historical cross-SDK matrix results are not corrected-contract release evidence.

The package root contains the Node.js checkpoint, Merkle, and signed-note
verification implementation. Browser-safe consumers that only prepare, inspect,
sign, or serialize registry-provided events can import the portable
`@dnsid-ai/log-c2sp-tlog/writer` subpath. Immutable binding-version
metadata is available from `@dnsid-ai/log-c2sp-tlog/version`.

```ts
import { createC2spTlogVerificationRegistry } from '@dnsid-ai/log-c2sp-tlog';

const registry = await createC2spTlogVerificationRegistry({
  // This URL is explicit, independently trusted application configuration.
  policyUrl: 'https://policy.example/dnsid-policy',
  // Local freshness policy used by verifyNonRevocation.
  checkpointMaxAge: 5 * 60 * 1000,
  allowedClockSkew: 30 * 1000,
});
```

The factory fetches the policy with SSRF-safe destination checks, rejects redirects, requires HTTP 200, bounds decoded responses during reading, and uses the same bounded resource fetcher for log evidence. With an independently distributed `trustProfile`, or `policyDocument`/`policyUrl` plus direct `bundleVerifierKeys`, set `checkpointMaxAge` and `maxBundleLifetimeMs`; the default reader then prefers `{lr log-prefix}/streams/{fqdn}?format=bundle` and shares its verified lifecycle snapshot across binding, continuity, and key-age checks. A missing or temporarily unavailable endpoint falls back to the bounded complete-log scan. A valid newer bundle also falls back when no consistency-proof source is available, allowing the complete scan to verify both roots independently. Malformed, expired, invalid, rollback, or conflicting bundle evidence never falls back. Set `requireStreamBundle` to disable fallback.

For an explicit application decision to trust Identity Digital-managed DNSid logs, use the separately named managed factory:

```ts
import { createDnsidManagedVerificationRegistry } from '@dnsid-ai/log-c2sp-tlog';

const registry = await createDnsidManagedVerificationRegistry();
```

It selects reviewed trust bundled with the SDK only for exact canonical `public` references to `https://log.dnsid.dev` or `https://log.dnsid.ai`. Both development and production use bundle-first verification with bounded raw-scan fallback only when bundle evidence is unavailable or unsupported. Unknown scopes and prefixes fail closed. The generic factory never selects managed roots when trust is omitted.

Set `checkpointMaxAge` when using `verifyNonRevocation`; omitting it makes that operation fail closed. Non-revocation always refreshes evidence instead of relying on the lifecycle snapshot retained by `VerifiedDomain`. `allowedClockSkew` defaults to zero. The factory installs an in-memory trusted-checkpoint store by default; that protects against rollback only for the process lifetime. Inject a durable `trustedCheckpointStore` when protection must survive restarts. A custom `resourceFetcher` must implement the bounded fetch contract and explicitly report all required security guarantees.

Checkpoint-store `load`/`compareAndSwap` and consistency-source
`fetchConsistencyProof` receive the verification signal as their last argument.
Custom stores must check cancellation at the atomic commit boundary and prevent
pending writes after cancellation; racing an uncancelable write is insufficient.
Checkpoint advancement shares the caller's cancellation and has a 30-second
standalone default (`timeoutMs`/`signal` options).

Never derive `policyUrl` from an unverified identity record, its `lr`, or a log prefix. Advanced deployments can compose `parseC2spPolicyFile`, `ScanStreamSource`, `registerC2spTlog`, and a custom checkpoint store directly for private transports, mirrors, archives, or portable bundles.

Public verification needs a trusted local policy and complete stream evidence. A single inclusion proof proves historical inclusion only; it is not current lifecycle state or non-revocation evidence.

Writers use `generateC2spTlogStreamId()` for each new identity instance. It
returns an opaque 128-bit cryptographically random value as unpadded base64url;
do not reuse a bare FQDN as the stream ID.

For writes, construct `C2spTlogBinding` with a bound reference, call
`prepareEvent`, and pass the immutable prepared value between signer processes.
Each process calls `parsePreparedEvent` before `signPreparedEvent`; existing
signatures and the provider's public key are checked before another signature is
added. The operational side of split ISSUANCE supplies its locally expected
FQDN, governance ID, entity key, and operational key as verification context;
the SDK rejects missing or mismatched expectations before adding the operational
countersignature. `entryBytes` requires the same ISSUANCE context and verifies
every role signature.

`writePreparedEvent` passes the exact canonical entry bytes and optional
idempotency key to the deployment adapter. Events after genesis in every scope also
require a `validateChain` callback backed by authoritative prior stream state;
the SDK will not append them based only on caller-supplied chain hashes.

Draft-01 ISSUANCE entries contain the recorded entity and operational public keys and carry `sigs.ae` and `sigs.op`. KEY_ROTATION entries carry both the previous-key authorization in `sigs.prev_op` and the new-key proof of possession in `sigs.new_op`. Other supported lifecycle entries carry `sigs.ae`. The draft-01 behavior supports ISSUANCE, KEY_ROTATION, REVOCATION, RETIREMENT, MIGRATION, and DELEGATION.

Candidate selection deduplicates exact signed payloads, not complete entry bytes.
It accepts valid ES256 high-S/low-S variants and independently re-signed copies
without changing first-applied order, sequence or key age. Every role signature
must verify before a new payload can create a contradiction. Authority comes
from its verified predecessor, including superseded keys; signed forks and new
post-terminal events fail closed. Bundle summaries count logical events, but
every supplied inclusion proof verifies exact complete bytes, even for ignored
copies. `readEvent` independently authenticates every role of the requested
occurrence; an invalid-signature replay is not valid standalone evidence.

Inbound migration requires `verifyMigration` to return the verified prior-log
history through `finalEntryRef`, plus the entity and active operational keys it
establishes. To return `LoggedStateEvidence`, it also supplies the aligned
`priorHistoryReferences`; these preserve prior-log bounds without deriving them
from destination indexes. `rebuildHistory` validates imported state and returns
one stitched history with the migration event exactly once. A missing, terminal,
key-inconsistent, or boundary-incomplete prior history fails closed. Migration
callbacks receive a second `{ signal }` argument and must propagate that same
budget through recursive predecessor verification. The callback owns exact-cutoff
proof verification and cumulative recursion/history/response limits.

Read operations and standalone stream verifiers have a 30-second overall default.
Factory/reader `signal` settings and per-call stream-verifier options propagate
cancellation; injected sources must honor it. Raw scans default to one million
entries and 256 MiB aggregate entry bytes; lifecycle replay additionally caps
retained history at 10,000 logical events. Copies still consume input limits.
Reuse registries/transports/checkpoint stores, monitor fallback cost, and lower
scan limits or require bundles for predictable cost.

Lifecycle and non-revocation verification require a timestamped witness quorum. `checkpointMaxAge` is required only for current non-revocation checks; historical binding and key-continuity checks accept older authenticated checkpoints. Text policies in the C2SP `tlog-policy` format, including nested groups, can be loaded with `parseC2spPolicyFile`.

This package currently supports C2SP signed-note Ed25519 log signatures (type `0x01`) and timestamped Ed25519 witness cosignatures (type `0x04`).

`verifyC2spStreamBundle` verifies canonical
`dnsid-c2sp-stream-bundle@v1` bytes against exact independently accepted policy
bytes, a trusted bundle-signing key, C2SP inclusion proofs, lifecycle signatures,
checkpoint freshness, trusted-index completeness, and the origin-scoped checkpoint store. Callers must set
positive bundle byte, event-count, and lifetime limits. The exported
`C2SP_TLOG_SPECIFICATIONS` object identifies the exact external C2SP revisions
implemented by this package.
