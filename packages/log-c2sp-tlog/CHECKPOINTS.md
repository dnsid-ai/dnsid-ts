# Checkpoint trust and recovery

## Verification and diagnostics

Both registry factories share one checkpoint store across their readers. The
default `InMemoryTrustedC2spCheckpointStore` lasts only as long as that instance.
Recreating it loses remembered trust. A genuinely unseen origin uses
trust-on-first-use after independent checkpoint signature and witness checks.

Checkpoint errors use `VerificationError.code === VerificationCode.LogError`
and these non-transient `errorCategory` values:

| Category | Condition |
| --- | --- |
| `LOG_ROLLBACK` | Candidate tree is smaller than trusted state. |
| `LOG_FORK` | Equal tree sizes have different roots. |
| `LOG_INCONSISTENT` | A supplied growth proof is invalid, or a candidate-valid scan contradicts the trusted prefix. |
| `CHECKPOINT_STORE_ERROR` | Storage fails or returns malformed state. |

`C2spCheckpointConsistencyError` exposes `origin`, `trustedTreeSize`,
`observedTreeSize`, `trustedRootHash`, and `observedRootHash`. Roots are independent
copies. Available underlying failures remain in `cause`. These fields survive
public reader and bundle verification. A category describes the observation,
not its cause or permission to reset trust.

A scan must reproduce the candidate root with contiguous indexes before it can
establish a trusted-prefix contradiction. Bad candidate scans are
`INVALID_EVIDENCE`. `MissingC2spConsistencyEvidenceError` separately identifies
absent consistency capability. Only this condition permits consistency-related
raw-scan fallback in preferred-bundle mode. Invalid proofs, storage errors,
retrieval failures, and cancellation do not permit that fallback. Retrieval
failures retain their retry classification and cause.

## Injected storage contract

This SDK provides no durable checkpoint adapter or administrative recovery API.
Applications can inject a `TrustedC2spCheckpointStore` into either
`createC2spTlogVerificationRegistry` or `createDnsidManagedVerificationRegistry`,
then inject that registry as `deps.logRegistry` during configuration construction.
Stores, initialization, and recovery are code-only. There are no deployment-file
members or SDK environment variables for them.

An adapter must:

- Validate a nonempty matching origin, nonnegative safe-integer tree size,
  32-byte `Uint8Array` root, and valid `Date` witnessed time. Invalid caller input
  is `ArgumentError`; invalid stored state is `CHECKPOINT_STORE_ERROR`.
- Return independent snapshots. Atomically compare all four fields, including
  witnessed time. An absent expected state matches only an unseen origin; a
  failed comparison writes nothing. The verifier reloads and verifies continuity
  against the winner before another attempt.
- Honor the supplied signal and remaining verification budget, including lock
  waits and staged-data flushing. Check cancellation immediately before
  irreversible publication. Never leave a queued write that can later publish
  after pre-publication cancellation.
- Treat publication followed by cancellation or an I/O failure as potentially
  committed. Report failure and reconcile the actual stored state; do not assume
  the old state remains or blindly repeat an administrative replacement.
- Exclude competing writers across every process sharing its namespace. Do not
  steal locks based only on age. Release/recovery must verify ownership and must
  not remove a successor's lock. Unexpected lock errors must fail closed.

A durable adapter additionally needs explicit initialization separate from open,
strict record decoding without rounding, atomic crash-safe replacement, and
acknowledgment only after durable commit. Missing, unreadable, corrupt, or
unsupported existing storage must fail closed, never create empty trust or fall
back to memory. Document how unseen origins differ from lost recorded state,
supported filesystem/database and locking assumptions, contention bounds,
backup handling, and recovery. Retain trust outside the verified service's
rollback boundary. Backups must not silently restore an older verifier baseline.
Native crash, corruption, restart, multi-process, locking, and commit-failure tests
are required for the chosen adapter; shared signed vectors do not test these.

## Deployment-owned re-baselining

A signed checkpoint, announced log restore, restart, or retry does not authorize
a continuity break. Direct store CAS is a storage primitive, not authorization.
Deployment recovery tooling must:

1. Stop and drain or fence verification and lifecycle writers for the origin
   across all processes. Preserve the old tuple, observed signed checkpoints,
   witness statements, failed proofs, and incident logs in an evidence archive.
2. Obtain independently authenticated recovery-authority approval for the exact
   origin, old tuple, replacement tuple, and trust policy. Record the approver,
   authorization time, reason, and incident/evidence references **before** replacement.
   Audit arguments alone do not authenticate an operator; the failing log cannot
   authorize its own reset.
3. Independently verify replacement origin, log signature, witness quorum, and
   freshness under the approved policy, binding the result to the approved
   size/root/time tuple. Validate recovered lifecycle state separately.
4. Replace only the exact reviewed old tuple. Stale expected state, any storage
   failure, or an uncertain commit stops recovery for reconciliation, without
   reload-and-retry authorization. Require durable acknowledgment for durable
   storage, then read back the replacement before resuming. If replacement is
   prohibited, explicitly initialize and seed a separate namespace and switch
   fenced consumers; retain the old namespace.
5. Retain an audit record linking both tuples, authorization/evidence references,
   replacement time, and reconciled outcome. Discard affected cached results and
   retained verified objects, rebuild readers/registries, and complete fresh
   identity and lifecycle verification before resuming workflows.

SDK tests cannot establish operator authorization or evidence-archive integrity.
