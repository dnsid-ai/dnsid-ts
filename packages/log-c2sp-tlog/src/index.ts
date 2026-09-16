/**
 * C2SP tlog-backed lifecycle log support for DNSid.
 *
 * Implements the `c2sp-tlog` log method: reading, writing, and verifying DNSid
 * lifecycle transparency logs built on the C2SP specifications
 * (tlog-checkpoint, tlog-tiles, signed-note, tlog-cosignature, and related
 * documents; see {@link C2SP_TLOG_SPECIFICATIONS}). A stream in such a log
 * records an agent's identity-record lifecycle events (ISSUANCE, KEY_ROTATION,
 * REVOCATION, ...) as canonical JSON entries in a Merkle tree, authenticated
 * by witnessed checkpoints under a local trust policy.
 *
 * Key entry points: {@link createC2spTlogVerificationRegistry} for generic
 * caller-supplied trust, {@link createDnsidManagedVerificationRegistry} for the
 * reviewed Identity Digital-managed trust catalog, {@link registerC2spTlog} / {@link C2spTlogReader} for
 * lower-level composition, {@link C2spTlogBinding} and the prepared-event writer
 * API for appending events, and {@link verifyC2spStreamBundle} for offline bundles.
 *
 * @packageDocumentation
 */
import type { LogRegistry } from '@dnsid-ai/protocol';
import { C2spTlogReader, type C2spTlogReaderOptions } from './reader.ts';

/** Registers the `c2sp-tlog` log method on a protocol {@link LogRegistry}, constructing a {@link C2spTlogReader} per lr. */
export function registerC2spTlog(registry: LogRegistry, options: C2spTlogReaderOptions): void {
  registry.register('c2sp-tlog', (lr) => new C2spTlogReader(lr, options));
}

export { parseC2spTlogLr, canonicalLogPrefix, checkpointOrigin, generateC2spTlogStreamId } from './lr.ts';
export type { C2spTlogScope, ParsedC2spTlogLr } from './lr.ts';
export { canonicalJson, canonicalBytes, parseJsonNoDuplicateMembers, assertCanonicalJsonBytes } from './canonical.ts';
export { c2spEventId, canonicalizeC2spEvent, signedC2spEventBytes, signedC2spEntryBytes, prepareC2spTlogEvent, parseC2spEventEntry, c2spEnvelopeToEvent, eventToC2spEnvelope, parseC2spSignatures, requiredC2spSignatureNames } from './event-codec.ts';
export type { C2spEventContext, C2spJsonEvent, C2spSignatureValue, C2spSignatures } from './event-codec.ts';
export { leafHash, nodeHash, inclusionRoot, verifyInclusion, merkleRootFromEntries } from './merkle.ts';
export { parseTlogProofV1, verifyC2spTlogProof } from './proof.ts';
export type { TlogProofV1 } from './proof.ts';
export { parseCheckpoint, parseNoteSignature } from './checkpoint.ts';
export type { Checkpoint, NoteSignature } from './checkpoint.ts';
export { parseSignedNoteVerifierKey, verifyCheckpointSignature, verifyNoteSignature, verifiedCosignatureTimestamp } from './signed-note.ts';
export type { SignedNoteKey } from './signed-note.ts';
export { parseC2spPolicyFile, enforceCheckpointPolicy, normalizedOriginPolicy } from './policy.ts';
export type { C2spTlogPolicy, C2spTlogOriginPolicy, C2spTlogQuorumRule, CheckpointPolicyResult } from './policy.ts';
export { checkpointPath, tilePath, entryBundlePath, parseEntryBundle, encodeEntryBundle } from './tiles.ts';
export {
  ScanStreamSource,
  createDefaultC2spBoundedResourceFetcher,
  createFetchBackedC2spResourceFetcher,
  requiredC2spResourceFetchGuarantees,
  validateC2spResourceFetcher,
  C2SP_ENTRIES_PER_BUNDLE,
  DEFAULT_C2SP_MAX_TREE_SIZE,
  DEFAULT_C2SP_MAX_CHECKPOINT_BYTES,
  DEFAULT_C2SP_MAX_ENTRY_BUNDLE_BYTES,
  DEFAULT_C2SP_MAX_TOTAL_ENTRY_BYTES,
  DEFAULT_C2SP_REQUEST_TIMEOUT_MS,
} from './stream-source.ts';
export type {
  C2spBoundedResourceFetcher,
  C2spResourceFetchGuarantees,
  C2spResourceFetchOptions,
  IndexedEntry,
  ScanStreamSourceOptions,
  StreamEvidence,
  StreamSource,
} from './stream-source.ts';
export { stitchVerifiedMigrationHistory, verifyStreamLifecycle, verifyLifecycle, verifyLoggedEventSignature, stateHash } from './stream-verifier.ts';
export type { MigrationVerificationResult, VerifiedLifecycleEvent, StreamVerifierOptions } from './stream-verifier.ts';
export { C2spTlogReader, C2spTlogBinding, C2spTlogClient } from './reader.ts';
export type { C2spStreamBundleReaderOptions, C2spTlogReaderOptions } from './reader.ts';
export { createC2spTlogVerificationRegistry } from './verification-registry.ts';
export type { C2spScanLimits, C2spTlogVerificationOptions } from './verification-registry.ts';
export { createDnsidManagedVerificationRegistry } from './managed-verification-registry.ts';
export type { DnsidManagedVerificationOptions } from './managed-verification-registry.ts';
export { parseC2spTlogTrustProfile } from './trust-profile.ts';
export type { C2spTlogTrustProfile } from './trust-profile.ts';
export { prepareC2spTlogEventForSigning, parsePreparedC2spTlogEvent, signPreparedC2spTlogEvent, c2spTlogEntryBytes, writePreparedEvent } from './writer.ts';
export type { C2spSignerRole, C2spChain, PreparedC2spTlogEvent, PreparedC2spVerificationContext, SignPreparedC2spOptions, C2spTlogAppendOptions } from './writer.ts';
export { C2spTlogError, C2spTlogParseError, C2spTlogVerificationError } from './errors.ts';
export { C2SP_TLOG_PROFILE_VERSION, C2SP_TLOG_SPECIFICATIONS, DNSID_C2SP_METHOD_REVISION } from './version.ts';
export { advanceTrustedC2spCheckpoint, InMemoryTrustedC2spCheckpointStore, verifyC2spConsistencyProof } from './checkpoint-trust.ts';
export type { C2spConsistencyProofSource, TrustedC2spCheckpoint, TrustedC2spCheckpointStore } from './checkpoint-trust.ts';
export { DEFAULT_C2SP_MAX_STREAM_BUNDLE_BYTES, DEFAULT_C2SP_MAX_STREAM_BUNDLE_EVENTS, parseC2spStreamBundle, verifyC2spStreamBundle } from './stream-bundle.ts';
export type {
  C2spStreamBundle,
  C2spStreamBundleEvent,
  C2spStreamBundleSignature,
  C2spStreamBundleState,
  ParseC2spStreamBundleOptions,
  VerifyC2spStreamBundleOptions,
  VerifiedC2spStreamBundle,
} from './stream-bundle.ts';
