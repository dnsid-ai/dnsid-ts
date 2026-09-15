import { createPublicKey, verify as verifySignature } from 'node:crypto';

import { withVerificationBudget, type VerificationOptions, normalizeFQDN, type DnsIdJWK, type LogEvent, type LogRef } from '@identity-digital/dnsid-protocol';

import { b64url } from './base64.ts';
import { assertCanonicalJsonBytes, canonicalBytes, parseJsonNoDuplicateMembers } from './canonical.ts';
import { parseCheckpoint, type Checkpoint } from './checkpoint.ts';
import { advanceTrustedC2spCheckpoint, type C2spConsistencyProofSource, type TrustedC2spCheckpointStore } from './checkpoint-trust.ts';
import { C2spTlogParseError, C2spTlogVerificationError } from './errors.ts';
import { parseC2spTlogLr, type ParsedC2spTlogLr } from './lr.ts';
import { sha256, verifyInclusion } from './merkle.ts';
import { enforceCheckpointPolicy, normalizedOriginPolicy, parseC2spPolicyFile } from './policy.ts';
import type { SignedNoteKey } from './signed-note.ts';
import { stitchVerifiedMigrationHistory, stitchVerifiedMigrationReferences, verifyStreamLifecycle, type MigrationVerificationResult, type StreamVerifierOptions, type VerifiedLifecycleEvent } from './stream-verifier.ts';

const BUNDLE_MEMBERS = ['checkpoint', 'complete_through_size', 'completeness_mode', 'events', 'expires', 'fqdn', 'lr', 'policy_hash', 'sig', 'state', 'type', 'v'];
const EVENT_MEMBERS = ['entry', 'index', 'proof'];
const STATE_MEMBERS = ['event_count', 'last_event_type', 'logged_state'];
const SIGNATURE_MEMBERS = ['alg', 'kid', 'value'];

export const DEFAULT_C2SP_MAX_STREAM_BUNDLE_BYTES = 8 * 1024 * 1024;
export const DEFAULT_C2SP_MAX_STREAM_BUNDLE_EVENTS = 10_000;
const DEFAULT_C2SP_MAX_STREAM_BUNDLE_TREE_SIZE = 1_000_000;

/** One bundled lifecycle event: log index, raw entry bytes, and its inclusion proof path. */
export interface C2spStreamBundleEvent {
  index: number;
  entryBytes: Uint8Array;
  proof: Uint8Array[];
}

/** Bundle-asserted lifecycle summary, checked against the verified history. */
export interface C2spStreamBundleState {
  eventCount: number;
  lastEventType: string;
  loggedState: 'UNKNOWN' | 'ACTIVE' | 'REVOKED' | 'RETIRED';
}

/** Bundle producer's Ed25519 signature over the bundle's signed bytes. */
export interface C2spStreamBundleSignature {
  alg: 'EdDSA';
  kid: string;
  value: Uint8Array;
}

/**
 * Parsed `dnsid-c2sp-stream-bundle` (v1): self-contained, offline-verifiable
 * evidence for one agent's lifecycle stream — a witnessed checkpoint, the
 * stream's events with inclusion proofs, a state summary, an expiry, and the
 * producer's signature.
 */
export interface C2spStreamBundle {
  fqdn: string;
  reference: ParsedC2spTlogLr;
  checkpoint: Checkpoint;
  checkpointBytes: Uint8Array;
  policyHash: Uint8Array;
  completeThroughSize: number;
  completenessMode: 'trusted-index';
  events: C2spStreamBundleEvent[];
  state: C2spStreamBundleState;
  expires: number;
  signature: C2spStreamBundleSignature;
  signedBytes: Uint8Array;
  bytes: Uint8Array;
}

/** Size limits applied while parsing an untrusted stream bundle. */
export interface ParseC2spStreamBundleOptions {
  maxBundleBytes: number;
  maxEvents: number;
}

/** Trusted inputs and freshness limits for verifying a stream bundle. */
export interface VerifyC2spStreamBundleOptions extends ParseC2spStreamBundleOptions, VerificationOptions {
  /** DNS name of the agent the bundle must describe. */
  expectedFqdn: string;
  /** Canonical bound c2sp-tlog lr the bundle must reference. */
  expectedLogReference: string;
  /** Local C2SP policy file bytes; their hash must match the bundle's `policy_hash`. */
  policyBytes: Uint8Array;
  /** Trusted bundle-producer keys (with key IDs) accepted for the bundle signature. */
  bundleKeys: SignedNoteKey[];
  /** Trusted accountable-entity key for the identity record. */
  entityKey: DnsIdJWK;
  /** Maximum allowed distance between checkpoint witness time and bundle expiry. */
  maxBundleLifetimeMs: number;
  /** Maximum accepted checkpoint age relative to now. */
  checkpointFreshnessMs: number;
  /** Maximum accepted checkpoint tree size (default 1,000,000). */
  maxTreeSize?: number;
  maxClockSkewMs?: number;
  nowMs?: number;
  verifyMigration?: StreamVerifierOptions['verifyMigration'];
  trustedCheckpointStore: TrustedC2spCheckpointStore;
  consistencyProofSource?: C2spConsistencyProofSource;
}

type VerifyC2spStreamBundleContentsOptions = Omit<VerifyC2spStreamBundleOptions, 'trustedCheckpointStore' | 'consistencyProofSource'>;

/** Result of successful stream bundle verification. */
export interface VerifiedC2spStreamBundle {
  bundle: C2spStreamBundle;
  events: VerifiedLifecycleEvent[];
  /** The verified lifecycle events in log order. */
  lifecycle: LogEvent[];
  /** Verified log reference aligned with each stitched lifecycle event, when prior migration boundaries were supplied. */
  historyReferences?: LogRef[];
  /** Thumbprint of the agent's operational key after the last verified event. */
  activeOperationalKeyThumbprint: string;
  checkpointWitnessTime: Date;
}

/**
 * Parses and structurally validates a canonical-JSON stream bundle without
 * verifying any signatures, proofs, or freshness: exact member sets, canonical
 * base64url fields, a canonical bound lr, and strictly increasing event indexes.
 *
 * @throws C2spTlogParseError when the bundle is oversized or malformed.
 */
export function parseC2spStreamBundle(bytes: Uint8Array, options: ParseC2spStreamBundleOptions): C2spStreamBundle {
  positiveInteger(options.maxBundleBytes, 'maxBundleBytes');
  positiveInteger(options.maxEvents, 'maxEvents');
  if (bytes.length === 0 || bytes.length > options.maxBundleBytes) {
    throw new C2spTlogParseError(`stream bundle exceeds configured byte maximum ${options.maxBundleBytes}`);
  }
  const parsed = parseJsonNoDuplicateMembers(bytes);
  assertCanonicalJsonBytes(bytes, parsed);
  const object = exactObject(parsed, BUNDLE_MEMBERS, 'stream bundle');
  if (object.v !== 1 || object.type !== 'dnsid-c2sp-stream-bundle') {
    throw new C2spTlogParseError('unsupported C2SP stream bundle');
  }
  if (typeof object.fqdn !== 'string' || object.fqdn !== normalizeFQDN(object.fqdn, true)) {
    throw new C2spTlogParseError('stream bundle fqdn must be a normalized lowercase DNSid FQDN');
  }
  if (typeof object.lr !== 'string') throw new C2spTlogParseError('stream bundle lr must be a string');
  const reference = parseC2spTlogLr(object.lr);
  if (reference.entryIndex !== undefined || reference.lr !== object.lr) throw new C2spTlogParseError('stream bundle lr must be a canonical bound reference');
  const checkpointBytes = strictBase64url(object.checkpoint, 'checkpoint');
  let checkpoint: Checkpoint;
  try { checkpoint = parseCheckpoint(new TextDecoder('utf-8', { fatal: true }).decode(checkpointBytes)); }
  catch (cause) { throw new C2spTlogParseError(`invalid stream bundle checkpoint: ${(cause as Error).message}`); }
  const policyHash = strictBase64url(object.policy_hash, 'policy_hash', 32);
  const completeThroughSize = safeInteger(object.complete_through_size, 'complete_through_size');
  if (object.completeness_mode !== 'trusted-index') throw new C2spTlogParseError('unsupported stream bundle completeness_mode');
  if (!Array.isArray(object.events)) throw new C2spTlogParseError('stream bundle events must be an array');
  if (object.events.length > options.maxEvents) throw new C2spTlogParseError(`stream bundle exceeds configured event maximum ${options.maxEvents}`);
  const events = object.events.map((value, position) => parseEvent(value, position, completeThroughSize));
  for (let i = 1; i < events.length; i++) {
    if (events[i]!.index <= events[i - 1]!.index) throw new C2spTlogParseError('stream bundle event indexes must be unique and strictly increasing');
  }
  const stateObject = exactObject(object.state, STATE_MEMBERS, 'stream bundle state');
  const loggedState = stateObject.logged_state;
  if (loggedState !== 'UNKNOWN' && loggedState !== 'ACTIVE' && loggedState !== 'REVOKED' && loggedState !== 'RETIRED') {
    throw new C2spTlogParseError('stream bundle state has invalid logged_state');
  }
  if (typeof stateObject.last_event_type !== 'string') throw new C2spTlogParseError('stream bundle state last_event_type must be a string');
  const state: C2spStreamBundleState = {
    eventCount: safeInteger(stateObject.event_count, 'state.event_count'),
    lastEventType: stateObject.last_event_type,
    loggedState: loggedState as C2spStreamBundleState['loggedState'],
  };
  const expires = safeInteger(object.expires, 'expires');
  const sigObject = exactObject(object.sig, SIGNATURE_MEMBERS, 'stream bundle sig');
  if (sigObject.alg !== 'EdDSA' || typeof sigObject.kid !== 'string' || !sigObject.kid) {
    throw new C2spTlogParseError('stream bundle sig must identify an EdDSA key');
  }
  const signature = { alg: 'EdDSA' as const, kid: sigObject.kid, value: strictBase64url(sigObject.value, 'sig.value', 64) };
  const { sig: _sig, ...unsigned } = object;
  return {
    fqdn: object.fqdn,
    reference,
    checkpoint,
    checkpointBytes,
    policyHash,
    completeThroughSize,
    completenessMode: 'trusted-index',
    events,
    state,
    expires,
    signature,
    signedBytes: canonicalBytes(unsigned),
    bytes: bytes.slice(),
  };
}

/**
 * Fully verifies a stream bundle for offline identity-record validation:
 * checks the expected agent FQDN and log reference, the producer signature,
 * the policy hash, checkpoint policy and trusted-checkpoint advancement,
 * freshness and expiry windows, each event's inclusion proof, and the complete
 * lifecycle history, then confirms the bundle's asserted state summary.
 *
 * @returns The verified bundle, lifecycle, and active operational key thumbprint.
 * @throws C2spTlogParseError when the bundle is malformed.
 * @throws C2spTlogVerificationError when any verification step fails.
 */
export async function verifyC2spStreamBundle(bytes: Uint8Array, options: VerifyC2spStreamBundleOptions): Promise<VerifiedC2spStreamBundle> {
  return withVerificationBudget(async signal => {
    const verified = await verifyC2spStreamBundleContents(bytes, { ...options, signal });
    await advanceTrustedC2spCheckpoint(options.trustedCheckpointStore, verified.bundle.reference, verified.bundle.checkpoint, verified.checkpointWitnessTime, {
      signal,
      consistencyProofSource: options.consistencyProofSource,
    });
    return verified;
  }, options);
}

/** @internal Fully verifies bundle contents without mutating trusted checkpoint state. */
export async function verifyC2spStreamBundleContents(bytes: Uint8Array, options: VerifyC2spStreamBundleContentsOptions): Promise<VerifiedC2spStreamBundle> {
  const bundle = parseC2spStreamBundle(bytes, options);
  const expectedFqdn = normalizeFQDN(options.expectedFqdn, true);
  const expectedReference = parseC2spTlogLr(options.expectedLogReference);
  if (expectedReference.entryIndex !== undefined || expectedReference.lr !== options.expectedLogReference) {
    throw new C2spTlogVerificationError('expected log reference must be canonical and bound');
  }
  if (bundle.fqdn !== expectedFqdn) throw new C2spTlogVerificationError('stream bundle fqdn does not match expected identity');
  if (bundle.reference.lr !== expectedReference.lr) throw new C2spTlogVerificationError('stream bundle lr does not match expected identity record');
  if (!equalBytes(bundle.policyHash, sha256(options.policyBytes))) throw new C2spTlogVerificationError('stream bundle policy_hash mismatch');
  const policyText = new TextDecoder('utf-8', { fatal: true }).decode(options.policyBytes);
  const policy = parseC2spPolicyFile(policyText);
  const checkpointKeys = normalizedOriginPolicy(policy, bundle.reference.origin);
  verifyBundleSignature(bundle, options.bundleKeys, [...checkpointKeys.logKeys, ...checkpointKeys.witnessKeys]);
  const nowMs = options.nowMs ?? Date.now();
  const maxClockSkewMs = nonNegativeInteger(options.maxClockSkewMs ?? 0, 'maxClockSkewMs');
  const policyResult = enforceCheckpointPolicy(bundle.checkpoint, bundle.reference.origin, policy, bundle.reference.scope, nowMs, maxClockSkewMs);
  if (bundle.checkpoint.treeSize !== bundle.completeThroughSize) throw new C2spTlogVerificationError('stream bundle checkpoint size mismatch');
  const maxTreeSize = positiveInteger(options.maxTreeSize ?? DEFAULT_C2SP_MAX_STREAM_BUNDLE_TREE_SIZE, 'maxTreeSize');
  if (bundle.checkpoint.treeSize > maxTreeSize) throw new C2spTlogVerificationError('stream bundle checkpoint exceeds configured tree-size maximum');
  const witnessTime = policyResult.checkpointWitnessTime;
  if (!witnessTime) throw new C2spTlogVerificationError('stream bundle freshness requires an accepted timestamped witness quorum');
  const checkpointFreshnessMs = positiveInteger(options.checkpointFreshnessMs, 'checkpointFreshnessMs');
  if (nowMs - witnessTime.getTime() > checkpointFreshnessMs) throw new C2spTlogVerificationError('stream bundle checkpoint is too stale');
  const maxBundleLifetimeMs = positiveInteger(options.maxBundleLifetimeMs, 'maxBundleLifetimeMs');
  if (bundle.expires * 1000 <= nowMs) throw new C2spTlogVerificationError('stream bundle is expired');
  if (bundle.expires * 1000 > witnessTime.getTime() + maxBundleLifetimeMs) throw new C2spTlogVerificationError('stream bundle expiry exceeds configured maximum lifetime');
  for (const event of bundle.events) {
    if (!verifyInclusion(event.entryBytes, event.index, bundle.completeThroughSize, bundle.checkpoint.rootHash, event.proof)) {
      throw new C2spTlogVerificationError(`invalid stream bundle inclusion proof at index ${event.index}`);
    }
  }
  const entries = bundle.events.map(event => ({ index: event.index, bytes: event.entryBytes }));
  let migration: MigrationVerificationResult | undefined;
  const verified = await verifyStreamLifecycle(entries, bundle.fqdn, {
    signal: options.signal,
    scope: bundle.reference.scope,
    logOrigin: bundle.reference.origin,
    streamId: bundle.reference.streamId,
    lr: bundle.reference.lr,
    signerKey: options.entityKey,
    checkpointIntegrationTimeMs: witnessTime.getTime() + maxClockSkewMs,
    verifyMigration: options.verifyMigration && (async (event, invocation) => {
      migration = await options.verifyMigration!(event, invocation);
      return migration;
    }),
  });
  const expectedState = lifecycleSummary(verified);
  if (bundle.state.eventCount !== expectedState.eventCount
    || bundle.state.lastEventType !== expectedState.lastEventType
    || bundle.state.loggedState !== expectedState.loggedState) {
    throw new C2spTlogVerificationError('stream bundle state does not match verified lifecycle history');
  }
  if (verified.length === 0) throw new C2spTlogVerificationError('empty stream bundle cannot prove current identity state');
  let lifecycle = verified.map(event => event.event);
  const currentReferences = verified.map(event => `${bundle.reference.lr}@${event.index}`);
  let historyReferences: LogRef[] | undefined = currentReferences;
  if (lifecycle[0]?.type === 'MIGRATION') {
    if (!migration) throw new C2spTlogVerificationError('MIGRATION requires stitched verified prior-log history', 'INVALID_MIGRATION');
    if (migration.priorHistoryReferences) historyReferences = stitchVerifiedMigrationReferences(lifecycle, currentReferences, migration);
    else historyReferences = undefined;
    lifecycle = await stitchVerifiedMigrationHistory(bundle.fqdn, lifecycle, migration);
  }
  const activeOperationalKeyThumbprint = activeOperationalThumbprint(lifecycle);
  return { bundle, events: verified, lifecycle, historyReferences, activeOperationalKeyThumbprint, checkpointWitnessTime: witnessTime };
}

function parseEvent(value: unknown, position: number, treeSize: number): C2spStreamBundleEvent {
  const object = exactObject(value, EVENT_MEMBERS, `stream bundle event ${position}`);
  const index = safeInteger(object.index, `events[${position}].index`);
  if (index >= treeSize) throw new C2spTlogParseError('stream bundle event index must be less than complete_through_size');
  const entryBytes = strictBase64url(object.entry, `events[${position}].entry`);
  if (entryBytes.length === 0 || entryBytes.length > 65_535) throw new C2spTlogParseError('stream bundle entry length is outside 1..65535 bytes');
  const proofBytes = strictBase64url(object.proof, `events[${position}].proof`);
  if (proofBytes.length % 32 !== 0 || proofBytes.length / 32 > 64) throw new C2spTlogParseError('stream bundle proof must contain at most 64 SHA-256 nodes');
  const proof: Uint8Array[] = [];
  for (let offset = 0; offset < proofBytes.length; offset += 32) proof.push(proofBytes.slice(offset, offset + 32));
  return { index, entryBytes, proof };
}

/** Verifies the bundle's Ed25519 signature against the unique trusted key matching its `name+keyid` kid. */
function verifyBundleSignature(bundle: C2spStreamBundle, keys: SignedNoteKey[], checkpointKeys: SignedNoteKey[]): void {
  if (!Array.isArray(keys) || keys.some(key => !key || key.kind !== 'ed25519'
    || !(key.keyBytes instanceof Uint8Array) || key.keyBytes.length !== 32
    || (key.signatureType !== undefined && (!(key.signatureType instanceof Uint8Array)
      || key.signatureType.length !== 1 || key.signatureType[0] !== 1)))) {
    throw new C2spTlogVerificationError('stream bundle signer must be Ed25519');
  }
  const checkpointPublicKeys = new Set(checkpointKeys.map(key => Buffer.from(key.keyBytes).toString('hex')));
  if (keys.some(key => checkpointPublicKeys.has(Buffer.from(key.keyBytes).toString('hex')))) {
    throw new C2spTlogVerificationError('stream bundle signer must be independent of checkpoint policy keys');
  }
  const candidates = keys.filter(candidate => candidate.keyId !== undefined
    && bundle.signature.kid === `${candidate.name}+${Buffer.from(candidate.keyId).toString('hex')}`);
  if (candidates.length !== 1 || candidates[0]!.keyBytes.length !== 32) {
    throw new C2spTlogVerificationError('stream bundle signature key is not uniquely trusted');
  }
  const key = candidates[0]!;
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(key.keyBytes)]),
      format: 'der',
      type: 'spki',
    });
    if (!verifySignature(null, Buffer.from(bundle.signedBytes), publicKey, Buffer.from(bundle.signature.value))) {
      throw new C2spTlogVerificationError('invalid stream bundle signature');
    }
  } catch (cause) {
    if (cause instanceof C2spTlogVerificationError) throw cause;
    throw new C2spTlogVerificationError('invalid stream bundle signature');
  }
}

function lifecycleSummary(events: VerifiedLifecycleEvent[]): C2spStreamBundleState {
  if (events.length === 0) return { eventCount: 0, lastEventType: '', loggedState: 'UNKNOWN' };
  const lastEventType = events.at(-1)!.event.type;
  const loggedState = lastEventType === 'REVOCATION' ? 'REVOKED' : lastEventType === 'RETIREMENT' ? 'RETIRED' : 'ACTIVE';
  return { eventCount: events.length, lastEventType, loggedState };
}

function activeOperationalThumbprint(events: LogEvent[]): string {
  let thumbprint = '';
  for (const event of events) {
    if (event.type === 'ISSUANCE') {
      if (!event.initialOperationalThumbprint) throw new C2spTlogVerificationError('verified ISSUANCE does not contain an operational-key thumbprint');
      thumbprint = event.initialOperationalThumbprint;
    }
    if (event.type === 'KEY_ROTATION') {
      if (!event.newOperationalThumbprint) throw new C2spTlogVerificationError('verified KEY_ROTATION does not contain an operational-key thumbprint');
      thumbprint = event.newOperationalThumbprint;
    }
  }
  if (!thumbprint) throw new C2spTlogVerificationError('verified stream bundle does not establish an operational key');
  return thumbprint;
}

/** Requires `value` to be an object with exactly the given member names. */
function exactObject(value: unknown, members: string[], name: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new C2spTlogParseError(`${name} must be an object`);
  const object = value as Record<string, unknown>;
  const keys = Object.keys(object).sort();
  const expected = members.slice().sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new C2spTlogParseError(`${name} has unsupported or missing members`);
  }
  return object;
}

function strictBase64url(value: unknown, name: string, expectedLength?: number): Uint8Array {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) throw new C2spTlogParseError(`${name} must be unpadded base64url`);
  const bytes = new Uint8Array(Buffer.from(value, 'base64url'));
  if (b64url(bytes) !== value) throw new C2spTlogParseError(`${name} must use canonical base64url`);
  if (expectedLength !== undefined && bytes.length !== expectedLength) throw new C2spTlogParseError(`${name} has invalid decoded length`);
  return bytes;
}

function safeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new C2spTlogParseError(`${name} must be a non-negative safe integer`);
  return value as number;
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new C2spTlogVerificationError(`${name} must be a positive integer`);
  return value;
}

function nonNegativeInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new C2spTlogVerificationError(`${name} must be a non-negative integer`);
  return value;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return Buffer.from(left).equals(Buffer.from(right));
}
