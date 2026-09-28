import { createHash } from 'node:crypto';

import { parseJsonNoDuplicateMembers } from './canonical.ts';
import { C2spTlogParseError } from './errors.ts';
import { parseC2spTlogLr, type C2spTlogScope } from './lr.ts';
import { normalizedOriginPolicy, parseC2spPolicyFile, type C2spTlogPolicy } from './policy.ts';
import { parseSignedNoteVerifierKey, type SignedNoteKey } from './signed-note.ts';

const V1_MEMBERS = ['bundle_verifier_keys', 'log_prefix', 'scope', 'tlog_policy', 'version'];
const V2_MEMBERS = ['epochs', 'log_prefix', 'scope', 'version'];
const EPOCH_REQUIRED_MEMBERS = ['bundle_verifier_keys', 'id', 'tlog_policy'];
const EPOCH_OPTIONAL_MEMBERS = ['max_tree_size', 'min_tree_size'];

/** Maximum number of epochs in a version 2 trust profile. */
const MAX_TRUST_PROFILE_EPOCHS = 8;
/** Epoch ids are 1-64 characters of `A-Z a-z 0-9 . _ -`. */
const TRUST_EPOCH_ID = /^[A-Za-z0-9._-]{1,64}$/;
/** Epoch tree-size bounds are decimal integers without sign, fraction or exponent. */
const TREE_SIZE_LEXEME = /^[1-9][0-9]*$/;

/**
 * Version 1 trust profile: one C2SP tlog-policy document and the stream-bundle
 * signers bound to it, for one exact DNSid C2SP log.
 */
export interface C2spTlogTrustProfileV1 {
  version: 1;
  scope: C2spTlogScope;
  logPrefix: string;
  policyDocument: Uint8Array;
  bundleVerifierKeys: SignedNoteKey[];
}

/**
 * One complete trust epoch of a version 2 trust profile: a tlog-policy
 * document with exactly one log key, the stream-bundle signers bound to it,
 * and optional inclusive checkpoint tree-size bounds.
 *
 * `policyDocument` must be byte-identical to the policy the epoch's log server
 * renders, because stream bundles bind its SHA-256 as `policy_hash`. An absent
 * bound is open.
 */
export interface C2spTlogTrustEpoch {
  /** Epoch id: 1-64 characters of `A-Z a-z 0-9 . _ -`, or `''` for a version 1 profile. */
  id: string;
  policyDocument: Uint8Array;
  bundleVerifierKeys: SignedNoteKey[];
  /** Smallest accepted checkpoint tree size (inclusive), 1 to 2^53-1. */
  minTreeSize?: number;
  /** Largest accepted checkpoint tree size (inclusive), 1 to 2^53-1. */
  maxTreeSize?: number;
}

/**
 * Version 2 trust profile: an ordered list of complete trust epochs for one
 * log, used to rotate its log, witness and bundle keys together. A checkpoint
 * or stream bundle is accepted only when it satisfies one epoch completely;
 * signatures are never combined across epochs.
 */
export interface C2spTlogTrustProfileV2 {
  version: 2;
  scope: C2spTlogScope;
  logPrefix: string;
  epochs: C2spTlogTrustEpoch[];
}

/** Independently distributed trust for one exact DNSid C2SP log. Narrow on `version`. */
export type C2spTlogTrustProfile = C2spTlogTrustProfileV1 | C2spTlogTrustProfileV2;

/**
 * Parses and validates a DNSid C2SP trust-profile JSON document: version 1
 * (`dnsid-c2sp-tlog-trust-profile@v1`) or version 2 (epochs). Members that
 * belong to the other version are rejected even when empty.
 *
 * @throws C2spTlogParseError when the document is malformed or invalid.
 */
export function parseC2spTlogTrustProfile(bytes: Uint8Array): C2spTlogTrustProfile {
  const value = parseJsonNoDuplicateMembers(bytes);
  if (value && typeof value === 'object' && !Array.isArray(value) && (value as Record<string, unknown>).version === 2) {
    return parseTrustProfileV2(bytes);
  }
  return parseTrustProfileV1(value);
}

/**
 * Returns the profile's trust epochs in profile order. A version 1 profile
 * yields one epoch with id `''` and no tree-size bounds.
 *
 * @throws C2spTlogParseError when the profile is invalid.
 */
export function c2spTlogTrustEpochs(profile: C2spTlogTrustProfile): C2spTlogTrustEpoch[] {
  validateC2spTlogTrustProfile(profile);
  if (profile.version === 1) {
    return [{ id: '', policyDocument: profile.policyDocument.slice(), bundleVerifierKeys: [...profile.bundleVerifierKeys] }];
  }
  return profile.epochs.map(cloneEpoch);
}

/**
 * Builds a checkpoint policy that accepts a checkpoint only when it satisfies
 * one of `epochs` completely: that epoch's log signature, tree-size bounds and
 * witness quorum. Epochs are tried in order and must all name one log origin,
 * so trusted checkpoint state, which is keyed by origin, carries across them.
 *
 * @throws C2spTlogParseError when the epoch set is invalid.
 */
export function createC2spTlogEpochPolicy(epochs: C2spTlogTrustEpoch[]): C2spTlogPolicy {
  if (!Array.isArray(epochs) || epochs.length === 0 || !(epochs[0]?.policyDocument instanceof Uint8Array)) {
    throw new C2spTlogParseError('C2SP tlog epoch policy requires at least one trust epoch');
  }
  const first = parseC2spPolicyFile(new TextDecoder('utf-8', { fatal: true }).decode(epochs[0].policyDocument));
  const origins = Object.keys(first.origins);
  if (origins.length !== 1) throw new C2spTlogParseError('trust epoch policy must contain exactly one log key, named for the log origin');
  validateC2spTlogTrustEpochs(epochs, origins[0]!);
  return {
    origins: {},
    epochs: epochs.map(epoch => ({
      id: epoch.id,
      policy: parseC2spPolicyFile(new TextDecoder('utf-8', { fatal: true }).decode(epoch.policyDocument)),
      ...(epoch.minTreeSize === undefined ? {} : { minTreeSize: epoch.minTreeSize }),
      ...(epoch.maxTreeSize === undefined ? {} : { maxTreeSize: epoch.maxTreeSize }),
    })),
  };
}

/**
 * Returns the checkpoint policy a trust profile defines, as the verification
 * registry uses it: the parsed `tlog_policy` for version 1 (unchanged), or an
 * epoch policy ({@link createC2spTlogEpochPolicy}) for version 2.
 *
 * @throws C2spTlogParseError when the profile is invalid.
 */
export function c2spTlogTrustProfilePolicy(profile: C2spTlogTrustProfile): C2spTlogPolicy {
  validateC2spTlogTrustProfile(profile);
  if (profile.version === 1) return parseC2spPolicyFile(new TextDecoder('utf-8', { fatal: true }).decode(profile.policyDocument));
  return createC2spTlogEpochPolicy(profile.epochs);
}

function parseTrustProfileV1(value: unknown): C2spTlogTrustProfileV1 {
  const object = exactObject(value, V1_MEMBERS);
  if (object.version !== 1 || typeof object.scope !== 'string' || typeof object.log_prefix !== 'string'
    || typeof object.tlog_policy !== 'string' || !Array.isArray(object.bundle_verifier_keys)) {
    throw new C2spTlogParseError('invalid C2SP tlog trust profile');
  }
  const reference = parseC2spTlogLr(`c2sp-tlog:${object.scope}:${object.log_prefix}#trust-profile`);
  const policyDocument = new TextEncoder().encode(object.tlog_policy);
  const profile = {
    version: 1 as const,
    scope: reference.scope,
    logPrefix: reference.logPrefix,
    policyDocument,
    bundleVerifierKeys: parseBundleVerifierKeyStrings(object.bundle_verifier_keys),
  };
  validateC2spTlogTrustProfile(profile);
  return profile;
}

function parseTrustProfileV2(bytes: Uint8Array): C2spTlogTrustProfileV2 {
  // Re-read with number source text so bounds are checked lexically, exactly
  // as a strict integer decoder would; JSON.parse alone maps 5.0 and 5e0 to 5.
  const { value, numberSource } = parseWithNumberSource(bytes);
  const object = exactObject(value, V2_MEMBERS);
  if (numberSource(object, 'version') !== '2' || typeof object.scope !== 'string' || typeof object.log_prefix !== 'string') {
    throw new C2spTlogParseError('invalid C2SP tlog trust profile');
  }
  if (!Array.isArray(object.epochs) || object.epochs.length === 0 || object.epochs.length > MAX_TRUST_PROFILE_EPOCHS) {
    throw new C2spTlogParseError(`C2SP tlog trust profile version 2 needs between 1 and ${MAX_TRUST_PROFILE_EPOCHS} epochs`);
  }
  const reference = parseC2spTlogLr(`c2sp-tlog:${object.scope}:${object.log_prefix}#trust-profile`);
  const epochs = object.epochs.map((epochValue): C2spTlogTrustEpoch => {
    const epoch = exactEpochObject(epochValue);
    if (typeof epoch.id !== 'string' || typeof epoch.tlog_policy !== 'string' || !Array.isArray(epoch.bundle_verifier_keys)) {
      throw new C2spTlogParseError('invalid C2SP tlog trust profile epoch');
    }
    const parsed: C2spTlogTrustEpoch = {
      id: epoch.id,
      policyDocument: new TextEncoder().encode(epoch.tlog_policy),
      bundleVerifierKeys: parseBundleVerifierKeyStrings(epoch.bundle_verifier_keys),
    };
    const minTreeSize = treeSizeBound(epoch, 'min_tree_size', numberSource);
    const maxTreeSize = treeSizeBound(epoch, 'max_tree_size', numberSource);
    if (minTreeSize !== undefined) parsed.minTreeSize = minTreeSize;
    if (maxTreeSize !== undefined) parsed.maxTreeSize = maxTreeSize;
    return parsed;
  });
  const profile: C2spTlogTrustProfileV2 = { version: 2, scope: reference.scope, logPrefix: reference.logPrefix, epochs };
  validateC2spTlogTrustProfile(profile);
  return profile;
}

/**
 * @internal Validates a parsed or programmatically built trust profile.
 * @throws C2spTlogParseError when the profile is invalid.
 */
export function validateC2spTlogTrustProfile(profile: C2spTlogTrustProfile): void {
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)
    || (profile.version !== 1 && profile.version !== 2)
    || typeof profile.scope !== 'string' || typeof profile.logPrefix !== 'string') {
    throw new C2spTlogParseError('invalid C2SP tlog trust profile');
  }
  const reference = parseC2spTlogLr(`c2sp-tlog:${profile.scope}:${profile.logPrefix}#trust-profile`);
  if (profile.version === 1) {
    const v1 = profile as C2spTlogTrustProfileV1 & { epochs?: unknown };
    if (v1.epochs !== undefined || !(v1.policyDocument instanceof Uint8Array)
      || !Array.isArray(v1.bundleVerifierKeys) || v1.bundleVerifierKeys.length === 0) {
      throw new C2spTlogParseError('invalid C2SP tlog trust profile');
    }
    const text = new TextDecoder('utf-8', { fatal: true }).decode(v1.policyDocument);
    const checkpointKeys = normalizedOriginPolicy(parseC2spPolicyFile(text), reference.origin);
    validateC2spBundleVerifierKeys(
      v1.bundleVerifierKeys,
      [...checkpointKeys.logKeys, ...checkpointKeys.witnessKeys],
      'dnsid-stream-bundle',
    );
    return;
  }
  const v2 = profile as C2spTlogTrustProfileV2 & { policyDocument?: unknown; bundleVerifierKeys?: unknown };
  if (v2.policyDocument !== undefined || v2.bundleVerifierKeys !== undefined) {
    throw new C2spTlogParseError('C2SP tlog trust profile version 2 must carry its policies and bundle keys in epochs');
  }
  validateC2spTlogTrustEpochs(v2.epochs, reference.origin);
}

/**
 * @internal Validates an ordered trust-epoch set for one log: 1 to 8 epochs
 * with distinct valid ids, each a complete single-log policy named for the
 * origin with independent bundle keys and ordered bounds, and no two epochs
 * sharing both a bundle key ID and a policy document.
 * @throws C2spTlogParseError when the set is invalid.
 */
export function validateC2spTlogTrustEpochs(epochs: C2spTlogTrustEpoch[], origin: string): void {
  if (!Array.isArray(epochs) || epochs.length === 0 || epochs.length > MAX_TRUST_PROFILE_EPOCHS) {
    throw new C2spTlogParseError(`C2SP tlog trust profile needs between 1 and ${MAX_TRUST_PROFILE_EPOCHS} epochs`);
  }
  const ids = new Set<string>();
  epochs.forEach((epoch, index) => {
    if (!epoch || typeof epoch !== 'object' || Array.isArray(epoch) || typeof epoch.id !== 'string' || !TRUST_EPOCH_ID.test(epoch.id)) {
      throw new C2spTlogParseError('C2SP tlog trust profile epoch id must be 1 to 64 characters of A-Z, a-z, 0-9, ".", "_" or "-"');
    }
    if (ids.has(epoch.id)) throw new C2spTlogParseError('C2SP tlog trust profile epoch ids must be distinct');
    ids.add(epoch.id);
    try {
      validateTrustEpoch(epoch, origin);
    } catch (cause) {
      throw new C2spTlogParseError(`C2SP tlog trust profile epoch ${JSON.stringify(epoch.id)}: ${cause instanceof Error ? cause.message : String(cause)}`, cause);
    }
    for (const earlier of epochs.slice(0, index)) {
      if (!Buffer.from(earlier.policyDocument).equals(Buffer.from(epoch.policyDocument))) continue;
      const earlierKids = new Set(earlier.bundleVerifierKeys.map(bundleKeyId));
      if (epoch.bundleVerifierKeys.some(key => earlierKids.has(bundleKeyId(key)))) {
        throw new C2spTlogParseError(`C2SP tlog trust epochs ${JSON.stringify(earlier.id)} and ${JSON.stringify(epoch.id)} share a bundle key ID and policy, so bundle selection is ambiguous`);
      }
    }
  });
}

/** Validates one epoch: exactly one log key named for `origin`, verified key hashes, independent bundle keys, bounds. */
function validateTrustEpoch(epoch: C2spTlogTrustEpoch, origin: string): void {
  if (!(epoch.policyDocument instanceof Uint8Array) || !Array.isArray(epoch.bundleVerifierKeys) || epoch.bundleVerifierKeys.length === 0) {
    throw new C2spTlogParseError('trust epoch needs a policy document and a bundle verifier key');
  }
  const text = new TextDecoder('utf-8', { fatal: true }).decode(epoch.policyDocument);
  const policy = parseC2spPolicyFile(text);
  // An epoch is one log key; rotation is expressed with epochs, never with a
  // second log line, so no single epoch can mix keys.
  const logKeys = Object.values(policy.origins).flatMap(origin => origin.logKeys);
  if (logKeys.length !== 1 || !policy.origins[origin]) {
    throw new C2spTlogParseError('trust epoch policy must contain exactly one log key, named for the log origin');
  }
  const normalized = normalizedOriginPolicy(policy, origin);
  // Every declared key counts, including witnesses outside the quorum rule.
  const declaredWitnessKeys = (policy.origins[origin]!.witnessKeys ?? []).filter((key): key is SignedNoteKey => typeof key !== 'string');
  const checkpointKeys = [...normalized.logKeys, ...declaredWitnessKeys, ...normalized.witnessKeys];
  if (checkpointKeys.some(key => !key.keyId || !keyHashMatches(key))) {
    throw new C2spTlogParseError('trust epoch policy key hash does not match its key');
  }
  validateC2spBundleVerifierKeys(epoch.bundleVerifierKeys, checkpointKeys, 'dnsid-stream-bundle');
  for (const bound of [epoch.minTreeSize, epoch.maxTreeSize]) {
    if (bound !== undefined && (!Number.isSafeInteger(bound) || bound < 1)) {
      throw new C2spTlogParseError('trust epoch tree-size bounds must be integers between 1 and 2^53-1; omit a bound to leave it open');
    }
  }
  if (epoch.minTreeSize !== undefined && epoch.maxTreeSize !== undefined && epoch.minTreeSize > epoch.maxTreeSize) {
    throw new C2spTlogParseError('trust epoch min_tree_size exceeds max_tree_size');
  }
}

/** @internal Validates independently trusted stream-bundle signer keys. */
export function validateC2spBundleVerifierKeys(
  keys: SignedNoteKey[],
  checkpointKeys: SignedNoteKey[] = [],
  requiredName?: string,
): void {
  if (!Array.isArray(keys)) throw new C2spTlogParseError('C2SP tlog bundle verifier keys must be an array');
  keys.forEach(key => validateBundleKey(key, requiredName));
  const ids = keys.map(bundleKeyId);
  const publicKeys = keys.map(key => Buffer.from(key.keyBytes).toString('hex'));
  if (new Set(ids).size !== ids.length || new Set(publicKeys).size !== publicKeys.length) {
    throw new C2spTlogParseError('C2SP tlog bundle verifier keys must have distinct public keys and key IDs');
  }
  const checkpointPublicKeys = new Set(checkpointKeys.map(key => Buffer.from(key.keyBytes).toString('hex')));
  if (publicKeys.some(key => checkpointPublicKeys.has(key))) {
    throw new C2spTlogParseError('C2SP tlog bundle signer must be independent of checkpoint policy keys');
  }
}

/** @internal The `name+keyhash` identifier a stream bundle's `sig.kid` names. */
export function bundleKeyId(key: SignedNoteKey): string {
  return `${key.name}+${Buffer.from(key.keyId ?? []).toString('hex')}`;
}

function parseBundleVerifierKeyStrings(keys: unknown[]): SignedNoteKey[] {
  if (keys.length === 0 || keys.some(key => typeof key !== 'string' || key.length === 0)) {
    throw new C2spTlogParseError('C2SP tlog trust profile requires bundle verifier keys');
  }
  const keyStrings = keys as string[];
  if (new Set(keyStrings).size !== keyStrings.length) throw new C2spTlogParseError('C2SP tlog trust profile bundle verifier keys must be distinct');
  return keyStrings.map(key => {
    if (key !== key.trim()) throw new C2spTlogParseError('invalid C2SP tlog trust profile bundle verifier key');
    const parsed = parseSignedNoteVerifierKey(key);
    validateBundleKey(parsed, 'dnsid-stream-bundle');
    return parsed;
  });
}

function validateBundleKey(key: SignedNoteKey, requiredName?: string): void {
  if (!key || typeof key !== 'object' || Array.isArray(key) || typeof key.name !== 'string' || !key.name
    || (requiredName !== undefined && key.name !== requiredName)
    || key.kind !== 'ed25519' || !(key.keyBytes instanceof Uint8Array) || key.keyBytes.length !== 32
    || !(key.keyId instanceof Uint8Array) || key.keyId.length !== 4
    || !(key.signatureType instanceof Uint8Array) || key.signatureType.length !== 1 || key.signatureType[0] !== 1) {
    throw new C2spTlogParseError('invalid C2SP tlog trust profile bundle verifier key');
  }
  if (!keyHashMatches(key)) throw new C2spTlogParseError('invalid C2SP tlog trust profile bundle verifier key hash');
}

/** Checks the signed-note key hash: the first four bytes of SHA-256(name || "\n" || type || key). */
function keyHashMatches(key: SignedNoteKey): boolean {
  if (!(key.keyId instanceof Uint8Array) || !(key.signatureType instanceof Uint8Array)) return false;
  const hash = createHash('sha256').update(key.name).update('\n').update(key.signatureType).update(key.keyBytes).digest().subarray(0, 4);
  return hash.equals(Buffer.from(key.keyId));
}

function treeSizeBound(epoch: Record<string, unknown>, member: string, numberSource: NumberSource): number | undefined {
  const value = epoch[member];
  if (value === undefined || value === null) return undefined;
  const source = numberSource(epoch, member);
  if (source === undefined || !TREE_SIZE_LEXEME.test(source) || !Number.isSafeInteger(value) || (value as number) < 1) {
    throw new C2spTlogParseError(`C2SP tlog trust profile epoch ${member} must be an integer between 1 and 2^53-1; omit it to leave the bound open`);
  }
  return value as number;
}

type NumberSource = (holder: Record<string, unknown>, member: string) => string | undefined;

/**
 * Parses already strictly validated JSON again, recording the source text of
 * every number by its holder object and member name.
 */
function parseWithNumberSource(bytes: Uint8Array): { value: unknown; numberSource: NumberSource } {
  const sources = new WeakMap<object, Map<string, string>>();
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const reviver = function (this: object, key: string, value: unknown, context?: { source?: string }): unknown {
    if (typeof value === 'number') {
      if (typeof context?.source !== 'string') throw new C2spTlogParseError('JSON number source text is unavailable in this runtime');
      let members = sources.get(this);
      if (!members) sources.set(this, members = new Map());
      members.set(key, context.source);
    }
    return value;
  };
  let value: unknown;
  try {
    value = JSON.parse(text, reviver as (this: unknown, key: string, value: unknown) => unknown);
  } catch (cause) {
    if (cause instanceof C2spTlogParseError) throw cause;
    throw new C2spTlogParseError('malformed C2SP tlog trust profile JSON', cause);
  }
  return { value, numberSource: (holder, member) => sources.get(holder)?.get(member) };
}

function exactObject(value: unknown, members: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new C2spTlogParseError('C2SP tlog trust profile must be an object');
  const keys = Object.keys(value).sort();
  if (keys.length !== members.length || keys.some((key, index) => key !== members[index])) {
    throw new C2spTlogParseError('C2SP tlog trust profile has unsupported or missing members');
  }
  return value as Record<string, unknown>;
}

function exactEpochObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new C2spTlogParseError('C2SP tlog trust profile epoch must be an object');
  const keys = Object.keys(value);
  if (EPOCH_REQUIRED_MEMBERS.some(member => !keys.includes(member))
    || keys.some(key => !EPOCH_REQUIRED_MEMBERS.includes(key) && !EPOCH_OPTIONAL_MEMBERS.includes(key))) {
    throw new C2spTlogParseError('C2SP tlog trust profile epoch has unsupported or missing members');
  }
  return value as Record<string, unknown>;
}

function cloneEpoch(epoch: C2spTlogTrustEpoch): C2spTlogTrustEpoch {
  const clone: C2spTlogTrustEpoch = { id: epoch.id, policyDocument: epoch.policyDocument.slice(), bundleVerifierKeys: [...epoch.bundleVerifierKeys] };
  if (epoch.minTreeSize !== undefined) clone.minTreeSize = epoch.minTreeSize;
  if (epoch.maxTreeSize !== undefined) clone.maxTreeSize = epoch.maxTreeSize;
  return clone;
}
