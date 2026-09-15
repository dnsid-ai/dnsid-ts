import { createHash } from 'node:crypto';

import { parseJsonNoDuplicateMembers } from './canonical.ts';
import { C2spTlogParseError } from './errors.ts';
import { parseC2spTlogLr, type C2spTlogScope } from './lr.ts';
import { normalizedOriginPolicy, parseC2spPolicyFile } from './policy.ts';
import { parseSignedNoteVerifierKey, type SignedNoteKey } from './signed-note.ts';

const MEMBERS = ['bundle_verifier_keys', 'log_prefix', 'scope', 'tlog_policy', 'version'];

/** Independently distributed trust for one exact DNSid C2SP log. */
export interface C2spTlogTrustProfile {
  version: 1;
  scope: C2spTlogScope;
  logPrefix: string;
  policyDocument: Uint8Array;
  bundleVerifierKeys: SignedNoteKey[];
}

/** Parses and validates a `dnsid-c2sp-tlog-trust-profile@v1` JSON document. */
export function parseC2spTlogTrustProfile(bytes: Uint8Array): C2spTlogTrustProfile {
  const value = parseJsonNoDuplicateMembers(bytes);
  const object = exactObject(value);
  if (object.version !== 1 || typeof object.scope !== 'string' || typeof object.log_prefix !== 'string'
    || typeof object.tlog_policy !== 'string' || !Array.isArray(object.bundle_verifier_keys)) {
    throw new C2spTlogParseError('invalid C2SP tlog trust profile');
  }
  const reference = parseC2spTlogLr(`c2sp-tlog:${object.scope}:${object.log_prefix}#trust-profile`);
  const policyDocument = new TextEncoder().encode(object.tlog_policy);
  if (object.bundle_verifier_keys.length === 0 || object.bundle_verifier_keys.some(key => typeof key !== 'string' || key.length === 0)) {
    throw new C2spTlogParseError('C2SP tlog trust profile requires bundle verifier keys');
  }
  const keyStrings = object.bundle_verifier_keys as string[];
  if (new Set(keyStrings).size !== keyStrings.length) throw new C2spTlogParseError('C2SP tlog trust profile bundle verifier keys must be distinct');
  const bundleVerifierKeys = keyStrings.map(key => {
    if (key !== key.trim()) throw new C2spTlogParseError('invalid C2SP tlog trust profile bundle verifier key');
    const parsed = parseSignedNoteVerifierKey(key);
    validateBundleKey(parsed, 'dnsid-stream-bundle');
    return parsed;
  });
  const profile = {
    version: 1 as const,
    scope: reference.scope,
    logPrefix: reference.logPrefix,
    policyDocument,
    bundleVerifierKeys,
  };
  validateC2spTlogTrustProfile(profile);
  return profile;
}

export function validateC2spTlogTrustProfile(profile: C2spTlogTrustProfile): void {
  if (!profile || typeof profile !== 'object' || Array.isArray(profile) || profile.version !== 1
    || typeof profile.scope !== 'string' || typeof profile.logPrefix !== 'string'
    || !(profile.policyDocument instanceof Uint8Array) || !Array.isArray(profile.bundleVerifierKeys)
    || profile.bundleVerifierKeys.length === 0) {
    throw new C2spTlogParseError('invalid C2SP tlog trust profile');
  }
  const reference = parseC2spTlogLr(`c2sp-tlog:${profile.scope}:${profile.logPrefix}#trust-profile`);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(profile.policyDocument);
  const checkpointKeys = normalizedOriginPolicy(parseC2spPolicyFile(text), reference.origin);
  validateC2spBundleVerifierKeys(
    profile.bundleVerifierKeys,
    [...checkpointKeys.logKeys, ...checkpointKeys.witnessKeys],
    'dnsid-stream-bundle',
  );
}

/** @internal Validates independently trusted stream-bundle signer keys. */
export function validateC2spBundleVerifierKeys(
  keys: SignedNoteKey[],
  checkpointKeys: SignedNoteKey[] = [],
  requiredName?: string,
): void {
  if (!Array.isArray(keys)) throw new C2spTlogParseError('C2SP tlog bundle verifier keys must be an array');
  keys.forEach(key => validateBundleKey(key, requiredName));
  const ids = keys.map(key => `${key.name}+${Buffer.from(key.keyId!).toString('hex')}`);
  const publicKeys = keys.map(key => Buffer.from(key.keyBytes).toString('hex'));
  if (new Set(ids).size !== ids.length || new Set(publicKeys).size !== publicKeys.length) {
    throw new C2spTlogParseError('C2SP tlog bundle verifier keys must have distinct public keys and key IDs');
  }
  const checkpointPublicKeys = new Set(checkpointKeys.map(key => Buffer.from(key.keyBytes).toString('hex')));
  if (publicKeys.some(key => checkpointPublicKeys.has(key))) {
    throw new C2spTlogParseError('C2SP tlog bundle signer must be independent of checkpoint policy keys');
  }
}

function validateBundleKey(key: SignedNoteKey, requiredName?: string): void {
  if (!key || typeof key !== 'object' || Array.isArray(key) || typeof key.name !== 'string' || !key.name
    || (requiredName !== undefined && key.name !== requiredName)
    || key.kind !== 'ed25519' || !(key.keyBytes instanceof Uint8Array) || key.keyBytes.length !== 32
    || !(key.keyId instanceof Uint8Array) || key.keyId.length !== 4
    || !(key.signatureType instanceof Uint8Array) || key.signatureType.length !== 1 || key.signatureType[0] !== 1) {
    throw new C2spTlogParseError('invalid C2SP tlog trust profile bundle verifier key');
  }
  const hash = createHash('sha256').update(key.name).update('\n').update(key.signatureType).update(key.keyBytes).digest().subarray(0, 4);
  if (!hash.equals(Buffer.from(key.keyId))) throw new C2spTlogParseError('invalid C2SP tlog trust profile bundle verifier key hash');
}

function exactObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new C2spTlogParseError('C2SP tlog trust profile must be an object');
  const keys = Object.keys(value).sort();
  if (keys.length !== MEMBERS.length || keys.some((key, index) => key !== MEMBERS[index])) {
    throw new C2spTlogParseError('C2SP tlog trust profile has unsupported or missing members');
  }
  return value as Record<string, unknown>;
}
