import { C2spTlogVerificationError } from './errors.ts';
import type { Checkpoint } from './checkpoint.ts';
import { parseSignedNoteVerifierKey, verifiedCosignatureTimestamp, verifyCheckpointSignature, verifyNoteSignature, type SignedNoteKey } from './signed-note.ts';

/** Signed notes carry at most this many signature lines (c2sp.org/signed-note verifiers may stop at 100). */
const MAX_CHECKPOINT_SIGNATURES = 100;

/**
 * Witness-quorum requirement for accepting a checkpoint: no witnesses, a single
 * named witness, or a threshold over nested member rules.
 */
export type C2spTlogQuorumRule =
  | { kind: 'none' }
  | { kind: 'witness'; key: SignedNoteKey | string }
  | { kind: 'threshold'; threshold: number; members: C2spTlogQuorumRule[] };

/** Local trust configuration for one checkpoint origin. Keys may be parsed or in signed-note verifier-key text form. */
export interface C2spTlogOriginPolicy {
  /** Accepted log signing keys; each key name must equal the origin. */
  logKeys: (SignedNoteKey | string)[];
  /** Witness cosignature keys used by the flat `quorum` count when no `quorumRule` is given. */
  witnessKeys?: (SignedNoteKey | string)[];
  /** Flat witness quorum count; superseded by `quorumRule` when both are set. */
  quorum?: number;
  quorumRule?: C2spTlogQuorumRule;
  /** @deprecated Ignored: every scope requires a logical predecessor chain. */
  unchained?: boolean;
}

/**
 * One trust epoch of an epoch policy: a single-log policy for the origin and
 * optional inclusive checkpoint tree-size bounds.
 */
export interface C2spTlogPolicyEpoch {
  /** Epoch id reported in {@link CheckpointPolicyResult.trustEpoch}. */
  id: string;
  /** The epoch's own policy, holding exactly one log key for the origin. */
  policy: C2spTlogPolicy;
  /** Smallest accepted checkpoint tree size (inclusive). */
  minTreeSize?: number;
  /** Largest accepted checkpoint tree size (inclusive). */
  maxTreeSize?: number;
}

/**
 * Local C2SP tlog trust policy: per-origin rules, optionally pinned to one lr scope.
 *
 * When `epochs` is set, `origins` is ignored and a checkpoint is accepted only
 * when it satisfies one epoch completely: that epoch's log signature, tree-size
 * bounds and witness quorum. Signatures are never combined across epochs.
 */
export interface C2spTlogPolicy {
  scope?: string;
  origins: Record<string, C2spTlogOriginPolicy>;
  /** Ordered trust epochs; build them with `createC2spTlogEpochPolicy`. */
  epochs?: C2spTlogPolicyEpoch[];
}

/** Origin policy after key parsing and quorum-rule validation. */
export interface NormalizedOriginPolicy {
  logKeys: SignedNoteKey[];
  witnessKeys: SignedNoteKey[];
  quorum: number;
  quorumRule: NormalizedQuorumRule;
  /** @deprecated Ignored: every scope requires a logical predecessor chain. */
  unchained: boolean;
}

type NormalizedQuorumRule =
  | { kind: 'none' }
  | { kind: 'witness'; key: SignedNoteKey }
  | { kind: 'threshold'; threshold: number; members: NormalizedQuorumRule[] };

/** Outcome of checkpoint policy enforcement. */
export interface CheckpointPolicyResult {
  /** Epoch-second timestamps of the accepted witness cosignatures. */
  acceptedWitnessTimestamps: number[];
  /** Earliest accepted witness timestamp; undefined when the quorum rule required no witnesses. */
  checkpointWitnessTime?: Date;
  /** Id of the trust epoch that accepted the checkpoint; `''` for a policy without epochs. */
  trustEpoch: string;
}

/** Optional checks applied by {@link enforceCheckpointPolicy}. */
export interface CheckpointPolicyOptions {
  /**
   * Maximum age in milliseconds of the accepted witness time. When set, a
   * checkpoint without an accepted timestamp, or with an older one, is
   * rejected; with epochs, an epoch that fails freshness does not accept.
   */
  maxCheckpointAgeMs?: number;
}

/**
 * Resolves and validates the policy for `origin`: parses key strings, checks
 * signature types (0x01 for log keys, 0x04 for witness cosignature keys),
 * requires distinct underlying public keys, and normalizes the quorum rule.
 *
 * @throws C2spTlogVerificationError when the origin has no policy or the policy is invalid.
 */
export function normalizedOriginPolicy(policy: C2spTlogPolicy, origin: string): NormalizedOriginPolicy {
  const p = policy.origins[origin];
  if (!p) throw new C2spTlogVerificationError(`no local C2SP policy for origin ${origin}`);
  const logKeys = p.logKeys.map(asKey);
  const witnessKeys = (p.witnessKeys ?? []).map(asKey);
  const quorum = p.quorum ?? 0;
  if (!Number.isSafeInteger(quorum) || quorum < 0) throw new C2spTlogVerificationError('checkpoint witness quorum must be a non-negative integer');
  if (quorum > witnessKeys.length) throw new C2spTlogVerificationError('checkpoint witness quorum exceeds configured witnesses');
  if (logKeys.length === 0) throw new C2spTlogVerificationError('checkpoint policy requires at least one log key');
  if (logKeys.some(key => key.name !== origin)) throw new C2spTlogVerificationError('checkpoint log key name must match its origin');
  if (logKeys.some(key => key.signatureType !== undefined && (key.signatureType.length !== 1 || key.signatureType[0] !== 0x01))) {
    throw new C2spTlogVerificationError('checkpoint log keys must use the supported log signature type 0x01');
  }
  if (witnessKeys.some(key => key.signatureType?.length !== 1 || key.signatureType[0] !== 0x04)) {
    throw new C2spTlogVerificationError('checkpoint witness keys must use the supported cosignature type 0x04');
  }

  assertDistinctUnderlyingKeys(logKeys, 'checkpoint log keys');
  assertDistinctUnderlyingKeys(witnessKeys, 'checkpoint witness keys');
  const logIdentities = new Set(logKeys.map(keyIdentity));
  if (witnessKeys.some(key => logIdentities.has(keyIdentity(key)))) {
    throw new C2spTlogVerificationError('checkpoint log and witness keys must use distinct underlying public keys');
  }

  const quorumRule = normalizeQuorumRule(p.quorumRule ?? flatQuorumRule(witnessKeys, quorum));
  const ruleWitnessKeys = collectWitnessKeys(quorumRule);
  if (ruleWitnessKeys.some(key => key.signatureType?.length !== 1 || key.signatureType[0] !== 0x04)) {
    throw new C2spTlogVerificationError('checkpoint quorum witness keys must use the supported cosignature type 0x04');
  }
  assertDistinctUnderlyingKeys(ruleWitnessKeys, 'checkpoint quorum witness keys');
  if (ruleWitnessKeys.some(key => logIdentities.has(keyIdentity(key)))) {
    throw new C2spTlogVerificationError('checkpoint log and witness keys must use distinct underlying public keys');
  }
  return {
    logKeys,
    witnessKeys: ruleWitnessKeys,
    quorum: topLevelThreshold(quorumRule),
    quorumRule,
    unchained: p.unchained ?? false,
  };
}

/**
 * Enforces the local trust policy on a parsed checkpoint: origin and scope
 * match, a valid signature from an accepted log key, and a satisfied witness
 * quorum of timestamped cosignatures no further than `maxClockSkewMs` in the
 * future. Public scope additionally requires a non-empty quorum rule.
 *
 * With `policy.epochs`, epochs are tried in order. An epoch is relevant when
 * the checkpoint carries a signature line under its log key name and key hash.
 * A relevant epoch checks, in order, its log signature, its tree-size bounds,
 * its own witness quorum (by witness name and key hash) and, when
 * `options.maxCheckpointAgeMs` is set, freshness. The first epoch passing every
 * check accepts. Otherwise the error is that of the first relevant epoch, or a
 * missing log signature when no epoch is relevant.
 *
 * @returns The accepted witness timestamps, derived checkpoint witness time and accepting epoch.
 * @throws C2spTlogVerificationError when any requirement is not met.
 */
export function enforceCheckpointPolicy(
  checkpoint: Checkpoint,
  origin: string,
  policy: C2spTlogPolicy,
  scope: string,
  nowMs = Date.now(),
  maxClockSkewMs = 0,
  options: CheckpointPolicyOptions = {},
): CheckpointPolicyResult {
  if (!Number.isSafeInteger(maxClockSkewMs) || maxClockSkewMs < 0) throw new C2spTlogVerificationError('maximum clock skew must be a non-negative integer');
  const maxCheckpointAgeMs = options.maxCheckpointAgeMs;
  if (maxCheckpointAgeMs !== undefined && (!Number.isSafeInteger(maxCheckpointAgeMs) || maxCheckpointAgeMs < 1)) {
    throw new C2spTlogVerificationError('maximum checkpoint age must be a positive integer');
  }
  if (policy.scope !== undefined && policy.scope !== scope) throw new C2spTlogVerificationError(`C2SP policy scope ${policy.scope} does not match ${scope}`);
  if (checkpoint.origin !== origin) throw new C2spTlogVerificationError(`checkpoint origin mismatch: ${checkpoint.origin}`);
  if (policy.epochs === undefined) return enforceSinglePolicy(checkpoint, origin, policy, scope, nowMs, maxClockSkewMs, maxCheckpointAgeMs, undefined);
  if (!Array.isArray(policy.epochs) || policy.epochs.length === 0) throw new C2spTlogVerificationError('C2SP epoch policy requires at least one epoch');
  let reported: unknown;
  for (const epoch of policy.epochs) {
    if (!epochLogKeySigned(checkpoint, origin, epoch)) continue;
    try {
      return enforceSinglePolicy(checkpoint, origin, epoch.policy, scope, nowMs, maxClockSkewMs, maxCheckpointAgeMs, epoch);
    } catch (cause) {
      reported ??= cause;
    }
  }
  if (reported !== undefined) throw reported;
  throw new C2spTlogVerificationError('checkpoint missing accepted log signature: no trust epoch log key signed the checkpoint');
}

/** Reports whether the checkpoint carries a signature line under the epoch's log key name and key hash; the signature is verified later. */
function epochLogKeySigned(checkpoint: Checkpoint, origin: string, epoch: C2spTlogPolicyEpoch): boolean {
  const originPolicy = epoch.policy?.origins?.[origin];
  if (!originPolicy) return false;
  return originPolicy.logKeys.map(asKey).some(key => key.keyId !== undefined && checkpoint.signatures.some(sig =>
    sig.name === key.name && sig.keyHash !== undefined && Buffer.from(sig.keyHash).equals(Buffer.from(key.keyId!))));
}

/**
 * Signed-note verification under one epoch's keys (c2sp.org/signed-note):
 * the first signature line under each of the epoch's keys (name and key hash)
 * must verify, and later lines under the same key are ignored. Lines under
 * other keys, including other epochs' keys, are ignored.
 */
function assertEpochSignaturesValid(checkpoint: Checkpoint, keys: SignedNoteKey[]): void {
  if (checkpoint.signatures.length > MAX_CHECKPOINT_SIGNATURES) throw new C2spTlogVerificationError('checkpoint missing accepted log signature: too many signature lines');
  const seen = new Set<string>();
  for (const sig of checkpoint.signatures) {
    if (!sig.keyHash) continue;
    const id = `${sig.name}+${Buffer.from(sig.keyHash).toString('hex')}`;
    const key = keys.find(candidate => candidate.keyId !== undefined && `${candidate.name}+${Buffer.from(candidate.keyId).toString('hex')}` === id);
    if (!key || seen.has(id)) continue;
    seen.add(id);
    if (!verifyNoteSignature(checkpoint.signedText, sig, key)) {
      throw new C2spTlogVerificationError(`checkpoint missing accepted log signature: invalid signature by trusted key ${id}`);
    }
  }
}

function enforceSinglePolicy(
  checkpoint: Checkpoint,
  origin: string,
  policy: C2spTlogPolicy,
  scope: string,
  nowMs: number,
  maxClockSkewMs: number,
  maxCheckpointAgeMs: number | undefined,
  epoch: C2spTlogPolicyEpoch | undefined,
): CheckpointPolicyResult {
  const p = normalizedOriginPolicy(policy, origin);
  const acceptedLogKeys = scope === 'public' ? p.logKeys.filter((key) => key.signatureType?.[0] === 0x01) : p.logKeys;
  if (epoch) assertEpochSignaturesValid(checkpoint, [...p.logKeys, ...(policy.origins[origin]!.witnessKeys ?? []).map(asKey), ...p.witnessKeys]);
  if (!acceptedLogKeys.some((k) => verifyCheckpointSignature(checkpoint, k))) throw new C2spTlogVerificationError('checkpoint missing accepted log signature');
  if (epoch?.maxTreeSize !== undefined && checkpoint.treeSize > epoch.maxTreeSize) {
    throw new C2spTlogVerificationError(`checkpoint tree size ${checkpoint.treeSize} is above trust epoch ${JSON.stringify(epoch.id)} max_tree_size ${epoch.maxTreeSize}`);
  }
  if (epoch?.minTreeSize !== undefined && checkpoint.treeSize < epoch.minTreeSize) {
    throw new C2spTlogVerificationError(`checkpoint tree size ${checkpoint.treeSize} is below trust epoch ${JSON.stringify(epoch.id)} min_tree_size ${epoch.minTreeSize}`);
  }
  if (scope === 'public' && p.quorumRule.kind === 'none') throw new C2spTlogVerificationError('public C2SP policy requires a non-zero witness quorum');
  const acceptedWitnessTimestamps = evaluateQuorum(p.quorumRule, checkpoint, nowMs, maxClockSkewMs);
  if (!acceptedWitnessTimestamps) throw new C2spTlogVerificationError('checkpoint witness quorum not satisfied by valid timestamped cosignatures');
  const witnessSeconds = acceptedWitnessTimestamps.length > 0 ? Math.min(...acceptedWitnessTimestamps) : undefined;
  const checkpointWitnessTime = witnessSeconds === undefined ? undefined : new Date(witnessSeconds * 1000);
  if (maxCheckpointAgeMs !== undefined) {
    if (!checkpointWitnessTime) throw new C2spTlogVerificationError('C2SP checkpoint freshness requires an accepted timestamped witness quorum');
    if (nowMs - checkpointWitnessTime.getTime() > maxCheckpointAgeMs) throw new C2spTlogVerificationError('C2SP checkpoint is stale');
  }
  return { acceptedWitnessTimestamps, checkpointWitnessTime, trustEpoch: epoch?.id ?? '' };
}

/**
 * Parses a C2SP tlog-policy file (`log`, `witness`, `group`, and exactly one
 * `quorum` directive) into a {@link C2spTlogPolicy} keyed by log-key origin.
 * All configured logs share the declared witnesses and quorum rule.
 *
 * @throws C2spTlogVerificationError when a line is malformed, names collide,
 *   key types are unsupported, or the quorum directive is missing or repeated.
 */
export function parseC2spPolicyFile(text: string): C2spTlogPolicy {
  assertPolicyCharacters(text);
  const logs: SignedNoteKey[] = [];
  const witnesses = new Map<string, SignedNoteKey>();
  const rules = new Map<string, C2spTlogQuorumRule>();
  let quorumRule: C2spTlogQuorumRule | undefined;
  let quorumLines = 0;

  for (const [index, rawLine] of text.split('\n').entries()) {
    const line = rawLine.replace(/^[\t ]+|[\t ]+$/g, '');
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(/[\t ]+/);
    const directive = parts.shift();
    try {
      if (directive === 'log' && (parts.length === 1 || parts.length === 2)) {
        logs.push(parseSignedNoteVerifierKey(parts[0]!));
      } else if (directive === 'witness' && (parts.length === 2 || parts.length === 3)) {
        const name = parts[0]!;
        assertNewPolicyName(name, witnesses, rules);
        const key = parseSignedNoteVerifierKey(parts[1]!);
        witnesses.set(name, key);
        rules.set(name, { kind: 'witness', key });
      } else if (directive === 'group' && parts.length >= 3) {
        const name = parts.shift()!;
        assertNewPolicyName(name, witnesses, rules);
        const thresholdText = parts.shift()!;
        const memberNames = parts;
        if (new Set(memberNames).size !== memberNames.length) throw new Error('group members must be distinct');
        const members = memberNames.map((member) => {
          const rule = rules.get(member);
          if (!rule) throw new Error(`group references unknown preceding witness or group ${member}`);
          return rule;
        });
        const threshold = thresholdText === 'any' ? 1 : thresholdText === 'all' ? members.length : parseDecimalThreshold(thresholdText);
        if (threshold < 1 || threshold > members.length) throw new Error('invalid group threshold');
        rules.set(name, { kind: 'threshold', threshold, members });
      } else if (directive === 'quorum' && parts.length === 1) {
        quorumLines++;
        if (quorumLines > 1) throw new Error('policy must contain exactly one quorum directive');
        if (parts[0] === 'none') quorumRule = { kind: 'none' };
        else {
          quorumRule = rules.get(parts[0]!);
          if (!quorumRule) throw new Error(`quorum references unknown preceding witness or group ${parts[0]}`);
        }
      } else {
        throw new Error('unsupported directive or wrong number of fields');
      }
    } catch (cause) {
      throw new C2spTlogVerificationError(`invalid C2SP policy line ${index + 1}: ${(cause as Error).message}`);
    }
  }
  if (quorumLines !== 1 || !quorumRule) throw new C2spTlogVerificationError('C2SP policy requires exactly one quorum directive');
  if (logs.some(key => key.signatureType !== undefined && (key.signatureType.length !== 1 || key.signatureType[0] !== 0x01))) {
    throw new C2spTlogVerificationError('C2SP policy log keys must use the supported log signature type 0x01');
  }
  if ([...witnesses.values()].some(key => key.signatureType?.length !== 1 || key.signatureType[0] !== 0x04)) {
    throw new C2spTlogVerificationError('C2SP policy witness keys must use the supported cosignature type 0x04');
  }
  assertDistinctUnderlyingKeys(logs, 'C2SP policy logs');
  assertDistinctUnderlyingKeys([...witnesses.values()], 'C2SP policy witnesses');
  const logIdentities = new Set(logs.map(keyIdentity));
  if ([...witnesses.values()].some(key => logIdentities.has(keyIdentity(key)))) {
    throw new C2spTlogVerificationError('C2SP policy log and witness keys must use distinct underlying public keys');
  }

  const witnessKeys = [...witnesses.values()];
  const quorum = legacyQuorum(quorumRule);
  const origins: C2spTlogPolicy['origins'] = {};
  for (const log of logs) {
    const current = origins[log.name];
    if (current) current.logKeys.push(log);
    else origins[log.name] = { logKeys: [log], witnessKeys, quorum, quorumRule };
  }
  return { origins };
}

function asKey(k: SignedNoteKey | string): SignedNoteKey {
  return typeof k === 'string' ? parseSignedNoteVerifierKey(k) : k;
}

function normalizeQuorumRule(rule: C2spTlogQuorumRule): NormalizedQuorumRule {
  if (rule.kind === 'none') return rule;
  if (rule.kind === 'witness') return { kind: 'witness', key: asKey(rule.key) };
  if (!Number.isSafeInteger(rule.threshold) || rule.threshold < 1 || rule.threshold > rule.members.length) {
    throw new C2spTlogVerificationError('checkpoint quorum rule has an invalid threshold');
  }
  return { kind: 'threshold', threshold: rule.threshold, members: rule.members.map(normalizeQuorumRule) };
}

function flatQuorumRule(witnessKeys: SignedNoteKey[], quorum: number): C2spTlogQuorumRule {
  if (quorum === 0) return { kind: 'none' };
  return { kind: 'threshold', threshold: quorum, members: witnessKeys.map(key => ({ kind: 'witness', key })) };
}

function collectWitnessKeys(rule: NormalizedQuorumRule): SignedNoteKey[] {
  if (rule.kind === 'none') return [];
  if (rule.kind === 'witness') return [rule.key];
  return rule.members.flatMap(collectWitnessKeys);
}

/** Returns the witness timestamps satisfying `rule` against the checkpoint's cosignatures, or undefined when unsatisfied. */
function evaluateQuorum(rule: NormalizedQuorumRule, checkpoint: Checkpoint, nowMs: number, maxClockSkewMs: number): number[] | undefined {
  if (rule.kind === 'none') return [];
  if (rule.kind === 'witness') {
    const timestamp = verifiedCosignatureTimestamp(checkpoint, rule.key);
    return timestamp !== undefined && timestamp * 1000 <= nowMs + maxClockSkewMs ? [timestamp] : undefined;
  }
  const satisfied = rule.members
    .map(member => evaluateQuorum(member, checkpoint, nowMs, maxClockSkewMs))
    .filter((value): value is number[] => value !== undefined)
    .sort((a, b) => Math.min(...b) - Math.min(...a));
  if (satisfied.length < rule.threshold) return undefined;
  return satisfied.slice(0, rule.threshold).flat();
}

function assertDistinctUnderlyingKeys(keys: SignedNoteKey[], label: string): void {
  const identities = keys.map(keyIdentity);
  if (new Set(identities).size !== identities.length) throw new C2spTlogVerificationError(`${label} must be distinct by underlying public key`);
}

function keyIdentity(key: SignedNoteKey): string {
  return `${key.kind}\0${Buffer.from(key.keyBytes).toString('hex')}`;
}

function assertPolicyCharacters(text: string): void {
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (code === 0x09 || code === 0x0a || code >= 0x20) continue;
    throw new C2spTlogVerificationError(`invalid C2SP policy character at offset ${index}`);
  }
}

function assertNewPolicyName(name: string, witnesses: Map<string, SignedNoteKey>, rules: Map<string, C2spTlogQuorumRule>): void {
  if (name === 'none') throw new Error('none is a reserved policy name');
  if (witnesses.has(name) || rules.has(name)) throw new Error(`duplicate policy name ${name}`);
}

function parseDecimalThreshold(value: string): number {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) throw new Error('invalid group threshold');
  const threshold = Number(value);
  if (!Number.isSafeInteger(threshold)) throw new Error('invalid group threshold');
  return threshold;
}

function legacyQuorum(rule: C2spTlogQuorumRule): number | undefined {
  if (rule.kind === 'none') return 0;
  if (rule.kind === 'witness') return 1;
  return rule.members.every(member => member.kind === 'witness') ? rule.threshold : undefined;
}

function topLevelThreshold(rule: NormalizedQuorumRule): number {
  if (rule.kind === 'none') return 0;
  if (rule.kind === 'witness') return 1;
  return rule.threshold;
}
