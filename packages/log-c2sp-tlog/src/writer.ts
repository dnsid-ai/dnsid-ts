import {
  fromBase64Url,
  jwkThumbprint,
  toBase64Url,
  verifyWithKey,
  type DnsIdJWK,
  type KeyProvider,
  type LogEvent,
  type LogRef,
  normalizeFQDN,
} from '@dnsid-ai/protocol';
import {
  canonicalizeUnknownC2spEnvelope,
  c2spEventId,
  assertSupportedLifecycleJwk,
  eventToC2spEnvelope,
  parseC2spEventEntry,
  parseC2spSignatures,
  requiredC2spSignatureNames,
  type C2spJsonEvent,
  type C2spSignatureValue,
  type C2spSignatures,
} from './event-codec.ts';
import { assertCanonicalJsonBytes, canonicalBytes, parseJsonNoDuplicateMembers } from './canonical.ts';
import { C2spTlogParseError, C2spTlogVerificationError, c2spLogError } from './errors.ts';
import { parseC2spTlogLr, type ParsedC2spTlogLr } from './lr.ts';

/** Role a signature is produced under when signing a prepared lifecycle event. */
export type C2spSignerRole = 'Entity' | 'OperationalCountersignature' | 'PreviousOperational' | 'NewOperational';

/** Chain metadata linking a public non-genesis event to its predecessor in the stream. */
export interface C2spChain {
  sequence: number;
  previousEventId?: string;
  previousStateHash?: string;
}

/** Immutable lifecycle event staged for signing and append: envelope, signed bytes, and the roles still required. */
export interface PreparedC2spTlogEvent {
  readonly reference: ParsedC2spTlogLr;
  readonly envelope: Readonly<C2spJsonEvent>;
  readonly signedBytes: Uint8Array;
  readonly eventId: string;
  readonly requiredSignatures: readonly C2spSignerRole[];
}

/** Trusted expectations a prepared event (and its existing signatures) is validated against. */
export interface PreparedC2spVerificationContext {
  /** Locally expected DNS identity. Required when countersigning or serializing ISSUANCE. */
  expectedFqdn?: string;
  /** Locally expected governance identifier. Required when countersigning or serializing ISSUANCE. */
  expectedGovernanceId?: string;
  /** Trusted accountable-entity key. Required when countersigning or serializing ISSUANCE. */
  entityKey?: DnsIdJWK;
  /** Trusted initial operational key. Required when countersigning or serializing ISSUANCE. */
  operationalKey?: DnsIdJWK;
  previousOperationalKey?: DnsIdJWK;
}

/** Options for {@link signPreparedC2spTlogEvent}. */
export interface SignPreparedC2spOptions extends PreparedC2spVerificationContext {
  /** Allow overwriting an existing signature for the same role. */
  replaceExisting?: boolean;
}

/** Options for {@link writePreparedEvent}; `submit` performs the deployment-specific append. */
export interface C2spTlogAppendOptions extends PreparedC2spVerificationContext {
  /** Appends the finished entry bytes to the log and returns its assigned index. */
  submit: (entryBytes: Uint8Array, idempotencyKey?: string) => Promise<{ index: number }>;
  idempotencyKey?: string;
  /** Required for non-genesis public events to validate authoritative prior stream state. */
  validateChain?: (prepared: PreparedC2spTlogEvent) => Promise<void>;
}

const ROLE_TO_SIGNATURE: Record<C2spSignerRole, keyof C2spSignatures> = {
  Entity: 'ae',
  OperationalCountersignature: 'op',
  PreviousOperational: 'prev_op',
  NewOperational: 'new_op',
};

const SIGNATURE_TO_ROLE: Record<keyof C2spSignatures, C2spSignerRole> = {
  ae: 'Entity',
  op: 'OperationalCountersignature',
  prev_op: 'PreviousOperational',
  new_op: 'NewOperational',
};

/**
 * Stages a lifecycle event for signing against a bound (index-free) log
 * reference, deriving genesis chain metadata for public ISSUANCE and inbound
 * MIGRATION events.
 *
 * @throws C2spTlogParseError when the reference, event, or chain metadata is invalid.
 */
export function prepareC2spTlogEventForSigning(event: LogEvent, lr: string, chain?: C2spChain): PreparedC2spTlogEvent {
  const reference = boundReference(lr);
  const normalizedChain = prepareChain(event, reference, chain);
  const envelope = eventToC2spEnvelope(event, {
    scope: reference.scope,
    logOrigin: reference.origin,
    streamId: reference.streamId,
    lr: reference.lr,
    seq: normalizedChain?.sequence,
    prevEventId: normalizedChain?.previousEventId,
    prevStateHash: normalizedChain?.previousStateHash,
  }, false);
  return makePrepared(reference, assertPreparedEnvelope(envelope, reference));
}

/**
 * Reconstructs a prepared event from canonical envelope bytes (for example
 * received from another signer), verifying canonical form, the log binding,
 * ISSUANCE expectations, and every signature already present.
 *
 * @throws C2spTlogParseError when the bytes or envelope are malformed.
 * @throws C2spTlogVerificationError when expectations or existing signatures fail.
 */
export async function parsePreparedC2spTlogEvent(
  bytes: Uint8Array,
  lr: string,
  context: PreparedC2spVerificationContext = {},
): Promise<PreparedC2spTlogEvent> {
  assertEntrySize(bytes);
  const parsed = parseJsonNoDuplicateMembers(bytes);
  assertCanonicalJsonBytes(bytes, parsed);
  const envelope = assertPreparedEnvelope(parsed, boundReference(lr));
  const prepared = makePrepared(boundReference(lr), envelope);
  await assertIssuanceExpectations(prepared, context, false);
  await verifyExistingSignatures(prepared, context);
  return prepared;
}

/**
 * Adds one role's signature to a prepared event using the key provider,
 * verifying the provider key matches the key the envelope requires for that
 * role and that existing signatures remain valid.
 *
 * @returns A new prepared event carrying the added signature.
 * @throws C2spTlogVerificationError when the role is not required, already
 *   signed (without `replaceExisting`), or key/signature checks fail.
 */
export async function signPreparedC2spTlogEvent(
  prepared: PreparedC2spTlogEvent,
  role: C2spSignerRole,
  keyProvider: KeyProvider,
  options: SignPreparedC2spOptions = {},
): Promise<PreparedC2spTlogEvent> {
  assertPreparedIntegrity(prepared);
  if (!prepared.requiredSignatures.includes(role)) {
    throw new C2spTlogVerificationError(`${role} is not required for ${String(prepared.envelope.type)}`);
  }
  await assertIssuanceExpectations(
    prepared,
    options,
    role === 'Entity' || role === 'OperationalCountersignature',
  );
  await verifyExistingSignatures(prepared, options);
  const signatureName = ROLE_TO_SIGNATURE[role];
  const signatures = parseC2spSignatures(prepared.envelope.sigs, String(prepared.envelope.type), false);
  if (signatures[signatureName] && !options.replaceExisting) {
    throw new C2spTlogVerificationError(`prepared event already has a ${role} signature`);
  }
  const expectedKey = await keyForRole(prepared, role, options);
  const providerKey = await keyProvider.jwk(expectedKey.kid);
  await assertSameKey(providerKey, expectedKey, role);
  const signature = await keyProvider.signKey(expectedKey.kid, prepared.signedBytes);
  const nextSignatures = { ...signatures, [signatureName]: { kid: expectedKey.kid, sig: toBase64Url(signature) } };
  return makePrepared(prepared.reference, { ...prepared.envelope, sigs: nextSignatures });
}

/**
 * Finalizes a fully signed prepared event into its canonical log entry bytes,
 * re-verifying all required signatures and the entry's parseability.
 *
 * @throws C2spTlogVerificationError when a required signature is missing or invalid.
 * @throws C2spTlogParseError when the entry is malformed or oversized.
 */
export async function c2spTlogEntryBytes(
  prepared: PreparedC2spTlogEvent,
  context: PreparedC2spVerificationContext = {},
): Promise<Uint8Array> {
  assertPreparedIntegrity(prepared);
  await assertIssuanceExpectations(prepared, context, true);
  const signatures = parseC2spSignatures(prepared.envelope.sigs, String(prepared.envelope.type), true);
  for (const role of prepared.requiredSignatures) {
    if (!signatures[ROLE_TO_SIGNATURE[role]]) throw new C2spTlogVerificationError(`missing required ${role} signature`);
  }
  await verifyExistingSignatures(prepared, context);
  const bytes = canonicalBytes(prepared.envelope);
  assertEntrySize(bytes);
  await parseC2spEventEntry(bytes, {
    scope: prepared.reference.scope,
    logOrigin: prepared.reference.origin,
    streamId: prepared.reference.streamId,
    lr: prepared.reference.lr,
  });
  return bytes;
}

/**
 * Appends a finalized prepared event to the log via `options.submit`, running
 * the required chain validation for public non-genesis events.
 *
 * @returns The event's log reference (`<lr>@<index>`).
 * @throws C2spTlogVerificationError when finalization, chain validation, or the
 *   returned index is invalid.
 */
export async function writePreparedEvent(prepared: PreparedC2spTlogEvent, options: C2spTlogAppendOptions): Promise<LogRef> {
  const entryBytes = await c2spTlogEntryBytes(prepared, options);
  const sequence = prepared.envelope.seq;
  if (sequence !== 0) {
    if (!options.validateChain) throw new C2spTlogVerificationError('public non-genesis append requires authoritative chain validation');
    try {
      await options.validateChain(prepared);
    } catch (cause) {
      throw c2spLogError('C2SP authoritative chain validation failed', cause, false);
    }
  }
  let result: { index: number };
  try {
    result = await options.submit(entryBytes, options.idempotencyKey);
  } catch (cause) {
    const transient = !isTerminalSubmissionFailure(cause);
    throw c2spLogError(
      transient
        ? 'C2SP append is unavailable; retry exact bytes with the same idempotency key'
        : 'C2SP append was rejected terminally',
      cause,
      transient,
    );
  }
  if (!Number.isSafeInteger(result.index) || result.index < 0) throw new C2spTlogVerificationError('append returned an invalid entry index');
  return `${prepared.reference.lr}@${result.index}`;
}

function isTerminalSubmissionFailure(cause: unknown): boolean {
  if (!cause || typeof cause !== 'object') return false;
  if ('retryWithSameBytes' in cause && (cause as { retryWithSameBytes?: unknown }).retryWithSameBytes === false) return true;
  if ('retryable' in cause && (cause as { retryable?: unknown }).retryable === false) return true;
  return 'state' in cause && (cause as { state?: unknown }).state === 'rejected';
}

function makePrepared(reference: ParsedC2spTlogLr, envelope: C2spJsonEvent): PreparedC2spTlogEvent {
  const type = String(envelope.type);
  parseC2spSignatures(envelope.sigs, type, false);
  const signedBytes = canonicalizeUnknownC2spEnvelope(envelope, false);
  const requiredSignatures = Object.freeze(requiredC2spSignatureNames(type).map(name => SIGNATURE_TO_ROLE[name]));
  return Object.freeze({
    reference: Object.freeze({ ...reference }),
    envelope: deepFreeze(structuredClone(envelope)),
    signedBytes,
    eventId: c2spEventId(signedBytes),
    requiredSignatures,
  });
}

function assertPreparedEnvelope(value: unknown, reference: ParsedC2spTlogLr): C2spJsonEvent {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new C2spTlogParseError('prepared C2SP event must be an object');
  const envelope = value as C2spJsonEvent;
  if (envelope.v !== 1 || envelope.kind !== 'dnsid.lifecycle') throw new C2spTlogParseError('unsupported C2SP event envelope');
  if (typeof envelope.type !== 'string') throw new C2spTlogParseError('prepared C2SP event missing type');
  requiredC2spSignatureNames(envelope.type);
  if (typeof envelope.fqdn !== 'string' || !envelope.fqdn) throw new C2spTlogParseError('prepared C2SP event missing fqdn');
  let normalizedFqdn: string;
  try {
    normalizedFqdn = normalizeFQDN(envelope.fqdn, true);
  } catch {
    throw new C2spTlogParseError('prepared C2SP event has invalid fqdn');
  }
  if (reference.streamId === normalizedFqdn) {
    throw new C2spTlogParseError('new C2SP streams must use an opaque stream ID distinct from the event fqdn');
  }
  if (!Number.isSafeInteger(envelope.ts) || (envelope.ts as number) < 0) throw new C2spTlogParseError('prepared C2SP event has invalid ts');
  {
    const expected = { method: 'c2sp-tlog', log_origin: reference.origin, stream_id: reference.streamId, lr: reference.lr };
    for (const [name, expectedValue] of Object.entries(expected)) {
      if (envelope[name] !== expectedValue) throw new C2spTlogParseError(`public C2SP event ${name} mismatch`);
    }
  }
  {
    assertPublicChainShape(envelope);
    if (envelope.seq === 0 && envelope.type !== 'ISSUANCE' && envelope.type !== 'MIGRATION') {
      throw new C2spTlogParseError('public seq=0 event must be ISSUANCE or inbound MIGRATION');
    }
  }
  if (envelope.type === 'MIGRATION') {
    if (envelope.new_lr !== reference.lr) throw new C2spTlogParseError('inbound MIGRATION new_lr must match the bound reference');
    if (envelope.prev_lr === envelope.new_lr) throw new C2spTlogParseError('inbound MIGRATION prev_lr must differ from new_lr');
    if (envelope.seq !== 0) throw new C2spTlogParseError('inbound MIGRATION must be public stream genesis');
  }
  parseC2spSignatures(envelope.sigs, envelope.type, false);
  return envelope;
}

function prepareChain(event: LogEvent, reference: ParsedC2spTlogLr, chain?: C2spChain): C2spChain | undefined {
  if (event.type === 'MIGRATION') {
    if (event.newLog !== reference.lr) throw new C2spTlogParseError('inbound MIGRATION new_lr must match the bound reference');
    if (event.previousLog === event.newLog) throw new C2spTlogParseError('inbound MIGRATION prev_lr must differ from new_lr');
    if (chain && (chain.sequence !== 0 || chain.previousEventId !== undefined || chain.previousStateHash !== undefined)) {
      throw new C2spTlogParseError('public inbound MIGRATION must be an unchained seq=0 event');
    }
    return { sequence: 0 };
  }
  if (event.type === 'ISSUANCE') {
    if (chain && (chain.sequence !== 0 || chain.previousEventId !== undefined || chain.previousStateHash !== undefined)) {
      throw new C2spTlogParseError('public ISSUANCE must be an unchained seq=0 event');
    }
    return { sequence: 0 };
  }
  if (!chain) throw new C2spTlogParseError('public non-genesis event requires prepared chain metadata');
  return chain;
}

function assertPublicChainShape(envelope: C2spJsonEvent): void {
  if (!Number.isSafeInteger(envelope.seq) || (envelope.seq as number) < 0) throw new C2spTlogParseError('public C2SP event has invalid seq');
  if (['prev_index', 'prev_leaf_hash', 'event_id'].some(name => name in envelope)) throw new C2spTlogParseError('prohibited C2SP chain field');
  const priorNames = ['prev_event_id', 'prev_state_hash'];
  if (envelope.seq === 0) {
    if (priorNames.some(name => envelope[name] !== undefined)) throw new C2spTlogParseError('public seq=0 event must not contain previous-chain fields');
    return;
  }
  for (const name of ['prev_event_id', 'prev_state_hash']) {
    if (typeof envelope[name] !== 'string' || !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(envelope[name] as string)) throw new C2spTlogParseError(`public C2SP event missing ${name}`);
  }
}

async function verifyExistingSignatures(prepared: PreparedC2spTlogEvent, context: PreparedC2spVerificationContext): Promise<void> {
  const signatures = parseC2spSignatures(prepared.envelope.sigs, String(prepared.envelope.type), false);
  for (const [name, signature] of Object.entries(signatures) as Array<[keyof C2spSignatures, C2spSignatureValue | undefined]>) {
    if (!signature) continue;
    const role = SIGNATURE_TO_ROLE[name];
    const key = await keyForRole(prepared, role, context);
    if (signature.kid !== key.kid) throw new C2spTlogVerificationError(`${role} signature kid does not match the required key`);
    if (!await verifyWithKey(prepared.signedBytes, fromBase64Url(signature.sig), key)) {
      throw new C2spTlogVerificationError(`invalid existing ${role} signature`);
    }
  }
}

async function keyForRole(prepared: PreparedC2spTlogEvent, role: C2spSignerRole, context: PreparedC2spVerificationContext): Promise<DnsIdJWK> {
  const envelope = prepared.envelope;
  if (role === 'Entity') {
    if (envelope.type === 'ISSUANCE') {
      const embedded = asJwk(envelope.ek, 'ek');
      if (context.entityKey) {
        await assertExpectedKey(embedded, context.entityKey, 'entity key');
        return context.entityKey;
      }
      return embedded;
    }
    if (context.entityKey) return context.entityKey;
    throw new C2spTlogVerificationError('Entity signing requires a trusted entity key');
  }
  if (role === 'OperationalCountersignature') {
    const embedded = asJwk(envelope.ku, 'ku');
    if (context.operationalKey) {
      await assertExpectedKey(embedded, context.operationalKey, 'operational key');
      return context.operationalKey;
    }
    return embedded;
  }
  if (role === 'NewOperational') return asJwk(envelope.new_ku, 'new_ku');
  if (context.previousOperationalKey) return context.previousOperationalKey;
  throw new C2spTlogVerificationError('PreviousOperational signing requires the trusted previous operational key');
}

async function assertIssuanceExpectations(
  prepared: PreparedC2spTlogEvent,
  context: PreparedC2spVerificationContext,
  requireComplete: boolean,
): Promise<void> {
  if (prepared.envelope.type !== 'ISSUANCE') return;
  const embeddedEntityKey = asJwk(prepared.envelope.ek, 'ek');
  const embeddedOperationalKey = asJwk(prepared.envelope.ku, 'ku');
  if (await jwkThumbprint(embeddedEntityKey) === await jwkThumbprint(embeddedOperationalKey)) {
    throw new C2spTlogVerificationError('ISSUANCE entity and operational keys must be distinct');
  }
  const missing = [
    context.expectedFqdn === undefined ? 'expectedFqdn' : undefined,
    context.expectedGovernanceId === undefined ? 'expectedGovernanceId' : undefined,
    context.entityKey === undefined ? 'entityKey' : undefined,
    context.operationalKey === undefined ? 'operationalKey' : undefined,
  ].filter((name): name is string => name !== undefined);
  if (requireComplete && missing.length > 0) {
    throw new C2spTlogVerificationError(`ISSUANCE verification requires trusted ${missing.join(', ')}`);
  }
  if (context.expectedFqdn !== undefined && prepared.envelope.fqdn !== context.expectedFqdn) {
    throw new C2spTlogVerificationError('ISSUANCE fqdn does not match the expected identity');
  }
  if (context.expectedGovernanceId !== undefined && prepared.envelope.gi !== context.expectedGovernanceId) {
    throw new C2spTlogVerificationError('ISSUANCE gi does not match the expected governance ID');
  }
  if (context.entityKey) await assertExpectedKey(embeddedEntityKey, context.entityKey, 'entity key');
  if (context.operationalKey) await assertExpectedKey(embeddedOperationalKey, context.operationalKey, 'operational key');
}

async function assertExpectedKey(actual: DnsIdJWK, expected: DnsIdJWK, name: string): Promise<void> {
  if (actual.kid !== expected.kid || actual.alg !== expected.alg || await jwkThumbprint(actual) !== await jwkThumbprint(expected)) {
    throw new C2spTlogVerificationError(`ISSUANCE ${name} does not match the trusted key`);
  }
}

async function assertSameKey(actual: DnsIdJWK, expected: DnsIdJWK, role: C2spSignerRole): Promise<void> {
  if (actual.kid !== expected.kid || actual.alg !== expected.alg || await jwkThumbprint(actual) !== await jwkThumbprint(expected)) {
    throw new C2spTlogVerificationError(`${role} key provider does not match the prepared event`);
  }
}

function asJwk(value: unknown, name: string): DnsIdJWK {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new C2spTlogParseError(`prepared C2SP event missing ${name}`);
  const key = value as Record<string, unknown>;
  if (typeof key.kty !== 'string' || typeof key.kid !== 'string' || !key.kid || typeof key.alg !== 'string' || !key.alg) {
    throw new C2spTlogParseError(`prepared C2SP event has malformed ${name}`);
  }
  return assertSupportedLifecycleJwk(key as DnsIdJWK, name);
}

function boundReference(lr: string): ParsedC2spTlogLr {
  const parsed = parseC2spTlogLr(lr);
  if (parsed.entryIndex !== undefined) throw new C2spTlogParseError('prepared events require a bound reference without @index');
  return parsed;
}

function assertPreparedIntegrity(prepared: PreparedC2spTlogEvent): void {
  const expected = canonicalizeUnknownC2spEnvelope(prepared.envelope as C2spJsonEvent, false);
  if (prepared.eventId !== c2spEventId(expected) || !bytesEqual(expected, prepared.signedBytes)) throw new C2spTlogVerificationError('prepared signed bytes do not match the envelope');
  assertPreparedEnvelope(prepared.envelope, prepared.reference);
}

function assertEntrySize(bytes: Uint8Array): void {
  if (bytes.length === 0 || bytes.length > 0xffff) throw new C2spTlogParseError('C2SP entry must be between 1 and 65535 bytes');
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}
