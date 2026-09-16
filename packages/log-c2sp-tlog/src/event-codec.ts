import { sha256Bytes, normalizeFQDN, jwkThumbprint, type C2spIssuanceEvent, type DnsIdJWK, type LogEvent } from '@dnsid-ai/protocol';
import { canonicalBytes, canonicalJson, parseJsonNoDuplicateMembers, assertCanonicalJsonBytes } from './canonical.ts';
import { C2spTlogParseError } from './errors.ts';

import { b64url } from './base64.ts';

/** Logical ID of canonical signed bytes; signatures and Merkle indexes are excluded. */
export function c2spEventId(signedBytes: Uint8Array): string {
  return b64url(sha256Bytes.create().update(new TextEncoder().encode('dnsid-c2sp-event-v1\0')).update(signedBytes).digest());
}

const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const MAX_ENTRY_BYTES = 0xffff;
const SUPPORTED = new Set(['ISSUANCE', 'KEY_ROTATION', 'REVOCATION', 'RETIREMENT', 'MIGRATION', 'DELEGATION']);
const SIGNATURE_RE = /^[A-Za-z0-9_-]+$/;

/** Log binding and chaining context stamped into (and expected of) a c2sp-tlog event envelope. */
export interface C2spEventContext { scope?: string; logOrigin?: string; streamId?: string; lr?: string; seq?: number; prevEventId?: string; prevStateHash?: string }
/** Raw JSON envelope of a DNSid lifecycle event as stored in a c2sp-tlog entry. */
export type C2spJsonEvent = Record<string, unknown>;
/** One envelope signature: signing key ID and unpadded base64url signature. */
export interface C2spSignatureValue { kid: string; sig: string }
/** Envelope `sigs` object keyed by signer role: accountable entity, operational countersignature, previous/new operational key. */
export interface C2spSignatures { ae?: C2spSignatureValue; op?: C2spSignatureValue; prev_op?: C2spSignatureValue; new_op?: C2spSignatureValue }

/**
 * Converts a protocol {@link LogEvent} into its c2sp-tlog JSON envelope
 * (`v: 1`, `kind: 'dnsid.lifecycle'`) with per-type payload fields, the log
 * binding from `context`, and optionally the event's existing signatures.
 *
 * @throws C2spTlogParseError for unsupported event types, malformed lifecycle
 *   keys, or missing public-scope binding fields.
 */
export function eventToC2spEnvelope(event: LogEvent, context: C2spEventContext = {}, includeSigs = true): C2spJsonEvent {
  const obj: C2spJsonEvent = {
    v: 1,
    kind: 'dnsid.lifecycle',
    type: event.type,
    fqdn: event.domain,
    ts: epochSeconds(event.timestamp, 'timestamp'),
  };
  switch (event.type) {
    case 'ISSUANCE': {
      const issuance = requireC2spIssuanceEvent(event);
      assertSupportedLifecycleJwk(issuance.initialEntityPublicKey, 'ek');
      assertSupportedLifecycleJwk(issuance.initialOperationalPublicKey, 'ku');
      if (issuance.initialEntityAlg !== issuance.initialEntityPublicKey.alg
        || issuance.initialOperationalAlg !== issuance.initialOperationalPublicKey.alg) {
        throw new C2spTlogParseError('ISSUANCE lifecycle-key algorithm metadata mismatch');
      }
      if (lifecycleJwksShareKeyMaterial(issuance.initialEntityPublicKey, issuance.initialOperationalPublicKey)) {
        throw new C2spTlogParseError('ISSUANCE entity and operational keys must be distinct');
      }
      Object.assign(obj, { gi: issuance.governanceId, ek: issuance.initialEntityPublicKey, ku: issuance.initialOperationalPublicKey });
      break;
    }
    case 'KEY_ROTATION':
      assertSupportedLifecycleJwk(event.newOperationalPublicKey, 'new_ku');
      if (event.newOperationalAlg !== event.newOperationalPublicKey.alg) {
        throw new C2spTlogParseError('KEY_ROTATION lifecycle-key algorithm metadata mismatch');
      }
      Object.assign(obj, { prev_thumb: event.previousOperationalThumbprint, new_ku: event.newOperationalPublicKey, new_thumb: event.newOperationalThumbprint });
      break;
    case 'REVOCATION': obj.reason = event.reason; break;
    case 'RETIREMENT': break;
    case 'MIGRATION': Object.assign(obj, { prev_lr: event.previousLog, new_lr: event.newLog, prev_ref: event.finalEntryRef }); break;
    case 'DELEGATION': Object.assign(obj, { delegatee: event.delegatee, scope: event.scope, expiry: epochSeconds(event.expiry, 'expiry') }); break;
  }
  if (context.scope === 'public' || context.logOrigin || context.streamId || context.lr) {
    obj.method = 'c2sp-tlog';
    if (context.logOrigin) obj.log_origin = context.logOrigin;
    if (context.streamId) obj.stream_id = context.streamId;
    if (context.lr) obj.lr = context.lr;
  }
  if (context.seq !== undefined) obj.seq = context.seq;
  if (context.prevEventId !== undefined) obj.prev_event_id = context.prevEventId;
  if (context.prevStateHash) obj.prev_state_hash = context.prevStateHash;
  validatePublicFields(obj, context);
  if (includeSigs) {
    const sigs = signaturesFromEvent(event);
    if (Object.keys(sigs).length > 0) obj.sigs = sigs;
  }
  return obj;
}

/**
 * Converts a parsed c2sp-tlog JSON envelope back into a protocol
 * {@link LogEvent}, requiring a complete `sigs` object and consistent embedded
 * key material (distinct entity/operational keys, matching signature kids).
 *
 * @throws C2spTlogParseError when the envelope is malformed or inconsistent.
 */
export async function c2spEnvelopeToEvent(obj: unknown): Promise<LogEvent> {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new C2spTlogParseError('C2SP event entry must be an object');
  const e = obj as C2spJsonEvent;
  if (e.v !== 1 || e.kind !== 'dnsid.lifecycle') throw new C2spTlogParseError('unsupported C2SP event envelope');
  if (e.method !== undefined && e.method !== 'c2sp-tlog') throw new C2spTlogParseError('C2SP event method mismatch');
  const type = asString(e.type, 'type');
  if (!SUPPORTED.has(type)) throw new C2spTlogParseError(`unsupported DNSid lifecycle event type: ${type}`);
  const timestamp = dateFromSeconds(asSafeInt(e.ts, 'ts'), 'ts');
  const domain = asString(e.fqdn, 'fqdn');
  const sigs = parseC2spSignatures(e.sigs, type, true);
  const chain = parseChainFields(e);

  switch (type) {
    case 'ISSUANCE': {
      const entityKey = asJwk(e.ek, 'ek');
      const operationalKey = asJwk(e.ku, 'ku');
      const entityThumbprint = await jwkThumbprint(entityKey);
      const operationalThumbprint = await jwkThumbprint(operationalKey);
      if (entityThumbprint === operationalThumbprint) throw new C2spTlogParseError('ISSUANCE entity and operational keys must be distinct');
      if (sigs.ae!.kid !== entityKey.kid || sigs.op!.kid !== operationalKey.kid) throw new C2spTlogParseError('ISSUANCE signature kid does not match recorded key');
      return {
        type, domain, governanceId: asString(e.gi, 'gi'), timestamp,
        initialEntityKid: entityKey.kid, initialEntityAlg: asString(entityKey.alg, 'ek.alg'), initialEntityPublicKey: entityKey, initialEntityThumbprint: entityThumbprint,
        initialOperationalKid: operationalKey.kid, initialOperationalAlg: asString(operationalKey.alg, 'ku.alg'), initialOperationalPublicKey: operationalKey, initialOperationalThumbprint: operationalThumbprint,
        signingKid: sigs.ae!.kid, sig: sigs.ae!.sig, operationalCountersig: sigs.op!.sig,
        ...chain,
      } as LogEvent;
    }
    case 'KEY_ROTATION': {
      const newKey = asJwk(e.new_ku, 'new_ku');
      if (sigs.new_op!.kid !== newKey.kid) throw new C2spTlogParseError('KEY_ROTATION new_op kid does not match new_ku');
      return {
        type, domain, timestamp,
        previousOperationalKid: sigs.prev_op!.kid,
        previousOperationalThumbprint: asString(e.prev_thumb, 'prev_thumb'),
        newOperationalKid: newKey.kid,
        newOperationalAlg: asString(newKey.alg, 'new_ku.alg'),
        newOperationalPublicKey: newKey,
        newOperationalThumbprint: asString(e.new_thumb, 'new_thumb'),
        signingKid: sigs.prev_op!.kid, sig: sigs.prev_op!.sig, newOperationalProof: sigs.new_op!.sig,
        ...chain,
      } as LogEvent;
    }
    case 'REVOCATION':
      return { type, domain, timestamp, reason: asRevocationReason(e.reason), signingKid: sigs.ae!.kid, sig: sigs.ae!.sig, ...chain } as LogEvent;
    case 'RETIREMENT':
      return { type, domain, timestamp, signingKid: sigs.ae!.kid, sig: sigs.ae!.sig, ...chain } as LogEvent;
    case 'MIGRATION':
      return { type, domain, timestamp, previousLog: asString(e.prev_lr, 'prev_lr'), newLog: asString(e.new_lr, 'new_lr'), finalEntryRef: asString(e.prev_ref, 'prev_ref'), signingKid: sigs.ae!.kid, sig: sigs.ae!.sig, ...chain } as LogEvent;
    case 'DELEGATION':
      return { type, domain, timestamp, delegatee: asString(e.delegatee, 'delegatee'), scope: asString(e.scope, 'scope'), expiry: dateFromSeconds(asSafeInt(e.expiry, 'expiry'), 'expiry'), signingKid: sigs.ae!.kid, sig: sigs.ae!.sig, ...chain } as LogEvent;
    default: throw new C2spTlogParseError(`unsupported DNSid lifecycle event type: ${type}`);
  }
}

/**
 * Parses a raw c2sp-tlog log entry (canonical JSON bytes, 1..65535 bytes) into
 * a {@link LogEvent}, verifying the bytes are canonical and, for public scope,
 * that the signed log binding matches `context`.
 *
 * @throws C2spTlogParseError when the entry is oversized, non-canonical, or malformed.
 */
export async function parseC2spEventEntry(bytes: Uint8Array, context: C2spEventContext = {}): Promise<LogEvent> {
  assertEntrySize(bytes);
  const obj = parseJsonNoDuplicateMembers(bytes);
  assertCanonicalJsonBytes(bytes, obj);
  validatePublicFields(obj, context);
  return c2spEnvelopeToEvent(obj);
}

/**
 * Extracts the authorizing signature of a stored entry: the accountable-entity
 * signature (`sigs.ae`), or the previous operational key's signature
 * (`sigs.prev_op`) for `KEY_ROTATION` events.
 *
 * @returns The event type, agent FQDN, signing key id, and signature value.
 * @throws C2spTlogParseError when the entry is oversized, non-canonical, an
 *   unsupported envelope, or missing the required signature.
 */
export function parseC2spAuthorization(bytes: Uint8Array, context: C2spEventContext = {}): {
  type: LogEvent['type']; domain: string; kid: string; signature: string;
} {
  assertEntrySize(bytes);
  const obj = parseJsonNoDuplicateMembers(bytes);
  assertCanonicalJsonBytes(bytes, obj);
  validatePublicFields(obj, context);
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new C2spTlogParseError('C2SP event entry must be an object');
  const event = obj as C2spJsonEvent;
  if (event.v !== 1 || event.kind !== 'dnsid.lifecycle') throw new C2spTlogParseError('unsupported C2SP event envelope');
  const type = asString(event.type, 'type');
  if (!SUPPORTED.has(type)) throw new C2spTlogParseError(`unsupported DNSid lifecycle event type: ${type}`);
  if (!event.sigs || typeof event.sigs !== 'object' || Array.isArray(event.sigs)) throw new C2spTlogParseError('C2SP event missing sigs object');
  const role = type === 'KEY_ROTATION' ? 'prev_op' : 'ae';
  const signature = parseSignatureValue((event.sigs as Record<string, unknown>)[role], `sigs.${role}`);
  return { type: type as LogEvent['type'], domain: asString(event.fqdn, 'fqdn'), kid: signature.kid, signature: signature.sig };
}

/**
 * Extracts the signed byte string of a stored entry: the canonical envelope
 * with the `sigs` member removed. These are the bytes each lifecycle signature
 * covers.
 *
 * @throws C2spTlogParseError when the entry is oversized or non-canonical.
 */
export function signedC2spEntryBytes(bytes: Uint8Array): Uint8Array {
  assertEntrySize(bytes);
  const obj = parseJsonNoDuplicateMembers(bytes);
  assertCanonicalJsonBytes(bytes, obj);
  return canonicalizeUnknownC2spEnvelope(obj as C2spJsonEvent, false);
}

/**
 * Serializes a fully signed event to its canonical c2sp-tlog entry bytes,
 * requiring every signature the event type demands.
 *
 * @throws C2spTlogParseError when signatures are incomplete or the entry is oversized.
 */
export function canonicalizeC2spEvent(event: LogEvent, context: C2spEventContext = {}): Uint8Array {
  const envelope = eventToC2spEnvelope(event, context, true);
  parseC2spSignatures(envelope.sigs, event.type, true);
  const bytes = canonicalBytes(envelope);
  assertEntrySize(bytes);
  return bytes;
}

/** Canonical to-be-signed bytes for `event`: its envelope without signatures. */
export function signedC2spEventBytes(event: LogEvent, context: C2spEventContext = {}): Uint8Array {
  return canonicalBytes(eventToC2spEnvelope(event, context, false));
}

/**
 * Builds the unsigned envelope for an event about to be signed, validating the
 * public-scope binding fields against `context`.
 *
 * @throws C2spTlogParseError when the event or its public binding is invalid.
 */
export function prepareC2spTlogEvent(event: LogEvent, context: C2spEventContext): C2spJsonEvent {
  const obj = eventToC2spEnvelope(event, context, false);
  validatePublicFields(obj, context);
  return obj;
}

/** Canonical bytes of an envelope object, optionally stripping `sigs` to yield the signed byte string. */
export function canonicalizeUnknownC2spEnvelope(obj: C2spJsonEvent, includeSigs = true): Uint8Array {
  const copy = { ...obj };
  if (!includeSigs) delete copy.sigs;
  return new TextEncoder().encode(canonicalJson(copy));
}

/** Collects an event's existing signatures into the envelope `sigs` shape for its type. */
function signaturesFromEvent(event: LogEvent): C2spSignatures {
  if (event.type === 'ISSUANCE') {
    const issuance = requireC2spIssuanceEvent(event);
    return {
      ...(issuance.sig ? { ae: { kid: issuance.signingKid ?? issuance.initialEntityKid, sig: issuance.sig } } : {}),
      ...(issuance.operationalCountersig ? { op: { kid: issuance.initialOperationalKid, sig: issuance.operationalCountersig } } : {}),
    };
  }
  if (event.type === 'KEY_ROTATION') {
    return {
      ...(event.sig ? { prev_op: { kid: event.signingKid ?? event.previousOperationalKid, sig: event.sig } } : {}),
      ...(event.newOperationalProof ? { new_op: { kid: event.newOperationalKid, sig: event.newOperationalProof } } : {}),
    };
  }
  return event.sig ? { ae: { kid: event.signingKid ?? '', sig: event.sig } } : {};
}

function requireC2spIssuanceEvent(event: Extract<LogEvent, { type: 'ISSUANCE' }>): C2spIssuanceEvent {
  const strings = [
    event.initialOperationalKid,
    event.initialOperationalAlg,
    event.initialOperationalThumbprint,
    event.initialEntityKid,
    event.initialEntityAlg,
    event.initialEntityThumbprint,
  ];
  if (strings.some(value => typeof value !== 'string' || value.length === 0)
    || !event.initialOperationalPublicKey
    || !event.initialEntityPublicKey) {
    throw new C2spTlogParseError('ISSUANCE is missing c2sp-tlog key metadata');
  }
  return event as C2spIssuanceEvent;
}

/**
 * Signature roles a lifecycle event type must carry: `ae`+`op` for ISSUANCE,
 * `prev_op`+`new_op` for KEY_ROTATION, `ae` for every other supported type.
 *
 * @throws C2spTlogParseError for unsupported event types.
 */
export function requiredC2spSignatureNames(type: string): Array<keyof C2spSignatures> {
  if (type === 'ISSUANCE') return ['ae', 'op'];
  if (type === 'KEY_ROTATION') return ['prev_op', 'new_op'];
  if (SUPPORTED.has(type)) return ['ae'];
  throw new C2spTlogParseError(`unsupported DNSid lifecycle event type: ${type}`);
}

/**
 * Parses and validates an envelope `sigs` object for an event type, rejecting
 * roles the type does not allow.
 *
 * @param requireComplete When true, every required role must be present.
 * @throws C2spTlogParseError when the object, a role, or a signature value is invalid.
 */
export function parseC2spSignatures(value: unknown, type: string, requireComplete = true): C2spSignatures {
  if (value === undefined && !requireComplete) return {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new C2spTlogParseError('C2SP event missing sigs object');
  const raw = value as Record<string, unknown>;
  const parsed: C2spSignatures = {};
  if (raw.ae !== undefined) parsed.ae = parseSignatureValue(raw.ae, 'sigs.ae');
  if (raw.op !== undefined) parsed.op = parseSignatureValue(raw.op, 'sigs.op');
  if (raw.prev_op !== undefined) parsed.prev_op = parseSignatureValue(raw.prev_op, 'sigs.prev_op');
  if (raw.new_op !== undefined) parsed.new_op = parseSignatureValue(raw.new_op, 'sigs.new_op');
  const allowed = new Set<string>(requiredC2spSignatureNames(type));
  for (const key of Object.keys(raw)) if (!allowed.has(key)) throw new C2spTlogParseError(`unexpected signature role: ${key}`);
  if (requireComplete) {
    for (const key of allowed) if (!parsed[key as keyof typeof parsed]) throw new C2spTlogParseError(`missing sigs.${key}`);
  }
  return parsed;
}

function parseSignatureValue(value: unknown, name: string): C2spSignatureValue {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new C2spTlogParseError(`${name} must be an object`);
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(key => key !== 'kid' && key !== 'sig')) throw new C2spTlogParseError(`${name} contains an unknown member`);
  const kid = asString(raw.kid, `${name}.kid`);
  const sig = asString(raw.sig, `${name}.sig`);
  if (!SIGNATURE_RE.test(sig)) throw new C2spTlogParseError(`${name}.sig must be unpadded base64url`);
  return { kid, sig };
}

function parseChainFields(e: C2spJsonEvent): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  // Signed chain errors must reach authentication before continuity rejection.
  for (const name of ['seq', 'prev_event_id', 'prev_state_hash', 'prev_index', 'prev_leaf_hash', 'event_id']) {
    if (name in e) out[name] = e[name];
  }
  return out;
}

/** For public scope, requires the signed method/log_origin/stream_id/lr fields and checks them against `context`. */
function validatePublicFields(obj: unknown, context: C2spEventContext): void {
  const e = obj as C2spJsonEvent;
  if (!e || typeof e !== 'object' || Array.isArray(e)) throw new C2spTlogParseError('C2SP event must be an object');
  if (typeof e.fqdn !== 'string' || e.stream_id === normalizeFQDN(e.fqdn, true)) throw new C2spTlogParseError('C2SP requires an opaque stream ID distinct from the identity FQDN');
  const expected: Record<string, unknown> = { method: 'c2sp-tlog', log_origin: context.logOrigin, stream_id: context.streamId, lr: context.lr };
  for (const k of ['method', 'log_origin', 'stream_id', 'lr']) {
    if (typeof e[k] !== 'string' || !e[k]) throw new C2spTlogParseError(`public C2SP event missing signed ${k}`);
    if (expected[k] !== undefined && e[k] !== expected[k]) throw new C2spTlogParseError(`public C2SP event ${k} mismatch`);
  }
}

function epochSeconds(date: Date, name: string): number {
  const millis = date.getTime();
  if (!Number.isSafeInteger(millis) || millis < 0 || millis % 1000 !== 0) throw new C2spTlogParseError(`${name} must have whole-second precision`);
  const seconds = millis / 1000;
  if (!Number.isSafeInteger(seconds) || seconds > MAX_SAFE) throw new C2spTlogParseError(`${name} outside safe integer range`);
  return seconds;
}

function dateFromSeconds(seconds: number, name: string): Date {
  const millis = seconds * 1000;
  const date = new Date(millis);
  if (!Number.isSafeInteger(millis) || !Number.isFinite(date.getTime())) throw new C2spTlogParseError(`${name} outside Date range`);
  return date;
}

function asString(value: unknown, name: string): string {
  if (typeof value !== 'string' || !value) throw new C2spTlogParseError(`missing ${name}`);
  return value;
}

function asSafeInt(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > MAX_SAFE) throw new C2spTlogParseError(`${name} outside safe integer range`);
  return value as number;
}

function asJwk(value: unknown, name: string): DnsIdJWK {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new C2spTlogParseError(`missing ${name}`);
  const jwk = value as Record<string, unknown>;
  asString(jwk.kty, `${name}.kty`);
  asString(jwk.kid, `${name}.kid`);
  asString(jwk.alg, `${name}.alg`);
  return assertSupportedLifecycleJwk(jwk as DnsIdJWK, name);
}

/**
 * Asserts that a lifecycle JWK is a supported public signing key: EdDSA over
 * Ed25519 or ES256 over P-256, with no private key material.
 *
 * @returns The validated key, unchanged.
 * @throws C2spTlogParseError when the key is unsupported or malformed.
 */
export function assertSupportedLifecycleJwk(key: DnsIdJWK, name = 'lifecycle key'): DnsIdJWK {
  if (key.use !== undefined && key.use !== 'sig') throw new C2spTlogParseError(`${name} must be a signing JWK`);
  if ((key as unknown as Record<string, unknown>).d !== undefined) throw new C2spTlogParseError(`${name} must contain only public key material`);
  if (key.alg === 'EdDSA') {
    if (key.kty !== 'OKP' || key.crv !== 'Ed25519' || typeof key.x !== 'string' || !key.x) {
      throw new C2spTlogParseError(`${name} EdDSA key must be an Ed25519 public JWK`);
    }
    return key;
  }
  if (key.alg === 'ES256') {
    if (key.kty !== 'EC' || key.crv !== 'P-256' || typeof key.x !== 'string' || !key.x || typeof key.y !== 'string' || !key.y) {
      throw new C2spTlogParseError(`${name} ES256 key must be a P-256 public JWK`);
    }
    return key;
  }
  throw new C2spTlogParseError(`${name} uses unsupported lifecycle-key algorithm: ${String(key.alg)}`);
}

function lifecycleJwksShareKeyMaterial(a: DnsIdJWK, b: DnsIdJWK): boolean {
  if (a.kty !== b.kty) return false;
  if (a.kty === 'OKP') return a.crv === b.crv && a.x === b.x;
  if (a.kty === 'EC') return a.crv === b.crv && a.x === b.x && a.y === b.y;
  return false;
}

function asRevocationReason(value: unknown): Extract<LogEvent, { type: 'REVOCATION' }>['reason'] {
  if (value !== 'keyCompromise' && value !== 'policyViolation' && value !== 'superseded' && value !== 'cessationOfOperation') throw new C2spTlogParseError('invalid REVOCATION reason');
  return value;
}

function assertEntrySize(bytes: Uint8Array): void {
  if (bytes.length === 0 || bytes.length > MAX_ENTRY_BYTES) throw new C2spTlogParseError('C2SP entry must be between 1 and 65535 bytes');
}
