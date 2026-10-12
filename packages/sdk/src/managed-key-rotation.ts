import {
  ArgumentError,
  normalizeFQDN,
  JWKS,
  VerificationCode,
  VerificationError,
  jwkThumbprint,
  type DnsIdJWK,
  type KeyProvider,
  type VerifiedDomain,
} from '@dnsid-ai/protocol';
import type {
  KeyRotationPreparationRequest,
  PreparedRegistryEvent,
  SubmissionResult,
} from '@dnsid-ai/registry';
import type { C2spSignatures } from '@dnsid-ai/log-c2sp-tlog';
import {
  c2spTlogEntryBytes,
  parsePreparedC2spTlogEvent,
  signPreparedC2spTlogEvent,
} from '@dnsid-ai/log-c2sp-tlog/writer';

export interface ManagedKeyRotationRegistry {
  prepareKeyRotation(
    domain: string,
    request: KeyRotationPreparationRequest,
    idempotencyKey: string,
  ): Promise<PreparedRegistryEvent>;
  submitPreparedEvent(
    domain: string,
    entryBytes: Uint8Array,
    idempotencyKey: string,
  ): Promise<SubmissionResult>;
}

export interface ManagedKeyRotationCoordination {
  /** Durably persists exact bytes and every subsequent reconciliation state. */
  persistRotation: (rotation: ManagedKeyRotationResult) => Promise<void>;
  /** Blocks new application signing and drains in-flight request/directory signing before resolving;
   * resumes signing only after durable activation. */
  setApplicationSigningPaused: (paused: boolean) => Promise<void>;
  /** Restores the application signer before signing is resumed. */
  setApplicationSigner: (provider: KeyProvider, kid: string) => Promise<void>;
  /** Must return fresh, protocol-verified signed TXT/ku evidence, not cached pre-rotation evidence. */
  verifyPublicationEvidence: (domain: string) => Promise<VerifiedDomain>;
}

export interface RotateManagedOperationalKeyOptions extends ManagedKeyRotationCoordination {
  domain: string;
  /** Exact unindexed c2sp-tlog reference configured for this identity. */
  logReference: string;
  keyProvider: KeyProvider;
  previousProviderReference: string;
  /** Omit to rotate within the previous provider. */
  targetKeyProvider?: KeyProvider;
  newProviderReference: string;
  registryClient: ManagedKeyRotationRegistry;
  idempotencyKey: string;
}

export interface ManagedKeyRotationResult {
  readonly domain: string;
  readonly logReference: string;
  readonly previousKid: string;
  readonly newKid: string;
  readonly previousProviderReference: string;
  readonly newProviderReference: string;
  readonly previousKey: DnsIdJWK;
  readonly previousThumbprint: string;
  readonly newThumbprint: string;
  readonly entryHash: string;
  /**
   * Persist these exact bytes with idempotencyKey while activated is false.
   * Callers must pause new application signing until this rotation is accepted.
   */
  readonly entryBytes: Uint8Array;
  readonly idempotencyKey: string;
  readonly submission?: SubmissionResult;
  readonly activated: boolean;
  readonly applicationSigningPaused: boolean;
}

export interface ResumeManagedOperationalKeyRotationOptions extends ManagedKeyRotationCoordination {
  /** Resolves durable references, never the current deployment's selected provider. */
  resolveKeyProvider: (reference: string) => Promise<KeyProvider>;
  registryClient: Pick<ManagedKeyRotationRegistry, 'submitPreparedEvent'>;
  rotation: ManagedKeyRotationResult;
}

/** Submission failed after the completed entry bytes were fixed. */
export class ManagedKeyRotationSubmissionError extends VerificationError {
  readonly rotation: ManagedKeyRotationResult;
  readonly retryWithSameBytes: boolean;

  constructor(message: string, rotation: ManagedKeyRotationResult, retryWithSameBytes: boolean, cause?: unknown) {
    super(message, { code: VerificationCode.LogError, transient: retryWithSameBytes, cause });
    this.name = 'ManagedKeyRotationSubmissionError';
    this.rotation = rotation;
    this.retryWithSameBytes = retryWithSameBytes;
  }
}

/** Registry acceptance succeeded, but local key-state reconciliation did not. */
export class ManagedKeyRotationActivationError extends VerificationError {
  readonly rotation: ManagedKeyRotationResult;

  constructor(message: string, rotation: ManagedKeyRotationResult, cause?: unknown) {
    super(message, { code: VerificationCode.LogError, transient: true, cause });
    this.name = 'ManagedKeyRotationActivationError';
    this.rotation = rotation;
  }
}

/**
 * Runs C2SP registry-managed rotation. The registry owns managed ku publication
 * and append reconciliation; local activation happens only after an accepted
 * result for the exact, durably persisted bytes while application signing is paused.
 */
export async function rotateManagedOperationalKey(
  options: RotateManagedOperationalKeyOptions,
): Promise<ManagedKeyRotationResult> {
  assertCoordination(options);
  const domain = normalizeFQDN(options.domain, true);
  assertOperationReferences(options.previousProviderReference, options.newProviderReference, options.idempotencyKey);
  const target = options.targetKeyProvider ?? options.keyProvider;
  if ((target === options.keyProvider) !== (options.previousProviderReference === options.newProviderReference)) {
    throw new ArgumentError('provider references must identify the selected previous and target providers');
  }
  const previousKey = await options.keyProvider.signingKey();
  new JWKS([previousKey]).validateOperational();
  const previousThumbprint = await jwkThumbprint(previousKey);
  const newKid = await target.generateKey();
  const newKey = await target.jwk(newKid);
  new JWKS([newKey]).validateOperational();
  if (await jwkThumbprint(newKey) === previousThumbprint) {
    throw permanentRotationError('managed KEY_ROTATION requires a distinct pending operational key');
  }

  let raw: PreparedRegistryEvent;
  try {
    raw = await options.registryClient.prepareKeyRotation(domain, {
      previousKeyId: previousThumbprint,
      publicKey: newKey,
    }, options.idempotencyKey);
  } catch (cause) {
    throw new VerificationError('managed key rotation preparation is unavailable', {
      code: VerificationCode.LogError,
      transient: true,
      cause,
    });
  }
  if (raw.logReference !== options.logReference) {
    throw permanentRotationError(`registry preparation returned unexpected log reference ${raw.logReference}`);
  }

  const context = { expectedFqdn: domain, previousOperationalKey: previousKey };
  let prepared = await parsePreparedC2spTlogEvent(raw.entryBytes, raw.logReference, context);
  if (prepared.envelope.type !== 'KEY_ROTATION') {
    throw permanentRotationError(`registry preparation returned ${String(prepared.envelope.type)} instead of KEY_ROTATION`);
  }
  if (prepared.envelope.fqdn !== domain) {
    throw permanentRotationError('registry KEY_ROTATION fqdn does not match the expected identity');
  }
  if (prepared.envelope.prev_thumb !== previousThumbprint) {
    throw permanentRotationError('registry KEY_ROTATION previous thumbprint does not match the active operational key');
  }
  await assertPreparedRotationKey(prepared.envelope.new_ku, prepared.envelope.new_thumb, newKey);

  prepared = await signPreparedC2spTlogEvent(prepared, 'PreviousOperational', options.keyProvider, context);
  prepared = await signPreparedC2spTlogEvent(prepared, 'NewOperational', target, context);
  const entryBytes = await c2spTlogEntryBytes(prepared, context);
  const rotation: ManagedKeyRotationResult = {
    domain,
    logReference: options.logReference,
    previousKid: previousKey.kid,
    newKid,
    previousProviderReference: options.previousProviderReference,
    newProviderReference: options.newProviderReference,
    previousKey,
    previousThumbprint,
    newThumbprint: await jwkThumbprint(newKey),
    entryHash: await sha256Hex(entryBytes),
    entryBytes: entryBytes.slice(),
    idempotencyKey: options.idempotencyKey,
    activated: false,
    applicationSigningPaused: true,
  };
  try {
    await options.persistRotation(rotation);
    await options.setApplicationSigningPaused(true);
  } catch (cause) {
    throw new ManagedKeyRotationSubmissionError('managed rotation persistence or pause failed; resume this state', rotation, true, cause);
  }
  return submitManagedRotation(options, options.keyProvider, target, rotation);
}

/** Retries only the persisted completed bytes and activates on acceptance. */
export async function resumeManagedOperationalKeyRotation(
  options: ResumeManagedOperationalKeyRotationOptions,
): Promise<ManagedKeyRotationResult> {
  assertCoordination(options);
  if (typeof options.resolveKeyProvider !== 'function') throw new ArgumentError('managed rotation recovery requires resolveKeyProvider');
  const rotation = options.rotation;
  try {
    assertOperationReferences(rotation.previousProviderReference, rotation.newProviderReference, rotation.idempotencyKey);
    const previous = await options.resolveKeyProvider(rotation.previousProviderReference);
    const target = rotation.newProviderReference === rotation.previousProviderReference
      ? previous : await options.resolveKeyProvider(rotation.newProviderReference);
    await validateSavedRotation(rotation, previous, target);
    if (rotation.submission?.state === 'rejected') {
      throw new ManagedKeyRotationSubmissionError('cannot resume a rejected managed key rotation', rotation, false);
    }
    await options.setApplicationSigningPaused(true);
    if (rotation.submission?.state === 'accepted') {
      await assertSubmissionMatchesRotation(rotation, rotation.submission);
      return activateRotation(options, previous, target, rotation);
    }
    if (rotation.activated) throw permanentRotationError('activated rotation has no accepted submission');
    return submitManagedRotation(options, previous, target, rotation);
  } catch (cause) {
    if (cause instanceof ManagedKeyRotationSubmissionError || cause instanceof ManagedKeyRotationActivationError) throw cause;
    throw new ManagedKeyRotationActivationError('managed rotation recovery failed; signing must remain paused', rotation, cause);
  }
}

async function submitManagedRotation(
  options: ManagedKeyRotationCoordination & { registryClient: Pick<ManagedKeyRotationRegistry, 'submitPreparedEvent'> },
  previous: KeyProvider,
  target: KeyProvider,
  rotation: ManagedKeyRotationResult,
): Promise<ManagedKeyRotationResult> {
  let submission: SubmissionResult;
  try {
    submission = await options.registryClient.submitPreparedEvent(rotation.domain, rotation.entryBytes, rotation.idempotencyKey);
  } catch (cause) {
    const retryWithSameBytes = structuredRetryWithSameBytes(cause);
    throw new ManagedKeyRotationSubmissionError(
      retryWithSameBytes
        ? 'managed key rotation submission is unresolved; retry the same bytes and idempotency key'
        : 'managed key rotation submission failed terminally',
      rotation,
      retryWithSameBytes,
      cause,
    );
  }

  const next = { ...rotation, submission };
  try {
    await assertSubmissionMatchesRotation(rotation, submission);
    await options.persistRotation(next);
  } catch (cause) {
    throw new ManagedKeyRotationSubmissionError('managed rotation acceptance binding or persistence failed; resume this state', next, true, cause);
  }
  if (submission.state === 'rejected') {
    throw new ManagedKeyRotationSubmissionError(
      `registry rejected the prepared KEY_ROTATION: ${submission.errorCode ?? 'unknown error'}`,
      next,
      false,
    );
  }
  if (submission.state !== 'accepted') return next;

  return activateRotation(options, previous, target, next);
}

async function activateRotation(
  options: ManagedKeyRotationCoordination,
  previous: KeyProvider,
  target: KeyProvider,
  rotation: ManagedKeyRotationResult,
): Promise<ManagedKeyRotationResult> {
  let recoverable = rotation;
  try {
    await verifyAcceptedPublication(options, rotation);
    if (!rotation.activated) await reconcileAcceptedRotation(previous, target, rotation);
    const activated = { ...rotation, activated: true, applicationSigningPaused: true };
    await options.persistRotation(activated);
    recoverable = activated;
    await assertKeyBinding(await target.signingKey(), rotation.newKid, rotation.newThumbprint);
    await options.setApplicationSigner(target, rotation.newKid);
    await options.setApplicationSigningPaused(false);
    const completed = { ...activated, applicationSigningPaused: false };
    await options.persistRotation(completed);
    return completed;
  } catch (cause) {
    throw new ManagedKeyRotationActivationError(
      'managed key rotation was accepted, but local key activation is incomplete; resume with this rotation state',
      recoverable,
      cause,
    );
  }
}

async function reconcileAcceptedRotation(previous: KeyProvider, target: KeyProvider, rotation: ManagedKeyRotationResult): Promise<void> {
  const active = await target.signingKey();
  if (active.kid !== rotation.newKid) {
    if (previous === target) await assertKeyBinding(active, rotation.previousKid, rotation.previousThumbprint);
    await target.activate(rotation.newKid);
  }
  await assertKeyBinding(await target.signingKey(), rotation.newKid, rotation.newThumbprint);
  if ((await previous.listKeyIds()).includes(rotation.previousKid)) await previous.supersede(rotation.previousKid);
}

function assertCoordination(options: ManagedKeyRotationCoordination): void {
  for (const name of ['persistRotation', 'setApplicationSigningPaused', 'setApplicationSigner', 'verifyPublicationEvidence'] as const) {
    if (typeof options[name] !== 'function') throw new ArgumentError(`managed rotation requires ${name}`);
  }
}

function assertOperationReferences(previous: string, next: string, idempotencyKey: string): void {
  if (!previous?.trim() || !next?.trim() || !idempotencyKey
    || idempotencyKey.trim() !== idempotencyKey || idempotencyKey.length > 200) {
    throw permanentRotationError('managed rotation requires provider references and a valid idempotency key');
  }
}

async function assertKeyBinding(key: DnsIdJWK, kid: string, thumbprint: string): Promise<void> {
  new JWKS([key]).validateOperational();
  if (key.kid !== kid || await jwkThumbprint(key) !== thumbprint) {
    throw permanentRotationError('saved managed rotation key binding mismatch');
  }
}

async function validateSavedRotation(rotation: ManagedKeyRotationResult, previous: KeyProvider, target: KeyProvider): Promise<void> {
  assertOperationReferences(rotation.previousProviderReference, rotation.newProviderReference, rotation.idempotencyKey);
  if (typeof rotation.activated !== 'boolean' || typeof rotation.applicationSigningPaused !== 'boolean'
    || normalizeFQDN(rotation.domain, true) !== rotation.domain
    || await sha256Hex(rotation.entryBytes) !== rotation.entryHash) {
    throw permanentRotationError('saved managed rotation domain or entry hash mismatch');
  }
  await assertKeyBinding(rotation.previousKey, rotation.previousKid, rotation.previousThumbprint);
  if ((await previous.listKeyIds()).includes(rotation.previousKid)) {
    await assertKeyBinding(await previous.jwk(rotation.previousKid), rotation.previousKid, rotation.previousThumbprint);
  } else if (!rotation.activated && (await target.signingKey()).kid !== rotation.newKid) {
    throw permanentRotationError('saved previous key is unavailable before activation');
  }
  const next = await target.jwk(rotation.newKid);
  await assertKeyBinding(next, rotation.newKid, rotation.newThumbprint);
  const context = { expectedFqdn: rotation.domain, previousOperationalKey: rotation.previousKey };
  const prepared = await parsePreparedC2spTlogEvent(rotation.entryBytes, rotation.logReference, context);
  if (prepared.envelope.type !== 'KEY_ROTATION' || prepared.envelope.fqdn !== rotation.domain
    || prepared.envelope.prev_thumb !== rotation.previousThumbprint) {
    throw permanentRotationError('saved managed rotation event binding mismatch');
  }
  await assertPreparedRotationKey(prepared.envelope.new_ku, prepared.envelope.new_thumb, next);
  await c2spTlogEntryBytes(prepared, context);
  if (rotation.submission) await assertSubmissionMatchesRotation(rotation, rotation.submission);
}

async function verifyAcceptedPublication(options: ManagedKeyRotationCoordination, rotation: ManagedKeyRotationResult): Promise<void> {
  const verified = await options.verifyPublicationEvidence(rotation.domain);
  if (verified.domain !== rotation.domain || verified.record.lr !== rotation.logReference) {
    throw permanentRotationError('current signed publication does not match managed rotation');
  }
  await assertKeyBinding(verified.jwks.currentOperationalSigningKey(), rotation.newKid, rotation.newThumbprint);
  const prepared = await parsePreparedC2spTlogEvent(rotation.entryBytes, rotation.logReference, {
    expectedFqdn: rotation.domain, previousOperationalKey: rotation.previousKey,
  });
  const signatures = prepared.envelope.sigs as C2spSignatures;
  // Verified inclusion and matching signatures bind continuity to the saved signed event.
  const event = await verified.logReader.readEvent(rotation.submission!.logRef!);
  if (event.type !== 'KEY_ROTATION' || event.domain !== rotation.domain
    || event.previousOperationalThumbprint !== rotation.previousThumbprint
    || event.newOperationalKid !== rotation.newKid || event.newOperationalThumbprint !== rotation.newThumbprint
    || event.signingKid !== signatures.prev_op!.kid || event.sig !== signatures.prev_op!.sig
    || event.newOperationalProof !== signatures.new_op!.sig
    || event.timestamp.getTime() !== (prepared.envelope.ts as number) * 1000) {
    throw permanentRotationError('accepted managed rotation continuity mismatch');
  }
}

async function assertPreparedRotationKey(value: unknown, thumbprint: unknown, expected: DnsIdJWK): Promise<void> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw permanentRotationError('registry KEY_ROTATION is missing new_ku');
  const actual = value as DnsIdJWK;
  const actualThumbprint = await jwkThumbprint(actual);
  const expectedThumbprint = await jwkThumbprint(expected);
  if (actual.kid !== expected.kid || actual.alg !== expected.alg || actualThumbprint !== expectedThumbprint) {
    throw permanentRotationError('registry KEY_ROTATION new key does not match the generated pending key');
  }
  if (thumbprint !== expectedThumbprint) throw permanentRotationError('registry KEY_ROTATION new thumbprint does not match the generated pending key');
}

async function assertSubmissionMatchesRotation(rotation: ManagedKeyRotationResult, submission: SubmissionResult): Promise<void> {
  if (rotation.submission?.entryHash && submission.entryHash && rotation.submission.entryHash !== submission.entryHash) {
    throw permanentRotationError('registry reconciled a different entry hash for this managed key rotation');
  }
  if (submission.entryHash !== undefined && submission.entryHash !== rotation.entryHash) {
    throw permanentRotationError('submission entry hash does not match the exact managed key rotation bytes');
  }
  if (submission.state !== 'accepted') return;
  const expectedHash = await sha256Hex(rotation.entryBytes);
  if (submission.entryHash !== expectedHash) {
    throw permanentRotationError('accepted submission entry hash does not match the exact managed key rotation bytes');
  }
  if (submission.logRef !== `${rotation.logReference}@${submission.index}` || !Number.isSafeInteger(submission.index) || submission.index! < 0) {
    throw permanentRotationError('accepted submission log reference does not match managed rotation');
  }
  if (submission.keyId !== rotation.newKid) {
    throw permanentRotationError('accepted submission key_id does not match the generated pending key');
  }
}

function structuredRetryWithSameBytes(cause: unknown): boolean {
  if (cause && typeof cause === 'object' && 'retryWithSameBytes' in cause
    && typeof (cause as { retryWithSameBytes?: unknown }).retryWithSameBytes === 'boolean') {
    return (cause as { retryWithSameBytes: boolean }).retryWithSameBytes;
  }
  return true;
}

function permanentRotationError(message: string, cause?: unknown): VerificationError {
  return new VerificationError(message, { code: VerificationCode.LogError, transient: false, cause });
}

async function sha256Hex(value: Uint8Array): Promise<string> {
  const bytes = value.slice();
  const digest = await crypto.subtle.digest('SHA-256', bytes.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}
