import {
  JWKS,
  VerificationCode,
  VerificationError,
  jwkThumbprint,
  type DnsIdJWK,
  type KeyProvider,
} from '@dnsid-ai/protocol';
import type {
  KeyRotationPreparationRequest,
  PreparedRegistryEvent,
  SubmissionResult,
} from '@dnsid-ai/registry';
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

export interface RotateManagedOperationalKeyOptions {
  domain: string;
  /** Exact unindexed c2sp-tlog reference configured for this identity. */
  logReference: string;
  keyProvider: KeyProvider;
  registryClient: ManagedKeyRotationRegistry;
  idempotencyKey: string;
  /** Durably persists exact bytes and every subsequent reconciliation state. */
  persistRotation: (rotation: ManagedKeyRotationResult) => Promise<void>;
  /** Pauses application signing before submission and resumes it only after durable activation. */
  setApplicationSigningPaused: (paused: boolean) => Promise<void>;
}

export interface ManagedKeyRotationResult {
  readonly domain: string;
  readonly logReference: string;
  readonly previousKid: string;
  readonly newKid: string;
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

export interface ResumeManagedOperationalKeyRotationOptions {
  keyProvider: KeyProvider;
  registryClient: Pick<ManagedKeyRotationRegistry, 'submitPreparedEvent'>;
  rotation: ManagedKeyRotationResult;
  persistRotation: (rotation: ManagedKeyRotationResult) => Promise<void>;
  setApplicationSigningPaused: (paused: boolean) => Promise<void>;
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
  const previousKey = await options.keyProvider.signingKey();
  new JWKS([previousKey]).validateOperational();
  const previousThumbprint = await jwkThumbprint(previousKey);
  const newKid = await options.keyProvider.generateKey();
  const newKey = await options.keyProvider.jwk(newKid);
  new JWKS([newKey]).validateOperational();
  if (await jwkThumbprint(newKey) === previousThumbprint) {
    throw permanentRotationError('managed KEY_ROTATION requires a distinct pending operational key');
  }

  let raw: PreparedRegistryEvent;
  try {
    raw = await options.registryClient.prepareKeyRotation(options.domain, {
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

  const context = { expectedFqdn: options.domain, previousOperationalKey: previousKey };
  let prepared = await parsePreparedC2spTlogEvent(raw.entryBytes, raw.logReference, context);
  if (prepared.envelope.type !== 'KEY_ROTATION') {
    throw permanentRotationError(`registry preparation returned ${String(prepared.envelope.type)} instead of KEY_ROTATION`);
  }
  if (prepared.envelope.fqdn !== options.domain) {
    throw permanentRotationError('registry KEY_ROTATION fqdn does not match the expected identity');
  }
  if (prepared.envelope.prev_thumb !== previousThumbprint) {
    throw permanentRotationError('registry KEY_ROTATION previous thumbprint does not match the active operational key');
  }
  await assertPreparedRotationKey(prepared.envelope.new_ku, prepared.envelope.new_thumb, newKey);

  prepared = await signPreparedC2spTlogEvent(prepared, 'PreviousOperational', options.keyProvider, context);
  prepared = await signPreparedC2spTlogEvent(prepared, 'NewOperational', options.keyProvider, context);
  const entryBytes = await c2spTlogEntryBytes(prepared, context);
  const rotation: ManagedKeyRotationResult = {
    domain: options.domain,
    logReference: options.logReference,
    previousKid: previousKey.kid,
    newKid,
    entryBytes: entryBytes.slice(),
    idempotencyKey: options.idempotencyKey,
    activated: false,
    applicationSigningPaused: true,
  };
  await options.persistRotation(rotation);
  await options.setApplicationSigningPaused(true);
  return submitManagedRotation(options.keyProvider, options.registryClient, rotation, options.persistRotation, options.setApplicationSigningPaused);
}

/** Retries only the persisted completed bytes and activates on acceptance. */
export async function resumeManagedOperationalKeyRotation(
  options: ResumeManagedOperationalKeyRotationOptions,
): Promise<ManagedKeyRotationResult> {
  if (options.rotation.activated) {
    if (!options.rotation.applicationSigningPaused) return options.rotation;
    await options.setApplicationSigningPaused(false);
    const completed = { ...options.rotation, applicationSigningPaused: false };
    await options.persistRotation(completed);
    return completed;
  }
  if (options.rotation.submission?.state === 'rejected') {
    throw permanentRotationError('cannot resume a rejected managed key rotation');
  }
  await options.setApplicationSigningPaused(true);
  return submitManagedRotation(options.keyProvider, options.registryClient, options.rotation, options.persistRotation, options.setApplicationSigningPaused);
}

async function submitManagedRotation(
  keyProvider: KeyProvider,
  registryClient: Pick<ManagedKeyRotationRegistry, 'submitPreparedEvent'>,
  rotation: ManagedKeyRotationResult,
  persistRotation: (rotation: ManagedKeyRotationResult) => Promise<void>,
  setApplicationSigningPaused: (paused: boolean) => Promise<void>,
): Promise<ManagedKeyRotationResult> {
  let submission: SubmissionResult;
  try {
    submission = await registryClient.submitPreparedEvent(rotation.domain, rotation.entryBytes, rotation.idempotencyKey);
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

  await assertSubmissionMatchesRotation(rotation, submission);
  const next = { ...rotation, submission };
  await persistRotation(next);
  if (submission.state === 'rejected') {
    throw new ManagedKeyRotationSubmissionError(
      `registry rejected the prepared KEY_ROTATION: ${submission.errorCode ?? 'unknown error'}`,
      next,
      false,
    );
  }
  if (submission.state !== 'accepted') return next;

  let recoverable = next;
  try {
    await reconcileAcceptedRotation(keyProvider, rotation);
    const activated = { ...next, activated: true };
    await persistRotation(activated);
    recoverable = activated;
    await setApplicationSigningPaused(false);
    const completed = { ...activated, applicationSigningPaused: false };
    await persistRotation(completed);
    return completed;
  } catch (cause) {
    throw new ManagedKeyRotationActivationError(
      'managed key rotation was accepted, but local key activation is incomplete; resume with this rotation state',
      recoverable,
      cause,
    );
  }
}

async function reconcileAcceptedRotation(keyProvider: KeyProvider, rotation: ManagedKeyRotationResult): Promise<void> {
  const activeKid = (await keyProvider.signingKey()).kid;
  if (activeKid === rotation.previousKid) {
    await keyProvider.activate(rotation.newKid);
  } else if (activeKid !== rotation.newKid) {
    throw permanentRotationError(`unexpected active key ${activeKid} while reconciling managed key rotation`);
  }

  if ((await keyProvider.listKeyIds()).includes(rotation.previousKid)) {
    await keyProvider.supersede(rotation.previousKid);
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
  if (submission.state !== 'accepted') return;
  const expectedHash = await sha256Hex(rotation.entryBytes);
  if (submission.entryHash !== expectedHash) {
    throw permanentRotationError('accepted submission entry hash does not match the exact managed key rotation bytes');
  }
  if (submission.keyId !== undefined && submission.keyId !== rotation.newKid) {
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
