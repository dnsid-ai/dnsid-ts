import {
  JWKS,
  VerificationCode,
  VerificationError,
  jwkThumbprint,
  normalizeFQDN,
  type DnsIdJWK,
  type KeyProvider,
} from '@dnsid-ai/protocol';
import type { PreparedRegistryEvent, SubmissionResult } from '@dnsid-ai/registry';
import {
  c2spTlogEntryBytes,
  parsePreparedC2spTlogEvent,
  signPreparedC2spTlogEvent,
} from '@dnsid-ai/log-c2sp-tlog/writer';

export interface ManagedIssuanceRegistry {
  prepareIssuance(domain: string, idempotencyKey: string): Promise<PreparedRegistryEvent>;
  submitPreparedEvent(domain: string, entryBytes: Uint8Array, idempotencyKey: string): Promise<SubmissionResult>;
}

export interface ManagedIssuanceState {
  readonly domain: string;
  readonly governanceId: string;
  readonly idempotencyKey: string;
  readonly entityKid: string;
  readonly entityThumbprint: string;
  readonly operationalKid: string;
  readonly operationalThumbprint: string;
  /** Undefined only while the durable intent precedes remote preparation. */
  readonly logReference?: string;
  /** Exact completed canonical bytes. Undefined only for an intent. */
  readonly entryBytes?: Uint8Array;
  /** SHA-256 of entryBytes, persisted before the first submission. */
  readonly entryHash?: string;
  readonly submission?: ManagedIssuanceSubmission;
  readonly terminalFailure?: {
    readonly stage: 'preparation' | 'submission';
    readonly errorCode?: string;
  };
  readonly activated: boolean;
}

export type ManagedIssuanceSubmission = SubmissionResult | {
  readonly state: 'indeterminate';
  readonly entryHash: string;
  readonly errorCode?: string;
};

export interface ManagedIssuanceCoordination {
  /** Loads the one durable setup operation, if it exists. */
  loadIssuance: () => Promise<ManagedIssuanceState | undefined>;
  /** Atomically creates the intent; returns the existing operation if the create lost a race. */
  createIssuance: (intent: ManagedIssuanceState) => Promise<ManagedIssuanceState | undefined>;
  /** Atomically persists the intent, exact bytes, and every reconciliation transition. */
  persistIssuance: (issuance: ManagedIssuanceState) => Promise<void>;
  /**
   * Publishes/converges status only after exact-byte log acceptance is durably bound.
   * Must be idempotent because a crash can replay it before `activated` is persisted.
   */
  activateAcceptedIssuance: (issuance: ManagedIssuanceState) => Promise<void>;
}

export interface IssueManagedIdentityOptions extends ManagedIssuanceCoordination {
  domain: string;
  governanceId: string;
  /** Trusted accountable-entity public key whose existing `sigs.ae` is required. */
  entityKey: DnsIdJWK;
  operationalKeyProvider: KeyProvider;
  registryClient: ManagedIssuanceRegistry;
  idempotencyKey: string;
  /** Optional configured reference; a registry response must match it exactly. */
  logReference?: string;
}

export interface ResumeManagedIssuanceOptions extends ManagedIssuanceCoordination {
  entityKey: DnsIdJWK;
  operationalKeyProvider: KeyProvider;
  registryClient: ManagedIssuanceRegistry;
}

export class ManagedIssuanceSubmissionError extends VerificationError {
  readonly issuance: ManagedIssuanceState;
  readonly retryWithSameBytes: boolean;

  constructor(message: string, issuance: ManagedIssuanceState, retryWithSameBytes: boolean, transient: boolean, cause?: unknown) {
    super(message, { code: VerificationCode.LogError, transient, cause });
    this.name = 'ManagedIssuanceSubmissionError';
    this.issuance = issuance;
    this.retryWithSameBytes = retryWithSameBytes;
  }
}

export class ManagedIssuanceActivationError extends VerificationError {
  readonly issuance: ManagedIssuanceState;

  constructor(issuance: ManagedIssuanceState, cause: unknown) {
    super('managed ISSUANCE was accepted, but publication or activation is incomplete; resume this issuance', {
      code: VerificationCode.LogError,
      transient: true,
      cause,
    });
    this.name = 'ManagedIssuanceActivationError';
    this.issuance = issuance;
  }
}

/** Starts one durable managed setup operation, or resumes the already persisted one. */
export async function issueManagedIdentity(options: IssueManagedIdentityOptions): Promise<ManagedIssuanceState> {
  const domain = normalizeFQDN(options.domain, true);
  const governanceId = normalizeFQDN(options.governanceId, true);
  if (!options.idempotencyKey
    || options.idempotencyKey.trim() !== options.idempotencyKey
    || options.idempotencyKey.length > 200) {
    throw permanentLogError('managed ISSUANCE idempotencyKey must contain 1 to 200 characters without surrounding whitespace');
  }
  const existing = await options.loadIssuance();
  const { entityKey, operationalKey } = await trustedKeys(options.entityKey, options.operationalKeyProvider);
  if (existing) {
    assertSameOperation(existing, { ...options, domain, governanceId });
    return resumeManagedIssuanceState(options, existing, entityKey, operationalKey);
  }

  const intent: ManagedIssuanceState = {
    domain,
    governanceId,
    idempotencyKey: options.idempotencyKey,
    entityKid: entityKey.kid,
    entityThumbprint: await jwkThumbprint(entityKey),
    operationalKid: operationalKey.kid,
    operationalThumbprint: await jwkThumbprint(operationalKey),
    activated: false,
  };
  const raced = await options.createIssuance(intent);
  if (raced) {
    assertSameOperation(raced, { ...options, domain, governanceId });
    return resumeManagedIssuanceState(options, raced, entityKey, operationalKey);
  }
  return prepareAndSubmit(options, intent, entityKey, operationalKey);
}

/** Resumes only the durable operation, reusing its preparation key or exact completed bytes. */
export async function resumeManagedIssuance(options: ResumeManagedIssuanceOptions): Promise<ManagedIssuanceState> {
  const issuance = await options.loadIssuance();
  if (!issuance) throw permanentLogError('no durable managed ISSUANCE operation exists');
  const { entityKey, operationalKey } = await trustedKeys(options.entityKey, options.operationalKeyProvider);
  return resumeManagedIssuanceState(options, issuance, entityKey, operationalKey);
}

async function resumeManagedIssuanceState(
  options: ResumeManagedIssuanceOptions,
  issuance: ManagedIssuanceState,
  entityKey: DnsIdJWK,
  operationalKey: DnsIdJWK,
): Promise<ManagedIssuanceState> {
  await assertPersistedKeys(issuance, entityKey, operationalKey);
  if (issuance.activated) return issuance;
  if (issuance.terminalFailure || issuance.submission?.state === 'rejected') {
    throw permanentLogError('cannot resume a terminally failed managed ISSUANCE');
  }
  if (issuance.submission?.state === 'accepted') {
    await verifyPersistedCompletedIssuance(issuance, entityKey, operationalKey);
    await assertAcceptedBinding(issuance, issuance.submission);
    return activate(options, issuance);
  }
  if (!issuance.entryBytes || !issuance.logReference) {
    return prepareAndSubmit(options, issuance, entityKey, operationalKey);
  }
  return submit(options, issuance);
}

async function prepareAndSubmit(
  options: ResumeManagedIssuanceOptions & { logReference?: string },
  intent: ManagedIssuanceState,
  entityKey: DnsIdJWK,
  operationalKey: DnsIdJWK,
): Promise<ManagedIssuanceState> {
  let raw: PreparedRegistryEvent;
  try {
    raw = await options.registryClient.prepareIssuance(intent.domain, intent.idempotencyKey);
  } catch (cause) {
    if (isTerminalFailure(cause)) {
      const terminal = {
        ...intent,
        terminalFailure: { stage: 'preparation' as const, errorCode: structuredErrorCode(cause) },
      };
      await options.persistIssuance(terminal);
      throw new ManagedIssuanceSubmissionError('managed ISSUANCE preparation failed terminally', terminal, false, false, cause);
    }
    throw new ManagedIssuanceSubmissionError('managed ISSUANCE preparation is unavailable; resume the durable intent', intent, false, true, cause);
  }
  const context = {
    expectedFqdn: intent.domain,
    expectedGovernanceId: intent.governanceId,
    entityKey,
    operationalKey,
  };
  let prepared;
  try {
    if (options.logReference && raw.logReference !== options.logReference) {
      throw permanentLogError(`registry preparation returned unexpected log reference ${raw.logReference}`);
    }
    prepared = await parsePreparedC2spTlogEvent(raw.entryBytes, raw.logReference, context);
    if (prepared.envelope.type !== 'ISSUANCE') {
      throw permanentLogError(`registry preparation returned ${String(prepared.envelope.type)} instead of ISSUANCE`);
    }
    const existingSignatures = prepared.envelope.sigs as { ae?: unknown } | undefined;
    if (!existingSignatures?.ae) throw permanentLogError('registry ISSUANCE preparation is missing the accountable-entity signature');
  } catch (cause) {
    const terminal = {
      ...intent,
      terminalFailure: { stage: 'preparation' as const, errorCode: structuredErrorCode(cause) },
    };
    await options.persistIssuance(terminal);
    throw new ManagedIssuanceSubmissionError('managed ISSUANCE preparation failed trusted validation', terminal, false, false, cause);
  }
  prepared = await signPreparedC2spTlogEvent(prepared, 'OperationalCountersignature', options.operationalKeyProvider, context);
  const entryBytes = await c2spTlogEntryBytes(prepared, context);
  const completed = {
    ...intent,
    logReference: raw.logReference,
    entryBytes: entryBytes.slice(),
    entryHash: await sha256Hex(entryBytes),
  };
  await options.persistIssuance(completed);
  return submit(options, completed);
}

async function submit(options: ResumeManagedIssuanceOptions, issuance: ManagedIssuanceState): Promise<ManagedIssuanceState> {
  if (!issuance.entryBytes || !issuance.logReference) throw permanentLogError('managed ISSUANCE exact bytes are not persisted');
  const { entityKey, operationalKey } = await trustedKeys(options.entityKey, options.operationalKeyProvider);
  await verifyPersistedCompletedIssuance(issuance, entityKey, operationalKey);
  let submission: SubmissionResult;
  try {
    submission = await options.registryClient.submitPreparedEvent(
      issuance.domain,
      issuance.entryBytes.slice(),
      issuance.idempotencyKey,
    );
  } catch (cause) {
    const sameBytes = retryWithSameBytes(cause);
    let recoverable = issuance;
    if (sameBytes) {
      recoverable = {
        ...issuance,
        submission: {
          state: 'indeterminate',
          entryHash: issuance.entryHash!,
          errorCode: structuredErrorCode(cause),
        },
      };
      await options.persistIssuance(recoverable);
    } else {
      recoverable = {
        ...issuance,
        submission: {
          state: 'rejected',
          entryHash: issuance.entryHash!,
          errorCode: structuredErrorCode(cause),
        },
        terminalFailure: { stage: 'submission', errorCode: structuredErrorCode(cause) },
      };
      await options.persistIssuance(recoverable);
    }
    throw new ManagedIssuanceSubmissionError(
      sameBytes
        ? 'managed ISSUANCE submission is indeterminate; retry the same bytes and idempotency key'
        : 'managed ISSUANCE submission failed terminally',
      recoverable,
      sameBytes,
      sameBytes,
      cause,
    );
  }
  await assertAcceptedBinding(issuance, submission);
  const reconciled = { ...issuance, submission };
  await options.persistIssuance(reconciled);
  if (submission.state === 'rejected') {
    throw new ManagedIssuanceSubmissionError(
      `registry rejected the prepared ISSUANCE: ${submission.errorCode ?? 'unknown error'}`,
      reconciled,
      false,
      false,
    );
  }
  if (submission.state !== 'accepted') return reconciled;
  return activate(options, reconciled);
}

async function activate(options: ManagedIssuanceCoordination, issuance: ManagedIssuanceState): Promise<ManagedIssuanceState> {
  try {
    await options.activateAcceptedIssuance(issuance);
    const activated = { ...issuance, activated: true };
    await options.persistIssuance(activated);
    return activated;
  } catch (cause) {
    throw new ManagedIssuanceActivationError(issuance, cause);
  }
}

async function trustedKeys(entityKey: DnsIdJWK, operationalProvider: KeyProvider): Promise<{
  entityKey: DnsIdJWK;
  operationalKey: DnsIdJWK;
}> {
  const operationalKey = await operationalProvider.signingKey();
  new JWKS([entityKey]).validateRecordSigning();
  new JWKS([operationalKey]).validateOperational();
  if (await jwkThumbprint(entityKey) === await jwkThumbprint(operationalKey)) {
    throw permanentLogError('managed ISSUANCE requires distinct entity and operational keys');
  }
  return { entityKey, operationalKey };
}

async function assertPersistedKeys(state: ManagedIssuanceState, entityKey: DnsIdJWK, operationalKey: DnsIdJWK): Promise<void> {
  if (state.entityKid !== entityKey.kid || state.entityThumbprint !== await jwkThumbprint(entityKey)) {
    throw permanentLogError('durable managed ISSUANCE entity key does not match the trusted provider');
  }
  if (state.operationalKid !== operationalKey.kid || state.operationalThumbprint !== await jwkThumbprint(operationalKey)) {
    throw permanentLogError('durable managed ISSUANCE operational key does not match the trusted provider');
  }
}

async function verifyPersistedCompletedIssuance(
  state: ManagedIssuanceState,
  entityKey: DnsIdJWK,
  operationalKey: DnsIdJWK,
): Promise<void> {
  if (!state.entryBytes || !state.entryHash || !state.logReference) {
    throw permanentLogError('durable managed ISSUANCE is missing exact bytes, hash, or log reference');
  }
  const actualHash = await sha256Hex(state.entryBytes);
  if (actualHash !== state.entryHash) throw permanentLogError('durable managed ISSUANCE bytes do not match their persisted hash');
  const context = {
    expectedFqdn: state.domain,
    expectedGovernanceId: state.governanceId,
    entityKey,
    operationalKey,
  };
  const prepared = await parsePreparedC2spTlogEvent(state.entryBytes, state.logReference, context);
  const canonical = await c2spTlogEntryBytes(prepared, context);
  if (!bytesEqual(canonical, state.entryBytes)) throw permanentLogError('durable managed ISSUANCE bytes are not the canonical completed entry');
}

function assertSameOperation(state: ManagedIssuanceState, options: IssueManagedIdentityOptions): void {
  if (state.domain !== options.domain
    || state.governanceId !== options.governanceId
    || state.idempotencyKey !== options.idempotencyKey) {
    throw permanentLogError('a different durable managed ISSUANCE operation already exists');
  }
}

async function assertAcceptedBinding(issuance: ManagedIssuanceState, submission: SubmissionResult): Promise<void> {
  if (issuance.submission?.entryHash && submission.entryHash !== issuance.submission.entryHash) {
    throw permanentLogError('registry reconciled a different entry hash for this managed ISSUANCE');
  }
  if (submission.state !== 'accepted') return;
  const expectedHash = await sha256Hex(issuance.entryBytes!);
  if (submission.entryHash !== expectedHash) throw permanentLogError('accepted entry hash does not match the exact managed ISSUANCE bytes');
  if (!Number.isSafeInteger(submission.index) || submission.index! < 0) throw permanentLogError('accepted managed ISSUANCE is missing a valid index');
  const expectedReference = `${issuance.logReference}@${submission.index}`;
  if (submission.logRef !== expectedReference) throw permanentLogError('accepted managed ISSUANCE final log reference does not match its prepared binding');
}

function retryWithSameBytes(cause: unknown): boolean {
  return !(cause && typeof cause === 'object' && 'retryWithSameBytes' in cause
    && (cause as { retryWithSameBytes?: unknown }).retryWithSameBytes === false);
}

function isTerminalFailure(cause: unknown): boolean {
  if (!cause || typeof cause !== 'object') return false;
  if ('retryable' in cause && (cause as { retryable?: unknown }).retryable === false) return true;
  if ('state' in cause && (cause as { state?: unknown }).state === 'rejected') return true;
  return 'retryWithSameBytes' in cause && (cause as { retryWithSameBytes?: unknown }).retryWithSameBytes === false;
}

function structuredErrorCode(cause: unknown): string | undefined {
  if (cause && typeof cause === 'object' && 'code' in cause && typeof (cause as { code?: unknown }).code === 'string') {
    return (cause as { code: string }).code;
  }
  return undefined;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function permanentLogError(message: string, cause?: unknown): VerificationError {
  return new VerificationError(message, { code: VerificationCode.LogError, transient: false, cause });
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const copy = bytes.slice();
  const digest = await crypto.subtle.digest('SHA-256', copy.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}
