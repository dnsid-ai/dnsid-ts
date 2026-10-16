import {
  VerificationCode,
  VerificationError,
  type LifecycleErrorCategory,
} from '@dnsid-ai/protocol';

/** Base error for all c2sp-tlog failures. */
export class C2spTlogError extends VerificationError {
  readonly status?: number;

  constructor(message: string, options: {
    transient?: boolean;
    errorCategory?: LifecycleErrorCategory;
    cause?: unknown;
    status?: number;
  } = {}) {
    super(message, {
      code: VerificationCode.LogError,
      transient: options.transient,
      errorCategory: options.errorCategory ?? 'INVALID_EVIDENCE',
      cause: options.cause,
    });
    this.name = 'C2spTlogError';
    this.status = options.status;
  }
}

/** Thrown when c2sp-tlog input (checkpoint, entry, reference, bundle, ...) is malformed or non-canonical. */
export class C2spTlogParseError extends C2spTlogError {
  constructor(message: string, cause?: unknown) {
    super(message, { cause });
    this.name = 'C2spTlogParseError';
  }
}

/** Thrown when well-formed c2sp-tlog evidence fails cryptographic or policy verification. */
export class C2spTlogVerificationError extends C2spTlogError {
  /** Lifecycle conformance category for this failure; defaults to `INVALID_EVIDENCE`. */
  readonly errorCategory: LifecycleErrorCategory;

  constructor(message: string, errorCategory: LifecycleErrorCategory = 'INVALID_EVIDENCE', cause?: unknown) {
    super(message, { errorCategory, cause });
    this.name = 'C2spTlogVerificationError';
    this.errorCategory = errorCategory;
  }
}

/**
 * Which continuity check a candidate checkpoint failed. The vocabulary is shared with the Go
 * (`CheckpointAdvanceErrorKind`) and Python (`C2spLifecycleErrorCategory`) SDKs; each kind
 * describes an observation, never its cause.
 */
export type C2spCheckpointAdvanceKind = 'rollback' | 'root_conflict' | 'consistency_failed';

const advanceKindCategory: Record<C2spCheckpointAdvanceKind, LifecycleErrorCategory> = {
  rollback: 'LOG_ROLLBACK',
  root_conflict: 'LOG_FORK',
  consistency_failed: 'LOG_INCONSISTENT',
};

/** The subset of a trusted checkpoint a consistency error records. */
export interface C2spCheckpointSummary {
  origin: string;
  treeSize: number;
  rootHash: Uint8Array;
}

/**
 * A candidate checkpoint violates previously accepted trust. Never transient: retrying must
 * not reset checkpoint trust, and no kind authorizes discarding trusted history.
 *
 * Carries both checkpoints so a consumer can route the failure without matching message text:
 * `LOG_ROLLBACK` (`rollback`) is an availability event to raise with operations and security,
 * `LOG_FORK` (`root_conflict`) is a security event, and `LOG_INCONSISTENT` (`consistency_failed`)
 * leans security. An authorized re-baseline is an explicit administrative decision, never a
 * verification outcome.
 */
export class C2spCheckpointConsistencyError extends C2spTlogVerificationError {
  readonly kind: C2spCheckpointAdvanceKind;
  readonly origin: string;
  readonly trustedTreeSize: number;
  readonly observedTreeSize: number;
  readonly trustedRootHash: Uint8Array;
  readonly observedRootHash: Uint8Array;
  /** True only for `root_conflict`: an observed equal-size root conflict, not proven malice. False never implies the failure is safe. */
  readonly splitView: boolean;

  constructor(message: string, kind: C2spCheckpointAdvanceKind, trusted: C2spCheckpointSummary, observed: C2spCheckpointSummary, cause?: unknown) {
    super(message, advanceKindCategory[kind], cause);
    this.name = 'C2spCheckpointConsistencyError';
    this.kind = kind;
    this.origin = trusted.origin;
    this.trustedTreeSize = trusted.treeSize;
    this.observedTreeSize = observed.treeSize;
    // Copies: an error consumer must not be able to mutate checkpoint-store state through them.
    this.trustedRootHash = Uint8Array.from(trusted.rootHash);
    this.observedRootHash = Uint8Array.from(observed.rootHash);
    this.splitView = kind === 'root_conflict';
  }
}

/**
 * Trusted checkpoint storage is unavailable, corrupt, or refused the write. Non-transient:
 * restore the storage or investigate before retrying, and never substitute empty trust.
 */
export class C2spCheckpointStoreError extends C2spTlogError {
  constructor(message: string, cause?: unknown) {
    super(message, { errorCategory: 'CHECKPOINT_STORE_ERROR', transient: false, cause });
    this.name = 'C2spCheckpointStoreError';
  }
}

/** Adapts a public C2SP boundary failure to the shared SDK log-error taxonomy. */
export function c2spLogError(message: string, cause: unknown, transient: boolean): VerificationError {
  if (cause instanceof VerificationError && cause.code === VerificationCode.LogError) return cause;
  return new VerificationError(message, {
    code: VerificationCode.LogError,
    transient,
    errorCategory: 'INVALID_EVIDENCE',
    cause,
  });
}
