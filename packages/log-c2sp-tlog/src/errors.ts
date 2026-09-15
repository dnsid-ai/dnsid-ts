import {
  VerificationCode,
  VerificationError,
  type LifecycleErrorCategory,
} from '@identity-digital/dnsid-protocol';

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

  constructor(message: string, errorCategory: LifecycleErrorCategory = 'INVALID_EVIDENCE') {
    super(message, { errorCategory });
    this.name = 'C2spTlogVerificationError';
    this.errorCategory = errorCategory;
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
