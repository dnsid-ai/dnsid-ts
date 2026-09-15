/** Machine-readable classification of a DNSid verification failure, carried on {@link VerificationError}. */
export enum VerificationCode {
  /** DNS lookup of the `_dnsid` TXT record failed or returned no identity record. Absence alone is not classified as transient. */
  DNSResolution = 'DNSResolution',
  /** DNSSEC validation failed, or the zone is unsigned when the configured DNSSEC mode requires signing. */
  DNSSECFailed = 'DNSSECFailed',
  /** The identity record or a fetched JWKS is malformed or fails protocol validation. */
  RecordInvalid = 'RecordInvalid',
  /** The identity record signature (or a bilateral binding signature) does not verify against the entity key. */
  SignatureInvalid = 'SignatureInvalid',
  /** An HTTPS fetch of the JWKS or status endpoint failed at the transport/TLS layer. */
  TLSError = 'TLSError',
  /** The operational key is older than the identity record's `ka` maximum key age. */
  KeyAgeExceeded = 'KeyAgeExceeded',
  /** The agent status endpoint is unreachable or returned an unusable response. */
  StatusUnavailable = 'StatusUnavailable',
  /** The agent status document reports a state other than active (e.g. revoked or retired). */
  StatusNotActive = 'StatusNotActive',
  /** A transparency log read, entry check, or consistency verification failed. */
  LogError = 'LogError',
  /** Configured `trustedEntities` policy denied a protocol-valid counterparty. Always permanent. */
  CounterpartyNotAccepted = 'CounterpartyNotAccepted',
}

/** Stable, language-neutral categories used by lifecycle conformance vectors. */
export type LifecycleErrorCategory =
  | 'GENESIS_REQUIRED'
  | 'DUPLICATE_ISSUANCE'
  | 'INVALID_ISSUANCE'
  | 'TERMINAL_STATE'
  | 'DOMAIN_MISMATCH'
  | 'KEY_CONTINUITY'
  | 'INVALID_REVOCATION_REASON'
  | 'INVALID_MIGRATION'
  | 'SNAPSHOT_EMPTY'
  | 'SNAPSHOT_NON_PREFIX'
  | 'UNSUPPORTED_EVENT'
  | 'CHAIN_CONTINUITY'
  | 'INVALID_EVIDENCE'
  | 'INCOMPLETE_STREAM';

/** Thrown when raw input (e.g. a TXT record or duration string) cannot be parsed into its structured form. */
export class ParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ParseError';
  }
}

/** Thrown when parsed data is structurally sound but violates a DNSid protocol constraint. */
export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

/** Initialization options for {@link VerificationError}. */
export interface VerificationErrorInit {
  /** Classification of the failure. */
  code: VerificationCode;
  /** Lifecycle conformance category, when the failure maps to a lifecycle state-machine rule. */
  errorCategory?: LifecycleErrorCategory;
  /** True when retrying the verification may succeed (e.g. network timeouts). Defaults to false. */
  transient?: boolean;
  /** Agent state reported by the status document, when the failure is state-related. */
  agentState?: string;
  /** Observed verified governance ID; set only for `CounterpartyNotAccepted`. */
  verifiedGovernanceId?: string;
  /** Observed verified record-signing key RFC 7638 thumbprint; set only for `CounterpartyNotAccepted`. */
  verifiedEntityKeyThumbprint?: string;
  /** Underlying error, propagated as `Error.cause`. */
  cause?: unknown;
}

/**
 * Thrown when DNSid identity verification fails.
 *
 * Carries a {@link VerificationCode} for programmatic handling and a `transient`
 * flag indicating whether a retry may succeed (see `retryTransientVerification`).
 */
export class VerificationError extends Error {
  /** Classification of the failure. */
  readonly code: VerificationCode;
  /** True when retrying the verification may succeed. */
  readonly transient: boolean;
  /** Agent state reported by the status document, when the failure is state-related. */
  readonly agentState?: string;
  /** Lifecycle conformance category, when the failure maps to a lifecycle state-machine rule. */
  readonly errorCategory?: LifecycleErrorCategory;
  /** Observed verified governance ID (`CounterpartyNotAccepted` only). Never echoes configured policy. */
  readonly verifiedGovernanceId?: string;
  /** Observed verified record-signing key thumbprint (`CounterpartyNotAccepted` only). Never echoes configured pins. */
  readonly verifiedEntityKeyThumbprint?: string;

  constructor(message: string, init: VerificationErrorInit) {
    super(message, { cause: init.cause });
    this.name = 'VerificationError';
    this.code = init.code;
    this.transient = init.transient ?? false;
    this.agentState = init.agentState;
    this.errorCategory = init.errorCategory;
    this.verifiedGovernanceId = init.verifiedGovernanceId;
    this.verifiedEntityKeyThumbprint = init.verifiedEntityKeyThumbprint;
  }
}

/** Thrown when a caller passes an invalid or unusable argument to a DNSid API. */
export class ArgumentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ArgumentError';
  }
}
