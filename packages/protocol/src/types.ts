export enum DNSSECState {
  UNSIGNED = 'UNSIGNED',
  VALID = 'VALID',
  FAILED = 'FAILED',
  UNKNOWN = 'UNKNOWN',
}

export enum DNSSECMode {
  auto = 'auto',
  validated = 'validated',
  required = 'required',
}

export type AgentStatusState =
  | 'PENDING'
  | 'PROVISIONING'
  | 'VERIFYING'
  | 'ACTIVE'
  | 'RETIRED'
  | 'REVOKED';

export type RevocationReason =
  | 'keyCompromise'
  | 'policyViolation'
  | 'superseded'
  | 'cessationOfOperation';

export type MaxKeyAge = '24h' | '7d' | '30d' | '90d';

export interface DnsIdJWK {
  kty: string;
  kid: string;
  /** JOSE algorithm metadata. Required for draft-01 live ek/ku keys. */
  alg?: string;
  use?: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  [key: string]: unknown;
}

export interface AgentStatus {
  state: AgentStatusState;
  lastTransitionAt: Date;
  revocationReason?: RevocationReason;
}

export interface TLSCertificate {
  notAfter: Date;
  san: string[];
}

export type LogRef = string;

export interface TXTRecord {
  strings: string[];
  ttl: number;
}

/** Local identity publication settings (`DnsidConfig.identity`). Contains no verification or transport policy. */
export interface IdentityConfig {
  /** FQDN of the DNSid identity. Normalized with normalizeFQDN on construction. */
  domain: string;
  /** Registrant domain (`gi` tag). */
  governanceId: string;
  /** Log reference for the `lr` tag. Format: `{method}:{entry-ref}`. */
  logRef: string;
  /** HTTPS URL for the lifecycle status endpoint (`su` tag). */
  statusUrl: string;
  /** Comma-separated policy flags for the `fl` tag. */
  policyFlags?: string;
  /** Maximum signing key age for the `ka` tag. */
  maxKeyAge?: MaxKeyAge;
  /** HTTPS URL for the accountable-entity JWKS endpoint (`ek` tag). Required for draft-01 publishing. */
  ekUrl?: string;
  /** HTTPS URL for the identity's operational/runtime JWKS endpoint (`ku` tag). Required for draft-01 publishing. */
  kuUrl?: string;
  /** `_dnsid` behavior profile to emit. Defaults to `dnsid-draft-01`. */
  publishProfile?: string;
  /** HTTPS URL for the capabilities document (`cu` tag). */
  capabilitiesUrl?: string;
}

/** One counterparty allowlist entry. Exact `gi` match; optional pins on the current record-signing key. */
export interface TrustedEntity {
  /** Accountable-entity governance domain. Normalized with normalizeFQDN on construction. */
  governanceId: string;
  /** Unpadded base64url RFC 7638 SHA-256 thumbprints the current `ek` signing key must match. Non-empty when present. */
  entityKeyThumbprints?: string[];
}

/** Protocol verification and counterparty acceptance settings (`DnsidConfig.verification`). */
export interface VerificationConfig {
  /** Maximum age (seconds) of cached status before re-fetching `su`. Default: 0 (re-fetch every call). */
  statusCheckInterval?: number;
  /** DNSSEC enforcement mode. Default: 'auto'. */
  dnssecMode?: DNSSECMode;
  /** Counterparty allowlist. Absent: no acceptance decision. `[]`: deny all. */
  trustedEntities?: TrustedEntity[];
}

/** SDK-managed DNS and HTTPS deployment settings (`DnsidConfig.transport`). Never alters protocol semantics. */
export interface TransportConfig {
  /** Custom DNS server (`host`, `host:port`, or `[ipv6]:port`). Omit to use the system resolver. */
  dnsServer?: string;
  /** Path to a PEM CA bundle appended to the system root certificates for TLS verification. */
  caBundlePath?: string;
  /**
   * Hostnames whose resolved private or loopback addresses the default fetcher may contact. For
   * trusted test and private deployments only.
   */
  allowedUnsafeHosts?: readonly string[];
}

/** Single core configuration entry point. Omit `identity` for a verification-only manager. */
export interface DnsidConfig {
  identity?: IdentityConfig;
  verification?: VerificationConfig;
  transport?: TransportConfig;
}
