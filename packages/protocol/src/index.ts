/**
 * Protocol core for the DNSid TypeScript monorepo.
 *
 * `@dnsid-ai/protocol` provides the DNSid protocol engine and contracts:
 * TXT identity record parsing/validation/canonicalization, JWKS validation and
 * thumbprints, the `IdentityManager` verification and lifecycle engine, transparency
 * log contracts, strict agent status validation, and common DNSid error types.
 *
 * The package is runtime-neutral: DNS resolution, JSON fetching, key storage/signing,
 * and caching are injected through the `DNSResolver`, `JsonFetcher`, `KeyProvider`,
 * and `IdentityCache` interfaces. Node conveniences live in `@dnsid-ai/sdk/node`,
 * registry workflows in `@dnsid-ai/registry`.
 *
 * @packageDocumentation
 */
export {
  IdentityManager,
  JWKS_MAX_RESPONSE_BYTES,
  STATUS_MAX_RESPONSE_BYTES,
  verifyBilateralBinding,
  canonicalIssuanceBinding,
  validateDnsidConfig,
  normalizePrivateAddressHost,
  requireLocalDomain,
} from './identity-manager.ts';
export { sha256 as sha256Bytes } from '@noble/hashes/sha2.js';
export { withVerificationBudget, waitForVerification, type VerificationOptions } from './verification-budget.ts';
export { parseJsonNoDuplicateMembers, parseCompactJose, parseJoseObject } from './strict-json.ts';
export { isTransientVerificationError, retryTransientVerification } from './retry.ts';
export type { RetryBackoffOptions } from './retry.ts';
export type {
  FetchResult,
  IdentityManagerDependencies,
  IdentityResolver,
  JsonFetchOptions,
  JsonFetcher,
  SigningIdentityManager,
  LogSignerRole,
  OperationalKeyRotationOptions,
  OperationalKeyRotationResult,
} from './identity-manager.ts';
export {
  DNSID_VERSION,
  DNSID_DRAFT01_VERSION,
  DEFAULT_PUBLISH_PROFILE,
  SUPPORTED_PUBLISH_PROFILES,
  SUPPORTED_VALIDATION_PROFILES,
  DnsIdTxtRecord,
} from './txt-record.ts';
export { JWKS, jwkThumbprint, jwkSignatureAlg, keySetsShareKeyMaterial, SIGNING_ALGS } from './jwks.ts';
export { VerifiedDomain, DomainLog, DomainSnapshot } from './verified-domain.ts';
export { LogRegistry, NoopLogReader } from './log-registry.ts';
export type { Log, LoggedStateEvidence, LogReader } from './log.ts';
export type {
  LogEvent,
  LogEventType,
  IssuanceEvent,
  C2spIssuanceEvent,
  IssuanceKeySlot,
  KeyRotationEvent,
  RevocationEvent,
  RetirementEvent,
  MigrationEvent,
  DelegationEvent,
} from './log-events.ts';
export type { KeyProvider } from './key-provider.ts';
export type { DNSResolver } from './dns-resolver.ts';
export type { IdentityCache } from './identity-cache.ts';
export { InMemoryIdentityCache } from './identity-cache.ts';
export { validateAgentStatus, activeStatusDocument } from './agent-status.ts';
export {
  ParseError,
  ValidationError,
  VerificationError,
  VerificationCode,
  ArgumentError,
} from './errors.ts';
export type { LifecycleErrorCategory } from './errors.ts';
export {
  normalizeFQDN,
  isDomainName,
  parseKeyId,
  toBase64Url,
  fromBase64Url,
  toArrayBuffer,
  parseKaDuration,
  verifyWithKey,
  matchesDnsName,
} from './utils.ts';
export type {
  DnsidConfig,
  IdentityConfig,
  VerificationConfig,
  TransportConfig,
  TrustedEntity,
  DnsIdJWK,
  AgentStatus,
  AgentStatusState,
  RevocationReason,
  MaxKeyAge,
  TLSCertificate,
  LogRef,
  TXTRecord,
} from './types.ts';
export {
  DNSSECState,
  DNSSECMode,
} from './types.ts';
