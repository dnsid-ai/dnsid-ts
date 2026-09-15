/**
 * Runtime-neutral SDK entry point for DNSid.
 *
 * `@identity-digital/dnsid` aggregates the DNSid TypeScript packages: it re-exports
 * the full protocol core (`@identity-digital/dnsid-protocol`), the registry client and
 * publishing helpers, the JOSE, HTTP message signatures, and web bot auth
 * profiles, and managed operational key rotation workflows.
 *
 * This root entry point makes no runtime assumptions: callers inject DNS resolution,
 * JSON fetching, key-provider, cache, and log implementations (see
 * {@link createIdentityManager}). Node conveniences — LocalKeyProvider, environment
 * config loading, and Node identity manager factories — live behind the
 * `@identity-digital/dnsid/node` subpath. OIDC support deliberately lives in
 * `@identity-digital/dnsid-oidc` (Node-bound transport) and is not re-exported here.
 *
 * @packageDocumentation
 */
import { IdentityManager, LogRegistry } from '@identity-digital/dnsid-protocol';
import type { DnsidConfig, IdentityManagerDependencies } from '@identity-digital/dnsid-protocol';

export * from '@identity-digital/dnsid-protocol';
export {
  IdentityManager,
  JWKS_MAX_RESPONSE_BYTES,
  STATUS_MAX_RESPONSE_BYTES,
  isTransientVerificationError,
  retryTransientVerification,
  DNSID_VERSION,
  DnsIdTxtRecord,
  JWKS,
  jwkThumbprint,
  jwkSignatureAlg,
  SIGNING_ALGS,
  VerifiedDomain,
  DomainLog,
  DomainSnapshot,
  LogRegistry,
  NoopLogReader,
  InMemoryIdentityCache,
  validateAgentStatus,
  activeStatusDocument,
  ParseError,
  ValidationError,
  VerificationError,
  VerificationCode,
  ArgumentError,
  normalizeFQDN,
  isDomainName,
  parseKeyId,
  toBase64Url,
  fromBase64Url,
  toArrayBuffer,
  parseKaDuration,
  verifyWithKey,
  DNSSECState,
  DNSSECMode,
} from '@identity-digital/dnsid-protocol';
export * as jose from '@identity-digital/dnsid-jose';
export * as httpSignatures from '@identity-digital/dnsid-http-signatures';
export * as registry from '@identity-digital/dnsid-registry';
export * as webBotAuth from '@identity-digital/dnsid-web-bot-auth';
export { JoseProfile, createJoseProfile } from '@identity-digital/dnsid-jose';
export { HttpSignaturesProfile, createHttpSignaturesProfile } from '@identity-digital/dnsid-http-signatures';
export {
  RegistryClient,
  PreparedEventSubmissionError,
  RegistryWorkflowError,
  awaitRegistryManagedPublication,
  publishClientControlledRecord,
  publishToRegistry,
  DEFAULT_REGISTRY_URL,
} from '@identity-digital/dnsid-registry';
export {
  ManagedKeyRotationActivationError,
  ManagedKeyRotationSubmissionError,
  resumeManagedOperationalKeyRotation,
  rotateManagedOperationalKey,
} from './managed-key-rotation.ts';
export type {
  ManagedKeyRotationRegistry,
  ManagedKeyRotationResult,
  ResumeManagedOperationalKeyRotationOptions,
  RotateManagedOperationalKeyOptions,
} from './managed-key-rotation.ts';
export {
  ManagedIssuanceActivationError,
  ManagedIssuanceSubmissionError,
  issueManagedIdentity,
  resumeManagedIssuance,
} from './managed-issuance.ts';
export type {
  IssueManagedIdentityOptions,
  ManagedIssuanceCoordination,
  ManagedIssuanceRegistry,
  ManagedIssuanceState,
  ManagedIssuanceSubmission,
  ResumeManagedIssuanceOptions,
} from './managed-issuance.ts';
export { WebBotAuthProfile, createWebBotAuthProfile } from '@identity-digital/dnsid-web-bot-auth';

/** Runtime-neutral dependencies: DNS and JSON fetching must be injected. */
export type CreateIdentityManagerDependencies =
  IdentityManagerDependencies & Required<Pick<IdentityManagerDependencies, 'dnsResolver' | 'fetchJson'>>;

/**
 * Creates a DNSid IdentityManager from explicitly injected runtime dependencies.
 *
 * The root `@identity-digital/dnsid` entrypoint is runtime-neutral: callers provide DNS, HTTPS/JSON
 * fetching, key storage/signing, cache, and log implementations appropriate for Node,
 * browsers, workers, wallets, HSMs, or application backends. Omit `config.identity` for a
 * verification-only manager (see {@link createIdentityVerifier}).
 *
 * @example
 * ```ts
 * import { createIdentityManager } from '@identity-digital/dnsid';
 *
 * const idm = createIdentityManager({ identity, verification }, {
 *   keyProvider,       // operational key
 *   entityKeyProvider, // entity key
 *   dnsResolver,       // DNSSEC-aware resolver
 *   fetchJson,
 * });
 * const verified = await idm.verifyDomain('agent.example.com');
 * ```
 */
export function createIdentityManager(config: DnsidConfig, deps: CreateIdentityManagerDependencies): IdentityManager {
  return new IdentityManager(config, deps);
}

/**
 * Creates a verification-only IdentityManager: same constructor, `config.identity` omitted.
 *
 * The returned manager supports identity verification, verified log loading, and cache
 * eviction. Local signing, publication, and lifecycle mutation methods throw ArgumentError.
 */
export function createIdentityVerifier(
  config: Omit<DnsidConfig, 'identity'>,
  deps: Omit<CreateIdentityManagerDependencies, 'keyProvider' | 'entityKeyProvider'>,
): IdentityManager {
  return new IdentityManager(config, deps);
}

export { SDK_CONFORMANCE } from './conformance.ts';
export type { SDKConformance } from './conformance.ts';
