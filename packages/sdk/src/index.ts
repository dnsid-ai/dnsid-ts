/**
 * Runtime-neutral SDK entry point for DNSid.
 *
 * `@dnsid-ai/sdk` aggregates the DNSid TypeScript packages: it re-exports
 * the full protocol core (`@dnsid-ai/protocol`), the registry client and
 * publishing helpers, the JOSE, HTTP message signatures, and web bot auth
 * profiles, and managed operational key rotation workflows.
 *
 * This root entry point makes no runtime assumptions: callers inject DNS resolution,
 * JSON fetching, key-provider, cache, and log implementations (see
 * {@link createIdentityManager}). Node conveniences — LocalKeyProvider, environment
 * config loading, and Node identity manager factories — live behind the
 * `@dnsid-ai/sdk/node` subpath. OIDC support deliberately lives in
 * `@dnsid-ai/oidc` (Node-bound transport) and is not re-exported here.
 *
 * @packageDocumentation
 */
import { IdentityManager, LogRegistry } from '@dnsid-ai/protocol';
import type { DnsidConfig, IdentityManagerDependencies } from '@dnsid-ai/protocol';

export * from '@dnsid-ai/protocol';
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
} from '@dnsid-ai/protocol';
export * as jose from '@dnsid-ai/jose';
export * as httpSignatures from '@dnsid-ai/http-signatures';
export * as registry from '@dnsid-ai/registry';
export * as webBotAuth from '@dnsid-ai/web-bot-auth';
export { JoseProfile, createJoseProfile } from '@dnsid-ai/jose';
export { HttpSignaturesProfile, createHttpSignaturesProfile } from '@dnsid-ai/http-signatures';
export {
  RegistryClient,
  PreparedEventSubmissionError,
  RegistryWorkflowError,
  awaitRegistryManagedPublication,
  publishClientControlledRecord,
  publishToRegistry,
  DEFAULT_REGISTRY_URL,
} from '@dnsid-ai/registry';
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
export { WebBotAuthProfile, createWebBotAuthProfile } from '@dnsid-ai/web-bot-auth';

/** Runtime-neutral dependencies: DNS and JSON fetching must be injected. */
export type CreateIdentityManagerDependencies =
  IdentityManagerDependencies & Required<Pick<IdentityManagerDependencies, 'dnsResolver' | 'fetchJson'>>;

/**
 * Creates a DNSid IdentityManager from explicitly injected runtime dependencies.
 *
 * The root `@dnsid-ai/sdk` entrypoint is runtime-neutral: callers provide DNS, HTTPS/JSON
 * fetching, key storage/signing, cache, and log implementations appropriate for Node,
 * browsers, workers, wallets, HSMs, or application backends. Omit `config.identity` for a
 * verification-only manager (see {@link createIdentityVerifier}).
 *
 * @example
 * ```ts
 * import { createIdentityManager } from '@dnsid-ai/sdk';
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
