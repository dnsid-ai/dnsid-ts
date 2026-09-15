import type {
  DnsidConfig,
  IdentityConfig,
  TransportConfig,
  TrustedEntity,
  VerificationConfig,
  LogRef,
  DnsIdJWK,
  AgentStatus,
  TLSCertificate,
  TXTRecord,
} from './types.ts';
import { withVerificationBudget, waitForVerification, type VerificationOptions } from './verification-budget.ts';

interface SharedVerification {
  promise: Promise<VerifiedDomain>;
  controller: AbortController;
  callers: number;
  finished?: boolean;
}

import { DNSSECState, DNSSECMode } from './types.ts';
import { validateAgentStatus } from './agent-status.ts';
import type { KeyProvider } from './key-provider.ts';
import type { DNSResolver } from './dns-resolver.ts';
import type { IdentityCache } from './identity-cache.ts';
import { InMemoryIdentityCache } from './identity-cache.ts';
import { LogRegistry, NoopLogReader } from './log-registry.ts';
import type { Log, LogReader, LogSignerRole } from './log.ts';
export type { LogSignerRole } from './log.ts';
import type { LogEvent, IssuanceEvent, KeyRotationEvent } from './log-events.ts';
import { DEFAULT_PUBLISH_PROFILE, DnsIdTxtRecord, SUPPORTED_PUBLISH_PROFILES } from './txt-record.ts';
import { JWKS, jwkThumbprint, jwkSignatureAlg } from './jwks.ts';
import { VerifiedDomain, DomainLog } from './verified-domain.ts';
import { ArgumentError, ValidationError, VerificationError, VerificationCode } from './errors.ts';
import {
  normalizeFQDN,
  isDomainName,
  toBase64Url,
  fromBase64Url,
  parseKaDuration,
  verifyWithKey,
  matchesDnsName,
} from './utils.ts';

export interface FetchResult {
  data: unknown;
  tlsCert: TLSCertificate;
}

export interface OperationalKeyRotationOptions {
  /** Publishes the pending operational JWKS at the configured ku endpoint before continuity is appended. */
  publishKeySet: (keySet: JWKS) => Promise<void>;
  timestamp?: Date;
}

export interface OperationalKeyRotationResult {
  event: KeyRotationEvent;
  logRef: LogRef;
  keySet: JWKS;
}

export const JWKS_MAX_RESPONSE_BYTES = 256 * 1024;
export const STATUS_MAX_RESPONSE_BYTES = 16 * 1024;

export interface JsonFetchOptions {
  signal?: AbortSignal;
  allowedHost?: string;
  domainBoundary?: boolean;
  maxResponseBytes?: number;
}

export type JsonFetcher = (url: string, opts?: JsonFetchOptions) => Promise<FetchResult>;

/** Runtime objects injected into {@link IdentityManager}. Configuration data lives in {@link DnsidConfig}. */
export interface IdentityManagerDependencies {
  /** Local operational signer. Required with `config.identity`; rejected without it. */
  keyProvider?: KeyProvider;
  /** Accountable-entity key provider for `_dnsid` signing and lifecycle events. Rejected without `config.identity`. */
  entityKeyProvider?: KeyProvider;
  logRegistry?: LogRegistry;
  dnsResolver?: DNSResolver;
  cache?: IdentityCache;
  fetchJson?: JsonFetcher;
}

export interface IdentityResolver {
  verifyDomain(domain: string, peerCert?: TLSCertificate, options?: VerificationOptions): Promise<VerifiedDomain>;
}

export interface SigningIdentityManager extends IdentityResolver {
  config: { identity?: { domain: string } };
  getKeyProvider(): KeyProvider;
}

/** Returns `config.identity.domain` or throws `ArgumentError` for verification-only managers. */
export function requireLocalDomain(manager: SigningIdentityManager): string {
  const domain = manager.config.identity?.domain;
  if (!domain) throw new ArgumentError('a local identity (config.identity) is required');
  return domain;
}

function sgError(message: string): VerificationError {
  return new VerificationError(message, { code: VerificationCode.SignatureInvalid });
}

function verifyMtlsPeer(record: DnsIdTxtRecord, domain: string, peerCert?: TLSCertificate): void {
  if (!record.policyFlags().has('mtls')) return;
  if (!peerCert) {
    throw new VerificationError('fl=mtls: peer certificate is required', {
      code: VerificationCode.TLSError,
    });
  }
  if (!matchesDnsName(peerCert.san, domain)) {
    throw new VerificationError(
      `fl=mtls: peer certificate SAN does not match agent FQDN ${domain}`,
      { code: VerificationCode.TLSError },
    );
  }
}

/** Verifies a draft-01 bare base64url signature using the current ek key. */
async function verifyDraft01RecordSignature(sg: string, canonicalBytes: Uint8Array, ekJwks: JWKS): Promise<DnsIdJWK> {
  const key = ekJwks.currentRecordSigningKey();
  let sigBytes: Uint8Array;
  try { sigBytes = fromBase64Url(sg); } catch {
    throw sgError('sg is not valid unpadded base64url');
  }
  if (sg.includes('=') || toBase64Url(sigBytes) !== sg) throw sgError('sg is not valid unpadded base64url');
  if (!await verifyWithKey(canonicalBytes, sigBytes, key, jwkSignatureAlg(key))) {
    throw sgError('_dnsid record signature invalid');
  }
  return key;
}

/** Wraps validateAgentStatus, converting ValidationError to VerificationError for internal use. */
function parseAgentStatus(data: unknown): AgentStatus {
  try {
    return validateAgentStatus(data);
  } catch (e) {
    if (e instanceof ValidationError) {
      throw new VerificationError(e.message, { code: VerificationCode.RecordInvalid });
    }
    throw e;
  }
}

type LogCanonicalizer = Pick<LogReader, 'canonical'> & {
  additionalSignerRoles?(event: LogEvent): LogSignerRole[];
};

const IDENTITY_KEYS = ['domain', 'governanceId', 'logRef', 'statusUrl', 'policyFlags', 'maxKeyAge', 'ekUrl', 'kuUrl', 'publishProfile', 'capabilitiesUrl'];
const VERIFICATION_KEYS = ['statusCheckInterval', 'dnssecMode', 'trustedEntities'];
const TRANSPORT_KEYS = ['dnsServer', 'caBundlePath'];
const THUMBPRINT_RE = /^[A-Za-z0-9_-]{43}$/;

function requireObject(value: unknown, path: string, allowed: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ArgumentError(`${path} must be an object`);
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new ArgumentError(`${path} has unknown field "${key}"`);
  }
  return value as Record<string, unknown>;
}

function optionalString(raw: Record<string, unknown>, path: string, key: string): string | undefined {
  const value = raw[key];
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new ArgumentError(`${path}.${key} must be a string`);
  return value;
}

function validateIdentity(value: unknown): IdentityConfig {
  const raw = requireObject(value, 'config.identity', IDENTITY_KEYS);
  const str = (key: string) => optionalString(raw, 'config.identity', key);
  for (const key of ['domain', 'governanceId', 'logRef', 'statusUrl']) {
    if (!str(key)) throw new ArgumentError(`config.identity.${key} is required`);
  }
  let domain: string;
  try {
    domain = normalizeFQDN(raw.domain as string, true);
  } catch (e) {
    throw new ArgumentError(`config.identity.domain is not a valid agent FQDN: ${(e as Error).message}`);
  }
  let governanceId = raw.governanceId as string;
  if (isDomainName(governanceId)) {
    try {
      governanceId = normalizeFQDN(governanceId);
    } catch (e) {
      throw new ArgumentError(`config.identity.governanceId is not a valid FQDN: ${(e as Error).message}`);
    }
  }
  const identity: Record<string, unknown> = { domain, governanceId, logRef: raw.logRef, statusUrl: raw.statusUrl };
  for (const key of ['policyFlags', 'maxKeyAge', 'ekUrl', 'kuUrl', 'publishProfile', 'capabilitiesUrl']) {
    const v = str(key);
    if (v !== undefined) identity[key] = v;
  }
  return Object.freeze(identity as unknown as IdentityConfig);
}

function validateTrustedEntities(value: unknown): readonly TrustedEntity[] {
  if (!Array.isArray(value)) throw new ArgumentError('config.verification.trustedEntities must be an array');
  const seen = new Set<string>();
  return Object.freeze(value.map((entry, i) => {
    const path = `config.verification.trustedEntities[${i}]`;
    const raw = requireObject(entry, path, ['governanceId', 'entityKeyThumbprints']);
    if (typeof raw.governanceId !== 'string') throw new ArgumentError(`${path}.governanceId must be a string`);
    let governanceId: string;
    try {
      governanceId = normalizeFQDN(raw.governanceId);
    } catch (e) {
      throw new ArgumentError(`${path}.governanceId is not a valid domain: ${(e as Error).message}`);
    }
    if (seen.has(governanceId)) throw new ArgumentError(`${path}.governanceId duplicates an earlier entry`);
    seen.add(governanceId);
    const result: TrustedEntity = { governanceId };
    if (raw.entityKeyThumbprints !== undefined) {
      const pins = raw.entityKeyThumbprints;
      if (!Array.isArray(pins) || pins.length === 0) throw new ArgumentError(`${path}.entityKeyThumbprints must be a non-empty array`);
      // 43 unpadded base64url chars = 32 bytes; the last char must not carry non-zero trailing bits.
      if (pins.some(p => typeof p !== 'string' || !THUMBPRINT_RE.test(p) || !'AEIMQUYcgkosw048'.includes(p[42]!))) {
        throw new ArgumentError(`${path}.entityKeyThumbprints must contain canonical base64url SHA-256 thumbprints`);
      }
      if (new Set(pins).size !== pins.length) throw new ArgumentError(`${path}.entityKeyThumbprints contains duplicates`);
      result.entityKeyThumbprints = Object.freeze([...pins]) as string[];
    }
    return Object.freeze(result);
  }));
}

function validateVerification(value: unknown): VerificationConfig {
  const raw = requireObject(value, 'config.verification', VERIFICATION_KEYS);
  const verification: VerificationConfig = {};
  if (raw.statusCheckInterval !== undefined) {
    const n = raw.statusCheckInterval;
    if (typeof n !== 'number' || !Number.isFinite(n) || n < 0) throw new ArgumentError('config.verification.statusCheckInterval must be a finite non-negative number');
    verification.statusCheckInterval = n;
  }
  if (raw.dnssecMode !== undefined) {
    if (!Object.values(DNSSECMode).includes(raw.dnssecMode as DNSSECMode)) throw new ArgumentError(`config.verification.dnssecMode must be one of ${Object.values(DNSSECMode).join(', ')}`);
    verification.dnssecMode = raw.dnssecMode as DNSSECMode;
  }
  if (raw.trustedEntities !== undefined) verification.trustedEntities = validateTrustedEntities(raw.trustedEntities) as TrustedEntity[];
  return Object.freeze(verification);
}

function validateTransport(value: unknown): TransportConfig {
  const raw = requireObject(value, 'config.transport', TRANSPORT_KEYS);
  const transport: TransportConfig = {};
  for (const key of ['dnsServer', 'caBundlePath'] as const) {
    const v = optionalString(raw, 'config.transport', key);
    if (v !== undefined) transport[key] = v;
  }
  return Object.freeze(transport);
}

/**
 * Validates and snapshots a {@link DnsidConfig}. Shared by every constructor and loader so all
 * initialization paths apply identical defaults and rejections.
 */
export function validateDnsidConfig(config: unknown = {}): DnsidConfig {
  const raw = requireObject(config, 'config', ['identity', 'verification', 'transport']);
  return Object.freeze({
    identity: raw.identity === undefined ? undefined : validateIdentity(raw.identity),
    verification: validateVerification(raw.verification ?? {}),
    transport: validateTransport(raw.transport ?? {}),
  });
}

/**
 * Core DNSid protocol facade.
 *
 * This package-local version intentionally exposes only DNSid protocol-core methods.
 * JWT/JWS, HTTP Message Signatures, transport, registry workflows, and
 * concrete key storage live in sibling packages.
 */
export class IdentityManager implements IdentityResolver {
  /** Validated immutable snapshot. `identity` is absent for verification-only managers. */
  public readonly config: DnsidConfig & { verification: VerificationConfig; transport: TransportConfig };
  private readonly keyProvider: KeyProvider | null;
  private readonly entityKeyProvider: KeyProvider | null;
  private readonly localLogBinding: LogCanonicalizer | null;
  private readonly localLog: Log | null;
  private readonly logRegistry: LogRegistry | null;
  private readonly dnsResolver: DNSResolver | null;
  private readonly cache: IdentityCache;
  private readonly fetchJson: JsonFetcher | null;
  private readonly inFlightVerifications = new Map<string, SharedVerification>();
  private readonly inFlightStatusRefreshes = new Map<string, SharedVerification>();

  /**
   * @param config - Data-only configuration; omit `identity` for a verification-only manager.
   * @param deps - Injected runtime objects. The protocol core has no default DNS/HTTPS
   *   implementations, so `config.transport` settings have no consumer here and are rejected;
   *   runtime factories (for example `@identity-digital/dnsid/node`) consume them before delegating.
   */
  constructor(config: DnsidConfig = {}, deps: IdentityManagerDependencies = {}) {
    this.config = validateDnsidConfig(config) as typeof this.config;
    const { keyProvider, entityKeyProvider, logRegistry, dnsResolver, cache, fetchJson } = deps;
    if (this.config.identity) {
      if (!keyProvider) throw new ArgumentError('deps.keyProvider is required when config.identity is set');
    } else if (keyProvider || entityKeyProvider) {
      throw new ArgumentError('key providers have no consumer without config.identity');
    }
    if (this.config.transport.dnsServer !== undefined) throw new ArgumentError('config.transport.dnsServer has no SDK-managed consumer here; inject dnsResolver and fetchJson or use a runtime factory');
    if (this.config.transport.caBundlePath !== undefined) throw new ArgumentError('config.transport.caBundlePath has no SDK-managed consumer here; inject fetchJson or use a runtime factory');
    this.keyProvider = keyProvider ?? null;
    this.entityKeyProvider = entityKeyProvider ?? null;
    this.logRegistry = logRegistry?.snapshot() ?? null;
    const backend = cache ?? new InMemoryIdentityCache();
    const namespace = crypto.randomUUID();
    this.cache = {
      get: domain => backend.get(`${namespace}:${domain}`),
      put: (domain, result) => backend.put(`${namespace}:${domain}`, result),
      evict: domain => backend.evict(`${namespace}:${domain}`),
    };

    if (this.config.identity && logRegistry) {
      let reader;
      try {
        reader = logRegistry.newReader(this.config.identity.logRef);
      } catch (e) {
        throw new ArgumentError(`config.identity.logRef is malformed: ${(e as Error).message}`);
      }
      this.localLogBinding = reader;
      this.localLog = typeof (reader as unknown as Partial<Log>).writeEvent === 'function' ? reader as unknown as Log : null;
    } else {
      this.localLogBinding = null;
      this.localLog = null;
    }

    this.dnsResolver = dnsResolver ?? null;
    this.fetchJson = fetchJson ?? null;
  }

  getKeyProvider(): KeyProvider {
    return this.requireKeyProvider();
  }

  private requireKeyProvider(): KeyProvider {
    if (!this.keyProvider) throw new ArgumentError('local signing requires a keyProvider');
    return this.keyProvider;
  }

  private requireIdentity(): IdentityConfig {
    if (!this.config.identity) throw new ArgumentError('this operation requires a local identity (config.identity)');
    return this.config.identity;
  }

  /** Signs and appends a lifecycle event to the local identity log. */
  async signAndWriteEvent(event: LogEvent): Promise<LogRef> {
    for (const role of this.requiredLogSignatures(event)) {
      if (!this.hasLogSignature(event, role)) await this.signEvent(event, role);
    }
    return this.writeSignedEvent(event);
  }

  async canonicalizeLogEvent(event: LogEvent): Promise<Uint8Array> {
    if (!this.localLogBinding) throw new ArgumentError('local log binding is required');
    return this.localLogBinding.canonical(event);
  }

  requiredLogSignatures(event: LogEvent): LogSignerRole[] {
    return this.requiredLogSignaturesFor(event, this.localLogBinding);
  }

  private requiredLogSignaturesFor(event: LogEvent, binding: LogCanonicalizer | null): LogSignerRole[] {
    const base: LogSignerRole[] = event.type === 'ISSUANCE'
      ? ['Entity', 'OperationalCountersignature']
      : event.type === 'KEY_ROTATION'
        ? ['PreviousOperational']
        : ['Entity'];
    return [...new Set([...base, ...(binding?.additionalSignerRoles?.(event) ?? [])])];
  }

  async signEvent(event: LogEvent, role: LogSignerRole): Promise<LogEvent> {
    const provider = role === 'Entity' ? this.entityKeyProvider : this.keyProvider;
    if (!provider) {
      throw new ArgumentError(role === 'Entity'
        ? 'draft-01 event signing requires entityKeyProvider'
        : 'local event signing requires a keyProvider');
    }
    return this.signEventWithProvider(event, role, provider);
  }

  async signEventWithProvider(
    event: LogEvent,
    role: LogSignerRole,
    keyProvider: KeyProvider,
    logBinding: (Pick<LogReader, 'canonical'> & {
      additionalSignerRoles?(event: LogEvent): LogSignerRole[];
    }) | null = this.localLogBinding,
  ): Promise<LogEvent> {
    if (!logBinding) throw new ArgumentError('local log binding is required');
    if (!this.requiredLogSignaturesFor(event, logBinding).includes(role)) throw new ArgumentError(`${role} is not an authorized signer role for ${event.type}`);
    const canonical = await logBinding.canonical(event);
    if (role === 'Entity') {
      const key = await keyProvider.signingKey();
      if (event.type === 'ISSUANCE') await this.assertIssuanceEntityKey(event, key);
      event.signingKid = key.kid;
      event.sig = toBase64Url(await keyProvider.sign(canonical));
    } else if (role === 'OperationalCountersignature') {
      if (event.type !== 'ISSUANCE') throw new ArgumentError('operational countersignature is only valid for ISSUANCE');
      const key = await keyProvider.signingKey();
      await this.assertIssuanceOperationalKey(event, key);
      event.operationalCountersig = toBase64Url(await keyProvider.sign(canonical));
    } else if (role === 'PreviousOperational') {
      if (event.type !== 'KEY_ROTATION') throw new ArgumentError('previous-operational signature is only valid for KEY_ROTATION');
      const key = await keyProvider.jwk(event.previousOperationalKid);
      if (event.previousOperationalThumbprint !== await jwkThumbprint(key)) throw new ArgumentError('KEY_ROTATION previous operational key metadata mismatch');
      if (event.newOperationalKid !== event.newOperationalPublicKey.kid
        || event.newOperationalAlg !== event.newOperationalPublicKey.alg
        || event.newOperationalThumbprint !== await jwkThumbprint(event.newOperationalPublicKey)) {
        throw new ArgumentError('KEY_ROTATION new operational key metadata mismatch');
      }
      event.signingKid = key.kid;
      event.sig = toBase64Url(await keyProvider.signKey(key.kid, canonical));
    } else if (role === 'NewOperational') {
      if (event.type !== 'KEY_ROTATION') throw new ArgumentError('new-operational signature is only valid for KEY_ROTATION');
      const key = await keyProvider.jwk(event.newOperationalKid);
      if (event.newOperationalKid !== key.kid
        || event.newOperationalAlg !== key.alg
        || event.newOperationalThumbprint !== await jwkThumbprint(key)) {
        throw new ArgumentError('KEY_ROTATION new operational key metadata mismatch');
      }
      event.newOperationalProof = toBase64Url(await keyProvider.signKey(key.kid, canonical));
    }
    return event;
  }

  async writeSignedEvent(event: LogEvent): Promise<LogRef> {
    if (!this.localLog) throw new ArgumentError('local write log is required');
    for (const role of this.requiredLogSignatures(event)) {
      if (!this.hasLogSignature(event, role)) throw new ArgumentError(`missing required ${role} signature for ${event.type}`);
    }
    return this.localLog.writeEvent(event);
  }

  private hasLogSignature(event: LogEvent, role: LogSignerRole): boolean {
    if (role === 'OperationalCountersignature') return !!event.operationalCountersig;
    if (role === 'NewOperational') return event.type === 'KEY_ROTATION' && !!event.newOperationalProof;
    return !!event.sig;
  }

  private async assertIssuanceEntityKey(event: Extract<LogEvent, { type: 'ISSUANCE' }>, key: DnsIdJWK): Promise<void> {
    if (event.initialEntityKid !== key.kid || event.initialEntityAlg !== key.alg || event.initialEntityThumbprint !== await jwkThumbprint(key)) {
      throw new ArgumentError('ISSUANCE entity key metadata does not match the active entity key');
    }
  }

  private async assertIssuanceOperationalKey(event: Extract<LogEvent, { type: 'ISSUANCE' }>, key: DnsIdJWK): Promise<void> {
    if (event.initialOperationalKid !== key.kid || event.initialOperationalAlg !== key.alg || event.initialOperationalThumbprint !== await jwkThumbprint(key)) {
      throw new ArgumentError('ISSUANCE operational key metadata does not match the active operational key');
    }
  }

  /** Returns the local identity's operational public key set for ku JWKS publication. */
  async getKeySet(): Promise<JWKS> {
    const jwks = new JWKS([await this.requireKeyProvider().signingKey()]);
    jwks.validateOperational();
    return jwks;
  }

  /** Returns the accountable-entity public key set for ek JWKS publication. */
  async getEntityKeySet(): Promise<JWKS> {
    if (!this.entityKeyProvider) throw new ArgumentError('draft-01 GetEntityKeySet requires entityKeyProvider');
    const jwks = new JWKS([await this.entityKeyProvider.signingKey()]);
    jwks.validateRecordSigning();
    return jwks;
  }

  /** Runs the draft-01 operational-key rotation transaction. */
  async rotateOperationalKey(options: OperationalKeyRotationOptions): Promise<OperationalKeyRotationResult> {
    const keyProvider = this.requireKeyProvider();
    const previousKey = await keyProvider.signingKey();
    new JWKS([previousKey]).validateOperational();
    const newKid = await keyProvider.generateKey();
    const newKey = await keyProvider.jwk(newKid);
    const keySet = new JWKS([newKey]);
    keySet.validateOperational();
    const timestamp = options.timestamp ?? new Date(Math.floor(Date.now() / 1000) * 1000);
    if (!Number.isFinite(timestamp.getTime())) throw new ArgumentError('rotation timestamp is invalid');

    const event: KeyRotationEvent = {
      type: 'KEY_ROTATION',
      domain: this.requireIdentity().domain,
      previousOperationalKid: previousKey.kid,
      previousOperationalThumbprint: await jwkThumbprint(previousKey),
      newOperationalKid: newKey.kid,
      newOperationalAlg: newKey.alg!,
      newOperationalPublicKey: newKey,
      newOperationalThumbprint: await jwkThumbprint(newKey),
      timestamp,
    };
    await options.publishKeySet(keySet);
    const logRef = await this.signAndWriteEvent(event);
    await keyProvider.activate(newKid);
    await keyProvider.supersede(previousKey.kid);
    return { event, logRef, keySet };
  }

  /** Builds and signs the `_dnsid` TXT record for DNS publication. */
  async createTxtRecord(): Promise<string> {
    const keyProvider = this.requireKeyProvider();
    const record = this.createUnsignedTxtRecord();
    if (!this.entityKeyProvider) throw new ArgumentError('draft-01 CreateTxtRecord requires entityKeyProvider');
    const canonicalBytes = new TextEncoder().encode(record.canonical());
    const signingKey = await this.entityKeyProvider.signingKey();
    const agentKey = await keyProvider.signingKey();
    new JWKS([signingKey]).validateRecordSigning();
    new JWKS([agentKey]).validateOperational();
    if (await jwkThumbprint(signingKey) === await jwkThumbprint(agentKey)) {
      throw new ArgumentError('draft-01 entity and agent keys must be distinct');
    }
    record.sg = toBase64Url(await this.entityKeyProvider.sign(canonicalBytes));

    return record.serialize();
  }

  private createUnsignedTxtRecord(): DnsIdTxtRecord {
    const { domain, governanceId, logRef, statusUrl, ekUrl, kuUrl, publishProfile, policyFlags, maxKeyAge, capabilitiesUrl } =
      this.requireIdentity();
    const profile = publishProfile ?? DEFAULT_PUBLISH_PROFILE;
    if (!SUPPORTED_PUBLISH_PROFILES.includes(profile as typeof SUPPORTED_PUBLISH_PROFILES[number])) {
      throw new ArgumentError(`unsupported DNSid publish profile: ${profile}`);
    }
    if (!ekUrl || !kuUrl) throw new ArgumentError('draft-01 publishing requires ekUrl and kuUrl');

    const record = new DnsIdTxtRecord();
    record.v = profile;
    record.gi = governanceId;
    record.ek = ekUrl;
    record.ku = kuUrl;
    record.lr = logRef;
    record.su = statusUrl;
    record.agentFQDN = domain;
    if (policyFlags)     record.fl = policyFlags;
    if (maxKeyAge)       record.ka = maxKeyAge;
    if (capabilitiesUrl) record.cu = capabilitiesUrl;

    try {
      record.validate();
    } catch (e) {
      throw new ArgumentError(`invalid TXT record configuration: ${(e as Error).message}`);
    }
    return record;
  }

  /**
   * Verifies a DNSid identity according to the protocol, then enforces configured
   * `trustedEntities` acceptance. Acceptance runs per invocation, including cache hits,
   * and is never cached; a denial leaves valid protocol evidence cached.
   */
  async verifyDomain(domain: string, peerCert?: TLSCertificate, options: VerificationOptions = {}): Promise<VerifiedDomain> {
    return withVerificationBudget(signal => this.verifyDomainWithinBudget(domain, peerCert, signal, true), options);
  }

  /**
   * Protocol-only verification used to confirm registry-managed publication of the local
   * identity. Skips counterparty acceptance, so it is restricted to `config.identity.domain`:
   * it cannot verify a counterparty and is never an acceptance decision.
   * @internal
   */
  async verifyPublicationEvidence(domain: string, options: VerificationOptions = {}): Promise<VerifiedDomain> {
    const local = this.requireIdentity().domain;
    let requested: string;
    try {
      requested = normalizeFQDN(domain);
    } catch (e) {
      throw new ArgumentError(`domain is not a valid FQDN: ${(e as Error).message}`);
    }
    if (requested !== local) {
      throw new ArgumentError(`publication evidence is only available for the local identity ${local}, not ${requested}`);
    }
    return withVerificationBudget(signal => this.verifyDomainWithinBudget(requested, undefined, signal, false), options);
  }

  private async verifyDomainWithinBudget(domain: string, peerCert: TLSCertificate | undefined, signal: AbortSignal, enforceAcceptance: boolean): Promise<VerifiedDomain> {
    try {
      domain = normalizeFQDN(domain);
    } catch (e) {
      throw new ArgumentError(`domain is not a valid FQDN: ${(e as Error).message}`);
    }

    // Shared/coalesced work ends here; everything below is per-invocation policy.
    const result = await this.verifyReusableIdentity(domain, peerCert, signal);
    verifyMtlsPeer(result.record, domain, peerCert);
    if (enforceAcceptance) this.enforceCounterpartyAcceptance(result);
    this.requireFreshEvidence(result);
    return result;
  }

  /** Static allowlist / key-pin check. No policy configured means no decision; `[]` denies all. */
  private enforceCounterpartyAcceptance(result: VerifiedDomain): void {
    const policy = this.config.verification.trustedEntities;
    if (!policy) return;
    const governanceId = result.record.governanceId();
    const thumbprint = result.signingKeyThumbprint;
    const entry = policy.find(e => e.governanceId === governanceId);
    if (entry && (!entry.entityKeyThumbprints || entry.entityKeyThumbprints.includes(thumbprint))) return;
    throw new VerificationError(
      `counterparty not accepted: governance ID ${governanceId} with entity key ${thumbprint}`,
      { code: VerificationCode.CounterpartyNotAccepted, verifiedGovernanceId: governanceId, verifiedEntityKeyThumbprint: thumbprint },
    );
  }

  private async verifyReusableIdentity(domain: string, peerCert: TLSCertificate | undefined, signal: AbortSignal): Promise<VerifiedDomain> {
    const cached = this.cache.get(domain);
    if (cached) {
      verifyMtlsPeer(cached.record, domain, peerCert);
      const statusCheckIntervalMs = (this.config.verification.statusCheckInterval ?? 0) * 1000;
      if (statusCheckIntervalMs > 0 && Date.now() - cached.lastStatusCheckAt.getTime() < statusCheckIntervalMs) {
        return cached;
      }
      return this.joinShared(this.inFlightStatusRefreshes.get(domain) ?? this.startShared(this.inFlightStatusRefreshes, domain, child => this.refreshStatus(domain, cached, child)), signal);
    }

    const existing = this.inFlightVerifications.get(domain);
    if (existing) {
      const result = await this.joinShared(existing, signal);
      // Zero-TTL evidence belongs only to the operation that acquired it.
      if (result.dnsTTL > 0) return result;
      return this.verifyDomainUncached(domain, signal);
    }

    return this.joinShared(this.startShared(this.inFlightVerifications, domain, child => this.verifyDomainUncached(domain, child)), signal);
  }

  private startShared(map: Map<string, SharedVerification>, domain: string, operation: (signal: AbortSignal) => Promise<VerifiedDomain>): SharedVerification {
    const controller = new AbortController();
    const shared = { controller, callers: 0 } as SharedVerification;
    // ponytail: shared work has a 30s cap; expose a worker budget if longer scans become necessary.
    shared.promise = withVerificationBudget(operation, { signal: controller.signal }).then(result => {
      if (!controller.signal.aborted && map.get(domain) === shared) this.cache.put(domain, result);
      return result;
    }).catch(error => {
      if (map.get(domain) === shared && error instanceof VerificationError && error.code === VerificationCode.StatusNotActive) this.cache.evict(domain);
      throw error;
    }).finally(() => { shared.finished = true; if (map.get(domain) === shared) map.delete(domain); });
    map.set(domain, shared);
    return shared;
  }

  private async joinShared(shared: SharedVerification, signal: AbortSignal): Promise<VerifiedDomain> {
    shared.callers++;
    try { return await waitForVerification(() => shared.promise, signal); }
    finally { if (--shared.callers === 0 && !shared.finished) shared.controller.abort(); }
  }

  private async refreshStatus(domain: string, cached: VerifiedDomain, signal: AbortSignal): Promise<VerifiedDomain> {
    let status: AgentStatus;
    try {
      const { data } = await this.fetchProtocolJson(cached.record.su, { maxResponseBytes: STATUS_MAX_RESPONSE_BYTES, signal });
      status = parseAgentStatus(data);
    } catch (e) {
      if (e instanceof VerificationError) throw e;
      throw new VerificationError(`status re-fetch failed: ${(e as Error).message}`, {
        code: VerificationCode.StatusUnavailable, transient: true,
      });
    }
    if (status.state !== 'ACTIVE') {
      throw new VerificationError(`agent is not ACTIVE: ${status.state}`, {
        code: VerificationCode.StatusNotActive,
        agentState: status.state,
      });
    }

    const refreshed = new VerifiedDomain({
      domain: cached.domain,
      record: cached.record,
      jwks: cached.jwks,
      recordSigningJwks: cached.recordSigningJwks,
      signingKey: cached.signingKey,
      signingKeyThumbprint: cached.signingKeyThumbprint,
      tlsCert: cached.tlsCert,
      recordSigningTlsCert: cached.recordSigningTlsCert,
      registryStatus: status,
      verifiedAt: cached.verifiedAt,
      dnsTTL: cached.dnsTTL,
      dnsExpiresAt: cached.dnsExpiresAt,
      keyBoundAt: cached.keyBoundAt,
      lastStatusCheckAt: new Date(),
      dnssecState: cached.dnssecState,
      logReader: cached.logReader,
    });
    this.requireFreshEvidence(refreshed);
    return refreshed;
  }

  private requireFreshEvidence(result: VerifiedDomain): void {
    const now = Date.now();
    let code: VerificationCode | undefined;
    if ([result.tlsCert, result.recordSigningTlsCert].some(cert =>
      !Number.isFinite(cert.notAfter.getTime()) || now >= cert.notAfter.getTime())) code = VerificationCode.TLSError;
    else if (result.record.ka && now >= result.keyBoundAt.getTime() + parseKaDuration(result.record.ka)) code = VerificationCode.KeyAgeExceeded;
    else if (result.dnsTTL > 0 && now >= result.dnsExpiresAt.getTime()) code = VerificationCode.DNSResolution;
    if (code) {
      this.cache.evict(result.domain);
      throw new VerificationError('identity evidence expired during verification', { code, transient: code === VerificationCode.DNSResolution });
    }
  }

  private async verifyDomainUncached(domain: string, signal: AbortSignal): Promise<VerifiedDomain> {
    const dnsAcquiredAt = Date.now(); // Lookup start is conservative even for injected resolvers.
    let txtRecords: TXTRecord[];
    let dnssecState: DNSSECState;
    try {
      if (!this.dnsResolver) {
        throw new VerificationError('no DNSResolver configured for protocol verification', {
          code: VerificationCode.DNSResolution,
          transient: false,
        });
      }
      [txtRecords, dnssecState] = await waitForVerification(() => this.dnsResolver!.fetchTXT(`_dnsid.${domain}`, { signal }), signal);
    } catch (e) {
      throw new VerificationError(`DNS lookup failed: ${(e as Error).message}`, {
        code: VerificationCode.DNSResolution, transient: true,
      });
    }

    if (!Object.values(DNSSECState).includes(dnssecState)) {
      throw new VerificationError(`invalid DNSSEC state: ${String(dnssecState)}`, {
        code: VerificationCode.DNSSECFailed,
      });
    }
    if (dnssecState === DNSSECState.FAILED) {
      throw new VerificationError(`DNSSEC validation failed for ${domain}`, {
        code: VerificationCode.DNSSECFailed,
      });
    }
    const mode = this.config.verification.dnssecMode ?? DNSSECMode.auto;
    switch (mode) {
      case DNSSECMode.auto:
        break;
      case DNSSECMode.validated:
        if (dnssecState === DNSSECState.UNKNOWN) {
          throw new VerificationError(`DNSSEC validation state is unknown for ${domain}`, {
            code: VerificationCode.DNSSECFailed,
          });
        }
        break;
      case DNSSECMode.required:
        if (dnssecState !== DNSSECState.VALID) {
          throw new VerificationError(`DNSSEC required but state is ${dnssecState}`, {
            code: VerificationCode.DNSSECFailed,
          });
        }
        break;
      default:
        throw new VerificationError(`invalid DNSSEC mode: ${String(mode)}`, {
          code: VerificationCode.DNSSECFailed,
        });
    }

    if (txtRecords.length === 0) {
      throw new VerificationError(`no _dnsid TXT record found for ${domain}`, {
        code: VerificationCode.DNSResolution,
      });
    }
    if (txtRecords.length !== 1) {
      throw new VerificationError(
        `expected exactly one _dnsid TXT record, got ${txtRecords.length}`,
        { code: VerificationCode.RecordInvalid },
      );
    }

    const strings = txtRecords[0]!.strings;
    if (!Array.isArray(strings) || strings.length > 1024 || strings.some(part => typeof part !== 'string') || strings.reduce((size, part) => size + part.length, 0) > 65535) throw new VerificationError('TXT response exceeds bounds', { code: VerificationCode.RecordInvalid });
    const raw = strings.join('');
    const dnsTTL = txtRecords[0]!.ttl;
    if (!Number.isFinite(dnsTTL) || dnsTTL < 0) throw new VerificationError('invalid DNS TTL', { code: VerificationCode.DNSResolution });
    const dnsExpiresAt = new Date(dnsAcquiredAt + dnsTTL * 1000);
    if (!Number.isFinite(dnsExpiresAt.getTime())) throw new VerificationError('invalid DNS expiry', { code: VerificationCode.DNSResolution });

    let record: DnsIdTxtRecord;
    try {
      record = DnsIdTxtRecord.parse(raw);
    } catch (e) {
      throw new VerificationError(`TXT record parse failed: ${(e as Error).message}`, {
        code: VerificationCode.RecordInvalid,
        cause: e,
      });
    }

    record.agentFQDN = domain;
    try {
      record.validate();
    } catch (e) {
      throw new VerificationError(`TXT record validation failed: ${(e as Error).message}`, {
        code: VerificationCode.RecordInvalid,
        cause: e,
      });
    }

    let recordSigningJwks: JWKS;
    let recordSigningTlsCert: TLSCertificate;
    try {
      const result = await this.fetchProtocolJson(record.signatureVerificationKeyURI(), {
        signal,
        allowedHost: record.signatureVerificationKeyAllowedHost(),
        domainBoundary: true,
        maxResponseBytes: JWKS_MAX_RESPONSE_BYTES,
      });
      const jwksData = result.data as { keys?: unknown[] };
      if (!Array.isArray(jwksData?.keys)) {
        throw new VerificationError('record-signing JWKS response missing keys array', { code: VerificationCode.RecordInvalid });
      }
      recordSigningJwks = new JWKS(jwksData.keys as DnsIdJWK[]);
      recordSigningTlsCert = result.tlsCert;
      await recordSigningJwks.validateRecordSigningKeyset();
    } catch (e) {
      if (e instanceof VerificationError) throw e;
      if (e instanceof ValidationError) {
        throw new VerificationError(`record-signing JWKS validation failed: ${e.message}`, {
          code: VerificationCode.RecordInvalid,
          cause: e,
        });
      }
      throw new VerificationError(`record-signing JWKS fetch failed: ${(e as Error).message}`, {
        code: VerificationCode.TLSError, transient: true,
      });
    }

    const canonicalBytes = new TextEncoder().encode(record.canonical());
    const signingKey = await verifyDraft01RecordSignature(record.sg, canonicalBytes, recordSigningJwks);

    let jwks = recordSigningJwks;
    let tlsCert = recordSigningTlsCert;
    if (record.runtimeKeyURI() !== record.signatureVerificationKeyURI()) {
      try {
        const result = await this.fetchProtocolJson(record.runtimeKeyURI(), {
          signal,
          allowedHost: record.runtimeKeyAllowedHost(),
          maxResponseBytes: JWKS_MAX_RESPONSE_BYTES,
        });
        const jwksData = result.data as { keys?: unknown[] };
        if (!Array.isArray(jwksData?.keys)) {
          throw new VerificationError('runtime JWKS response missing keys array', { code: VerificationCode.RecordInvalid });
        }
        jwks = new JWKS(jwksData.keys as DnsIdJWK[]);
        tlsCert = result.tlsCert;
        jwks.validateOperational();
      } catch (e) {
        if (e instanceof VerificationError) throw e;
        if (e instanceof ValidationError) {
          throw new VerificationError(`runtime JWKS validation failed: ${e.message}`, {
            code: VerificationCode.RecordInvalid,
            cause: e,
          });
        }
        throw new VerificationError(`runtime JWKS fetch failed: ${(e as Error).message}`, {
          code: VerificationCode.TLSError, transient: true,
        });
      }
    }

    // No key published in ek may share an RFC 7638 thumbprint with a ku key.
    const thumbprintOf = async (key: DnsIdJWK, set: string): Promise<string> => {
      try {
        return await jwkThumbprint(key);
      } catch (e) {
        throw new VerificationError(`invalid key in ${set} JWK Set: ${(e as Error).message}`, {
          code: VerificationCode.RecordInvalid, cause: e,
        });
      }
    };
    const ekThumbprints = new Set(await Promise.all(recordSigningJwks.keys.map(k => thumbprintOf(k, 'ek'))));
    for (const key of jwks.keys) {
      if (ekThumbprints.has(await thumbprintOf(key, 'ku'))) {
        throw new VerificationError('ek and ku keys must be distinct', { code: VerificationCode.RecordInvalid });
      }
    }

    let logReader;
    try {
      logReader = this.logRegistry
        ? this.logRegistry.newReader(record.lr, { signal })
        : new NoopLogReader(record.lr.split(':')[0] ?? '');
    } catch (e) {
      throw new VerificationError(`malformed lr in _dnsid record: ${(e as Error).message}`, {
        code: VerificationCode.RecordInvalid,
      });
    }

    // Self-accounted identities have a structural agent-FQDN/gi relationship.
    // Delegated cross-domain identities do not, so verified bilateral ISSUANCE
    // evidence is the only acceptable governance relationship and must fail
    // closed when no implementation for the advertised log method is present.
    if (!record.hasStructuralGovernanceRelationship() && logReader instanceof NoopLogReader) {
      throw new VerificationError(
        'delegated governance relationship requires verified ISSUANCE evidence',
        { code: VerificationCode.LogError, transient: false },
      );
    }

    const operationalKey = jwks.currentOperationalSigningKey();
    const signingKeyThumbprint = await jwkThumbprint(signingKey);
    const operationalThumbprint = await jwkThumbprint(operationalKey);
    if (signingKeyThumbprint === operationalThumbprint) {
      throw new VerificationError('ek and ku keys must be distinct', { code: VerificationCode.RecordInvalid });
    }
    const binding = await waitForVerification(() => logReader.verifyBilateralBinding(record, signingKey, operationalKey), signal);
    await waitForVerification(() => logReader.verifyOperationalContinuity(domain, binding.initialOperationalThumbprint, operationalThumbprint), signal);

    let keyBoundAt = new Date(0);
    if (record.ka) {
      keyBoundAt = await waitForVerification(() => logReader.keyTimestamp(domain, operationalThumbprint), signal);
      if (Date.now() - keyBoundAt.getTime() > parseKaDuration(record.ka)) {
        throw new VerificationError(`signing key exceeds maximum key age ${record.ka}`, {
          code: VerificationCode.KeyAgeExceeded,
        });
      }
    }

    let status: AgentStatus;
    try {
      const { data } = await this.fetchProtocolJson(record.su, { maxResponseBytes: STATUS_MAX_RESPONSE_BYTES, signal });
      status = parseAgentStatus(data);
    } catch (e) {
      if (e instanceof VerificationError) throw e;
      throw new VerificationError(`status fetch failed: ${(e as Error).message}`, {
        code: VerificationCode.StatusUnavailable, transient: true,
      });
    }

    if (status.state !== 'ACTIVE') {
      throw new VerificationError(`agent is not ACTIVE: ${status.state}`, {
        code: VerificationCode.StatusNotActive,
        agentState: status.state,
      });
    }

    const now = new Date();
    const result = new VerifiedDomain({
      domain,
      record,
      jwks,
      recordSigningJwks,
      signingKey,
      signingKeyThumbprint,
      tlsCert,
      recordSigningTlsCert,
      registryStatus: status,
      verifiedAt: now,
      dnsTTL,
      dnsExpiresAt,
      keyBoundAt,
      lastStatusCheckAt: now,
      dnssecState,
      logReader,
    });

    this.requireFreshEvidence(result);
    return result;
  }

  /** Loads the full verified event history for a domain from its bound lifecycle log. */
  async loadDomainLog(vd: VerifiedDomain): Promise<DomainLog> {
    if (vd.logReader instanceof NoopLogReader) {
      const method = vd.record.lr.split(':')[0] ?? 'unknown';
      throw new VerificationError(
        `loadDomainLog: no LogReader registered for method '${method}'; ` +
        'register a factory via LogRegistry.register() before calling loadDomainLog',
        { code: VerificationCode.LogError, transient: false },
      );
    }
    const events = await vd.logReader.rebuildHistory(vd.domain);
    return new DomainLog(vd.domain, events);
  }

  /** Removes a domain from the IdentityManager cache. */
  evictDomain(domain: string): void {
    let normalized: string;
    try {
      normalized = normalizeFQDN(domain);
    } catch (e) {
      throw new ArgumentError(`domain is not a valid FQDN: ${(e as Error).message}`);
    }
    this.inFlightVerifications.delete(normalized);
    this.inFlightStatusRefreshes.delete(normalized);
    this.cache.evict(normalized);
  }

  private async fetchProtocolJson(url: string, opts?: JsonFetchOptions): Promise<FetchResult> {
    if (!this.fetchJson) {
      throw new VerificationError('no JSON fetcher configured for protocol verification', {
        code: VerificationCode.TLSError,
        transient: false,
      });
    }
    return opts?.signal ? waitForVerification(() => this.fetchJson!(url, opts), opts.signal) : this.fetchJson(url, opts);
  }
}

/**
 * Canonical bytes covered by BOTH the entity signature and the operational
 * countersignature of a draft-01 bilateral ISSUANCE event. Both signatures
 * MUST cover identical content, so this is the single source of that content.
 *
 * ponytail: minimal, fixed-order line encoding — no JSON key-ordering traps.
 * Replace with the spec's canonicalization/test vectors once they land.
 */
export function canonicalIssuanceBinding(event: IssuanceEvent): Uint8Array {
  if (!event.entityKey || !event.operationalKey) {
    throw new VerificationError('ISSUANCE binding requires entityKey and operationalKey', {
      code: VerificationCode.RecordInvalid,
    });
  }
  const lines = [
    'DNSID-ISSUANCE-BINDING',
    `domain=${normalizeFQDN(event.domain)}`,
    `gi=${event.governanceId}`,
    `ek=${event.entityKey.thumbprint}`,
    `ku=${event.operationalKey.thumbprint}`,
    `ts=${event.timestamp.toISOString()}`,
  ];
  return new TextEncoder().encode(lines.join('\n'));
}

/**
 * draft-01 step-5 bilateral binding check. ISSUANCE is bilateral: it is only
 * valid when BOTH the accountable-entity record-signing key (ek) and the initial
 * operational key (ku) signed the same canonical binding, and that binding
 * corresponds to the TXT record and current key material.
 *
 * Verifies, against key material recorded IN THE EVENT:
 *  1. Each slot's `thumbprint` equals `jwkThumbprint(jwk)` (the canonical binding
 *     only commits to the thumbprint, so the embedded JWK must be pinned to it).
 *  2. `entitySig` under `entityKey`, and `operationalSig` under `operationalKey`.
 *  3. Same DNSid FQDN and same `gi` as the record.
 *  4. The ISSUANCE-recorded entity key is the key currently at `ek`.
 *
 * It does NOT reject a rotated `ku`: the current operational key may be the
 * initial key OR a key linked to it by KEY_ROTATION continuity. That linkage
 * (and entity KEY_ROTATION linkage) is verified separately by
 * LogReader.verifyOperationalContinuity, which runs unconditionally in the
 * draft-01 path of verifyDomain. The recorded initial operational thumbprint is
 * returned so the caller can hand it to that continuity check.
 */
export async function verifyBilateralBinding(
  event: IssuanceEvent,
  record: DnsIdTxtRecord,
  currentEntityKey: DnsIdJWK,
): Promise<{ initialOperationalThumbprint: string }> {
  if (event.type !== 'ISSUANCE') {
    throw new VerificationError('bilateral binding requires an ISSUANCE event', {
      code: VerificationCode.RecordInvalid,
    });
  }
  const { entityKey, operationalKey, entitySig, operationalSig } = event;
  if (!entityKey || !entitySig) {
    throw new VerificationError('ISSUANCE is missing the entity-key signature', {
      code: VerificationCode.SignatureInvalid,
    });
  }
  if (!operationalKey || !operationalSig) {
    throw new VerificationError('ISSUANCE is missing the operational-key countersignature', {
      code: VerificationCode.SignatureInvalid,
    });
  }

  // 1. Both signatures over the same canonical binding, each against its recorded key.
  //    The canonical binding only commits to slot.thumbprint, so pin the embedded
  //    JWK to that thumbprint before trusting it — otherwise a crafted event could
  //    carry the real thumbprint but a foreign JWK and sign with the foreign key.
  const binding = canonicalIssuanceBinding(event);
  const verifySlot = async (sig: string, slot: { jwk: DnsIdJWK; thumbprint: string; alg: string }, which: string) => {
    if (await jwkThumbprint(slot.jwk) !== slot.thumbprint) {
      throw new VerificationError(`ISSUANCE ${which} key JWK does not match its recorded thumbprint`, {
        code: VerificationCode.RecordInvalid,
      });
    }
    let bytes: Uint8Array;
    try {
      bytes = fromBase64Url(sig);
    } catch {
      throw new VerificationError(`ISSUANCE ${which} signature is not valid base64url`, {
        code: VerificationCode.SignatureInvalid,
      });
    }
    if (!await verifyWithKey(binding, bytes, slot.jwk, slot.alg)) {
      throw new VerificationError(`ISSUANCE ${which} signature is invalid`, {
        code: VerificationCode.SignatureInvalid,
      });
    }
  };
  await verifySlot(entitySig, entityKey, 'entity');
  await verifySlot(operationalSig, operationalKey, 'operational');

  // 2. Correspondence: same DNSid FQDN and same gi.
  if (normalizeFQDN(event.domain) !== normalizeFQDN(record.agentFQDN)) {
    throw new VerificationError('ISSUANCE FQDN does not match the TXT record', {
      code: VerificationCode.RecordInvalid,
    });
  }
  if (event.governanceId !== record.gi) {
    throw new VerificationError('ISSUANCE gi does not match the TXT record', {
      code: VerificationCode.RecordInvalid,
    });
  }

  // 3. Recorded entity key corresponds to the key currently at ek.
  if (await jwkThumbprint(currentEntityKey) !== entityKey.thumbprint) {
    throw new VerificationError('ISSUANCE-recorded entity key does not match the current ek key', {
      code: VerificationCode.RecordInvalid,
    });
  }

  // The current ku may be the initial op key OR a rotated key linked to it by
  // KEY_ROTATION continuity — that is verifyOperationalContinuity's job, not
  // ours. Expose the recorded initial thumbprint so the caller can chain it.
  return { initialOperationalThumbprint: operationalKey.thumbprint };
}
