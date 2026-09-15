/**
 * Registry control-plane client and TXT publishing helpers for DNSid.
 *
 * `@identity-digital/dnsid-registry` owns the DNSid registry API surface:
 * `RegistryClient` (agent registration, verification, lifecycle, prepared C2SP
 * transparency-log events, record signing) plus publication workflows —
 * `publishClientControlledRecord` for client-controlled identity records signed with
 * the entity key, and `awaitRegistryManagedPublication` for registry-managed
 * publication verified against observed DNS. Registry workflow status is kept
 * separate from the protocol-strict agent status types in
 * `@identity-digital/dnsid-protocol`.
 *
 * @packageDocumentation
 */
import {
  ArgumentError,
  DEFAULT_PUBLISH_PROFILE,
  SUPPORTED_PUBLISH_PROFILES,
  DnsIdTxtRecord,
  fromBase64Url,
  jwkThumbprint,
  JWKS,
  normalizeFQDN,
  ParseError,
  toBase64Url,
  validateAgentStatus,
  ValidationError,
} from '@identity-digital/dnsid-protocol';
import type {
  AgentStatus,
  IdentityConfig,
  DnsIdJWK,
  KeyProvider,
} from '@identity-digital/dnsid-protocol';

export type PublicationAuthority = 'client' | 'registry';

export interface AgentRegistrationInput {
  domain?: string;
  /** Optional product display name. Not published in the DNSid record. */
  name?: string;
  /** @deprecated The product registry has no arbitrary registration metadata field. */
  metadata?: Record<string, unknown>;
  publicKeyJwk?: DnsIdJWK;
  /** Registry environment. Omitted means `sandbox`, which is registry-managed. */
  environment?: 'sandbox' | 'production';
  managed?: boolean;
  zoneId?: string;
  capabilitiesUrl?: string;
  /** Persist before registration; reuse with the same input when reconciling a failed attempt. */
  idempotencyKey: string;
}

/** Registration may have succeeded; reconcile rather than retrying with a new key. */
export class RegistrationError extends Error {
  constructor(
    readonly idempotencyKey: string,
    /** Assigned domain, when the creation response was successfully parsed. */
    readonly domain: string | undefined,
    cause: unknown,
  ) {
    super(`registry registration failed; retain the same input and idempotency key for recovery: ${cause instanceof Error ? cause.message : String(cause)}`, { cause });
    this.name = 'RegistrationError';
  }
}

export interface LiveAgentRegistrationInput {
  publicKeyJwk: DnsIdJWK;
  environment?: 'production';
  name?: string;
  capabilitiesUrl?: string;
}

export interface LiveChallengeTranscript {
  protocol: 'dnsid-live-provisioning-pop/v1';
  orgId: string;
  agentId: string;
  fqdn: string;
  keyId: string;
  nonce: string;
  expiresAt: Date;
}

export interface LiveProvisioningResponse {
  requestId: string;
  agentId: string;
  status: string;
  challenge: string;
  challengeMessage: string;
  /** Assigned domain, derived from a validated challenge transcript while challenge_pending. */
  domain?: string;
  challengeTranscript?: LiveChallengeTranscript;
  raw?: unknown;
}

/** Default registry base URL used when none is provided. */
export const DEFAULT_REGISTRY_URL = 'https://api.dnsid.ai';

export interface RegistryClientOptions {
  /** HTTPS registry API base URL. Defaults to `https://api.dnsid.ai`. */
  baseUrl?: string;
  token?: string;
  headers?: HeadersInit;
  credentials?: RequestCredentials;
  fetch?: typeof fetch;
}

function validateRegistrationInput(input: AgentRegistrationInput): { environment: string; managed: boolean } {
  const environment = input.environment ?? 'sandbox';
  if (!['sandbox', 'production'].includes(environment)) {
    throw new ArgumentError('registration environment must be "sandbox" or "production"');
  }
  if (input.domain && input.zoneId) {
    throw new ArgumentError('domain and zoneId cannot both be supplied');
  }
  const managed = input.managed === true || environment === 'sandbox' || Boolean(input.zoneId);
  if (managed && input.domain) {
    throw new ArgumentError('domain must not be supplied for managed registrations; the registry assigns it');
  }
  if (!managed && !input.domain) {
    throw new ArgumentError('self-managed registration requires a domain');
  }
  return { environment, managed };
}

export type IdentitySignatureAlgorithm = 'EdDSA' | 'ES256';

export interface CanonicalRecordContentResponse {
  canonical: string;
  signingKid: string;
}

export interface IdentityRecordToSign {
  domain: string;
  canonicalContent: string;
  signingKid: string;
  tags?: Record<string, string>;
  expiresAt?: Date;
  raw?: unknown;
}

export interface SubmitIdentityRecordSignatureInput {
  signature: Uint8Array | string;
}

export interface ChallengeSignatureInput {
  nonce: string;
  signature: Uint8Array | string;
}

export interface LiveProofInput {
  requestId: string;
  challenge: string;
  publicKeyJwk: DnsIdJWK;
  signature: Uint8Array | string;
}

export interface LiveProofResponse {
  requestId: string;
  agentId: string;
  status: string;
  raw?: unknown;
}

export interface LiveProofReissueResponse extends LiveProofResponse {
  challenge: string;
  challengeMessage: string;
  domain: string;
  challengeTranscript: LiveChallengeTranscript;
}

export interface LifecycleResult {
  id: string;
  registryStatus: string;
  statusNote?: string;
  raw?: unknown;
}

export interface AgentRegistration {
  id: string;
  domain: string;
  publicationAuthority: PublicationAuthority;
  registryStatus: string;
  dnsPublished?: boolean;
  protocolStatus?: AgentStatus;
  registryUrl: string;
  oidcIssuerUrl?: string;
  publicationConfig?: PublicationConfig;
  raw?: unknown;
}

/** Authoritative profile-known values used by the registry to prepare an identity record. */
export interface PublicationConfig {
  publishProfile: string;
  governanceId: string;
  kuUrl: string;
  ekUrl: string;
  logRef: string;
  statusUrl: string;
  capabilitiesUrl?: string;
  maxKeyAge?: IdentityConfig['maxKeyAge'];
}

export interface PublishedRecord {
  domain: string;
  ownerName: string;
  txtRecord: string;
  ttl: number;
  publicationStatus: string;
  protocolStatus?: AgentStatus;
  raw?: unknown;
}

export interface PreparedRegistryEvent {
  entryBytes: Uint8Array;
  logReference: string;
}

export interface KeyRotationPreparationRequest {
  previousKeyId: string;
  publicKey: DnsIdJWK;
}

/** Owner-authorized reason codes accepted by the registry revoke API. */
export type RegistryRevocationReason = 'owner_request' | 'key_compromise';

export interface SubmissionResult {
  state: 'pending' | 'accepted' | 'rejected';
  entryHash: string;
  index?: number;
  logRef?: string;
  errorCode?: string;
  keyId?: string;
  raw?: unknown;
}

export type PreparedEventSubmissionErrorState = 'pending' | 'rejected' | 'indeterminate';

/**
 * Structured product error from exact-byte C2SP submission.
 *
 * `retryWithSameBytes` is deliberately true only when retrying the same
 * idempotency key and byte sequence is safe and required for reconciliation.
 */
export class PreparedEventSubmissionError extends Error {
  readonly code: string;
  readonly httpStatus: number;
  readonly state: PreparedEventSubmissionErrorState;
  readonly retryable: boolean;
  readonly retryWithSameBytes: boolean;

  constructor(options: {
    code: string;
    httpStatus: number;
    message: string;
    state: PreparedEventSubmissionErrorState;
    retryable: boolean;
    retryWithSameBytes: boolean;
  }) {
    super(options.message);
    this.name = 'PreparedEventSubmissionError';
    this.code = options.code;
    this.httpStatus = options.httpStatus;
    this.state = options.state;
    this.retryable = options.retryable;
    this.retryWithSameBytes = options.retryWithSameBytes;
  }
}

export interface PublishTxtRecordValidationOptions {
  expectedCanonicalContent: string;
  agentFQDN?: string;
  signingKid: string;
}

export class RegistryClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly headers?: HeadersInit;
  private readonly token?: string;
  private readonly credentials?: RequestCredentials;

  constructor(options: RegistryClientOptions = {}) {
    this.baseUrl = validateRegistryBaseUrl(options.baseUrl ?? DEFAULT_REGISTRY_URL);
    this.fetchImpl = options.fetch ?? fetch;
    this.headers = options.headers;
    this.token = options.token;
    this.credentials = options.credentials;
  }

  async registerAgent(input: AgentRegistrationInput): Promise<AgentRegistration> {
    if ('tier' in input) throw new ArgumentError('use registerLiveAgent for Live registration');
    const { environment, managed } = validateRegistrationInput(input);
    if (input.publicKeyJwk) assertPublicJwk(input.publicKeyJwk);
    const idempotencyKey = input.idempotencyKey;
    validateIdempotencyKey(idempotencyKey);
    let domain: string | undefined;
    try {
      const resp = await this.post('/api/v1/agent', {
        domain: input.domain,
        name: input.name,
        public_key: input.publicKeyJwk,
        environment,
        managed,
        zone_id: input.zoneId,
        capabilities_url: input.capabilitiesUrl,
      }, idempotencyKey);
      if (resp.status !== 201) throw new Error(`invalid registry registration response: expected HTTP 201, received ${resp.status}`);
      const raw = await readJsonObject(resp, 'registry register response');
      domain = requiredString(raw, 'domain', 'registry register response');
      const registration = await this.getRegistration(domain);
      if (!registration) throw new Error(`registry did not return the newly registered agent ${domain}`);
      return { ...registration, oidcIssuerUrl: optionalString(raw, 'oidc_issuer_url') };
    } catch (cause) {
      throw new RegistrationError(idempotencyKey, domain, cause);
    }
  }

  async registerLiveAgent(input: LiveAgentRegistrationInput, idempotencyKey: string): Promise<LiveProvisioningResponse> {
    if (!input.publicKeyJwk) throw new ArgumentError('live registration requires publicKeyJwk');
    if (input.environment !== undefined && input.environment !== 'production') throw new ArgumentError('live registration environment must be "production" or omitted');
    validateIdempotencyKey(idempotencyKey);
    assertManagedLivePublicJwk(input.publicKeyJwk);
    const publicKeyJwk = { ...input.publicKeyJwk };
    const expectedKeyId = await jwkThumbprint(publicKeyJwk);
    const resp = await this.post('/api/v1/agent', {
      name: input.name,
      public_key: publicKeyJwk,
      tier: 'live',
      environment: input.environment ?? 'production',
      managed: true,
      capabilities_url: input.capabilitiesUrl,
    }, idempotencyKey);
    if (resp.status !== 202) throw new Error(`invalid registry live registration response: expected HTTP 202, received ${resp.status}`);
    const raw = await readJsonObject(resp, 'registry live registration response');
    const requestId = requiredString(raw, 'request_id', 'registry live registration response');
    if (requestId !== idempotencyKey) throw new Error('invalid registry live registration response: request_id does not match Idempotency-Key');
    const agentId = requiredString(raw, 'agent_id', 'registry live registration response');
    const status = requiredString(raw, 'status', 'registry live registration response');
    const challenge = wireString(raw, 'challenge', 'registry live registration response');
    const challengeMessage = wireString(raw, 'challenge_message', 'registry live registration response');
    const response: LiveProvisioningResponse = { requestId, agentId, status, challenge, challengeMessage, raw };
    if (normalizeRegistryStatus(status) !== 'CHALLENGE_PENDING') return response;
    return {
      ...response,
      ...parseLiveChallenge(challenge, challengeMessage, agentId, expectedKeyId),
    };
  }

  async registerSelfManagedAgent(input: Omit<AgentRegistrationInput, 'managed' | 'zoneId'> & { domain: string }): Promise<AgentRegistration> {
    return this.registerAgent({ ...input, managed: false });
  }

  async registerManagedAgent(input: Omit<AgentRegistrationInput, 'domain' | 'managed' | 'zoneId'>): Promise<AgentRegistration> {
    return this.registerAgent({ ...input, managed: true });
  }

  async registerInZone(input: Omit<AgentRegistrationInput, 'domain' | 'managed'> & { zoneId: string }): Promise<AgentRegistration> {
    return this.registerAgent({ ...input, managed: true });
  }

  async verifyAgent(domain: string): Promise<AgentRegistration> {
    return this.triggerVerification(domain);
  }

  async triggerVerification(domain: string): Promise<AgentRegistration> {
    await this.post(`/api/v1/agent/${encodeURIComponent(domain)}/verify`);
    const registration = await this.getRegistration(domain);
    if (!registration) throw new Error(`registry did not return the verified agent ${domain}`);
    return registration;
  }

  async submitChallengeSignature(domain: string, input: ChallengeSignatureInput): Promise<LifecycleResult> {
    const resp = await this.post(`/api/v1/agent/${encodeURIComponent(domain)}/challenge`, {
      nonce: input.nonce,
      signature: signatureText(input.signature),
    });
    return lifecycleResultFromResponse(await readJsonObject(resp, 'registry challenge response'));
  }

  async submitLiveProof(domain: string, input: LiveProofInput): Promise<LiveProofResponse> {
    validateIdempotencyKey(input.requestId);
    assertManagedLivePublicJwk(input.publicKeyJwk);
    const resp = await this.post(`/api/v1/agent/${encodeURIComponent(domain)}/proof`, {
      request_id: input.requestId,
      challenge: input.challenge,
      public_key: input.publicKeyJwk,
      signature: signatureText(input.signature),
    }, input.requestId);
    if (resp.status !== 202) throw new Error(`invalid registry live proof response: expected HTTP 202, received ${resp.status}`);
    const raw = await readJsonObject(resp, 'registry live proof response');
    const requestId = requiredString(raw, 'request_id', 'registry live proof response');
    if (requestId !== input.requestId) throw new Error('invalid registry live proof response: request_id does not match Idempotency-Key');
    return {
      requestId,
      agentId: requiredString(raw, 'agent_id', 'registry live proof response'),
      status: requiredString(raw, 'status', 'registry live proof response'),
      raw,
    };
  }

  async reissueLiveProof(domain: string, requestId: string, publicKeyJwk: DnsIdJWK): Promise<LiveProofReissueResponse> {
    validateIdempotencyKey(requestId);
    assertManagedLivePublicJwk(publicKeyJwk);
    const expectedKeyId = await jwkThumbprint({ ...publicKeyJwk });
    const resp = await this.post(`/api/v1/agent/${encodeURIComponent(domain)}/proof/reissue`, {
      request_id: requestId,
    }, requestId);
    if (resp.status !== 202) throw new Error(`invalid registry live proof reissue response: expected HTTP 202, received ${resp.status}`);
    const raw = await readJsonObject(resp, 'registry live proof reissue response');
    const responseRequestId = requiredString(raw, 'request_id', 'registry live proof reissue response');
    if (responseRequestId !== requestId) throw new Error('invalid registry live proof reissue response: request_id does not match Idempotency-Key');
    const agentId = requiredString(raw, 'agent_id', 'registry live proof reissue response');
    const challenge = requiredString(raw, 'challenge', 'registry live proof reissue response');
    const challengeMessage = requiredString(raw, 'challenge_message', 'registry live proof reissue response');
    return {
      requestId: responseRequestId,
      agentId,
      status: requiredString(raw, 'status', 'registry live proof reissue response'),
      challenge,
      challengeMessage,
      ...parseLiveChallenge(challenge, challengeMessage, agentId, expectedKeyId, domain),
      raw,
    };
  }

  async getAgent(domain: string): Promise<AgentRegistration | undefined> {
    return this.getRegistration(domain);
  }

  async waitForStatus(
    domain: string,
    predicate: (status: AgentRegistration) => boolean,
    options: { intervalMs?: number; timeoutMs?: number } = {},
  ): Promise<AgentRegistration> {
    const intervalMs = options.intervalMs ?? 1000;
    const deadline = Date.now() + (options.timeoutMs ?? 60_000);
    while (Date.now() <= deadline) {
      const status = await this.getRegistration(domain);
      if (status && isFailedRegistryStatus(status.registryStatus)) {
        throw new RegistryWorkflowError(`registry reached terminal status ${status.registryStatus} for ${domain}`, status);
      }
      if (status && predicate(status)) return status;
      await delay(intervalMs);
    }
    throw new Error(`timed out waiting for registry status for ${domain}`);
  }

  async publishTxtRecordWithSigner(
    domain: string,
    sign: (canonical: Uint8Array) => Promise<Uint8Array | string>,
    validation: PublishTxtRecordValidationOptions,
  ): Promise<PublishedRecord> {
    const record = await this.getIdentityRecordToSign(domain, validation.agentFQDN, validation.signingKid);
    if (record.signingKid !== validation.signingKid) {
      throw new Error('registry canonicalContent targets a different active signing kid');
    }
    assertKnownTagsCanonicalMatch(record.canonicalContent, validation.expectedCanonicalContent, validation.agentFQDN ?? domain);

    const signature = await sign(new TextEncoder().encode(record.canonicalContent));
    return this.submitIdentityRecordSignature(domain, { signature });
  }

  async getIdentityRecordToSign(domain: string, agentFQDN = domain, signingKid?: string): Promise<IdentityRecordToSign> {
    const recordResp = await this.post(
      `/api/v1/agent/${encodeURIComponent(domain)}/record`,
      signingKid === undefined ? undefined : { signingKid },
    );
    const recordRaw = await readJsonObject(recordResp, 'registry record response');
    const registryCanonical = requiredString(recordRaw, 'canonicalContent', 'registry record response');
    try {
      DnsIdTxtRecord.parseUnsignedCanonical(registryCanonical, agentFQDN);
    } catch (e) {
      if (e instanceof ParseError || e instanceof ValidationError) {
        throw new Error(`registry canonicalContent is invalid: ${e.message}`);
      }
      throw e;
    }
    const tags = recordRaw['tags'];
    const responseSigningKid = optionalString(recordRaw, 'signingKid') ?? optionalString(recordRaw, 'signing_kid');
    if (responseSigningKid === undefined) {
      throw new Error('invalid registry record response: signingKid must be a non-empty string');
    }
    return {
      domain: optionalString(recordRaw, 'fqdn') ?? domain,
      canonicalContent: registryCanonical,
      signingKid: responseSigningKid,
      tags: isStringRecord(tags) ? tags : undefined,
      expiresAt: optionalDate(recordRaw, 'expiresAt'),
      raw: recordRaw,
    };
  }

  async canonicalRecordContent(domain: string, signingKid: string): Promise<CanonicalRecordContentResponse> {
    const record = await this.getIdentityRecordToSign(domain, domain, signingKid);
    return { canonical: record.canonicalContent, signingKid: record.signingKid };
  }

  async submitIdentityRecordSignature(domain: string, input: SubmitIdentityRecordSignatureInput): Promise<PublishedRecord> {
    const sigResp = await this.post(`/api/v1/agent/${encodeURIComponent(domain)}/signature`, {
      signature: signatureText(input.signature),
    });
    const sigRaw = await readJsonObject(sigResp, 'registry signature response');
    return publishedRecordFromSignatureResponse(domain, sigRaw);
  }

  async getRegistration(domain: string): Promise<AgentRegistration | undefined> {
    const resp = await this.request(`/api/v1/agent/${encodeURIComponent(domain)}/status`, { method: 'GET' });
    if (resp.status === 404) return undefined;
    if (!resp.ok) throw new Error(`registry status failed: HTTP ${await responseDetail(resp)}`);
    const raw = await readJsonObject(resp, 'registry status response');
    const managed = requiredString(raw, 'managed', 'registry status response');
    const publicationAuthority = managed === 'dnsid' ? 'registry' : managed === 'self' ? 'client' : undefined;
    if (!publicationAuthority) throw new Error(`unsupported registry managed mode: ${managed}`);
    const protocolStatusRaw = raw['protocolStatus'];
    return {
      id: requiredString(raw, 'id', 'registry status response'),
      domain: optionalString(raw, 'domain') ?? domain,
      publicationAuthority,
      registryStatus: requiredString(raw, 'status', 'registry status response'),
      dnsPublished: typeof raw.dns_published === 'boolean' ? raw.dns_published : undefined,
      protocolStatus: protocolStatusRaw === undefined ? undefined : validateAgentStatus(protocolStatusRaw),
      registryUrl: this.baseUrl,
      publicationConfig: publicationConfigFromResponse(raw['publication_config']),
      raw,
    };
  }

  /** @deprecated Use getRegistration(). */
  async getAgentStatus(domain: string): Promise<AgentRegistration | undefined> {
    return this.getRegistration(domain);
  }

  async prepareIssuance(domain: string, idempotencyKey: string): Promise<PreparedRegistryEvent> {
    if (!domain || domain.trim() !== domain) throw new Error('domain is required');
    validateIdempotencyKey(idempotencyKey);
    const resp = await this.postRaw(
      `/api/v1/agent/${encodeURIComponent(domain)}/tlog/issuance/prepare`,
      undefined,
      idempotencyKey,
    );
    const logReference = resp.headers.get('DNSID-Log-Reference');
    if (!logReference) throw new Error('invalid registry issuance response: DNSID-Log-Reference is required');
    return { entryBytes: new Uint8Array(await resp.arrayBuffer()), logReference };
  }

  /** Requires owner credentials (session or API key); an agent bearer token is not accepted. */
  async prepareKeyRotation(
    domain: string,
    request: KeyRotationPreparationRequest,
    idempotencyKey: string,
  ): Promise<PreparedRegistryEvent> {
    if (!request.previousKeyId) throw new Error('previousKeyId is required');
    validateIdempotencyKey(idempotencyKey);
    assertPublicJwk(request.publicKey);
    const resp = await this.postRaw(`/api/v1/agent/${encodeURIComponent(domain)}/tlog/key-rotation/prepare`, JSON.stringify({
      previous_key_id: request.previousKeyId,
      public_key: request.publicKey,
    }), idempotencyKey);
    const logReference = resp.headers.get('DNSID-Log-Reference');
    if (!logReference) throw new Error('invalid registry key rotation response: DNSID-Log-Reference is required');
    return { entryBytes: new Uint8Array(await resp.arrayBuffer()), logReference };
  }

  async submitPreparedEvent(domain: string, entryBytes: Uint8Array, idempotencyKey: string): Promise<SubmissionResult> {
    if (entryBytes.length === 0) throw new Error('entryBytes must not be empty');
    validateIdempotencyKey(idempotencyKey);
    // Snapshot once so the bytes hashed below are exactly the bytes passed to
    // fetch even if the caller mutates its Uint8Array while the request runs.
    const submittedEntry = entryBytes.slice();
    const resp = await this.postRawResponse(
      `/api/v1/agent/${encodeURIComponent(domain)}/tlog/events`,
      submittedEntry.buffer.slice(submittedEntry.byteOffset, submittedEntry.byteOffset + submittedEntry.byteLength) as ArrayBuffer,
      idempotencyKey,
    );
    if (!resp.ok) throw await preparedEventSubmissionError(resp);
    const raw = await readJsonObject(resp, 'registry tlog submission response');
    const state = requiredString(raw, 'state', 'registry tlog submission response');
    if (state !== 'pending' && state !== 'accepted' && state !== 'rejected') {
      throw new Error(`invalid registry tlog submission response: unsupported state ${state}`);
    }
    const index = typeof raw['index'] === 'number' ? raw['index'] : undefined;
    if (index !== undefined && (!Number.isSafeInteger(index) || index < 0)) {
      throw new Error('invalid registry tlog submission response: index must be a non-negative safe integer');
    }
    const entryHash = requiredString(raw, 'entry_hash', 'registry tlog submission response');
    if (state === 'accepted') {
      if (!/^[0-9a-f]{64}$/.test(entryHash)) {
        throw new Error('invalid registry tlog submission response: accepted entry_hash must be lowercase SHA-256 hex');
      }
      const expectedEntryHash = await sha256Hex(submittedEntry);
      if (entryHash !== expectedEntryHash) {
        throw new Error('registry accepted a different prepared-event entry_hash than the exact submitted bytes');
      }
    }
    return {
      state,
      entryHash,
      index,
      logRef: optionalString(raw, 'lr'),
      errorCode: optionalString(raw, 'error_code'),
      keyId: optionalString(raw, 'key_id'),
      raw,
    };
  }

  async revokeAgent(
    domain: string,
    agentId: string,
    reason: RegistryRevocationReason,
  ): Promise<LifecycleResult> {
    if (!agentId || agentId.trim() !== agentId) throw new Error('agentId must be a non-empty string without surrounding whitespace');
    if (reason !== 'owner_request' && reason !== 'key_compromise') throw new Error('revocation reason is invalid');
    const resp = await this.post(`/api/v1/agent/${encodeURIComponent(domain)}/revoke`, {
      agent_id: agentId,
      reason,
    });
    return lifecycleResultFromResponse(await readJsonObject(resp, 'registry revoke response'));
  }

  async retireAgent(domain: string, agentId: string): Promise<LifecycleResult> {
    if (!agentId || agentId.trim() !== agentId) throw new Error('agentId must be a non-empty string without surrounding whitespace');
    const resp = await this.post(`/api/v1/agent/${encodeURIComponent(domain)}/retire`, { agent_id: agentId });
    return lifecycleResultFromResponse(await readJsonObject(resp, 'registry retire response'));
  }

  async cancelAgent(domain: string): Promise<LifecycleResult> {
    const resp = await this.post(`/api/v1/agent/${encodeURIComponent(domain)}/cancel`);
    return lifecycleResultFromResponse(await readJsonObject(resp, 'registry cancel response'));
  }

  /** Best-effort unregister; unsupported and already-absent agents are successful no-ops. */
  async unregisterAgent(domain: string): Promise<void> {
    const resp = await this.request(`/api/v1/agent/${encodeURIComponent(domain)}`, { method: 'DELETE' });
    if (!resp.ok && resp.status !== 404 && resp.status !== 405) {
      throw new Error(`registry unregister failed: HTTP ${await responseDetail(resp)}`);
    }
  }

  private async post(path: string, body?: unknown, idempotencyKey?: string): Promise<Response> {
    return this.postRaw(path, body === undefined ? undefined : JSON.stringify(body), idempotencyKey);
  }

  private async postRaw(path: string, body?: BodyInit, idempotencyKey?: string): Promise<Response> {
    const resp = await this.postRawResponse(path, body, idempotencyKey);
    if (!resp.ok) throw new Error(`registry request failed: HTTP ${await responseDetail(resp)}`);
    return resp;
  }

  private async postRawResponse(path: string, body?: BodyInit, idempotencyKey?: string): Promise<Response> {
    const headers = new Headers(this.headers);
    headers.set('Content-Type', 'application/json');
    if (idempotencyKey) headers.set('Idempotency-Key', idempotencyKey);
    return this.request(path, { method: 'POST', headers, body });
  }

  private async request(path: string, init: RequestInit): Promise<Response> {
    const headers = new Headers(this.headers);
    new Headers(init.headers).forEach((value, key) => headers.set(key, value));
    if (this.token) headers.set('Authorization', `Bearer ${this.token}`);
    return this.fetchImpl(`${this.baseUrl}${path}`, { ...init, headers, credentials: init.credentials ?? this.credentials });
  }
}

function validateRegistryBaseUrl(raw: string): string {
  let url: URL;
  try { url = new URL(raw); } catch { throw new ArgumentError('registry baseUrl must be an HTTPS URL'); }
  if (url.protocol !== 'https:' || !url.hostname) {
    throw new ArgumentError('registry baseUrl must be an HTTPS URL');
  }
  if (url.username || url.password) throw new ArgumentError('registry baseUrl must not include userinfo');
  if (url.search || url.hash) throw new ArgumentError('registry baseUrl must not include query or fragment');
  return url.toString().replace(/\/$/, '');
}

function validateIdempotencyKey(value: string): void {
  if (typeof value !== 'string' || !value) throw new Error('idempotencyKey is required');
  if (value.trim() !== value) throw new Error('idempotencyKey must not contain surrounding whitespace');
  if (/[\u0000-\u001f\u007f]/.test(value)) throw new Error('idempotencyKey must not contain control characters');
  if (new TextEncoder().encode(value).byteLength > 200) {
    throw new Error('idempotencyKey must not exceed 200 UTF-8 bytes');
  }
}

export interface PublishClientControlledRecordOptions {
  config: IdentityConfig;
  entityKeyProvider: KeyProvider;
  registryClient: RegistryClient;
  /** Explicit legacy `ka` override. No value is inferred when the authoritative config omits `maxKeyAge`. */
  effectiveMaxKeyAge?: IdentityConfig['maxKeyAge'] | null;
}

/** @deprecated Use PublishClientControlledRecordOptions. */
export type PublishToRegistryOptions = PublishClientControlledRecordOptions;

/**
 * Protocol-evidence verifier for publication confirmation. Satisfied by
 * `IdentityManager.verifyPublicationEvidence`, which runs every protocol check
 * but not counterparty acceptance: confirming our own publication is a
 * control-plane operation, not an acceptance decision.
 */
export interface RegistryPublicationVerifier {
  verifyPublicationEvidence(domain: string): Promise<{
    record: { v: string; serialize(): string };
    dnsTTL: number;
    registryStatus: AgentStatus;
  }>;
}

export interface AwaitRegistryManagedPublicationOptions {
  domain: string;
  registryClient: RegistryClient;
  identityManager: RegistryPublicationVerifier;
  publishProfile?: string;
  intervalMs?: number;
  timeoutMs?: number;
}

export class RegistryWorkflowError extends Error {
  readonly registration: AgentRegistration;

  constructor(message: string, registration: AgentRegistration) {
    super(message);
    this.name = 'RegistryWorkflowError';
    this.registration = registration;
  }
}

export async function publishClientControlledRecord(
  opts: PublishClientControlledRecordOptions,
): Promise<PublishedRecord> {
  const profile = opts.config.publishProfile ?? DEFAULT_PUBLISH_PROFILE;
  if (!SUPPORTED_PUBLISH_PROFILES.includes(profile as typeof SUPPORTED_PUBLISH_PROFILES[number])) {
    throw new Error(`unsupported DNSid publish profile: ${profile}`);
  }
  const registration = await opts.registryClient.getRegistration(opts.config.domain);
  if (!registration) throw new Error(`registry has no registration for ${opts.config.domain}`);
  if (registration.publicationAuthority !== 'client') {
    throw new Error('registry controls accountable-entity publication');
  }
  const signingKey = await opts.entityKeyProvider.signingKey();
  new JWKS([signingKey]).validateRecordSigning();
  const effectiveMaxKeyAge = opts.config.maxKeyAge
    ?? (opts.effectiveMaxKeyAge === null ? undefined : opts.effectiveMaxKeyAge);
  const effectiveConfig = {
    ...opts.config,
    maxKeyAge: effectiveMaxKeyAge,
  };
  const expected = buildUnsignedDnsIdTxtRecord(effectiveConfig);
  return opts.registryClient.publishTxtRecordWithSigner(opts.config.domain, async canonical => {
    const sigBytes = await opts.entityKeyProvider.sign(canonical);
    return toBase64Url(sigBytes);
  }, {
    expectedCanonicalContent: expected.canonical(),
    agentFQDN: opts.config.domain,
    signingKid: signingKey.kid,
  });
}

/** @deprecated Use publishClientControlledRecord(). */
export function publishToRegistry(opts: PublishToRegistryOptions): Promise<PublishedRecord> {
  return publishClientControlledRecord(opts);
}

export async function awaitRegistryManagedPublication(
  options: AwaitRegistryManagedPublicationOptions,
): Promise<PublishedRecord> {
  const expectedProfile = options.publishProfile ?? DEFAULT_PUBLISH_PROFILE;
  if (!SUPPORTED_PUBLISH_PROFILES.includes(expectedProfile as typeof SUPPORTED_PUBLISH_PROFILES[number])) {
    throw new Error(`unsupported DNSid publish profile: ${expectedProfile}`);
  }
  const intervalMs = options.intervalMs ?? 1000;
  const deadline = Date.now() + (options.timeoutMs ?? 60_000);
  let registration = await options.registryClient.getRegistration(options.domain);
  if (!registration) throw new Error(`registry has no registration for ${options.domain}`);
  if (registration.publicationAuthority !== 'registry') {
    throw new Error('client controls accountable-entity publication');
  }

  while (normalizeRegistryStatus(registration.registryStatus) !== 'READY' || registration.dnsPublished !== true) {
    if (isFailedRegistryStatus(registration.registryStatus)) {
      throw new RegistryWorkflowError(`registry publication failed with status ${registration.registryStatus}`, registration);
    }
    if (Date.now() >= deadline) throw new RegistryWorkflowError(`timed out waiting for registry publication for ${options.domain}`, registration);
    await delay(intervalMs);
    const next = await options.registryClient.getRegistration(options.domain);
    if (!next) throw new RegistryWorkflowError(`registry registration disappeared for ${options.domain}`, registration);
    registration = next;
  }

  const verified = await options.identityManager.verifyPublicationEvidence(options.domain);
  if (verified.record.v !== expectedProfile) {
    throw new Error(`published DNSid record uses unexpected profile ${verified.record.v}; expected ${expectedProfile}`);
  }
  return {
    domain: options.domain,
    ownerName: `_dnsid.${options.domain}`,
    txtRecord: verified.record.serialize(),
    ttl: verified.dnsTTL,
    publicationStatus: registration.registryStatus,
    protocolStatus: verified.registryStatus,
    raw: registration.raw,
  };
}

function buildUnsignedDnsIdTxtRecord(config: IdentityConfig): DnsIdTxtRecord {
  const record = new DnsIdTxtRecord();
  record.v = config.publishProfile ?? DEFAULT_PUBLISH_PROFILE;
  record.gi = config.governanceId;
  record.ek = config.ekUrl ?? '';
  record.ku = config.kuUrl ?? '';
  record.lr = config.logRef;
  record.su = config.statusUrl;
  record.agentFQDN = config.domain;
  if (config.policyFlags)     record.fl = config.policyFlags;
  if (config.maxKeyAge)       record.ka = config.maxKeyAge;
  if (config.capabilitiesUrl) record.cu = config.capabilitiesUrl;
  try {
    record.validate();
  } catch (e) {
    throw new Error(`invalid local TXT record configuration: ${(e as Error).message}`);
  }
  return record;
}

function assertKnownTagsCanonicalMatch(registryCanonical: string, expectedCanonical: string, agentFQDN: string): void {
  let registryRecord: DnsIdTxtRecord;
  let expectedRecord: DnsIdTxtRecord;
  try {
    registryRecord = DnsIdTxtRecord.parseUnsignedCanonical(registryCanonical, agentFQDN);
    expectedRecord = DnsIdTxtRecord.parseUnsignedCanonical(expectedCanonical, agentFQDN);
  } catch (e) {
    if (e instanceof ParseError || e instanceof ValidationError) {
      throw new Error(`canonicalContent comparison failed: ${e.message}`);
    }
    throw e;
  }
  if (!SUPPORTED_PUBLISH_PROFILES.includes(expectedRecord.v as typeof SUPPORTED_PUBLISH_PROFILES[number])) {
    throw new Error(`unsupported DNSid publish profile: ${expectedRecord.v}`);
  }
  if (knownTagsCanonicalForRegistryCompare(registryRecord) !== knownTagsCanonicalForRegistryCompare(expectedRecord)) {
    const differingTags = differingKnownTags(registryRecord, expectedRecord);
    throw new Error(`registry canonicalContent does not match effective publication config; differing known tags: ${differingTags.join(', ')}`);
  }
}

function knownTagsCanonicalForRegistryCompare(record: DnsIdTxtRecord): string {
  return record.knownTagsCanonical();
}

function differingKnownTags(registry: DnsIdTxtRecord, expected: DnsIdTxtRecord): string[] {
  const tags = ['v', 'gi', 'ek', 'ku', 'lr', 'su', 'fl', 'ka', 'cu'] as const;
  return tags.filter(tag => registry[tag] !== expected[tag]);
}

async function preparedEventSubmissionError(resp: Response): Promise<PreparedEventSubmissionError> {
  const raw = await readErrorResponse(resp);
  const code = raw.code ?? `HTTP_${resp.status}`;
  const indeterminate = code === 'TLOG_SUBMISSION_INDETERMINATE';
  const busy = code === 'TLOG_SUBMISSION_BUSY';
  return new PreparedEventSubmissionError({
    code,
    httpStatus: resp.status,
    message: raw.message ?? `prepared-event submission failed: HTTP ${resp.status} ${resp.statusText}`,
    state: indeterminate ? 'indeterminate' : busy ? 'pending' : 'rejected',
    retryable: indeterminate || busy,
    retryWithSameBytes: indeterminate || busy,
  });
}

async function readErrorResponse(resp: Response): Promise<{ code?: string; message?: string }> {
  let value: unknown;
  try {
    value = await resp.json();
  } catch {
    return {};
  }
  if (!isObject(value)) return {};
  return {
    code: optionalString(value, 'error') ?? optionalString(value, 'code'),
    message: optionalString(value, 'message'),
  };
}

async function sha256Hex(value: Uint8Array): Promise<string> {
  const input = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
}

function normalizeRegistryStatus(value: unknown): string { return String(value ?? '').toUpperCase(); }
function isFailedRegistryStatus(status: string): boolean {
  return ['ERROR', 'REJECTED', 'CANCELLED', 'REVOKED', 'RETIRED'].includes(normalizeRegistryStatus(status));
}

function publishedRecordFromSignatureResponse(domain: string, raw: Record<string, unknown>): PublishedRecord {
  const fqdn = requiredString(raw, 'fqdn', 'registry signature response');
  const status = requiredString(raw, 'status', 'registry signature response');
  const records = raw['records'];
  if (!Array.isArray(records) || records.length === 0) throw new Error('invalid registry signature response: records must be a non-empty array');
  const first = records[0];
  if (!isObject(first)) throw new Error('invalid registry signature response: records[0] must be an object');
  const protocolStatusRaw = raw['protocolStatus'];
  return {
    domain: fqdn || domain,
    ownerName: requiredString(first, 'name', 'registry signature response records[0]'),
    txtRecord: requiredString(first, 'value', 'registry signature response records[0]'),
    ttl: requiredNumber(first, 'ttl', 'registry signature response records[0]'),
    publicationStatus: status,
    protocolStatus: protocolStatusRaw === undefined ? undefined : validateAgentStatus(protocolStatusRaw),
    raw,
  };
}

async function readJsonObject(resp: Response, label: string): Promise<Record<string, unknown>> {
  const value = await resp.json() as unknown;
  if (!isObject(value)) throw new Error(`invalid ${label}: expected JSON object`);
  return value;
}
function isObject(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function requiredString(raw: Record<string, unknown>, field: string, label: string): string {
  const value = raw[field];
  if (typeof value !== 'string' || value.length === 0) throw new Error(`invalid ${label}: ${field} must be a non-empty string`);
  return value;
}
function wireString(raw: Record<string, unknown>, field: string, label: string): string {
  const value = raw[field];
  if (typeof value !== 'string') throw new Error(`invalid ${label}: ${field} must be a string`);
  return value;
}
function optionalString(raw: Record<string, unknown>, field: string): string | undefined {
  const value = raw[field];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}
function publicationConfigFromResponse(value: unknown): PublicationConfig | undefined {
  if (value === undefined) return undefined;
  if (!isObject(value)) throw new Error('invalid registry status response: publication_config must be an object');
  const maxKeyAge = optionalString(value, 'max_key_age');
  if (maxKeyAge !== undefined && !['24h', '7d', '30d', '90d'].includes(maxKeyAge)) {
    throw new Error('invalid registry status response: publication_config.max_key_age is unsupported');
  }
  return {
    publishProfile: requiredString(value, 'publish_profile', 'registry status response publication_config'),
    governanceId: requiredString(value, 'governance_id', 'registry status response publication_config'),
    kuUrl: requiredString(value, 'ku_url', 'registry status response publication_config'),
    ekUrl: requiredString(value, 'ek_url', 'registry status response publication_config'),
    logRef: requiredString(value, 'log_ref', 'registry status response publication_config'),
    statusUrl: requiredString(value, 'status_url', 'registry status response publication_config'),
    capabilitiesUrl: optionalString(value, 'capabilities_url'),
    maxKeyAge: maxKeyAge as IdentityConfig['maxKeyAge'],
  };
}
function requiredNumber(raw: Record<string, unknown>, field: string, label: string): number {
  const value = raw[field];
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error(`invalid ${label}: ${field} must be a finite number`);
  return value;
}
export function required(name: string, values: Record<string, string | undefined>): string {
  const value = values[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}
export function requiredInt(name: string, values: Record<string, string | undefined>): number {
  const raw = required(name, values);
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}
function optionalDate(raw: Record<string, unknown>, field: string): Date | undefined {
  const value = raw[field];
  if (typeof value !== 'string' || !value) return undefined;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error(`invalid registry response: ${field} must be an ISO date`);
  return date;
}
function isStringRecord(value: unknown): value is Record<string, string> {
  return isObject(value) && Object.values(value).every(item => typeof item === 'string');
}
function signatureText(signature: Uint8Array | string): string {
  return typeof signature === 'string' ? signature : toBase64Url(signature);
}
function lifecycleResultFromResponse(raw: Record<string, unknown>): LifecycleResult {
  return {
    id: requiredString(raw, 'id', 'registry lifecycle response'),
    registryStatus: requiredString(raw, 'status', 'registry lifecycle response'),
    statusNote: optionalString(raw, 'status_note'),
    raw,
  };
}

function parseLiveChallenge(
  challenge: string,
  challengeMessage: string,
  agentId: string,
  expectedKeyId: string,
  expectedDomain?: string,
): { domain: string; challengeTranscript: LiveChallengeTranscript } {
  const label = 'registry Live challenge transcript';
  if (!/^[A-Za-z0-9_-]+$/.test(challenge) || !/^[A-Za-z0-9_-]+$/.test(challengeMessage)) {
    throw new Error(`invalid ${label}: challenge and challenge_message must be non-empty unpadded base64url strings`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(fromBase64Url(challengeMessage)));
  } catch {
    throw new Error(`invalid ${label}: challenge_message must encode a UTF-8 JSON object`);
  }
  if (!isObject(raw)) throw new Error(`invalid ${label}: expected JSON object`);
  const protocol = requiredString(raw, 'protocol', label);
  const orgId = requiredString(raw, 'org_id', label);
  const transcriptAgentId = requiredString(raw, 'agent_id', label);
  const fqdn = requiredString(raw, 'fqdn', label);
  const keyId = requiredString(raw, 'key_id', label);
  const nonce = requiredString(raw, 'nonce', label);
  const expires = requiredString(raw, 'expires_at', label);
  if (protocol !== 'dnsid-live-provisioning-pop/v1') throw new Error(`invalid ${label}: unsupported protocol`);
  if (transcriptAgentId !== agentId || nonce !== challenge) throw new Error(`invalid ${label}: outer response binding mismatch`);
  if (keyId !== expectedKeyId) throw new Error(`invalid ${label}: public key binding mismatch`);
  let domain: string;
  try {
    domain = normalizeFQDN(fqdn, true);
    if (expectedDomain && domain !== normalizeFQDN(expectedDomain, true)) throw new Error('mismatch');
  } catch {
    throw new Error(`invalid ${label}: fqdn is invalid or does not match the proof route`);
  }
  const expiresAt = new Date(expires);
  if (Number.isNaN(expiresAt.getTime())) throw new Error(`invalid ${label}: expires_at must be a timestamp`);
  return {
    domain,
    challengeTranscript: {
      protocol: 'dnsid-live-provisioning-pop/v1', orgId, agentId: transcriptAgentId,
      fqdn: domain, keyId, nonce, expiresAt,
    },
  };
}

function assertPublicJwk(jwk: DnsIdJWK): void {
  if ('keys' in jwk) throw new Error('publicKey must be a single JWK, not a JWKS');
  new JWKS([jwk]).validateOperational();
  for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']) {
    if (jwk[member] !== undefined) throw new Error(`publicKey must not contain private JWK member ${member}`);
  }
}
function assertManagedLivePublicJwk(jwk: DnsIdJWK): void {
  assertPublicJwk(jwk);
  let keyLength = 0;
  try { keyLength = typeof jwk.x === 'string' ? fromBase64Url(jwk.x).length : 0; } catch { /* invalid below */ }
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || jwk.alg !== 'EdDSA' || keyLength !== 32) {
    throw new ArgumentError('managed Live publicKeyJwk must be an OKP/Ed25519 key with alg="EdDSA"');
  }
}
function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
async function responseDetail(resp: Response): Promise<string> {
  let detail = `${resp.status} ${resp.statusText}`;
  try { const text = await resp.text(); if (text) detail += ` ${text}`; } catch { /* ignore */ }
  return detail;
}
