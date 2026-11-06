/** Known Foundry named Live creation. Requires the server gates documented at compliance 665aa67. */
import {
  ArgumentError, IdentityManager, JWKS, VerificationCode, VerificationError,
  issueManagedIdentity, jwkThumbprint, normalizeFQDN, validateDnsidConfig, verifyWithKey, ValidationError,
  type AgentStatusState, type DnsIdJWK, type IdentityManagerDependencies,
  type KeyProvider, type LogEvent, type LogRegistry, type ManagedIssuanceState, type VerifiedDomain,
} from '@dnsid-ai/sdk';
import {
  loadEnvironment, logRegistryFromTrust, operationalKeyProvider, validateKeySource,
  type FoundryConfig, type LoadedConfig,
} from '@dnsid-ai/sdk/node';
import {
  DEFAULT_REGISTRY_URL, RegistryClient, RegistryRequestError,
  type AgentRegistration, type LiveAgentRegistrationInput, type LiveProvisioningResponse,
  type PublicationConfig,
} from '@dnsid-ai/registry';
import { createDefaultDnsResolver, createDnsidFetch, createSsrfSafeFetch, fetchJson, type FetchLike } from '@dnsid-ai/transport';
import { canonicalBytes, canonicalJson, createDefaultC2spBoundedResourceFetcher, parseC2spTlogLr, parseJsonNoDuplicateMembers, parsePreparedC2spTlogIssuance, c2spTlogEntryBytes } from '@dnsid-ai/log-c2sp-tlog';
import { Deadline, FoundryError, SigningPaused, UnsupportedRegistry, type FoundryErrorCategory } from './errors.ts';
import {
  FileFoundryStore, decodeBytes, deriveIssuanceKey, deriveRegistrationKey,
  parseFoundryOperation, publicKey, validateName,
  type FoundryOperation, type FoundryStore, type FoundryTransaction,
} from './store.ts';

export { Deadline, FoundryError, SigningPaused, UnsupportedRegistry } from './errors.ts';
export type { FoundryErrorCategory, FoundryErrorFacts } from './errors.ts';
export { FileFoundryStore, deriveIssuanceKey, deriveRegistrationKey, parseFoundryOperation, validateName } from './store.ts';
export type { FoundryOperation, FoundryOperationKey, FoundryPhase, FoundryStore, FoundryTransaction } from './store.ts';

export type FoundryRegistry = Pick<RegistryClient, 'getOrganizationOnboarding' | 'registerLiveAgent' |
  'getRegistration' | 'submitLiveProof' | 'reissueLiveProof' | 'prepareIssuance' | 'submitPreparedEvent'>;

export interface FoundryDependencies extends Pick<IdentityManagerDependencies, 'keyProvider' | 'logRegistry' | 'dnsResolver' | 'fetchJson'> {
  registryClient?: FoundryRegistry;
  store?: FoundryStore;
  /** Registry-only secret. Never included in loaded configuration or recovery data. */
  credential?: string;
  /** Stable non-secret reference when the provider is supplied by application code. */
  providerReference?: Record<string, unknown>;
}
export interface FoundryCallOptions {
  signal?: AbortSignal;
  /** Whole-call timeout in milliseconds. Defaults to 30 seconds for create and 10 minutes for active. */
  timeoutMs?: number;
}
export interface CreateOptions extends FoundryCallOptions, FoundryDependencies {
  /** Explicit merged configuration. When supplied, no environment is read. */
  config?: LoadedConfig;
}

interface Context {
  config: LoadedConfig;
  registryUrl: string;
  registry: FoundryRegistry;
  store: FoundryStore;
  provider: KeyProvider;
  providerReference: Record<string, unknown>;
  logRegistry: LogRegistry;
  dnsResolver: NonNullable<IdentityManagerDependencies['dnsResolver']>;
  fetchJson: NonNullable<IdentityManagerDependencies['fetchJson']>;
  deadline: Deadline;
}

/** The configured facade and explicitly injected calls run the same implementation. */
export async function create(name: string, options: CreateOptions = {}): Promise<FoundryIdentity> {
  const deadline = new Deadline(options.timeoutMs, options.signal);
  let operation: FoundryOperation | undefined;
  try {
    deadline.check();
    validateName(name);
    const env = options.config === undefined ? { ...process.env } : undefined;
    const config = options.config ?? await deadline.call(() => loadEnvironment(env));
    const context = await compose(config, { ...options, credential: options.credential ?? env?.DNSID_API_KEY?.trim() }, deadline);
    const account = await onboarding(context);
    return await context.store.withLock({ registryUrl: context.registryUrl, organizationId: account.organizationId, name }, deadline, async transaction => {
      operation = await transaction.load();
      if (operation) {
        operation = parseFoundryOperation(canonicalBytes(operation));
        assertBindings(context, operation, account.organizationId, account.governanceId!);
        await validateSavedOperation(operation);
        registryOutcome(operation);
      }
      const key = await signingKey(context, operation !== undefined);
      if (operation) await assertKey(operation.currentPublicKey ?? operation.initialPublicKey, key, operation);
      else {
        operation = {
          schemaVersion: 1, phase: 'creation-pending', registryUrl: context.registryUrl,
          organizationId: account.organizationId, governanceId: account.governanceId!, name,
          keySource: context.providerReference, initialPublicKey: key,
          creationInput: { name, tier: 'live', managed: true, environment: 'production', public_key: key },
          ...(config.logTrust ? { logTrust: portable(config.logTrust) } : {}),
        };
        await transaction.save(operation);
      }
      if (operation.phase === 'complete') return FoundryIdentity.open(context, operation, key, operation.signingPaused !== true);
      if (!operation.identityId || !operation.domain) {
        const registrationKey = await registrationId(operation);
        const frozen = operation.creationInput;
        const input: LiveAgentRegistrationInput = {
          name: frozen.name, publicKeyJwk: frozen.public_key,
          ...(frozen.environment ? { environment: frozen.environment } : {}),
          ...(typeof frozen.capabilities_url === 'string' ? { capabilitiesUrl: frozen.capabilities_url } : {}),
        };
        const response = await retry(context, () => context.registry.registerLiveAgent(input, registrationKey, { signal: deadline.signal }));
        if (response.requestId !== registrationKey || !response.agentId || !response.status || operation.identityId && operation.identityId !== response.agentId) throw failure('binding', operation, 'Live creation response does not match the frozen request');
        operation.identityId = response.agentId;
        operation.requestId = response.requestId;
        operation.registryStatus = response.status;
        if (response.domain) operation.domain = normalizeFQDN(response.domain, true);
        try {
          if (response.challengeMessage) {
            operation.proof = await challenge(operation, response);
            operation.domain = operation.proof.domain as string;
          } else if (response.status.toUpperCase() === 'CHALLENGE_PENDING') {
            throw failure('unsupported-contract', operation, 'challenge_pending response has no challenge');
          }
        } catch (cause) { await transaction.save(operation); throw cause; }
        if (operation.domain) operation.phase = operation.proof ? 'proof-pending' : 'identity-known';
        await transaction.save(operation);
      } else if (operation.domain) {
        const observation = await retry(context, () => context.registry.getRegistration(operation!.domain!, { signal: deadline.signal }));
        observeRegistration(operation, observation);
        await transaction.save(operation);
      }
      registryOutcome(operation);
      if (!operation.domain) throw failure('resumable', operation, 'registry accepted creation but has not returned a domain; saved ID and status can be resumed', true);
      return FoundryIdentity.open(context, operation, key, false);
    });
  } catch (cause) { throw normalizeError(cause, operation, deadline); }
}

/** A stable identity handle. No background work is started by create or active. */
export class FoundryIdentity {
  readonly domain: string;
  state?: AgentStatusState;
  registryStatus?: string;
  private manager?: IdentityManager;
  private readonly signer: ApplicationSigner;
  /** @internal */
  static open(context: Context, operation: FoundryOperation, key: DnsIdJWK, enabled: boolean): FoundryIdentity {
    return new FoundryIdentity(context, operation, key, enabled);
  }
  private constructor(private readonly context: Context, private operation: FoundryOperation, key: DnsIdJWK, enabled: boolean) {
    this.domain = operation.domain!;
    this.registryStatus = operation.registryStatus;
    this.signer = new ApplicationSigner(context.provider, key, !enabled);
    if (operation.publicationConfig) this.identityManager();
  }

  /** Returns the same normally constructed manager after publication configuration is saved. */
  identityManager(): IdentityManager {
    if (this.manager) return this.manager;
    if (!this.operation.publicationConfig) throw new SigningPaused();
    this.manager = makeManager(this.context, this.operation, this.signer, false);
    return this.manager;
  }

  /** Signs raw bytes under the same pause controller used by profile helpers. */
  sign(data: Uint8Array): Promise<Uint8Array> { return this.signer.sign(data); }

  async active(options: FoundryCallOptions = {}): Promise<this> {
    const deadline = new Deadline(options.timeoutMs ?? 600_000, options.signal);
    const context = { ...this.context, deadline };
    try {
      await context.store.withLock(this.operation, deadline, async transaction => {
        const saved = await transaction.load();
        if (!saved) throw failure('storage', this.operation, 'named recovery state is missing');
        this.operation = parseFoundryOperation(canonicalBytes(saved));
        const operation = this.operation;
        try {
          const account = await onboarding(context);
          if (account.organizationId !== operation.organizationId) throw failure('binding', operation, 'credential belongs to a different organization');
          assertBindings(context, operation, account.organizationId, account.governanceId!);
          await validateSavedOperation(operation);
          if (operation.domain !== this.domain) throw failure('binding', operation, 'assigned domain changed');
          registryOutcome(operation);
          const key = await signingKey(context, true);
          await assertKey(operation.currentPublicKey ?? operation.initialPublicKey, key, operation);
          let registration = await this.waitForRegistry(context, transaction);
          if (!operation.publicationConfig) throw failure('unsupported-contract', operation, 'registry did not supply publication configuration');
          this.identityManager();
          if (!operation.entityPublicKey) {
            const publication = operation.publicationConfig as unknown as PublicationConfig;
            const result = await deadline.call(() => context.fetchJson(publication.ekUrl, { signal: deadline.signal, revalidate: true, maxResponseBytes: 256 * 1024 }));
            const document = result.data as { keys?: unknown } | null;
            if (!document || !Array.isArray(document.keys)) throw failure('binding', operation, 'entity endpoint did not return a JWKS');
            const keys = new JWKS(document.keys.map(publicKey));
            await keys.validateRecordSigningKeyset();
            operation.entityPublicKey = publicKey(keys.currentRecordSigningKey());
            await transaction.save(operation);
          }
          if (operation.phase !== 'complete') {
            await this.issue(context, transaction, key);
            registration = await this.waitForRegistry(context, transaction);
          }
          // Fresh, isolated public verification never changes application counterparty policy.
          for (let delay = 1000; ; delay = Math.min(delay * 2, 15_000)) {
            deadline.check();
            try {
              const verifier = makeManager(context, operation, this.signer, true);
              const verified = await deadline.call(() => verifier.verifyLocalPublication({ signal: deadline.signal, timeoutMs: Math.max(1, deadline.end - Date.now()) }));
              this.state = verified.registryStatus.state;
              operation.publicState = this.state;
              await verifyPublicBindings(operation, verified, key);
              await assertInitialIssuance(operation, (await deadline.call(() => verified.logReader.rebuildHistory(this.domain)))[0]);
              const evidence = await deadline.call(() => verified.verifyNonRevocation());
              if (evidence.loggedState !== 'ACTIVE') throw failure('terminal', operation, 'public lifecycle is terminal');
              operation.phase = 'complete';
              delete operation.signingPaused;
              await transaction.save(operation);
              this.signer.enable(key);
              this.registryStatus = registration.registryStatus;
              return;
            } catch (cause) {
              const error = normalizeError(cause, operation, deadline);
              if (['deadline', 'cancelled'].includes(error.category)) throw error;
              if (cause instanceof VerificationError && cause.agentState) {
                if (['PENDING', 'PROVISIONING', 'VERIFYING', 'ACTIVE', 'REVOKED', 'RETIRED'].includes(cause.agentState)) {
                  this.state = cause.agentState as AgentStatusState;
                  operation.publicState = this.state;
                }
                if (['REVOKED', 'RETIRED'].includes(cause.agentState)) {
                  throw failure('terminal', operation, 'public identity is terminal', false, cause);
                }
              }
              if (!publicPending(cause)) throw cause;
              await deadline.wait(delay);
              const next = await retry(context, () => context.registry.getRegistration(this.domain, { signal: deadline.signal }));
              observeRegistration(operation, next);
              this.registryStatus = operation.registryStatus;
              await transaction.save(operation);
              registryOutcome(operation);
            }
          }
        } catch (cause) {
          const error = normalizeError(cause, operation, deadline);
          if (['binding', 'KEY_MISMATCH', 'terminal'].includes(error.category)) {
            this.signer.pause();
            operation.signingPaused = true;
            await transaction.save(operation);
          }
          throw error;
        }
      });
      return this;
    } catch (cause) {
      const error = normalizeError(cause, this.operation, deadline);
      throw error;
    }
  }

  private async waitForRegistry(context: Context, transaction: FoundryTransaction): Promise<AgentRegistration> {
    const operation = this.operation;
    for (let delay = 1000; ; delay = Math.min(delay * 2, 15_000)) {
      const registration = await retry(context, () => context.registry.getRegistration(this.domain, { signal: context.deadline.signal }));
      observeRegistration(operation, registration);
      this.registryStatus = operation.registryStatus;
      await transaction.save(operation);
      registryOutcome(operation);
      const status = operation.registryStatus!.toUpperCase();
      if (operation.proof && !operation.proof.outcome) await this.prove(context, transaction);
      if (status === 'VERIFIED' || status === 'READY') {
        const publication = registration!.publicationConfig;
        validatePublication(operation, publication);
        if (!operation.publicationConfig) {
          operation.publicationConfig = portable(publication!) as Record<string, unknown>;
          if (registration!.oidcIssuerUrl) operation.oidcIssuerUrl = registration!.oidcIssuerUrl;
          await transaction.save(operation);
        } else if (canonicalJson(operation.publicationConfig) !== canonicalJson(portable(publication))) {
          throw failure('binding', operation, 'registry publication configuration changed');
        }
        return registration!;
      }
      await context.deadline.wait(delay);
    }
  }

  private async prove(context: Context, transaction: FoundryTransaction): Promise<void> {
    const operation = this.operation;
    let proof = operation.proof!;
    const waitingForProof = !['VERIFIED', 'READY'].includes(operation.registryStatus!.toUpperCase());
    if (Date.parse(proof.expiresAt as string) <= Date.now() && (proof.submissionState !== 'submitting' || waitingForProof)) {
      try {
        const replacement = await retry(context, () => context.registry.reissueLiveProof(this.domain, operation.requestId!, operation.initialPublicKey, { signal: context.deadline.signal }));
        proof = operation.proof = await challenge(operation, replacement);
      } catch (cause) {
        if (!(cause instanceof RegistryRequestError) || cause.httpStatus !== 409) throw cause;
        proof.outcome = { httpStatus: 409 };
        operation.phase = 'identity-known';
        await transaction.save(operation);
        return;
      }
      await transaction.save(operation);
    }
    if (!proof.request) {
      const signature = await providerCall(context, 'signKey', operation.initialPublicKey.kid, decodeBytes(proof.challengeMessage));
      proof.request = { requestId: operation.requestId!, challenge: proof.challenge, publicKeyJwk: operation.initialPublicKey, signature: Buffer.from(signature).toString('base64url') };
      proof.submissionState = 'prepared';
      await transaction.save(operation);
    }
    proof.submissionState = 'submitting';
    await transaction.save(operation);
    const request = proof.request as Parameters<FoundryRegistry['submitLiveProof']>[1];
    const response = await retry(context, () => context.registry.submitLiveProof(this.domain, request, { signal: context.deadline.signal }));
    if (response.requestId !== operation.requestId || response.agentId !== operation.identityId) throw failure('binding', operation, 'proof response changed identity or requestId');
    proof.outcome = { requestId: response.requestId, agentId: response.agentId, status: response.status };
    operation.phase = 'identity-known';
    await transaction.save(operation);
  }

  private async recoverIssuance(context: Context, transaction: FoundryTransaction, key: DnsIdJWK): Promise<void> {
    const operation = this.operation;
    const publication = operation.publicationConfig as unknown as PublicationConfig;
    const reader = context.logRegistry.newReader(publication.logRef, { signal: context.deadline.signal, revalidate: true });
    try {
      await context.deadline.call(() => reader.verifyBilateralBinding({ agentFQDN: this.domain, gi: operation.governanceId }, operation.entityPublicKey, key));
      const history = await context.deadline.call(() => reader.rebuildHistory(this.domain));
      const first = history.find(event => event.type === 'ISSUANCE');
      if (!first) throw failure('resumable', operation, 'accepted ISSUANCE is not visible in lifecycle history yet', true);
      await assertInitialIssuance(operation, first);
      const evidence = await context.deadline.call(() => reader.verifyNonRevocation(this.domain, new Date()));
      operation.issuance = {
        ...operation.issuance,
        // This acceptance is independent of the losing replica's bytes and receipt.
        acceptance: { source: 'verified-history', logReference: evidence.historyStart,
          initialOperationalThumbprint: first.initialOperationalThumbprint,
          initialEntityThumbprint: first.initialEntityThumbprint, verifiedAt: new Date().toISOString() },
      };
      operation.phase = 'issuance-accepted';
      await transaction.save(operation);
    } catch (cause) {
      if (cause instanceof VerificationError && cause.errorCategory === 'GENESIS_REQUIRED') throw failure('resumable', operation, 'accepted ISSUANCE is not visible in lifecycle history yet', true, cause);
      throw cause;
    }
  }

  private async issue(context: Context, transaction: FoundryTransaction, key: DnsIdJWK): Promise<void> {
    const operation = this.operation;
    if (operation.issuance?.acceptance || (operation.issuance?.submission as { state?: string } | undefined)?.state === 'accepted' || operation.issuance?.rejection) {
      await this.recoverIssuance(context, transaction, key);
      return;
    }
    let requestFailure: unknown;
    for (let delay = 1000; ; delay = Math.min(delay * 2, 15_000)) {
      try {
        const publication = operation.publicationConfig as unknown as PublicationConfig;
        const initialProvider = boundedProvider(context);
        const state = await issueManagedIdentity({
          domain: this.domain, governanceId: operation.governanceId,
          entityKey: operation.entityPublicKey!, operationalKeyProvider: initialProvider,
          registryClient: {
            prepareIssuance: async (domain, idempotencyKey) => {
              if (operation.issuance?.preparedEntryBytes) return { entryBytes: decodeBytes(operation.issuance.preparedEntryBytes) };
              try {
                const prepared = await context.registry.prepareIssuance(domain, idempotencyKey, { signal: context.deadline.signal });
                operation.issuance = { ...operation.issuance, preparedEntryBytes: Buffer.from(prepared.entryBytes).toString('base64url') };
                await transaction.save(operation);
                return prepared;
              } catch (cause) { await recordRejection('preparation', cause); throw cause; }
            },
            submitPreparedEvent: async (domain, bytes, idempotencyKey) => {
              try {
                const result = await context.registry.submitPreparedEvent(domain, bytes, idempotencyKey, { signal: context.deadline.signal });
                if (result.state === 'rejected') await recordRejection('submission', { code: result.errorCode, state: result.state });
                return result;
              } catch (cause) { await recordRejection('submission', cause); throw cause; }
            },
          },
          idempotencyKey: deriveIssuanceKey(await registrationId(operation)), logReference: publication.logRef,
          loadIssuance: async () => operation.issuance?.domain ? issuanceState(operation.issuance) : undefined,
          createIssuance: async intent => { await persist(intent); return undefined; },
          persistIssuance: persist,
          activateAcceptedIssuance: async () => {},
        });
        if (state.submission?.state === 'accepted') {
          operation.phase = 'issuance-accepted';
          await transaction.save(operation);
          return;
        }
      } catch (cause) {
        if (requestFailure) throw normalizeError(requestFailure, operation, context.deadline);
        if (operation.issuance?.rejection) {
          await this.recoverIssuance(context, transaction, key);
          return;
        }
        if (!transient(cause) && !(cause && typeof cause === 'object' && 'retryWithSameBytes' in cause && cause.retryWithSameBytes === true)) {
          throw normalizeError(cause, operation, context.deadline);
        }
      }
      await context.deadline.wait(delay);
    }
    async function recordRejection(stage: 'preparation' | 'submission', cause: unknown): Promise<void> {
      const error = cause as { code?: string; httpStatus?: number; state?: string } | null;
      if (!serverRejected(cause)) {
        if (error?.state === 'rejected' || error?.httpStatus !== undefined && error.httpStatus >= 400 && error.httpStatus < 500 && ![408, 425, 429].includes(error.httpStatus)) requestFailure = cause;
        return;
      }
      operation.issuance = { ...operation.issuance, rejection: portable({ stage, code: error!.code, httpStatus: error!.httpStatus }) };
      await transaction.save(operation);
    }
    async function persist(state: ManagedIssuanceState): Promise<void> {
      // Authentication and routing failures do not reject the durable issuance bytes.
      if (requestFailure) return;
      const saved = portable(state) as Record<string, unknown>;
      // A rejected byte string is not a final operation failure while log recovery is pending.
      if (operation.issuance?.rejection) delete saved.terminalFailure;
      operation.issuance = { ...operation.issuance, ...saved };
      await transaction.save(operation);
    }
  }
}

class ApplicationSigner implements KeyProvider {
  constructor(private readonly provider: KeyProvider, private key: DnsIdJWK, private paused: boolean) {}
  pause(): void { this.paused = true; }
  enable(key: DnsIdJWK): void { this.key = key; this.paused = false; }
  async signingKey(): Promise<DnsIdJWK> { return { ...this.key }; }
  async jwk(kid: string): Promise<DnsIdJWK> { if (kid !== this.key.kid) throw new SigningPaused(); return this.signingKey(); }
  async listKeyIds(): Promise<string[]> { return [this.key.kid]; }
  async sign(bytes: Uint8Array): Promise<Uint8Array> { return this.signKey(this.key.kid, bytes); }
  async signKey(kid: string, bytes: Uint8Array): Promise<Uint8Array> {
    if (this.paused || kid !== this.key.kid) throw new SigningPaused();
    return this.provider.signKey(kid, bytes);
  }
  async generateKey(): Promise<string> { throw new FoundryError('unsupported-contract', 'key rotation is not supported by this facade', { resumable: false }); }
  async activate(): Promise<void> { this.pause(); throw new SigningPaused(); }
  async supersede(): Promise<void> { this.pause(); throw new SigningPaused(); }
}

async function compose(config: LoadedConfig, deps: FoundryDependencies, deadline: Deadline): Promise<Context> {
  if (config.dnsid?.identity !== undefined) throw new ArgumentError('Foundry create does not accept ordinary identity selectors');
  const validated = validateDnsidConfig(config.dnsid ?? {});
  const foundry: FoundryConfig = config.foundry ?? {};
  for (const [field, value] of Object.entries(foundry)) {
    if (!['organizationId', 'governanceId'].includes(field) || typeof value !== 'string' || !value) throw new ArgumentError(`invalid foundry.${field}`);
  }
  if (foundry.governanceId) normalizeFQDN(foundry.governanceId, true);
  if (!deps.logRegistry) {
    if (!config.logTrust) throw new ArgumentError('Foundry requires explicit logTrust or deps.logRegistry');
    const variants = ['managed', 'profile', 'policyUrl', 'policyDocument'].filter(field => config.logTrust![field as keyof typeof config.logTrust] !== undefined);
    if (variants.length !== 1 || config.logTrust.managed === false) throw new ArgumentError('logTrust requires exactly one variant; managed must be true');
  }
  if (!deps.keyProvider) await deadline.call(() => validateKeySource(config.keySource));
  let provider = deps.keyProvider;
  if (!provider) {
    try { provider = await deadline.call(() => operationalKeyProvider(config.keySource ?? {}, '')); }
    catch (cause) {
      if ((cause as NodeJS.ErrnoException).code === 'ENOENT') throw new FoundryError('KEY_MISSING', 'configured signing key does not exist; supply a provider with an existing key or ensureSigningKey({signal})', { resumable: true, cause });
      throw cause;
    }
  }
  if (!provider) {
    console.warn('Local private-key files are unsuitable for production. Configure a cloud key provider.');
    throw new FoundryError('KEY_MISSING', 'no signing key provider is configured', { resumable: true });
  }
  const registryUrl = new URL(config.registry?.registryUrl ?? DEFAULT_REGISTRY_URL).toString().replace(/\/$/, '');
  const transport = validated.transport ?? {};
  const registry = deps.registryClient ?? new RegistryClient({ baseUrl: registryUrl, token: deps.credential,
    fetch: registryFetch(registryUrl, transport, deadline) as typeof fetch });
  let trust = config.logTrust;
  if (!deps.logRegistry && trust?.policyUrl) {
    const policyDocument = await createDefaultC2spBoundedResourceFetcher(transport).fetchBounded(trust.policyUrl, 1024 * 1024,
      { signal: deadline.signal, timeoutMs: Math.max(1, deadline.end - Date.now()) });
    trust = { ...trust, policyUrl: undefined, policyDocument };
  }
  const logRegistry = deps.logRegistry ?? await deadline.call(() => logRegistryFromTrust(trust!, transport));
  return {
    config, registryUrl, registry, provider, logRegistry,
    store: deps.store ?? new FileFoundryStore(),
    providerReference: deps.providerReference ?? portable(deps.keyProvider ? { provider: 'injected' } : config.keySource ?? { provider: 'file' }) as Record<string, unknown>,
    dnsResolver: deps.dnsResolver ?? createDefaultDnsResolver(transport),
    fetchJson: deps.fetchJson ?? ((url, options) => fetchJson(url, { ...options, ...transport })),
    deadline,
  };
}

function registryFetch(base: string, transport: NonNullable<LoadedConfig['dnsid']>['transport'], initialDeadline: Deadline): FetchLike {
  const url = new URL(base);
  const local = url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  const send = local ? createDnsidFetch(transport ?? {}) : createSsrfSafeFetch(transport ?? {}, { privateAddressHosts: transport?.privateAddressHosts });
  return async (input, init) => {
    if (new URL(input instanceof Request ? input.url : input).origin !== url.origin) throw new Error('registry transport refuses other origins');
    const signal = init?.signal ?? initialDeadline.signal;
    const response = await send(input, { ...init, signal, redirect: 'manual' });
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new FoundryError('unsupported-contract', 'authenticated registry redirects are forbidden', { resumable: false, httpStatus: response.status });
    }
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let length = 0;
    if (reader) try {
      for (;;) {
        signal?.throwIfAborted();
        const { done, value } = await reader.read();
        if (done) break;
        length += value.length;
        if (length > 1024 * 1024) throw new Error('registry response exceeds 1 MiB');
        chunks.push(value);
      }
    } catch (cause) { await reader.cancel().catch(() => {}); throw cause; }
    finally { reader.releaseLock(); }
    const headers = new Headers(response.headers);
    headers.delete('content-encoding'); headers.delete('content-length');
    return new Response([204, 205, 304].includes(response.status) ? null : Buffer.concat(chunks), { status: response.status, statusText: response.statusText, headers });
  };
}

async function onboarding(context: Context) {
  let account;
  try { account = await retry(context, () => context.registry.getOrganizationOnboarding({ signal: context.deadline.signal })); }
  catch (cause) {
    if (cause instanceof RegistryRequestError && [404, 405].includes(cause.httpStatus)) throw new UnsupportedRegistry({ httpStatus: cause.httpStatus, code: cause.code, cause });
    if (cause instanceof ArgumentError) throw new FoundryError('binding', 'invalid organization onboarding binding', { resumable: false, cause });
    if (!(cause instanceof RegistryRequestError) && !(cause instanceof FoundryError) && !(cause instanceof VerificationError)) throw new UnsupportedRegistry({ cause });
    throw cause;
  }
  if (!account.organizationId || !account.governanceId || !account.gi || account.gi.domain === undefined || account.gi.state === undefined || account.gi.gateAuthorized === undefined || account.entityKeyStatus === undefined) throw new UnsupportedRegistry();
  const expected = context.config.foundry;
  if (expected?.organizationId !== undefined && expected.organizationId !== account.organizationId
    || expected?.governanceId !== undefined && normalizeFQDN(expected.governanceId, true) !== normalizeFQDN(account.governanceId, true)) throw new FoundryError('binding', 'configured Foundry account does not match onboarding', { resumable: false });
  if (!account.ready || account.gi.state !== 'verified' || account.gi.gateAuthorized !== true || account.entityKeyStatus !== 'verified') throw new FoundryError('workflow-outcome', 'organization onboarding is not ready', { resumable: true });
  return { ...account, governanceId: normalizeFQDN(account.governanceId, true) };
}

function assertBindings(context: Context, operation: FoundryOperation, organizationId: string, governanceId: string): void {
  if (operation.registryUrl !== context.registryUrl || operation.organizationId !== organizationId || normalizeFQDN(operation.governanceId, true) !== governanceId) throw failure('binding', operation, 'saved account bindings do not match onboarding');
  if (operation.logTrust !== undefined && context.config.logTrust !== undefined && canonicalJson(operation.logTrust) !== canonicalJson(portable(context.config.logTrust))) throw failure('binding', operation, 'saved log trust does not match configuration');
}

async function signingKey(context: Context, established: boolean): Promise<DnsIdJWK> {
  let key = context.provider.activeSigningKey ? await providerCall(context, 'activeSigningKey') : await providerCall(context, 'signingKey');
  if (!key) {
    const provider = context.provider as KeyProvider & { ensureSigningKey?: (options?: { signal: AbortSignal }) => Promise<unknown> };
    if (!established && provider.ensureSigningKey) {
      await context.deadline.call(() => provider.ensureSigningKey!({ signal: context.deadline.signal }));
      key = await providerCall(context, 'signingKey');
    } else throw new FoundryError('KEY_MISSING', 'provider has no signing key; supply it or a provider with ensureSigningKey({signal})', { resumable: true });
  }
  if (key.kty !== 'OKP' || key.crv !== 'Ed25519' || key.alg !== 'EdDSA') throw new FoundryError('unsupported-algorithm', 'Foundry Live creation requires Ed25519 with EdDSA', { resumable: false });
  const result = publicKey(key);
  await context.deadline.call(() => new JWKS([result]).validateRecordSigningKeyset());
  return { ...result };
}

async function providerCall(context: Context, method: keyof KeyProvider, ...args: unknown[]): Promise<any> {
  return context.deadline.call(() => Reflect.apply(context.provider[method] as Function, context.provider, [...args, { signal: context.deadline.signal }]));
}
function boundedProvider(context: Context): KeyProvider {
  return new Proxy(context.provider, { get: (target, property) => typeof Reflect.get(target, property) === 'function'
    ? (...args: unknown[]) => providerCall(context, property as keyof KeyProvider, ...args) : Reflect.get(target, property) });
}
async function assertKey(expected: DnsIdJWK, actual: DnsIdJWK, operation: FoundryOperation): Promise<void> {
  if (expected.kid !== actual.kid || expected.alg !== actual.alg || await jwkThumbprint(expected) !== await jwkThumbprint(actual)) throw failure('KEY_MISMATCH', operation, 'use the provider key this identity was created with; run one identity per cloud provider');
}
async function validateSavedOperation(operation: FoundryOperation): Promise<void> {
  if (operation.requestId !== undefined && operation.requestId !== await registrationId(operation)) throw failure('binding', operation, 'saved requestId does not match the creation binding');
  if (Object.keys(operation.creationInput).some(field => !['name', 'tier', 'managed', 'public_key', 'environment', 'capabilities_url'].includes(field))) throw failure('unsupported-contract', operation, 'frozen creation input contains unsupported fields');
  if (operation.proof) {
    await challenge(operation, { requestId: operation.requestId!, agentId: operation.identityId!, status: 'challenge_pending',
      challenge: operation.proof.challenge as string, challengeMessage: operation.proof.challengeMessage as string, domain: operation.domain });
    const request = operation.proof.request as { signature: string } | undefined;
    if (request && !await verifyWithKey(decodeBytes(operation.proof.challengeMessage), decodeBytes(request.signature), operation.initialPublicKey, 'EdDSA')) throw failure('binding', operation, 'saved proof signature is invalid');
  }
  for (const member of ['preparedEntryBytes', 'entryBytes']) {
    if (!operation.issuance?.[member]) continue;
    if (!operation.entityPublicKey) throw failure('binding', operation, 'saved issuance has no entity key');
    const context = { expectedFqdn: operation.domain!, expectedGovernanceId: operation.governanceId, entityKey: operation.entityPublicKey, operationalKey: operation.initialPublicKey };
    const prepared = await parsePreparedC2spTlogIssuance(decodeBytes(operation.issuance[member]), context);
    if (prepared.reference.lr !== operation.publicationConfig?.logRef) throw failure('binding', operation, 'saved issuance log does not match publication configuration');
    if (member === 'entryBytes') await c2spTlogEntryBytes(prepared, context);
  }
}

async function assertInitialIssuance(operation: FoundryOperation, event: LogEvent | undefined): Promise<void> {
  if (!event || event.type !== 'ISSUANCE' || event.domain !== operation.domain
    || normalizeFQDN(event.governanceId, true) !== normalizeFQDN(operation.governanceId, true)
    || event.initialOperationalThumbprint !== await jwkThumbprint(operation.initialPublicKey)
    || event.initialEntityThumbprint !== await jwkThumbprint(operation.entityPublicKey!)) throw failure('binding', operation, 'accepted ISSUANCE has different identity or key bindings');
}

async function registrationId(operation: FoundryOperation): Promise<string> {
  return deriveRegistrationKey(operation.organizationId, operation.name, await jwkThumbprint(operation.initialPublicKey));
}

async function challenge(operation: FoundryOperation, response: LiveProvisioningResponse): Promise<Record<string, unknown>> {
  const transcript = parseJsonNoDuplicateMembers(decodeBytes(response.challengeMessage)) as Record<string, unknown>;
  if (!transcript || typeof transcript !== 'object' || Array.isArray(transcript)
    || transcript.protocol !== 'dnsid-live-provisioning-pop/v1' || transcript.org_id !== operation.organizationId
    || transcript.agent_id !== operation.identityId || transcript.nonce !== response.challenge
    || transcript.key_id !== await jwkThumbprint(operation.initialPublicKey)
    || response.agentId !== operation.identityId || response.requestId !== operation.requestId
    || typeof transcript.fqdn !== 'string' || typeof transcript.expires_at !== 'string' || !Number.isFinite(Date.parse(transcript.expires_at))) throw failure('binding', operation, 'Live challenge does not match the saved operation and key');
  const domain = normalizeFQDN(transcript.fqdn, true);
  if (operation.domain && domain !== operation.domain || response.domain && normalizeFQDN(response.domain, true) !== domain) throw failure('binding', operation, 'Live challenge changed the assigned domain');
  return { challenge: response.challenge, challengeMessage: response.challengeMessage, expiresAt: new Date(transcript.expires_at).toISOString(), domain };
}
function observeRegistration(operation: FoundryOperation, registration: AgentRegistration | undefined): void {
  if (!registration) throw failure('resumable', operation, 'authenticated registry read did not find the known identity', true);
  if (registration.id !== operation.identityId || normalizeFQDN(registration.domain, true) !== operation.domain || registration.publicationAuthority !== 'registry') throw failure('binding', operation, 'registry read changed identity, domain, or publication authority');
  operation.registryStatus = registration.registryStatus;
}
function registryOutcome(operation: FoundryOperation): void {
  const state = operation.registryStatus?.toUpperCase();
  if (state === 'REVOKED' || state === 'RETIRED' || operation.publicState === 'REVOKED' || operation.publicState === 'RETIRED') throw failure('terminal', operation, 'identity is terminal; same-name replacement is disabled');
  if (state === 'ERROR' || state === 'REJECTED' || state === 'CANCELLED') throw failure('workflow-outcome', operation, `registry workflow returned ${state}; the name remains owned`);
}
function validatePublication(operation: FoundryOperation, publication: PublicationConfig | undefined): void {
  if (!publication) throw failure('unsupported-contract', operation, 'registry publication configuration is missing');
  if (normalizeFQDN(publication.governanceId, true) !== normalizeFQDN(operation.governanceId, true)) throw failure('binding', operation, 'publication GI differs from onboarding');
  if (publication.publishProfile !== 'dnsid-draft-01') throw failure('unsupported-contract', operation, 'Foundry requires bilateral draft-01 publication');
  parseC2spTlogLr(publication.logRef);
  for (const field of ['ekUrl', 'kuUrl', 'statusUrl'] as const) {
    const url = new URL(publication[field]);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw failure('binding', operation, `invalid publication ${field}`);
  }
}
function makeManager(context: Context, operation: FoundryOperation, signer: KeyProvider, isolated: boolean): IdentityManager {
  const publication = operation.publicationConfig as unknown as PublicationConfig;
  validatePublication(operation, publication);
  return new IdentityManager({ identity: { domain: operation.domain!, ...publication, governanceId: operation.governanceId },
    verification: isolated ? { dnssecMode: context.config.dnsid?.verification?.dnssecMode } : context.config.dnsid?.verification },
  { keyProvider: signer, logRegistry: context.logRegistry, dnsResolver: context.dnsResolver, fetchJson: context.fetchJson });
}
async function verifyPublicBindings(operation: FoundryOperation, verified: VerifiedDomain, key: DnsIdJWK): Promise<void> {
  const publication = operation.publicationConfig as unknown as PublicationConfig;
  if (verified.domain !== operation.domain || verified.record.v !== publication.publishProfile
    || verified.record.governanceId() !== operation.governanceId || verified.record.lr !== publication.logRef
    || verified.signingKeyThumbprint !== await jwkThumbprint(operation.entityPublicKey!)) throw failure('binding', operation, 'public identity has different domain, profile, GI, entity key, or log');
  const current = verified.jwks.currentOperationalSigningKey();
  await assertKey(key, current, operation);
  if (verified.registryStatus.state !== 'ACTIVE') throw failure('resumable', operation, 'public protocol state is not ACTIVE', true);
}
function portable(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value, (_key, item) => item instanceof Uint8Array ? Buffer.from(item).toString('base64url') : item));
}
function issuanceState(value: Record<string, unknown>): ManagedIssuanceState {
  return { ...value, ...(value.entryBytes !== undefined ? { entryBytes: decodeBytes(value.entryBytes) } : {}) } as unknown as ManagedIssuanceState;
}
function publicPending(cause: unknown): boolean {
  return cause instanceof VerificationError && (cause.transient || cause.code === VerificationCode.RecordNotFound || cause.code === VerificationCode.StatusNotActive && cause.agentState !== 'REVOKED' && cause.agentState !== 'RETIRED');
}
function serverRejected(cause: unknown): boolean {
  if (!cause || typeof cause !== 'object') return false;
  const error = cause as { httpStatus?: number; code?: string };
  return (error.httpStatus === undefined || error.httpStatus >= 400 && error.httpStatus < 500 && ![401, 403, 404, 408, 425, 429].includes(error.httpStatus))
    && ['IDEMPOTENCY_MISMATCH', 'TLOG_PREPARATION_MISMATCH', 'TLOG_INVALID_ENTRY'].includes(error.code ?? '');
}
function transient(cause: unknown): boolean {
  if (cause instanceof FoundryError) return cause.category === 'resumable';
  if (cause instanceof VerificationError) return cause.transient;
  if (cause instanceof RegistryRequestError) return [408, 425, 429].includes(cause.httpStatus) || cause.httpStatus >= 500;
  return cause instanceof Error && ('code' in cause && ['ECONNRESET', 'ETIMEDOUT', 'ECONNREFUSED'].includes(String(cause.code)) || cause instanceof TypeError && cause.cause !== undefined);
}
async function retry<T>(context: Context, call: () => Promise<T>): Promise<T> {
  for (let delay = 1000; ; delay = Math.min(delay * 2, 15_000)) {
    try { return await context.deadline.call(call); }
    catch (cause) { context.deadline.check(); if (!transient(cause)) throw cause; await context.deadline.wait(delay); }
  }
}
function failure(category: FoundryErrorCategory, operation: FoundryOperation, message: string, resumable = false, cause?: unknown): FoundryError {
  const rejection = operation.issuance?.rejection as { code?: string; httpStatus?: number } | undefined;
  return new FoundryError(category, message, { phase: operation.phase, identityId: operation.identityId, domain: operation.domain, registryStatus: operation.registryStatus,
    code: rejection?.code, httpStatus: rejection?.httpStatus, resumable, cause });
}
function normalizeError(cause: unknown, operation: FoundryOperation | undefined, deadline: Deadline): FoundryError {
  if (!(cause instanceof FoundryError && ['busy', 'deadline', 'cancelled'].includes(cause.category))) {
    try { deadline.check(); } catch (error) { cause = error; }
  }
  if (cause instanceof UnsupportedRegistry) return cause;
  const raw = cause && typeof cause === 'object' ? cause as { httpStatus?: number; code?: string; category?: FoundryErrorCategory; resumable?: boolean; issuance?: ManagedIssuanceState } : {};
  let code = raw.issuance?.submission?.errorCode;
  let httpStatus = raw.httpStatus;
  const seen = new Set<unknown>();
  for (let current: unknown = cause; current && typeof current === 'object' && !seen.has(current);) {
    seen.add(current);
    const error = current as { code?: unknown; httpStatus?: unknown; cause?: unknown };
    if (typeof error.httpStatus === 'number') httpStatus = error.httpStatus;
    if (!(current instanceof VerificationError) && typeof error.code === 'string') code = error.code;
    current = error.cause;
  }
  code ??= raw.code;
  const category = ['KEY_MISSING', 'KEY_MISMATCH', 'KEY_REVOKED'].includes(code ?? '') ? code as FoundryErrorCategory
    : raw.category ?? (raw.issuance ? 'workflow-outcome' : cause instanceof VerificationError && !cause.transient || cause instanceof ValidationError ? 'binding'
      : cause instanceof ArgumentError || cause instanceof TypeError || cause instanceof RangeError ? 'unsupported-contract' : 'resumable');
  const message = category === 'KEY_MISMATCH' ? 'use the provider key this identity was created with; run one identity per cloud provider'
    : cause instanceof Error ? cause.message : 'Foundry setup failed';
  return new FoundryError(category, message, {
    phase: operation?.phase, identityId: operation?.identityId, domain: operation?.domain,
    registryStatus: operation?.registryStatus, httpStatus, code,
    resumable: raw.resumable ?? (raw.issuance !== undefined || category === 'resumable' || category === 'deadline' || category === 'busy' || category === 'cancelled'), cause,
  });
}
