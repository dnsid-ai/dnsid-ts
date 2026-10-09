import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  ArgumentError, SUPPORTED_PUBLISH_PROFILES, DnsIdTxtRecord, JWKS, JWKS_MAX_RESPONSE_BYTES,
  VerificationCode, VerificationError, jwkThumbprint, normalizeFQDN, validateDnsidConfig,
  type DnsIdJWK, type IdentityConfig, type IdentityManager, type IdentityManagerDependencies,
  type LoggedStateEvidence, type LogReader,
} from '@dnsid-ai/protocol';
import {
  DEFAULT_REGISTRY_URL, RegistryClient, RegistrationError, RegistryRequestError, RegistryWorkflowError,
  awaitRegistryManagedPublication, publicationConfigFromResponse, validateAgentRegistrationInput,
  type AgentRegistration, type AgentRegistrationInput, type PublishedRecord,
} from '@dnsid-ai/registry';
import { canonicalBytes, parseC2spEventEntry, parseC2spTlogLr } from '@dnsid-ai/log-c2sp-tlog';
import { constructIdentityManager, operationalKeyProvider, validateKeySource, validateLoadedDnsidConfig, type LoadedConfig, type ManagedRegistrationConfig } from './config-loading.ts';
import { LocalKeyProvider, type LocalKeyAlgorithm } from './local-key-provider.ts';
import { issueManagedIdentity, validateAcceptedManagedIssuance, validateCompletedManagedIssuance, validatePreparedManagedIssuance, type ManagedIssuanceState } from './managed-issuance.ts';

export type ManagedRegistrationPhase = 'storage' | 'organization' | 'key' | 'creation' | 'ownership' | 'entity' | 'issuance' | 'publication' | 'verification' | 'complete';

export interface ManagedRegistrationScope {
  registryUrl: string;
  organizationId: string;
  name: string;
}

export interface AcceptedRegistrationIssuance {
  entryHash: string;
  logRef: string;
  index: number;
}

export interface ManagedRegistrationState extends ManagedRegistrationScope {
  version: 3;
  phase: ManagedRegistrationPhase;
  bindings: string;
  expectations: ManagedRegistrationConfig & { organizationId: string; governanceId: string };
  /** Frozen extra input, removed atomically when validated identity facts are durable. */
  creationInput?: AgentRegistrationInput;
  creationFingerprint: string;
  providerReference: string;
  operationalKey?: DnsIdJWK;
  usedKeyThumbprints?: string[];
  history?: ManagedRegistrationState[];
  creation?: { domain?: string; id?: string; response?: Record<string, unknown>; unsupportedWorkflow?: boolean };
  registration?: AgentRegistration;
  observedRegistryStatus?: string;
  entityKey?: DnsIdJWK;
  entityThumbprint?: string;
  issuance?: ManagedIssuanceState;
  acceptedIssuance?: AcceptedRegistrationIssuance;
  completed: boolean;
}

export interface ManagedRegistrationStore {
  /** Select tenant-isolated state before acquiring the operation lock. */
  forIdentity(scope: ManagedRegistrationScope): ManagedRegistrationStore;
  /** Stable local-key locator, persisted before generation. Custom providers use providerReference. */
  readonly keyStorePath: string;
  acquire(signal: AbortSignal): Promise<() => Promise<void>>;
  load(): Promise<ManagedRegistrationState | undefined>;
  persist(state: ManagedRegistrationState): Promise<void>;
}

export class ManagedRegistrationError extends Error {
  readonly domain?: string;
  readonly registrationId?: string;
  readonly registryStatus?: string;
  readonly setupCompleted?: boolean;
  readonly issuanceState?: NonNullable<ManagedIssuanceState['submission']>['state'];
  constructor(
    readonly code: string,
    readonly phase: ManagedRegistrationPhase,
    readonly resumable: boolean,
    state?: ManagedRegistrationState,
    cause?: unknown,
  ) {
    super(`managed registration failed: ${code} (${phase})`, { cause });
    this.name = 'ManagedRegistrationError';
    this.domain = state?.registration?.domain ?? state?.creation?.domain;
    this.registrationId = state?.registration?.id ?? state?.creation?.id;
    this.registryStatus = state?.observedRegistryStatus;
    this.setupCompleted = state?.completed;
    this.issuanceState = state?.acceptedIssuance ? 'accepted' : state?.issuance?.submission?.state;
  }
}

export interface RegisterManagedIdentityOptions {
  name: string;
  /** Explicit fresh-key replacement after confirmed revocation/retirement; retains history. */
  replace?: boolean;
  loaded: LoadedConfig;
  credential: string;
  store: ManagedRegistrationStore;
  input?: AgentRegistrationInput;
  deps?: IdentityManagerDependencies;
  /** Required with an injected provider; it must rediscover the same key and refuse pending rotations. */
  providerReference?: string;
  /** Stable independently configured trust selection when logRegistry is injected. */
  logTrustReference?: string;
  /** Injected registry networking is caller-owned and must honor RequestInit.signal. */
  fetch?: typeof fetch;
  signal?: AbortSignal;
  /** Finite overall budget, default five minutes. */
  timeoutMs?: number;
  intervalMs?: number;
}

export interface ManagedRegistrationResult {
  registration: AgentRegistration;
  identityManager: IdentityManager;
  publishedRecord: PublishedRecord;
  loggedStateEvidence: LoggedStateEvidence;
}

/**
 * Creates or resumes one durable managed identity; never discovers configuration sources.
 * Requires permanent organization-scoped claims, atomic named opening, and server validation
 * of derived organization/name/key bindings before allocation. Verify this server contract
 * before use; an acknowledgement flag cannot establish support.
 */
export async function registerManagedIdentity(options: RegisterManagedIdentityOptions): Promise<ManagedRegistrationResult> {
  const loaded = structuredClone(options.loaded);
  const name = normalizeManagedRegistrationName(options.name);
  const timeout = options.timeoutMs ?? 300_000;
  const interval = options.intervalMs ?? 1000;
  if (!Number.isFinite(timeout) || timeout <= 0 || timeout > 2 ** 31 - 1 || !Number.isFinite(interval) || interval < 0) throw new ArgumentError('invalid managed setup time budget');
  const deadline = performance.now() + timeout;
  const signal = AbortSignal.any([AbortSignal.timeout(Math.ceil(timeout)), ...(options.signal ? [options.signal] : [])]);
  const remaining = () => { signal.throwIfAborted(); return Math.max(1, deadline - performance.now()); };
  const expectations = setupExpectations(loaded);
  validateLoadedDnsidConfig(loaded.dnsid ?? {});
  const effective = validateDnsidConfig({ ...loaded.dnsid, identity: undefined });
  validatePartialIdentity(loaded.dnsid?.identity, expectations);
  const input = options.input === undefined ? undefined : normalizeInput(options.input);
  if (input?.name !== undefined && input.name !== name) throw new ArgumentError('input.name must match the normalized setup name');
  if (input?.governanceDomain && expectations.governanceId && input.governanceDomain !== expectations.governanceId) throw new ArgumentError('requested governanceDomain does not match registration.governanceId');
  if (typeof options.credential !== 'string' || !options.credential || /\s/.test(options.credential)) throw new ArgumentError('registry credential must be one nonempty API token');
  if (!options.deps?.logRegistry && !loaded.logTrust) throw new ArgumentError('managed setup requires explicit log trust');
  if (options.deps?.logRegistry && !options.logTrustReference) throw new ArgumentError('injected logRegistry requires a stable logTrustReference');
  if (!options.deps?.keyProvider) {
    await validateKeySource(loaded.keySource);
    if (loaded.keySource?.cliDirectory || loaded.keySource?.entityKeyPath) throw new ArgumentError('managed setup uses a durable operational key store, not CLI/entity private keys');
  }
  if (options.deps?.entityKeyProvider) throw new ArgumentError('managed setup does not use an entity private-key provider');
  if (options.providerReference !== undefined && (typeof options.providerReference !== 'string' || !options.providerReference.trim())) throw new ArgumentError('providerReference must be nonempty');
  if (options.deps?.keyProvider && !options.providerReference) throw new ArgumentError('injected keyProvider requires a stable providerReference');
  // Validate transport and trust before creation; this credential-free manager has no local keys.
  const verifierConfig = { ...loaded, dnsid: { ...loaded.dnsid, identity: undefined }, keySource: undefined };
  const bindings = stable({ transport: effective.transport, verification: {
    dnssecMode: effective.verification!.dnssecMode,
    statusCheckInterval: effective.verification!.statusCheckInterval,
  }, logTrust: options.deps?.logRegistry ? options.logTrustReference : loaded.logTrust,
  provider: options.deps?.keyProvider ? 'injected' : loaded.keySource?.provider ?? 'file',
  providerSettings: options.deps?.keyProvider ? undefined : loaded.keySource?.settings,
  generationAlgorithm: options.deps?.keyProvider ? undefined : loaded.keySource?.generation?.algorithm });
  let state: ManagedRegistrationState | undefined;
  let phase: ManagedRegistrationPhase = 'storage';
  let release: (() => Promise<void>) | undefined;
  let observationWrite: Promise<void> | undefined;
  let failure: unknown;
  let store = options.store;
  try {
    remaining();
    await boundedRead(() => constructIdentityManager(verifierConfig, { ...options.deps, keyProvider: undefined, entityKeyProvider: undefined, cache: undefined }), signal);
    remaining();
    const transport = loaded.dnsid?.transport ?? {};
    const network = options.fetch ?? (await import('@dnsid-ai/transport')).createDnsidFetch(transport);
    const client = new RegistryClient({ baseUrl: loaded.registry?.registryUrl, token: options.credential,
      fetch: (url, init) => network(url, { ...init, redirect: 'error', signal: AbortSignal.any([signal, ...(init?.signal ? [init.signal] : [])]) }),
    });
    // Obtain the normalized/defaulted endpoint without reading environment configuration.
    const registryUrl = new URL(loaded.registry?.registryUrl ?? DEFAULT_REGISTRY_URL).toString().replace(/\/$/, '');
    const retry = async <T>(run: () => Promise<T>): Promise<T> => {
      for (;;) {
        remaining();
        try { return await run(); }
        catch (cause) {
          if (signal.aborted) throw cause;
          const absent = (phase === 'publication' || phase === 'verification') && cause instanceof VerificationError
            && cause.code === VerificationCode.DNSResolution && cause.message === `no _dnsid TXT record found for ${state!.registration!.domain}`;
          if (!transient(cause) && !absent) throw cause;
          await sleep(Math.min(interval, remaining()), undefined, { signal });
        }
      }
    };
    phase = 'organization';
    const discover = async () => {
      const account = await retry(() => client.getOrganizationOnboarding({ signal }));
      const gi = account.governanceId && normalizeFQDN(account.governanceId, true);
      if (!gi || !account.gi?.domain || normalizeFQDN(account.gi.domain, true) !== gi
        || account.gi.state !== 'verified' || account.gi.gateAuthorized !== true || account.entityKeyStatus !== 'verified') {
        throw new ManagedRegistrationError('ACCOUNT_NOT_READY', phase, false, state);
      }
      if (expectations.organizationId && expectations.organizationId !== account.organizationId
        || expectations.governanceId && expectations.governanceId !== gi
        || state && (state.organizationId !== account.organizationId || state.expectations.governanceId !== gi)) {
        throw new ManagedRegistrationError('ACCOUNT_BINDING', phase, false, state);
      }
      return { organizationId: account.organizationId, governanceId: gi };
    };
    let discovered: Awaited<ReturnType<typeof discover>> | undefined;
    const organizationId = expectations.organizationId ?? (discovered = await discover()).organizationId;
    const scope = { registryUrl, organizationId, name };
    phase = 'storage';
    store = options.store.forIdentity(scope);
    release = await store.acquire(signal);
    state = await store.load();
    if (state) {
      await validateState(state);
      if (state.registryUrl !== registryUrl || state.organizationId !== organizationId || state.name !== name) throw new ManagedRegistrationError('CONFLICTING_STATE', phase, false, state);
    }
    if (state?.creation?.unsupportedWorkflow) throw new ManagedRegistrationError('UNSUPPORTED_WORKFLOW', 'creation', false, state);
    const governanceId = expectations.governanceId ?? discovered?.governanceId ?? state?.expectations.governanceId
      ?? (await discover()).governanceId;
    const resolved = { ...expectations, organizationId, governanceId };
    let continuingReplacement = options.replace && !!state?.history?.length && !state.completed;
    let replacementObservation: AgentRegistration | undefined;
    if (options.replace && state?.registration) {
      replacementObservation = await retry(() => client.getRegistration(state!.registration!.domain));
      if (!replacementObservation || replacementObservation.id !== state.registration.id || replacementObservation.domain !== state.registration.domain) throw new ManagedRegistrationError('REPLACEMENT_REQUIRES_TERMINAL_STATE', phase, false, state);
      if (['REVOKED', 'RETIRED'].includes(replacementObservation.registryStatus.toUpperCase())) continuingReplacement = false;
      else if (!continuingReplacement) throw new ManagedRegistrationError('REPLACEMENT_REQUIRES_TERMINAL_STATE', phase, false, state);
    }
    if (state && ((!options.replace || continuingReplacement) && !sameDeploymentBindings(state.bindings, bindings, state.completed) || stable(state.expectations) !== stable(resolved))) throw new ManagedRegistrationError('CONFLICTING_STATE', phase, false, state);
    if (input?.governanceDomain && input.governanceDomain !== governanceId) throw new ArgumentError('requested governanceDomain does not match resolved governanceId');
    validatePartialIdentity(loaded.dnsid?.identity, resolved);
    const source = options.deps?.keyProvider ? undefined : loaded.keySource;
    const explicitReference = options.providerReference ?? source?.keyRef ?? source?.keyStorePath
      ?? (source?.generation && `${source.generation.locator}.${managedRegistrationScopeId(scope)}`);
    let providerReference = explicitReference ?? state?.providerReference ?? store.keyStorePath;
    if (!options.deps?.keyProvider && (!source?.provider || source.provider === 'file')) {
      providerReference = path.resolve(providerReference);
      console.warn('Managed registration uses local private-key files, unsuitable for production. Configure keySource.provider/keyRef for cloud custody.');
    }
    const persist = async () => { state!.phase = phase; await store.persist(state!); };
    let history = state?.history;
    if (options.replace && !continuingReplacement) {
      if (!state?.registration) throw new ManagedRegistrationError('REPLACEMENT_REQUIRES_TERMINAL_STATE', phase, false, state);
      const observed = replacementObservation!;
      if (options.deps?.keyProvider || source?.keyRef) {
        const candidate = options.deps?.keyProvider ?? (source?.provider && source.provider !== 'file'
          ? await boundedRead(() => operationalKeyProvider(source!, ''), signal)
          : await recoverLocalKey(providerReference, true, state));
        const thumbprint = await jwkThumbprint(await candidate!.signingKey());
        if ([state, ...state.history ?? []].some(previous => previous.usedKeyThumbprints?.includes(thumbprint))) throw new ManagedRegistrationError('REPLACEMENT_KEY_REUSE', phase, false, state);
      }
      const { history: previous, ...archived } = state;
      archived.observedRegistryStatus = observed.registryStatus.toUpperCase();
      history = [...previous ?? [], archived];
      providerReference = explicitReference ?? `${store.keyStorePath}.${crypto.randomUUID()}`;
      state = undefined;
    }
    const creationInput = extraCreationInput(input ?? {});
    if (state && (explicitReference && state.providerReference !== providerReference && !state.completed
      || input && state.creationFingerprint !== fingerprint(creationInput))) throw new ManagedRegistrationError('CONFLICTING_STATE', phase, false, state);
    if (!state) {
      state = { version: 3, phase, ...scope, bindings, expectations: resolved,
        creationInput, creationFingerprint: fingerprint(creationInput), providerReference, completed: false, history,
        operationalKey: input?.publicKeyJwk,
        usedKeyThumbprints: input?.publicKeyJwk ? [await jwkThumbprint(input.publicKeyJwk)] : undefined };
      await persist();
    }
    phase = 'key';
    const isCloud = !options.deps?.keyProvider && source?.provider && source.provider !== 'file';
    const provider = options.deps?.keyProvider ?? (isCloud
      ? await boundedRead(() => operationalKeyProvider(source!, ''), signal)
      : await recoverLocalKey(providerReference, !!state.operationalKey && state.phase !== 'storage' || !!source?.keyRef, state, source?.generation?.algorithm as LocalKeyAlgorithm | undefined));
    if (!provider) throw new ManagedRegistrationError('MISSING_KEY', phase, false, state);
    if (provider instanceof LocalKeyProvider && provider.hasPendingKeys()) throw new ManagedRegistrationError('ROTATION_RECOVERY_REQUIRED', phase, false, state);
    const currentKey = await provider.signingKey();
    new JWKS([currentKey]).validateOperational();
    assertPublic(currentKey);
    if (!state.completed && source?.generation && source.generation.algorithm !== currentKey.alg) throw new ManagedRegistrationError('KEY_BINDING', phase, false, state);
    if (state.completed && state.bindings !== bindings && await jwkThumbprint(currentKey) === await jwkThumbprint(state.operationalKey!)) throw new ManagedRegistrationError('KEY_SOURCE_BINDING', phase, false, state);
    if (!state.completed && state.operationalKey && !await sameKey(currentKey, state.operationalKey)) throw new ManagedRegistrationError('KEY_BINDING', phase, false, state);
    if (!state.operationalKey) {
      if (input?.publicKeyJwk && !await sameKey(currentKey, input.publicKeyJwk)) throw new ManagedRegistrationError('KEY_BINDING', phase, false, state);
      const thumbprint = await jwkThumbprint(currentKey);
      if (state.history?.some(previous => previous.usedKeyThumbprints?.includes(thumbprint))) throw new ManagedRegistrationError('REPLACEMENT_KEY_REUSE', phase, false, state);
      state.operationalKey = currentKey;
      state.usedKeyThumbprints = [thumbprint];
      await persist();
    }
    if (state.phase === 'storage') await persist();
    if (input?.publicKeyJwk && !await sameKey(input.publicKeyJwk, state.operationalKey)) throw new ManagedRegistrationError('KEY_BINDING', phase, false, state);
    const { registrationKey, issuanceKey } = await deriveManagedRegistrationKeys(organizationId, name, state.operationalKey);
    phase = 'creation';
    const knownIdentity = !!state.registration;
    if (!state.registration) {
      const request = { ...state.creationInput, name, publicKeyJwk: state.operationalKey };
      const registration = await retry(async () => {
        try {
          if (state!.creation?.id && state!.creation.domain && state!.creation.response) {
            const observed = await client.getRegistration(state!.creation.domain);
            if (!observed || observed.id !== state!.creation.id || observed.domain !== state!.creation.domain) throw new ManagedRegistrationError('CREATION_BINDING', phase, false, state);
            const issuer = state!.creation.response.oidc_issuer_url;
            if (issuer !== undefined && (typeof issuer !== 'string' || !issuer.trim())) throw new ArgumentError('invalid retained OIDC issuer');
            return { ...observed, publicationConfig: publicationConfigFromResponse(state!.creation.response.publication_config), oidcIssuerUrl: issuer };
          }
          return await client.registerAgent(request, registrationKey);
        }
        catch (cause) {
          if (cause instanceof RegistrationError) {
            if (cause.creation || cause.domain) {
              const facts = { domain: cause.domain,
                id: typeof cause.creation?.id === 'string' ? cause.creation.id : typeof cause.creation?.agent_id === 'string' ? cause.creation.agent_id : undefined,
                response: cause.creation, unsupportedWorkflow: cause.httpStatus === 202 || undefined };
              if (state!.creation && stable(state!.creation) !== stable(facts)) throw new ManagedRegistrationError('CREATION_BINDING', phase, false, state, cause);
              state!.creation = facts;
              await persist();
            }
            if (cause.httpStatus === 202) throw new ManagedRegistrationError('UNSUPPORTED_WORKFLOW', phase, false, state, cause);
          }
          throw cause;
        }
      });
      if (state.creation && (state.creation.domain && state.creation.domain !== registration.domain || state.creation.id && state.creation.id !== registration.id)) throw new ManagedRegistrationError('CREATION_BINDING', phase, false, state);
      if (state.creation?.response) {
        const original = publicationConfigFromResponse(state.creation.response.publication_config);
        if (stable(original) !== stable(registration.publicationConfig)
          || state.creation.response.oidc_issuer_url !== registration.oidcIssuerUrl) throw new ManagedRegistrationError('CREATION_BINDING', phase, false, state);
      }
      state.observedRegistryStatus = registration.registryStatus;
      const { raw: _raw, ...snapshot } = registration;
      state.registration = snapshot;
      // Keep invalid/unsupported creation facts without compacting them prematurely.
      try {
        assertReplacementIdentity(state);
        identityFromRegistration(registration, resolved);
      }
      catch (error) { await persist(); throw error; }
      delete state.creationInput;
      delete state.creation;
      await persist();
    }
    assertReplacementIdentity(state);
    const registration = state.registration;
    let identity = identityFromRegistration(registration, resolved);
    for (const [key, value] of Object.entries(loaded.dnsid?.identity ?? {})) {
      const normalized = value !== undefined && (key === 'domain' || key === 'governanceId') ? normalizeFQDN(value, true) : value;
      if (normalized !== undefined && normalized !== identity[key as keyof IdentityConfig]) throw new ManagedRegistrationError('IDENTITY_BINDING', phase, false, state);
    }
    let currentRegistration = registration;
    if (knownIdentity) {
      const current = await retry(() => client.getRegistration(registration.domain));
      if (!current) throw new ManagedRegistrationError('REGISTRATION_MISSING', phase, false, state);
      assertRegistration(registration, current, state, state.completed);
      state.observedRegistryStatus = current.registryStatus;
      if (terminal(current.registryStatus)) throw new ManagedRegistrationError('REGISTRY_TERMINAL', phase, false, state);
      currentRegistration = current;
      identity = identityFromRegistration(currentRegistration, resolved);
    }
    const managerConfig = { ...loaded, dnsid: { ...loaded.dnsid, identity }, keySource: undefined };
    const manager = await boundedRead(() => constructIdentityManager(managerConfig, { ...options.deps, keyProvider: provider }), signal);
    phase = 'ownership';
    if (!state.completed && !state.acceptedIssuance && !state.issuance?.submission) {
      await retry(async () => {
        const observed = await client.getRegistration(registration.domain);
        if (!observed) throw new ManagedRegistrationError('REGISTRATION_MISSING', phase, false, state);
        assertRegistration(registration, observed, state!);
        state!.observedRegistryStatus = observed.registryStatus;
        await persist();
        if (terminal(observed.registryStatus)) throw new ManagedRegistrationError('REGISTRY_TERMINAL', phase, false, state);
        if (!['VERIFIED', 'READY'].includes(observed.registryStatus.toUpperCase())) throw new VerificationError('ownership verification pending', { code: VerificationCode.StatusUnavailable, transient: true });
      });
    }
    phase = 'entity';
    if (!state.entityKey) {
      const fetchJson = options.deps?.fetchJson ?? ((url, opts) => import('@dnsid-ai/transport').then(t => t.fetchJson(url, { ...transport, ...opts })));
      const result = await retry(() => boundedRead(() => fetchJson(resolved.entityKeyUrl, { signal, maxResponseBytes: JWKS_MAX_RESPONSE_BYTES }), signal));
      const data = result.data as { keys?: DnsIdJWK[] } | null;
      if (!data || !Array.isArray(data.keys)) throw new ArgumentError('entity bootstrap response must contain a JWKS');
      const jwks = new JWKS(data.keys);
      await jwks.validateRecordSigningKeyset();
      const entityKey = jwks.currentRecordSigningKey();
      assertPublic(entityKey);
      state.entityKey = entityKey;
      state.entityThumbprint = await jwkThumbprint(entityKey);
      await persist();
    }
    // Isolated credential-free verification; application policy and caches are not evidence.
    const pinnedConfig = { ...managerConfig, dnsid: { ...managerConfig.dnsid, verification: {
      ...loaded.dnsid?.verification, trustedEntities: [{ governanceId: resolved.governanceId, entityKeyThumbprints: [state.entityThumbprint!] }],
    } } };
    const publicDeps = { ...options.deps, keyProvider: undefined, entityKeyProvider: undefined, cache: undefined };
    const newVerifier = () => boundedRead(() => constructIdentityManager({
      ...pinnedConfig, dnsid: { ...pinnedConfig.dnsid, identity: undefined },
    }, publicDeps), signal);
    phase = 'issuance';
    if (state.acceptedIssuance || state.issuance?.submission?.state === 'accepted'
      || state.observedRegistryStatus?.toUpperCase() === 'READY') {
      await retry(async () => {
        const verifier = await newVerifier();
        const verified = await verifier.verifyDomain(registration.domain, undefined, { signal, timeoutMs: remaining() });
        assertRecord(verified.record, identity, state!);
        if (!await sameKey(verified.jwks.currentOperationalSigningKey(), currentKey)) throw new ManagedRegistrationError('PUBLIC_KEY_BINDING', phase, false, state);
        await recoverAcceptedIssuance(verified.logReader, state!, signal);
        await persist();
      });
    } else {
      await retry(async () => {
        const issuance = await issueManagedIdentity({ domain: registration.domain, governanceId: resolved.governanceId,
          entityKey: state!.entityKey!, operationalKeyProvider: provider, registryClient: {
            prepareIssuance: (domain, key) => { remaining(); return client.prepareIssuance(domain, key); },
            submitPreparedEvent: (domain, bytes, key) => { remaining(); return client.submitPreparedEvent(domain, bytes, key); },
          },
          idempotencyKey: issuanceKey, logReference: parseC2spTlogLr(identity.logRef).lr,
          loadIssuance: async () => state!.issuance,
          createIssuance: async intent => { state!.issuance = intent; await persist(); return undefined; },
          persistIssuance: async issuance => { state!.issuance = issuance; await persist(); },
          // The registry owns convergence. Accepted bytes are durable before this internal observation marker.
          activateAcceptedIssuance: async () => {},
        });
        if (issuance.submission?.state !== 'accepted') throw new VerificationError('issuance acceptance pending', { code: VerificationCode.LogError, transient: true });
      });
    }
    phase = 'publication';
    const publicationManager = await boundedRead(() => constructIdentityManager(pinnedConfig, { ...publicDeps, keyProvider: provider }), signal);
    const publishedRecord = await retry(() => awaitRegistryManagedPublication({ domain: registration.domain,
      registryClient: client, identityManager: publicationManager, expectedRegistration: currentRegistration,
      publishProfile: identity.publishProfile, intervalMs: interval, timeoutMs: remaining(), signal,
      onObservation: async observed => {
        state!.observedRegistryStatus = observed.registryStatus;
        observationWrite = persist();
        await observationWrite;
      },
    }));
    phase = 'verification';
    const observed = await retry(async () => {
      const verifier = await newVerifier();
      const verified = await verifier.verifyDomain(registration.domain, undefined, { signal, timeoutMs: remaining() });
      assertRecord(verified.record, identity, state!);
      if (verified.signingKeyThumbprint !== state!.entityThumbprint || !await sameKey(verified.jwks.currentOperationalSigningKey(), currentKey)) throw new ManagedRegistrationError('PUBLIC_KEY_BINDING', phase, false, state);
      const bilateral = await boundedRead(() => verified.logReader.verifyBilateralBinding(verified.record, state!.entityKey, currentKey), signal);
      if (bilateral.initialOperationalThumbprint !== await jwkThumbprint(state!.operationalKey!)
        || bilateral.initialEntityThumbprint !== state!.entityThumbprint) throw new ManagedRegistrationError('HISTORICAL_KEY_BINDING', phase, false, state);
      await recoverAcceptedIssuance(verified.logReader, state!, signal);
      const history = await boundedRead(() => verified.logReader.rebuildHistory(registration.domain), signal);
      for (const event of history) {
        const thumbprint = event.type === 'KEY_ROTATION' ? event.newOperationalThumbprint : undefined;
        if (thumbprint && !state!.usedKeyThumbprints!.includes(thumbprint)) state!.usedKeyThumbprints!.push(thumbprint);
      }
      const evidence = await boundedRead(() => verified.verifyNonRevocation(new Date()), signal);
      remaining();
      if (evidence.loggedState !== 'ACTIVE' || parseC2spTlogLr(evidence.logReference).lr !== parseC2spTlogLr(identity.logRef).lr) throw new ManagedRegistrationError('PUBLIC_LOG_BINDING', phase, false, state);
      return evidence;
    });
    remaining();
    phase = 'complete';
    state.completed = true;
    state.providerReference = providerReference;
    state.bindings = bindings;
    const currentThumbprint = await jwkThumbprint(currentKey);
    if (!state.usedKeyThumbprints!.includes(currentThumbprint)) state.usedKeyThumbprints!.push(currentThumbprint);
    await persist();
    remaining();
    return { registration, identityManager: manager, publishedRecord, loggedStateEvidence: observed };
  } catch (cause) {
    // Publication cancellation must not release the store while its observer is still writing.
    if (observationWrite) {
      try { await observationWrite; }
      catch (storageCause) { if (storageCause !== cause) cause = new AggregateError([cause, storageCause]); }
    }
    failure = cause;
    if (cause instanceof ManagedRegistrationError) throw cause;
    if (state && cause instanceof RegistryWorkflowError) {
      state.observedRegistryStatus = cause.registration.registryStatus;
      state.phase = phase;
      try { await store.persist(state); }
      catch (storageCause) {
        failure = new ManagedRegistrationError('STORAGE_FAILED', 'storage', false, state, new AggregateError([cause, storageCause]));
        throw failure;
      }
    }
    failure = new ManagedRegistrationError(signal.aborted ? 'CANCELLED_OR_DEADLINE' : 'SETUP_FAILED', phase, signal.aborted || transient(cause), state, cause);
    throw failure;
  } finally {
    try { await release?.(); }
    catch (cause) {
      throw new ManagedRegistrationError('STORAGE_RELEASE_FAILED', 'storage', false, state,
        failure === undefined ? cause : new AggregateError([failure, cause]));
    }
  }
}

function setupExpectations(loaded: LoadedConfig): ManagedRegistrationConfig {
  const config = loaded.registration;
  if (!config?.entityKeyUrl) throw new ArgumentError('registration.entityKeyUrl is required');
  const governanceId = config.governanceId === undefined ? undefined : normalizeFQDN(config.governanceId, true);
  if (config.organizationId !== undefined && (typeof config.organizationId !== 'string' || !config.organizationId.trim() || config.organizationId !== config.organizationId.trim())) throw new ArgumentError('registration.organizationId must be nonempty');
  let url: URL;
  try { url = new URL(config.entityKeyUrl); } catch { throw new ArgumentError('registration.entityKeyUrl must be HTTPS'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new ArgumentError('registration.entityKeyUrl must be HTTPS without userinfo or fragment');
  return { organizationId: config.organizationId, governanceId, entityKeyUrl: config.entityKeyUrl };
}

function validatePartialIdentity(identity: Partial<IdentityConfig> | undefined, expected: ManagedRegistrationConfig): void {
  if (!identity) return;
  if (identity.domain !== undefined) normalizeFQDN(identity.domain, true);
  if (identity.governanceId !== undefined && expected.governanceId !== undefined && normalizeFQDN(identity.governanceId, true) !== expected.governanceId
    || identity.ekUrl !== undefined && identity.ekUrl !== expected.entityKeyUrl) throw new ArgumentError('local identity contradicts managed setup expectations');
  if (identity.logRef !== undefined) parseC2spTlogLr(identity.logRef);
  if (identity.publishProfile !== undefined && !SUPPORTED_PUBLISH_PROFILES.includes(identity.publishProfile as typeof SUPPORTED_PUBLISH_PROFILES[number])) throw new ArgumentError('unsupported local publish profile');
  if (identity.maxKeyAge !== undefined && !['24h', '7d', '30d', '90d'].includes(identity.maxKeyAge)) throw new ArgumentError('unsupported local maxKeyAge');
  for (const field of ['statusUrl', 'ekUrl', 'kuUrl', 'capabilitiesUrl'] as const) {
    if (identity[field] === undefined) continue;
    let url: URL;
    try { url = new URL(identity[field]); } catch { throw new ArgumentError(`identity.${field} must be HTTPS`); }
    if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new ArgumentError(`identity.${field} must be HTTPS without userinfo or fragment`);
  }
}

function normalizeInput(input: AgentRegistrationInput): AgentRegistrationInput {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new ArgumentError('registration input must be an object');
  const request = structuredClone(input);
  const allowed = ['domain', 'governanceDomain', 'rootDomain', 'name', 'publicKeyJwk', 'environment', 'managed', 'zoneId', 'capabilitiesUrl'];
  if (Object.keys(request).some(key => !allowed.includes(key))) throw new ArgumentError('unsupported managed registration input member');
  if (request.managed !== undefined && typeof request.managed !== 'boolean' || request.zoneId !== undefined && typeof request.zoneId !== 'string') throw new ArgumentError('invalid registration selector');
  validateAgentRegistrationInput(request, false);
  return request;
}

function identityFromRegistration(registration: AgentRegistration, expected: ManagedRegistrationConfig): IdentityConfig {
  const config = registration.publicationConfig;
  if (registration.publicationAuthority !== 'registry') throw new ManagedRegistrationError('UNSUPPORTED_AUTHORITY', 'creation', false, { registration } as ManagedRegistrationState);
  if (!config || config.governanceId !== expected.governanceId || config.ekUrl !== expected.entityKeyUrl
    || !SUPPORTED_PUBLISH_PROFILES.includes(config.publishProfile as typeof SUPPORTED_PUBLISH_PROFILES[number])) throw new ManagedRegistrationError('PUBLICATION_BINDING', 'creation', false, { registration } as ManagedRegistrationState);
  const identity = { ...config, domain: registration.domain };
  parseC2spTlogLr(identity.logRef);
  validateDnsidConfig({ identity });
  return identity;
}

function assertReplacementIdentity(state: ManagedRegistrationState): void {
  const registration = state.registration!;
  if (state.history?.some(previous => previous.registration?.id === registration.id || previous.registration?.domain === registration.domain
    || previous.registration?.publicationConfig?.logRef === registration.publicationConfig?.logRef)) throw new ManagedRegistrationError('REPLACEMENT_IDENTITY_REUSE', 'creation', false, state);
}

function assertRegistration(expected: AgentRegistration, observed: AgentRegistration, state: ManagedRegistrationState, allowRotation = false): void {
  const snapshot = (r: AgentRegistration) => ({ id: r.id, domain: r.domain, publicationAuthority: r.publicationAuthority, publicationConfig: allowRotation && r.publicationConfig ? { ...r.publicationConfig, kuUrl: undefined } : r.publicationConfig, oidcIssuerUrl: r.oidcIssuerUrl, registryUrl: r.registryUrl });
  if (stable(snapshot(expected)) !== stable(snapshot(observed))) throw new ManagedRegistrationError('PUBLICATION_BINDING', 'ownership', false, state);
}

function assertRecord(record: DnsIdTxtRecord, identity: IdentityConfig, state: ManagedRegistrationState): void {
  const expected = new DnsIdTxtRecord();
  Object.assign(expected, { agentFQDN: identity.domain, v: identity.publishProfile, gi: identity.governanceId,
    ek: identity.ekUrl, ku: identity.kuUrl, lr: identity.logRef, su: identity.statusUrl,
    cu: identity.capabilitiesUrl, ka: identity.maxKeyAge });
  if (record.knownTagsCanonical() !== expected.knownTagsCanonical()) throw new ManagedRegistrationError('PUBLICATION_BINDING', 'verification', false, state);
}

async function recoverLocalKey(locator: string, initialized: boolean, state: ManagedRegistrationState, algorithm?: LocalKeyAlgorithm): Promise<LocalKeyProvider> {
  try {
    const stat = await fs.lstat(locator);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) throw new ManagedRegistrationError('UNSAFE_STORAGE', 'key', false, state);
    return await LocalKeyProvider.load(locator);
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code !== 'ENOENT') throw cause;
    if (initialized) throw new ManagedRegistrationError('MISSING_KEY', 'key', false, state);
    let files: string[] = [];
    try { files = await fs.readdir(path.dirname(locator)); }
    catch (cause) { if ((cause as NodeJS.ErrnoException).code !== 'ENOENT') throw cause; }
    if (files.some(name => name.startsWith(path.basename(locator)))) throw new ManagedRegistrationError('AMBIGUOUS_KEY_CREATION', 'key', false, state);
    return LocalKeyProvider.load(locator, true, algorithm);
  }
}

async function validateState(state: ManagedRegistrationState): Promise<void> {
  try {
    if (!state || state.version !== 3 || !state.registryUrl || !state.organizationId || !state.bindings || !state.providerReference
      || normalizeManagedRegistrationName(state.name) !== state.name || !/^[0-9a-f]{64}$/.test(state.creationFingerprint)
      || typeof state.completed !== 'boolean') throw new Error('invalid intent');
    const deployment = JSON.parse(state.bindings);
    if (!deployment || typeof deployment !== 'object' || Array.isArray(deployment)) throw new Error('invalid deployment binding');
    setupExpectations({ registration: state.expectations });
    if (!state.expectations.governanceId || state.expectations.organizationId !== state.organizationId) throw new Error('invalid account binding');
    if (!['storage', 'key', 'creation', 'ownership', 'entity', 'issuance', 'publication', 'verification', 'complete'].includes(state.phase)) throw new Error('invalid phase');
    if (state.creationInput) {
      normalizeInput(state.creationInput);
      if (state.creationInput.name !== undefined || state.creationInput.publicKeyJwk !== undefined
        || fingerprint(state.creationInput) !== state.creationFingerprint) throw new Error('invalid creation input');
    } else if (!state.registration) throw new Error('missing unresolved input');
    if (state.operationalKey) {
      assertPublic(state.operationalKey);
      new JWKS([state.operationalKey]).validateOperational();
      if (!state.usedKeyThumbprints?.includes(await jwkThumbprint(state.operationalKey))) throw new Error('missing initial key binding');
    }
    if (state.registration) {
      if (!state.operationalKey || !state.registration.id || state.registration.registryUrl !== state.registryUrl
        || normalizeFQDN(state.registration.domain, true) !== state.registration.domain) throw new Error('invalid registration');
      if (state.registration.publicationConfig) validateDnsidConfig({ identity: { ...state.registration.publicationConfig, domain: state.registration.domain } });
    }
    if (state.entityKey) {
      assertPublic(state.entityKey);
      await new JWKS([state.entityKey]).validateRecordSigningKeyset();
      if (state.entityThumbprint !== await jwkThumbprint(state.entityKey)) throw new Error('invalid entity pin');
    }
    if (state.entityKey && !state.registration) throw new Error('entity selection without registration');
    if (state.creation && !state.operationalKey) throw new Error('creation without key');
    if (state.issuance) {
      if (state.acceptedIssuance || !state.entityKey || !state.operationalKey || !state.registration
        || state.issuance.domain !== state.registration.domain || state.issuance.governanceId !== state.expectations.governanceId
        || state.issuance.idempotencyKey !== (await deriveManagedRegistrationKeys(state.organizationId, state.name, state.operationalKey)).issuanceKey
        || state.issuance.entityKid !== state.entityKey.kid || state.issuance.operationalKid !== state.operationalKey.kid
        || state.issuance.entityThumbprint !== state.entityThumbprint || state.issuance.operationalThumbprint !== await jwkThumbprint(state.operationalKey)
        || state.issuance.submission && !state.issuance.entryBytes) throw new Error('invalid issuance');
      if (!!state.issuance.entryBytes !== !!state.issuance.entryHash || !!state.issuance.preparedEntryBytes !== !!state.issuance.logReference
        || state.issuance.entryBytes && !state.issuance.preparedEntryBytes) throw new Error('incomplete issuance artifacts');
      if (state.issuance.submission?.state === 'accepted') await validateAcceptedManagedIssuance(state.issuance, state.entityKey, state.operationalKey);
      else if (state.issuance.entryBytes) await validateCompletedManagedIssuance(state.issuance, state.entityKey, state.operationalKey);
      else if (state.issuance.preparedEntryBytes) await validatePreparedManagedIssuance(state.issuance, state.entityKey, state.operationalKey);
    }
    if (state.acceptedIssuance) {
      const accepted = state.acceptedIssuance;
      if (!state.entityKey || !state.registration?.publicationConfig || !/^[0-9a-f]{64}$/.test(accepted.entryHash)
        || !Number.isSafeInteger(accepted.index) || accepted.index < 0
        || accepted.logRef !== `${parseC2spTlogLr(state.registration.publicationConfig.logRef).lr}@${accepted.index}`) throw new Error('invalid accepted issuance');
    }
    if (state.completed && !state.acceptedIssuance) throw new Error('invalid completion');
    for (const previous of state.history ?? []) {
      if (previous.history || previous.registryUrl !== state.registryUrl || previous.organizationId !== state.organizationId
        || previous.name !== state.name || !['REVOKED', 'RETIRED'].includes(previous.observedRegistryStatus ?? '')) throw new Error('invalid replacement history');
      await validateState(previous);
    }
  } catch (cause) { throw new ManagedRegistrationError('CORRUPT_STATE', 'storage', false, state, cause); }
}

/** Trim a case-sensitive display handle; it is not a domain or a filesystem path. */
export function normalizeManagedRegistrationName(name: string): string {
  if (typeof name !== 'string') throw new ArgumentError('managed registration name is required');
  const normalized = name.trim();
  if (!normalized || Array.from(normalized).length > 255 || /[\uD800-\uDFFF]/u.test(normalized)) throw new ArgumentError('managed registration name must contain 1 to 255 Unicode code points');
  return normalized;
}

/** Safe deterministic state-directory identifier for the complete tenant/name tuple. */
export function managedRegistrationScopeId(scope: ManagedRegistrationScope): string {
  return fingerprint([scope.registryUrl, scope.organizationId, normalizeManagedRegistrationName(scope.name)]);
}

/** RFC 8785 JCS, RFC 7638 key thumbprint, SHA-256 and unpadded base64url. */
export async function deriveManagedRegistrationKeys(organizationId: string, name: string, initialKey: DnsIdJWK) {
  const registrationKey = createHash('sha256').update(canonicalBytes([
    'dnsid-managed-registration-v1', organizationId, normalizeManagedRegistrationName(name), await jwkThumbprint(initialKey),
  ])).digest('base64url');
  const issuanceKey = createHash('sha256').update(canonicalBytes(['dnsid-managed-issuance-v1', registrationKey])).digest('base64url');
  return { registrationKey, issuanceKey };
}

function extraCreationInput(input: AgentRegistrationInput): AgentRegistrationInput {
  const { name: _name, publicKeyJwk: _publicKey, ...extra } = input;
  return Object.fromEntries(Object.entries(extra).filter(([, value]) => value !== undefined));
}

function fingerprint(value: unknown): string {
  return createHash('sha256').update(canonicalBytes(value)).digest('hex');
}

async function recoverAcceptedIssuance(reader: LogReader, state: ManagedRegistrationState, signal: AbortSignal): Promise<void> {
  const bindingReader = reader as LogReader & {
    readIssuance?: (domain: string) => Promise<{ entryBytes: Uint8Array; index: number; logRef: string }>;
  };
  if (!bindingReader.readIssuance) throw new ManagedRegistrationError('ISSUANCE_RECOVERY_UNAVAILABLE', 'issuance', false, state);
  const accepted = await boundedRead(() => bindingReader.readIssuance!(state.registration!.domain), signal);
  const entryHash = createHash('sha256').update(accepted.entryBytes).digest('hex');
  const expected = state.acceptedIssuance ?? state.issuance?.submission;
  if (expected && expected.entryHash !== entryHash || state.issuance?.entryHash && state.issuance.entryHash !== entryHash) throw new ManagedRegistrationError('ISSUANCE_BINDING', 'issuance', false, state);
  if (state.acceptedIssuance && (state.acceptedIssuance.logRef !== accepted.logRef || state.acceptedIssuance.index !== accepted.index)) throw new ManagedRegistrationError('ISSUANCE_BINDING', 'issuance', false, state);
  const event = await parseC2spEventEntry(accepted.entryBytes);
  if (event.type !== 'ISSUANCE' || !event.initialOperationalPublicKey) throw new ManagedRegistrationError('ISSUANCE_BINDING', 'issuance', false, state);
  const initialKey = !state.acceptedIssuance && !state.issuance ? event.initialOperationalPublicKey : state.operationalKey!;
  const issuance: ManagedIssuanceState = {
    domain: state.registration!.domain, governanceId: state.expectations.governanceId,
    idempotencyKey: (await deriveManagedRegistrationKeys(state.organizationId, state.name, initialKey)).issuanceKey,
    entityKid: state.entityKey!.kid, entityThumbprint: state.entityThumbprint!,
    operationalKid: initialKey.kid, operationalThumbprint: await jwkThumbprint(initialKey),
    logReference: parseC2spTlogLr(state.registration!.publicationConfig!.logRef).lr,
    entryBytes: accepted.entryBytes, entryHash,
    submission: { state: 'accepted', entryHash, index: accepted.index, logRef: accepted.logRef }, activated: true,
  };
  await validateAcceptedManagedIssuance(issuance, state.entityKey!, initialKey);
  state.operationalKey = initialKey;
  const initialThumbprint = await jwkThumbprint(initialKey);
  if (!state.usedKeyThumbprints!.includes(initialThumbprint)) state.usedKeyThumbprints!.push(initialThumbprint);
  state.acceptedIssuance = { entryHash, index: accepted.index, logRef: accepted.logRef };
  delete state.issuance;
}

function assertPublic(key: DnsIdJWK): void {
  if (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some(field => field in key)) throw new ArgumentError('private key material is forbidden in setup recovery data');
}

async function sameKey(a: DnsIdJWK, b: DnsIdJWK): Promise<boolean> {
  return a.kid === b.kid && a.alg === b.alg && await jwkThumbprint(a) === await jwkThumbprint(b);
}
/** Only read-only work may outlive cancellation; mutations must settle before releasing the store. */
async function boundedRead<T>(read: () => Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted();
  let abort!: () => void;
  const cancelled = new Promise<never>((_resolve, reject) => {
    abort = () => reject(signal.reason);
    signal.addEventListener('abort', abort, { once: true });
  });
  try { return await Promise.race([read(), cancelled]); }
  finally { signal.removeEventListener('abort', abort); }
}

function terminal(status: string): boolean { return ['ERROR', 'REJECTED', 'CANCELLED', 'REVOKED', 'RETIRED'].includes(status.toUpperCase()); }
function transient(cause: unknown): boolean {
  if (cause instanceof VerificationError) return cause.transient && cause.code !== VerificationCode.RecordInvalid;
  if (cause instanceof RegistrationError) return cause.httpStatus === undefined || cause.httpStatus >= 500 || cause.httpStatus === 429
    || cause.httpStatus === 201 && cause.cause instanceof TypeError;
  if (cause instanceof RegistryRequestError) return cause.httpStatus >= 500 || cause.httpStatus === 429;
  if (cause instanceof RegistryWorkflowError) return false;
  return cause instanceof TypeError; // Fetch transport failures; no broad verification retries.
}
function sameDeploymentBindings(saved: string, current: string, allowProviderChange: boolean): boolean {
  if (!allowProviderChange) return saved === current;
  const previous = JSON.parse(saved);
  const expected = JSON.parse(current);
  for (const binding of [previous, expected]) {
    delete binding.provider; delete binding.providerSettings; delete binding.generationAlgorithm;
  }
  return stable(previous) === stable(expected);
}

function stable(value: unknown): string {
  return JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item)
    ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);
}
