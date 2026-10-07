import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import {
  awaitRegistryManagedPublication, issueManagedIdentity, isTransientVerificationError,
  jwkThumbprint, JWKS, registry, retryTransientVerification, VerificationCode, VerificationError,
  type DnsIdJWK, type ManagedIssuanceState,
} from '@dnsid-ai/sdk';
import {
  constructIdentityManager, createRegistryClientFromEnvironment, loadEnvironment,
  LocalKeyProvider, mergeLoadedConfig,
} from '@dnsid-ai/sdk/node';
import { fetchJson } from '@dnsid-ai/transport';
import { prepareStateDirectory, readState, writeState } from './state.ts';

// Deployment trust is selected by the application, never by an unverified record.
const REGISTRY_URL = 'https://api.dev.dnsid.ai';
const GOVERNANCE_ID = 'dev.dnsid.ai';
const ENTITY_KEY_URL = 'https://dnsid.dev.dnsid.ai/.well-known/dnsid-ek.json';
const LOG_PREFIX = 'https://log.dev.dnsid.ai';

interface State {
  request: { registryUrl: string; input: registry.AgentRegistrationInput; idempotencyKey: string };
  registration?: registry.AgentRegistration;
  creationError?: { domain?: string; creation?: unknown; httpStatus?: number; code?: string };
  entityKey?: DnsIdJWK;
  issuance?: ManagedIssuanceState;
}

export async function runRegistration(directory: string, token: string): Promise<void> {
  await prepareStateDirectory(directory);
  let state = await readState<State>(directory, 'recovery.json');
  // Import the original example's recovery files without allocating a new operation.
  if (!state) {
    const request = await readState<State['request']>(directory, 'request.json');
    const registration = await readState<registry.AgentRegistration>(directory, 'registration.json');
    const issuance = await readState<ManagedIssuanceState>(directory, 'issuance.json');
    assert(request || (!registration && !issuance), 'original registration request is missing; restore it from backup');
    if (request) state = { request, registration, issuance, entityKey: await readState(directory, 'entity-key.json') };
  }
  const keys = await LocalKeyProvider.load(join(directory, 'keys.json'), !state);
  state ??= { request: {
    registryUrl: REGISTRY_URL, input: { environment: 'sandbox', publicKeyJwk: await keys.signingKey() },
    idempotencyKey: randomUUID(),
  } };
  assert.equal(state.request.registryUrl, REGISTRY_URL, 'state belongs to a different registry');
  assert.deepEqual(state.request.input.publicKeyJwk, await keys.signingKey(), 'saved operational key changed');
  const save = () => writeState(directory, 'recovery.json', state);
  await save(); // Complete request and replay key are durable before any mutation.

  const env = { ...process.env, DNSID_REGISTRY_URL: process.env.DNSID_REGISTRY_URL ?? REGISTRY_URL, DNSID_API_KEY: token };
  assert.equal(env.DNSID_REGISTRY_URL, REGISTRY_URL, 'this example supports only the dev registry');
  const loaded = await loadEnvironment(env);
  // Setup owns the new identity/key; retain SDK-loaded verification and transport settings.
  delete loaded.dnsid?.identity;
  delete loaded.keySource;
  loaded.logTrust = { managed: true };
  const client = await createRegistryClientFromEnvironment(env, {
    fetch: (url, init) => {
      assert.equal(new URL(String(url)).origin, REGISTRY_URL, 'unexpected registry origin');
      return fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(30_000) });
    },
  });
  if (!state.registration) {
    try {
      state.registration = await client.registerAgent(state.request.input, state.request.idempotencyKey);
      await save();
    } catch (error) {
      if (error instanceof registry.RegistrationError) {
        state.creationError = { domain: error.domain, creation: error.creation, httpStatus: error.httpStatus, code: error.code };
        await save();
      }
      throw error;
    }
  }
  const registration = state.registration;
  const { domain, publicationConfig } = registration;
  assert.equal(registration.publicationAuthority, 'registry');
  assert(domain.endsWith('.sandbox.dev.dnsid.ai'), 'expected a dev sandbox domain');
  assert(publicationConfig, 'missing creation-time publication configuration');
  assert.equal(publicationConfig.governanceId, GOVERNANCE_ID);
  assert.equal(publicationConfig.ekUrl, ENTITY_KEY_URL);
  assert.equal(publicationConfig.logRef, `c2sp-tlog:public:${LOG_PREFIX}#${registration.id}`);
  console.log(`Registered: ${domain}`);

  const current = await client.waitForStatus(domain,
    status => ['VERIFIED', 'READY', 'ERROR', 'REJECTED', 'CANCELLED', 'REVOKED'].includes(status.registryStatus),
    { intervalMs: 1000, timeoutMs: 60_000 });
  assert.equal(current.id, registration.id, 'identity instance changed');
  assert.equal(current.publicationAuthority, 'registry');
  assert(['VERIFIED', 'READY'].includes(current.registryStatus), `registration stopped at ${current.registryStatus}`);
  if (!state.entityKey) {
    const response = await fetchJson(ENTITY_KEY_URL, { allowedHost: new URL(ENTITY_KEY_URL).hostname, maxResponseBytes: 65_536 });
    const jwks = new JWKS((response.data as { keys: DnsIdJWK[] }).keys);
    await jwks.validateRecordSigningKeyset();
    state.entityKey = jwks.currentRecordSigningKey();
    await save();
  }
  const verification = { trustedEntities: [{ governanceId: GOVERNANCE_ID, entityKeyThumbprints: [await jwkThumbprint(state.entityKey)] }] };
  const verifierConfig = mergeLoadedConfig(loaded, { dnsid: { verification } });
  const manager = await constructIdentityManager(mergeLoadedConfig(verifierConfig, {
    dnsid: { identity: { domain, ...publicationConfig } },
  }), { keyProvider: keys });
  const retry = <T>(operation: () => Promise<T>) => retryTransientVerification(operation, {
    maxAttempts: 10, initialDelayMs: 2000, maxDelayMs: 5000,
    shouldRetry: error => isTransientVerificationError(error)
      || (error instanceof VerificationError && error.code === VerificationCode.DNSResolution),
  });
  const issuance = await issueManagedIdentity({
    domain, governanceId: GOVERNANCE_ID, entityKey: state.entityKey, operationalKeyProvider: keys,
    registryClient: client, logReference: publicationConfig.logRef,
    idempotencyKey: state.issuance?.idempotencyKey ?? randomUUID(),
    loadIssuance: async () => state.issuance,
    createIssuance: async intent => {
      if (state.issuance) return state.issuance;
      state.issuance = intent;
      await save();
      return undefined;
    },
    persistIssuance: async issuance => { state.issuance = issuance; await save(); },
    activateAcceptedIssuance: async () => {
      await retry(() => awaitRegistryManagedPublication({
        domain, registryClient: client, identityManager: manager,
        publishProfile: publicationConfig.publishProfile, timeoutMs: 90_000,
      }));
    },
  });
  assert(issuance.activated, `issuance is ${issuance.submission?.state ?? 'incomplete'}; rerun with the same directory`);
  // Fresh verification has no private key, local identity, or owner credential.
  const verifier = await constructIdentityManager(verifierConfig);
  await retry(async () => {
    const verified = await verifier.verifyDomain(domain);
    assert.equal(verified.record.lr, publicationConfig.logRef);
    assert.equal(verified.registryStatus.state, 'ACTIVE');
    await verified.verifyNonRevocation();
    console.log(`Verified: ${verified.domain} status=ACTIVE DNSSEC=${verified.dnssecState}`);
  });
}
