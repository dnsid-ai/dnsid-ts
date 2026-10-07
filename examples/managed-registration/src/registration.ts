import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import {
  awaitRegistryManagedPublication,
  issueManagedIdentity,
  isTransientVerificationError,
  jwkThumbprint,
  JWKS,
  registry,
  RegistryClient,
  retryTransientVerification,
  VerificationCode,
  VerificationError,
  type DnsIdJWK,
  type ManagedIssuanceState,
} from '@dnsid-ai/sdk';
import { createNodeIdentityManager, createNodeIdentityVerifier, LocalKeyProvider } from '@dnsid-ai/sdk/node';
import { createDnsidManagedVerificationRegistry } from '@dnsid-ai/log-c2sp-tlog';
import { fetchJson } from '@dnsid-ai/transport';
import { prepareStateDirectory, readState, writeState } from './state.ts';

// Application configuration, not trust discovered from an unverified DNSid record.
const REGISTRY_URL = 'https://api.dev.dnsid.ai';
const GOVERNANCE_ID = 'dev.dnsid.ai';
const ENTITY_KEY_URL = 'https://dnsid.dev.dnsid.ai/.well-known/dnsid-ek.json';
const LOG_PREFIX = 'https://log.dev.dnsid.ai';

interface RegistrationRequest {
  registryUrl: string;
  input: registry.AgentRegistrationInput;
  idempotencyKey: string;
}

async function register(directory: string, client: RegistryClient): Promise<registry.AgentRegistration> {
  let request = await readState<RegistrationRequest>(directory, 'request.json');
  const saved = await readState<registry.AgentRegistration>(directory, 'registration.json');
  if (!request) {
    assert(!saved && !await readState(directory, 'issuance.json'), 'original registration request is missing; restore it from backup');
  }
  const keys = await LocalKeyProvider.load(join(directory, 'keys.json'), !request);
  if (!request) {
    request = {
      registryUrl: REGISTRY_URL,
      input: { environment: 'sandbox', publicKeyJwk: await keys.signingKey() },
      idempotencyKey: randomUUID(),
    };
    // Persist the complete original request before the first remote mutation.
    await writeState(directory, 'request.json', request);
  }
  assert.equal(request.registryUrl, REGISTRY_URL, 'state belongs to a different registry');
  assert.deepEqual(request.input.publicKeyJwk, await keys.signingKey(), 'saved operational key changed');

  if (saved) return saved;
  try {
    const registration = await client.registerAgent(request.input, request.idempotencyKey);
    await writeState(directory, 'registration.json', registration);
    return registration;
  } catch (error) {
    if (error instanceof registry.RegistrationError) {
      await writeState(directory, 'registration-error.json', {
        domain: error.domain, creation: error.creation, httpStatus: error.httpStatus, code: error.code,
      });
    }
    throw error;
  }
}

async function loadEntityKey(directory: string): Promise<DnsIdJWK> {
  const saved = await readState<DnsIdJWK>(directory, 'entity-key.json');
  if (saved) return saved;
  const response = await fetchJson(ENTITY_KEY_URL, {
    allowedHost: new URL(ENTITY_KEY_URL).hostname,
    maxResponseBytes: 65_536,
  });
  const keys = new JWKS((response.data as { keys: DnsIdJWK[] }).keys);
  await keys.validateRecordSigningKeyset();
  const key = keys.currentRecordSigningKey();
  await writeState(directory, 'entity-key.json', key);
  return key;
}

export async function runRegistration(directory: string, token: string): Promise<void> {
  await prepareStateDirectory(directory);
  const client = new RegistryClient({
    baseUrl: REGISTRY_URL,
    token,
    fetch: (url, init) => {
      assert.equal(new URL(String(url)).origin, REGISTRY_URL, 'unexpected registry origin');
      return fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(30_000) });
    },
  });

  console.log('1. Register or recover the sandbox identity');
  const registration = await register(directory, client);
  const { domain, publicationConfig } = registration;
  assert.equal(registration.publicationAuthority, 'registry');
  assert(domain.endsWith('.sandbox.dev.dnsid.ai'), 'expected a dev sandbox domain');
  assert(publicationConfig, 'creation response has no publication configuration');
  assert.equal(publicationConfig.governanceId, GOVERNANCE_ID);
  assert.equal(publicationConfig.ekUrl, ENTITY_KEY_URL);
  assert.equal(publicationConfig.logRef, `c2sp-tlog:public:${LOG_PREFIX}#${registration.id}`);

  // Sandbox ownership verification is automatic; no hosted challenge server is needed.
  const current = await client.waitForStatus(domain,
    status => ['VERIFIED', 'READY', 'ERROR', 'REJECTED', 'CANCELLED', 'REVOKED'].includes(status.registryStatus),
    { intervalMs: 1000, timeoutMs: 60_000 });
  assert.equal(current.id, registration.id, 'identity instance changed');
  assert.equal(current.publicationAuthority, 'registry');
  assert(['VERIFIED', 'READY'].includes(current.registryStatus), `registration stopped at ${current.registryStatus}`);

  console.log('2. Issue the identity or resume the saved ISSUANCE');
  const operationalKeyProvider = await LocalKeyProvider.load(join(directory, 'keys.json'));
  const entityKey = await loadEntityKey(directory);
  const logRegistry = await createDnsidManagedVerificationRegistry();
  const verification = {
    trustedEntities: [{ governanceId: GOVERNANCE_ID, entityKeyThumbprints: [await jwkThumbprint(entityKey)] }],
  };
  const identityManager = await createNodeIdentityManager({
    identity: { domain, ...publicationConfig }, verification,
  }, { keyProvider: operationalKeyProvider, logRegistry });
  const loadIssuance = () => readState<ManagedIssuanceState>(directory, 'issuance.json');
  const existing = await loadIssuance();
  const issuance = await issueManagedIdentity({
    domain, governanceId: GOVERNANCE_ID, entityKey, operationalKeyProvider,
    registryClient: client,
    logReference: publicationConfig.logRef,
    idempotencyKey: existing?.idempotencyKey ?? randomUUID(),
    loadIssuance,
    createIssuance: async intent => {
      const saved = await loadIssuance();
      if (saved) return saved;
      await writeState(directory, 'issuance.json', intent);
      return undefined;
    },
    persistIssuance: state => writeState(directory, 'issuance.json', state),
    activateAcceptedIssuance: async () => {
      console.log('3. Wait for registry publication and verify its evidence');
      // READY can precede TXT visibility through recursive DNS. Only retry reads;
      // signature, key-binding, and trust-policy failures still fail closed.
      const publication = await retryTransientVerification(() => awaitRegistryManagedPublication({
        domain, registryClient: client, identityManager,
        publishProfile: publicationConfig.publishProfile, timeoutMs: 90_000,
      }), {
        maxAttempts: 10, initialDelayMs: 2000, maxDelayMs: 5000,
        shouldRetry: error => isTransientVerificationError(error)
          || (error instanceof VerificationError && error.code === VerificationCode.DNSResolution),
      });
      await writeState(directory, 'publication.json', publication);
    },
  });
  assert(issuance.activated, `issuance is ${issuance.submission?.state ?? 'incomplete'}; rerun with the same directory`);

  console.log('4. Verify independently from public DNS, without registry credentials');
  const verifier = await createNodeIdentityVerifier({ verification }, {
    logRegistry: await createDnsidManagedVerificationRegistry(),
  });
  const verified = await verifier.verifyDomain(domain);
  assert.equal(verified.registryStatus.state, 'ACTIVE');
  const result = {
    domain: verified.domain, protocolState: verified.registryStatus.state,
    publishProfile: verified.record.v, governanceId: verified.record.governanceId(),
    dnssecState: verified.dnssecState, logReference: verified.record.lr, verifiedAt: verified.verifiedAt,
  };
  await writeState(directory, 'verification.json', result);
  console.log(JSON.stringify(result, null, 2));
}
