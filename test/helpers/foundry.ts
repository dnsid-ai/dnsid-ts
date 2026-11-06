import { createHash } from 'node:crypto';
import { vi } from 'vitest';
import {
  DNSSECState, DnsIdTxtRecord, LogRegistry, jwkThumbprint,
  type AgentStatusState, type C2spIssuanceEvent, type DnsIdJWK,
  type DNSResolver, type KeyProvider, type LogReader,
} from '@dnsid-ai/sdk';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
import {
  C2spTlogVerificationError, canonicalBytes, parseC2spEventEntry,
  prepareC2spTlogEventForSigning, signPreparedC2spTlogEvent, signedC2spEntryBytes,
} from '@dnsid-ai/log-c2sp-tlog';
import { PreparedEventSubmissionError, RegistryRequestError, type AgentRegistration, type LiveProvisioningResponse, type PublicationConfig } from '@dnsid-ai/registry';
import { FileFoundryStore, type CreateOptions, type FoundryRegistry } from '@dnsid-ai/foundry';

export const ORG = '11111111-1111-4111-8111-111111111111';
export const DOMAIN = 'agent.example.com';
export const GI = 'example.com';
export const LR = 'c2sp-tlog:public:https://log.example/dnsid#ERERERERERERERERERERER';
export const publication: PublicationConfig = {
  publishProfile: 'dnsid-draft-01', governanceId: GI, kuUrl: `https://${DOMAIN}/ku`,
  ekUrl: `https://${GI}/ek`, logRef: LR, statusUrl: `https://${DOMAIN}/status`,
};

export async function foundryFixture(directory: string) {
  const provider = await LocalKeyProvider.generate();
  const entity = await LocalKeyProvider.generate('ES256');
  const operationalKey = await provider.signingKey();
  const entityKey = await entity.signingKey();
  let accepted: C2spIssuanceEvent | undefined;
  let preparedBytes: Uint8Array | undefined;
  let registrationKey = '';
  const fixture = {
    provider, entity, operationalKey, entityKey,
    organizationId: ORG, governanceId: GI, ready: true,
    registryStatus: 'VERIFIED', publicState: 'ACTIVE' as AgentStatusState,
    proofRequired: false, replayWithoutDomain: false, expiredProof: false,
    dnsMissing: false, publicKey: operationalKey, publicGovernance: GI, publicLog: LR,
    submitMode: 'accepted' as 'accepted' | 'lost' | 'reject-winner' | 'rejected',
    acceptedBytes: undefined as Uint8Array | undefined,
    prepared: () => preparedBytes,
    registry: {} as FoundryRegistry,
    reader: {} as LogReader,
    options: {} as CreateOptions,
  };
  const proof = async (): Promise<LiveProvisioningResponse> => {
    const challengeMessage = Buffer.from(JSON.stringify({ protocol: 'dnsid-live-provisioning-pop/v1',
      org_id: fixture.organizationId, agent_id: 'agent-1', fqdn: DOMAIN,
      key_id: await jwkThumbprint(operationalKey), nonce: 'bm9uY2U',
      expires_at: new Date(Date.now() + (fixture.expiredProof ? -1000 : 60_000)).toISOString(),
    })).toString('base64url');
    return { requestId: registrationKey, agentId: 'agent-1', status: 'challenge_pending',
      challenge: 'bm9uY2U', challengeMessage, domain: DOMAIN };
  };
  const registry: FoundryRegistry = {
    getOrganizationOnboarding: vi.fn(async () => ({ organizationId: fixture.organizationId, governanceId: fixture.governanceId, ready: fixture.ready,
      gi: { domain: fixture.governanceId, state: fixture.ready ? 'verified' : 'pending', gateAuthorized: fixture.ready }, entityKeyStatus: 'verified' })),
    registerLiveAgent: vi.fn(async (input, idempotencyKey) => {
      if (await jwkThumbprint(input.publicKeyJwk) !== await jwkThumbprint(operationalKey)) throw new RegistryRequestError(409, 'KEY_MISMATCH', 'name is bound to a different initial key');
      registrationKey = idempotencyKey;
      if (fixture.proofRequired) return proof();
      return { requestId: idempotencyKey, agentId: 'agent-1', status: fixture.registryStatus, challenge: '', challengeMessage: '',
        ...(fixture.replayWithoutDomain ? {} : { domain: DOMAIN }) };
    }),
    getRegistration: vi.fn(async (): Promise<AgentRegistration> => ({ id: 'agent-1', domain: DOMAIN, publicationAuthority: 'registry',
      registryStatus: fixture.registryStatus, publicationConfig: publication, registryUrl: 'https://registry.example', oidcIssuerUrl: 'https://issuer.example/exact' })),
    submitLiveProof: vi.fn(async (_domain, request) => {
      fixture.registryStatus = 'VERIFIED';
      return { requestId: request.requestId, agentId: 'agent-1', status: 'proof_accepted' };
    }),
    reissueLiveProof: vi.fn(async () => { fixture.expiredProof = false; return { ...await proof(), domain: DOMAIN, challengeTranscript: {} as never }; }),
    prepareIssuance: vi.fn(async () => {
      if (accepted) throw new RegistryRequestError(409, 'TLOG_PREPARATION_MISMATCH', 'issuance already exists');
      const event: C2spIssuanceEvent = {
        type: 'ISSUANCE', domain: DOMAIN, governanceId: GI, timestamp: new Date(Math.floor(Date.now() / 1000) * 1000),
        initialEntityKid: entityKey.kid, initialEntityAlg: entityKey.alg!, initialEntityPublicKey: entityKey,
        initialEntityThumbprint: await jwkThumbprint(entityKey), initialOperationalKid: operationalKey.kid,
        initialOperationalAlg: operationalKey.alg!, initialOperationalPublicKey: operationalKey,
        initialOperationalThumbprint: await jwkThumbprint(operationalKey),
      };
      const prepared = await signPreparedC2spTlogEvent(prepareC2spTlogEventForSigning(event, LR), 'Entity', entity,
        { expectedFqdn: DOMAIN, expectedGovernanceId: GI, entityKey, operationalKey });
      preparedBytes = canonicalBytes(prepared.envelope);
      return { entryBytes: preparedBytes };
    }),
    submitPreparedEvent: vi.fn(async (_domain, bytes) => {
      if (fixture.submitMode === 'rejected') throw new PreparedEventSubmissionError({ code: 'TLOG_INVALID_ENTRY', httpStatus: 422,
        state: 'rejected', retryable: false, retryWithSameBytes: false, message: 'invalid entry' });
      let acceptedBytes = bytes.slice();
      if (fixture.submitMode === 'reject-winner') {
        const envelope = JSON.parse(Buffer.from(bytes).toString());
        envelope.sigs.ae.sig = Buffer.from(await entity.sign(signedC2spEntryBytes(bytes))).toString('base64url');
        acceptedBytes = canonicalBytes(envelope);
      }
      accepted = await parseC2spEventEntry(acceptedBytes) as C2spIssuanceEvent;
      fixture.acceptedBytes = acceptedBytes;
      fixture.registryStatus = 'READY';
      if (fixture.submitMode === 'lost') { fixture.submitMode = 'accepted'; throw new Error('response lost'); }
      if (fixture.submitMode === 'reject-winner') throw new PreparedEventSubmissionError({ code: 'IDEMPOTENCY_MISMATCH', httpStatus: 422,
        state: 'rejected', retryable: false, retryWithSameBytes: false, message: 'another signature won' });
      return { state: 'accepted' as const, entryHash: createHash('sha256').update(bytes).digest('hex'), index: 0, logRef: `${LR}@0` };
    }),
  };
  const reader: LogReader = {
    canonical: vi.fn(async () => new Uint8Array()),
    keyTimestamp: vi.fn(async () => new Date()),
    verifyBilateralBinding: vi.fn(async () => {
      if (!accepted) throw new C2spTlogVerificationError('no issuance yet', 'GENESIS_REQUIRED');
      return { initialOperationalThumbprint: await jwkThumbprint(operationalKey), initialEntityThumbprint: await jwkThumbprint(entityKey), timestamp: accepted.timestamp };
    }),
    verifyOperationalContinuity: vi.fn(async () => {}),
    verifyNonRevocation: vi.fn(async () => ({ logReference: LR, loggedState: 'ACTIVE' as const, historyStart: `${LR}@0`, historyEnd: `${LR}@0`,
      completeThrough: '1', completenessMode: 'test', checkpoint: new Uint8Array([1]), freshnessTime: new Date() })),
    rebuildHistory: vi.fn(async () => accepted ? [accepted] : []),
    readEvent: vi.fn(async () => { if (!accepted) throw new Error('absent'); return accepted; }),
  };
  const logRegistry = new LogRegistry();
  logRegistry.register('c2sp-tlog', () => reader);
  const record = async () => {
    const result = new DnsIdTxtRecord();
    result.agentFQDN = DOMAIN; result.v = 'dnsid-draft-01'; result.gi = fixture.publicGovernance;
    result.ek = publication.ekUrl; result.ku = publication.kuUrl; result.lr = fixture.publicLog; result.su = publication.statusUrl;
    result.sg = Buffer.from(await entity.sign(new TextEncoder().encode(result.canonical()))).toString('base64url');
    return result;
  };
  fixture.registry = registry;
  fixture.reader = reader;
  fixture.options = {
    config: { registry: { registryUrl: 'https://registry.example' }, foundry: { organizationId: ORG, governanceId: GI } },
    keyProvider: provider, logRegistry, registryClient: registry, store: new FileFoundryStore(directory),
    providerReference: { provider: 'file', keyRef: '/operator/keys.json' },
    dnsResolver: { fetchTXT: vi.fn(async () => [fixture.dnsMissing ? [] : [{ strings: [(await record()).serialize()], ttl: 300 }], DNSSECState.UNSIGNED] as Awaited<ReturnType<DNSResolver['fetchTXT']>>) },
    fetchJson: vi.fn(async url => ({ data: url === publication.statusUrl
      ? { state: fixture.publicState, lastTransitionAt: new Date().toISOString(), ...(fixture.publicState === 'REVOKED' ? { revocationReason: 'keyCompromise' } : {}) }
      : { keys: [url === publication.ekUrl ? entityKey : fixture.publicKey] }, tlsCert: { san: [GI, DOMAIN], notAfter: new Date('2099-01-01') } })),
    timeoutMs: 1000,
  };
  return fixture;
}
