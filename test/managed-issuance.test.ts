import { describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import {
  jwkThumbprint,
  toArrayBuffer,
  type C2spIssuanceEvent,
  type DnsIdJWK,
  type KeyProvider,
} from '@identity-digital/dnsid-protocol';
import {
  canonicalBytes,
  prepareC2spTlogEventForSigning,
  signPreparedC2spTlogEvent,
} from '@identity-digital/dnsid-log-c2sp-tlog';
import {
  ManagedIssuanceActivationError,
  ManagedIssuanceSubmissionError,
  issueManagedIdentity,
  resumeManagedIssuance,
  type ManagedIssuanceRegistry,
  type ManagedIssuanceState,
} from '@identity-digital/dnsid';
import { PreparedEventSubmissionError, type SubmissionResult } from '@identity-digital/dnsid-registry';

const DOMAIN = 'agent.example.com';
const GOVERNANCE = 'example.com';
const LR = 'c2sp-tlog:public:https://log.example/dnsid#ERERERERERERERERERERER';

async function key(kid: string): Promise<{ publicJwk: DnsIdJWK; privateKey: CryptoKey }> {
  const pair = await generateKeyPair('ES256', { extractable: true });
  return {
    publicJwk: { ...await exportJWK(pair.publicKey), kid, alg: 'ES256', use: 'sig' } as DnsIdJWK,
    privateKey: pair.privateKey as CryptoKey,
  };
}

function provider(value: Awaited<ReturnType<typeof key>>): KeyProvider {
  return {
    signingKey: async () => value.publicJwk,
    jwk: async kid => {
      if (kid !== value.publicJwk.kid) throw new Error('key not found');
      return value.publicJwk;
    },
    listKeyIds: async () => [value.publicJwk.kid],
    sign: async bytes => sign(value.privateKey, bytes),
    signKey: async (kid, bytes) => {
      if (kid !== value.publicJwk.kid) throw new Error('key not found');
      return sign(value.privateKey, bytes);
    },
    generateKey: async () => { throw new Error('not implemented'); },
    activate: async () => { throw new Error('not implemented'); },
    supersede: async () => { throw new Error('not implemented'); },
  };
}

class IssuanceRegistry implements ManagedIssuanceRegistry {
  state: SubmissionResult['state'] = 'accepted';
  preparationError?: unknown;
  submissionError?: unknown;
  entryHashOverride?: string;
  logRefOverride?: string;
  prepareCalls = 0;
  readonly submissions: Array<{ bytes: Uint8Array; key: string }> = [];

  constructor(
    private readonly entity: Awaited<ReturnType<typeof key>>,
    private readonly operational: DnsIdJWK,
  ) {}

  async prepareIssuance(domain: string): Promise<{ entryBytes: Uint8Array; logReference: string }> {
    this.prepareCalls++;
    if (this.preparationError) throw this.preparationError;
    const event: C2spIssuanceEvent = {
      type: 'ISSUANCE',
      domain,
      governanceId: GOVERNANCE,
      timestamp: new Date('2026-07-31T12:00:00Z'),
      initialEntityKid: this.entity.publicJwk.kid,
      initialEntityAlg: this.entity.publicJwk.alg!,
      initialEntityPublicKey: this.entity.publicJwk,
      initialEntityThumbprint: await jwkThumbprint(this.entity.publicJwk),
      initialOperationalKid: this.operational.kid,
      initialOperationalAlg: this.operational.alg!,
      initialOperationalPublicKey: this.operational,
      initialOperationalThumbprint: await jwkThumbprint(this.operational),
    };
    const prepared = await signPreparedC2spTlogEvent(
      prepareC2spTlogEventForSigning(event, LR),
      'Entity',
      provider(this.entity),
      {
        expectedFqdn: domain,
        expectedGovernanceId: GOVERNANCE,
        entityKey: this.entity.publicJwk,
        operationalKey: this.operational,
      },
    );
    return { entryBytes: canonicalBytes(prepared.envelope), logReference: LR };
  }

  async submitPreparedEvent(_domain: string, bytes: Uint8Array, key: string): Promise<SubmissionResult> {
    this.submissions.push({ bytes: bytes.slice(), key });
    if (this.submissionError) throw this.submissionError;
    const entryHash = await sha256Hex(bytes);
    return {
      state: this.state,
      entryHash: this.entryHashOverride ?? entryHash,
      index: this.state === 'accepted' ? 0 : undefined,
      logRef: this.state === 'accepted' ? (this.logRefOverride ?? `${LR}@0`) : undefined,
    };
  }
}

describe('managed ISSUANCE coordination', () => {
  it('rejects idempotency keys longer than the shared 200-character limit', async () => {
    const entity = await key('entity');
    const operational = await key('op');
    const registry = new IssuanceRegistry(entity, operational.publicJwk);
    const createIssuance = vi.fn(async () => undefined);
    await expect(issueManagedIdentity({
      domain: DOMAIN,
      governanceId: GOVERNANCE,
      entityKey: entity.publicJwk,
      operationalKeyProvider: provider(operational),
      registryClient: registry,
      idempotencyKey: 'x'.repeat(201),
      loadIssuance: async () => undefined,
      createIssuance,
      persistIssuance: async () => undefined,
      activateAcceptedIssuance: async () => undefined,
    })).rejects.toMatchObject({ code: 'LogError', transient: false, message: expect.stringContaining('1 to 200') });
    expect(createIssuance).not.toHaveBeenCalled();
    expect(registry.prepareCalls).toBe(0);
  });

  it('persists an intent before preparation, exact bytes before submit, then activates after acceptance', async () => {
    const entity = await key('entity');
    const operational = await key('op');
    const registry = new IssuanceRegistry(entity, operational.publicJwk);
    let durable: ManagedIssuanceState | undefined;
    const order: string[] = [];
    const prepare = vi.spyOn(registry, 'prepareIssuance').mockImplementation(async (...args) => {
      order.push('prepare');
      return IssuanceRegistry.prototype.prepareIssuance.apply(registry, args);
    });
    const submit = vi.spyOn(registry, 'submitPreparedEvent').mockImplementation(async (...args) => {
      order.push('submit');
      return IssuanceRegistry.prototype.submitPreparedEvent.apply(registry, args);
    });
    const activate = vi.fn(async () => { order.push('activate'); });

    const result = await issueManagedIdentity({
      domain: DOMAIN,
      governanceId: GOVERNANCE,
      entityKey: entity.publicJwk,
      operationalKeyProvider: provider(operational),
      registryClient: registry,
      idempotencyKey: 'issuance-1',
      loadIssuance: async () => durable,
      createIssuance: async intent => {
        durable = structuredClone(intent);
        order.push('create-intent');
        return undefined;
      },
      persistIssuance: async state => {
        durable = structuredClone(state);
        order.push(state.activated ? 'persist-complete' : state.entryBytes ? (state.submission ? 'persist-accepted' : 'persist-bytes') : 'persist-intent');
      },
      activateAcceptedIssuance: activate,
    });

    expect(order).toEqual(['create-intent', 'prepare', 'persist-bytes', 'submit', 'persist-accepted', 'activate', 'persist-complete']);
    expect(result).toMatchObject({ activated: true, submission: { state: 'accepted', logRef: `${LR}@0` } });
    expect(prepare).toHaveBeenCalledOnce();
    expect(submit).toHaveBeenCalledOnce();
  });

  it('resumes an intent with the same preparation idempotency key and never activates while pending', async () => {
    const entity = await key('entity');
    const operational = await key('op');
    const registry = new IssuanceRegistry(entity, operational.publicJwk);
    const persisted: ManagedIssuanceState[] = [];
    const coordination = {
      loadIssuance: async () => persisted.at(-1),
      createIssuance: async (intent: ManagedIssuanceState) => { persisted.push(structuredClone(intent)); return undefined; },
      persistIssuance: async (state: ManagedIssuanceState) => { persisted.push(structuredClone(state)); },
      activateAcceptedIssuance: vi.fn(async () => undefined),
    };
    registry.preparationError = new Error('offline');
    let failure: ManagedIssuanceSubmissionError | undefined;
    try {
      await issueManagedIdentity({
        domain: DOMAIN, governanceId: GOVERNANCE, entityKey: entity.publicJwk,
        operationalKeyProvider: provider(operational), registryClient: registry,
        idempotencyKey: 'issuance-1', ...coordination,
      });
    } catch (error) {
      failure = error as ManagedIssuanceSubmissionError;
    }
    expect(failure).toBeInstanceOf(ManagedIssuanceSubmissionError);
    expect(failure!.transient).toBe(true);
    expect(persisted).toHaveLength(1);
    expect(persisted[0]!.entryBytes).toBeUndefined();

    registry.preparationError = undefined;
    registry.state = 'pending';
    const pending = await resumeManagedIssuance({
      entityKey: entity.publicJwk, operationalKeyProvider: provider(operational),
      registryClient: registry, ...coordination,
    });
    expect(pending.submission?.state).toBe('pending');
    expect(coordination.activateAcceptedIssuance).not.toHaveBeenCalled();
    expect(registry.prepareCalls).toBe(2);
  });

  it('retries only persisted completed bytes after an indeterminate submit', async () => {
    const entity = await key('entity');
    const operational = await key('op');
    const registry = new IssuanceRegistry(entity, operational.publicJwk);
    let durable: ManagedIssuanceState | undefined;
    const coordination = {
      loadIssuance: async () => durable,
      createIssuance: async (intent: ManagedIssuanceState) => { durable = structuredClone(intent); return undefined; },
      persistIssuance: async (state: ManagedIssuanceState) => { durable = structuredClone(state); },
      activateAcceptedIssuance: vi.fn(async () => undefined),
    };
    registry.submissionError = new PreparedEventSubmissionError({
      code: 'TLOG_SUBMISSION_INDETERMINATE', httpStatus: 503, message: 'unknown',
      state: 'indeterminate', retryable: true, retryWithSameBytes: true,
    });
    await expect(issueManagedIdentity({
      domain: DOMAIN, governanceId: GOVERNANCE, entityKey: entity.publicJwk,
      operationalKeyProvider: provider(operational), registryClient: registry,
      idempotencyKey: 'issuance-1', ...coordination,
    })).rejects.toMatchObject({ transient: true, retryWithSameBytes: true });
    expect(durable?.entryBytes).toBeDefined();
    expect(durable?.submission).toMatchObject({
      state: 'indeterminate',
      entryHash: durable?.entryHash,
      errorCode: 'TLOG_SUBMISSION_INDETERMINATE',
    });

    registry.submissionError = undefined;
    const accepted = await resumeManagedIssuance({
      entityKey: entity.publicJwk, operationalKeyProvider: provider(operational),
      registryClient: registry, ...coordination,
    });
    expect(accepted.activated).toBe(true);
    expect(registry.prepareCalls).toBe(1);
    expect(registry.submissions[1]!.bytes).toEqual(registry.submissions[0]!.bytes);
    expect(registry.submissions.map(item => item.key)).toEqual(['issuance-1', 'issuance-1']);
  });

  it('resumes activation without resubmission after accepted binding was persisted', async () => {
    const entity = await key('entity');
    const operational = await key('op');
    const registry = new IssuanceRegistry(entity, operational.publicJwk);
    let durable: ManagedIssuanceState | undefined;
    const activation = vi.fn()
      .mockRejectedValueOnce(new Error('publication unavailable'))
      .mockResolvedValueOnce(undefined);
    const coordination = {
      loadIssuance: async () => durable,
      createIssuance: async (intent: ManagedIssuanceState) => { durable = structuredClone(intent); return undefined; },
      persistIssuance: async (state: ManagedIssuanceState) => { durable = structuredClone(state); },
      activateAcceptedIssuance: activation,
    };
    await expect(issueManagedIdentity({
      domain: DOMAIN, governanceId: GOVERNANCE, entityKey: entity.publicJwk,
      operationalKeyProvider: provider(operational), registryClient: registry,
      idempotencyKey: 'issuance-1', ...coordination,
    })).rejects.toBeInstanceOf(ManagedIssuanceActivationError);
    expect(durable?.submission?.state).toBe('accepted');

    const complete = await resumeManagedIssuance({
      entityKey: entity.publicJwk, operationalKeyProvider: provider(operational),
      registryClient: registry, ...coordination,
    });
    expect(complete.activated).toBe(true);
    expect(registry.submissions).toHaveLength(1);
    expect(activation).toHaveBeenCalledTimes(2);
  });

  it('rejects tampered durable bytes or hash before resubmission', async () => {
    const entity = await key('entity');
    const operational = await key('op');
    const registry = new IssuanceRegistry(entity, operational.publicJwk);
    let durable: ManagedIssuanceState | undefined;
    const coordination = {
      loadIssuance: async () => durable,
      createIssuance: async (intent: ManagedIssuanceState) => { durable = structuredClone(intent); return undefined; },
      persistIssuance: async (state: ManagedIssuanceState) => { durable = structuredClone(state); },
      activateAcceptedIssuance: vi.fn(async () => undefined),
    };
    registry.state = 'pending';
    await issueManagedIdentity({
      domain: DOMAIN, governanceId: GOVERNANCE, entityKey: entity.publicJwk,
      operationalKeyProvider: provider(operational), registryClient: registry,
      idempotencyKey: 'issuance-1', ...coordination,
    });
    expect(registry.submissions).toHaveLength(1);

    durable = { ...durable!, entryHash: '0'.repeat(64) };
    await expect(resumeManagedIssuance({
      entityKey: entity.publicJwk, operationalKeyProvider: provider(operational),
      registryClient: registry, ...coordination,
    })).rejects.toMatchObject({ code: 'LogError', transient: false, message: expect.stringContaining('persisted hash') });
    expect(registry.submissions).toHaveLength(1);

    const bytes = durable.entryBytes!.slice();
    bytes[0] = bytes[0]! ^ 1;
    durable = { ...durable, entryBytes: bytes, entryHash: await sha256Hex(bytes) };
    await expect(resumeManagedIssuance({
      entityKey: entity.publicJwk, operationalKeyProvider: provider(operational),
      registryClient: registry, ...coordination,
    })).rejects.toMatchObject({ code: 'LogError', transient: false });
    expect(registry.submissions).toHaveLength(1);
  });

  it('rejects accepted hash and final-reference mismatches before activation', async () => {
    const entity = await key('entity');
    const operational = await key('op');
    const activation = vi.fn(async () => undefined);
    for (const mismatch of ['hash', 'reference'] as const) {
      const registry = new IssuanceRegistry(entity, operational.publicJwk);
      if (mismatch === 'hash') registry.entryHashOverride = '0'.repeat(64);
      else registry.logRefOverride = `${LR}@7`;
      let durable: ManagedIssuanceState | undefined;
      await expect(issueManagedIdentity({
        domain: DOMAIN, governanceId: GOVERNANCE, entityKey: entity.publicJwk,
        operationalKeyProvider: provider(operational), registryClient: registry,
        idempotencyKey: `issuance-${mismatch}`,
        loadIssuance: async () => durable,
        createIssuance: async intent => { durable = structuredClone(intent); return undefined; },
        persistIssuance: async state => { durable = structuredClone(state); },
        activateAcceptedIssuance: activation,
      })).rejects.toMatchObject({ code: 'LogError', transient: false });
    }
    expect(activation).not.toHaveBeenCalled();
  });

  it('persists a terminal preparation failure and will not prepare again on restart', async () => {
    const entity = await key('entity');
    const operational = await key('op');
    const registry = new IssuanceRegistry(entity, operational.publicJwk);
    let durable: ManagedIssuanceState | undefined;
    registry.preparationError = new PreparedEventSubmissionError({
      code: 'TLOG_PREPARATION_CONFLICT', httpStatus: 409, message: 'terminal conflict',
      state: 'rejected', retryable: false, retryWithSameBytes: false,
    });
    const coordination = {
      loadIssuance: async () => durable,
      createIssuance: async (intent: ManagedIssuanceState) => { durable = structuredClone(intent); return undefined; },
      persistIssuance: async (state: ManagedIssuanceState) => { durable = structuredClone(state); },
      activateAcceptedIssuance: vi.fn(async () => undefined),
    };
    await expect(issueManagedIdentity({
      domain: DOMAIN, governanceId: GOVERNANCE, entityKey: entity.publicJwk,
      operationalKeyProvider: provider(operational), registryClient: registry,
      idempotencyKey: 'issuance-terminal', ...coordination,
    })).rejects.toMatchObject({ transient: false, retryWithSameBytes: false });
    expect(durable?.terminalFailure).toEqual({ stage: 'preparation', errorCode: 'TLOG_PREPARATION_CONFLICT' });

    await expect(resumeManagedIssuance({
      entityKey: entity.publicJwk, operationalKeyProvider: provider(operational),
      registryClient: registry, ...coordination,
    })).rejects.toThrow('terminally failed');
    expect(registry.prepareCalls).toBe(1);
  });

  it('persists a terminal submit outcome and will not resubmit on restart', async () => {
    const entity = await key('entity');
    const operational = await key('op');
    const registry = new IssuanceRegistry(entity, operational.publicJwk);
    let durable: ManagedIssuanceState | undefined;
    registry.submissionError = new PreparedEventSubmissionError({
      code: 'TLOG_SUBMISSION_REJECTED', httpStatus: 409, message: 'rejected',
      state: 'rejected', retryable: false, retryWithSameBytes: false,
    });
    const coordination = {
      loadIssuance: async () => durable,
      createIssuance: async (intent: ManagedIssuanceState) => { durable = structuredClone(intent); return undefined; },
      persistIssuance: async (state: ManagedIssuanceState) => { durable = structuredClone(state); },
      activateAcceptedIssuance: vi.fn(async () => undefined),
    };
    await expect(issueManagedIdentity({
      domain: DOMAIN, governanceId: GOVERNANCE, entityKey: entity.publicJwk,
      operationalKeyProvider: provider(operational), registryClient: registry,
      idempotencyKey: 'issuance-terminal-submit', ...coordination,
    })).rejects.toMatchObject({ transient: false, retryWithSameBytes: false });
    expect(durable).toMatchObject({
      submission: { state: 'rejected', errorCode: 'TLOG_SUBMISSION_REJECTED' },
      terminalFailure: { stage: 'submission', errorCode: 'TLOG_SUBMISSION_REJECTED' },
    });

    await expect(resumeManagedIssuance({
      entityKey: entity.publicJwk, operationalKeyProvider: provider(operational),
      registryClient: registry, ...coordination,
    })).rejects.toThrow('terminally failed');
    expect(registry.submissions).toHaveLength(1);
  });

  it('uses atomic intent creation to converge a concurrent setup start', async () => {
    const entity = await key('entity');
    const operational = await key('op');
    const registry = new IssuanceRegistry(entity, operational.publicJwk);
    registry.state = 'pending';
    const existing: ManagedIssuanceState = {
      domain: DOMAIN,
      governanceId: GOVERNANCE,
      idempotencyKey: 'issuance-race',
      entityKid: entity.publicJwk.kid,
      entityThumbprint: await jwkThumbprint(entity.publicJwk),
      operationalKid: operational.publicJwk.kid,
      operationalThumbprint: await jwkThumbprint(operational.publicJwk),
      activated: false,
    };
    let durable = existing;
    const load = vi.fn(async () => undefined);
    const create = vi.fn(async () => existing);
    const result = await issueManagedIdentity({
      domain: DOMAIN, governanceId: GOVERNANCE, entityKey: entity.publicJwk,
      operationalKeyProvider: provider(operational), registryClient: registry,
      idempotencyKey: 'issuance-race',
      loadIssuance: load,
      createIssuance: create,
      persistIssuance: async state => { durable = structuredClone(state); },
      activateAcceptedIssuance: vi.fn(async () => undefined),
    });
    expect(load).toHaveBeenCalledOnce();
    expect(create).toHaveBeenCalledOnce();
    expect(registry.prepareCalls).toBe(1);
    expect(result.submission?.state).toBe('pending');
  });
});

async function sign(privateKey: CryptoKey, bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    toArrayBuffer(bytes),
  ));
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', toArrayBuffer(bytes));
  return Buffer.from(digest).toString('hex');
}
