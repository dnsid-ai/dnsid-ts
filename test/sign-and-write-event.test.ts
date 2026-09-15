import { describe, it, expect, vi } from 'vitest';
import {
  ArgumentError,
  DNSSECState,
  DnsIdTxtRecord,
  DomainLog,
  IdentityManager,
  JWKS,
  LogRegistry,
  NoopLogReader,
  VerifiedDomain,
} from '@identity-digital/dnsid-protocol';
import type {
  IdentityConfig,
  DnsIdJWK,
  IssuanceEvent,
  KeyProvider,
  Log,
  LoggedStateEvidence,
  LogEvent,
  LogReader,
  LogRef,
  LogSignerRole,
} from '@identity-digital/dnsid-protocol';

// ---- fixtures ----

const EC_KEY: DnsIdJWK = {
  kty: 'EC', kid: 'key-1', alg: 'ES256', use: 'sig',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};
const ENTITY_KEY: DnsIdJWK = { ...EC_KEY, kid: 'entity-key-1' };
const EC_THUMBPRINT = 'oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U';

const BASE_CONFIG: IdentityConfig = {
  domain: 'agent.example.com',
  governanceId: 'example.com',
  logRef: 'microledger:abc123',
  statusUrl: 'https://agent.example.com/status',
};

const FAKE_SIG = new Uint8Array(64).fill(0xAB);

function makeKeyProvider(key = EC_KEY): KeyProvider {
  return {
    signingKey:  vi.fn().mockResolvedValue(key),
    jwk:         vi.fn().mockResolvedValue(key),
    listKeyIds:  vi.fn().mockResolvedValue([key.kid]),
    sign:        vi.fn().mockResolvedValue(FAKE_SIG),
    signKey:     vi.fn().mockResolvedValue(FAKE_SIG),
    generateKey: vi.fn(),
    activate:    vi.fn(),
    supersede:   vi.fn(),
    purge:       vi.fn(),
  };
}

function makeIssuance(): IssuanceEvent {
  return {
    type: 'ISSUANCE',
    domain: 'agent.example.com',
    governanceId: 'example.com',
    initialOperationalKid: EC_KEY.kid,
    initialOperationalAlg: EC_KEY.alg!,
    initialOperationalPublicKey: EC_KEY,
    initialOperationalThumbprint: EC_THUMBPRINT,
    initialEntityKid: ENTITY_KEY.kid,
    initialEntityAlg: ENTITY_KEY.alg!,
    initialEntityPublicKey: ENTITY_KEY,
    initialEntityThumbprint: EC_THUMBPRINT,
    timestamp: new Date(),
  };
}

// ---- Test double: a Log+LogReader implementation ----

class FakeLog implements Log, LogReader {
  written: LogEvent[] = [];

  constructor(private readonly additionalRoles: LogSignerRole[] = []) {}

  canonical(_event: LogEvent): Promise<Uint8Array> {
    return Promise.resolve(new TextEncoder().encode('canonical'));
  }
  additionalSignerRoles(): LogSignerRole[] { return this.additionalRoles; }
  writeEvent = vi.fn(async (event: LogEvent): Promise<LogRef> => {
    this.written.push(event);
    return 'microledger:entry-1';
  });
  keyTimestamp(): Promise<Date> { return Promise.resolve(new Date()); }
  verifyBilateralBinding(): Promise<{ initialOperationalThumbprint: string; initialEntityThumbprint: string; timestamp: Date }> {
    return Promise.resolve({ initialOperationalThumbprint: '', initialEntityThumbprint: '', timestamp: new Date() });
  }
  verifyOperationalContinuity(): Promise<void> { return Promise.resolve(); }
  verifyNonRevocation(): Promise<LoggedStateEvidence> {
    return Promise.resolve({
      logReference: 'microledger:abc',
      loggedState: 'ACTIVE',
      historyStart: 'microledger:entry-1',
      historyEnd: 'microledger:entry-1',
      completeThrough: '1',
      completenessMode: 'test',
      checkpoint: new Uint8Array(),
      freshnessTime: new Date(),
    });
  }
  readEvent(): Promise<LogEvent> { return Promise.reject(new Error('not implemented')); }
  rebuildHistory(): Promise<LogEvent[]> { return Promise.resolve(this.written); }
}

function makeManagerWithLog(additionalRoles: LogSignerRole[] = []) {
  const fakeLog = new FakeLog(additionalRoles);
  const registry = new LogRegistry();
  registry.register('microledger', () => fakeLog);

  const kp = makeKeyProvider();
  const entityKp = makeKeyProvider(ENTITY_KEY);
  const manager = new IdentityManager({ identity: BASE_CONFIG }, { keyProvider: kp, logRegistry: registry, entityKeyProvider: entityKp });
  return { manager, fakeLog, kp, entityKp };
}

// ---- signAndWriteEvent ----

describe('IdentityManager.signAndWriteEvent()', () => {
  it('throws ArgumentError when no registry is provided', async () => {
    const manager = new IdentityManager({ identity: BASE_CONFIG }, { keyProvider: makeKeyProvider() });
    const event = makeIssuance();
    await expect(manager.signAndWriteEvent(event)).rejects.toThrow(ArgumentError);
  });

  it('requires an entity key provider for entity-signed events', async () => {
    const fakeLog = new FakeLog();
    const registry = new LogRegistry();
    registry.register('microledger', () => fakeLog);
    const manager = new IdentityManager({ identity: BASE_CONFIG }, { keyProvider: makeKeyProvider(), logRegistry: registry });
    await expect(manager.signAndWriteEvent(makeIssuance())).rejects.toThrow(ArgumentError);
  });

  it('uses the previous operational key for KEY_ROTATION', async () => {
    const { manager, kp, entityKp } = makeManagerWithLog();
    (kp.jwk as ReturnType<typeof vi.fn>).mockImplementation((kid: string) => Promise.resolve({ ...EC_KEY, kid }));
    const event: LogEvent = {
      type: 'KEY_ROTATION',
      domain: BASE_CONFIG.domain,
      previousOperationalKid: EC_KEY.kid,
      previousOperationalThumbprint: EC_THUMBPRINT,
      newOperationalKid: 'key-2',
      newOperationalAlg: 'ES256',
      newOperationalPublicKey: { ...EC_KEY, kid: 'key-2' },
      newOperationalThumbprint: EC_THUMBPRINT,
      timestamp: new Date(),
    };
    await manager.signAndWriteEvent(event);
    expect(kp.signKey).toHaveBeenCalledOnce();
    expect(entityKp.sign).not.toHaveBeenCalled();
    expect(event.signingKid).toBe(EC_KEY.kid);
    expect(event).not.toHaveProperty('newOperationalProof');
  });

  it('automatically adds signatures required by the log method', async () => {
    const { manager, kp } = makeManagerWithLog(['NewOperational']);
    (kp.jwk as ReturnType<typeof vi.fn>).mockImplementation((kid: string) => Promise.resolve({ ...EC_KEY, kid }));
    const event: LogEvent = {
      type: 'KEY_ROTATION',
      domain: BASE_CONFIG.domain,
      previousOperationalKid: EC_KEY.kid,
      previousOperationalThumbprint: EC_THUMBPRINT,
      newOperationalKid: 'key-2',
      newOperationalAlg: 'ES256',
      newOperationalPublicKey: { ...EC_KEY, kid: 'key-2' },
      newOperationalThumbprint: EC_THUMBPRINT,
      timestamp: new Date(),
    };
    await manager.signAndWriteEvent(event);
    expect(kp.signKey).toHaveBeenCalledTimes(2);
    expect(event.newOperationalProof).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('sets signingKid on the event from the entity key', async () => {
    const { manager } = makeManagerWithLog();
    const event = makeIssuance();
    await manager.signAndWriteEvent(event);
    expect(event.signingKid).toBe('entity-key-1');
  });

  it('sets sig on the event as a base64url string', async () => {
    const { manager } = makeManagerWithLog();
    const event = makeIssuance();
    await manager.signAndWriteEvent(event);
    expect(typeof event.sig).toBe('string');
    expect(event.sig).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('calls entityKeyProvider.sign() with the canonical bytes', async () => {
    const { manager, kp, entityKp } = makeManagerWithLog();
    const event = makeIssuance();
    await manager.signAndWriteEvent(event);
    expect(kp.sign).toHaveBeenCalledOnce();
    expect(entityKp.sign).toHaveBeenCalledOnce();
    const arg = (entityKp.sign as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(arg).toBeInstanceOf(Uint8Array);
  });

  it('supports provider-explicit signing without access to another signer role', async () => {
    const { manager, fakeLog } = makeManagerWithLog();
    const provider = makeKeyProvider(ENTITY_KEY);
    const event = makeIssuance();
    await manager.signEventWithProvider(event, 'Entity', provider, fakeLog);
    expect(provider.sign).toHaveBeenCalledOnce();
    expect(event.sig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(event.operationalCountersig).toBeUndefined();
  });

  it('writes the event to the log and returns the LogRef', async () => {
    const { manager, fakeLog } = makeManagerWithLog();
    const event = makeIssuance();
    const ref = await manager.signAndWriteEvent(event);
    expect(ref).toBe('microledger:entry-1');
    expect(fakeLog.written).toHaveLength(1);
    expect(fakeLog.written[0]).toBe(event);
  });

  it('calls entityKeyProvider.signingKey() to get the current active key', async () => {
    const { manager, kp, entityKp } = makeManagerWithLog();
    await manager.signAndWriteEvent(makeIssuance());
    expect(kp.signingKey).toHaveBeenCalledOnce();
    expect(entityKp.signingKey).toHaveBeenCalledOnce();
  });

  it('adds an operational countersignature to ISSUANCE over the same canonical bytes', async () => {
    const { manager, kp, entityKp } = makeManagerWithLog();
    const event = makeIssuance();
    await manager.signAndWriteEvent(event);
    expect(event.operationalCountersig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect((kp.sign as ReturnType<typeof vi.fn>).mock.calls[0][0]).toEqual((entityKp.sign as ReturnType<typeof vi.fn>).mock.calls[0][0]);
  });
});

describe('IdentityManager.rotateOperationalKey()', () => {
  it('publishes the pending key, writes continuity evidence, activates it, then supersedes the old key', async () => {
    const { manager, kp, fakeLog } = makeManagerWithLog(['NewOperational']);
    const nextKey: DnsIdJWK = { ...EC_KEY, kid: 'key-2', y: `${EC_KEY.y!.slice(0, -1)}1` };
    (kp.signingKey as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(EC_KEY)
      .mockResolvedValue(nextKey);
    (kp.generateKey as ReturnType<typeof vi.fn>).mockResolvedValue(nextKey.kid);
    (kp.jwk as ReturnType<typeof vi.fn>).mockImplementation((kid: string) =>
      Promise.resolve(kid === EC_KEY.kid ? EC_KEY : nextKey));
    const publishKeySet = vi.fn().mockResolvedValue(undefined);

    const result = await manager.rotateOperationalKey({
      publishKeySet,
      timestamp: new Date('2026-07-13T12:00:00Z'),
    });

    expect(result.logRef).toBe('microledger:entry-1');
    expect(fakeLog.written).toEqual([result.event]);
    expect(result.event.signingKid).toBe(EC_KEY.kid);
    expect(kp.signKey).toHaveBeenCalledTimes(2);
    expect(result.event.newOperationalProof).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(kp.activate).toHaveBeenCalledWith(nextKey.kid);
    expect(publishKeySet).toHaveBeenCalledWith(result.keySet);
    expect(result.keySet.keys).toEqual([nextKey]);
    expect(kp.supersede).toHaveBeenCalledWith(EC_KEY.kid);
    expect(publishKeySet.mock.invocationCallOrder[0])
      .toBeLessThan(fakeLog.writeEvent.mock.invocationCallOrder[0]!);
    expect(fakeLog.writeEvent.mock.invocationCallOrder[0])
      .toBeLessThan((kp.activate as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0]!);
    expect((kp.activate as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0])
      .toBeLessThan((kp.supersede as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0]!);
  });

  it('does not append or activate the new key when publication fails', async () => {
    const { manager, kp, fakeLog } = makeManagerWithLog();
    const nextKey: DnsIdJWK = { ...EC_KEY, kid: 'key-2', y: `${EC_KEY.y!.slice(0, -1)}1` };
    (kp.signingKey as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(EC_KEY)
      .mockResolvedValue(nextKey);
    (kp.generateKey as ReturnType<typeof vi.fn>).mockResolvedValue(nextKey.kid);
    (kp.jwk as ReturnType<typeof vi.fn>).mockImplementation((kid: string) =>
      Promise.resolve(kid === EC_KEY.kid ? EC_KEY : nextKey));

    await expect(manager.rotateOperationalKey({
      publishKeySet: vi.fn().mockRejectedValue(new Error('publish failed')),
    })).rejects.toThrow('publish failed');
    expect(fakeLog.writeEvent).not.toHaveBeenCalled();
    expect(kp.activate).not.toHaveBeenCalled();
    expect(kp.supersede).not.toHaveBeenCalled();
  });
});

// ---- loadDomainLog ----

describe('IdentityManager.loadDomainLog()', () => {
  it('throws VerificationError when the logReader is NoopLogReader', async () => {
    // Without a registry, logReader = NoopLogReader; rebuildHistory raises
    const manager = new IdentityManager({ identity: BASE_CONFIG }, { keyProvider: makeKeyProvider() });

    const record = new DnsIdTxtRecord();
    record.v = 'DNSid1'; record.gi = 'example.com';
    record.ek = 'https://example.com/entity-jwks.json';
    record.ku = 'https://agent.example.com/.well-known/jwks.json';
    record.lr = 'microledger:abc'; record.su = 'https://agent.example.com/status'; record.sg = 'sig';
    record.agentFQDN = 'agent.example.com';

    const vd = new VerifiedDomain({
      domain: 'agent.example.com', record,
      jwks: new JWKS([EC_KEY]), signingKey: EC_KEY, signingKeyThumbprint: 'test-thumbprint',
      tlsCert: { notAfter: new Date('2099-01-01'), san: [] },
      registryStatus: { state: 'ACTIVE', lastTransitionAt: new Date() },
      verifiedAt: new Date(), dnsTTL: 3600, keyBoundAt: new Date(0),
      lastStatusCheckAt: new Date(), dnssecState: DNSSECState.UNSIGNED,
      logReader: new NoopLogReader('microledger'),
    });

    await expect(manager.loadDomainLog(vd)).rejects.toThrow();
  });

  it('returns a DomainLog with events from the log', async () => {
    const { manager, fakeLog } = makeManagerWithLog();
    const issuance = makeIssuance();
    fakeLog.written = [issuance];

    const record = new DnsIdTxtRecord();
    record.v = 'DNSid1'; record.gi = 'example.com';
    record.ek = 'https://example.com/entity-jwks.json';
    record.ku = 'https://agent.example.com/.well-known/jwks.json';
    record.lr = 'microledger:abc'; record.su = 'https://agent.example.com/status'; record.sg = 'sig';
    record.agentFQDN = 'agent.example.com';

    const vd = new VerifiedDomain({
      domain: 'agent.example.com', record,
      jwks: new JWKS([EC_KEY]), signingKey: EC_KEY, signingKeyThumbprint: 'test-thumbprint',
      tlsCert: { notAfter: new Date('2099-01-01'), san: [] },
      registryStatus: { state: 'ACTIVE', lastTransitionAt: new Date() },
      verifiedAt: new Date(), dnsTTL: 3600, keyBoundAt: new Date(0),
      lastStatusCheckAt: new Date(), dnssecState: DNSSECState.UNSIGNED,
      logReader: fakeLog,
    });

    const log = await manager.loadDomainLog(vd);
    expect(log).toBeInstanceOf(DomainLog);
    expect(log.domain).toBe('agent.example.com');
    expect(log.events).toEqual([issuance]);
  });
});
