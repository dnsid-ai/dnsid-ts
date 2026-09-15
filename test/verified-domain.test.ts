import { afterEach, describe, it, expect, vi } from 'vitest';
import {
  DNSSECState,
  DnsIdTxtRecord,
  DomainLog,
  InMemoryIdentityCache,
  JWKS,
  NoopLogReader,
  VerificationCode,
  VerificationError,
  VerifiedDomain,
} from '@identity-digital/dnsid-protocol';
import type {
  AgentStatus,
  DnsIdJWK,
  IssuanceEvent,
  KeyRotationEvent,
  LoggedStateEvidence,
  LogReader,
  MigrationEvent,
  RetirementEvent,
  RevocationEvent,
  TLSCertificate,
} from '@identity-digital/dnsid-protocol';

// ---- fixtures ----

const EC_KEY: DnsIdJWK = {
  kty: 'EC', kid: 'key-1', alg: 'ES256', use: 'sig',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};
const ENTITY_KEY: DnsIdJWK = { ...EC_KEY, kid: 'entity-key-1', x: `${EC_KEY.x!.slice(0, -1)}A` };
const ROTATED_KEY: DnsIdJWK = { ...EC_KEY, kid: 'key-2', y: `${EC_KEY.y!.slice(0, -1)}B` };

const ACTIVE_STATUS: AgentStatus = {
  state: 'ACTIVE',
  lastTransitionAt: new Date('2024-01-01T00:00:00Z'),
};

const LOG_EVIDENCE: LoggedStateEvidence = {
  logReference: 'microledger:abc',
  loggedState: 'ACTIVE',
  historyStart: 'microledger:event-1',
  historyEnd: 'microledger:event-2',
  completeThrough: '2',
  completenessMode: 'full-scan',
  checkpoint: new Uint8Array([1]),
  freshnessTime: new Date('2025-01-01T12:00:00Z'),
};

const CERT_FAR_FUTURE: TLSCertificate = {
  notAfter: new Date('2099-01-01T00:00:00Z'),
  san: ['agent.example.com'],
};

function makeRecord(ku = 'https://agent.example.com/.well-known/jwks.json', ka?: string): DnsIdTxtRecord {
  const r = new DnsIdTxtRecord();
  r.v = 'DNSid1'; r.gi = 'example.com'; r.ek = 'https://example.com/entity-jwks.json'; r.ku = ku;
  r.lr = 'microledger:abc'; r.su = 'https://agent.example.com/status'; r.sg = 'sig';
  r.agentFQDN = 'agent.example.com';
  if (ka) r.ka = ka;
  return r;
}

function makeVD(overrides: {
  verifiedAt?: Date;
  dnsTTL?: number;
  tlsCert?: TLSCertificate;
  signingKey?: DnsIdJWK;
  ka?: string;
  keyBoundAt?: Date;
  policyFlags?: string;
  logReader?: LogReader;
}): VerifiedDomain {
  const { verifiedAt = new Date('2025-01-01T00:00:00Z'), dnsTTL = 3600, tlsCert = CERT_FAR_FUTURE,
    signingKey = EC_KEY, ka, keyBoundAt = new Date(0), policyFlags,
    logReader = new NoopLogReader('microledger') } = overrides;
  const record = makeRecord(undefined, ka);
  record.fl = policyFlags;
  return new VerifiedDomain({
    domain: 'agent.example.com',
    record,
    jwks: new JWKS([EC_KEY]),
    signingKey,
    signingKeyThumbprint: 'test-thumbprint',
    tlsCert,
    registryStatus: ACTIVE_STATUS,
    verifiedAt,
    dnsTTL,
    keyBoundAt,
    lastStatusCheckAt: verifiedAt,
    dnssecState: DNSSECState.UNSIGNED,
    logReader,
  });
}

afterEach(() => {
  vi.useRealTimers();
});

// ---- VerifiedDomain.expiry() ----

describe('VerifiedDomain.expiry()', () => {
  it('returns verifiedAt + dnsTTL when that is the minimum', () => {
    const verifiedAt = new Date('2025-01-01T00:00:00Z');
    const vd = makeVD({ verifiedAt, dnsTTL: 300 }); // TTL = 5 min
    const expected = new Date(verifiedAt.getTime() + 300 * 1000);
    expect(vd.expiry()).toEqual(expected);
  });

  it('returns TLS cert notAfter when it is before the DNS TTL expiry', () => {
    const verifiedAt = new Date('2025-01-01T00:00:00Z');
    const earlyExpiry = new Date('2025-01-01T00:01:00Z'); // 1 min from now
    const vd = makeVD({
      verifiedAt,
      dnsTTL: 3600,
      tlsCert: { notAfter: earlyExpiry, san: [] },
    });
    expect(vd.expiry()).toEqual(earlyExpiry);
  });

  it('factors in ka bound when ka is set and keyBoundAt is non-zero', () => {
    const verifiedAt = new Date('2025-01-01T00:00:00Z');
    const keyBoundAt = new Date('2025-01-01T00:00:00Z');
    // ka=24h means key expires 24h after keyBoundAt
    const expectedKaExpiry = new Date(keyBoundAt.getTime() + 24 * 60 * 60 * 1000);
    const vd = makeVD({ verifiedAt, dnsTTL: 7 * 24 * 3600, ka: '24h', keyBoundAt });
    // DNS TTL expires in 7 days; ka expires in 24h — ka should win
    expect(vd.expiry()).toEqual(expectedKaExpiry);
  });

  it('does not ignore an epoch key-age bound', () => {
    const verifiedAt = new Date('2025-01-01T00:00:00Z');
    const vd = makeVD({ verifiedAt, dnsTTL: 60, ka: '24h', keyBoundAt: new Date(0) });
    const expected = new Date(24 * 60 * 60 * 1000);
    expect(vd.expiry()).toEqual(expected);
  });

  it('ignores signing key exp when it is undefined', () => {
    const verifiedAt = new Date('2025-01-01T00:00:00Z');
    const vd = makeVD({ verifiedAt, dnsTTL: 60 });
    const expected = new Date(verifiedAt.getTime() + 60 * 1000);
    expect(vd.expiry()).toEqual(expected);
  });
});

// ---- operation-level log checks ----

describe('VerifiedDomain operation-level log checks', () => {
  it('reports whether fl=logchk requests a check for high-value operations', () => {
    expect(makeVD({ policyFlags: 'mtls,logchk' }).requiresLogCheck()).toBe(true);
    expect(makeVD({ policyFlags: 'mtls' }).requiresLogCheck()).toBe(false);
  });

  it('delegates an explicit non-revocation check to the verified log reader', async () => {
    const logReader = new NoopLogReader('microledger');
    const verifyNonRevocation = vi.spyOn(logReader, 'verifyNonRevocation').mockResolvedValue(LOG_EVIDENCE);
    const vd = makeVD({ policyFlags: 'logchk', logReader });
    const at = new Date('2025-01-01T12:00:00Z');

    await expect(vd.verifyNonRevocation(at)).resolves.toBe(LOG_EVIDENCE);
    expect(verifyNonRevocation).toHaveBeenCalledWith(vd.domain, at);
  });

  it('fails closed when the log check cannot be performed', async () => {
    const vd = makeVD({ policyFlags: 'logchk' });
    await expect(vd.verifyNonRevocation()).rejects.toMatchObject({ code: VerificationCode.LogError });
  });
});

// ---- InMemoryIdentityCache ----

describe('InMemoryIdentityCache', () => {
  it('treats entries as stale exactly at VerifiedDomain.expiry()', () => {
    const verifiedAt = new Date('2025-01-01T00:00:00Z');
    vi.useFakeTimers();
    vi.setSystemTime(verifiedAt);

    const cache = new InMemoryIdentityCache();
    const vd = makeVD({ verifiedAt, dnsTTL: 60 });
    cache.put(vd.domain, vd);

    vi.setSystemTime(new Date(verifiedAt.getTime() + 60 * 1000));
    expect(cache.get(vd.domain)).toBeNull();
  });
});

// ---- DomainLog.snapshotAt() ----

const T0 = new Date('2024-01-01T00:00:00Z');
const T1 = new Date('2024-06-01T00:00:00Z');
const T2 = new Date('2024-09-01T00:00:00Z');
const T3 = new Date('2024-12-01T00:00:00Z');

const ISSUANCE: IssuanceEvent = {
  type: 'ISSUANCE',
  domain: 'agent.example.com',
  governanceId: 'example.com',
  initialOperationalKid: 'key-1',
  initialOperationalAlg: 'ES256',
  initialOperationalPublicKey: EC_KEY,
  initialOperationalThumbprint: 'oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U',
  initialEntityKid: 'entity-key-1',
  initialEntityAlg: 'ES256',
  initialEntityPublicKey: ENTITY_KEY,
  initialEntityThumbprint: 'AeJdkz9nIVt2n0QtUlD8jD_gt9puXAeosRjy11jRvmU',
  timestamp: T1,
};

const ROTATION: KeyRotationEvent = {
  type: 'KEY_ROTATION',
  domain: 'agent.example.com',
  previousOperationalKid: 'key-1',
  previousOperationalThumbprint: 'oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U',
  newOperationalKid: 'key-2',
  newOperationalAlg: 'ES256',
  newOperationalThumbprint: '_LPvmoYqF4lXsUS7qOBTY23bCOCcGTcOpgLhB9ak19g',
  newOperationalPublicKey: ROTATED_KEY,
  timestamp: T2,
};

const REVOCATION: RevocationEvent = {
  type: 'REVOCATION',
  domain: 'agent.example.com',
  timestamp: T3,
  reason: 'keyCompromise',
};

describe('DomainLog.snapshotAt()', () => {
  it('exposes stable lifecycle conformance error categories', () => {
    const migration: MigrationEvent = {
      type: 'MIGRATION', domain: 'agent.example.com', previousLog: 'same:ref', newLog: 'same:ref',
      finalEntryRef: 'same:entry-1', timestamp: T2,
    };
    const future = { type: 'FUTURE_EVENT', domain: 'agent.example.com', timestamp: T2 } as unknown as IssuanceEvent;
    const nonPrefixFuture: RetirementEvent = { type: 'RETIREMENT', domain: 'agent.example.com', timestamp: T3 };
    const cases: Array<[string, () => unknown]> = [
      ['SNAPSHOT_EMPTY', () => new DomainLog('agent.example.com', []).snapshotAt(T3)],
      ['GENESIS_REQUIRED', () => new DomainLog('agent.example.com', [ROTATION]).snapshotAt(T3)],
      ['INVALID_ISSUANCE', () => new DomainLog('agent.example.com', [{
        ...ISSUANCE,
        initialEntityPublicKey: ISSUANCE.initialOperationalPublicKey,
        initialEntityThumbprint: ISSUANCE.initialOperationalThumbprint,
      }]).snapshotAt(T3)],
      ['DUPLICATE_ISSUANCE', () => new DomainLog('agent.example.com', [ISSUANCE, { ...ISSUANCE, timestamp: T2 }]).snapshotAt(T3)],
      ['TERMINAL_STATE', () => new DomainLog('agent.example.com', [ISSUANCE, REVOCATION, ROTATION]).snapshotAt(new Date('2025-01-01T00:00:00Z'))],
      ['DOMAIN_MISMATCH', () => new DomainLog('agent.example.com', [{ ...ISSUANCE, domain: 'other.example.com' }]).snapshotAt(T3)],
      ['KEY_CONTINUITY', () => new DomainLog('agent.example.com', [ISSUANCE, { ...ROTATION, previousOperationalThumbprint: 'stale' }]).snapshotAt(T3)],
      ['INVALID_REVOCATION_REASON', () => new DomainLog('agent.example.com', [ISSUANCE, { ...REVOCATION, reason: 'ownerRequest' } as unknown as RevocationEvent]).snapshotAt(T3)],
      ['INVALID_MIGRATION', () => new DomainLog('agent.example.com', [ISSUANCE, migration]).snapshotAt(T3)],
      ['SNAPSHOT_NON_PREFIX', () => new DomainLog('agent.example.com', [ISSUANCE, nonPrefixFuture, ROTATION]).snapshotAt(T2)],
      ['UNSUPPORTED_EVENT', () => new DomainLog('agent.example.com', [ISSUANCE, future]).snapshotAt(T3)],
    ];

    for (const [errorCategory, operation] of cases) {
      try {
        operation();
        expect.fail(`expected ${errorCategory}`);
      } catch (error) {
        expect(error).toBeInstanceOf(VerificationError);
        expect((error as VerificationError).errorCategory).toBe(errorCategory);
      }
    }
  });

  it('throws VerificationError when no events exist', () => {
    const log = new DomainLog('agent.example.com', []);
    expect(() => log.snapshotAt(T3)).toThrow(VerificationError);
  });

  it('throws VerificationError when requested time is before first event', () => {
    const log = new DomainLog('agent.example.com', [ISSUANCE]);
    expect(() => log.snapshotAt(T0)).toThrow(VerificationError);
  });

  it('throws VerificationError when there is no ISSUANCE in the range', () => {
    const nonIssuance: MigrationEvent = {
      type: 'MIGRATION',
      domain: 'agent.example.com',
      previousLog: 'old:ref',
      newLog: 'new:ref',
      finalEntryRef: 'ref',
      timestamp: T1,
    };
    const log = new DomainLog('agent.example.com', [nonIssuance]);
    expect(() => log.snapshotAt(T3)).toThrow(VerificationError);
  });

  it('exposes state as the AgentStatusState union, not bare string', () => {
    const log = new DomainLog('agent.example.com', [ISSUANCE]);
    const snap = log.snapshotAt(T2);
    // @ts-expect-error state is AgentStatusState, so an off-spec literal is not assignable
    const bad: typeof snap.historicalState = 'UNKNOWN';
    expect(bad).toBe('UNKNOWN');
  });

  it('returns ACTIVE state after ISSUANCE', () => {
    const log = new DomainLog('agent.example.com', [ISSUANCE]);
    const snap = log.snapshotAt(T2);
    expect(snap.historicalState).toBe('ACTIVE');
    expect(snap.activeKey).toEqual(EC_KEY);
    expect(snap.activeKeyThumbprint).toBe(ISSUANCE.initialOperationalThumbprint);
    expect(snap.governanceId).toBe('example.com');
    expect(snap.keyBoundAt).toEqual(T1);
  });

  it('rejects ISSUANCE without entity/operational key separation', () => {
    const invalid: IssuanceEvent = {
      ...ISSUANCE,
      initialEntityKid: ISSUANCE.initialOperationalKid,
      initialEntityPublicKey: ISSUANCE.initialOperationalPublicKey,
      initialEntityThumbprint: ISSUANCE.initialOperationalThumbprint,
    };
    expect(() => new DomainLog('agent.example.com', [invalid]).snapshotAt(T2))
      .toThrow('ISSUANCE key binding is invalid');
  });

  it('updates active key after KEY_ROTATION', () => {
    const log = new DomainLog('agent.example.com', [ISSUANCE, ROTATION]);
    const snap = log.snapshotAt(T3);
    expect(snap.activeKey.kid).toBe('key-2');
    expect(snap.activeKeyThumbprint).toBe(ROTATION.newOperationalThumbprint);
    expect(snap.keyBoundAt).toEqual(T2);
    expect(snap.historicalState).toBe('ACTIVE');
  });

  it('shows pre-rotation key at time between ISSUANCE and KEY_ROTATION', () => {
    const log = new DomainLog('agent.example.com', [ISSUANCE, ROTATION]);
    const midT = new Date('2024-07-01T00:00:00Z');
    const snap = log.snapshotAt(midT);
    expect(snap.activeKey.kid).toBe('key-1');
    expect(snap.historicalState).toBe('ACTIVE');
  });

  it('returns REVOKED state after REVOCATION', () => {
    const log = new DomainLog('agent.example.com', [ISSUANCE, REVOCATION]);
    const snap = log.snapshotAt(new Date('2025-01-01T00:00:00Z'));
    expect(snap.historicalState).toBe('REVOKED');
  });

  it('rejects an invalid revocation reason at runtime', () => {
    const invalid = { ...REVOCATION, reason: 'ownerRequest' } as unknown as RevocationEvent;
    expect(() => new DomainLog('agent.example.com', [ISSUANCE, invalid])
      .snapshotAt(new Date('2025-01-01T00:00:00Z'))).toThrow('invalid REVOCATION reason');
  });

  it('returns RETIRED state after RETIREMENT', () => {
    const retirement: RetirementEvent = {
      type: 'RETIREMENT', domain: 'agent.example.com', timestamp: T3,
    };
    const log = new DomainLog('agent.example.com', [ISSUANCE, retirement]);
    const snap = log.snapshotAt(new Date('2025-01-01T00:00:00Z'));
    expect(snap.historicalState).toBe('RETIRED');
  });

  it('includes only events up to the requested time', () => {
    const log = new DomainLog('agent.example.com', [ISSUANCE, ROTATION, REVOCATION]);
    const snap = log.snapshotAt(T2); // at time of rotation but before revocation
    expect(snap.events).toHaveLength(2);
    expect(snap.events.map(e => e.type)).toEqual(['ISSUANCE', 'KEY_ROTATION']);
  });

  it('rejects a timestamp boundary that would require a non-prefix subsequence', () => {
    const futureEvent: RetirementEvent = {
      type: 'RETIREMENT', domain: 'agent.example.com', timestamp: T3,
    };
    const log = new DomainLog('agent.example.com', [ISSUANCE, futureEvent, ROTATION]);
    expect(() => log.snapshotAt(T2)).toThrow('snapshot time is not a verified lifecycle prefix');
  });

  it('sets snapshotAt to the requested time', () => {
    const log = new DomainLog('agent.example.com', [ISSUANCE]);
    const at = new Date('2024-08-15T12:00:00Z');
    const snap = log.snapshotAt(at);
    expect(snap.snapshotAt).toEqual(at);
  });

  it('error code is LogError', () => {
    const log = new DomainLog('agent.example.com', []);
    try {
      log.snapshotAt(T3);
      expect.fail('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VerificationError);
      expect((e as VerificationError).code).toBe(VerificationCode.LogError);
    }
  });

  it('throws VerificationError (not null assertion crash) when first event is REVOCATION', () => {
    const log = new DomainLog('agent.example.com', [REVOCATION]);
    expect(() => log.snapshotAt(new Date('2025-01-01T00:00:00Z'))).toThrow(VerificationError);
  });

  it('throws VerificationError (not null assertion crash) when first event is RETIREMENT', () => {
    const retirement: RetirementEvent = {
      type: 'RETIREMENT', domain: 'agent.example.com', timestamp: T1,
    };
    const log = new DomainLog('agent.example.com', [retirement]);
    expect(() => log.snapshotAt(new Date('2025-01-01T00:00:00Z'))).toThrow(VerificationError);
  });

  it('rejects a second ISSUANCE in one identity history', () => {
    const reissuance: IssuanceEvent = { ...ISSUANCE, timestamp: T2 };
    const log = new DomainLog('agent.example.com', [ISSUANCE, reissuance]);
    expect(() => log.snapshotAt(T3)).toThrow('duplicate ISSUANCE in one identity history');
  });

  it('rejects KEY_ROTATION outside an active issuance', () => {
    const log = new DomainLog('agent.example.com', [ROTATION]);
    expect(() => log.snapshotAt(T3)).toThrow('first lifecycle event must be ISSUANCE');
  });

  it('rejects lifecycle events after a terminal state', () => {
    const migration: MigrationEvent = {
      type: 'MIGRATION',
      domain: 'agent.example.com',
      previousLog: 'old:ref',
      newLog: 'new:ref',
      finalEntryRef: 'ref',
      timestamp: new Date('2025-01-01T00:00:00Z'),
    };
    const log = new DomainLog('agent.example.com', [ISSUANCE, REVOCATION, migration]);
    expect(() => log.snapshotAt(new Date('2025-02-01T00:00:00Z'))).toThrow('event after terminal identity state');
  });

  it('rejects reissuance after termination in the same history', () => {
    const reissuanceTime = new Date('2025-01-01T00:00:00Z');
    const reissuance: IssuanceEvent = {
      ...ISSUANCE,
      initialOperationalKid: 'key-3',
      initialOperationalPublicKey: { ...EC_KEY, kid: 'key-3' },
      initialOperationalThumbprint: ISSUANCE.initialOperationalThumbprint,
      timestamp: reissuanceTime,
    };
    const log = new DomainLog('agent.example.com', [ISSUANCE, REVOCATION, reissuance]);
    expect(() => log.snapshotAt(new Date('2025-02-01T00:00:00Z')))
      .toThrow('event after terminal identity state');
  });

  it('rejects an applied event for another domain', () => {
    const wrongDomain = { ...ISSUANCE, domain: 'other.example.com' };
    expect(() => new DomainLog('agent.example.com', [wrongDomain]).snapshotAt(T3))
      .toThrow('lifecycle event domain mismatch');
  });

  it('rejects rotation that does not continue from the active key', () => {
    const stale = { ...ROTATION, previousOperationalThumbprint: 'stale-thumbprint' };
    expect(() => new DomainLog('agent.example.com', [ISSUANCE, stale]).snapshotAt(T3))
      .toThrow('does not continue from the active key');
  });

  it('rejects rotation to the active key material', () => {
    const sameKey = {
      ...ROTATION,
      newOperationalKid: EC_KEY.kid,
      newOperationalPublicKey: EC_KEY,
      newOperationalThumbprint: ISSUANCE.initialOperationalThumbprint!,
    };
    expect(() => new DomainLog('agent.example.com', [ISSUANCE, sameKey]).snapshotAt(T3))
      .toThrow('KEY_ROTATION new key is invalid');
  });

  it('rejects migration to the current log', () => {
    const migration: MigrationEvent = {
      type: 'MIGRATION',
      domain: 'agent.example.com',
      previousLog: 'same:ref',
      newLog: 'same:ref',
      finalEntryRef: 'same:entry-1',
      timestamp: T2,
    };
    expect(() => new DomainLog('agent.example.com', [ISSUANCE, migration]).snapshotAt(T3))
      .toThrow('invalid MIGRATION');
  });

  it('rejects unsupported lifecycle events', () => {
    const future = {
      type: 'FUTURE_EVENT',
      domain: 'agent.example.com',
      timestamp: T2,
    } as unknown as IssuanceEvent;
    expect(() => new DomainLog('agent.example.com', [ISSUANCE, future]).snapshotAt(T3))
      .toThrow('unsupported lifecycle event type');
  });

  it('allows replacement only as a fresh history', () => {
    const replacement: IssuanceEvent = {
      ...ISSUANCE,
      initialOperationalKid: 'key-9',
      initialOperationalPublicKey: { ...ROTATED_KEY, kid: 'key-9' },
      initialOperationalThumbprint: ROTATION.newOperationalThumbprint,
      timestamp: T2,
    };
    const snap = new DomainLog('agent.example.com', [replacement]).snapshotAt(T3);
    expect(snap.historicalState).toBe('ACTIVE');
    expect(snap.activeKeyThumbprint).toBe(ROTATION.newOperationalThumbprint);
    expect(snap.events).toHaveLength(1);
  });
});
