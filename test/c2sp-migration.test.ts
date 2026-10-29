import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { DNSSECState, DnsIdTxtRecord, createIdentityVerifier, type DnsIdJWK } from '@dnsid-ai/sdk';
import {
  C2spTlogReader, canonicalBytes, checkpointPath, createC2spTlogVerificationRegistry,
  encodeEntryBundle, entryBundlePath, leafHash, merkleRootFromEntries, parseC2spPolicyFile,
  parseC2spTlogLr, parseCheckpoint, parseSignedNoteVerifierKey, requiredC2spResourceFetchGuarantees,
  signedC2spEntryBytes, type C2spMigrationVerificationLimits,
} from '@dnsid-ai/log-c2sp-tlog';

interface MigrationLog {
  lr: string;
  policy: string;
  checkpoint: string;
  entries: Array<{ index: number; entry: string; proof: string }>;
}
interface MigrationCase {
  domain: string;
  entityJwk: DnsIdJWK;
  operationalThumbprint: string;
  logs: MigrationLog[];
  target: number;
  maxDepth: number | null;
  at: number;
  beforeGenesis: number;
}
// Generated from dnsid-sdk-compliance/harness/migration_vectors.py; all logs are hermetic fixtures.
const vectors = JSON.parse(readFileSync(new URL('./vectors/c2sp-migration.json', import.meta.url), 'utf8')) as Array<{
  id: string; input: { migrationCase: MigrationCase };
  expect: { ok: boolean; eventCount?: number; keyTimestamp?: number; cutoffEventCount?: number };
}>;
const caseFor = (name: string) => structuredClone(vectors.find(vector => vector.id === `migration-${name}`)!.input.migrationCase);
const entryBytes = (log: MigrationLog) => log.entries.map(entry => Buffer.from(entry.entry, 'base64url'));
const privateKey = (seed: number) => createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seed)]), format: 'der', type: 'pkcs8',
});

// Fixture keys are disposable seeds shared with the compliance migration vectors.
function repackage(log: MigrationLog, entries: Uint8Array[], logSeed = 4): MigrationLog {
  const checkpoint = parseCheckpoint(log.checkpoint);
  const publicBytes = Buffer.from(createPublicKey(privateKey(logSeed)).export({ format: 'jwk' }).x!, 'base64url');
  const keyId = createHash('sha256').update(checkpoint.origin).update('\n').update(Buffer.from([1])).update(publicBytes).digest().subarray(0, 4);
  const body = `${checkpoint.origin}\n${entries.length}\n${Buffer.from(merkleRootFromEntries(entries)).toString('base64')}\n`;
  const signatures = checkpoint.signatures.map((signature, index) => {
    const time = signature.signature.slice(0, 8);
    const payload = index === 0 ? body : `cosignature/v1\ntime ${Buffer.from(time).readBigUInt64BE()}\n${body}`;
    const signed = sign(null, Buffer.from(payload), privateKey(index === 0 ? logSeed : 5));
    return `— ${signature.name} ${Buffer.concat([index === 0 ? keyId : signature.keyHash!, ...(index === 0 ? [] : [time]), signed]).toString('base64')}`;
  });
  return { ...log, policy: log.policy.replace(/^log .*$/m, `log ${checkpoint.origin}+${keyId.toString('hex')}+${Buffer.concat([Buffer.from([1]), publicBytes]).toString('base64')}`), checkpoint: `${body}\n${signatures.join('\n')}\n`, entries: entries.map((bytes, index) => ({ index, entry: Buffer.from(bytes).toString('base64url'), proof: '' })) };
}

function bundleFor(log: MigrationLog, omitLastCopy = false) {
  const name = 'migration-bundle';
  const publicBytes = Buffer.from(createPublicKey(privateKey(6)).export({ format: 'jwk' }).x!, 'base64url');
  const keyId = createHash('sha256').update(name).update('\n').update(Buffer.from([1])).update(publicBytes).digest().subarray(0, 4);
  const key = parseSignedNoteVerifierKey(`${name}+${keyId.toString('hex')}+${Buffer.concat([Buffer.from([1]), publicBytes]).toString('base64')}`);
  const bytes = entryBytes(log);
  const distinct = new Set(bytes.map(entry => Buffer.from(signedC2spEntryBytes(entry)).toString('base64url')));
  const lastType = JSON.parse(bytes.at(-1)!.toString()).type;
  const unsigned = {
    v: 1, type: 'dnsid-c2sp-stream-bundle', fqdn: 'agent.example', lr: log.lr,
    checkpoint: Buffer.from(log.checkpoint).toString('base64url'),
    policy_hash: createHash('sha256').update(log.policy).digest('base64url'),
    complete_through_size: bytes.length, completeness_mode: 'trusted-index',
    events: log.entries.filter((_, index) => !omitLastCopy || index === 0).map(entry => ({
      index: entry.index, entry: entry.entry, proof: bytes.length === 1 ? '' : Buffer.from(leafHash(bytes[1 - entry.index]!)).toString('base64url'),
    })),
    state: { event_count: distinct.size, last_event_type: lastType, logged_state: lastType === 'REVOCATION' ? 'REVOKED' : 'ACTIVE' },
    expires: Math.floor(Date.now() / 1000) + 60,
  };
  return { key, bytes: canonicalBytes({ ...unsigned, sig: {
    alg: 'EdDSA', kid: `${name}+${keyId.toString('hex')}`, value: sign(null, canonicalBytes(unsigned), privateKey(6)).toString('base64url'),
  } }) };
}

function readersFor(testCase: MigrationCase, limits?: C2spMigrationVerificationLimits, bundled = false, omitLastCopy = false) {
  const readers = new Map<string, C2spTlogReader>();
  testCase.logs.forEach((log, index) => {
    const bundle = bundled ? bundleFor(log, omitLastCopy) : undefined;
    readers.set(log.lr, new C2spTlogReader(log.lr, {
      policy: parseC2spPolicyFile(log.policy), entityKey: testCase.entityJwk, checkpointMaxAge: 10 ** 13,
      migrationLimits: index === testCase.target ? limits ?? (testCase.maxDepth ? { maxDepth: testCase.maxDepth } : undefined) : undefined,
      migrationReaderFactory: lr => readers.get(lr)!,
      streamSource: { load: async () => ({ checkpoint: parseCheckpoint(log.checkpoint), complete: true, entries: log.entries.map(entry => ({ index: entry.index, bytes: Buffer.from(entry.entry, 'base64url') })) }) },
      resourceFetcher: bundle ? { fetchBounded: async () => bundle.bytes, securityGuarantees: requiredC2spResourceFetchGuarantees } : undefined,
      streamBundle: bundle ? { policyDocument: Buffer.from(log.policy), bundleKeys: [bundle.key], maxBundleLifetimeMs: 10 ** 13, checkpointFreshnessMs: 10 ** 13, required: true } : undefined,
    }));
  });
  return readers;
}

describe('recursive C2SP migration', () => {
  for (const bundled of [false, true]) {
    it.each(vectors)('$id (bundled=' + bundled + ')', async vector => {
      const testCase = vector.input.migrationCase;
      const targetLog = testCase.logs[testCase.target]!;
      const reader = readersFor(testCase, undefined, bundled).get(targetLog.lr)!;
      if (!vector.expect.ok) {
        await expect(reader.rebuildHistory(testCase.domain)).rejects.toMatchObject({ code: 'LogError' });
        return;
      }
      await expect(reader.rebuildHistory(testCase.domain)).resolves.toHaveLength(vector.expect.eventCount!);
      await expect(reader.keyTimestamp(testCase.domain, testCase.operationalThumbprint)).resolves.toEqual(new Date(vector.expect.keyTimestamp! * 1000));
      await expect(reader.verifyNonRevocation(testCase.domain, new Date(testCase.at * 1000))).resolves.toMatchObject({ loggedState: 'ACTIVE', historyStart: `${testCase.logs[0]!.lr}@0`, historyEnd: `${targetLog.lr}@0` });
      await expect(reader.verifyNonRevocation(testCase.domain, new Date(testCase.beforeGenesis * 1000))).rejects.toMatchObject({ errorCategory: 'SNAPSHOT_EMPTY' });
      const cutoff = await reader.rebuildHistoryThrough(testCase.domain, `${targetLog.lr}@0`);
      expect(cutoff.priorHistory).toHaveLength(vector.expect.cutoffEventCount!);
      expect(cutoff.priorHistoryReferences).toEqual(testCase.logs.map(log => `${log.lr}@0`));
      expect(cutoff.entityKey).toEqual(testCase.entityJwk);
    });
  }

  it.each([{ maxHistoryEvents: 2 }, { maxResponseBytes: 2000 }])('carries target limits through all hops: %j', async limits => {
    const testCase = caseFor('two-hop-keeps-key-age');
    // Each predecessor fits separately; only the cumulative chain exceeds these limits.
    for (const log of testCase.logs) expect(Buffer.byteLength(log.checkpoint) + entryBytes(log)[0]!.length).toBeLessThan(2000);
    const reader = readersFor(testCase, limits).get(testCase.logs[2]!.lr)!;
    await expect(reader.rebuildHistory(testCase.domain)).rejects.toMatchObject({ errorCategory: 'INVALID_MIGRATION' });
  });

  it('bounds cumulative bundle responses across hops', async () => {
    const testCase = caseFor('two-hop-keeps-key-age');
    const maximum = Math.max(...testCase.logs.map(log => bundleFor(log).bytes.length));
    const reader = readersFor(testCase, { maxResponseBytes: maximum }, true).get(testCase.logs[2]!.lr)!;
    await expect(reader.rebuildHistory(testCase.domain)).rejects.toMatchObject({ errorCategory: 'INVALID_MIGRATION' });
  });

  it.each([0, -1, 1.5, Infinity, Number.MAX_SAFE_INTEGER + 1])('rejects invalid migration limits: %s', value => {
    const testCase = caseFor('source-genesis');
    for (const name of ['maxDepth', 'maxHistoryEvents', 'maxResponseBytes']) expect(() => readersFor(testCase, { [name]: value })).toThrow('positive safe integer');
  });

  it.each([false, true])('exports a valid later copy but rejects an invalid countersignature (bundled=%s)', async bundled => {
    const testCase = caseFor('source-genesis');
    const first = testCase.logs[0]!;
    const bytes = entryBytes(first)[0]!;
    testCase.logs[0] = repackage(first, [bytes, bytes]);
    const reader = readersFor(testCase, undefined, bundled, true).get(first.lr)!;
    const result = await reader.rebuildHistoryThrough(testCase.domain, `${first.lr}@1`);
    expect(result.priorHistory).toHaveLength(1);
    expect(result.priorHistoryReferences).toEqual([`${first.lr}@1`]);
    const invalid = JSON.parse(bytes.toString());
    invalid.sigs.op.sig = Buffer.alloc(64).toString('base64url');
    testCase.logs[0] = repackage(first, [bytes, canonicalBytes(invalid)]);
    await expect(readersFor(testCase, undefined, bundled, true).get(first.lr)!.rebuildHistoryThrough(testCase.domain, `${first.lr}@1`)).rejects.toMatchObject({ code: 'LogError' });
  });

  it('rejects a conflict through the cutoff and a cutoff that is noise or belongs to another log', async () => {
    const testCase = caseFor('source-genesis');
    const log = testCase.logs[0]!;
    const bytes = entryBytes(log)[0]!;
    const { sigs, ...payload } = JSON.parse(bytes.toString());
    payload.ts += 1;
    sigs.ae.sig = sign(null, canonicalBytes(payload), privateKey(1)).toString('base64url');
    sigs.op.sig = sign(null, canonicalBytes(payload), privateKey(2)).toString('base64url');
    testCase.logs[0] = repackage(log, [bytes, canonicalBytes({ ...payload, sigs })]);
    await expect(readersFor(testCase).get(log.lr)!.rebuildHistoryThrough(testCase.domain, `${log.lr}@1`)).rejects.toThrow();
    testCase.logs[0] = repackage(log, [bytes, Buffer.from('not a DNSid event')]);
    const reader = readersFor(testCase).get(log.lr)!;
    for (const ref of [`${log.lr}@1`, `${log.lr}@2`, `${log.lr}@00`, `${log.lr.replace('log-a', 'log-b')}@0`]) {
      await expect(reader.rebuildHistoryThrough(testCase.domain, ref)).rejects.toThrow();
    }
  });

  it('verifies the destination entity signature with the imported entity key', async () => {
    const testCase = caseFor('one-hop-keeps-key-age');
    const destination = testCase.logs[1]!;
    const event = JSON.parse(entryBytes(destination)[0]!.toString());
    event.sigs.ae.sig = Buffer.alloc(64).toString('base64url');
    testCase.logs[1] = repackage(destination, [canonicalBytes(event)]);
    await expect(readersFor(testCase).get(destination.lr)!.rebuildHistory(testCase.domain)).rejects.toThrow();
  });

  it('ignores an invalid-signature migration copy before the valid genesis', async () => {
    const testCase = caseFor('one-hop-keeps-key-age');
    const destination = testCase.logs[1]!;
    const bytes = entryBytes(destination)[0]!;
    const event = JSON.parse(bytes.toString());
    event.sigs.ae.sig = Buffer.alloc(64).toString('base64url');
    testCase.logs[1] = repackage(destination, [canonicalBytes(event), bytes]);
    await expect(readersFor(testCase).get(destination.lr)!.rebuildHistory(testCase.domain)).resolves.toHaveLength(2);
  });

  it('keeps the custom migration callback working and takes it before the factory', async () => {
    const testCase = caseFor('one-hop-keeps-key-age');
    const prior = readersFor(testCase).get(testCase.logs[0]!.lr)!;
    const destination = testCase.logs[1]!;
    const factory = vi.fn(() => { throw new Error('must not dispatch'); });
    const verifyMigration = vi.fn(event => prior.rebuildHistoryThrough(testCase.domain, event.finalEntryRef));
    const reader = new C2spTlogReader(destination.lr, {
      policy: parseC2spPolicyFile(destination.policy), entityKey: testCase.entityJwk,
      streamSource: { load: async () => ({ checkpoint: parseCheckpoint(destination.checkpoint), complete: true, entries: [{ index: 0, bytes: entryBytes(destination)[0]! }] }) },
      verifyMigration, migrationReaderFactory: factory,
    });
    await expect(reader.rebuildHistory(testCase.domain)).resolves.toHaveLength(2);
    await expect(reader.readEvent(`${destination.lr}@0`)).resolves.toMatchObject({ type: 'MIGRATION' });
    expect(factory).not.toHaveBeenCalled();
    expect(verifyMigration).toHaveBeenCalledOnce();
  });

  it('wires the convenience registry into IdentityManager without a custom migration callback', async () => {
    const testCase = caseFor('two-hop-keeps-key-age');
    testCase.logs = testCase.logs.map((log, index) => repackage(log, entryBytes(log), 10 + index));
    const resources = new Map<string, Uint8Array>();
    for (const log of testCase.logs) {
      const { logPrefix } = parseC2spTlogLr(log.lr);
      resources.set(checkpointPath(logPrefix), Buffer.from(log.checkpoint));
      resources.set(entryBundlePath(logPrefix, 0, log.entries.length), encodeEntryBundle(entryBytes(log)));
    }
    const policies = testCase.logs.map(log => log.policy.split('\n').find(line => line.startsWith('log '))).join('\n') + '\n' + testCase.logs[0]!.policy.split('\n').filter(line => !line.startsWith('log ')).join('\n');
    const logRegistry = await createC2spTlogVerificationRegistry({
      policyDocument: Buffer.from(policies), checkpointMaxAge: 10 ** 13,
      resourceFetcher: { fetchBounded: async url => { const bytes = resources.get(url); if (!bytes) throw new Error(`unexpected fixture URL: ${url}`); return bytes; }, securityGuarantees: requiredC2spResourceFetchGuarantees },
    });
    const record = new DnsIdTxtRecord();
    Object.assign(record, { v: 'dnsid-draft-01', gi: 'example', ek: 'https://entity.example/jwks', ku: 'https://agent.example/jwks', su: 'https://agent.example/status', lr: testCase.logs[2]!.lr, agentFQDN: testCase.domain });
    record.sg = sign(null, Buffer.from(record.canonical()), privateKey(1)).toString('base64url');
    const operational = JSON.parse(entryBytes(testCase.logs[0]!)[0]!.toString()).ku;
    const tlsCert = { notAfter: new Date('2099-01-01'), san: [testCase.domain, 'entity.example'] };
    const manager = createIdentityVerifier({}, {
      logRegistry,
      dnsResolver: { fetchTXT: async () => [[{ strings: [record.serialize()], ttl: 300 }], DNSSECState.UNSIGNED] },
      fetchJson: async url => {
        if (url === record.ek) return { data: { keys: [testCase.entityJwk] }, tlsCert };
        if (url === record.ku) return { data: { keys: [operational] }, tlsCert };
        if (url === record.su) return { data: { state: 'ACTIVE', lastTransitionAt: new Date().toISOString() }, tlsCert };
        throw new Error(`unexpected JSON URL: ${url}`);
      },
    });
    const verified = await manager.verifyDomain(testCase.domain);
    expect((await manager.loadDomainLog(verified)).events).toHaveLength(3);
    await expect(verified.logReader.keyTimestamp(testCase.domain, testCase.operationalThumbprint)).resolves.toEqual(new Date((testCase.beforeGenesis + 1) * 1000));
  });
});
