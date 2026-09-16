import { createHash, createPrivateKey, generateKeyPairSync, sign as signEd25519, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { correctedBundle } from './helpers/corrected-c2sp-bundle.ts';

import { jwkThumbprint, type C2spIssuanceEvent, type DnsIdJWK, type LogEvent } from '@dnsid-ai/protocol';
import {
  C2SP_TLOG_PROFILE_VERSION,
  C2SP_TLOG_SPECIFICATIONS,
  C2spTlogError,
  C2spTlogReader,
  InMemoryTrustedC2spCheckpointStore,
  canonicalBytes,
  canonicalizeC2spEvent,
  checkpointPath,
  createC2spTlogVerificationRegistry,
  createFetchBackedC2spResourceFetcher,
  encodeEntryBundle,
  entryBundlePath,
  leafHash,
  merkleRootFromEntries,
  parseCheckpoint,
  parseC2spPolicyFile,
  parseC2spTlogLr,
  parseC2spStreamBundle,
  parseC2spTlogTrustProfile,
  parseSignedNoteVerifierKey,
  requiredC2spResourceFetchGuarantees,
  signedC2spEventBytes,
  verifyC2spStreamBundle,
} from '@dnsid-ai/log-c2sp-tlog';

const BUNDLE_EXTRA_ENTRY = new TextEncoder().encode('bundle tree non-lifecycle entry');
const HISTORICAL_ISSUANCE_ENTRY = '{"ek":{"alg":"EdDSA","crv":"Ed25519","kid":"ae-test-1","kty":"OKP","x":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"},"fqdn":"agent.example","gi":"example.com","kind":"dnsid.lifecycle","ku":{"alg":"EdDSA","crv":"Ed25519","kid":"op-test-1","kty":"OKP","x":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q"},"sigs":{"ae":{"kid":"ae-test-1","sig":"Qp_IOg6S-ksElLBrMTwUqQ6slrt-W-wbXtadHY6nXOPbUXs1013_kNdrMWYEWjVZcvXptqxwshbKu-wtz4h6CQ"},"op":{"kid":"op-test-1","sig":"jWSZhq4Cm5FeHipM1MX5LVdej9cpStNAaoCFZSG3G_w-0w4rhYss2Vvi0lz7DcvVFO8K2nde0VfX2c5Ga5bvAg"}},"ts":1782172800,"type":"ISSUANCE","v":1}';
const LR = 'c2sp-tlog:testnet:https://log.example/dnsid#test-instance';
const ORIGIN = 'log.example/dnsid';
// Regenerate actual lifecycle signatures; never rewrite a signed fixture's bytes without signing.
const ISSUANCE_ENTRY = (() => {
  const { sigs, ...payload } = JSON.parse(HISTORICAL_ISSUANCE_ENTRY);
  Object.assign(payload, { method: 'c2sp-tlog', log_origin: ORIGIN, stream_id: 'test-instance', lr: LR, seq: 0 });
  for (const [role, seed] of [['ae', 1], ['op', 2]] as const) {
    const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seed)]), format: 'der', type: 'pkcs8' });
    sigs[role].sig = signEd25519(null, canonicalBytes(payload), key).toString('base64url');
  }
  return new TextDecoder().decode(canonicalBytes({ ...payload, sigs }));
})();

interface Fixture {
  bytes: Uint8Array;
  object: Record<string, unknown>;
  options: Parameters<typeof verifyC2spStreamBundle>[1];
  bundleKeyText: string;
  checkpoint(entries: Uint8Array[]): Uint8Array;
  resign(): Uint8Array;
}

interface SharedVector {
  bundle: string;
  expected: {
    active_operational_thumbprint: string;
    bundle_signer_kid: string;
    event_count: number;
    status: string;
  };
  negative_mutations: Array<{
    append?: string;
    name: string;
    path: string;
    resign?: boolean;
    value?: unknown;
  }>;
  policy: string;
  trust: {
    bundle_verifier_key: string;
    checkpoint_freshness_ms: number;
    entity_jwk: DnsIdJWK;
    max_bundle_lifetime_ms: number;
    now: number;
  };
}

const SHARED_VECTOR = JSON.parse(readFileSync(
  new URL('./vectors/c2sp-stream-bundle-v1.json', import.meta.url),
  'utf8',
)) as SharedVector;
const HISTORICAL_BUNDLE = SHARED_VECTOR.bundle;
SHARED_VECTOR.bundle = correctedBundle(HISTORICAL_BUNDLE);

function sharedVectorOptions(): Parameters<typeof verifyC2spStreamBundle>[1] {
  return {
    expectedFqdn: 'agent.example.com',
    expectedLogReference: 'c2sp-tlog:public:https://log.example#EREREREREREREREREREREQ',
    policyBytes: new TextEncoder().encode(SHARED_VECTOR.policy),
    bundleKeys: [parseSignedNoteVerifierKey(SHARED_VECTOR.trust.bundle_verifier_key)],
    entityKey: SHARED_VECTOR.trust.entity_jwk,
    maxBundleBytes: 128 * 1024,
    maxEvents: 16,
    maxBundleLifetimeMs: SHARED_VECTOR.trust.max_bundle_lifetime_ms,
    checkpointFreshnessMs: SHARED_VECTOR.trust.checkpoint_freshness_ms,
    nowMs: SHARED_VECTOR.trust.now * 1000,
    trustedCheckpointStore: new InMemoryTrustedC2spCheckpointStore(),
  };
}

function mutateSharedVector(mutation: SharedVector['negative_mutations'][number]): Uint8Array {
  const object = JSON.parse(SHARED_VECTOR.bundle) as Record<string, unknown>;
  const segments = mutation.path.split('/').slice(1);
  let target: Record<string, unknown> | unknown[] = object;
  for (const segment of segments.slice(0, -1)) target = target[segment as keyof typeof target] as Record<string, unknown>;
  const final = segments.at(-1)!;
  const previous = target[final as keyof typeof target];
  target[final as keyof typeof target] = mutation.append ? `${String(previous)}${mutation.append}` : mutation.value;
  if (mutation.resign) {
    const { sig, ...unsigned } = object;
    const seed = Buffer.alloc(32, 6);
    const privateKey = createPrivateKey({
      key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
      format: 'der',
      type: 'pkcs8',
    });
    (sig as Record<string, unknown>).value = signEd25519(null, Buffer.from(canonicalBytes(unsigned)), privateKey).toString('base64url');
  }
  return canonicalBytes(object);
}

function signedNoteKey(name: string, signatureType: number) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicBytes = Buffer.from(publicKey.export({ format: 'jwk' }).x!, 'base64url');
  const type = Buffer.from([signatureType]);
  const keyId = createHash('sha256').update(name).update('\n').update(type).update(publicBytes).digest().subarray(0, 4);
  const text = `${name}+${keyId.toString('hex')}+${Buffer.concat([type, publicBytes]).toString('base64')}`;
  return { publicKey, privateKey, keyId, text, parsed: parseSignedNoteVerifierKey(text) };
}

function signCheckpointLine(name: string, keyId: Buffer, body: string, privateKey: KeyObject): string {
  const signature = signEd25519(null, Buffer.from(body), privateKey);
  return `— ${name} ${Buffer.concat([keyId, signature]).toString('base64')}`;
}

function fixture(extraEntry?: Uint8Array): Fixture {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const entryBytes = new TextEncoder().encode(ISSUANCE_ENTRY);
  const treeEntries = extraEntry ? [entryBytes, extraEntry] : [entryBytes];
  const log = signedNoteKey(ORIGIN, 0x01);
  const witness = signedNoteKey('witness.example', 0x04);
  const checkpoint = (entries: Uint8Array[]) => {
    const checkpointBody = `${ORIGIN}\n${entries.length}\n${Buffer.from(merkleRootFromEntries(entries)).toString('base64')}\n`;
    const timestampBytes = Buffer.alloc(8);
    timestampBytes.writeBigUInt64BE(BigInt(nowSeconds));
    const witnessSignature = signEd25519(
      null,
      Buffer.from(`cosignature/v1\ntime ${nowSeconds}\n${checkpointBody}`),
      witness.privateKey,
    );
    return new TextEncoder().encode(`${checkpointBody}\n${signCheckpointLine(ORIGIN, log.keyId, checkpointBody, log.privateKey)}\n— witness.example ${Buffer.concat([witness.keyId, timestampBytes, witnessSignature]).toString('base64')}\n`);
  };
  const checkpointBytes = checkpoint(treeEntries);
  const policyBytes = new TextEncoder().encode(`log ${log.text}\nwitness W ${witness.text}\nquorum W\n`);
  const bundleKey = signedNoteKey('dnsid-stream-bundle', 0x01);
  const unsigned = {
    v: 1,
    type: 'dnsid-c2sp-stream-bundle',
    fqdn: 'agent.example',
    lr: LR,
    checkpoint: Buffer.from(checkpointBytes).toString('base64url'),
    policy_hash: createHash('sha256').update(policyBytes).digest('base64url'),
    complete_through_size: treeEntries.length,
    completeness_mode: 'trusted-index',
    events: [{
      index: 0,
      entry: Buffer.from(entryBytes).toString('base64url'),
      proof: extraEntry ? Buffer.from(leafHash(extraEntry)).toString('base64url') : '',
    }],
    state: { event_count: 1, last_event_type: 'ISSUANCE', logged_state: 'ACTIVE' },
    expires: nowSeconds + 30,
  };
  const object = {
    ...unsigned,
    sig: { alg: 'EdDSA', kid: `dnsid-stream-bundle+${bundleKey.keyId.toString('hex')}`, value: '' },
  };
  const resign = () => {
    const { sig: _sig, ...toSign } = object;
    (object.sig as Record<string, unknown>).value = signEd25519(null, Buffer.from(canonicalBytes(toSign)), bundleKey.privateKey).toString('base64url');
    return canonicalBytes(object);
  };
  const bytes = resign();
  return {
    object,
    bytes,
    bundleKeyText: bundleKey.text,
    checkpoint,
    resign,
    options: {
      expectedFqdn: 'agent.example',
      expectedLogReference: LR,
      policyBytes,
      bundleKeys: [bundleKey.parsed],
      entityKey: (JSON.parse(ISSUANCE_ENTRY) as { ek: DnsIdJWK }).ek,
      maxBundleBytes: 128 * 1024,
      maxEvents: 16,
      maxBundleLifetimeMs: 60_000,
      checkpointFreshnessMs: 60_000,
      nowMs: nowSeconds * 1000,
      trustedCheckpointStore: new InMemoryTrustedC2spCheckpointStore(),
    },
  };
}

async function migrationFixture(nested: boolean) {
  const lifecycleKey = (kid: string) => {
    const pair = generateKeyPairSync('ed25519');
    return {
      ...pair,
      jwk: { ...pair.publicKey.export({ format: 'jwk' }), kid, alg: 'EdDSA' } as DnsIdJWK,
    };
  };
  const entity = lifecycleKey('migration-entity');
  const operational = lifecycleKey('migration-op');
  const now = Math.floor(Date.now() / 1000);
  const oldLr = 'c2sp-tlog:testnet:https://old.example/dnsid#old-stream';
  const middleLr = 'c2sp-tlog:testnet:https://middle.example/dnsid#middle-stream';
  const priorIssuance: C2spIssuanceEvent = {
    type: 'ISSUANCE',
    domain: 'agent.example',
    governanceId: 'example.com',
    timestamp: new Date((now - 30) * 1000),
    initialOperationalKid: operational.jwk.kid,
    initialOperationalAlg: operational.jwk.alg!,
    initialOperationalPublicKey: operational.jwk,
    initialOperationalThumbprint: await jwkThumbprint(operational.jwk),
    initialEntityKid: entity.jwk.kid,
    initialEntityAlg: entity.jwk.alg!,
    initialEntityPublicKey: entity.jwk,
    initialEntityThumbprint: await jwkThumbprint(entity.jwk),
  };
  const priorHistory: LogEvent[] = [priorIssuance];
  const priorHistoryReferences = [`${oldLr}@7`];
  if (nested) {
    priorHistory.push({
      type: 'MIGRATION',
      domain: priorIssuance.domain,
      previousLog: oldLr,
      newLog: middleLr,
      finalEntryRef: `${oldLr}@7`,
      timestamp: new Date((now - 25) * 1000),
    });
    priorHistoryReferences.push(`${middleLr}@3`);
  }
  const previousLog = nested ? middleLr : oldLr;
  const migration = {
    type: 'MIGRATION' as const,
    domain: priorIssuance.domain,
    previousLog,
    newLog: LR,
    finalEntryRef: priorHistoryReferences.at(-1)!,
    timestamp: new Date((now - 20) * 1000),
  };
  const parsed = parseC2spTlogLr(LR);
  const context = { scope: parsed.scope, logOrigin: parsed.origin, streamId: parsed.streamId, lr: parsed.lr, seq: 0 };
  const signed = {
    ...migration,
    signingKid: entity.jwk.kid,
    sig: signEd25519(null, Buffer.from(signedC2spEventBytes(migration, context)), entity.privateKey).toString('base64url'),
  };
  const entryBytes = canonicalizeC2spEvent(signed, context);
  const value = fixture();
  const checkpointBytes = value.checkpoint([entryBytes]);
  value.object.checkpoint = Buffer.from(checkpointBytes).toString('base64url');
  value.object.events = [{ index: 0, entry: Buffer.from(entryBytes).toString('base64url'), proof: '' }];
  value.object.state = { event_count: 1, last_event_type: 'MIGRATION', logged_state: 'ACTIVE' };
  value.bytes = value.resign();
  value.options.entityKey = entity.jwk;
  const verificationResult = {
    entityKey: entity.jwk,
    activeOperationalKey: operational.jwk,
    priorHistory,
    priorHistoryReferences,
  };
  value.options.verifyMigration = async () => verificationResult;
  return { value, checkpointBytes, entryBytes, migration, priorHistoryReferences, verificationResult };
}

function trustProfile(value: Fixture) {
  return parseC2spTlogTrustProfile(new TextEncoder().encode(JSON.stringify({
    version: 1,
    scope: 'testnet',
    log_prefix: 'https://log.example/dnsid',
    tlog_policy: new TextDecoder().decode(value.options.policyBytes),
    bundle_verifier_keys: [value.bundleKeyText],
  })));
}

async function missingConsistencyReader(rawEntries: Uint8Array[], required = false) {
  const value = fixture(BUNDLE_EXTRA_ENTRY);
  const endpoint = 'https://log.example/dnsid/streams/agent.example?format=bundle';
  const fetchBounded = vi.fn(async (url: string) => {
    if (url === endpoint) return value.bytes;
    if (url === checkpointPath('https://log.example/dnsid')) return value.checkpoint(rawEntries);
    if (url === entryBundlePath('https://log.example/dnsid', 0, rawEntries.length)) return encodeEntryBundle(rawEntries);
    throw new Error(`unexpected URL ${url}`);
  });
  const store = new InMemoryTrustedC2spCheckpointStore();
  await store.compareAndSwap(ORIGIN, undefined, {
    origin: ORIGIN,
    treeSize: 1,
    rootHash: merkleRootFromEntries([new TextEncoder().encode(ISSUANCE_ENTRY)]),
    witnessTime: new Date(0),
  });
  const registry = await createC2spTlogVerificationRegistry({
    policyDocument: value.options.policyBytes,
    bundleVerifierKeys: value.options.bundleKeys,
    resourceFetcher: { fetchBounded, securityGuarantees: requiredC2spResourceFetchGuarantees },
    trustedCheckpointStore: store,
    checkpointMaxAge: 60_000,
    maxBundleLifetimeMs: 60_000,
    requireStreamBundle: required,
  });
  const issuance = JSON.parse(ISSUANCE_ENTRY) as { ek: DnsIdJWK; gi: string; ku: DnsIdJWK };
  return {
    fetchBounded,
    store,
    verify: () => (registry.newReader(LR) as C2spTlogReader)
      .verifyBilateralBinding({ agentFQDN: 'agent.example', gi: issuance.gi }, issuance.ek, issuance.ku),
  };
}

describe('C2SP stream bundles', () => {
  it.each(['abort', 'deadline'])('does not advance trust after %s during consistency fetching', async mode => {
    vi.useFakeTimers();
    let release!: (proof: Uint8Array[]) => void;
    try {
      const value = fixture(BUNDLE_EXTRA_ENTRY);
      const store = value.options.trustedCheckpointStore;
      await store.compareAndSwap(ORIGIN, undefined, {
        origin: ORIGIN, treeSize: 1, rootHash: leafHash(new TextEncoder().encode(ISSUANCE_ENTRY)), witnessTime: new Date(),
      });
      const previous = await store.load(ORIGIN);
      let started!: () => void;
      const ready = new Promise<void>(resolve => { started = resolve; });
      const proof = new Promise<Uint8Array[]>(resolve => { release = resolve; });
      let proofSignal: AbortSignal | undefined;
      const controller = new AbortController();
      const pending = verifyC2spStreamBundle(value.bytes, {
        ...value.options, signal: controller.signal, timeoutMs: 1000,
        consistencyProofSource: { fetchConsistencyProof: async (_ref, _from, _to, signal) => {
          proofSignal = signal;
          started();
          return proof; // Deliberately noncooperative fetch: a late result must not commit.
        } },
      });
      const rejected = expect(pending).rejects.toThrow(/deadline|canceled/);
      await ready;
      if (mode === 'abort') controller.abort();
      else await vi.advanceTimersByTimeAsync(1000);
      await rejected;
      expect(proofSignal?.aborted).toBe(true);
      release([leafHash(BUNDLE_EXTRA_ENTRY)]);
      await vi.advanceTimersByTimeAsync(0);
      await expect(store.load(ORIGIN)).resolves.toEqual(previous);
    } finally { release?.([]); vi.useRealTimers(); }
  });
  it('exports the exact C2SP profile pins', () => {
    expect(C2SP_TLOG_PROFILE_VERSION).toBe(1);
    expect(C2SP_TLOG_SPECIFICATIONS).toMatchObject({
      'tlog-checkpoint': 'https://c2sp.org/tlog-checkpoint@v1.0.0',
      'tlog-cosignature': 'https://c2sp.org/tlog-cosignature@v1.0.1',
      'signed-note': 'https://c2sp.org/signed-note@v1.0.0',
    });
  });

  it.each([false, true])('authenticates the exact later readEvent occurrence (invalid countersignature=%s)', async invalid => {
    const first = new TextEncoder().encode(ISSUANCE_ENTRY);
    const copy = JSON.parse(ISSUANCE_ENTRY);
    if (invalid) copy.sigs.op.sig = 'AA';
    const copyBytes = canonicalBytes(copy);
    const value = fixture(copyBytes);
    const checkpoint = Buffer.from(value.object.checkpoint as string, 'base64url').toString();
    const reader = new C2spTlogReader(LR, {
      policy: parseC2spPolicyFile(new TextDecoder().decode(value.options.policyBytes)),
      entityKey: value.options.entityKey,
      proofs: { '1': `c2sp.org/tlog-proof@v1\nindex 1\n${Buffer.from(leafHash(first)).toString('base64')}\n\n${checkpoint}` },
      streamSource: { load: async () => ({ checkpoint: parseCheckpoint(checkpoint), entries: [{ index: 0, bytes: first }, { index: 1, bytes: copyBytes }], complete: true }) },
      resourceFetcher: { fetchBounded: async () => value.bytes, securityGuarantees: requiredC2spResourceFetchGuarantees },
      streamBundle: { policyDocument: value.options.policyBytes, bundleKeys: value.options.bundleKeys, maxBundleLifetimeMs: 60000, checkpointFreshnessMs: 60000, required: true },
    });
    if (invalid) await expect(reader.readEvent(`${LR}@1`)).rejects.toThrow('operational countersignature');
    else await expect(reader.readEvent(`${LR}@1`)).resolves.toMatchObject({ type: 'ISSUANCE' });
  });

  it('counts logical events while verifying every supplied copy proof', async () => {
    const copy = JSON.parse(ISSUANCE_ENTRY);
    copy.sigs.op.sig = 'AA';
    const copyBytes = canonicalBytes(copy);
    const value = fixture(copyBytes);
    (value.object.events as unknown[]).push({ index: 1, entry: Buffer.from(copyBytes).toString('base64url'), proof: Buffer.from(leafHash(new TextEncoder().encode(ISSUANCE_ENTRY))).toString('base64url') });
    await expect(verifyC2spStreamBundle(value.resign(), value.options)).resolves.toMatchObject({ events: [{ index: 0 }] });
    (value.object.events as Array<{ proof: string }>)[1]!.proof = Buffer.alloc(32).toString('base64url');
    await expect(verifyC2spStreamBundle(value.resign(), value.options)).rejects.toThrow('inclusion proof');
  });

  it('verifies a canonical trusted-index bundle end to end', async () => {
    const value = fixture();
    const parsed = parseC2spStreamBundle(value.bytes, value.options);
    expect(parsed.events).toHaveLength(1);
    const verified = await verifyC2spStreamBundle(value.bytes, value.options);
    expect(verified.lifecycle.map(event => event.type)).toEqual(['ISSUANCE']);
    expect(verified.activeOperationalKeyThumbprint).toBe('aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU');
  });

  it.each([
    ['single migration, raw complete scan', false, false],
    ['single migration, verified stream bundle', true, false],
    ['nested migration, raw complete scan', false, true],
    ['nested migration, verified stream bundle', true, true],
  ] as const)('returns migrated evidence for %s', async (_name, bundled, nested) => {
    const { value, checkpointBytes, entryBytes, migration, priorHistoryReferences } = await migrationFixture(nested);
    const common = {
      policy: parseC2spPolicyFile(new TextDecoder().decode(value.options.policyBytes)),
      entityKey: value.options.entityKey,
      checkpointMaxAge: 60_000,
      verifyMigration: value.options.verifyMigration,
    };
    const reader = bundled
      ? new C2spTlogReader(LR, {
        ...common,
        resourceFetcher: {
          fetchBounded: async () => value.bytes,
          securityGuarantees: requiredC2spResourceFetchGuarantees,
        },
        streamBundle: {
          policyDocument: value.options.policyBytes,
          bundleKeys: value.options.bundleKeys,
          maxBundleLifetimeMs: value.options.maxBundleLifetimeMs,
          checkpointFreshnessMs: value.options.checkpointFreshnessMs,
        },
      })
      : new C2spTlogReader(LR, {
        ...common,
        streamSource: {
          load: async () => ({
            checkpoint: parseCheckpoint(new TextDecoder().decode(checkpointBytes)),
            entries: [{ index: 0, bytes: entryBytes }],
            complete: true,
          }),
        },
      });

    const beforeMigration = await reader.verifyNonRevocation(migration.domain, new Date(migration.timestamp.getTime() - 1));
    expect(beforeMigration).toMatchObject({
      logReference: LR,
      historyStart: priorHistoryReferences[0],
      historyEnd: priorHistoryReferences.at(-1),
      completeThrough: '1',
      completenessMode: bundled ? 'trusted-index' : 'full-scan',
    });
    const afterMigration = await reader.verifyNonRevocation(migration.domain, migration.timestamp);
    expect(afterMigration).toMatchObject({
      logReference: LR,
      historyStart: priorHistoryReferences[0],
      historyEnd: `${LR}@0`,
      loggedState: 'ACTIVE',
      completeThrough: '1',
      completenessMode: bundled ? 'trusted-index' : 'full-scan',
    });
    expect(afterMigration.checkpoint).toEqual(checkpointBytes);
  });

  it.each([
    ['missing references', undefined, 'no verified history bounds'],
    ['malformed references', ['malformed'], 'malformed log reference'],
    ['mismatched signed cutoff', ['c2sp-tlog:testnet:https://old.example/dnsid#old-stream@6'], 'signed prev_ref'],
  ] as const)('fails closed for migrated prior evidence with %s', async (_name, references, message) => {
    const { value, checkpointBytes, entryBytes, migration, verificationResult } = await migrationFixture(false);
    const reader = new C2spTlogReader(LR, {
      policy: parseC2spPolicyFile(new TextDecoder().decode(value.options.policyBytes)),
      entityKey: value.options.entityKey,
      checkpointMaxAge: 60_000,
      verifyMigration: async () => ({ ...verificationResult, priorHistoryReferences: references ? [...references] : undefined }),
      streamSource: {
        load: async () => ({
          checkpoint: parseCheckpoint(new TextDecoder().decode(checkpointBytes)),
          entries: [{ index: 0, bytes: entryBytes }],
          complete: true,
        }),
      },
    });

    await expect(reader.verifyNonRevocation(migration.domain, migration.timestamp))
      .rejects.toMatchObject({ message: expect.stringContaining(message), errorCategory: expect.any(String) });
  });

  it('rejects the historical chain and verifies independently regenerated signatures and proofs', async () => {
    await expect(verifyC2spStreamBundle(new TextEncoder().encode(HISTORICAL_BUNDLE), sharedVectorOptions())).rejects.toMatchObject({ errorCategory: 'CHAIN_CONTINUITY' });
    const bytes = new TextEncoder().encode(SHARED_VECTOR.bundle);
    expect(Buffer.from(canonicalBytes(JSON.parse(SHARED_VECTOR.bundle))).equals(Buffer.from(bytes))).toBe(true);
    const parsed = parseC2spStreamBundle(bytes, sharedVectorOptions());
    expect(parsed.signature.kid).toBe(SHARED_VECTOR.expected.bundle_signer_kid);
    const verified = await verifyC2spStreamBundle(bytes, sharedVectorOptions());
    expect(verified.events).toHaveLength(SHARED_VECTOR.expected.event_count);
    expect(verified.bundle.state.loggedState).toBe(SHARED_VECTOR.expected.status);
    expect(verified.activeOperationalKeyThumbprint).toBe(SHARED_VECTOR.expected.active_operational_thumbprint);
  });

  it.each(SHARED_VECTOR.negative_mutations)('rejects shared-vector mutation $name', async mutation => {
    const messages: Record<string, string> = {
      'padded-policy-hash': 'unpadded base64url',
      'wrong-state': 'state does not match',
      expired: 'expired',
      'unsupported-completeness': 'unsupported',
      'out-of-order-index': 'strictly increasing',
      'proof-length': 'SHA-256 nodes',
    };
    await expect(verifyC2spStreamBundle(mutateSharedVector(mutation), sharedVectorOptions()))
      .rejects.toThrow(messages[mutation.name]);
  });

  it('rejects non-canonical encoding and alternate base64url', () => {
    const value = fixture();
    expect(() => parseC2spStreamBundle(new TextEncoder().encode(`${JSON.stringify(value.object)}\n`), value.options))
      .toThrow('canonical JCS');
    const padded = structuredClone(value.object) as { events: Array<{ entry: string }> };
    padded.events[0]!.entry += '=';
    expect(() => parseC2spStreamBundle(canonicalBytes(padded), value.options)).toThrow('unpadded base64url');
  });

  it('rejects invalid completeness, policy, state, freshness, and signature claims', async () => {
    const cases: Array<[string, (value: Fixture) => void, string]> = [
      ['unsupported mode', value => { value.object.completeness_mode = 'untrusted-index'; }, 'completeness_mode'],
      ['wrong policy', value => { value.options.policyBytes = new TextEncoder().encode('changed'); }, 'policy_hash'],
      ['wrong state', value => { (value.object.state as Record<string, unknown>).logged_state = 'REVOKED'; }, 'state does not match'],
      ['expired', value => { value.object.expires = 1_782_345_700; }, 'expired'],
      ['untrusted signer', value => { value.options.bundleKeys = []; }, 'not uniquely trusted'],
      ['ambiguous signer', value => { value.options.bundleKeys.push(value.options.bundleKeys[0]!); }, 'not uniquely trusted'],
      ['checkpoint key overlap', value => {
        const logKey = new TextDecoder().decode(value.options.policyBytes).split(/\s+/)[1]!;
        value.options.bundleKeys = [parseSignedNoteVerifierKey(logKey)];
      }, 'independent of checkpoint'],
    ];
    for (const [, mutate, message] of cases) {
      const value = fixture();
      mutate(value);
      const bytes = value.resign();
      await expect(verifyC2spStreamBundle(bytes, value.options)).rejects.toThrow(message);
    }
  });

  it('does not trust a checkpoint from a bundle rejected after checkpoint validation', async () => {
    const value = fixture();
    (value.object.state as Record<string, unknown>).logged_state = 'REVOKED';

    await expect(verifyC2spStreamBundle(value.resign(), value.options)).rejects.toThrow('state does not match');
    await expect(value.options.trustedCheckpointStore.load(ORIGIN)).resolves.toBeUndefined();
  });

  it('uses one default-reader bundle snapshot for binding, continuity, and key age', async () => {
    const value = fixture();
    const endpoint = 'https://log.example/dnsid/streams/agent.example?format=bundle';
    let response = value.bytes;
    const fetchBounded = vi.fn(async (url: string) => {
      if (url !== endpoint) throw new Error(`unexpected raw-scan request ${url}`);
      return response;
    });
    const registry = await createC2spTlogVerificationRegistry({
      policyDocument: value.options.policyBytes,
      bundleVerifierKeys: value.options.bundleKeys,
      resourceFetcher: { fetchBounded, securityGuarantees: requiredC2spResourceFetchGuarantees },
      checkpointMaxAge: 60_000,
      maxBundleLifetimeMs: 60_000,
    });
    const reader = registry.newReader(LR) as C2spTlogReader;
    const issuance = JSON.parse(ISSUANCE_ENTRY) as { ek: DnsIdJWK; gi: string; ku: DnsIdJWK };
    const record = { agentFQDN: 'agent.example', gi: issuance.gi };

    const binding = await reader.verifyBilateralBinding(record, issuance.ek, issuance.ku);
    await reader.verifyOperationalContinuity('agent.example', binding.initialOperationalThumbprint, binding.initialOperationalThumbprint);
    await expect(reader.keyTimestamp('agent.example', binding.initialOperationalThumbprint)).resolves.toEqual(new Date(1_782_172_800_000));
    expect(fetchBounded).toHaveBeenCalledOnce();
    expect(fetchBounded).toHaveBeenCalledWith(endpoint, 8 * 1024 * 1024, expect.objectContaining({ timeoutMs: 10_000 }));

    await expect(reader.verifyNonRevocation('agent.example', new Date())).resolves.toEqual({
      logReference: LR,
      loggedState: 'ACTIVE',
      historyStart: `${LR}@0`,
      historyEnd: `${LR}@0`,
      completeThrough: '1',
      completenessMode: 'trusted-index',
      checkpoint: new Uint8Array(Buffer.from(value.object.checkpoint as string, 'base64url')),
      freshnessTime: expect.any(Date),
    });
    expect(fetchBounded).toHaveBeenCalledTimes(2);

    response = canonicalBytes({});
    const invalidReader = registry.newReader(LR) as C2spTlogReader;
    await expect(invalidReader.verifyBilateralBinding(record, issuance.ek, issuance.ku)).rejects.toThrow('members');
    expect(fetchBounded).toHaveBeenCalledTimes(3);
  });

  it('binds bundle authorization to the proofed readEvent entry', async () => {
    const value = fixture();
    const proofedObject = JSON.parse(ISSUANCE_ENTRY) as Record<string, unknown>;
    proofedObject.ts = (proofedObject.ts as number) - 1;
    const proofedEntry = canonicalBytes(proofedObject);
    const checkpoint = parseCheckpoint(new TextDecoder().decode(value.checkpoint([proofedEntry])));
    const reader = new C2spTlogReader(LR, {
      policy: parseC2spPolicyFile(new TextDecoder().decode(value.options.policyBytes)),
      entityKey: value.options.entityKey,
      streamSource: { load: async () => ({ checkpoint, entries: [{ index: 0, bytes: proofedEntry }], complete: false }) },
      proofs: { '0': { index: 0, hashes: [], checkpoint } },
      resourceFetcher: {
        fetchBounded: async () => value.bytes,
        securityGuarantees: requiredC2spResourceFetchGuarantees,
      },
      streamBundle: {
        policyDocument: value.options.policyBytes,
        bundleKeys: value.options.bundleKeys,
        maxBundleLifetimeMs: value.options.maxBundleLifetimeMs,
        checkpointFreshnessMs: value.options.checkpointFreshnessMs,
      },
    });

    await expect(reader.readEvent(`${LR}@0`)).rejects.toThrow('not authorized by its lifecycle history');
  });

  it.each([404, 599])('falls back to the bounded raw scanner for status %i', async (status) => {
    const value = fixture();
    const endpoint = 'https://log.example/dnsid/streams/agent.example?format=bundle';
    const entryBytes = new TextEncoder().encode(ISSUANCE_ENTRY);
    const rawBundle = encodeEntryBundle([entryBytes]);
    const fetchBounded = vi.fn(async (url: string) => {
      if (url === endpoint) throw new C2spTlogError('unavailable', { status });
      if (url === checkpointPath('https://log.example/dnsid')) return new Uint8Array(Buffer.from(value.object.checkpoint as string, 'base64url'));
      if (url === entryBundlePath('https://log.example/dnsid', 0, 1)) return rawBundle;
      throw new Error(`unexpected URL ${url}`);
    });
    const registry = await createC2spTlogVerificationRegistry({
      trustProfile: trustProfile(value),
      resourceFetcher: { fetchBounded, securityGuarantees: requiredC2spResourceFetchGuarantees },
      checkpointMaxAge: 60_000,
      maxBundleLifetimeMs: 60_000,
    });
    const issuance = JSON.parse(ISSUANCE_ENTRY) as { ek: DnsIdJWK; gi: string; ku: DnsIdJWK };
    const reader = registry.newReader(LR) as C2spTlogReader;

    await expect(reader.verifyBilateralBinding({ agentFQDN: 'agent.example', gi: issuance.gi }, issuance.ek, issuance.ku)).resolves.toBeDefined();
    expect(fetchBounded.mock.calls.map(([url]) => url)).toEqual([
      endpoint,
      checkpointPath('https://log.example/dnsid'),
      entryBundlePath('https://log.example/dnsid', 0, 1),
    ]);

    fetchBounded.mockClear();
    const requiredRegistry = await createC2spTlogVerificationRegistry({
      trustProfile: trustProfile(value),
      resourceFetcher: { fetchBounded, securityGuarantees: requiredC2spResourceFetchGuarantees },
      checkpointMaxAge: 60_000,
      maxBundleLifetimeMs: 60_000,
      requireStreamBundle: true,
    });
    await expect((requiredRegistry.newReader(LR) as C2spTlogReader)
      .verifyBilateralBinding({ agentFQDN: 'agent.example', gi: issuance.gi }, issuance.ek, issuance.ku))
      .rejects.toThrow('unavailable');
    expect(fetchBounded).toHaveBeenCalledOnce();
  });

  it('fails closed instead of falling back for status 600', async () => {
    const value = fixture();
    const fetchImpl = vi.fn(async () => ({
      body: null,
      headers: new Headers(),
      redirected: false,
      status: 600,
    }) as Response);
    const registry = await createC2spTlogVerificationRegistry({
      trustProfile: trustProfile(value),
      resourceFetcher: createFetchBackedC2spResourceFetcher(fetchImpl, requiredC2spResourceFetchGuarantees()),
      checkpointMaxAge: 60_000,
      maxBundleLifetimeMs: 60_000,
    });
    const issuance = JSON.parse(ISSUANCE_ENTRY) as { ek: DnsIdJWK; gi: string; ku: DnsIdJWK };

    await expect((registry.newReader(LR) as C2spTlogReader)
      .verifyBilateralBinding({ agentFQDN: 'agent.example', gi: issuance.gi }, issuance.ek, issuance.ku))
      .rejects.toMatchObject({ status: 600, transient: false });
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it('uses a matching complete scan as missing bundle consistency evidence', async () => {
    const entry = new TextEncoder().encode(ISSUANCE_ENTRY);
    const value = await missingConsistencyReader([entry, BUNDLE_EXTRA_ENTRY]);

    await expect(value.verify()).resolves.toBeDefined();
    expect(value.fetchBounded.mock.calls.map(([url]) => url)).toEqual([
      'https://log.example/dnsid/streams/agent.example?format=bundle',
      checkpointPath('https://log.example/dnsid'),
      entryBundlePath('https://log.example/dnsid', 0, 2),
    ]);
    await expect(value.store.load(ORIGIN)).resolves.toMatchObject({ treeSize: 2 });
  });

  it('accepts a newer raw scan only when its bundle-size prefix matches', async () => {
    const value = await missingConsistencyReader([
      new TextEncoder().encode(ISSUANCE_ENTRY),
      BUNDLE_EXTRA_ENTRY,
      new TextEncoder().encode('newer unrelated log entry'),
    ]);

    await expect(value.verify()).resolves.toBeDefined();
    await expect(value.store.load(ORIGIN)).resolves.toMatchObject({ treeSize: 2 });
  });

  it.each([
    ['conflicting bundle prefix', [new TextEncoder().encode(ISSUANCE_ENTRY), new TextEncoder().encode('conflict')], 'candidate checkpoint'],
    ['raw scan shorter than bundle', [new TextEncoder().encode(ISSUANCE_ENTRY)], 'candidate checkpoint prefix'],
  ])('rejects missing-consistency fallback with a %s', async (_name, entries, message) => {
    const value = await missingConsistencyReader(entries);

    await expect(value.verify()).rejects.toThrow(message);
    await expect(value.store.load(ORIGIN)).resolves.toMatchObject({ treeSize: 1 });
  });

  it('does not raw scan for missing consistency evidence when bundles are required', async () => {
    const value = await missingConsistencyReader([new TextEncoder().encode(ISSUANCE_ENTRY), BUNDLE_EXTRA_ENTRY], true);

    await expect(value.verify()).rejects.toThrow('requires consistency proof');
    expect(value.fetchBounded).toHaveBeenCalledOnce();
    await expect(value.store.load(ORIGIN)).resolves.toMatchObject({ treeSize: 1 });
  });

  it('allows historical bundle verification without enabling fresh non-revocation', async () => {
    const value = fixture();
    const registry = await createC2spTlogVerificationRegistry({
      trustProfile: trustProfile(value),
      resourceFetcher: {
        fetchBounded: async () => value.bytes,
        securityGuarantees: requiredC2spResourceFetchGuarantees,
      },
      maxBundleLifetimeMs: 60_000,
    });
    const reader = registry.newReader(LR) as C2spTlogReader;
    await expect(reader.verifyNonRevocation('agent.example', new Date()))
      .rejects.toThrow('checkpointMaxAge');
  });

  it('rejects event bounds and malformed inclusion proofs before verification', async () => {
    const value = fixture();
    value.object.events = [
      { index: 0, entry: Buffer.from(ISSUANCE_ENTRY).toString('base64url'), proof: '' },
      { index: 0, entry: Buffer.from(ISSUANCE_ENTRY).toString('base64url'), proof: '' },
    ];
    expect(() => parseC2spStreamBundle(canonicalBytes(value.object), value.options)).toThrow('strictly increasing');

    const malformed = fixture();
    (malformed.object.events as Array<Record<string, unknown>>)[0]!.proof = Buffer.alloc(31).toString('base64url');
    expect(() => parseC2spStreamBundle(canonicalBytes(malformed.object), malformed.options)).toThrow('SHA-256 nodes');

    const bounded = fixture();
    bounded.options.maxEvents = 0;
    expect(() => parseC2spStreamBundle(bounded.bytes, bounded.options)).toThrow('positive integer');

    const oversizedTree = fixture(BUNDLE_EXTRA_ENTRY);
    oversizedTree.options.maxTreeSize = 1;
    await expect(verifyC2spStreamBundle(oversizedTree.bytes, oversizedTree.options))
      .rejects.toThrow('tree-size maximum');
  });
});
