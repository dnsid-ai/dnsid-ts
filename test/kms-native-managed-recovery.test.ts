import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { CreateKeyCommand, GetPublicKeyCommand, KMSClient, SignCommand } from '@aws-sdk/client-kms';
import { AwsKmsKeyProvider, AwsSdkKmsFacade, type AwsKmsKeyState } from '@dnsid-ai/key-aws';
import { GcpCloudKmsKeyProvider, type GcpCloudKmsConfig } from '@dnsid-ai/key-gcp';
import { DNSSECState, DnsIdTxtRecord, jwkThumbprint, type DnsIdJWK, type KeyProvider } from '@dnsid-ai/protocol';
import { RegistryClient } from '@dnsid-ai/registry';
import { ManagedKeyRotationActivationError, rotateManagedOperationalKey, resumeManagedOperationalKeyRotation, type ManagedKeyRotationResult } from '@dnsid-ai/sdk';
import { createNodeIdentityManager } from '@dnsid-ai/sdk/node';
import { canonicalBytes, c2spEventId, signedC2spEntryBytes, stateHash, prepareC2spTlogEventForSigning, checkpointPath, entryBundlePath, encodeEntryBundle, merkleRootFromEntries, createC2spTlogVerificationRegistry, requiredC2spResourceFetchGuarantees } from '@dnsid-ai/log-c2sp-tlog';
import { it, vi } from 'vitest';

// Provisional deterministic composed proof: shared design 01/12, native plan N1–N4.
// Only vendor RPC and external DNS/HTTPS/registry/log bytes are simulated.
// No own provider/manager/orchestrator/reader verdicts are replaced.
const DOMAIN = 'agent.example.com';
const PREFIX = 'https://log.example/tlog';
const ORIGIN = 'log.example/tlog';
const LR = `c2sp-tlog:testnet:${PREFIX}#fixture-stream`;
const privateKey = (seed: number) => createPrivateKey({ key: Buffer.concat([
  Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seed),
]), format: 'der', type: 'pkcs8' });
const secretA = privateKey(1), secretB = privateKey(2), entitySecret = privateKey(3);
const publicJwk = (secret: ReturnType<typeof privateKey>, kid: string) => ({
  ...createPublicKey(secret).export({ format: 'jwk' }), kid, alg: 'EdDSA', use: 'sig',
}) as DnsIdJWK;
const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
function crc(bytes: Uint8Array) {
  let c = 0xffffffff;
  for (const b of bytes) { c ^= b; for (let i = 0; i < 8; i++) c = (c >>> 1) ^ ((c & 1) ? 0x82f63b78 : 0); }
  return (c ^ 0xffffffff) >>> 0;
}
async function native(vendor: 'AWS' | 'GCP', pendingFault?: 'name' | 'crc') {
  let creates = 0;
  const a = vendor === 'AWS' ? 'arn:aws:kms:us-east-1:111122223333:key/11111111-1111-4111-8111-111111111111' : 'projects/test/locations/global/keyRings/agents/cryptoKeys/signer/cryptoKeyVersions/7';
  const b = vendor === 'AWS' ? a.replaceAll('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222') : a.replace('/7', '/8');
  const secret = (ref: string) => { assert([a, b].includes(ref)); return ref === a ? secretA : secretB; };
  const awsClient = vendor === 'AWS' ? new KMSClient({ region: 'us-east-1' }) : undefined;
  const rpc = vendor === 'AWS' ? vi.spyOn(awsClient!, 'send').mockImplementation(async command => {
    if (command instanceof CreateKeyCommand) {
      assert.equal(command.input.KeySpec, 'ECC_NIST_EDWARDS25519'); creates++;
      return { KeyMetadata: { Arn: b } };
    }
    if (command instanceof GetPublicKeyCommand) return { KeyId: command.input.KeyId,
      PublicKey: createPublicKey(secret(command.input.KeyId!)).export({ type: 'spki', format: 'der' }),
      KeySpec: 'ECC_NIST_EDWARDS25519', KeyUsage: 'SIGN_VERIFY', SigningAlgorithms: ['ED25519_SHA_512'] };
    if (command instanceof SignCommand) {
      assert.equal(command.input.SigningAlgorithm, 'ED25519_SHA_512'); assert.equal(command.input.MessageType, 'RAW');
      return { KeyId: command.input.KeyId, SigningAlgorithm: 'ED25519_SHA_512', Signature: sign(null, command.input.Message!, secret(command.input.KeyId!)) };
    }
    assert.fail(`unexpected cloud mutation ${command.constructor.name}`);
  }) : undefined;
  const gcp = {
    getPublicKey: async ({ name }: { name: string }) => {
      const pem = createPublicKey(secret(name)).export({ type: 'spki', format: 'pem' }).toString();
      return [{ name: name === b && pendingFault === 'name' ? a : name, algorithm: 'EC_SIGN_ED25519', protectionLevel: 'SOFTWARE', pem,
        pemCrc32c: { value: crc(Buffer.from(pem)) + (name === b && pendingFault === 'crc' ? 1 : 0) } }];
    },
    createCryptoKeyVersion: async ({ parent }: { parent: string }) => {
      assert.equal(parent, a.split('/cryptoKeyVersions/')[0]); creates++;
      return [{ name: b, algorithm: 'EC_SIGN_ED25519', state: 'ENABLED', protectionLevel: 'SOFTWARE' }];
    },
    asymmetricSign: async ({ name, data, dataCrc32c }: { name: string; data: Uint8Array; dataCrc32c?: { value?: unknown } }) => {
      assert.equal(Number(dataCrc32c?.value), crc(data));
      const signature = sign(null, data, secret(name));
      return [{ name, signature, signatureCrc32c: { value: crc(signature) }, verifiedDataCrc32c: true }];
    },
  };
  const open = (ref = a, snapshot?: AwsKmsKeyState, pendingKeyVersion?: string): Promise<KeyProvider> => {
    if (vendor === 'AWS') return AwsKmsKeyProvider.load(new AwsSdkKmsFacade(awsClient!), { state: snapshot ?? { activeKeyId: ref }, algorithm: 'ED25519_SHA_512' });
    const config: GcpCloudKmsConfig = { activeKeyVersion: ref, algorithm: 'EC_SIGN_ED25519',
      ...(pendingKeyVersion === undefined ? {} : { pendingKeyVersion }) };
    return GcpCloudKmsKeyProvider.load(gcp, config);
  };
  try { return { provider: await open(), open, a, b, creates: () => creates,
    close: () => { rpc?.mockRestore(); awsClient?.destroy(); } }; }
  catch (error) { rpc?.mockRestore(); awsClient?.destroy(); throw error; }
}

async function publication(old: DnsIdJWK) {
  const entity = publicJwk(entitySecret, 'entity');
  const record = new DnsIdTxtRecord();
  Object.assign(record, { v: 'dnsid-draft-01', gi: 'example.com', agentFQDN: DOMAIN,
    ek: 'https://example.com/entity.jwks', ku: `https://${DOMAIN}/operational.jwks`,
    lr: LR, su: `https://${DOMAIN}/status` });
  record.sg = sign(null, Buffer.from(record.canonical()), entitySecret).toString('base64url');
  const second = Math.floor(Date.now() / 1000);
  const payload = { v: 1, kind: 'dnsid.lifecycle', type: 'ISSUANCE', method: 'c2sp-tlog',
    log_origin: ORIGIN, stream_id: 'fixture-stream', lr: LR, seq: 0, fqdn: DOMAIN,
    gi: 'example.com', ts: second, ek: entity, ku: old };
  const signed = canonicalBytes(payload);
  const issuance = canonicalBytes({ ...payload, sigs: {
    ae: { kid: entity.kid, sig: sign(null, signed, entitySecret).toString('base64url') },
    op: { kid: old.kid, sig: sign(null, signed, secretA).toString('base64url') },
  } });
  const predecessor = c2spEventId(signedC2spEntryBytes(issuance));
  const priorState = stateHash({ fqdn: DOMAIN, status: 'ACTIVE', entity_thumb: await jwkThumbprint(entity), operational_thumb: await jwkThumbprint(old) });
  const note = (name: string, type: number, seed: number) => {
    const key = privateKey(seed);
    const typed = Buffer.concat([Buffer.from([type]), Buffer.from(createPublicKey(key).export({ format: 'jwk' }).x!, 'base64url')]);
    const id = createHash('sha256').update(name).update('\n').update(typed).digest().subarray(0, 4);
    return { key, id, text: `${name}+${id.toString('hex')}+${typed.toString('base64')}` };
  };
  const log = note(ORIGIN, 1, 4), witness = note('witness.example', 4, 5);
  let published = old;
  let entries = [issuance];
  let reads = 0;
  let forbidden = false;
  const cert = { notAfter: new Date('2099-01-01'), san: [DOMAIN, 'example.com'] };
  const touched = () => { assert(!forbidden, 'terminal restore attempted publication I/O'); reads++; };
  async function manager(provider: KeyProvider) {
    // Every manager gets a fresh real reader: no fabricated checkpoint-growth proof.
    const logRegistry = await createC2spTlogVerificationRegistry({
      policyDocument: Buffer.from(`log ${log.text}\nwitness W ${witness.text}\nquorum W\n`), checkpointMaxAge: 60_000,
      resourceFetcher: { securityGuarantees: requiredC2spResourceFetchGuarantees,
        fetchBounded: async (url, maximum) => {
          touched();
          const body = `${ORIGIN}\n${entries.length}\n${Buffer.from(merkleRootFromEntries(entries)).toString('base64')}\n`;
          const timestamp = Buffer.alloc(8); timestamp.writeBigUInt64BE(BigInt(second));
          const checkpoint = Buffer.from(`${body}\n— ${ORIGIN} ${Buffer.concat([log.id, sign(null, Buffer.from(body), log.key)]).toString('base64')}\n— witness.example ${Buffer.concat([witness.id, timestamp, sign(null, Buffer.from(`cosignature/v1\ntime ${second}\n${body}`), witness.key)]).toString('base64')}\n`);
          const resources = new Map([[checkpointPath(PREFIX), checkpoint], [entryBundlePath(PREFIX, 0, entries.length), encodeEntryBundle(entries)]]);
          const bytes = resources.get(url); assert(bytes, `unexpected resource ${url}`); assert(bytes.length <= maximum); return bytes;
        } },
    });
    return createNodeIdentityManager({ identity: { domain: DOMAIN, governanceId: 'example.com', logRef: LR, statusUrl: record.su, ekUrl: record.ek, kuUrl: record.ku } }, {
      keyProvider: provider, logRegistry,
      dnsResolver: { fetchTXT: async () => { touched(); return [[{ strings: [record.serialize()], ttl: 300 }], DNSSECState.UNSIGNED]; } },
      fetchJson: async url => {
        touched();
        if (url === record.ek) return { data: { keys: [entity] }, tlsCert: cert };
        if (url === record.ku) return { data: { keys: [published] }, tlsCert: cert };
        assert.equal(url, record.su); return { data: { state: 'ACTIVE', lastTransitionAt: new Date().toISOString() }, tlsCert: cert };
      },
    });
  }
  return { record, manager, reads: () => reads, forbid: () => { forbidden = true; },
    publish: (key: DnsIdJWK) => { published = key; }, current: () => published,
    accept: (entry: Uint8Array) => { entries = [issuance, entry.slice()]; },
    prepare: async (next: DnsIdJWK) => canonicalBytes(prepareC2spTlogEventForSigning({
      type: 'KEY_ROTATION', domain: DOMAIN, previousOperationalKid: old.kid,
      previousOperationalThumbprint: await jwkThumbprint(old), newOperationalKid: next.kid,
      newOperationalAlg: 'EdDSA', newOperationalPublicKey: next,
      newOperationalThumbprint: await jwkThumbprint(next), timestamp: new Date(),
    }, LR, { sequence: 1, previousEventId: predecessor, previousStateHash: priorState }).envelope),
  };
}

for (const vendor of ['AWS', 'GCP'] as const) {
  for (const mode of ['N1 completion', 'N2 activated crash', 'N3 saved binding rejection', ...(vendor === 'AWS' ? ['N4 saved pending', 'N4 retained boundary'] : ['N5 saved pending', 'N5 wrong B binding'])]) {
    it(`${vendor} native ${mode}`, async () => {
      vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime(new Date('2026-10-27T12:00:00Z'));
      let cloud: Awaited<ReturnType<typeof native>> | undefined;
      try {
        cloud = await native(vendor);
        let provider = cloud.provider;
        const old = await provider.signingKey();
        const fixture = await publication(old);
        const config = { selectedReference: cloud.a }; const configBefore = JSON.stringify(config);
        let appManager = await fixture.manager(provider);
        const verifyManager = await fixture.manager(provider);
        let paused = false, wired = false;
        let durable: ManagedKeyRotationResult | undefined;
        let durableProvider: AwsKmsKeyState | undefined;
        const events: string[] = [];
        const message = Buffer.from('native composed application signature');
        const applicationSign = async () => { assert(!paused, 'application signing paused'); return appManager.getKeyProvider()!.sign(message); };
        let submitted: Uint8Array | undefined;
        let preparedKey: DnsIdJWK | undefined;
        let submissions = 0, preparations = 0, accepted = false, terminal = false;
        const registry = new RegistryClient({ baseUrl: 'https://registry.example', fetch: async (url, init) => {
          assert(!terminal, 'terminal restore attempted registry I/O');
          assert.equal(init?.method, 'POST');
          assert.equal(new Headers(init?.headers).get('Idempotency-Key'), 'native-recovery');
          if (String(url).endsWith('/prepare')) {
            preparations++;
            const request = JSON.parse(String(init?.body)); preparedKey = request.public_key;
            assert.equal(request.previous_key_id, await jwkThumbprint(old));
            assert.deepEqual(await provider.signingKey(), old);
            assert.equal(JSON.stringify(config), configBefore);
            assert.equal(cloud!.creates(), 1);
            assert(verify(null, message, createPublicKey(secretB), await provider.signKey(preparedKey!.kid, message)));
            assert(verify(null, message, createPublicKey(secretA), await provider.sign(message)));
            const prepared = await fixture.prepare(preparedKey!);
            return new Response(new Uint8Array(prepared).buffer);
          }
          assert(String(url).endsWith('/tlog/events'));
          submissions++;
          const bytes = new Uint8Array(init!.body as ArrayBuffer);
          if (submitted) assert.deepEqual(bytes, submitted); else submitted = bytes.slice();
          assert(paused); assert(durable); assert.deepEqual(durable.entryBytes, bytes);
          fixture.publish(preparedKey!);
          assert.equal(fixture.current().kid, preparedKey!.kid);
          assert.deepEqual(await provider.signingKey(), old);
          await assert.rejects(applicationSign, /paused/);
          if (accepted) fixture.accept(bytes);
          return Response.json({ state: accepted ? 'accepted' : 'pending', entry_hash: hash(bytes),
            ...(accepted ? { index: 1, lr: `${LR}@1`, key_id: preparedKey!.kid } : {}) });
        } });
        let crash = mode === 'N2 activated crash' || mode === 'N3 saved binding rejection';
        const coordination = {
          previousProviderReference: 'saved-native-state', newProviderReference: 'saved-native-state', identityManager: verifyManager,
          persistRotation: async (rotation: ManagedKeyRotationResult) => {
            durable = structuredClone(rotation);
            if (provider instanceof AwsKmsKeyProvider) durableProvider = structuredClone(provider.stateSnapshot());
            events.push(rotation.activated ? 'durable-activated' : 'durable-pending');
          },
          setApplicationSigningPaused: async (value: boolean) => {
            if (!value) assert(wired, 'must wire accepted signer before unpause');
            paused = value; events.push(value ? 'pause' : 'unpause');
          },
          setApplicationSigner: async (selected: KeyProvider, kid: string) => {
            assert(durable?.activated); assert(paused); assert.equal((await selected.signingKey()).kid, kid);
            if (crash) { crash = false; throw new Error('app crash before signer wiring'); }
            appManager = await fixture.manager(selected); wired = true; events.push('wire');
          },
        };
        const pending = await rotateManagedOperationalKey({ domain: DOMAIN, logReference: LR, keyProvider: provider,
          registryClient: registry, idempotencyKey: 'native-recovery', ...coordination });
        assert.equal(pending.activated, false); assert(paused); assert.equal(submissions, 1);
        assert.deepEqual(await provider.signingKey(), old); assert.equal(JSON.stringify(config), configBefore);
        accepted = true;
        let resumeRecord = pending;
        let resolutions = 0;
        if (mode.startsWith('N5')) {
          // Given a real pending record, application storage owns both immutable refs.
          // Cloned callbacks model application persistence, not filesystem durability.
          assert(durable); assert.equal(durable.activated, false);
          assert.equal(durable.applicationSigningPaused, true);
          const appSaved = structuredClone({ activeKeyVersion: cloud.a,
            pendingKeyVersion: cloud.b, rotation: durable });
          assert.equal(appSaved.rotation.submission?.state, 'pending');
          assert.equal(appSaved.rotation.previousProviderReference, appSaved.rotation.newProviderReference);
          assert.deepEqual(appSaved.rotation.entryBytes, submitted);
          const savedHash = hash(appSaved.rotation.entryBytes);
          // When reopened through the public open-only A-active/B-pending surface.
          provider = await cloud.open(appSaved.activeKeyVersion, undefined, appSaved.pendingKeyVersion);
          coordination.identityManager = await fixture.manager(provider);
          assert.deepEqual(await provider.signingKey(), old);
          assert.deepEqual(await provider.listKeyIds(), [old.kid]);
          assert(verify(null, message, createPublicKey(secretA), await provider.sign(message)));
          let reopenedB: DnsIdJWK | undefined;
          let lookupFailure: unknown;
          try { reopenedB = await provider.jwk(appSaved.rotation.newKid); }
          catch (error) { lookupFailure = error; }
          assert.equal(lookupFailure, undefined, 'saved pending B must be accessible for proof without becoming the active signer');
          assert.deepEqual(reopenedB, preparedKey);
          assert(verify(null, message, createPublicKey(secretB), await provider.signKey(appSaved.rotation.newKid, message)));
          assert.equal(cloud.creates(), 1); assert.equal(preparations, 1); assert.equal(submissions, 1);
          assert(paused); assert(!wired); assert(!events.includes('unpause'));
          resumeRecord = structuredClone(appSaved.rotation);
          assert.equal(hash(resumeRecord.entryBytes), savedHash);
          if (mode === 'N5 wrong B binding') resumeRecord = { ...resumeRecord, newThumbprint: 'wrong' };
        }
        if (mode.startsWith('N4')) {
          // App persists real accepted response and native eligibility, then loses all provider objects.
          const submission = await registry.submitPreparedEvent(DOMAIN, pending.entryBytes, pending.idempotencyKey);
          resumeRecord = { ...pending, submission };
          await coordination.persistRotation(resumeRecord);
          assert(provider instanceof AwsKmsKeyProvider);
          if (mode === 'N4 retained boundary') {
            await provider.activate(pending.newKid);
            // Characterization only: inherited AWS active+retained inventory is NOT active-only conformance.
            assert.deepEqual(await provider.listKeyIds(), [pending.newKid, old.kid]);
            durableProvider = structuredClone(provider.stateSnapshot());
          }
          provider = await cloud.open(cloud.a, structuredClone(durableProvider));
          if (mode === 'N4 saved pending') assert.deepEqual(await provider.signingKey(), old);
          else await assert.rejects(() => provider.signKey(old.kid, message));
          coordination.identityManager = await fixture.manager(provider);
        }
        const resume = () => resumeManagedOperationalKeyRotation({ rotation: resumeRecord, resolveKeyProvider: async reference => {
          resolutions++; assert.equal(reference, 'saved-native-state'); return provider;
        }, registryClient: registry, ...coordination });
        if (mode === 'N5 wrong B binding') {
          const beforeReads = fixture.reads();
          await assert.rejects(resume, error => error instanceof ManagedKeyRotationActivationError && error.cause instanceof Error && /key binding mismatch/.test(error.cause.message));
          assert.equal(resolutions, 1); assert(paused); assert(!wired);
          assert(!events.includes('unpause')); assert(!events.includes('durable-activated'));
          assert.deepEqual(await provider.signingKey(), old);
          assert.deepEqual(await provider.listKeyIds(), [old.kid]);
          assert.equal(fixture.reads(), beforeReads); assert.equal(submissions, 1);
          assert.equal(preparations, 1); assert.equal(cloud.creates(), 1);
          return;
        }
        if (mode === 'N2 activated crash' || mode === 'N3 saved binding rejection') {
          await assert.rejects(resume, error => error instanceof ManagedKeyRotationActivationError && error.cause instanceof Error && error.cause.message === 'app crash before signer wiring');
          assert(durable?.activated); assert(durable.applicationSigningPaused); assert(paused); assert(!wired);
          resumeRecord = structuredClone(durable);
          provider = await cloud.open(cloud.b, durableProvider && structuredClone(durableProvider));
          // GCP reopen is sole already-reconciled B, NOT restoration of its unavailable multi-key map.
          coordination.identityManager = await fixture.manager(provider);
          terminal = true; fixture.forbid();
          const beforeReads = fixture.reads();
          if (mode === 'N3 saved binding rejection') {
            resumeRecord = { ...resumeRecord, newThumbprint: 'wrong' };
            await assert.rejects(resume, error => error instanceof ManagedKeyRotationActivationError && error.cause instanceof Error && /key binding mismatch/.test(error.cause.message));
            assert(paused); assert(!wired); assert(!events.includes('unpause'));
            assert.equal(fixture.reads(), beforeReads); assert.equal(submissions, 2); assert.equal(cloud.creates(), 1);
            return;
          }
          await resume(); assert.equal(fixture.reads(), beforeReads);
        } else await resume();
        if (mode === 'N5 saved pending') assert.equal(resolutions, 1, 'equal opaque refs resolve the application-saved A/B provider once');
        assert.equal((await provider.signingKey()).kid, pending.newKid);
        assert.deepEqual(await provider.listKeyIds(), [pending.newKid]);
        assert.equal((await appManager.getKeySet()).currentOperationalSigningKey().kid, pending.newKid);
        const signature = await applicationSign();
        assert(verify(null, message, createPublicKey(secretB), signature));
        assert(!verify(null, message, createPublicKey(secretA), signature));
        await assert.rejects(() => provider.signKey(old.kid, message));
        assert.equal(cloud.creates(), 1); assert.equal(preparations, 1); assert.equal(submissions, 2);
        assert.equal(JSON.stringify(config), configBefore);
        assert(events.indexOf('durable-activated') < events.indexOf('wire'));
        assert(events.indexOf('wire') < events.indexOf('unpause'));
        assert.equal(durable?.applicationSigningPaused, false);
        assert(fixture.reads() > 0, 'real external publication/log bytes must have been read');
      } finally { cloud?.close(); vi.useRealTimers(); }
    });
  }
}

// Shared 12 saved-eligibility row + agreed pendingKeyVersion realization. Mode: fake-only.
for (const fault of ['name', 'crc'] as const) {
  it(`GCP pending load rejects invalid B public response (${fault}) without changing ordinary A-only startup`, async () => {
    const cloud = await native('GCP', fault);
    try {
      // Given A opens normally, When B metadata is invalid, Then fail closed.
      const old = await cloud.provider.signingKey();
      await assert.rejects(() => cloud.open(cloud.a, undefined, cloud.b));
      const ordinary = await cloud.open(cloud.a);
      assert.deepEqual(await ordinary.signingKey(), old);
      assert.deepEqual(await ordinary.listKeyIds(), [old.kid]);
      const message = Buffer.from('ordinary A-only startup');
      assert(verify(null, message, createPublicKey(secretA), await ordinary.sign(message)));
      assert.deepEqual(await cloud.provider.signingKey(), old);
      assert.equal(cloud.creates(), 0, 'load must never generate a replacement');
    } finally { cloud.close(); }
  });
}

// README saved A-active/B-pending duplicate rejection. Mode: fake-only.
it('GCP pending load rejects identical immutable versions before any RPC', async () => {
  // Given the application saved the same immutable reference for A and B.
  const a = 'projects/test/locations/global/keyRings/agents/cryptoKeys/signer/cryptoKeyVersions/7';
  const gcp = {
    getPublicKey: vi.fn(async () => { assert.fail('unexpected public-key RPC'); }),
    createCryptoKeyVersion: vi.fn(async () => { assert.fail('unexpected version creation'); }),
    asymmetricSign: vi.fn(async () => { assert.fail('unexpected signing RPC'); }),
  };
  // When loaded, Then reject the duplicate reference before any vendor RPC.
  await assert.rejects(() => GcpCloudKmsKeyProvider.load(gcp, {
    activeKeyVersion: a, pendingKeyVersion: a, algorithm: 'EC_SIGN_ED25519',
  }), { message: 'Google Cloud KMS active and pending versions must differ' });
  assert.equal(gcp.getPublicKey.mock.calls.length, 0);
  assert.equal(gcp.createCryptoKeyVersion.mock.calls.length, 0);
  assert.equal(gcp.asymmetricSign.mock.calls.length, 0);
});

// README saved A-active/B-pending duplicate rejection. Mode: fake-only.
it('GCP pending load rejects distinct versions with the same public key', async () => {
  // Given distinct immutable A/B references with valid metadata and identical A PEM.
  const a = 'projects/test/locations/global/keyRings/agents/cryptoKeys/signer/cryptoKeyVersions/7';
  const b = a.replace('/7', '/8');
  const pem = createPublicKey(secretA).export({ type: 'spki', format: 'pem' }).toString();
  const gcp = {
    getPublicKey: vi.fn(async ({ name }: { name: string }) => {
      assert([a, b].includes(name));
      return [{ name, algorithm: 'EC_SIGN_ED25519', protectionLevel: 'SOFTWARE', pem,
        pemCrc32c: { value: crc(Buffer.from(pem)) } }];
    }),
    createCryptoKeyVersion: vi.fn(async () => { assert.fail('unexpected version creation'); }),
    asymmetricSign: vi.fn(async () => { assert.fail('unexpected signing RPC'); }),
  };
  // When loaded, Then reject B's duplicate public identity, not its valid binding.
  await assert.rejects(() => GcpCloudKmsKeyProvider.load(gcp, {
    activeKeyVersion: a, pendingKeyVersion: b, algorithm: 'EC_SIGN_ED25519',
  }), { message: 'Google Cloud KMS pending version has duplicate public key' });
  assert.deepEqual(gcp.getPublicKey.mock.calls.map(([request]) => request.name), [a, b]);
  assert.equal(gcp.createCryptoKeyVersion.mock.calls.length, 0);
  assert.equal(gcp.asymmetricSign.mock.calls.length, 0);
});
