import { describe, expect, it } from 'vitest';
import { DomainLog, jwkThumbprint, toArrayBuffer, type DnsIdJWK, type KeyProvider, type LogEvent } from '@dnsid-ai/protocol';
import {
  C2spTlogVerificationError,
  c2spEnvelopeToEvent,
  c2spEventId,
  c2spTlogEntryBytes,
  canonicalizeC2spEvent,
  eventToC2spEnvelope,
  parseC2spEventEntry,
  parseC2spSignatures,
  parsePreparedC2spTlogEvent,
  prepareC2spTlogEventForSigning,
  requiredC2spSignatureNames,
  signedC2spEntryBytes,
  signPreparedC2spTlogEvent,
  stateHash,
  stitchVerifiedMigrationHistory,
  verifyLifecycle,
  verifyStreamLifecycle,
} from '@dnsid-ai/log-c2sp-tlog';
import { LifecycleStreamBuilder, testKey, type TestKey } from './helpers/entity-rotation-stream.ts';

const STREAM_ID = 'ERERERERERERERERERERER';
const CONTEXT = { scope: 'testnet', logOrigin: 'log.example/dnsid', streamId: STREAM_ID, lr: `c2sp-tlog:testnet:https://log.example/dnsid#${STREAM_ID}` };
const FQDN = 'agent.example.com';
const CHECKPOINT_TIME = 1_000_000;

function indexed(entries: Uint8Array[]) {
  return entries.map((bytes, index) => ({ index, bytes }));
}

function verifyStream(entries: Uint8Array[], signerKey?: TestKey) {
  return verifyStreamLifecycle(indexed(entries), FQDN, { ...CONTEXT, signerKey: signerKey?.publicJwk, checkpointIntegrationTimeMs: CHECKPOINT_TIME });
}

async function keys() {
  return { e1: await testKey('entity-1'), e2: await testKey('entity-2'), e3: await testKey('entity-3'), o1: await testKey('op-1'), o2: await testKey('op-2'), o3: await testKey('op-3'), x: await testKey('attacker') };
}

function signingProvider(key: TestKey): KeyProvider {
  const sign = async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, toArrayBuffer(bytes)));
  return {
    signingKey: async () => key.publicJwk,
    jwk: async (kid) => { if (kid !== key.publicJwk.kid) throw new Error('key not found'); return key.publicJwk; },
    listKeyIds: async () => [key.publicJwk.kid],
    sign,
    signKey: async (kid, bytes) => { if (kid !== key.publicJwk.kid) throw new Error('key not found'); return sign(bytes); },
    generateKey: async () => { throw new Error('not implemented'); },
    activate: async () => { throw new Error('not implemented'); },
    supersede: async () => { throw new Error('not implemented'); },
  };
}

async function rotationEvent(from: TestKey, to: TestKey): Promise<Extract<LogEvent, { type: 'ENTITY_KEY_ROTATION' }>> {
  return {
    type: 'ENTITY_KEY_ROTATION', domain: FQDN, timestamp: new Date(5000),
    previousEntityKid: from.publicJwk.kid, previousEntityThumbprint: from.thumbprint,
    newEntityKid: to.publicJwk.kid, newEntityAlg: to.publicJwk.alg!, newEntityPublicKey: to.publicJwk, newEntityThumbprint: to.thumbprint,
  };
}

describe('ENTITY_KEY_ROTATION codec', () => {
  it('round-trips encode and decode with prev_ae/new_ae signatures', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    const bytes = await stream.entityKeyRotation(k.e2);
    const envelope = JSON.parse(new TextDecoder().decode(bytes));
    expect(envelope).toMatchObject({ type: 'ENTITY_KEY_ROTATION', prev_ek_thumb: k.e1.thumbprint, new_ek_thumb: k.e2.thumbprint, new_ek: k.e2.publicJwk });
    expect(Object.keys(envelope.sigs).sort()).toEqual(['new_ae', 'prev_ae']);
    const event = await parseC2spEventEntry(bytes, CONTEXT);
    expect(event).toMatchObject({
      type: 'ENTITY_KEY_ROTATION',
      previousEntityKid: k.e1.publicJwk.kid,
      previousEntityThumbprint: k.e1.thumbprint,
      newEntityKid: k.e2.publicJwk.kid,
      newEntityAlg: 'ES256',
      newEntityThumbprint: k.e2.thumbprint,
      newEntityPublicKey: k.e2.publicJwk,
      signingKid: k.e1.publicJwk.kid,
      sig: envelope.sigs.prev_ae.sig,
      newEntityProof: envelope.sigs.new_ae.sig,
    });
    const { seq, prev_event_id: prevEventId, prev_state_hash: prevStateHash } = event as unknown as Record<string, unknown>;
    expect(canonicalizeC2spEvent(event, { ...CONTEXT, seq: seq as number, prevEventId: prevEventId as string, prevStateHash: prevStateHash as string })).toEqual(bytes);
  });

  it('requires prev_ae then new_ae and rejects other roles', () => {
    expect(requiredC2spSignatureNames('ENTITY_KEY_ROTATION')).toEqual(['prev_ae', 'new_ae']);
    expect(() => parseC2spSignatures({ ae: { kid: 'a', sig: 'AA' } }, 'ENTITY_KEY_ROTATION')).toThrow('unexpected signature role: ae');
    expect(() => parseC2spSignatures({ prev_ae: { kid: 'a', sig: 'AA' } }, 'ENTITY_KEY_ROTATION')).toThrow('missing sigs.new_ae');
    expect(() => parseC2spSignatures({ prev_ae: { kid: 'a', sig: 'AA' }, new_ae: { kid: 'b', sig: 'AA' } }, 'KEY_ROTATION')).toThrow('unexpected signature role');
  });

  describe('structural validation (conformance 11)', () => {
    const cases: Array<[string, (envelope: Record<string, unknown>, k: Awaited<ReturnType<typeof keys>>) => void, string]> = [
      ['new_ek_thumb does not match new_ek', (envelope, k) => { envelope.new_ek_thumb = k.e3.thumbprint; }, 'new_ek_thumb does not match new_ek'],
      ['new_ek carries private key material', (envelope) => { envelope.new_ek = { ...(envelope.new_ek as object), d: 'AAAA' }; }, 'only public key material'],
      ['new_ek carries a non-EC private member', (envelope) => { envelope.new_ek = { ...(envelope.new_ek as object), p: 'AAAA' }; }, 'only public key material'],
      ['new_ek is missing kid', (envelope) => { const { kid: _kid, ...key } = envelope.new_ek as Record<string, unknown>; envelope.new_ek = key; }, 'new_ek.kid'],
      ['new_ek is missing alg', (envelope) => { const { alg: _alg, ...key } = envelope.new_ek as Record<string, unknown>; envelope.new_ek = key; }, 'new_ek.alg'],
      ['new_ek is not a signing key', (envelope) => { envelope.new_ek = { ...(envelope.new_ek as object), use: 'enc' }; }, 'must be a signing JWK'],
      ['new_ek has a truncated coordinate', (envelope) => { envelope.new_ek = { ...(envelope.new_ek as object), x: 'AAAA' }; }, '32-byte'],
      ['new_ek_thumb equals prev_ek_thumb', (envelope) => { envelope.prev_ek_thumb = envelope.new_ek_thumb; }, 'must differ from prev_ek_thumb'],
      ['prev_ek_thumb is missing', (envelope) => { delete envelope.prev_ek_thumb; }, 'missing prev_ek_thumb'],
      ['new_ek_thumb is missing', (envelope) => { delete envelope.new_ek_thumb; }, 'missing new_ek_thumb'],
      ['new_ek is missing', (envelope) => { delete envelope.new_ek; }, 'missing new_ek'],
    ];
    it.each(cases)('rejects %s', async (_name, mutate, message) => {
      const k = await keys();
      const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
      await stream.issuance(k.e1, k.o1);
      const bytes = await stream.entityKeyRotation(k.e2, { mutate: envelope => mutate(envelope, k) });
      await expect(parseC2spEventEntry(bytes, CONTEXT)).rejects.toThrow(message);
    });

    it('rejects a new_ae kid that does not name new_ek', async () => {
      const k = await keys();
      const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
      await stream.issuance(k.e1, k.o1);
      const bytes = await stream.entityKeyRotation(k.e2, { next: { kid: 'other' } });
      await expect(parseC2spEventEntry(bytes, CONTEXT)).rejects.toThrow('new_ae kid does not match new_ek');
    });

    it('rejects invalid events on encode', async () => {
      const k = await keys();
      const event = await rotationEvent(k.e1, k.e2);
      expect(() => eventToC2spEnvelope({ ...event, previousEntityThumbprint: k.e2.thumbprint }, CONTEXT)).toThrow('must differ from prev_ek_thumb');
      expect(() => eventToC2spEnvelope({ ...event, newEntityPublicKey: { ...k.e2.publicJwk, d: 'AAAA' } as DnsIdJWK }, CONTEXT)).toThrow('only public key material');
      expect(() => eventToC2spEnvelope({ ...event, newEntityAlg: 'EdDSA' }, CONTEXT)).toThrow('metadata mismatch');
      expect(() => eventToC2spEnvelope({ ...event, newEntityKid: 'other' }, CONTEXT)).toThrow('metadata mismatch');
    });
  });
});

describe('ENTITY_KEY_ROTATION lifecycle conformance', () => {
  it('1: binds the rotated key and rejects the ISSUANCE key as record ek', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(k.e2);
    await expect(verifyStream(stream.entries, k.e2)).resolves.toHaveLength(2);
    await expect(verifyStream(stream.entries, k.e1)).rejects.toThrow(`c2sp-tlog current entity key does not match record ek for ${FQDN}`);
  });

  it('2: chains two rotations so the current key is E3', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(k.e2);
    await stream.entityKeyRotation(k.e3);
    const selected = await verifyStream(stream.entries, k.e3);
    expect(selected.map(item => item.event.type)).toEqual(['ISSUANCE', 'ENTITY_KEY_ROTATION', 'ENTITY_KEY_ROTATION']);
    const snapshot = new DomainLog(FQDN, selected.map(item => item.event)).snapshotAt(new Date(CHECKPOINT_TIME));
    expect(snapshot.entityKeyThumbprint).toBe(k.e3.thumbprint);
    expect(snapshot.entityKeyBoundAt).toEqual(selected[2]!.event.timestamp);
    expect(snapshot.keyBoundAt).toEqual(selected[0]!.event.timestamp);
    expect(new DomainLog(FQDN, selected.map(item => item.event)).snapshotAt(selected[1]!.event.timestamp).entityKeyThumbprint).toBe(k.e2.thumbprint);
    for (const stale of [k.e1, k.e2]) await expect(verifyStream(stream.entries, stale)).rejects.toThrow('current entity key does not match record ek');
  });

  it('3: skips a rotation whose prev_ae is signed by the wrong key', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(k.e2, { previous: { signer: k.x }, apply: false });
    await expect(verifyStream(stream.entries, k.e1)).resolves.toHaveLength(1);
    await expect(verifyStream(stream.entries, k.e2)).rejects.toThrow(C2spTlogVerificationError);
  });

  it.each(['signed by the wrong key', 'missing'])('4: skips a rotation whose new_ae is %s', async variant => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(k.e2, { next: variant === 'missing' ? { omit: true } : { signer: k.x }, apply: false });
    await expect(verifyStream(stream.entries, k.e1)).resolves.toHaveLength(1);
    await expect(verifyStream(stream.entries, k.e2)).rejects.toThrow(C2spTlogVerificationError);
  });

  it('5: prev_ek_thumb not the active key is a key-continuity error', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(k.e2, { previousThumbprint: k.x.thumbprint, apply: false });
    await expect(verifyStream(stream.entries, k.e1)).rejects.toMatchObject({
      errorCategory: 'KEY_CONTINUITY',
      message: 'authenticated ENTITY_KEY_ROTATION does not continue from the active entity key',
    });
    await expect(verifyStream(stream.entries)).rejects.toMatchObject({ errorCategory: 'KEY_CONTINUITY' });
    // Anchored on the new key, no genesis can reach it through a continuous rotation.
    await expect(verifyStream(stream.entries, k.e2)).rejects.toMatchObject({ errorCategory: 'GENESIS_REQUIRED' });
  });

  it('6: new_ek equal to the current operational key is a key-continuity error', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(k.o1, { apply: false });
    await expect(verifyStream(stream.entries, k.e1)).rejects.toMatchObject({
      errorCategory: 'KEY_CONTINUITY',
      message: 'authenticated ENTITY_KEY_ROTATION new key binding is invalid',
    });
  });

  it('7: REVOCATION after rotation is authorized by E2, not E1', async () => {
    const k = await keys();
    const accepted = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await accepted.issuance(k.e1, k.o1);
    await accepted.entityKeyRotation(k.e2);
    await accepted.revocation();
    const selected = await verifyStream(accepted.entries, k.e2);
    expect(selected.map(item => item.event.type)).toEqual(['ISSUANCE', 'ENTITY_KEY_ROTATION', 'REVOCATION']);

    const skipped = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await skipped.issuance(k.e1, k.o1);
    await skipped.entityKeyRotation(k.e2);
    await skipped.revocation({ signer: k.e1, apply: false });
    await expect(verifyStream(skipped.entries, k.e2)).resolves.toHaveLength(2);
  });

  it('8: KEY_ROTATION before and after an ENTITY_KEY_ROTATION keeps both continuities', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.keyRotation(k.o2);
    await stream.entityKeyRotation(k.e2);
    await stream.keyRotation(k.o3);
    const selected = await verifyStream(stream.entries, k.e2);
    expect(selected.map(item => item.event.type)).toEqual(['ISSUANCE', 'KEY_ROTATION', 'ENTITY_KEY_ROTATION', 'KEY_ROTATION']);
    const snapshot = new DomainLog(FQDN, selected.map(item => item.event)).snapshotAt(new Date(CHECKPOINT_TIME));
    expect(snapshot.activeKeyThumbprint).toBe(k.o3.thumbprint);
    expect(snapshot.entityKeyThumbprint).toBe(k.e2.thumbprint);
    expect(stream.currentState()).toEqual({ fqdn: FQDN, status: 'ACTIVE', entity_thumb: k.e2.thumbprint, operational_thumb: k.o3.thumbprint });
  });

  it('8b: KEY_ROTATION may not install the rotated entity key as the operational key', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(k.e2);
    await stream.keyRotation(k.e2, { apply: false });
    await expect(verifyStream(stream.entries, k.e2)).rejects.toMatchObject({ errorCategory: 'KEY_CONTINUITY' });
  });

  it('9: an ENTITY_KEY_ROTATION cannot start a stream', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1, { apply: true });
    const rotation = await stream.entityKeyRotation(k.e2);
    await expect(verifyStream([rotation], k.e2)).rejects.toMatchObject({ errorCategory: 'GENESIS_REQUIRED' });
    await expect(verifyStream([rotation])).rejects.toMatchObject({ errorCategory: 'GENESIS_REQUIRED' });
  });

  it('10: an ENTITY_KEY_ROTATION after RETIREMENT is a terminal-state error', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.retirement();
    await stream.entityKeyRotation(k.e2, { apply: false });
    await expect(verifyStream(stream.entries, k.e1)).rejects.toMatchObject({ errorCategory: 'TERMINAL_STATE' });
  });

  it.each([
    ['new_ek_thumb does not match new_ek', (envelope: Record<string, unknown>, k: Awaited<ReturnType<typeof keys>>) => { envelope.new_ek_thumb = k.e3.thumbprint; }],
    ['new_ek_thumb equals prev_ek_thumb', (envelope: Record<string, unknown>) => { envelope.new_ek_thumb = envelope.prev_ek_thumb; }],
  ])('11: an authenticated rotation whose %s is a fatal invalid payload', async (_name, mutate) => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(k.e2, { mutate: envelope => mutate(envelope, k), apply: false });
    await expect(verifyStream(stream.entries, k.e1)).rejects.toMatchObject({ errorCategory: 'INVALID_EVIDENCE', message: 'authenticated lifecycle candidate is malformed' });
  });

  it.each(['d', 'p'])('11: a rotation whose new_ek carries private member %s is skipped as unauthenticated', async member => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(k.e2, { mutate: envelope => { envelope.new_ek = { ...(envelope.new_ek as object), [member]: 'AAAA' }; }, apply: false });
    await expect(verifyStream(stream.entries, k.e1)).resolves.toHaveLength(1);
  });

  it.each([
    ['new_ek has no kid', { mutate: (envelope: Record<string, unknown>) => { const { kid: _kid, ...key } = envelope.new_ek as Record<string, unknown>; envelope.new_ek = key; } }],
    ['new_ek has an empty kid', { mutate: (envelope: Record<string, unknown>) => { envelope.new_ek = { ...(envelope.new_ek as object), kid: '' }; } }],
    ['new_ae names another kid', { next: { kid: 'other' } }],
  ])('a rotation where %s cannot authenticate and is skipped', async (_name, options) => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(k.e2, { ...options, apply: false });
    await expect(verifyStream(stream.entries, k.e1)).resolves.toHaveLength(1);
    await expect(verifyStream(stream.entries)).resolves.toHaveLength(1);
  });

  it('an authenticated rotation whose new_ek lacks alg is fatal', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(k.e2, { mutate: envelope => { const { alg: _alg, ...key } = envelope.new_ek as Record<string, unknown>; envelope.new_ek = key; }, apply: false });
    await expect(verifyStream(stream.entries, k.e1)).rejects.toMatchObject({ errorCategory: 'INVALID_EVIDENCE', message: 'authenticated lifecycle candidate is malformed' });
  });

  it('chains the lifecycle state hash through the rotated entity thumbprint', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(k.e2);
    const revocation = await stream.revocation();
    const envelope = JSON.parse(new TextDecoder().decode(revocation));
    expect(envelope.prev_state_hash).toBe(stateHash({ fqdn: FQDN, status: 'ACTIVE', entity_thumb: k.e2.thumbprint, operational_thumb: k.o1.thumbprint }));
    expect(envelope.prev_event_id).toBe(c2spEventId(signedC2spEntryBytes(stream.entries[1]!)));
  });

  it('verifyLifecycle anchors signerKey at the end of the given events', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(k.e2);
    const selected = await verifyStream(stream.entries, k.e2);
    await expect(verifyLifecycle(selected, { ...CONTEXT, signerKey: k.e2.publicJwk, checkpointIntegrationTimeMs: CHECKPOINT_TIME })).resolves.toBeUndefined();
    await expect(verifyLifecycle(selected, { ...CONTEXT, signerKey: k.e1.publicJwk, checkpointIntegrationTimeMs: CHECKPOINT_TIME })).rejects.toThrow('current entity key does not match record ek');
    await expect(verifyLifecycle(selected.slice(0, 1), { ...CONTEXT, signerKey: k.e2.publicJwk, checkpointIntegrationTimeMs: CHECKPOINT_TIME })).rejects.toThrow('ISSUANCE entity key does not match trusted entity key');
  });

  it('DomainLog rejects a rotation that does not continue from the active entity key', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    const issuance = await parseC2spEventEntry(stream.entries[0]!, CONTEXT);
    const rotation = await rotationEvent(k.x, k.e2);
    expect(() => new DomainLog(FQDN, [issuance, rotation]).snapshotAt(new Date(CHECKPOINT_TIME))).toThrow('does not continue from the active entity key');
    const toOperational = await rotationEvent(k.e1, k.o1);
    expect(() => new DomainLog(FQDN, [issuance, toOperational]).snapshotAt(new Date(CHECKPOINT_TIME))).toThrow('new key binding is invalid');
  });
});

describe('ENTITY_KEY_ROTATION key types, forks and migration', () => {
  it('rotates between ES256 and Ed25519 entity keys', async () => {
    const k = await keys();
    const ed = await testKey('entity-ed', 'EdDSA');
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(ed);
    await stream.entityKeyRotation(k.e3);
    await expect(verifyStream(stream.entries, k.e3)).resolves.toHaveLength(3);
    const edNew = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await edNew.issuance(k.e1, k.o1);
    await edNew.entityKeyRotation(ed, { mutate: envelope => { envelope.new_ek = { ...(envelope.new_ek as object), x: 'AAAA' }; }, apply: false });
    await expect(verifyStream(edNew.entries, k.e1)).resolves.toHaveLength(1);
  });

  it('rejects a fork signed by the superseded entity key from before the rotation', async () => {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    const fork = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await fork.issuance(k.e1, k.o1);
    await stream.entityKeyRotation(k.e2);
    await fork.revocation();
    const entries = [...stream.entries, fork.entries[1]!];
    for (const record of [k.e1, k.e2, undefined]) {
      await expect(verifyStream(entries, record)).rejects.toMatchObject({ errorCategory: 'CHAIN_CONTINUITY' });
    }
  });

  it('continues a MIGRATION genesis through a later ENTITY_KEY_ROTATION', async () => {
    const k = await keys();
    const priorContext = { ...CONTEXT, logOrigin: 'old.example/dnsid', lr: `c2sp-tlog:testnet:https://old.example/dnsid#${STREAM_ID}` };
    const prior = new LifecycleStreamBuilder(FQDN, priorContext);
    await prior.issuance(k.e1, k.o1);
    await prior.entityKeyRotation(k.e2);
    const priorHistory = (await verifyStreamLifecycle(indexed(prior.entries), FQDN, { ...priorContext, signerKey: k.e2.publicJwk, checkpointIntegrationTimeMs: CHECKPOINT_TIME })).map(item => item.event);
    const destination = new LifecycleStreamBuilder(FQDN, CONTEXT);
    destination.entity = k.e2;
    await destination.migration(k.e2, k.o1, priorContext.lr, `${priorContext.lr}@1`);
    await destination.entityKeyRotation(k.e3);
    await destination.revocation();
    const verifyMigration = async () => ({ entityKey: k.e2.publicJwk, activeOperationalKey: k.o1.publicJwk, priorHistory });
    const selected = await verifyStreamLifecycle(indexed(destination.entries), FQDN, { ...CONTEXT, signerKey: k.e3.publicJwk, checkpointIntegrationTimeMs: CHECKPOINT_TIME, verifyMigration });
    expect(selected.map(item => item.event.type)).toEqual(['MIGRATION', 'ENTITY_KEY_ROTATION', 'REVOCATION']);
    await expect(verifyStreamLifecycle(indexed(destination.entries), FQDN, { ...CONTEXT, signerKey: k.e2.publicJwk, checkpointIntegrationTimeMs: CHECKPOINT_TIME, verifyMigration }))
      .rejects.toThrow('current entity key does not match record ek');
  });
});

describe('genesis selection anchored on the record ek', () => {
  it('still skips a spam ISSUANCE without any ENTITY_KEY_ROTATION', async () => {
    const k = await keys();
    const spam = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await spam.issuance(k.x, k.o2);
    const legit = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await legit.issuance(k.e1, k.o1);
    await legit.keyRotation(k.o3);
    const entries = [...spam.entries, ...legit.entries];
    const selected = await verifyStream(entries, k.e1);
    expect(selected.map(item => item.index)).toEqual([1, 2]);
    // The spam key itself selects its own genesis, exactly as the pinned filter did.
    await expect(verifyStream(entries, k.x)).resolves.toHaveLength(1);
    // No genesis holds the trusted key: the pre-existing failure.
    await expect(verifyStream(entries, k.e3)).rejects.toMatchObject({ errorCategory: 'GENESIS_REQUIRED', message: 'lifecycle contains no ISSUANCE event' });
  });

  it('skips a spam ISSUANCE before a rotated legitimate history', async () => {
    const k = await keys();
    const spam = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await spam.issuance(k.x, k.o2);
    const legit = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await legit.issuance(k.e1, k.o1);
    await legit.entityKeyRotation(k.e2);
    const selected = await verifyStream([...spam.entries, ...legit.entries], k.e2);
    expect(selected.map(item => item.index)).toEqual([1, 2]);
  });

  it('an attacker genesis cannot reach E2 without a valid new_ae by E2', async () => {
    const k = await keys();
    const attacker = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await attacker.issuance(k.x, k.o2);
    // The attacker can sign prev_ae, but not new_ae with E2's private key.
    await attacker.entityKeyRotation(k.e2, { next: { signer: k.x } });
    await attacker.revocation();
    const legit = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await legit.issuance(k.e1, k.o1);
    await legit.entityKeyRotation(k.e2);
    const selected = await verifyStream([...attacker.entries, ...legit.entries], k.e2);
    expect(selected.map(item => item.index)).toEqual([3, 4]);
    expect(selected.map(item => item.event.type)).toEqual(['ISSUANCE', 'ENTITY_KEY_ROTATION']);
    // Without the legitimate history the attacker's stream never binds E2.
    await expect(verifyStream(attacker.entries, k.e2)).rejects.toMatchObject({ errorCategory: 'GENESIS_REQUIRED' });
  });

  it('does not report failures of a genesis that never holds the trusted key', async () => {
    const k = await keys();
    const noisy = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await noisy.issuance(k.x, k.o2);
    await noisy.retirement();
    await noisy.keyRotation(k.o3, { apply: false });
    const legit = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await legit.issuance(k.e1, k.o1);
    await expect(verifyStream([...noisy.entries, ...legit.entries], k.e1)).resolves.toHaveLength(1);
    await expect(verifyStream(noisy.entries, k.x)).rejects.toMatchObject({ errorCategory: 'TERMINAL_STATE' });
  });

  it('verifies a MIGRATION prior history whose end-of-history entity key was rotated', async () => {
    const k = await keys();
    const prior = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await prior.issuance(k.e1, k.o1);
    await prior.entityKeyRotation(k.e2);
    const priorEvents = (await verifyStream(prior.entries, k.e2)).map(item => item.event);
    const migration = {
      type: 'MIGRATION', domain: FQDN, previousLog: CONTEXT.lr, newLog: 'c2sp-tlog:testnet:https://next.example/dnsid#ERERERERERERERERERERER',
      finalEntryRef: `${CONTEXT.lr}@1`, timestamp: new Date(10_000), signingKid: k.e2.publicJwk.kid, sig: 'AA',
    } as LogEvent;
    const stitched = await stitchVerifiedMigrationHistory(FQDN, [migration], { entityKey: k.e2.publicJwk, activeOperationalKey: k.o1.publicJwk, priorHistory: priorEvents });
    expect(stitched).toHaveLength(3);
    await expect(stitchVerifiedMigrationHistory(FQDN, [migration], { entityKey: k.e1.publicJwk, activeOperationalKey: k.o1.publicJwk, priorHistory: priorEvents }))
      .rejects.toThrow('does not establish the imported entity key');
  });
});

describe('ENTITY_KEY_ROTATION prepared-event signing', () => {
  async function prepared() {
    const k = await keys();
    const stream = new LifecycleStreamBuilder(FQDN, CONTEXT);
    await stream.issuance(k.e1, k.o1);
    const event = await rotationEvent(k.e1, k.e2);
    const chain = stream.chain();
    const staged = prepareC2spTlogEventForSigning(event, CONTEXT.lr, { sequence: chain.seq!, previousEventId: chain.prevEventId, previousStateHash: chain.prevStateHash });
    return { k, stream, staged };
  }

  it('reports PreviousEntity then NewEntity and signs both roles', async () => {
    const { k, stream, staged } = await prepared();
    expect(staged.requiredSignatures).toEqual(['PreviousEntity', 'NewEntity']);
    const withPrevious = await signPreparedC2spTlogEvent(staged, 'PreviousEntity', signingProvider(k.e1), { previousEntityKey: k.e1.publicJwk });
    await expect(c2spTlogEntryBytes(withPrevious, { previousEntityKey: k.e1.publicJwk })).rejects.toThrow('missing sigs.new_ae');
    const complete = await signPreparedC2spTlogEvent(withPrevious, 'NewEntity', signingProvider(k.e2), { previousEntityKey: k.e1.publicJwk });
    const bytes = await c2spTlogEntryBytes(complete, { previousEntityKey: k.e1.publicJwk });
    await expect(verifyStream([...stream.entries, bytes], k.e2)).resolves.toHaveLength(2);
    await expect(parsePreparedC2spTlogEvent(bytes, CONTEXT.lr, { previousEntityKey: k.e1.publicJwk })).resolves.toMatchObject({ requiredSignatures: ['PreviousEntity', 'NewEntity'] });
    await expect(parsePreparedC2spTlogEvent(bytes, CONTEXT.lr, { previousEntityKey: k.e3.publicJwk })).rejects.toThrow('prev_ek_thumb does not match');
  });

  it('refuses rotations every verifier would reject', async () => {
    const { k, stream } = await prepared();
    const chain = stream.chain();
    const toOperational = prepareC2spTlogEventForSigning(await rotationEvent(k.e1, k.o1), CONTEXT.lr, { sequence: chain.seq!, previousEventId: chain.prevEventId, previousStateHash: chain.prevStateHash });
    await expect(signPreparedC2spTlogEvent(toOperational, 'PreviousEntity', signingProvider(k.e1), { previousEntityKey: k.e1.publicJwk, operationalKey: k.o1.publicJwk }))
      .rejects.toThrow('must differ from the active operational key');
    const staged = prepareC2spTlogEventForSigning(await rotationEvent(k.e1, k.e2), CONTEXT.lr, { sequence: chain.seq!, previousEventId: chain.prevEventId, previousStateHash: chain.prevStateHash });
    await expect(signPreparedC2spTlogEvent(staged, 'NewEntity', signingProvider(k.e2), { entityKey: k.e3.publicJwk }))
      .rejects.toThrow('prev_ek_thumb does not match');
  });

  it('refuses mismatched or missing signing keys', async () => {
    const { k, staged } = await prepared();
    await expect(signPreparedC2spTlogEvent(staged, 'PreviousEntity', signingProvider(k.e1))).rejects.toThrow('requires the trusted previous entity key');
    await expect(signPreparedC2spTlogEvent(staged, 'PreviousEntity', signingProvider(k.e3), { previousEntityKey: k.e3.publicJwk })).rejects.toThrow('prev_ek_thumb does not match');
    await expect(signPreparedC2spTlogEvent(staged, 'NewEntity', signingProvider(k.x))).rejects.toThrow();
    await expect(signPreparedC2spTlogEvent(staged, 'Entity', signingProvider(k.e1))).rejects.toThrow('Entity is not required for ENTITY_KEY_ROTATION');
  });

  it('decodes to an event whose roles match the model fields', async () => {
    const { k, staged } = await prepared();
    let signed = await signPreparedC2spTlogEvent(staged, 'PreviousEntity', signingProvider(k.e1), { previousEntityKey: k.e1.publicJwk });
    signed = await signPreparedC2spTlogEvent(signed, 'NewEntity', signingProvider(k.e2), { previousEntityKey: k.e1.publicJwk });
    const event = await c2spEnvelopeToEvent(signed.envelope);
    expect(event).toMatchObject({ type: 'ENTITY_KEY_ROTATION', signingKid: k.e1.publicJwk.kid, newEntityKid: k.e2.publicJwk.kid });
    expect(await jwkThumbprint((event as Extract<LogEvent, { type: 'ENTITY_KEY_ROTATION' }>).newEntityPublicKey)).toBe(k.e2.thumbprint);
  });
});
