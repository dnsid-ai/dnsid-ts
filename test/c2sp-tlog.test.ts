import { describe, expect, it, vi } from 'vitest';
import { createHash, generateKeyPairSync, sign as signEd25519 } from 'node:crypto';
import { exportJWK, generateKeyPair } from 'jose';
import identityVectors from './vectors/c2sp-event-identity.json';
import { readFileSync } from 'node:fs';
import { DnsIdTxtRecord, jwkThumbprint, toArrayBuffer, toBase64Url, type C2spIssuanceEvent, type DnsIdJWK, type KeyProvider, type LogEvent } from '@identity-digital/dnsid-protocol';
import {
  canonicalBytes,
  canonicalizeC2spEvent as encodeEvent,
  c2spEventId,
  c2spEnvelopeToEvent,
  type C2spEventContext,
  canonicalLogPrefix,
  C2spTlogVerificationError,
  C2spTlogReader,
  createFetchBackedC2spResourceFetcher,
  entryBundlePath,
  generateC2spTlogStreamId,
  leafHash,
  merkleRootFromEntries,
  normalizedOriginPolicy,
  parseCheckpoint,
  parseC2spPolicyFile,
  parseC2spTlogLr,
  parseC2spEventEntry,
  parsePreparedC2spTlogEvent,
  parseSignedNoteVerifierKey,
  parseTlogProofV1,
  prepareC2spTlogEventForSigning,
  requiredC2spResourceFetchGuarantees,
  signPreparedC2spTlogEvent,
  ScanStreamSource,
  signedC2spEventBytes as encodeSignedEvent,
  signedC2spEntryBytes,
  stateHash,
  stitchVerifiedMigrationHistory,
  tilePath,
  verifyCheckpointSignature,
  verifyLifecycle,
  verifyStreamLifecycle,
  writePreparedEvent,
  type PreparedC2spVerificationContext,
  type VerifiedLifecycleEvent,
} from '@identity-digital/dnsid-log-c2sp-tlog';

const TEST_STREAM_ID = 'ERERERERERERERERERERER';
const DEFAULT_CONTEXT = { scope: 'testnet', logOrigin: 'log.example/dnsid', streamId: TEST_STREAM_ID, lr: `c2sp-tlog:testnet:https://log.example/dnsid#${TEST_STREAM_ID}` };
// Generated test histories use logical predecessors, regardless of their eventual log indexes.
let previousEntry: Uint8Array;
let previousSequence = 0;
let previousState: Record<string, unknown>;
function eventContext(event: LogEvent, context: C2spEventContext): C2spEventContext {
  const genesis = event.type === 'ISSUANCE' || event.type === 'MIGRATION';
  return { ...DEFAULT_CONTEXT, ...(genesis ? { seq: 0 } : {
    seq: previousSequence + 1,
    prevEventId: c2spEventId(signedC2spEntryBytes(previousEntry)),
    prevStateHash: stateHash(previousState),
  }), ...context };
}
function signedC2spEventBytes(event: LogEvent, context: C2spEventContext = {}): Uint8Array {
  return encodeSignedEvent(event, eventContext(event, context));
}
function canonicalizeC2spEvent(event: LogEvent, context: C2spEventContext = {}): Uint8Array {
  const bound = eventContext(event, context);
  const bytes = encodeEvent(event, bound);
  Object.assign(event, { seq: bound.seq }, bound.prevEventId === undefined ? {} : { prev_event_id: bound.prevEventId, prev_state_hash: bound.prevStateHash });
  previousEntry = bytes;
  previousSequence = bound.seq!;
  if (event.type === 'ISSUANCE') previousState = { fqdn: event.domain, status: 'ACTIVE', entity_thumb: event.initialEntityThumbprint, operational_thumb: event.initialOperationalThumbprint };
  if (event.type === 'KEY_ROTATION') previousState = { ...previousState, operational_thumb: event.newOperationalThumbprint };
  if (event.type === 'REVOCATION') previousState = { ...previousState, status: 'REVOKED' };
  if (event.type === 'RETIREMENT') previousState = { ...previousState, status: 'RETIRED' };
  return bytes;
}

async function es256Key(kid: string): Promise<{ publicJwk: DnsIdJWK; privateKey: CryptoKey }> {
  const kp = await generateKeyPair('ES256', { extractable: true });
  return { publicJwk: { ...await exportJWK(kp.publicKey), kid, alg: 'ES256' } as DnsIdJWK, privateKey: kp.privateKey as CryptoKey };
}

async function sign(bytes: Uint8Array, privateKey: CryptoKey): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, toArrayBuffer(bytes))));
}

function signingProvider(key: DnsIdJWK, privateKey: CryptoKey): KeyProvider {
  return {
    signingKey: async () => key,
    jwk: async (kid) => {
      if (kid !== key.kid) throw new Error('key not found');
      return key;
    },
    listKeyIds: async () => [key.kid],
    sign: async (bytes) => new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, toArrayBuffer(bytes))),
    signKey: async (kid, bytes) => {
      if (kid !== key.kid) throw new Error('key not found');
      return new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, toArrayBuffer(bytes)));
    },
    generateKey: async () => { throw new Error('not implemented'); },
    activate: async () => { throw new Error('not implemented'); },
    supersede: async () => { throw new Error('not implemented'); },
  };
}

async function issuance(entity: Awaited<ReturnType<typeof es256Key>>, operational: Awaited<ReturnType<typeof es256Key>>): Promise<C2spIssuanceEvent> {
  return {
    type: 'ISSUANCE', domain: 'agent.example.com', governanceId: 'entity', timestamp: new Date(1000),
    initialOperationalKid: operational.publicJwk.kid,
    initialOperationalAlg: operational.publicJwk.alg!,
    initialOperationalPublicKey: operational.publicJwk,
    initialOperationalThumbprint: await jwkThumbprint(operational.publicJwk),
    initialEntityKid: entity.publicJwk.kid,
    initialEntityAlg: entity.publicJwk.alg!,
    initialEntityPublicKey: entity.publicJwk,
    initialEntityThumbprint: await jwkThumbprint(entity.publicJwk),
  };
}

function issuanceVerificationContext(event: C2spIssuanceEvent): PreparedC2spVerificationContext {
  return {
    expectedFqdn: event.domain,
    expectedGovernanceId: event.governanceId,
    entityKey: event.initialEntityPublicKey,
    operationalKey: event.initialOperationalPublicKey,
  };
}

async function signIssuance(event: C2spIssuanceEvent, entity: CryptoKey, operational: CryptoKey, context = {}) {
  const bytes = signedC2spEventBytes(event, context);
  return { ...event, sig: await sign(bytes, entity), operationalCountersig: await sign(bytes, operational) };
}

const VECTOR_ISSUANCE_SIGNED = '{"ek":{"alg":"EdDSA","crv":"Ed25519","kid":"ae-test-1","kty":"OKP","x":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"},"fqdn":"agent.example","gi":"example.com","kind":"dnsid.lifecycle","ku":{"alg":"EdDSA","crv":"Ed25519","kid":"op-test-1","kty":"OKP","x":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q"},"ts":1782172800,"type":"ISSUANCE","v":1}';
const VECTOR_ISSUANCE = '{"ek":{"alg":"EdDSA","crv":"Ed25519","kid":"ae-test-1","kty":"OKP","x":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"},"fqdn":"agent.example","gi":"example.com","kind":"dnsid.lifecycle","ku":{"alg":"EdDSA","crv":"Ed25519","kid":"op-test-1","kty":"OKP","x":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q"},"sigs":{"ae":{"kid":"ae-test-1","sig":"Qp_IOg6S-ksElLBrMTwUqQ6slrt-W-wbXtadHY6nXOPbUXs1013_kNdrMWYEWjVZcvXptqxwshbKu-wtz4h6CQ"},"op":{"kid":"op-test-1","sig":"jWSZhq4Cm5FeHipM1MX5LVdej9cpStNAaoCFZSG3G_w-0w4rhYss2Vvi0lz7DcvVFO8K2nde0VfX2c5Ga5bvAg"}},"ts":1782172800,"type":"ISSUANCE","v":1}';
const VECTOR_ROTATION = '{"fqdn":"agent.example","kind":"dnsid.lifecycle","new_ku":{"alg":"EdDSA","crv":"Ed25519","kid":"op-test-2","kty":"OKP","x":"ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw"},"new_thumb":"d8Me3uJ82jhdsCstWyVMr3_I2ueeTYG5agM1-2r1_bY","prev_thumb":"aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU","sigs":{"new_op":{"kid":"op-test-2","sig":"JfWp_M8PVCoWAAqkiCX-3OjLlrRZLEcgusyTK6yDSJmeP0Ojw9Nc6cy-nDQjs21vx9-CyNMmWPOXAU_YJ6ddBg"},"prev_op":{"kid":"op-test-1","sig":"pPTFBLO3qGxqJ9xOrppA-z5SlQuPoCq1Sf9OwrizoN8K8VTtIuxg0xJDXE1BVzWnMt9GAcyx1yM3Rx3JZ16oCQ"}},"ts":1782259200,"type":"KEY_ROTATION","v":1}';
const VECTOR_REVOCATION = '{"fqdn":"agent.example","kind":"dnsid.lifecycle","reason":"keyCompromise","sigs":{"ae":{"kid":"ae-test-1","sig":"CjrMHNl_BdMG5qkbyttuCGyhlchkhTowOyfkZn2T-Wl_jnqYB5Jh0TYuNS6BLJlDLYS9OFD8FItH2dEJ0f4eCw"}},"ts":1782345600,"type":"REVOCATION","v":1}';

describe('C2SP tlog helpers', () => {
  it('verifies exact signed method vectors at d5a65d06f76eff4db81e50f8767a600d2ca7fc2a', async () => {
    const entries = readFileSync(new URL('./vectors/c2sp-method-events.ndjson', import.meta.url), 'utf8').trimEnd().split('\n').map(line => new TextEncoder().encode(line));
    expect(entries.map(bytes => c2spEventId(signedC2spEntryBytes(bytes)))).toEqual(['BcEvdCSvAUW3r4YER1-rXMGWMACv6--RGhn-CzPAnjE', 'JHvi5BXFBjjXS1PPQ0SBDT8areqAGJ9i_zAXUIxGgyE', 'J-odfRVwktq5YRgXEesz663r5AYJbYgT6qhwmfnyjxQ']);
    expect(Buffer.from(merkleRootFromEntries(entries)).toString('base64')).toBe('H3aq5vryyX/jMIrSuLhjl/64vwD/yvpOfXUxGjzC5Ns=');
    const genesis = await parseC2spEventEntry(entries[0]!) as C2spIssuanceEvent;
    await expect(verifyStreamLifecycle(entries.map((bytes, index) => ({ index, bytes })), genesis.domain, { signerKey: genesis.initialEntityPublicKey, checkpointIntegrationTimeMs: 1_782_345_700_000 })).resolves.toHaveLength(3);
  });

  it('matches the corrected independent event-ID and unchanged state-hash vectors', () => {
    for (const vector of identityVectors.vectors) {
      const bytes = canonicalBytes(vector.value);
      expect(new TextDecoder().decode(bytes)).toBe(vector.canonical);
      expect(vector.domain === 'event' ? c2spEventId(bytes) : stateHash(vector.value)).toBe(vector.hash);
    }
  });

  it('authenticates every role, deduplicates ES256 variants, and recognizes historical-key forks', async () => {
    const entity = await es256Key('entity');
    const op = await es256Key('op');
    const next = await es256Key('next');
    const genesis = await issuance(entity, op);
    const first = canonicalizeC2spEvent(await signIssuance(genesis, entity.privateKey, op.privateKey));
    const rotation: LogEvent = {
      type: 'KEY_ROTATION', domain: genesis.domain, timestamp: new Date(2000),
      previousOperationalKid: op.publicJwk.kid, previousOperationalThumbprint: genesis.initialOperationalThumbprint,
      newOperationalKid: next.publicJwk.kid, newOperationalAlg: 'ES256', newOperationalPublicKey: next.publicJwk,
      newOperationalThumbprint: await jwkThumbprint(next.publicJwk),
    };
    const bytes = signedC2spEventBytes(rotation);
    const second = canonicalizeC2spEvent({ ...rotation, sig: await sign(bytes, op.privateKey), newOperationalProof: await sign(bytes, next.privateKey) });
    const flipS = (entry: Uint8Array) => {
      const value = JSON.parse(new TextDecoder().decode(entry));
      for (const signature of Object.values(value.sigs) as Array<{ sig: string }>) {
        const raw = Buffer.from(signature.sig, 'base64url');
        const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
        const s = order - BigInt(`0x${raw.subarray(32).toString('hex')}`);
        signature.sig = Buffer.concat([raw.subarray(0, 32), Buffer.from(s.toString(16).padStart(64, '0'), 'hex')]).toString('base64url');
      }
      return canonicalBytes(value);
    };
    const stripped = JSON.parse(new TextDecoder().decode(second));
    delete stripped.sigs.new_op;
    const invalid = JSON.parse(new TextDecoder().decode(second));
    invalid.sigs.new_op.sig = 'AA';
    const verify = (entries: Uint8Array[]) => verifyStreamLifecycle(entries.map((bytes, index) => ({ index, bytes })), genesis.domain, { ...DEFAULT_CONTEXT, signerKey: entity.publicJwk, checkpointIntegrationTimeMs: 10000 });
    for (const originalsFirst of [true, false]) {
      const a = originalsFirst ? first : flipS(first);
      const b = originalsFirst ? second : flipS(second);
      expect(c2spEventId(signedC2spEntryBytes(a))).toBe(c2spEventId(signedC2spEntryBytes(first)));
      expect(leafHash(flipS(first))).not.toEqual(leafHash(first));
      const selected = await verify([a, canonicalBytes(stripped), canonicalBytes(invalid), b, first, second]);
      expect(selected.map(item => item.index)).toEqual([0, 3]);
    }
    const fork = JSON.parse(new TextDecoder().decode(second));
    delete fork.sigs;
    fork.ts = 3;
    const forkBytes = canonicalBytes(fork);
    fork.sigs = { prev_op: { kid: op.publicJwk.kid, sig: await sign(forkBytes, op.privateKey) }, new_op: { kid: next.publicJwk.kid, sig: await sign(forkBytes, next.privateKey) } };
    await expect(verify([first, second, canonicalBytes(fork)])).rejects.toMatchObject({ errorCategory: 'CHAIN_CONTINUITY' });
    delete fork.sigs.new_op;
    await expect(verify([first, second, canonicalBytes(fork)])).resolves.toHaveLength(2);
    const terminal = { ...JSON.parse(new TextDecoder().decode(second)), type: 'REVOCATION', ts: 4, seq: 2, prev_event_id: c2spEventId(signedC2spEntryBytes(second)), prev_state_hash: stateHash(previousState), reason: 'keyCompromise' };
    delete terminal.sigs;
    terminal.sigs = { ae: { kid: entity.publicJwk.kid, sig: await sign(canonicalBytes(terminal), entity.privateKey) } };
    const terminalBytes = canonicalBytes(terminal);
    await expect(verify([first, second, terminalBytes, flipS(first), flipS(second), flipS(terminalBytes)])).resolves.toHaveLength(3);
    delete terminal.sigs;
    terminal.ts = 5;
    terminal.sigs = { ae: { kid: entity.publicJwk.kid, sig: await sign(canonicalBytes(terminal), entity.privateKey) } };
    await expect(verify([first, second, terminalBytes, canonicalBytes(terminal)])).rejects.toMatchObject({ errorCategory: 'TERMINAL_STATE' });
  });
  it('generates opaque 128-bit unpadded base64url stream IDs', () => {
    const ids = Array.from({ length: 64 }, () => generateC2spTlogStreamId());
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) {
      expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
      expect(id).not.toContain('=');
      expect(Buffer.from(id, 'base64url')).toHaveLength(16);
    }
  });

  it('prepares, signs, submits, and parses an ISSUANCE entry', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const event = await issuance(entity, operational);
    const legacyLr = 'c2sp-tlog:public:https://log.example/dnsid#agent.example.com';
    expect(parseC2spTlogLr(legacyLr).streamId).toBe(event.domain);
    expect(() => prepareC2spTlogEventForSigning(event, legacyLr)).toThrow('opaque stream ID');
    const lrPrefix = `c2sp-tlog:public:https://log.example/dnsid#${TEST_STREAM_ID}`;
    const context = {
      scope: 'public',
      logOrigin: 'log.example/dnsid',
      streamId: TEST_STREAM_ID,
      lr: lrPrefix,
      seq: 0,
    };
    let prepared = prepareC2spTlogEventForSigning(event, lrPrefix);
    const verificationContext = issuanceVerificationContext(event);
    expect(prepared.requiredSignatures).toEqual(['Entity', 'OperationalCountersignature']);
    prepared = await signPreparedC2spTlogEvent(prepared, 'Entity', signingProvider(entity.publicJwk, entity.privateKey), verificationContext);
    prepared = await signPreparedC2spTlogEvent(prepared, 'OperationalCountersignature', signingProvider(operational.publicJwk, operational.privateKey), verificationContext);
    const signatures = prepared.envelope.sigs as { ae: { sig: string }; op: { sig: string } };
    const submit = vi.fn(async (entryBytes: Uint8Array) => {
      const parsed = await parseC2spEventEntry(entryBytes, context);
      expect(parsed).toMatchObject({
        type: 'ISSUANCE',
        domain: event.domain,
        sig: signatures.ae.sig,
        operationalCountersig: signatures.op.sig,
      });
      return { index: 7 };
    });

    await expect(writePreparedEvent(prepared, { ...verificationContext, submit, idempotencyKey: 'registration-1' })).resolves.toBe(`${lrPrefix}@7`);
    expect(submit).toHaveBeenCalledOnce();
    expect(submit).toHaveBeenCalledWith(expect.any(Uint8Array), 'registration-1');
    const unavailable = new Error('network timeout');
    await expect(writePreparedEvent(prepared, {
      ...verificationContext,
      submit: async () => { throw unavailable; },
      idempotencyKey: 'registration-1',
    })).rejects.toMatchObject({ code: 'LogError', transient: true, errorCategory: 'INVALID_EVIDENCE', cause: unavailable });
    const rejected = { state: 'rejected', retryable: false, retryWithSameBytes: false };
    await expect(writePreparedEvent(prepared, {
      ...verificationContext,
      submit: async () => { throw rejected; },
      idempotencyKey: 'registration-1',
    })).rejects.toMatchObject({
      code: 'LogError', transient: false, errorCategory: 'INVALID_EVIDENCE', cause: rejected,
    });
  });

  it('preserves unknown signed fields across split signing', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const lr = `c2sp-tlog:public:https://log.example/dnsid#${TEST_STREAM_ID}`;
    const event = await issuance(entity, operational);
    const initial = prepareC2spTlogEventForSigning(event, lr);
    const bytes = canonicalBytes({ ...initial.envelope, extension: { protected: true } });
    let parsed = await parsePreparedC2spTlogEvent(bytes, lr);
    parsed = await signPreparedC2spTlogEvent(parsed, 'Entity', signingProvider(entity.publicJwk, entity.privateKey), issuanceVerificationContext(event));
    parsed = await signPreparedC2spTlogEvent(parsed, 'OperationalCountersignature', signingProvider(operational.publicJwk, operational.privateKey), issuanceVerificationContext(event));
    expect(parsed.envelope.extension).toEqual({ protected: true });
  });

  it('pins the expected identity before countersigning split ISSUANCE', async () => {
    const entity = await es256Key('entity');
    const otherEntity = await es256Key('other-entity');
    const operational = await es256Key('op');
    const otherOperational = await es256Key('other-op');
    const event = await issuance(entity, operational);
    const lr = `c2sp-tlog:public:https://log.example/dnsid#${TEST_STREAM_ID}`;
    let prepared = prepareC2spTlogEventForSigning(event, lr);
    await expect(signPreparedC2spTlogEvent(prepared, 'Entity', signingProvider(entity.publicJwk, entity.privateKey)))
      .rejects.toThrow('requires trusted expectedFqdn, expectedGovernanceId, entityKey, operationalKey');
    await expect(signPreparedC2spTlogEvent(prepared, 'Entity', signingProvider(entity.publicJwk, entity.privateKey), {
      ...issuanceVerificationContext(event),
      expectedFqdn: 'victim.example.com',
    })).rejects.toThrow('fqdn does not match');
    prepared = await signPreparedC2spTlogEvent(
      prepared,
      'Entity',
      signingProvider(entity.publicJwk, entity.privateKey),
      issuanceVerificationContext(event),
    );
    const provider = signingProvider(operational.publicJwk, operational.privateKey);
    const expected = issuanceVerificationContext(event);

    await expect(signPreparedC2spTlogEvent(prepared, 'OperationalCountersignature', provider))
      .rejects.toThrow('requires trusted expectedFqdn, expectedGovernanceId, entityKey, operationalKey');
    await expect(signPreparedC2spTlogEvent(prepared, 'OperationalCountersignature', provider, { ...expected, expectedFqdn: 'victim.example.com' }))
      .rejects.toThrow('fqdn does not match');
    await expect(signPreparedC2spTlogEvent(prepared, 'OperationalCountersignature', provider, { ...expected, expectedGovernanceId: 'other-governance' }))
      .rejects.toThrow('gi does not match');
    await expect(signPreparedC2spTlogEvent(prepared, 'OperationalCountersignature', provider, { ...expected, entityKey: otherEntity.publicJwk }))
      .rejects.toThrow('entity key does not match');
    await expect(signPreparedC2spTlogEvent(prepared, 'OperationalCountersignature', provider, { ...expected, operationalKey: otherOperational.publicJwk }))
      .rejects.toThrow('operational key does not match');
  });

  it('validates supplied ISSUANCE expectations while parsing untrusted prepared bytes', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const event = await issuance(entity, operational);
    const lr = `c2sp-tlog:public:https://log.example/dnsid#${TEST_STREAM_ID}`;
    let prepared = prepareC2spTlogEventForSigning(event, lr);
    prepared = await signPreparedC2spTlogEvent(prepared, 'Entity', signingProvider(entity.publicJwk, entity.privateKey), issuanceVerificationContext(event));
    const bytes = canonicalBytes(prepared.envelope);

    await expect(parsePreparedC2spTlogEvent(bytes, lr, { ...issuanceVerificationContext(event), expectedFqdn: 'victim.example.com' }))
      .rejects.toThrow('fqdn does not match');
    await expect(parsePreparedC2spTlogEvent(bytes, lr, issuanceVerificationContext(event))).resolves.toMatchObject({
      envelope: { fqdn: event.domain, gi: event.governanceId },
    });
  });

  it('matches the method specification event and Merkle vectors', async () => {
    const encoder = new TextEncoder();
    const entries = [VECTOR_ISSUANCE, VECTOR_ROTATION, VECTOR_REVOCATION].map(value => encoder.encode(value));
    expect(new TextDecoder().decode(signedC2spEntryBytes(entries[0]!))).toBe(VECTOR_ISSUANCE_SIGNED);
    expect(entries[0]).toHaveLength(591);
    expect(Buffer.from(leafHash(entries[0]!)).toString('base64')).toBe('0B3JZBn2fwm7Ei8RI4w0Eud3KVXBWqtWpy156PwQD24=');
    expect(Buffer.from(leafHash(entries[1]!)).toString('base64')).toBe('5lXZzoyy6sXEMoWOQrzOAOvOQs/HAnY8gF/06+y090I=');
    expect(Buffer.from(leafHash(entries[2]!)).toString('base64')).toBe('tu8yFLzhY09shNhg0yFGnFzplzZAefioh6XF8NqQCBs=');
    // The draft's iMww... root uses yO1b... as leaf 1, which conflicts with its
    // own 5lXZ... hash for the published KEY_ROTATION entry bytes.
    expect(Buffer.from(merkleRootFromEntries(entries)).toString('base64')).toBe('VZEUN6esoy2pE7M6Cb1iq/x61YU27NDeCBtRdfzARok=');
    // Historical wire bytes remain Merkle vectors, not corrected lifecycle evidence.
    await expect(parseC2spEventEntry(entries[0]!)).rejects.toThrow('missing signed method');
  });

  it('requires the C2SP-specific new-key proof on KEY_ROTATION', async () => {
    const envelope = JSON.parse(VECTOR_ROTATION) as { sigs: Record<string, unknown> };
    delete envelope.sigs.new_op;
    await expect(c2spEnvelopeToEvent(envelope)).rejects.toThrow('missing sigs.new_op');
  });

  it('encodes C2SP tile N path components', () => {
    expect(tilePath('p', 0, 1234067)).toBe('p/tile/0/x001/x234/067');
    expect(entryBundlePath('p', 7, 5)).toBe('p/tile/entries/007.p/5');
  });

  it('parses standard signed-note verifier keys', () => {
    const keyBytes = Buffer.concat([Buffer.from([1]), Buffer.alloc(32, 250)]).toString('base64');
    expect(keyBytes).toContain('+');
    const key = parseSignedNoteVerifierKey(`example.com/foo+530d903a+${keyBytes}`);
    expect(key.name).toBe('example.com/foo');
    expect(Buffer.from(key.keyId!).toString('hex')).toBe('530d903a');
    expect(Buffer.from(key.signatureType!).toString('hex')).toBe('01');
    expect(key.keyBytes).toHaveLength(32);
  });

  it('verifies standard timestamped Ed25519 witness cosignatures', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const publicJwk = publicKey.export({ format: 'jwk' });
    const publicBytes = Buffer.from(publicJwk.x!, 'base64url');
    const name = 'witness.example';
    const signatureType = Buffer.from([0x04]);
    const keyId = createHash('sha256').update(name).update('\n').update(signatureType).update(publicBytes).digest().subarray(0, 4);
    const verifier = parseSignedNoteVerifierKey(`${name}+${keyId.toString('hex')}+${Buffer.concat([signatureType, publicBytes]).toString('base64')}`);
    const body = `origin\n1\n${Buffer.alloc(32).toString('base64')}\n`;
    const timestamp = 1234n;
    const timestampBytes = Buffer.alloc(8);
    timestampBytes.writeBigUInt64BE(timestamp);
    const signature = signEd25519(null, Buffer.from(`cosignature/v1\ntime ${timestamp}\n${body}`), privateKey);
    const checkpoint = parseCheckpoint(`${body}\n— ${name} ${Buffer.concat([keyId, timestampBytes, signature]).toString('base64')}\n`);
    expect(verifyCheckpointSignature(checkpoint, verifier)).toBe(true);
  });

  it('rejects invalid witness quorum values', () => {
    const key = { name: 'log', kind: 'ed25519' as const, keyBytes: new Uint8Array(32) };
    expect(() => normalizedOriginPolicy({ origins: { origin: { logKeys: [key], quorum: -1 } } }, 'origin')).toThrow('non-negative integer');
  });

  it('counts distinct underlying witness keys rather than names or key IDs', () => {
    const log = { name: 'origin', kind: 'ed25519' as const, keyBytes: new Uint8Array(32).fill(1) };
    const publicKey = new Uint8Array(32).fill(2);
    const first = { name: 'first', kind: 'ed25519' as const, keyBytes: publicKey, keyId: new Uint8Array([1, 2, 3, 4]), signatureType: new Uint8Array([0x04]) };
    const alias = { name: 'alias', kind: 'ed25519' as const, keyBytes: publicKey, keyId: new Uint8Array([5, 6, 7, 8]), signatureType: new Uint8Array([0x04]) };
    expect(() => normalizedOriginPolicy({ origins: { origin: { logKeys: [log], witnessKeys: [first, alias], quorum: 2 } } }, 'origin')).toThrow('underlying public key');
  });

  it('rejects reuse of one underlying key for the log and a witness', () => {
    const publicKey = new Uint8Array(32).fill(3);
    const log = { name: 'origin', kind: 'ed25519' as const, keyBytes: publicKey, signatureType: new Uint8Array([0x01]) };
    const witness = { name: 'witness', kind: 'ed25519' as const, keyBytes: publicKey, signatureType: new Uint8Array([0x04]) };
    expect(() => normalizedOriginPolicy({ origins: { origin: { logKeys: [log], witnessKeys: [witness], quorum: 1 } } }, 'origin')).toThrow('log and witness keys');
  });

  it('parses the method specification C2SP policy format', () => {
    const policy = parseC2spPolicyFile(`log testnet.dnsid.example/log+63868553+Ae1JKMYo0cLG6ukDOJBZlWEpWSc6XGP5NjbBRhSshzfR
witness witness1.testnet.dnsid.example witness1.testnet.dnsid.example+2c00c50d+BG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx
witness witness2.testnet.dnsid.example witness2.testnet.dnsid.example+9b878529+BIqHX/8es4RRV3rNWv7kBUVlaN18ieCQhjoFV7x69J8X
group local-witnesses 2 witness1.testnet.dnsid.example witness2.testnet.dnsid.example
quorum local-witnesses`);
    expect(policy.origins['testnet.dnsid.example/log']).toMatchObject({ quorum: 2 });
    expect(policy.origins['testnet.dnsid.example/log']!.witnessKeys).toHaveLength(2);
  });

  it('parses nested any/all groups and a direct witness quorum', () => {
    const vkey = (name: string, type: number, fill: number) => `${name}+00000000+${Buffer.concat([Buffer.from([type]), Buffer.alloc(32, fill)]).toString('base64')}`;
    const nested = parseC2spPolicyFile(`log ${vkey('origin', 1, 1)}
witness W1 ${vkey('witness-1', 4, 2)}
witness W2 ${vkey('witness-2', 4, 3)}
witness W3 ${vkey('witness-3', 4, 4)}
group pair any W1 W2
group nested all pair W3
quorum nested
`);
    expect(nested.origins.origin!.quorumRule).toMatchObject({
      kind: 'threshold',
      threshold: 2,
      members: [{ kind: 'threshold', threshold: 1 }, { kind: 'witness' }],
    });

    const direct = parseC2spPolicyFile(`log ${vkey('origin', 1, 1)}
witness W1 ${vkey('witness-1', 4, 2)}
quorum W1
`);
    expect(direct.origins.origin).toMatchObject({ quorum: 1, quorumRule: { kind: 'witness' } });
  });

  it('enforces tlog-policy syntax constraints', () => {
    const vkey = (name: string, type: number, fill: number) => `${name}+00000000+${Buffer.concat([Buffer.from([type]), Buffer.alloc(32, fill)]).toString('base64')}`;
    const log = `log ${vkey('origin', 1, 1)}`;
    const witness = `witness W ${vkey('witness', 4, 2)}`;
    expect(() => parseC2spPolicyFile(`${log}\r\nquorum none\n`)).toThrow('character');
    expect(() => parseC2spPolicyFile(`${log}\n${witness}\nquorum W\nquorum none\n`)).toThrow('exactly one quorum');
    expect(() => parseC2spPolicyFile(`${log}\ngroup G any missing\nquorum G\n`)).toThrow('unknown preceding');
    expect(() => parseC2spPolicyFile(`${log}\n${witness}\ngroup G all W W\nquorum G\n`)).toThrow('distinct');
  });

  it('authenticates and bounds a checkpoint before fetching entry bundles', async () => {
    const checkpoint = `origin\n100\n${Buffer.alloc(32).toString('base64')}\n`;
    const rejectingFetch = vi.fn().mockResolvedValue(new Response(checkpoint));
    const rejecting = new ScanStreamSource({
      authenticateCheckpoint: () => { throw new Error('untrusted checkpoint'); },
      maxTreeSize: 10,
    }, createFetchBackedC2spResourceFetcher(rejectingFetch, requiredC2spResourceFetchGuarantees()));
    await expect(rejecting.load('https://log.example')).rejects.toThrow('untrusted checkpoint');
    expect(rejectingFetch).toHaveBeenCalledTimes(1);

    const authenticateCheckpoint = vi.fn();
    const oversizedFetch = vi.fn().mockResolvedValue(new Response(checkpoint));
    const oversized = new ScanStreamSource(
      { authenticateCheckpoint, maxTreeSize: 10 },
      createFetchBackedC2spResourceFetcher(oversizedFetch, requiredC2spResourceFetchGuarantees()),
    );
    await expect(oversized.load('https://log.example')).rejects.toThrow('tree size exceeds');
    expect(authenticateCheckpoint).toHaveBeenCalledTimes(1);
    expect(oversizedFetch).toHaveBeenCalledTimes(1);
  });

  it('accepts a root URL as a C2SP log prefix', () => {
    expect(canonicalLogPrefix('https://log.example')).toBe('https://log.example');
  });

  it('enforces the method lr grammar and public HTTPS requirement', () => {
    expect(parseC2spTlogLr('c2sp-tlog:public:https://log.example/dnsid#agent.example').streamId).toBe('agent.example');
    expect(() => parseC2spTlogLr('c2sp-tlog:public:http://log.example/dnsid#agent.example')).toThrow('https');
    expect(() => parseC2spTlogLr('c2sp-tlog:private-lab.one:https://log.example/dnsid#agent.example')).toThrow('scope');
    expect(() => parseC2spTlogLr('c2sp-tlog:testnet:https://log.example/dnsid#agent/example')).toThrow('stream id');
    expect(parseC2spTlogLr('c2sp-tlog:testnet:https://log.example/dnsid#opaque_Stream~1').streamId).toBe('opaque_Stream~1');
    expect(() => parseC2spTlogLr('c2sp-tlog:testnet:https://LOG.example:443/dnsid#agent.example')).toThrow('canonical');
    expect(() => parseC2spTlogLr('c2sp-tlog:testnet:https://log.example/dnsid;other#agent.example')).toThrow('percent-encode');
  });

  it('rejects unsupported or mismatched lifecycle-key algorithms', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const event = await issuance(entity, operational);
    const unsupported = {
      ...event,
      initialOperationalAlg: 'ES384',
      initialOperationalPublicKey: { ...event.initialOperationalPublicKey, alg: 'ES384', crv: 'P-384' },
    } as C2spIssuanceEvent;
    expect(() => prepareC2spTlogEventForSigning(unsupported, `c2sp-tlog:testnet:https://log.example/dnsid#${TEST_STREAM_ID}`))
      .toThrow('unsupported lifecycle-key algorithm');

    const mismatched = { ...event, initialOperationalAlg: 'EdDSA' } as C2spIssuanceEvent;
    expect(() => prepareC2spTlogEventForSigning(mismatched, `c2sp-tlog:testnet:https://log.example/dnsid#${TEST_STREAM_ID}`))
      .toThrow('algorithm metadata mismatch');

    const envelope = JSON.parse(VECTOR_ISSUANCE) as Record<string, unknown>;
    envelope.ek = { ...(envelope.ek as Record<string, unknown>), alg: 'ES384', crv: 'P-384' };
    await expect(c2spEnvelopeToEvent(envelope)).rejects.toThrow('unsupported lifecycle-key algorithm');
  });

  it('treats the stream ID as a selection hint and verifies the signed event FQDN', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const event = await issuance(entity, operational);
    const lr = 'c2sp-tlog:testnet:https://log.example/dnsid#opaque_Stream~1';
    const reference = parseC2spTlogLr(lr);
    const context = { scope: reference.scope, logOrigin: reference.origin, streamId: reference.streamId, lr: reference.lr };
    expect(() => prepareC2spTlogEventForSigning(event, lr)).not.toThrow();

    const signed = await signIssuance(event, entity.privateKey, operational.privateKey, context);
    const bytes = canonicalizeC2spEvent(signed, context);
    await expect(verifyStreamLifecycle(
      [{ index: 0, bytes }],
      event.domain,
      { ...context, signerKey: entity.publicJwk, checkpointIntegrationTimeMs: 10_000 },
    )).resolves.toHaveLength(1);
    await expect(verifyStreamLifecycle(
      [{ index: 0, bytes }],
      'other.example.com',
      { ...context, signerKey: entity.publicJwk, checkpointIntegrationTimeMs: 10_000 },
    )).rejects.toThrow('lifecycle contains no ISSUANCE event');
  });

  it('rejects reuse of the entity key as the operational key', async () => {
    const entity = await es256Key('entity');
    const event = await issuance(entity, entity);
    const lr = `c2sp-tlog:testnet:https://log.example/dnsid#${TEST_STREAM_ID}`;
    expect(() => prepareC2spTlogEventForSigning(event, lr)).toThrow('must be distinct');

    const envelope = JSON.parse(VECTOR_ISSUANCE) as Record<string, unknown>;
    envelope.ku = envelope.ek;
    const sigs = envelope.sigs as Record<string, { kid: string }>;
    sigs.op!.kid = sigs.ae!.kid;
    await expect(c2spEnvelopeToEvent(envelope)).rejects.toThrow('must be distinct');

    const directEvent = { ...event, seq: 0, sig: 'AA', operationalCountersig: 'AA' };
    const bytes = canonicalBytes({ test: true });
    await expect(verifyLifecycle([
      { index: 0, bytes, leafHash: leafHash(bytes), event: directEvent },
    ], { checkpointIntegrationTimeMs: 10_000 })).rejects.toThrow('must be distinct');
  });

  it('checks issuance key distinctness from JWK material rather than thumbprint metadata', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const event = await issuance(entity, operational);
    event.initialEntityThumbprint = 'placeholder';
    event.initialOperationalThumbprint = 'placeholder';

    expect(() => prepareC2spTlogEventForSigning(
      event,
      `c2sp-tlog:testnet:https://log.example/dnsid#${TEST_STREAM_ID}`,
    )).not.toThrow();
  });

  it('accepts standard C2SP tlog proof magic', () => {
    const proof = parseTlogProofV1(`c2sp.org/tlog-proof@v1\nindex 0\n\norigin\n1\n${Buffer.alloc(32).toString('base64')}\n`);
    expect(proof.index).toBe(0);
    expect(proof.checkpoint.origin).toBe('origin');
  });

  it('rejects public entries whose signed metadata does not match the reader context', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const event = await issuance(entity, operational);
    const context = { scope: 'public', logOrigin: 'origin-a', streamId: TEST_STREAM_ID, lr: 'lr', seq: 0 };
    const signed = await signIssuance(event, entity.privateKey, operational.privateKey, context);
    const bytes = canonicalizeC2spEvent(signed, context);
    await expect(parseC2spEventEntry(bytes, { ...context, logOrigin: 'origin-b' })).rejects.toThrow('log_origin mismatch');
  });

  it('does not accept lifecycle events self-signed by the operational key', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const event = await issuance(entity, operational);
    const unsignedBytes = signedC2spEventBytes(event);
    const signed = { ...event, sig: await sign(unsignedBytes, operational.privateKey), operationalCountersig: await sign(unsignedBytes, operational.privateKey) };
    const bytes = canonicalizeC2spEvent(signed);
    const events: VerifiedLifecycleEvent[] = [{ index: 0, leafHash: leafHash(bytes), bytes, event: signed }];
    await expect(verifyLifecycle(events, { signerKey: entity.publicJwk, checkpointIntegrationTimeMs: 10_000 })).rejects.toThrow('invalid ISSUANCE entity signature');
  });

  it('verifies a two-event public lifecycle chain from a JSON-safe genesis state', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const issuanceEvent = await issuance(entity, operational);
    const context = { ...DEFAULT_CONTEXT, scope: 'public', seq: 0 };
    const signedIssuance = { ...await signIssuance(issuanceEvent, entity.privateKey, operational.privateKey, context), seq: 0 };
    const issuanceBytes = canonicalizeC2spEvent(signedIssuance, context);
    const prevState = { fqdn: issuanceEvent.domain, status: 'ACTIVE', entity_thumb: issuanceEvent.initialEntityThumbprint, operational_thumb: issuanceEvent.initialOperationalThumbprint };
    const revocation = {
      type: 'REVOCATION' as const,
      domain: 'agent.example.com',
      reason: 'keyCompromise' as const,
      timestamp: new Date(2000),
      seq: 1,
      prev_event_id: c2spEventId(signedC2spEntryBytes(issuanceBytes)),
      prev_state_hash: stateHash(prevState),
    };
    const revocationContext = { ...context, seq: 1, prevEventId: c2spEventId(signedC2spEntryBytes(issuanceBytes)), prevStateHash: stateHash(prevState) };
    const signedRevocation = { ...revocation, signingKid: entity.publicJwk.kid, sig: await sign(signedC2spEventBytes(revocation, revocationContext), entity.privateKey) };
    const revocationBytes = canonicalizeC2spEvent(signedRevocation, revocationContext);
    const events: VerifiedLifecycleEvent[] = [
      { index: 0, leafHash: leafHash(issuanceBytes), bytes: issuanceBytes, event: signedIssuance },
      { index: 1, leafHash: leafHash(revocationBytes), bytes: revocationBytes, event: signedRevocation },
    ];
    await expect(verifyLifecycle(events, { ...context, signerKey: entity.publicJwk, checkpointIntegrationTimeMs: 10_000 })).resolves.toBeUndefined();
  });

  it('fails closed on an authenticated candidate with invalid chain fields', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const next = await es256Key('next');
    const issuanceEvent = await issuance(entity, operational);
    const context = { ...DEFAULT_CONTEXT, scope: 'public' };
    const signedIssuance = { ...await signIssuance(issuanceEvent, entity.privateKey, operational.privateKey, { ...context, seq: 0 }), seq: 0 };
    const issuanceBytes = canonicalizeC2spEvent(signedIssuance, { ...context, seq: 0 });
    const activeState = {
      fqdn: issuanceEvent.domain,
      status: 'ACTIVE',
      entity_thumb: issuanceEvent.initialEntityThumbprint,
      operational_thumb: issuanceEvent.initialOperationalThumbprint,
    };

    const rotation = {
      type: 'KEY_ROTATION' as const,
      domain: issuanceEvent.domain,
      previousOperationalKid: operational.publicJwk.kid,
      previousOperationalThumbprint: issuanceEvent.initialOperationalThumbprint,
      newOperationalKid: next.publicJwk.kid,
      newOperationalAlg: next.publicJwk.alg!,
      newOperationalPublicKey: next.publicJwk,
      newOperationalThumbprint: await jwkThumbprint(next.publicJwk),
      timestamp: new Date(2_000),
      seq: 2,
      prev_event_id: toBase64Url(new Uint8Array(32).fill(1)),
      prev_state_hash: stateHash(activeState),
    };
    const rotationContext = {
      ...context,
      seq: 2,
      prevEventId: rotation.prev_event_id,
      prevStateHash: rotation.prev_state_hash,
    };
    const rotationSignedBytes = signedC2spEventBytes(rotation, rotationContext);
    const signedRotation = {
      ...rotation,
      signingKid: operational.publicJwk.kid,
      sig: await sign(rotationSignedBytes, operational.privateKey),
      newOperationalProof: await sign(rotationSignedBytes, next.privateKey),
    };
    const rotationBytes = canonicalizeC2spEvent(signedRotation, rotationContext);

    await expect(verifyStreamLifecycle([
      { index: 0, bytes: issuanceBytes },
      { index: 2, bytes: rotationBytes },
    ], issuanceEvent.domain, {
      ...context,
      signerKey: entity.publicJwk,
      checkpointIntegrationTimeMs: 10_000,
    })).rejects.toMatchObject({
      message: expect.stringContaining('invalid seq'),
      errorCategory: 'CHAIN_CONTINUITY',
    });

    const malformed = JSON.parse(new TextDecoder().decode(rotationBytes));
    malformed.seq = 'not-an-integer';
    delete malformed.sigs;
    const malformedSignedBytes = canonicalBytes(malformed);
    malformed.sigs = {
      prev_op: { kid: operational.publicJwk.kid, sig: await sign(malformedSignedBytes, operational.privateKey) },
      new_op: { kid: next.publicJwk.kid, sig: await sign(malformedSignedBytes, next.privateKey) },
    };
    await expect(verifyStreamLifecycle([
      { index: 0, bytes: issuanceBytes },
      { index: 2, bytes: canonicalBytes(malformed) },
    ], issuanceEvent.domain, {
      ...context,
      signerKey: entity.publicJwk,
      checkpointIntegrationTimeMs: 10_000,
    })).rejects.toMatchObject({ errorCategory: 'CHAIN_CONTINUITY' });
  });

  it('ignores an unauthorized signed candidate without advancing the public chain', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const next = await es256Key('next');
    const issuanceEvent = await issuance(entity, operational);
    const context = { ...DEFAULT_CONTEXT, scope: 'public' };
    const signedIssuance = { ...await signIssuance(issuanceEvent, entity.privateKey, operational.privateKey, { ...context, seq: 0 }), seq: 0 };
    const issuanceBytes = canonicalizeC2spEvent(signedIssuance, { ...context, seq: 0 });
    const activeState = {
      fqdn: issuanceEvent.domain,
      status: 'ACTIVE',
      entity_thumb: issuanceEvent.initialEntityThumbprint,
      operational_thumb: issuanceEvent.initialOperationalThumbprint,
    };
    const chain = {
      ...context,
      seq: 1,
      prevEventId: c2spEventId(signedC2spEntryBytes(issuanceBytes)),
      prevStateHash: stateHash(activeState),
    };
    const unauthorizedRevocation = {
      type: 'REVOCATION' as const,
      domain: issuanceEvent.domain,
      reason: 'keyCompromise' as const,
      timestamp: new Date(2_000),
      seq: 1,
      prev_event_id: chain.prevEventId,
      prev_state_hash: chain.prevStateHash,
    };
    const signedUnauthorized = {
      ...unauthorizedRevocation,
      signingKid: operational.publicJwk.kid,
      sig: await sign(signedC2spEventBytes(unauthorizedRevocation, chain), operational.privateKey),
    };
    const unauthorizedBytes = canonicalizeC2spEvent(signedUnauthorized, chain);
    const rotation = {
      type: 'KEY_ROTATION' as const,
      domain: issuanceEvent.domain,
      previousOperationalKid: operational.publicJwk.kid,
      previousOperationalThumbprint: issuanceEvent.initialOperationalThumbprint,
      newOperationalKid: next.publicJwk.kid,
      newOperationalAlg: next.publicJwk.alg!,
      newOperationalPublicKey: next.publicJwk,
      newOperationalThumbprint: await jwkThumbprint(next.publicJwk),
      timestamp: new Date(3_000),
      seq: 1,
      prev_event_id: chain.prevEventId,
      prev_state_hash: chain.prevStateHash,
    };
    const rotationSignedBytes = signedC2spEventBytes(rotation, chain);
    const signedRotation = {
      ...rotation,
      signingKid: operational.publicJwk.kid,
      sig: await sign(rotationSignedBytes, operational.privateKey),
      newOperationalProof: await sign(rotationSignedBytes, next.privateKey),
    };
    const rotationBytes = canonicalizeC2spEvent(signedRotation, chain);

    const verified = await verifyStreamLifecycle([
      { index: 0, bytes: issuanceBytes },
      { index: 1, bytes: unauthorizedBytes },
      { index: 2, bytes: rotationBytes },
    ], issuanceEvent.domain, {
      ...context,
      signerKey: entity.publicJwk,
      checkpointIntegrationTimeMs: 10_000,
    });
    expect(verified.map(item => item.index)).toEqual([0, 2]);
  });

  it('fails closed on an authenticated additional ISSUANCE', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const replacementOperational = await es256Key('replacement-op');
    const first = await issuance(entity, operational);
    const firstSigned = await signIssuance(first, entity.privateKey, operational.privateKey);
    const firstBytes = canonicalizeC2spEvent(firstSigned);
    const second = await issuance(entity, replacementOperational);
    second.timestamp = new Date(2_000);
    const secondSigned = await signIssuance(second, entity.privateKey, replacementOperational.privateKey);
    const secondBytes = canonicalizeC2spEvent(secondSigned);

    await expect(verifyStreamLifecycle([
      { index: 0, bytes: firstBytes },
      { index: 1, bytes: secondBytes },
    ], first.domain, {
      signerKey: entity.publicJwk,
      checkpointIntegrationTimeMs: 10_000,
    })).rejects.toMatchObject({
      message: expect.stringContaining('duplicate ISSUANCE'),
      errorCategory: 'DUPLICATE_ISSUANCE',
    });
  });

  it('deduplicates independently re-signed identical payloads', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const event = await issuance(entity, operational);
    const firstBytes = canonicalizeC2spEvent(await signIssuance(event, entity.privateKey, operational.privateKey));
    const resignedBytes = canonicalizeC2spEvent(await signIssuance(event, entity.privateKey, operational.privateKey));
    expect(resignedBytes).not.toEqual(firstBytes);
    expect(leafHash(resignedBytes)).not.toEqual(leafHash(firstBytes));

    await expect(verifyStreamLifecycle([
      { index: 0, bytes: firstBytes },
      { index: 1, bytes: resignedBytes },
    ], event.domain, {
      signerKey: entity.publicJwk,
      checkpointIntegrationTimeMs: 10_000,
    })).resolves.toHaveLength(1);
  });

  it('stitches verified prior history for inbound migration exactly once', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const priorIssuance = await issuance(entity, operational);
    const migration = {
      type: 'MIGRATION' as const,
      domain: priorIssuance.domain,
      previousLog: 'c2sp-tlog:public:https://old.example/log#agent.example.com',
      newLog: 'c2sp-tlog:public:https://new.example/log#agent.example.com',
      finalEntryRef: 'c2sp-tlog:public:https://old.example/log#agent.example.com@10',
      timestamp: new Date(2_000),
    };

    const stitched = await stitchVerifiedMigrationHistory(priorIssuance.domain, [migration], {
      entityKey: entity.publicJwk,
      activeOperationalKey: operational.publicJwk,
      priorHistory: [priorIssuance],
      priorHistoryReferences: [migration.finalEntryRef],
    });

    expect(stitched).toEqual([priorIssuance, migration]);
    await expect(stitchVerifiedMigrationHistory(priorIssuance.domain, [migration], {
      entityKey: entity.publicJwk,
      activeOperationalKey: operational.publicJwk,
      priorHistory: [priorIssuance],
    })).resolves.toEqual([priorIssuance, migration]);
    await expect(stitchVerifiedMigrationHistory(priorIssuance.domain, [migration], {
      entityKey: entity.publicJwk,
      activeOperationalKey: operational.publicJwk,
      priorHistory: [],
    })).rejects.toMatchObject({
      message: expect.stringContaining('requires stitched verified prior-log history'),
      errorCategory: 'INVALID_MIGRATION',
    });
    await expect(stitchVerifiedMigrationHistory(priorIssuance.domain, [migration], {
      entityKey: entity.publicJwk,
      activeOperationalKey: operational.publicJwk,
      priorHistory: [priorIssuance, migration],
    })).rejects.toThrow('exactly once');
    await expect(stitchVerifiedMigrationHistory(priorIssuance.domain, [migration], {
      entityKey: entity.publicJwk,
      activeOperationalKey: operational.publicJwk,
      priorHistory: [priorIssuance],
      priorHistoryReferences: ['malformed'],
    })).rejects.toMatchObject({ errorCategory: 'INVALID_MIGRATION' });
    await expect(stitchVerifiedMigrationHistory(priorIssuance.domain, [migration], {
      entityKey: entity.publicJwk,
      activeOperationalKey: operational.publicJwk,
      priorHistory: [priorIssuance],
      priorHistoryReferences: [`${migration.previousLog}@9`],
    })).rejects.toThrow('signed prev_ref');
    const wrongLogCutoff = { ...migration, finalEntryRef: 'c2sp-tlog:public:https://other.example/log#agent.example.com@10' };
    await expect(stitchVerifiedMigrationHistory(priorIssuance.domain, [wrongLogCutoff], {
      entityKey: entity.publicJwk,
      activeOperationalKey: operational.publicJwk,
      priorHistory: [priorIssuance],
      priorHistoryReferences: [wrongLogCutoff.finalEntryRef],
    })).rejects.toThrow('does not belong');
    const priorDelegation: LogEvent = {
      type: 'DELEGATION',
      domain: priorIssuance.domain,
      delegatee: 'delegate.example.com',
      scope: 'test',
      expiry: new Date(10_000),
      timestamp: new Date(1_500),
    };
    await expect(stitchVerifiedMigrationHistory(priorIssuance.domain, [migration], {
      entityKey: entity.publicJwk,
      activeOperationalKey: operational.publicJwk,
      priorHistory: [priorIssuance, priorDelegation],
      priorHistoryReferences: [
        'c2sp-tlog:public:https://other.example/log#agent.example.com@9',
        migration.finalEntryRef,
      ],
    })).rejects.toThrow('does not belong');

    for (const terminal of ['REVOCATION', 'RETIREMENT'] as const) {
      const event: LogEvent = terminal === 'REVOCATION'
        ? { type: terminal, domain: priorIssuance.domain, reason: 'keyCompromise', timestamp: new Date(1_500) }
        : { type: terminal, domain: priorIssuance.domain, timestamp: new Date(1_500) };
      await expect(stitchVerifiedMigrationHistory(priorIssuance.domain, [migration], {
        entityKey: entity.publicJwk,
        activeOperationalKey: operational.publicJwk,
        priorHistory: [priorIssuance, event],
      })).rejects.toMatchObject({ errorCategory: 'INVALID_MIGRATION' });
    }
  });

  it('rejects inbound migration when prior history cannot be verified', async () => {
    const entity = await es256Key('entity');
    const migration = {
      type: 'MIGRATION' as const,
      domain: 'agent.example.com',
      previousLog: 'c2sp-tlog:public:https://old.example/log#agent.example.com',
      newLog: 'c2sp-tlog:public:https://new.example/log#agent.example.com',
      finalEntryRef: 'c2sp-tlog:public:https://old.example/log#agent.example.com@10',
      timestamp: new Date(2_000),
    };
    expect(() => prepareC2spTlogEventForSigning(migration, migration.previousLog, {
      sequence: 1,
      previousEventId: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      previousStateHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    })).toThrow('new_lr must match the bound reference');
    const signedMigration = {
      ...migration,
      signingKid: entity.publicJwk.kid,
      sig: await sign(signedC2spEventBytes(migration), entity.privateKey),
    };

    await expect(verifyStreamLifecycle([
      { index: 0, bytes: canonicalizeC2spEvent(signedMigration) },
    ], migration.domain, {
      signerKey: entity.publicJwk,
      checkpointIntegrationTimeMs: 10_000,
      verifyMigration: async () => {
        throw new C2spTlogVerificationError('prior history unavailable', 'INVALID_MIGRATION');
      },
    })).rejects.toMatchObject({
      errorCategory: 'INVALID_MIGRATION',
    });
  });

  it('rejects outbound migration appended after genesis', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const issuanceEvent = await issuance(entity, operational);
    const signedIssuance = await signIssuance(issuanceEvent, entity.privateKey, operational.privateKey);
    const migration = {
      type: 'MIGRATION' as const,
      domain: issuanceEvent.domain,
      previousLog: 'c2sp-tlog:public:https://old.example/log#old-instance',
      newLog: 'other-method:new-instance',
      finalEntryRef: 'c2sp-tlog:public:https://old.example/log#old-instance@0',
      timestamp: new Date(2_000),
    };
    const signedMigration = {
      ...migration,
      signingKid: entity.publicJwk.kid,
      sig: await sign(signedC2spEventBytes(migration), entity.privateKey),
    };
    const issuanceBytes = canonicalizeC2spEvent(signedIssuance);
    const migrationBytes = canonicalizeC2spEvent(signedMigration);

    await expect(verifyStreamLifecycle([
      { index: 0, bytes: issuanceBytes },
      { index: 1, bytes: migrationBytes },
    ], issuanceEvent.domain, {
      signerKey: entity.publicJwk,
      checkpointIntegrationTimeMs: 10_000,
    })).rejects.toMatchObject({
      errorCategory: 'INVALID_MIGRATION',
    });
  });

  it('rejects a rotation that does not continue from the active operational key', async () => {
    const entity = await es256Key('entity');
    const active = await es256Key('active');
    const unrelated = await es256Key('unrelated');
    const next = await es256Key('next');
    const issuanceEvent = await issuance(entity, active);
    const signedIssuance = await signIssuance(issuanceEvent, entity.privateKey, active.privateKey);
    const issuanceBytes = canonicalizeC2spEvent(signedIssuance);
    const rotation = {
      type: 'KEY_ROTATION' as const,
      domain: issuanceEvent.domain,
      previousOperationalKid: unrelated.publicJwk.kid,
      previousOperationalThumbprint: await jwkThumbprint(unrelated.publicJwk),
      newOperationalKid: next.publicJwk.kid,
      newOperationalAlg: next.publicJwk.alg!,
      newOperationalPublicKey: next.publicJwk,
      newOperationalThumbprint: await jwkThumbprint(next.publicJwk),
      timestamp: new Date(2000),
    };
    const rotationSignedBytes = signedC2spEventBytes(rotation);
    const signedRotation = { ...rotation, signingKid: unrelated.publicJwk.kid, sig: await sign(rotationSignedBytes, unrelated.privateKey), newOperationalProof: await sign(rotationSignedBytes, next.privateKey) };
    const rotationBytes = canonicalizeC2spEvent(signedRotation);
    await expect(verifyLifecycle([
      { index: 0, leafHash: leafHash(issuanceBytes), bytes: issuanceBytes, event: signedIssuance },
      { index: 1, leafHash: leafHash(rotationBytes), bytes: rotationBytes, event: signedRotation },
    ], { signerKey: entity.publicJwk, checkpointIntegrationTimeMs: 10_000 })).rejects.toThrow('does not match active key');
  });

  it('rejects rotation to the already-active operational key', async () => {
    const entity = await es256Key('entity');
    const active = await es256Key('active');
    const issuanceEvent = await issuance(entity, active);
    const signedIssuance = await signIssuance(issuanceEvent, entity.privateKey, active.privateKey);
    const issuanceBytes = canonicalizeC2spEvent(signedIssuance);
    const rotation = {
      type: 'KEY_ROTATION' as const,
      domain: issuanceEvent.domain,
      previousOperationalKid: active.publicJwk.kid,
      previousOperationalThumbprint: issuanceEvent.initialOperationalThumbprint,
      newOperationalKid: active.publicJwk.kid,
      newOperationalAlg: active.publicJwk.alg!,
      newOperationalPublicKey: active.publicJwk,
      newOperationalThumbprint: issuanceEvent.initialOperationalThumbprint,
      timestamp: new Date(2_000),
    };
    const signedBytes = signedC2spEventBytes(rotation);
    const signedRotation = {
      ...rotation,
      signingKid: active.publicJwk.kid,
      sig: await sign(signedBytes, active.privateKey),
      newOperationalProof: await sign(signedBytes, active.privateKey),
    };
    const rotationBytes = canonicalizeC2spEvent(signedRotation);
    await expect(verifyLifecycle([
      { index: 0, leafHash: leafHash(issuanceBytes), bytes: issuanceBytes, event: signedIssuance },
      { index: 1, leafHash: leafHash(rotationBytes), bytes: rotationBytes, event: signedRotation },
    ], { signerKey: entity.publicJwk, checkpointIntegrationTimeMs: 10_000 }))
      .rejects.toThrow('must differ from active key');
  });

  it('ignores an invalid-signature candidate and applies a later valid event once', async () => {
    const entity = await es256Key('entity');
    const active = await es256Key('active');
    const next = await es256Key('next');
    const issuanceEvent = await issuance(entity, active);
    issuanceEvent.timestamp = new Date(3000);
    const signedIssuance = await signIssuance(issuanceEvent, entity.privateKey, active.privateKey);
    const issuanceBytes = canonicalizeC2spEvent(signedIssuance);

    const invalidRevocation = {
      type: 'REVOCATION' as const,
      domain: issuanceEvent.domain,
      reason: 'keyCompromise' as const,
      timestamp: new Date(2000),
    };
    const invalidSignedBytes = signedC2spEventBytes(invalidRevocation);
    const invalidSigned = { ...invalidRevocation, signingKid: active.publicJwk.kid, sig: await sign(invalidSignedBytes, active.privateKey) };
    const invalidBytes = canonicalizeC2spEvent(invalidSigned);
    // The unauthorized entry does not become the next logical predecessor.
    previousEntry = issuanceBytes;
    previousSequence = 0;
    previousState = { fqdn: issuanceEvent.domain, status: 'ACTIVE', entity_thumb: issuanceEvent.initialEntityThumbprint, operational_thumb: issuanceEvent.initialOperationalThumbprint };

    const rotation = {
      type: 'KEY_ROTATION' as const,
      domain: issuanceEvent.domain,
      previousOperationalKid: active.publicJwk.kid,
      previousOperationalThumbprint: await jwkThumbprint(active.publicJwk),
      newOperationalKid: next.publicJwk.kid,
      newOperationalAlg: next.publicJwk.alg!,
      newOperationalPublicKey: next.publicJwk,
      newOperationalThumbprint: await jwkThumbprint(next.publicJwk),
      timestamp: new Date(1000),
    };
    const rotationSignedBytes = signedC2spEventBytes(rotation);
    const signedRotation = {
      ...rotation,
      signingKid: active.publicJwk.kid,
      sig: await sign(rotationSignedBytes, active.privateKey),
      newOperationalProof: await sign(rotationSignedBytes, next.privateKey),
    };
    const rotationBytes = canonicalizeC2spEvent(signedRotation);

    const verified = await verifyStreamLifecycle([
      { index: 13, bytes: rotationBytes },
      { index: 11, bytes: invalidBytes },
      { index: 10, bytes: issuanceBytes },
      { index: 12, bytes: rotationBytes },
    ], issuanceEvent.domain, { signerKey: entity.publicJwk, checkpointIntegrationTimeMs: 10_000 });
    expect(verified.map(event => event.index)).toEqual([10, 12]);
    expect(verified.map(event => event.event.timestamp.getTime())).toEqual([3000, 1000]);
  });

  it('rejects an authenticated candidate after a valid terminal event', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const next = await es256Key('next');
    const issuanceEvent = await issuance(entity, operational);
    const signedIssuance = await signIssuance(issuanceEvent, entity.privateKey, operational.privateKey);
    const issuanceBytes = canonicalizeC2spEvent(signedIssuance);
    const revocation = {
      type: 'REVOCATION' as const,
      domain: issuanceEvent.domain,
      reason: 'keyCompromise' as const,
      timestamp: new Date(2_000),
    };
    const signedRevocation = {
      ...revocation,
      signingKid: entity.publicJwk.kid,
      sig: await sign(signedC2spEventBytes(revocation), entity.privateKey),
    };
    const revocationBytes = canonicalizeC2spEvent(signedRevocation);
    const rotation = {
      type: 'KEY_ROTATION' as const,
      domain: issuanceEvent.domain,
      previousOperationalKid: operational.publicJwk.kid,
      previousOperationalThumbprint: issuanceEvent.initialOperationalThumbprint,
      newOperationalKid: next.publicJwk.kid,
      newOperationalAlg: next.publicJwk.alg!,
      newOperationalPublicKey: next.publicJwk,
      newOperationalThumbprint: await jwkThumbprint(next.publicJwk),
      timestamp: new Date(3_000),
    };
    const rotationSignedBytes = signedC2spEventBytes(rotation);
    const signedRotation = {
      ...rotation,
      signingKid: operational.publicJwk.kid,
      sig: await sign(rotationSignedBytes, operational.privateKey),
      newOperationalProof: await sign(rotationSignedBytes, next.privateKey),
    };
    const rotationBytes = canonicalizeC2spEvent(signedRotation);

    await expect(verifyStreamLifecycle([
      { index: 0, bytes: issuanceBytes },
      { index: 1, bytes: revocationBytes },
      { index: 2, bytes: rotationBytes },
    ], issuanceEvent.domain, {
      signerKey: entity.publicJwk,
      checkpointIntegrationTimeMs: 10_000,
    })).rejects.toMatchObject({
      errorCategory: 'TERMINAL_STATE',
    });
  });

  it('ignores malformed, unsupported, cross-stream, wrong-domain, and invalid-signature global candidates', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const event = await issuance(entity, operational);
    const lr = `c2sp-tlog:public:https://log.example/dnsid#${TEST_STREAM_ID}`;
    const context = { scope: 'public', logOrigin: 'log.example/dnsid', streamId: TEST_STREAM_ID, lr, seq: 0 };
    const signed = { ...await signIssuance(event, entity.privateKey, operational.privateKey, context), seq: 0 };
    const validBytes = canonicalizeC2spEvent(signed, context);

    const wrongDomainEvent = { ...event, domain: 'other.example.com' };
    const wrongDomainSigned = { ...await signIssuance(wrongDomainEvent, entity.privateKey, operational.privateKey, context), seq: 0 };
    const wrongDomainBytes = canonicalizeC2spEvent(wrongDomainSigned, context);
    const wrongContext = { ...context, logOrigin: 'other-log.example/dnsid' };
    const wrongContextSigned = { ...await signIssuance(event, entity.privateKey, operational.privateKey, wrongContext), seq: 0 };
    const wrongContextBytes = canonicalizeC2spEvent(wrongContextSigned, wrongContext);
    const invalidSignatureEnvelope = JSON.parse(new TextDecoder().decode(validBytes)) as Record<string, unknown>;
    const invalidSignatures = invalidSignatureEnvelope.sigs as Record<string, { kid: string; sig: string }>;
    invalidSignatures.ae = { ...invalidSignatures.ae!, sig: 'AA' };
    const invalidSignatureBytes = canonicalBytes(invalidSignatureEnvelope);

    const verified = await verifyStreamLifecycle([
      { index: 0, bytes: new TextEncoder().encode('not a DNSid entry') },
      { index: 1, bytes: canonicalBytes({ v: 2, kind: 'dnsid.lifecycle', type: 'ISSUANCE' }) },
      { index: 2, bytes: canonicalBytes({ v: 1, kind: 'dnsid.lifecycle', type: 'FUTURE', fqdn: event.domain, ts: 1, sigs: {} }) },
      { index: 3, bytes: wrongContextBytes },
      { index: 4, bytes: wrongDomainBytes },
      { index: 5, bytes: invalidSignatureBytes },
      { index: 6, bytes: validBytes },
    ], event.domain, { ...context, signerKey: entity.publicJwk, checkpointIntegrationTimeMs: 10_000 });

    expect(verified.map(item => item.index)).toEqual([6]);
  });

  it('round-trips DELEGATION expiry as a Date', async () => {
    const entity = await es256Key('entity');
    const event = {
      type: 'DELEGATION' as const,
      domain: 'agent.example.com',
      delegatee: 'delegate.example.com',
      scope: 'publish',
      expiry: new Date(50_000),
      timestamp: new Date(10_000),
    };
    const signed = { ...event, signingKid: entity.publicJwk.kid, sig: await sign(signedC2spEventBytes(event), entity.privateKey) };
    const parsed = await parseC2spEventEntry(canonicalizeC2spEvent(signed));
    expect(parsed.type).toBe('DELEGATION');
    if (parsed.type === 'DELEGATION') expect(parsed.expiry).toEqual(new Date(50_000));
  });

  it('shares one lifecycle snapshot while refreshing non-revocation evidence', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const lr = `c2sp-tlog:testnet:https://log.example/tlog#${TEST_STREAM_ID}`;
    const origin = 'log.example/tlog';
    const context = { scope: 'testnet', logOrigin: origin, streamId: TEST_STREAM_ID, lr };
    const issuanceEvent = await issuance(entity, operational);
    issuanceEvent.governanceId = 'example.com';
    const signed = await signIssuance(issuanceEvent, entity.privateKey, operational.privateKey, context);
    const entryBytes = canonicalizeC2spEvent(signed, context);
    const rootHash = merkleRootFromEntries([entryBytes]);

    const { publicKey: logPublicKey, privateKey: logPrivateKey } = generateKeyPairSync('ed25519');
    const logPublicJwk = logPublicKey.export({ format: 'jwk' });
    const logPublicBytes = Buffer.from(logPublicJwk.x!, 'base64url');
    const logType = Buffer.from([0x01]);
    const logKeyId = createHash('sha256').update(origin).update('\n').update(logType).update(logPublicBytes).digest().subarray(0, 4);
    const signedText = `${origin}\n1\n${Buffer.from(rootHash).toString('base64')}\n`;
    const { publicKey: witnessPublicKey, privateKey: witnessPrivateKey } = generateKeyPairSync('ed25519');
    const witnessName = 'witness.example';
    const witnessPublicBytes = Buffer.from(witnessPublicKey.export({ format: 'jwk' }).x!, 'base64url');
    const witnessType = Buffer.from([0x04]);
    const witnessKeyId = createHash('sha256').update(witnessName).update('\n').update(witnessType).update(witnessPublicBytes).digest().subarray(0, 4);
    const witnessTimestamp = BigInt(Math.floor(Date.now() / 1000));
    const witnessTimestampBytes = Buffer.alloc(8);
    witnessTimestampBytes.writeBigUInt64BE(witnessTimestamp);
    const witnessSignature = signEd25519(null, Buffer.from(`cosignature/v1\ntime ${witnessTimestamp}\n${signedText}`), witnessPrivateKey);
    const checkpoint = {
      origin, treeSize: 1, rootHash, signedText,
      signatures: [
        { name: origin, keyHash: new Uint8Array(logKeyId), signature: new Uint8Array(signEd25519(null, Buffer.from(signedText), logPrivateKey)), raw: '' },
        { name: witnessName, keyHash: new Uint8Array(witnessKeyId), signature: new Uint8Array(Buffer.concat([witnessTimestampBytes, witnessSignature])), raw: '' },
      ],
    };
    const evidence = { checkpoint, entries: [{ index: 0, bytes: entryBytes }], complete: true };
    const streamSource = { load: vi.fn().mockResolvedValue(evidence) };
    const logKey = { name: origin, kind: 'ed25519' as const, keyBytes: new Uint8Array(logPublicBytes), keyId: new Uint8Array(logKeyId), signatureType: new Uint8Array([0x01]) };
    const witnessKey = { name: witnessName, kind: 'ed25519' as const, keyBytes: new Uint8Array(witnessPublicBytes), keyId: new Uint8Array(witnessKeyId), signatureType: new Uint8Array([0x04]) };
    const reader = new C2spTlogReader(lr, {
      policy: { scope: 'testnet', origins: { [origin]: { logKeys: [logKey], witnessKeys: [witnessKey], quorum: 1 } } },
      streamSource, entityKey: entity.publicJwk, checkpointMaxAge: 60_000, allowedClockSkew: 1000,
    });
    const record = new DnsIdTxtRecord();
    record.agentFQDN = issuanceEvent.domain;
    record.gi = issuanceEvent.governanceId;

    const binding = await reader.verifyBilateralBinding(record, entity.publicJwk, operational.publicJwk);
    await expect(reader.verifyOperationalContinuity(issuanceEvent.domain, binding.initialOperationalThumbprint, issuanceEvent.initialOperationalThumbprint))
      .resolves.toBeUndefined();
    await expect(reader.keyTimestamp(issuanceEvent.domain, issuanceEvent.initialOperationalThumbprint))
      .resolves.toEqual(issuanceEvent.timestamp);
    expect(streamSource.load).toHaveBeenCalledOnce();

    const nonRevocation = await reader.verifyNonRevocation(issuanceEvent.domain, new Date());
    expect(nonRevocation).toEqual({
      logReference: lr,
      loggedState: 'ACTIVE',
      historyStart: `${lr}@0`,
      historyEnd: `${lr}@0`,
      completeThrough: '1',
      completenessMode: 'full-scan',
      checkpoint: expect.any(Uint8Array),
      freshnessTime: new Date(Number(witnessTimestamp) * 1000),
    });
    expect(parseCheckpoint(new TextDecoder().decode(nonRevocation.checkpoint))).toMatchObject({ origin, treeSize: 1 });
    streamSource.load.mockResolvedValueOnce({ ...evidence, complete: false });
    await expect(reader.verifyNonRevocation(issuanceEvent.domain, new Date()))
      .rejects.toMatchObject({ message: expect.stringContaining('incomplete'), errorCategory: 'INCOMPLETE_STREAM' });
    streamSource.load.mockResolvedValueOnce({ ...evidence, entries: [{ index: 0, bytes: new TextEncoder().encode('poison') }] });
    await expect(reader.verifyNonRevocation(issuanceEvent.domain, new Date()))
      .rejects.toMatchObject({ message: expect.stringContaining('checkpoint root'), errorCategory: 'INVALID_EVIDENCE' });
    const dateNow = vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 60_001);
    await expect(reader.verifyNonRevocation(issuanceEvent.domain, new Date())).rejects.toThrow('too stale');
    dateNow.mockRestore();
    const unavailable = new Error('source offline');
    streamSource.load.mockRejectedValueOnce(unavailable);
    await expect(reader.verifyNonRevocation(issuanceEvent.domain, new Date()))
      .rejects.toMatchObject({ code: 'LogError', transient: true, cause: unavailable });
    expect(streamSource.load).toHaveBeenCalledTimes(6);
  });

  it('rejects complete terminal histories for binding, continuity, and non-revocation', async () => {
    const entity = await es256Key('entity');
    const operational = await es256Key('op');
    const issuanceEvent = await issuance(entity, operational);
    const revokedHistory: LogEvent[] = [issuanceEvent, {
      type: 'REVOCATION', domain: issuanceEvent.domain, reason: 'keyCompromise', timestamp: new Date(2_000),
    }];
    const retiredHistory: LogEvent[] = [issuanceEvent, {
      type: 'RETIREMENT', domain: issuanceEvent.domain, timestamp: new Date(2_000),
    }];
    const reader = new C2spTlogReader(
      'c2sp-tlog:testnet:https://log.example/tlog#agent.example.com',
      {
        policy: { scope: 'testnet', origins: {} },
        streamSource: { load: async () => { throw new Error('not used'); } },
        entityKey: entity.publicJwk,
        checkpointMaxAge: 60_000,
      },
    );
    const internal = reader as unknown as {
      loadCompleteHistory(domain: string): Promise<{ events: LogEvent[]; checkpointWitnessTime: Date }>;
      loadAndVerifyHistory(domain: string, entityKey: DnsIdJWK): Promise<{ events: LogEvent[]; checkpointWitnessTime: Date; migrated?: boolean }>;
    };
    const load = vi.spyOn(internal, 'loadCompleteHistory').mockResolvedValue({
      events: revokedHistory,
      checkpointWitnessTime: new Date(),
    });
    const record = new DnsIdTxtRecord();
    record.agentFQDN = issuanceEvent.domain;
    record.gi = issuanceEvent.governanceId;

    await expect(reader.verifyBilateralBinding(record, entity.publicJwk, operational.publicJwk)).rejects.toThrow('REVOKED');
    await expect(reader.verifyOperationalContinuity(
      issuanceEvent.domain,
      issuanceEvent.initialOperationalThumbprint,
      issuanceEvent.initialOperationalThumbprint,
    )).rejects.toThrow('REVOKED');
    const freshLoad = vi.spyOn(internal, 'loadAndVerifyHistory').mockResolvedValue({ events: revokedHistory, checkpointWitnessTime: new Date() });
    await expect(reader.verifyNonRevocation(issuanceEvent.domain, new Date())).rejects.toThrow('revoked');

    freshLoad.mockResolvedValue({ events: retiredHistory, checkpointWitnessTime: new Date() });
    await expect(reader.verifyNonRevocation(issuanceEvent.domain, new Date())).rejects.toThrow('retired');

    freshLoad.mockResolvedValue({ events: [issuanceEvent], checkpointWitnessTime: new Date() });
    await expect(reader.verifyNonRevocation(issuanceEvent.domain, new Date()))
      .rejects.toMatchObject({ message: expect.stringContaining('no verified history bounds'), errorCategory: 'INVALID_EVIDENCE' });
  });
});
