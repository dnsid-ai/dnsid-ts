import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, sign, verify, createPublicKey, type KeyObject } from 'node:crypto';
import {
  AwsKmsKeyProvider, createOrReuseAwsKmsKeyProvider,
  type AwsKmsBootstrapFacade, type AwsKmsSigningAlgorithm,
  type AwsKmsCreateSigningKeyInput, type AwsKmsGetPublicKeyInput,
  type AwsKmsCreateAliasInput, type AwsKmsSignInput,
} from '@dnsid-ai/key-aws';

// Explicit alias bootstrap reuses the validated winner and preserves native errors.
// Contract: packages/key-aws/README.md — Explicit create or reuse.
// Every case: Mode: fake-only (KMS faults and deterministic schedules).
// No AWS calls. Crypto is real Node crypto, not a mocked verification result.
// ES256 output: compliance 07, profile signature semantics: 64-byte JWA R || S.
// Non-destructive partial scope only: losing-candidate lifecycle is DEFERRED.
const variants = [
  { algorithm: 'ECDSA_SHA_256', spec: 'ECC_NIST_P256', alg: 'ES256' },
  { algorithm: 'ED25519_SHA_512', spec: 'ECC_NIST_EDWARDS25519', alg: 'EdDSA' },
] as const;
type Variant = typeof variants[number];
const alias = 'alias/Caller-Selected_62';
const payload = Buffer.from('independent AWS bootstrap winner proof');
const fault = (name: string) => Object.assign(new Error(`fixture ${name}`), { name });
function latch() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => { release = resolve; });
  return { promise, release };
}
type Material = { privateKey: KeyObject; publicKey: KeyObject; spec: string; algorithm: AwsKmsSigningAlgorithm };
type PublicResponse = Awaited<ReturnType<AwsKmsBootstrapFacade['getPublicKey']>>;

class Kms implements AwsKmsBootstrapFacade {
  keys = new Map<string, Material>();
  aliases = new Map<string, string>();
  ledger: { action: string; input: any }[] = [];
  next = 1;
  readFault?: (input: AwsKmsGetPublicKeyInput, ordinal: number) => unknown;
  readTransform?: (value: PublicResponse, input: AwsKmsGetPublicKeyInput) => PublicResponse;
  createFault?: unknown;
  aliasFault?: unknown;
  signFault?: unknown;
  commitBeforeAliasFault = false;
  conflictWinner?: string;
  // Two callers both see missing; both reach acquisition before the chosen caller wins.
  race?: { first: number; initialReads: number; arrivals: number; reads: ReturnType<typeof latch>; acquisitions: ReturnType<typeof latch>; published: ReturnType<typeof latch> };
  constructor(readonly v: Variant) {}
  seed() {
    const id = `00000000-0000-4000-8000-${String(this.next++).padStart(12, '0')}`;
    const pair = this.v.alg === 'ES256'
      ? generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
      : generateKeyPairSync('ed25519');
    this.keys.set(id, { ...pair, spec: this.v.spec, algorithm: this.v.algorithm });
    return id;
  }
  async createSigningKey(input: AwsKmsCreateSigningKeyInput) {
    this.ledger.push({ action: 'create', input });
    if (this.createFault) throw this.createFault;
    expect(input.keySpec).toBe(this.v.spec);
    return { keyId: this.seed() };
  }
  async getPublicKey(input: AwsKmsGetPublicKeyInput): Promise<PublicResponse> {
    this.ledger.push({ action: 'get', input });
    const ordinal = this.ledger.filter((x) => x.action === 'get' && x.input.keyId === alias).length;
    const error = this.readFault?.(input, ordinal);
    if (error) throw error;
    if (input.keyId === alias && this.race && this.race.initialReads < 2) {
      if (++this.race.initialReads === 2) this.race.reads.release();
      await this.race.reads.promise;
      throw fault('NotFoundException');
    }
    const id = this.aliases.get(input.keyId) ?? input.keyId;
    const key = this.keys.get(id);
    if (!key) throw fault('NotFoundException');
    const response = {
      keyId: id, publicKey: key.publicKey.export({ type: 'spki', format: 'der' }),
      keyUsage: 'SIGN_VERIFY', keySpec: key.spec, signingAlgorithms: [key.algorithm],
    };
    return this.readTransform?.(response, input) ?? response;
  }
  async createAlias(input: AwsKmsCreateAliasInput) {
    this.ledger.push({ action: 'alias', input });
    if (this.race) {
      const arrival = this.race.arrivals++;
      if (this.race.arrivals === 2) this.race.acquisitions.release();
      await this.race.acquisitions.promise;
      if (arrival !== this.race.first) await this.race.published.promise;
      else { this.aliases.set(input.aliasName, input.targetKeyId); this.race.published.release(); return; }
    }
    if (this.conflictWinner) this.aliases.set(input.aliasName, this.conflictWinner);
    if (this.aliasFault) {
      if (this.commitBeforeAliasFault) this.aliases.set(input.aliasName, input.targetKeyId);
      throw this.aliasFault;
    }
    if (this.aliases.has(input.aliasName)) throw fault('AlreadyExistsException');
    this.aliases.set(input.aliasName, input.targetKeyId);
  }
  async sign(input: AwsKmsSignInput) {
    this.ledger.push({ action: 'sign', input });
    if (this.signFault) throw this.signFault;
    const key = this.keys.get(input.keyId)!;
    expect(input.signingAlgorithm).toBe(key.algorithm);
    expect(input.messageType).toBe('RAW'); // this suite uses short payloads only
    return {
      keyId: input.keyId, signingAlgorithm: key.algorithm,
      // AWS ECDSA wire signatures are DER; the provider exposes JWA R || S.
      signature: sign(this.v.alg === 'ES256' ? 'sha256' : null, input.message, key.privateKey),
    };
  }
  async scheduleKeyDeletion(input: unknown) { this.ledger.push({ action: 'delete', input }); }
  async disableKey(input: unknown) { this.ledger.push({ action: 'disable', input }); }
  async updateAlias(input: unknown) { this.ledger.push({ action: 'retarget', input }); }
  async deleteAlias(input: unknown) { this.ledger.push({ action: 'deleteAlias', input }); }
}
function safe(kms: Kms) {
  expect(kms.ledger.filter((x) => ['delete', 'disable', 'retarget', 'deleteAlias'].includes(x.action))).toEqual([]);
}
async function provesWinner(provider: AwsKmsKeyProvider, id: string, kms: Kms) {
  const jwk = await provider.signingKey();
  const expected = kms.keys.get(id)!.publicKey.export({ format: 'jwk' });
  expect(jwk).toMatchObject({ ...expected, kid: id, alg: kms.v.alg });
  for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k']) expect(jwk).not.toHaveProperty(field);
  expect(provider.stateSnapshot().activeKeyId).toBe(id);
  expect(await provider.listKeyIds()).toEqual([id]);
  const signature = await provider.sign(payload);
  expect(signature).toHaveLength(64);
  const publicKey = createPublicKey({ key: jwk, format: 'jwk' });
  const options = kms.v.alg === 'ES256' ? { key: publicKey, dsaEncoding: 'ieee-p1363' as const } : publicKey;
  expect(verify(kms.v.alg === 'ES256' ? 'sha256' : null, payload, options, signature)).toBe(true);
  for (const [otherId, other] of kms.keys) {
    if (otherId === id) continue;
    const otherOptions = kms.v.alg === 'ES256' ? { key: other.publicKey, dsaEncoding: 'ieee-p1363' as const } : other.publicKey;
    expect(verify(kms.v.alg === 'ES256' ? 'sha256' : null, payload, otherOptions, signature)).toBe(false);
  }
  expect(kms.ledger.filter((x) => x.action === 'sign').at(-1)?.input.keyId).toBe(id);
  safe(kms);
}
function open(kms: Kms) { return createOrReuseAwsKmsKeyProvider(kms, { aliasName: alias, algorithm: kms.v.algorithm }); }

for (const v of variants) {
  describe(`PRE unchanged ${v.alg} [fake-only]`, () => {
    it('Given an existing alias, when ordinary load opens it, then no creation occurs and it signs with that key', async () => {
      const kms = new Kms(v); const id = kms.seed(); kms.aliases.set(alias, id);
      const provider = await AwsKmsKeyProvider.load(kms, { activeKeyId: alias, algorithm: v.algorithm });
      await provesWinner(provider, id, kms);
      expect(kms.ledger.filter((x) => ['create', 'alias'].includes(x.action))).toEqual([]);
    });
    it('Given a missing key, when ordinary load opens it, then it fails without generation', async () => {
      const kms = new Kms(v);
      await expect(AwsKmsKeyProvider.load(kms, { activeKeyId: alias, algorithm: v.algorithm })).rejects.toMatchObject({ name: 'NotFoundException' });
      expect(kms.ledger.map((x) => x.action)).toEqual(['get']); safe(kms);
    });
    it('Given an active key, when generation is explicit twice, then both keys are fresh pending and ordinary signing remains unchanged', async () => {
      const kms = new Kms(v); const id = kms.seed();
      const provider = await AwsKmsKeyProvider.load(kms, { activeKeyId: id, algorithm: v.algorithm });
      const a = await provider.generateKey(); const b = await provider.generateKey();
      expect(new Set([id, a, b]).size).toBe(3);
      expect(provider.stateSnapshot().pendingKeyIds).toEqual(expect.arrayContaining([a, b]));
      await provesWinner(provider, id, kms);
      expect(kms.ledger.filter((x) => x.action === 'create')).toHaveLength(2);
      expect(kms.ledger.filter((x) => x.action === 'alias')).toEqual([]);
    });
  });

  describe(`BOOTSTRAP ${v.alg} [fake-only]`, () => {
    it('Given an existing winner, when reused, then canonical keyRef, public JWK and real signature all identify the winner', async () => {
      const kms = new Kms(v); const id = kms.seed(); kms.seed(); kms.aliases.set(alias, id);
      const pending = open(kms);
      await expect(pending).resolves.toMatchObject({ keyRef: id });
      const result = await pending;
      expect(result.keyRef).toBe(id);
      expect(Object.keys(result).sort()).toEqual(['keyProvider', 'keyRef']);
      await provesWinner(result.keyProvider, id, kms);
      expect(kms.ledger.filter((x) => ['create', 'alias'].includes(x.action))).toEqual([]);
    });
    it('Given a missing alias, when explicitly bootstrapped and reopened by a fresh caller, then exact alias acquires one usable winner', async () => {
      const kms = new Kms(v);
      const first = await open(kms); const fresh = await open(kms);
      expect(first.keyRef).toBe(kms.aliases.get(alias)); expect(fresh.keyRef).toBe(first.keyRef);
      await provesWinner(first.keyProvider, first.keyRef, kms); await provesWinner(fresh.keyProvider, first.keyRef, kms);
      expect(kms.ledger.filter((x) => x.action === 'alias').map((x) => x.input)).toEqual([{ aliasName: alias, targetKeyId: first.keyRef }]);
      expect(kms.ledger.filter((x) => x.action === 'create')).toHaveLength(1);
    });
    for (const first of [0, 1]) it(`Given two missing readers, when acquisition arrival ${first} wins, then both callers and a fresh caller sign only as the winner`, async () => {
      const kms = new Kms(v);
      kms.race = { first, initialReads: 0, arrivals: 0, reads: latch(), acquisitions: latch(), published: latch() };
      const outcomes = await Promise.allSettled([open(kms), open(kms)]);
      expect(outcomes.map((x) => x.status)).toEqual(['fulfilled', 'fulfilled']);
      const winner = kms.aliases.get(alias)!;
      const acquisitions = kms.ledger.filter((x) => x.action === 'alias');
      expect(acquisitions[first].input.targetKeyId).toBe(winner);
      for (const outcome of outcomes) if (outcome.status === 'fulfilled') {
        expect(outcome.value.keyRef).toBe(winner); await provesWinner(outcome.value.keyProvider, winner, kms);
      }
      const allocated = kms.ledger.filter((x) => x.action === 'create').length;
      const fresh = await open(kms); expect(fresh.keyRef).toBe(winner); await provesWinner(fresh.keyProvider, winner, kms);
      expect(kms.ledger.filter((x) => x.action === 'create')).toHaveLength(allocated);
      // No fixed race-candidate count; no loser-disposition/retention acceptance.
      safe(kms);
    }, 2000);
    for (const name of ['AccessDeniedException', 'TimeoutError', 'KMSInternalException', 'Error']) {
      it(`Given initial ${name}, when opening, then the original error propagates without creation`, async () => {
        const kms = new Kms(v); const error = fault(name); kms.readFault = () => error;
        await expect(open(kms)).rejects.toBe(error);
        expect(kms.ledger.map((x) => x.action)).toEqual(['get']); safe(kms);
      });
    }
    for (const stage of ['create', 'acquire', 'ambiguous-acquire'] as const) {
      it(`Given ${stage} failure, when creating, then no presumed candidate is returned or destructively changed`, async () => {
        const kms = new Kms(v); const error = fault('AccessDeniedException');
        if (stage === 'create') kms.createFault = error;
        else { kms.aliasFault = error; kms.commitBeforeAliasFault = stage === 'ambiguous-acquire'; }
        await expect(open(kms)).rejects.toBe(error); safe(kms);
        expect(kms.ledger.filter((x) => x.action === 'create')).toHaveLength(1);
        expect(kms.ledger.filter((x) => x.action === 'alias')).toHaveLength(stage === 'create' ? 0 : 1);
        if (stage === 'ambiguous-acquire') {
          kms.aliasFault = undefined;
          const winner = kms.aliases.get(alias)!; const fresh = await open(kms);
          expect(fresh.keyRef).toBe(winner); await provesWinner(fresh.keyProvider, winner, kms);
          expect(kms.ledger.filter((x) => x.action === 'create')).toHaveLength(1);
        }
      });
    }
    for (const name of ['NotFoundException', 'AccessDeniedException', 'TimeoutError']) {
      it(`Given an acquisition conflict then ${name}, when rereading, then exactly one winner lookup fails unchanged and only an explicit new call can recover`, async () => {
        const kms = new Kms(v); const winner = kms.seed(); kms.conflictWinner = winner;
        const error = fault(name);
        kms.readFault = (input, ordinal) => input.keyId === alias && ordinal > 1 ? error : undefined;
        await expect(open(kms)).rejects.toBe(error);
        expect(kms.ledger.filter((x) => x.action === 'get' && x.input.keyId === alias)).toHaveLength(2);
        expect(kms.ledger.filter((x) => x.action === 'create')).toHaveLength(1); safe(kms);
        kms.readFault = undefined;
        const fresh = await open(kms); expect(fresh.keyRef).toBe(winner); await provesWinner(fresh.keyProvider, winner, kms);
        expect(kms.ledger.filter((x) => x.action === 'create')).toHaveLength(1);
      });
    }
    const invalid: [string, (r: PublicResponse) => PublicResponse][] = [
      ['absent ID', (r) => ({ ...r, keyId: undefined })],
      ['empty ID', (r) => ({ ...r, keyId: '' })],
      ['alias ID', (r) => ({ ...r, keyId: alias })],
      ['alias ARN', (r) => ({ ...r, keyId: 'arn:aws:kms:us-east-1:123456789012:alias/test' })],
      ['fragment ID', (r) => ({ ...r, keyId: 'key#fragment' })],
      ['wrong usage', (r) => ({ ...r, keyUsage: 'ENCRYPT_DECRYPT' })],
      ['missing usage', (r) => ({ ...r, keyUsage: undefined })],
      ['wrong spec', (r) => ({ ...r, keySpec: 'RSA_2048' })],
      ['missing spec', (r) => ({ ...r, keySpec: undefined })],
      ['wrong algorithm', (r) => ({ ...r, signingAlgorithms: ['RSASSA_PSS_SHA_256'] })],
      ['missing algorithms', (r) => ({ ...r, signingAlgorithms: undefined })],
      ['malformed SPKI', (r) => ({ ...r, publicKey: new Uint8Array([1, 2, 3]) })],
      ['empty SPKI', (r) => ({ ...r, publicKey: new Uint8Array() })],
      ['wrong key family', (r) => ({ ...r, publicKey: generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'der' }) })],
    ];
    for (const [label, transform] of invalid) it(`Given ${label} on the existing winner, when opening, then ArgumentError prevents fallback or overwrite`, async () => {
      const kms = new Kms(v); const id = kms.seed(); kms.aliases.set(alias, id); kms.readTransform = transform;
      await expect(open(kms)).rejects.toMatchObject({ name: 'ArgumentError' });
      expect(kms.aliases.get(alias)).toBe(id);
      expect(kms.ledger.filter((x) => ['create', 'alias', 'sign'].includes(x.action))).toEqual([]); safe(kms);
    });
    it('Given candidate public-key lookup reporting another identity, when creating, then identity-binding inconsistency fails closed', async () => {
      const kms = new Kms(v); const other = kms.seed();
      kms.readTransform = (r, input) => input.keyId !== alias && r.keyId !== other ? { ...r, keyId: other } : r;
      await expect(open(kms)).rejects.toMatchObject({ name: 'ArgumentError' }); safe(kms);
    });
    it('Given an acquired alias whose winner metadata is incompatible, when resolved, then no signer or overwrite is returned', async () => {
      const kms = new Kms(v); const winner = kms.seed(); kms.conflictWinner = winner;
      kms.readTransform = (r) => r.keyId === winner ? { ...r, keyUsage: 'ENCRYPT_DECRYPT' } : r;
      await expect(open(kms)).rejects.toMatchObject({ name: 'ArgumentError' });
      expect(kms.aliases.get(alias)).toBe(winner); safe(kms);
    });
    it('Given a usable winner then signing denial, when signing, then the original error propagates without replacement', async () => {
      const kms = new Kms(v); const id = kms.seed(); kms.aliases.set(alias, id);
      const result = await open(kms); const error = fault('AccessDeniedException'); kms.signFault = error;
      await expect(result.keyProvider.sign(payload)).rejects.toBe(error);
      expect(kms.ledger.filter((x) => ['create', 'alias'].includes(x.action))).toEqual([]); safe(kms);
    });
  });
}

describe('BOOTSTRAP input validation [fake-only]', () => {
  for (const value of [undefined, null, 42, '', ' alias/a', 'alias/a ', 'a', 'alias/', 'alias/aws/key', 'alias/a#b']) {
    it(`Given invalid alias ${JSON.stringify(value)}, when bootstrapping, then ArgumentError occurs before dependency calls`, async () => {
      const kms = new Kms(variants[0]);
      await expect(createOrReuseAwsKmsKeyProvider(kms, { aliasName: value as string, algorithm: variants[0].algorithm })).rejects.toMatchObject({ name: 'ArgumentError' });
      expect(kms.ledger).toEqual([]);
    });
  }
  for (const value of [undefined, null, '', 'ES256', 'EdDSA', 'ECDSA_SHA_384', ' ECDSA_SHA_256', 42]) {
    it(`Given invalid algorithm ${JSON.stringify(value)}, when bootstrapping, then ArgumentError occurs before dependency calls`, async () => {
      const kms = new Kms(variants[0]);
      await expect(createOrReuseAwsKmsKeyProvider(kms, { aliasName: alias, algorithm: value as AwsKmsSigningAlgorithm })).rejects.toMatchObject({ name: 'ArgumentError' });
      expect(kms.ledger).toEqual([]);
    });
  }
  it('Given a service-rejected alias outside local validation, when acquired, then service rejection propagates without invented normalization', async () => {
    const kms = new Kms(variants[0]); const error = fault('ValidationException'); kms.aliasFault = error;
    await expect(createOrReuseAwsKmsKeyProvider(kms, { aliasName: 'alias/contains space', algorithm: variants[0].algorithm })).rejects.toBe(error);
    expect(kms.ledger.find((x) => x.action === 'alias')?.input.aliasName).toBe('alias/contains space'); safe(kms);
  });
});
