import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { protos } from '@google-cloud/kms';
import {
  createOrReuseGcpCloudKmsKeyProvider,
  GcpCloudKmsKeyProvider,
  type GcpCloudKmsBootstrapClient,
  type GcpCloudKmsBootstrapResult,
} from '@dnsid-ai/key-gcp';

type Kms = GcpCloudKmsBootstrapClient;
type Request<M extends keyof Kms> = Parameters<Kms[M]>[0];
type CryptoKey = protos.google.cloud.kms.v1.ICryptoKey;
const config = {
  parent: 'projects/bootstrap-test/locations/us-central1/keyRings/operational',
  cryptoKeyId: 'dnsid-acme-research',
};
const namedKey = `${config.parent}/cryptoKeys/${config.cryptoKeyId}`;
const version = `${namedKey}/cryptoKeyVersions/1`;
const NOT_FOUND = 5;
const ALREADY_EXISTS = 6;
const DEADLINE_EXCEEDED = 4;
function serviceError(code: number): Error & { code: number } {
  return Object.assign(new Error(`independent fake service status ${code}`), { code });
}

// Independent bitwise Castagnoli CRC32C, not CRC32 or production code.
function crc32c(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function fixture() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  if (typeof jwk.x !== 'string') throw new Error('Ed25519 fixture missing x');
  const canonical = JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x });
  return {
    publicKey, privateKey,
    pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    x: jwk.x,
    kid: createHash('sha256').update(canonical).digest('base64url'),
  };
}
type Fixture = ReturnType<typeof fixture>;
type Stage = 'lookup' | 'create' | 'winner-read';
interface Hooks {
  lookup?: (actor: string, ordinal: number, present: boolean) => Promise<void>;
  create?: (actor: string) => Promise<void>;
  committed?: (actor: string) => Promise<void>;
}

// A shared named-resource service; client facades have no local signer state.
class NamedKms {
  readonly resources = new Map<string, Fixture>();
  readonly trace: Array<{ actor: string; op: string; name: string }> = [];
  readonly reads = new Map<string, number>();
  commits = 0;
  constructor(readonly candidate: Fixture, readonly hooks: Hooks = {}) {}
  seed(): void { this.resources.set(namedKey, this.candidate); }
  client(actor: string): Kms {
    const record = (op: string, name: string) => this.trace.push({ actor, op, name });
    const bound = (name: string | null | undefined): Fixture => {
      if (name !== version) throw serviceError(NOT_FOUND);
      const key = this.resources.get(namedKey);
      if (!key) throw serviceError(NOT_FOUND);
      return key;
    };
    return {
      getCryptoKey: async (request: Request<'getCryptoKey'>) => {
        const name = request.name ?? '';
        record('getCryptoKey', name);
        const ordinal = (this.reads.get(actor) ?? 0) + 1;
        this.reads.set(actor, ordinal);
        // Capture absence before the barrier, so both race callers see absence.
        const present = this.resources.has(name);
        await this.hooks.lookup?.(actor, ordinal, present);
        if (!present) throw serviceError(NOT_FOUND);
        return [this.keyDescription(name), undefined, undefined];
      },
      createCryptoKey: async (request: Request<'createCryptoKey'>) => {
        const name = `${request.parent}/cryptoKeys/${request.cryptoKeyId}`;
        record('createCryptoKey', name);
        await this.hooks.create?.(actor);
        // Resource-request invariants, not substitutes for consumer assertions.
        expect(request.parent).toBe(config.parent);
        expect(request.cryptoKeyId).toBe(config.cryptoKeyId);
        expect(request.skipInitialVersionCreation ?? false).toBe(false);
        expect([5, 'ASYMMETRIC_SIGN']).toContain(request.cryptoKey?.purpose);
        expect([40, 'EC_SIGN_ED25519']).toContain(request.cryptoKey?.versionTemplate?.algorithm);
        expect([1, 'SOFTWARE']).toContain(request.cryptoKey?.versionTemplate?.protectionLevel);
        if (this.resources.has(name)) throw serviceError(ALREADY_EXISTS);
        this.resources.set(name, this.candidate);
        this.commits++;
        await this.hooks.committed?.(actor);
        return [this.keyDescription(name), undefined, undefined];
      },
      getCryptoKeyVersion: async (request: Request<'getCryptoKeyVersion'>) => {
        record('getCryptoKeyVersion', request.name ?? '');
        bound(request.name);
        return [{ name: version, state: 'ENABLED', algorithm: 'EC_SIGN_ED25519', protectionLevel: 'SOFTWARE' }, undefined, undefined];
      },
      getPublicKey: async (request: Request<'getPublicKey'>) => {
        record('getPublicKey', request.name ?? '');
        const key = bound(request.name);
        return [{ name: version, pem: key.pem, pemCrc32c: { value: crc32c(Buffer.from(key.pem)) },
          algorithm: 'EC_SIGN_ED25519', protectionLevel: 'SOFTWARE', publicKeyFormat: 'PEM' }, undefined, undefined];
      },
      asymmetricSign: async (request: Request<'asymmetricSign'>) => {
        record('asymmetricSign', request.name ?? '');
        const key = bound(request.name);
        if (request.data == null || request.digest != null) throw new Error('Expected raw Ed25519 data');
        const data = typeof request.data === 'string'
          ? Buffer.from(request.data, 'base64') : Buffer.from(request.data);
        const supplied = request.dataCrc32c?.value;
        const checksum = supplied == null ? NaN : Number(supplied.toString());
        expect(checksum).toBe(crc32c(data));
        const signature = sign(null, data, key.privateKey);
        return [{ name: version, signature, signatureCrc32c: { value: crc32c(signature) },
          verifiedDataCrc32c: true, verifiedDigestCrc32c: false, protectionLevel: 'SOFTWARE' }, undefined, undefined];
      },
    };
  }
  private keyDescription(name: string): CryptoKey {
    return { name, purpose: 'ASYMMETRIC_SIGN', versionTemplate: {
      algorithm: 'EC_SIGN_ED25519', protectionLevel: 'SOFTWARE',
    } };
  }
  creates(): number { return this.trace.filter(call => call.op === 'createCryptoKey').length; }
}

async function assertSigner(provider: GcpCloudKmsKeyProvider, key: Fixture, message: string): Promise<void> {
  const jwk = await provider.signingKey();
  // Partial comparison deliberately permits optional JWK metadata (alg/use/etc).
  expect(jwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519', x: key.x, kid: key.kid });
  const payload = Buffer.from(message);
  const signature = await provider.sign(payload);
  expect(verify(null, payload, key.publicKey, signature)).toBe(true);
  expect(verify(null, Buffer.from(`${message}:tampered`), key.publicKey, signature)).toBe(false);
}
async function assertResult(result: GcpCloudKmsBootstrapResult, key: Fixture, message: string): Promise<void> {
  expect(result.keyRef).toBe(version);
  await assertSigner(result.keyProvider, key, message);
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}
// Deadlock guard only; timers do not schedule the race or determine its winner.
async function bounded<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([promise, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Bounded wait expired: ${label}`)), 2000);
    })]);
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

describe('explicit GCP initial-key bootstrap — independent cases 1–5', () => {
  it('case 1: absent key, repeat bootstrap and ordinary load return the committed signer', async () => {
    // Public known-answer check for the independent integrity fixture algorithm.
    expect(crc32c(Buffer.from('123456789'))).toBe(0xe3069283);
    const key = fixture();
    const kms = new NamedKms(key);
    const attempt = createOrReuseGcpCloudKmsKeyProvider(kms.client('first'), config);
    await expect(attempt).resolves.toMatchObject({ keyRef: version });
    const first = await attempt;
    await assertResult(first, key, 'absent bootstrap');
    const second = await createOrReuseGcpCloudKmsKeyProvider(kms.client('restart'), { ...config });
    await assertResult(second, key, 'restart bootstrap');
    const loaded = await GcpCloudKmsKeyProvider.load(kms.client('ordinary'), {
      activeKeyVersion: first.keyRef, algorithm: 'EC_SIGN_ED25519',
    });
    await assertSigner(loaded, key, 'ordinary immutable reference load');
    // Separate resource invariants: one named create, one stored identity.
    expect(kms.creates()).toBe(1);
    expect(kms.commits).toBe(1);
    expect([...kms.resources.keys()]).toEqual([namedKey]);
  });

  it('case 2: fresh callers reuse an existing independently verifiable signer', async () => {
    const key = fixture();
    const kms = new NamedKms(key);
    kms.seed();
    for (const actor of ['replica-a', 'replica-b', 'restart']) {
      const result = await createOrReuseGcpCloudKmsKeyProvider(kms.client(actor), { ...config });
      await assertResult(result, key, `existing signer ${actor}`);
    }
    expect(kms.creates()).toBe(0); // Separate resource invariant.
    expect(kms.commits).toBe(0);
    expect(kms.resources.size).toBe(1);
  });

  it('case 3: controlled ALREADY_EXISTS loser rereads the winner; later caller converges', async () => {
    const bothAbsent = deferred();
    const releaseLookups = deferred();
    const winnerCommitted = deferred();
    let absentCount = 0;
    const key = fixture();
    const kms = new NamedKms(key, {
      lookup: async (_actor, ordinal, present) => {
        if (ordinal !== 1 || present) return;
        if (++absentCount === 2) bothAbsent.resolve();
        await releaseLookups.promise;
      },
      create: async actor => { if (actor === 'loser') await winnerCommitted.promise; },
      committed: async actor => { if (actor === 'winner') winnerCommitted.resolve(); },
    });
    const winner = createOrReuseGcpCloudKmsKeyProvider(kms.client('winner'), config);
    const loser = createOrReuseGcpCloudKmsKeyProvider(kms.client('loser'), config);
    // Attach rejection handlers immediately, including while rendezvous is held.
    const joined = Promise.allSettled([winner, loser]);
    try {
      await bounded(bothAbsent.promise, 'both callers observed absence');
      releaseLookups.resolve();
      const results = await bounded(joined, 'both bootstrap calls finish');
      for (const [index, result] of results.entries()) {
        expect(result.status).toBe('fulfilled');
        if (result.status !== 'fulfilled') throw result.reason;
        await assertResult(result.value, key, `concurrent caller ${index}`);
      }
      const fresh = await createOrReuseGcpCloudKmsKeyProvider(kms.client('later'), config);
      await assertResult(fresh, key, 'later fresh caller');
      // Separate trace invariants; public signature assertions above are primary.
      expect(kms.creates()).toBe(2);
      expect(kms.commits).toBe(1);
      expect(kms.reads.get('loser')).toBeGreaterThanOrEqual(2);
      expect(kms.resources.size).toBe(1);
    } finally {
      releaseLookups.resolve();
      winnerCommitted.resolve();
      await bounded(joined, 'release and join owned concurrent calls');
    }
  }, 10000);

  for (const code of [7, 16, 14, DEADLINE_EXCEEDED]) {
    for (const stage of ['lookup', 'create', 'winner-read'] as const satisfies readonly Stage[]) {
      it(`case 4: service status ${code} at ${stage} is a public failure, not a fallback signer`, async () => {
        const fault = serviceError(code);
        const kms = new NamedKms(fixture(), {
          lookup: async (_actor, ordinal) => {
            if (stage === 'lookup' || (stage === 'winner-read' && ordinal > 1)) throw fault;
          },
          create: async () => {
            if (stage === 'create') throw fault;
            if (stage === 'winner-read') {
              kms.seed(); // Another replica won after this caller observed absence.
              throw serviceError(ALREADY_EXISTS);
            }
          },
        });
        // Numeric service status distinguishes injected failure from scaffold or
        // setup errors. Native propagation is documented; no wrapper is invented.
        await expect(createOrReuseGcpCloudKmsKeyProvider(kms.client('faulted'), config))
          .rejects.toMatchObject({ code });
        // Separate resource invariants, not the acceptance oracle.
        expect(kms.creates()).toBe(stage === 'lookup' ? 0 : 1);
        expect(kms.commits).toBe(0);
        expect(kms.trace.some(call => call.op === 'asymmetricSign')).toBe(false);
        if (stage === 'winner-read') {
          expect(kms.reads.get('faulted')).toBeGreaterThanOrEqual(2);
          expect(kms.resources.size).toBe(1);
        }
      });
    }
  }

  it('case 5: committed create timeout fails first; explicit retry recovers that exact signer', async () => {
    const key = fixture();
    const timeout = serviceError(DEADLINE_EXCEEDED);
    const kms = new NamedKms(key, { committed: async () => { throw timeout; } });
    await expect(createOrReuseGcpCloudKmsKeyProvider(kms.client('lost-response'), config))
      .rejects.toMatchObject({ code: DEADLINE_EXCEEDED });
    const recovered = await createOrReuseGcpCloudKmsKeyProvider(kms.client('retry'), { ...config });
    await assertResult(recovered, key, 'committed-create recovery');
    const later = await createOrReuseGcpCloudKmsKeyProvider(kms.client('later'), config);
    await assertResult(later, key, 'post-recovery restart');
    expect(kms.creates()).toBe(1); // Separate invariant: no second creation.
    expect(kms.commits).toBe(1);
    expect(kms.resources.get(namedKey)).toBe(key);
  });
});
