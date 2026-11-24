import { describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync, sign, verify, createPublicKey } from 'node:crypto';
import type { protos } from '@google-cloud/kms';
import { ArgumentError } from '@dnsid-ai/sdk';
import {
  createOrReuseGcpCloudKmsKeyProvider,
  type GcpCloudKmsBootstrapClient,
  type GcpCloudKmsBootstrapResult,
} from '@dnsid-ai/key-gcp';

type K = protos.google.cloud.kms.v1.ICryptoKey;
type V = protos.google.cloud.kms.v1.ICryptoKeyVersion;
type P = protos.google.cloud.kms.v1.IPublicKey;
type S = protos.google.cloud.kms.v1.IAsymmetricSignResponse;
type GetK = protos.google.cloud.kms.v1.IGetCryptoKeyRequest;
type CreateK = protos.google.cloud.kms.v1.ICreateCryptoKeyRequest;
type GetV = protos.google.cloud.kms.v1.IGetCryptoKeyVersionRequest;
type GetP = protos.google.cloud.kms.v1.IGetPublicKeyRequest;
type Sign = protos.google.cloud.kms.v1.IAsymmetricSignRequest;
type Reply<T, R> = readonly [T, R | undefined, {} | undefined];
type Trace = { method: string; request: unknown };
const parent = 'projects/project-a/locations/us-central1/keyRings/ring-a';
const config = { parent, cryptoKeyId: 'dnsid-acme-research' };
const resource = (c: typeof config) => `${c.parent}/cryptoKeys/${c.cryptoKeyId}`;
const grpc = (code: number) => Object.assign(new Error(`service status ${code}`), { code });

// Independent CRC32C (Castagnoli), not CRC32; fixtures never import SDK helpers.
function crc32c(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function fixture(c = config) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const name = resource(c);
  const ref = `${name}/cryptoKeyVersions/1`;
  const trace: Trace[] = [];
  const key: K = { name, purpose: 5, versionTemplate: { algorithm: 40, protectionLevel: 1 } };
  const version: V = { name: ref, state: 1, algorithm: 40, protectionLevel: 1 };
  const pub: P = { name: ref, algorithm: 40, protectionLevel: 1, pem,
    pemCrc32c: { value: crc32c(Buffer.from(pem)) } };
  const client: GcpCloudKmsBootstrapClient = {
    async getCryptoKey(request: GetK): Promise<Reply<K, GetK>> {
      trace.push({ method: 'getCryptoKey', request }); return [key, undefined, undefined];
    },
    async createCryptoKey(request: CreateK): Promise<Reply<K, CreateK>> {
      trace.push({ method: 'createCryptoKey', request }); return [key, undefined, undefined];
    },
    async getCryptoKeyVersion(request: GetV): Promise<Reply<V, GetV>> {
      trace.push({ method: 'getCryptoKeyVersion', request }); return [version, undefined, undefined];
    },
    async getPublicKey(request: GetP): Promise<Reply<P, GetP>> {
      trace.push({ method: 'getPublicKey', request }); return [pub, undefined, undefined];
    },
    async asymmetricSign(request: Sign): Promise<Reply<S, Sign>> {
      trace.push({ method: 'asymmetricSign', request });
      expect(request.name).toBe(ref); // Separate service-request invariant.
      expect(request.digest).toBeUndefined();
      expect(request.data).toBeInstanceOf(Uint8Array);
      const data = request.data as Uint8Array;
      expect(Number(request.dataCrc32c?.value)).toBe(crc32c(data));
      const signature = sign(null, data, privateKey);
      return [{ name: ref, signature, signatureCrc32c: { value: crc32c(signature) },
        verifiedDataCrc32c: true, protectionLevel: 1 }, undefined, undefined];
    },
  };
  return { client, trace, key, version, pub, ref, publicKey };
}
type Fixture = ReturnType<typeof fixture>;
function noMutation(f: Fixture) {
  expect(f.trace.filter(t => t.method === 'createCryptoKey')).toEqual([]);
  // Five-method seam intentionally contains no version/ancestor creation operation.
}
async function actorIdentity(result: GcpCloudKmsBootstrapResult, f: Fixture) {
  expect(result.keyRef).toBe(f.ref);
  const jwk = await result.keyProvider.signingKey();
  expect(jwk.kty).toBe('OKP');
  expect(jwk.crv).toBe('Ed25519');
  expect(jwk.x).toBe(f.publicKey.export({ format: 'jwk' }).x);
  const payload = Buffer.from('independent caller signature oracle');
  const signature = await result.keyProvider.sign(payload);
  expect(verify(null, payload, f.publicKey, signature)).toBe(true);
  const consumerKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
  expect(verify(null, payload, consumerKey, signature)).toBe(true);
  return { jwk, payload, signature };
}

// Mode: fake-only (invalid remote responses).
type ResponseMethod = 'getCryptoKey' | 'getCryptoKeyVersion' | 'getPublicKey';
const invalid: Array<[string, (f: Fixture) => void, ResponseMethod, (f: Fixture) => void]> = [
  ['named key missing name', f => { delete f.key.name; }, 'getCryptoKey', f => { expect(f.key.name).toBe(undefined); }],
  ['named key wrong binding', f => { f.key.name = resource(config) + '-other'; }, 'getCryptoKey', f => { expect(f.key.name).toBe(resource(config) + '-other'); }],
  ['named key wrong purpose', f => { f.key.purpose = 1; }, 'getCryptoKey', f => { expect(f.key.purpose).toBe(1); }],
  ['named key missing purpose', f => { delete f.key.purpose; }, 'getCryptoKey', f => { expect(f.key.purpose).toBe(undefined); }],
  ['version missing name', f => { delete f.version.name; }, 'getCryptoKeyVersion', f => { expect(f.version.name).toBe(undefined); }],
  ['version wrong key binding', f => { f.version.name = `${resource(config)}-other/cryptoKeyVersions/1`; }, 'getCryptoKeyVersion', f => { expect(f.version.name).toBe(`${resource(config)}-other/cryptoKeyVersions/1`); }],
  ['version wrong numeric version', f => { f.version.name = `${resource(config)}/cryptoKeyVersions/2`; }, 'getCryptoKeyVersion', f => { expect(f.version.name).toBe(`${resource(config)}/cryptoKeyVersions/2`); }],
  ['version disabled', f => { f.version.state = 2; }, 'getCryptoKeyVersion', f => { expect(f.version.state).toBe(2); }],
  ['version missing state', f => { delete f.version.state; }, 'getCryptoKeyVersion', f => { expect(f.version.state).toBe(undefined); }],
  ['version wrong algorithm', f => { f.version.algorithm = 12; }, 'getCryptoKeyVersion', f => { expect(f.version.algorithm).toBe(12); }],
  ['version missing algorithm', f => { delete f.version.algorithm; }, 'getCryptoKeyVersion', f => { expect(f.version.algorithm).toBe(undefined); }],
  ['version nonsoftware', f => { f.version.protectionLevel = 2; }, 'getCryptoKeyVersion', f => { expect(f.version.protectionLevel).toBe(2); }],
  ['version missing protection', f => { delete f.version.protectionLevel; }, 'getCryptoKeyVersion', f => { expect(f.version.protectionLevel).toBe(undefined); }],
  ['public response missing name', f => { delete f.pub.name; }, 'getPublicKey', f => { expect(f.pub.name).toBe(undefined); }],
  ['public response wrong binding', f => { f.pub.name = `${resource(config)}/cryptoKeyVersions/2`; }, 'getPublicKey', f => { expect(f.pub.name).toBe(`${resource(config)}/cryptoKeyVersions/2`); }],
  ['public response wrong algorithm', f => { f.pub.algorithm = 12; }, 'getPublicKey', f => { expect(f.pub.algorithm).toBe(12); }],
  ['public response nonsoftware', f => { f.pub.protectionLevel = 2; }, 'getPublicKey', f => { expect(f.pub.protectionLevel).toBe(2); }],
  ['public response missing PEM', f => { delete f.pub.pem; }, 'getPublicKey', f => { expect(f.pub.pem).toBe(undefined); }],
  ['public response malformed PEM with correct checksum', f => {
    f.pub.pem = 'not a public key'; f.pub.pemCrc32c = { value: crc32c(Buffer.from(f.pub.pem)) };
  }, 'getPublicKey', f => { expect(f.pub.pem).toBe('not a public key'); expect(f.pub.pemCrc32c?.value).toBe(crc32c(Buffer.from(f.pub.pem!))); }],
  ['public response mismatched integrity', f => {
    f.pub.pemCrc32c = { value: (crc32c(Buffer.from(f.pub.pem!)) ^ 1) >>> 0 };
  }, 'getPublicKey', f => { expect(f.pub.pemCrc32c?.value).toBe((crc32c(Buffer.from(f.pub.pem!)) ^ 1) >>> 0); }],
  ['public response missing integrity', f => { delete f.pub.pemCrc32c; }, 'getPublicKey', f => { expect(f.pub.pemCrc32c).toBe(undefined); }],
];
describe('GCP bootstrap response validation', () => {
  it.each(invalid)('%s', async (_label, invalidate, target, verifyDefect) => {
    const baseline = fixture();
    await actorIdentity(await createOrReuseGcpCloudKmsKeyProvider(baseline.client, config), baseline);
    noMutation(baseline);
    const f = fixture();
    invalidate(f);
    verifyDefect(f); // Preparation and crypto/checksum validation cannot satisfy rejection.
    const delivered: unknown[] = [];
    const fixtureErrors: unknown[] = [];
    // Wrap every seam so neither a fixture assertion nor a finite guard is an oracle.
    for (const method of ['getCryptoKey', 'createCryptoKey', 'getCryptoKeyVersion', 'getPublicKey', 'asymmetricSign'] as const) {
      const original = f.client[method].bind(f.client);
      const wrapped = async (request: never) => {
        try {
          if (f.trace.length >= 8) throw new Error('test guard: response-validation call budget');
          const response = await original(request);
          if (method === target) delivered.push(request);
          return response;
        } catch (error) {
          fixtureErrors.push(error);
          throw error;
        }
      };
      f.client[method] = wrapped as typeof f.client[typeof method];
    }
    let rejected = false;
    let caught: unknown;
    try { await createOrReuseGcpCloudKmsKeyProvider(f.client, config); }
    catch (error) { rejected = true; caught = error; }
    expect(rejected).toBe(true); // Generic fail-closed contract, not a guard-specific class.
    for (const error of fixtureErrors) expect(caught).not.toBe(error);
    expect(fixtureErrors).toEqual([]);
    expect(delivered).toEqual([{ name: target === 'getCryptoKey' ? resource(config) : f.ref }]);
    expect(f.trace.length).toBeLessThanOrEqual(8);
    expect(f.trace.some(t => t.method === 'asymmetricSign')).toBe(false);
    noMutation(f); // Independent invariant, not the acceptance oracle.
    console.info(JSON.stringify({ proof: 'malformed-response-delivery', label: _label, target,
      delivered: delivered.length, requests: delivered, fixtureErrors: fixtureErrors.length }));
  });
  it('missing initial version is failure without replacement', async () => {
    const f = fixture(); const missingVersion = grpc(5);
    f.client.getCryptoKeyVersion = async (request: GetV): Promise<Reply<V, GetV>> => {
      f.trace.push({ method: 'getCryptoKeyVersion', request }); throw missingVersion;
    };
    await expect(createOrReuseGcpCloudKmsKeyProvider(f.client, config)).rejects.toBe(missingVersion);
    noMutation(f);
  });
  it('ALREADY_EXISTS then NOT_FOUND terminates without another create', async () => {
    const f = fixture(); let reads = 0; let creates = 0;
    const missingKey = grpc(5); const unreadableWinner = grpc(5); const contention = grpc(6);
    f.client.getCryptoKey = async (request: GetK): Promise<Reply<K, GetK>> => {
      f.trace.push({ method: 'getCryptoKey', request }); reads++;
      // Bound a defective loop with a sentinel, then fail the exact invariant below.
      if (reads > 2) throw new Error('test guard: excess winner reads');
      throw reads === 1 ? missingKey : unreadableWinner;
    };
    f.client.createCryptoKey = async (request: CreateK): Promise<Reply<K, CreateK>> => {
      f.trace.push({ method: 'createCryptoKey', request }); creates++;
      if (creates > 1) throw new Error('test guard: excess creation');
      throw contention;
    };
    await expect(createOrReuseGcpCloudKmsKeyProvider(f.client, config)).rejects.toBe(unreadableWinner);
    expect(reads).toBe(2); expect(creates).toBe(1);
    expect(f.trace.map(t => t.method)).toEqual(['getCryptoKey', 'createCryptoKey', 'getCryptoKey']);
  });
});

// Mode: fake-only. Readiness changes only between separately initiated calls.
for (const state of ['PENDING_GENERATION', 5] as const) {
  for (const route of ['reuse', 'create', 'winner'] as const) {
    it(`pending initial version ${state} on ${route} rejects; separate same-scope call recovers version 1`, async () => {
      const f = fixture();
      f.version.state = state;
      let exists = route === 'reuse';
      let reads = 0; let creates = 0; let versions = 0;
      f.client.getCryptoKey = async (request: GetK): Promise<Reply<K, GetK>> => {
        f.trace.push({ method: 'getCryptoKey', request });
        if (++reads > 3) throw new Error('test guard: excess named-key reads');
        if (!exists) throw grpc(5);
        return [f.key, undefined, undefined];
      };
      f.client.createCryptoKey = async (request: CreateK): Promise<Reply<K, CreateK>> => {
        f.trace.push({ method: 'createCryptoKey', request });
        if (++creates > 1) throw new Error('test guard: replacement creation');
        exists = true;
        if (route === 'winner') throw grpc(6);
        return [f.key, undefined, undefined];
      };
      f.client.getCryptoKeyVersion = async (request: GetV): Promise<Reply<V, GetV>> => {
        f.trace.push({ method: 'getCryptoKeyVersion', request });
        if (++versions > 2) throw new Error('test guard: version polling');
        expect(request.name).toBe(f.ref);
        return [f.version, undefined, undefined];
      };
      // WHEN version 1 is pending, this invocation returns no provider/signer.
      await expect(createOrReuseGcpCloudKmsKeyProvider(f.client, { ...config })).rejects.toBeDefined();
      expect(versions).toBe(1);
      expect(reads).toBe(route === 'winner' ? 2 : 1);
      expect(creates).toBe(route === 'reuse' ? 0 : 1);
      expect(f.trace.some(t => t.method === 'getPublicKey' || t.method === 'asymmetricSign')).toBe(false);
      // External state transition, not a sleep, poll, retry policy or timing promise.
      f.version.state = 'ENABLED';
      const recovered = await createOrReuseGcpCloudKmsKeyProvider(f.client, { ...config });
      await actorIdentity(recovered, f); // Independent public-material/signature checks.
      expect(versions).toBe(2);
      expect(reads).toBe(route === 'winner' ? 3 : 2);
      expect(creates).toBe(route === 'reuse' ? 0 : 1);
      expect(f.ref).toBe(`${resource(config)}/cryptoKeyVersions/1`);
    });
  }
}

// Mode: real-capable; this suite supplies fake dependencies.
describe('GCP bootstrap input and scope boundaries', () => {
  it.each([
    ['empty parent', { ...config, parent: '' }],
    ['non-resource parent', { ...config, parent: 'not-a-key-ring-resource' }],
    ['empty ID', { ...config, cryptoKeyId: '' }],
    ['ID containing path separator', { ...config, cryptoKeyId: 'acme/research' }],
  ])('%s fails without mutation', async (_label, bad) => {
    const f = fixture();
    await expect(createOrReuseGcpCloudKmsKeyProvider(f.client, bad)).rejects.toBeInstanceOf(ArgumentError);
    noMutation(f);
  });
  it('missing ancestor remains failure, with no ancestor-creation capability', async () => {
    const f = fixture(); const missingKey = grpc(5); const missingAncestor = grpc(5);
    f.client.getCryptoKey = async (request: GetK): Promise<Reply<K, GetK>> => {
      f.trace.push({ method: 'getCryptoKey', request }); throw missingKey;
    };
    f.client.createCryptoKey = async (request: CreateK): Promise<Reply<K, CreateK>> => {
      f.trace.push({ method: 'createCryptoKey', request }); throw missingAncestor;
    };
    await expect(createOrReuseGcpCloudKmsKeyProvider(f.client, config)).rejects.toBe(missingAncestor);
    expect(f.trace.filter(t => t.method === 'createCryptoKey').length).toBeLessThanOrEqual(1);
    expect(f.trace.every(t => t.method === 'getCryptoKey' || t.method === 'createCryptoKey')).toBe(true);
  });
  it.each([
    ['project', { ...config, parent: parent.replace('project-a', 'project-b') }],
    ['location', { ...config, parent: parent.replace('us-central1', 'us-east1') }],
    ['keyRing', { ...config, parent: parent.replace('ring-a', 'ring-b') }],
    ['allocated ID', { ...config, cryptoKeyId: 'dnsid-acme-finance' }],
  ])('distinct %s scopes have independent verifiable signers', async (_dimension, other) => {
    const a = fixture(); const b = fixture(other);
    const ra = await createOrReuseGcpCloudKmsKeyProvider(a.client, config);
    const rb = await createOrReuseGcpCloudKmsKeyProvider(b.client, other);
    const ia = await actorIdentity(ra, a); const ib = await actorIdentity(rb, b);
    expect(ra.keyRef).not.toBe(rb.keyRef);
    expect(ia.jwk.x).not.toBe(ib.jwk.x);
    expect(verify(null, ia.payload, b.publicKey, ia.signature)).toBe(false);
    expect(verify(null, ib.payload, a.publicKey, ib.signature)).toBe(false);
    noMutation(a); noMutation(b);
  });
});

// Mode: fake-only. Caller composition only, not Foundry/server proof.
describe('GCP bootstrap caller composition', () => {
  it('explicit key bootstrap alone does not invoke the application agent-ID spy', async () => {
    const f = fixture(); const agentCreateOrReuse = vi.fn();
    const result = await createOrReuseGcpCloudKmsKeyProvider(f.client, config);
    await actorIdentity(result, f);
    expect(agentCreateOrReuse).not.toHaveBeenCalled();
  });
  it('caller first awaits key, then separately passes returned identity to its explicit ID operation', async () => {
    const f = fixture(); const events: string[] = [];
    const agentCreateOrReuse = vi.fn(async (identity: { keyRef: string; jwk: unknown }) => {
      events.push('explicit-ID'); return { identity };
    });
    // Application example, not a proposed registry API or product entry point.
    const result = await createOrReuseGcpCloudKmsKeyProvider(f.client, config);
    events.push('key-returned');
    expect(agentCreateOrReuse).not.toHaveBeenCalled();
    const jwk = await result.keyProvider.signingKey();
    const identity = { keyRef: result.keyRef, jwk };
    const id = await agentCreateOrReuse(identity);
    expect(id.identity).toBe(identity);
    expect(agentCreateOrReuse).toHaveBeenCalledExactlyOnceWith(identity);
    expect(identity.keyRef).toBe(f.ref);
    expect(jwk.x).toBe(f.publicKey.export({ format: 'jwk' }).x);
    expect(events).toEqual(['key-returned', 'explicit-ID']);
  });
  it('caller composition stops on key failure before explicit ID operation', async () => {
    const f = fixture(); const failure = grpc(7);
    const agentCreateOrReuse = vi.fn(async (_identity: unknown) => ({ id: 'caller-spy-id' }));
    f.client.getCryptoKey = async (_request: GetK): Promise<Reply<K, GetK>> => { throw failure; };
    async function applicationComposition() {
      const result = await createOrReuseGcpCloudKmsKeyProvider(f.client, config);
      return agentCreateOrReuse({ keyRef: result.keyRef, jwk: await result.keyProvider.signingKey() });
    }
    await expect(applicationComposition()).rejects.toBe(failure);
    expect(agentCreateOrReuse).not.toHaveBeenCalled();
    noMutation(f);
  });
});
