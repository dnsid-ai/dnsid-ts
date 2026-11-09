import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { HttpSignaturesProfile, jwkThumbprint } from '@dnsid-ai/sdk';
import { constructIdentityManager, loadFile } from '@dnsid-ai/sdk/node';
import { currentProfileFixture } from './current-profile.ts';

// Provisional compliance 3e5d4d7: configuration loading and KeyProvider contracts.
// Mode: fake-only RPC and existing DNS/HTTPS/log evidence harness; real SDK verification.
// Local eligibility is not authorized public rotation, persistence, or crash recovery.
const parent = 'projects/consumer/locations/global/keyRings/agents/cryptoKeys/signer';
const a = parent + '/cryptoKeyVersions/7'; const b = parent + '/cryptoKeyVersions/8';
const algorithm = 'EC_SIGN_ED25519';
const keys = new Map([a, b].map((version, i) => [version, createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, i + 1)]),
  format: 'der', type: 'pkcs8',
})]));
function crc(bytes: Uint8Array) {
  let c = 0xffffffff;
  for (const byte of bytes) { c ^= byte; for (let i = 0; i < 8; i++) c = (c >>> 1) ^ ((c & 1) ? 0x82f63b78 : 0); }
  return (c ^ 0xffffffff) >>> 0;
}

export async function gcpConsumer(mode: 'EdDSA' | 'existing' = 'EdDSA') {
  // Published A is built independently, never obtained from the selected provider.
  const raw = createPublicKey(keys.get(a)!).export({ format: 'jwk' });
  const published = { kty: 'OKP', crv: 'Ed25519', x: raw.x!, alg: 'EdDSA', use: 'sig', kid: '' };
  published.kid = await jwkThumbprint(published);
  const fixture = await currentProfileFixture('agent.example.com', published);
  const prototype = KeyManagementServiceClient.prototype;
  const names = ['getPublicKey', 'getCryptoKeyVersion', 'asymmetricSign', 'createCryptoKeyVersion', 'createCryptoKey',
    'importCryptoKeyVersion', 'updateCryptoKeyVersion', 'destroyCryptoKeyVersion', 'updateCryptoKeyPrimaryVersion'] as const;
  const originals = names.map(name => [name, prototype[name]] as const);
  let reads = 0; let creates = 0; let signs = 0;
  let failure: 'create' | 'read' | 'metadata' | undefined;
  // Test-only structural seam accommodates the official client's overloaded RPCs.
  const rpc = prototype as unknown as Record<string, (...args: any[]) => Promise<any>>;
  for (const name of names) rpc[name] = async () => assert.fail('forbidden RPC: ' + name);
  rpc.getPublicKey = async ({ name }: { name: string }) => {
    reads++; assert(keys.has(name));
    if (name === b && failure === 'read') throw new Error('read denied');
    const pem = createPublicKey(keys.get(name)!).export({ format: 'pem', type: 'spki' }).toString();
    return [{ name, algorithm, protectionLevel: 'SOFTWARE', pem, pemCrc32c: { value: crc(Buffer.from(pem)) } }];
  };
  rpc.getCryptoKeyVersion = async ({ name }: { name: string }) => {
    assert.equal(name, b);
    return [{ name, algorithm, protectionLevel: 'SOFTWARE', state: failure === 'metadata' ? 'DISABLED' : 'ENABLED' }];
  };
  rpc.createCryptoKeyVersion = async (request: { parent: string }) => {
    creates++; assert.equal(request.parent, parent);
    if (failure === 'create') throw new Error('create denied');
    return [{ name: b, algorithm, protectionLevel: 'SOFTWARE', state: failure === 'metadata' ? 'PENDING_GENERATION' : 'ENABLED' }];
  };
  rpc.asymmetricSign = async (request: { name: string; data: Uint8Array; dataCrc32c: { value: number }; digest?: unknown }) => {
    signs++; assert(keys.has(request.name)); assert.equal(request.digest, undefined);
    assert.equal(Number(request.dataCrc32c.value), crc(request.data));
    const signature = sign(null, request.data, keys.get(request.name)!);
    return [{ name: request.name, signature, signatureCrc32c: { value: crc(signature) }, verifiedDataCrc32c: true }];
  };
  const dir = await mkdtemp(join(tmpdir(), 'dnsid-gcp-consumer-'));
  const deps = { dnsResolver: fixture.dnsResolver, fetchJson: fixture.fetchJson, logRegistry: fixture.logRegistry };
  async function open(version = a, deploymentAlgorithm: string | undefined = mode === 'existing' ? undefined : 'EdDSA') {
    const file = join(dir, 'deployment.json');
    await writeFile(file, JSON.stringify({ dnsid: { identity: {
      domain: 'agent.example.com', governanceId: 'example.com', logRef: fixture.record.lr,
      statusUrl: fixture.record.su, ekUrl: fixture.record.ek, kuUrl: fixture.record.ku,
    } }, keySource: { provider: 'google-kms', keyRef: version, settings: { algorithm: deploymentAlgorithm } } }));
    return constructIdentityManager(await loadFile(file), deps);
  }
  async function roundTrip(manager: Awaited<ReturnType<typeof open>>) {
    const profile = HttpSignaturesProfile.fromIdentityManager(manager);
    const signed = await profile.createSignedHttpRequest(new Request('https://api.example.com/resource', { method: 'POST', body: 'original' }));
    assert.equal((await profile.verifySignedHttpRequest(signed.clone())).domain, 'agent.example.com');
    const tampered = new Request(signed.url, { method: signed.method, headers: signed.headers, body: 'tampered' });
    await assert.rejects(() => profile.verifySignedHttpRequest(tampered));
  }
  try {
    // F1: real selected factory must translate deployment JOSE vocabulary.
    const outcome = await open().then(manager => ({ ok: true as const, manager }), error => ({ ok: false as const, error }));
    assert.equal(outcome.ok, true, 'deployment must construct through the actual selected GCP package');
    const manager = outcome.manager; const provider = manager.getKeyProvider()!;
    assert.equal((await provider.signingKey()).kid, published.kid);
    assert.equal(reads, 1); assert.equal(creates, 0); assert.equal(signs, 0);
    await roundTrip(manager);
    const before = creates; const signedBefore = signs;
    await assert.rejects(() => open(b), /configured operational key does not match/);
    assert.equal(creates, before); assert.equal(signs, signedBefore);
    for (const unsupported of mode === 'existing' ? ['ES256', 'unknown'] : ['ES256', 'EC_SIGN_ED25519', 'unknown']) {
      const readsBefore: number = reads;
      await assert.rejects(() => open(a, unsupported));
      assert.equal(reads, readsBefore); assert.equal(creates, before); assert.equal(signs, signedBefore);
    }
    const bRaw = createPublicKey(keys.get(b)!).export({ format: 'jwk' });
    const bKid = await jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: bRaw.x!, kid: '', alg: 'EdDSA' });
    for (failure of ['create', 'read', 'metadata'] as const) {
      await assert.rejects(() => provider.generateKey());
      assert.deepEqual(await provider.listKeyIds(), [published.kid]);
      await assert.rejects(() => provider.jwk(bKid));
      const signCalls: number = signs;
      await assert.rejects(() => provider.signKey(bKid, new Uint8Array([1])));
      assert.equal(signs, signCalls);
      await roundTrip(manager);
    }
    failure = undefined;
    const pending = await provider.generateKey();
    assert.equal(pending, bKid); assert.deepEqual(await provider.listKeyIds(), [published.kid]);
    await roundTrip(manager); // Pending B did not change publication A or consumer signing.
    await provider.activate(pending);
    const payload = Buffer.from('explicit local activation, not public rotation');
    assert(verify(null, payload, createPublicKey(keys.get(b)!), await provider.sign(payload)));
    await assert.rejects(() => provider.signKey(published.kid, payload));
    assert.deepEqual(await provider.listKeyIds(), [pending]);
    await provider.supersede(published.kid);
    assert(verify(null, payload, createPublicKey(keys.get(b)!), await provider.sign(payload)));
  } finally {
    for (const [name, original] of originals) Object.defineProperty(prototype, name, { value: original, writable: true, configurable: true });
    await rm(dir, { recursive: true, force: true });
  }
}
