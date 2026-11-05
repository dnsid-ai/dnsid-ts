import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { GcpCloudKmsKeyProvider } from '@dnsid-ai/key-gcp';

// PROVISIONAL contract: dnsid-sdk-compliance@3e5d4d7ca662270739aa28b9e0d86fac2a704949
// docs/sdk-design/{01-core-identity-manager,12-configuration-loading}.md.
// Independent review found no findings; this is NOT maintainer acceptance.
// Mode: fake-only GCP (deterministic scheduling and forbidden mutation traps).
// No manager publication, orchestration, or crash-recovery claims.
const PARENT = 'projects/test/locations/global/keyRings/agents/cryptoKeys/signer';
const OLD = PARENT + '/cryptoKeyVersions/7'; const NEXT = PARENT + '/cryptoKeyVersions/8';
const ALGORITHM = 'EC_SIGN_ED25519';
// RFC8032 section7.1 TEST1 and TEST2 seeds, independent from provider implementations.
function key(seed: string) { return createPrivateKey({ key: Buffer.from('302e020100300506032b657004220420' + seed, 'hex'), format: 'der', type: 'pkcs8' }); }
const keys = new Map([
  [OLD, key('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')],
  [NEXT, key('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb')],
]);
function crc(bytes: Uint8Array) { let c = 0xffffffff; for (const b of bytes) { c ^= b; for (let i = 0; i < 8; i++) c = (c >>> 1) ^ ((c & 1) ? 0x82f63b78 : 0); } return (c ^ 0xffffffff) >>> 0; }
function deferred() { let resolve!: () => void; const promise = new Promise<void>(r => { resolve = r; }); return { promise, resolve }; }
function fakeCloud() {
  const client = {
    getPublicKey: vi.fn(async ({ name }: { name: string }) => {
      const pem = createPublicKey(keys.get(name)!).export({ type: 'spki', format: 'pem' }).toString();
      return [{ name, algorithm: ALGORITHM, protectionLevel: 'SOFTWARE', pem, pemCrc32c: { value: crc(Buffer.from(pem)) } }];
    }),
    createCryptoKeyVersion: vi.fn(async (_request: unknown) => [{ name: NEXT, algorithm: ALGORITHM, state: 'ENABLED', protectionLevel: 'SOFTWARE' }]),
    asymmetricSign: vi.fn(async ({ name, data }: { name: string; data: Uint8Array }) => {
      const signature = sign(null, data, keys.get(name)!);
      return [{ name, signature, signatureCrc32c: { value: crc(signature) }, verifiedDataCrc32c: true }];
    }),
    createCryptoKey: vi.fn(), updateCryptoKeyVersion: vi.fn(), destroyCryptoKeyVersion: vi.fn(),
    updateCryptoKeyPrimaryVersion: vi.fn(), importCryptoKeyVersion: vi.fn(),
  };
  return client;
}
async function setup() {
  const client = fakeCloud(); const config = { activeKeyVersion: OLD, algorithm: ALGORITHM };
  const outcome = await GcpCloudKmsKeyProvider.load(client, config).then(provider => ({ ok: true as const, provider }), error => ({ ok: false as const, error }));
  // Runtime prerequisite only; if it fails, lifecycle RED has NOT been reached.
  expect(outcome, 'runtime prerequisite: existing Ed25519 version opens').toMatchObject({ ok: true });
  if (!outcome.ok) throw new Error('unreachable');
  expect(client.createCryptoKeyVersion).not.toHaveBeenCalled();
  return { client, config, provider: outcome.provider };
}
async function generate(provider: GcpCloudKmsKeyProvider) {
  const outcome = await provider.generateKey().then(kid => ({ ok: true as const, kid }), error => ({ ok: false as const, error }));
  expect(outcome, 'explicit GenerateKey must create a pending Ed25519 version').toMatchObject({ ok: true });
  if (!outcome.ok) throw new Error('unreachable'); return outcome.kid;
}
function noCloudRetirement(client: ReturnType<typeof fakeCloud>) {
  expect(client.updateCryptoKeyVersion).not.toHaveBeenCalled(); expect(client.destroyCryptoKeyVersion).not.toHaveBeenCalled();
  expect(client.updateCryptoKeyPrimaryVersion).not.toHaveBeenCalled(); expect(client.createCryptoKey).not.toHaveBeenCalled();
  expect(client.importCryptoKeyVersion).not.toHaveBeenCalled();
}

describe('GCP provisional lifecycle (#56; Mode: fake-only)', () => {
  it('Given active version, When explicitly generating, Then same-parent successor is pending without active/config change', async () => {
    const { client, config, provider } = await setup(); const old = await provider.signingKey();
    const kid = await generate(provider);
    expect(kid).not.toBe(old.kid); expect(kid).not.toContain('#');
    expect(client.createCryptoKeyVersion).toHaveBeenCalledTimes(1);
    // Cloud KMS version algorithm is service output, not a required request field.
    // The independent pending JWK/signature checks below prove Ed25519.
    expect(client.createCryptoKeyVersion).toHaveBeenCalledWith(expect.objectContaining({ parent: PARENT }));
    expect(config).toEqual({ activeKeyVersion: OLD, algorithm: ALGORITHM });
    expect(await provider.signingKey()).toEqual(old); expect(await provider.listKeyIds()).toEqual([old.kid]);
    const pending = await provider.jwk(kid);
    expect(pending).toMatchObject({ kid, kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA' }); expect(pending).not.toHaveProperty('d');
    const payload = new Uint8Array([0, 255, 128, 42]);
    expect(verify(null, payload, createPublicKey(keys.get(NEXT)!), await provider.signKey(kid, payload))).toBe(true);
    expect(verify(null, payload, createPublicKey(keys.get(OLD)!), await provider.sign(payload))).toBe(true);
    noCloudRetirement(client);
  });

  it('Given pending successor, When explicitly activated, Then only successor is active and previous signing is denied', async () => {
    const { client, provider } = await setup(); const old = await provider.signingKey(); const kid = await generate(provider);
    await provider.activate(kid);
    expect((await provider.signingKey()).kid).toBe(kid); expect(await provider.listKeyIds()).toEqual([kid]);
    expect(await provider.jwk(old.kid)).toEqual(old);
    await expect(provider.signKey(old.kid, new Uint8Array([1]))).rejects.toThrow();
    await provider.supersede(old.kid);
    expect((await provider.signingKey()).kid).toBe(kid); expect(await provider.listKeyIds()).toEqual([kid]);
    noCloudRetirement(client);
  });

  for (const method of ['supersede', 'purge'] as const) {
    it(`Given sole active key, When ${method} is called, Then local signing stops and live list is empty without cloud retirement`, async () => {
      const { client, provider } = await setup(); const old = await provider.signingKey();
      const outcome = await provider[method](old.kid).then(() => ({ ok: true }), error => ({ ok: false, error }));
      expect(outcome, `${method} governs local eligibility`).toMatchObject({ ok: true });
      expect(await provider.listKeyIds()).toEqual([]);
      await expect(provider.sign(new Uint8Array([1]))).rejects.toThrow();
      await expect(provider.signKey(old.kid, new Uint8Array([1]))).rejects.toThrow();
      noCloudRetirement(client);
    });
  }

  it('Given an old signature in flight, When activation starts, Then promotion drains it and no new old-key signing enters', async () => {
    const { client, provider } = await setup(); const kid = await generate(provider);
    const entered = deferred(); const release = deferred(); const original = client.asymmetricSign.getMockImplementation()!;
    client.asymmetricSign.mockImplementationOnce(async request => { entered.resolve(); await release.promise; return original(request); });
    const payload = new Uint8Array([12]); const signing = provider.sign(payload); await entered.promise;
    let promoted = false;
    const activation = provider.activate(kid).then(() => { promoted = true; });
    try {
      // Explicit scheduler turns; no wall-clock sleeps or network timing dependency.
      await new Promise<void>(resolve => setImmediate(resolve));
      expect(promoted, 'activation must wait for the old in-flight signature').toBe(false);
      const calls = client.asymmetricSign.mock.calls.length;
      // A concurrent request may reject or wait for promotion; neither may enter
      // KMS with the old key while activation is draining.
      const concurrent = provider.sign(payload).then(value => ({ value }), error => ({ error }));
      await new Promise<void>(resolve => setImmediate(resolve));
      expect(client.asymmetricSign.mock.calls.length).toBe(calls);
      release.resolve(); await signing; await activation;
      const result = await concurrent;
      if ('value' in result) expect(verify(null, payload, createPublicKey(keys.get(NEXT)!), result.value)).toBe(true);
      expect((await provider.signingKey()).kid).toBe(kid);
    } finally { release.resolve(); await Promise.allSettled([signing, activation]); }
    noCloudRetirement(client);
  });
});
