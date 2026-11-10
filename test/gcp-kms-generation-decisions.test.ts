import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';

// Install offline safety before provider imports execute. All credentials are fake;
// injected clients below are the only permitted Google dependency.
const offline = vi.hoisted(async () => {
  const environment = [
    'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_EC2_METADATA_DISABLED',
    'GOOGLE_APPLICATION_CREDENTIALS', 'GCE_METADATA_HOST',
  ].map(name => [name, process.env[name]] as const);
  const restores: Array<() => void> = [];
  const fetch = globalThis.fetch;
  process.env.AWS_ACCESS_KEY_ID = 'fake-offline';
  process.env.AWS_SECRET_ACCESS_KEY = 'fake-offline';
  process.env.AWS_EC2_METADATA_DISABLED = 'true';
  process.env.GOOGLE_APPLICATION_CREDENTIALS = '/nonexistent/dnsid-test-only.json';
  process.env.GCE_METADATA_HOST = '127.0.0.1:9';
  const forbidden = () => { throw new Error('offline fake-only test forbids network'); };
  for (const [module, methods] of [
    ['node:http', ['request', 'get']], ['node:https', ['request', 'get']],
    ['node:net', ['connect', 'createConnection']], ['node:tls', ['connect']],
  ] as const) {
    const { default: api } = await import(module);
    for (const method of methods) {
      const guard = vi.spyOn(api, method).mockImplementation(forbidden);
      restores.push(() => guard.mockRestore());
    }
  }
  globalThis.fetch = forbidden;
  return () => {
    restores.reverse().forEach(restore => restore());
    globalThis.fetch = fetch;
    for (const [name, value] of environment) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  };
});
// Keep guards installed for every case, then restore only this file's mutations.
afterAll(async () => (await offline)());

import { ArgumentError } from '@dnsid-ai/protocol';
import { GcpCloudKmsKeyProvider } from '@dnsid-ai/key-gcp';

// Mode: fake-only for every TC (Google fault injection + fake clock).
// Contract: rotation readiness and service-error boundaries;
// packages/key-gcp/README.md (generation, pending eligibility, active signer);
// docs/reference/dnsid-key-gcp.md#create (20 delayed reads, 250ms, caller deadlines);
// docs/reference/dnsid-protocol-classes.md#argumenterror (invalid caller argument).
// The supplied contract extends the documented first-create readiness budget to
// rotation. No assertion here classifies incompatible parent configuration.
const PARENT = 'projects/test/locations/global/keyRings/agents/cryptoKeys/signer';
const OLD = `${PARENT}/cryptoKeyVersions/7`;
const PENDING = `${PARENT}/cryptoKeyVersions/8`;
const CREATED = `${PARENT}/cryptoKeyVersions/9`;
const ALGORITHM = 'EC_SIGN_ED25519';
const MESSAGE = new Uint8Array([0, 255, 128, 42]);
// Existing lifecycle suite's independent RFC8032 fixtures, plus a distinct
// deterministic test seed. Expected public identity comes from node:crypto only.
const seeds = [
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
  '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
  '03'.repeat(32),
];
const keys = new Map([OLD, PENDING, CREATED].map((name, i) => [name,
  createPrivateKey({ key: Buffer.from('302e020100300506032b657004220420' + seeds[i], 'hex'), format: 'der', type: 'pkcs8' })]));
function kid(name: string) {
  const { crv, kty, x } = createPublicKey(keys.get(name)!).export({ format: 'jwk' });
  return createHash('sha256').update(JSON.stringify({ crv, kty, x })).digest('base64url');
}
function crc(bytes: Uint8Array) {
  let c = 0xffffffff;
  for (const b of bytes) { c ^= b; for (let i = 0; i < 8; i++) c = (c >>> 1) ^ ((c & 1) ? 0x82f63b78 : 0); }
  return (c ^ 0xffffffff) >>> 0;
}
function metadata(state = 'ENABLED') { return { name: CREATED, state, algorithm: ALGORITHM, protectionLevel: 'SOFTWARE' }; }
function cloud() {
  return {
    getCryptoKey: vi.fn(async () => [{ name: PARENT, purpose: 'ASYMMETRIC_SIGN', versionTemplate: { algorithm: ALGORITHM, protectionLevel: 'SOFTWARE' } }]),
    createCryptoKeyVersion: vi.fn(async (_request: unknown) => [metadata()]),
    getCryptoKeyVersion: vi.fn(async (_request: { name: string }) => [metadata()]),
    getPublicKey: vi.fn(async ({ name }: { name: string }) => {
      const pem = createPublicKey(keys.get(name)!).export({ type: 'spki', format: 'pem' }).toString();
      return [{ name, algorithm: ALGORITHM, protectionLevel: 'SOFTWARE', pem, pemCrc32c: { value: crc(Buffer.from(pem)) } }];
    }),
    asymmetricSign: vi.fn(async ({ name, data }: { name: string; data: Uint8Array }) => {
      const signature = sign(null, data, keys.get(name)!);
      return [{ name, signature, signatureCrc32c: { value: crc(signature) }, verifiedDataCrc32c: true }];
    }),
    createCryptoKey: vi.fn(), updateCryptoKeyVersion: vi.fn(), destroyCryptoKeyVersion: vi.fn(),
    importCryptoKeyVersion: vi.fn(), updateCryptoKeyPrimaryVersion: vi.fn(), close: vi.fn(),
  };
}
async function setup() {
  const client = cloud();
  const config = { activeKeyVersion: OLD, algorithm: ALGORITHM };
  const provider = await GcpCloudKmsKeyProvider.load(client, config);
  // Preserve an already pending successor as well as the active key on failure.
  client.createCryptoKeyVersion.mockResolvedValueOnce([{ ...metadata(), name: PENDING }]);
  expect(await provider.generateKey('EdDSA')).toBe(kid(PENDING));
  client.createCryptoKeyVersion.mockClear(); client.getPublicKey.mockClear();
  return { client, provider, config };
}
function outcome(operation: Promise<unknown>) {
  return operation.then(value => ({ value, error: undefined }), (error: unknown) => ({ value: undefined, error }));
}
function chain(error: unknown) {
  const values: unknown[] = [];
  while (error instanceof Error && !values.includes(error)) { values.push(error); error = error.cause; }
  return values;
}
function noRemoteMutation(client: ReturnType<typeof cloud>) {
  for (const method of ['createCryptoKey', 'updateCryptoKeyVersion', 'destroyCryptoKeyVersion',
    'importCryptoKeyVersion', 'updateCryptoKeyPrimaryVersion', 'close'] as const) expect(client[method]).not.toHaveBeenCalled();
}
async function unchanged(ctx: Awaited<ReturnType<typeof setup>>) {
  const { provider, config, client } = ctx;
  expect(config).toEqual({ activeKeyVersion: OLD, algorithm: ALGORITHM });
  expect((await provider.signingKey()).kid).toBe(kid(OLD));
  expect(await provider.listKeyIds()).toEqual([kid(OLD)]);
  for (const name of [OLD, PENDING]) {
    expect((await provider.jwk(kid(name))).kid).toBe(kid(name));
    expect(verify(null, MESSAGE, createPublicKey(keys.get(name)!), await provider.signKey(kid(name), MESSAGE))).toBe(true);
  }
  await expect(provider.jwk(kid(CREATED))).rejects.toThrow();
  const signs = client.asymmetricSign.mock.calls.length;
  await expect(provider.signKey(kid(CREATED), MESSAGE)).rejects.toThrow();
  await expect(provider.activate(kid(CREATED))).rejects.toThrow();
  expect(client.asymmetricSign).toHaveBeenCalledTimes(signs);
  expect((await provider.signingKey()).kid).toBe(kid(OLD));
  noRemoteMutation(client);
}
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });

describe('GCP generateKey readiness and error boundaries [Mode: fake-only]', () => {
  it('Given unsupported caller algorithm, When generateKey runs, Then ArgumentError precedes Google creation', async () => {
    const ctx = await setup();
    await expect(ctx.provider.generateKey('ES256')).rejects.toBeInstanceOf(ArgumentError);
    expect(ctx.client.createCryptoKeyVersion).not.toHaveBeenCalled();
    expect(ctx.client.getPublicKey).not.toHaveBeenCalled();
    await unchanged(ctx);
  });

  it('Given pending generation, When the same version enables, Then delayed readiness precedes usable pending key without active promotion', async () => {
    const { client, provider } = await setup();
    client.createCryptoKeyVersion.mockResolvedValueOnce([metadata('PENDING_GENERATION')]);
    client.getCryptoKeyVersion.mockResolvedValueOnce([metadata('PENDING_GENERATION')]).mockResolvedValueOnce([metadata()]);
    vi.useFakeTimers(); let settled = false;
    const operation = outcome(provider.generateKey()).then(result => { settled = true; return result; });
    await vi.advanceTimersByTimeAsync(0);
    expect(settled, 'generation must await readiness, not return or reject while pending').toBe(false);
    expect(client.getPublicKey).not.toHaveBeenCalled();
    expect(client.getCryptoKeyVersion).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(249);
    expect(settled).toBe(false); expect(client.getCryptoKeyVersion).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(client.getCryptoKeyVersion).toHaveBeenCalledExactlyOnceWith({ name: CREATED });
    expect(settled).toBe(false); expect(client.getPublicKey).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(250);
    expect(await operation).toEqual({ value: kid(CREATED), error: undefined });
    expect(client.getCryptoKeyVersion.mock.calls).toEqual([[{ name: CREATED }], [{ name: CREATED }]]);
    expect(client.getPublicKey).toHaveBeenCalledExactlyOnceWith({ name: CREATED });
    expect(client.createCryptoKeyVersion).toHaveBeenCalledTimes(1);
    expect(verify(null, MESSAGE, createPublicKey(keys.get(CREATED)!), await provider.signKey(kid(CREATED), MESSAGE))).toBe(true);
    expect((await provider.signingKey()).kid).toBe(kid(OLD));
    expect(await provider.listKeyIds()).toEqual([kid(OLD)]);
    expect((await provider.jwk(kid(PENDING))).kid).toBe(kid(PENDING));
    expect(vi.getTimerCount()).toBe(0); noRemoteMutation(client);
  });

  it('Given permanent pending generation, When 20 delayed reads expire, Then bounded failure retains reference without changing active or pending state', async () => {
    const ctx = await setup(); const { client, provider } = ctx;
    client.createCryptoKeyVersion.mockResolvedValueOnce([metadata('PENDING_GENERATION')]);
    const times: number[] = [];
    client.getCryptoKeyVersion.mockImplementation(async () => { times.push(Date.now()); return [metadata('PENDING_GENERATION')]; });
    vi.useFakeTimers(); const start = Date.now(); let settled = false;
    const operation = outcome(provider.generateKey()).then(result => { settled = true; return result; });
    await vi.advanceTimersByTimeAsync(0);
    expect(settled, 'readiness failure may not bypass the finite polling budget').toBe(false);
    for (let read = 1; read <= 20; read++) {
      await vi.advanceTimersByTimeAsync(249);
      expect(client.getCryptoKeyVersion).toHaveBeenCalledTimes(read - 1); expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      expect(client.getCryptoKeyVersion).toHaveBeenCalledTimes(read); expect(settled).toBe(read === 20);
    }
    const result = await operation;
    expect(result.value).toBeUndefined(); expect(result.error).toBeInstanceOf(Error);
    expect(result.error).not.toBeInstanceOf(ArgumentError);
    expect((result.error as Error).message).toContain(CREATED);
    expect(times.map(time => time - start)).toEqual(Array.from({ length: 20 }, (_, i) => (i + 1) * 250));
    expect(client.getCryptoKeyVersion.mock.calls.every(([request]) => request.name === CREATED)).toBe(true);
    expect(client.createCryptoKeyVersion).toHaveBeenCalledTimes(1); expect(client.getPublicKey).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0); await unchanged(ctx);
  });

  for (const terminal of ['DISABLED', 'DESTROYED']) {
    it(`Given pending generation then ${terminal}, When readiness polls, Then fail with created reference and no state mutation`, async () => {
      const ctx = await setup(); const { client, provider } = ctx;
      client.createCryptoKeyVersion.mockResolvedValueOnce([metadata('PENDING_GENERATION')]);
      client.getCryptoKeyVersion.mockResolvedValueOnce([metadata(terminal)]);
      vi.useFakeTimers();
      const operation = outcome(provider.generateKey());
      await vi.advanceTimersByTimeAsync(250);
      const result = await operation;
      expect(client.getCryptoKeyVersion, 'pending rotation must inspect readiness before deciding terminal state').toHaveBeenCalledExactlyOnceWith({ name: CREATED });
      expect(result.value).toBeUndefined(); expect(result.error).toBeInstanceOf(Error);
      expect(result.error).not.toBeInstanceOf(ArgumentError);
      expect((result.error as Error).message).toContain(CREATED);
      expect(client.getPublicKey).not.toHaveBeenCalled(); expect(client.createCryptoKeyVersion).toHaveBeenCalledTimes(1);
      expect(vi.getTimerCount()).toBe(0); await unchanged(ctx);
    });
  }

  for (const failure of ['create-denied', 'readiness-denied', 'public-denied', 'public-crc', 'public-binding']) {
    it(`Given Google ${failure}, When generateKey rejects, Then service failure is not ArgumentError and known reference/cause survive`, async () => {
      const ctx = await setup(); const { client, provider } = ctx;
      const denied = Object.assign(new Error('fixture Google permission denied'), { code: 7 });
      if (failure === 'create-denied') client.createCryptoKeyVersion.mockRejectedValueOnce(denied);
      if (failure === 'readiness-denied') {
        client.createCryptoKeyVersion.mockResolvedValueOnce([metadata('PENDING_GENERATION')]);
        client.getCryptoKeyVersion.mockRejectedValueOnce(denied);
      }
      if (failure === 'public-denied') client.getPublicKey.mockRejectedValueOnce(denied);
      if (failure === 'public-crc' || failure === 'public-binding') {
        const get = client.getPublicKey.getMockImplementation()!;
        client.getPublicKey.mockImplementationOnce(async request => {
          const [response] = await get(request);
          if (failure === 'public-crc') response.pemCrc32c.value ^= 1;
          else response.name = PENDING;
          return [response];
        });
      }
      vi.useFakeTimers(); const operation = outcome(provider.generateKey());
      await vi.runAllTimersAsync(); const result = await operation;
      expect(result.value).toBeUndefined(); expect(result.error).toBeInstanceOf(Error);
      expect(result.error, 'Google service/integrity failures are not invalid caller input').not.toBeInstanceOf(ArgumentError);
      if (failure.endsWith('denied')) expect(chain(result.error)).toContain(denied);
      if (failure !== 'create-denied') expect((result.error as Error).message).toContain(CREATED);
      expect(client.createCryptoKeyVersion).toHaveBeenCalledTimes(1);
      if (failure === 'readiness-denied') expect(client.getCryptoKeyVersion).toHaveBeenCalledExactlyOnceWith({ name: CREATED });
      expect(vi.getTimerCount()).toBe(0); await unchanged(ctx);
    });
  }
});
