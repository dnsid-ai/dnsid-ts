import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { KeyProvider } from '@dnsid-ai/protocol';
import type { KeySource } from '../packages/sdk/src/config-loading.js';

// Authority: dnsid-sdk-compliance@3e5d4d7ca662270739aa28b9e0d86fac2a704949,
// docs/sdk-design/12-configuration-loading.md and docs/key-provider-packages.md.
// Mode: fake-only for optional-package availability; real isolated temporary files.
// No production network or credential chain is used.
const VERSION = 'projects/test/locations/global/keyRings/agents/cryptoKeys/signer/cryptoKeyVersions/7';
const source: KeySource = { provider: 'google-kms', keyRef: VERSION, settings: { algorithm: 'EC_SIGN_ED25519' } };
const identity = { domain: 'agent.example.com', governanceId: 'example.com', logRef: 'test:agent',
  statusUrl: 'https://agent.example.com/status', ekUrl: 'https://example.com/ek', kuUrl: 'https://agent.example.com/keys' };
function signer(): KeyProvider {
  const jwk = { kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', kid: 'injected', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' };
  return { signingKey: vi.fn(async () => jwk), jwk: vi.fn(async () => jwk), listKeyIds: vi.fn(async () => [jwk.kid]),
    sign: vi.fn(), signKey: vi.fn(), generateKey: vi.fn(), activate: vi.fn(), supersede: vi.fn() };
}
afterEach(() => { vi.doUnmock('@dnsid-ai/key-gcp'); vi.doUnmock('@dnsid-ai/key-aws'); vi.resetModules(); });

describe('GCP config (#56; Mode: fake-only optional packages)', () => {
  it('Given selected absent package, When validating, Then return actionable ArgumentError without file fallback', async () => {
    vi.doMock('@dnsid-ai/key-gcp', () => { throw Object.assign(new Error('package absent'), { code: 'ERR_MODULE_NOT_FOUND' }); });
    const { validateKeySource, operationalKeyProvider } = await import('../packages/sdk/src/config-loading.js');
    for (const action of [() => validateKeySource(source), () => operationalKeyProvider(source, identity.domain)]) {
      const result = await action().then(() => ({ ok: true }), error => ({ ok: false, name: error.name, message: error.message }));
      expect(result).toMatchObject({ ok: false, name: 'ArgumentError' });
      expect(result).toHaveProperty('message', expect.stringMatching(/google-kms|key-gcp/i));
      expect(result).toHaveProperty('message', expect.stringMatching(/install|build|bundle/i));
    }
  });

  it('Given only GCP selected, When availability is checked, Then lazy import only the fixed GCP package', async () => {
    const selected = vi.fn(() => ({ GcpCloudKmsKeyProvider: { load: vi.fn() } }));
    const other = vi.fn(() => { throw new Error('unselected AWS'); });
    vi.doMock('@dnsid-ai/key-gcp', selected); vi.doMock('@dnsid-ai/key-aws', other);
    const { validateKeySource } = await import('../packages/sdk/src/config-loading.js');
    expect(selected).not.toHaveBeenCalled(); expect(other).not.toHaveBeenCalled();
    const result = await validateKeySource(source).then(() => ({ ok: true }), error => ({ ok: false, error }));
    expect(result).toMatchObject({ ok: true });
    expect(selected).toHaveBeenCalledTimes(1); expect(other).not.toHaveBeenCalled();
  });

  it('Given an arbitrary module name, When validating, Then reject instead of resolving it', async () => {
    const selected = vi.fn(() => { throw new Error('must not import'); });
    vi.doMock('@dnsid-ai/key-gcp', selected);
    const { validateKeySource } = await import('../packages/sdk/src/config-loading.js');
    await expect(validateKeySource({ ...source, provider: './attacker-provider.js' as KeySource['provider'] })).rejects.toThrow();
    expect(selected).not.toHaveBeenCalled();
  });

  it('Given injected signer and invalid unavailable source, When constructing, Then bypass all displaced resolution', async () => {
    const selected = vi.fn(() => { throw new Error('must not load GCP'); });
    vi.doMock('@dnsid-ai/key-gcp', selected);
    const { constructIdentityManager } = await import('../packages/sdk/src/config-loading.js');
    const injected = signer();
    const result = await constructIdentityManager({ dnsid: { identity }, keySource: {
      ...source, keyRef: '', settings: { privateKey: 'displaced-invalid-settings' }, cliDirectory: '/must-not-open',
    } }, { keyProvider: injected }).then(() => ({ ok: true }), error => ({ ok: false, error }));
    expect(result).toMatchObject({ ok: true }); expect(selected).not.toHaveBeenCalled();
    expect(injected.generateKey).not.toHaveBeenCalled(); expect(injected.activate).not.toHaveBeenCalled();
  });

  it('Given local source then cloud overlay, When merged, Then replace operational group but keep entity path', async () => {
    const { mergeLoadedConfig } = await import('../packages/sdk/src/config-loading.js');
    expect(mergeLoadedConfig({ keySource: { provider: 'file', cliDirectory: '/unused/cli', keyStorePath: '/unused/keys', entityKeyPath: '/unused/entity' } },
      { keySource: source }).keySource).toEqual({ ...source, entityKeyPath: '/unused/entity' });
  });

  it('Given cloud deployment JSON, When loaded, Then parse without importing provider or changing files', async () => {
    const selected = vi.fn(() => { throw new Error('loader must not import provider'); });
    vi.doMock('@dnsid-ai/key-gcp', selected);
    const { loadFile } = await import('../packages/sdk/src/config-loading.js');
    const dir = await mkdtemp(join(tmpdir(), 'dnsid-gcp-config-'));
    const file = join(dir, 'config.json'); const bytes = JSON.stringify({ dnsid: { identity }, keySource: source });
    try {
      await writeFile(file, bytes);
      expect((await loadFile(file)).keySource).toEqual(source);
      expect(selected).not.toHaveBeenCalled(); expect(await readFile(file, 'utf8')).toBe(bytes);
      expect(await readdir(dir)).toEqual(['config.json']);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it('Given selected cloud factory, When opening existing key, Then never generate, import, export, or activate', async () => {
    const provider = signer(); const load = vi.fn(async () => provider);
    vi.doMock('@dnsid-ai/key-gcp', () => ({ GcpCloudKmsKeyProvider: { load } }));
    const { operationalKeyProvider } = await import('../packages/sdk/src/config-loading.js');
    const result = await operationalKeyProvider(source, identity.domain).then(value => ({ ok: true, value }), error => ({ ok: false, error }));
    expect(result).toMatchObject({ ok: true, value: provider });
    expect(load).toHaveBeenCalledTimes(1);
    expect(load.mock.calls[0]).toEqual(expect.arrayContaining([expect.objectContaining({ activeKeyVersion: VERSION, algorithm: 'EC_SIGN_ED25519' })]));
    expect(provider.generateKey).not.toHaveBeenCalled(); expect(provider.activate).not.toHaveBeenCalled();
    expect(provider.sign).not.toHaveBeenCalled();
  });

  for (const invalid of [
    { ...source, cliDirectory: '/must-not-open' }, { ...source, keyStorePath: '/must-not-open' },
    { ...source, keyRef: '' }, { ...source, settings: { algorithm: 'EC_SIGN_P256_SHA256' } },
    { ...source, settings: { algorithm: 'EC_SIGN_ED25519', privateKey: 'secret-not-permitted' } },
  ]) it(`Given invalid selection ${JSON.stringify(invalid)}, When validating, Then fail before opening`, async () => {
    const load = vi.fn(); vi.doMock('@dnsid-ai/key-gcp', () => ({ GcpCloudKmsKeyProvider: { load } }));
    const { validateKeySource } = await import('../packages/sdk/src/config-loading.js');
    await expect(validateKeySource(invalid)).rejects.toThrow(); expect(load).not.toHaveBeenCalled();
  });
});
