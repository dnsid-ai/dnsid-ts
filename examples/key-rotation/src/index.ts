import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import {
  createJoseProfile, resumeManagedOperationalKeyRotation, rotateManagedOperationalKey, VerificationCode,
  type KeyProvider, type ManagedKeyRotationResult,
} from '@dnsid-ai/sdk';
import {
  constructIdentityManager, createRegistryClientFromEnvironment, loadEnvironment, LocalKeyProvider,
} from '@dnsid-ai/sdk/node';

async function main() {
  // shortcut: one process owns this store; add a cross-process lock before sharing it.
  // The local registry hosts ku, status, and the lifecycle log; no server is needed.
  const configDir = process.env.DNSID_CONFIG_DIR;
  assert(configDir && process.env.DNSID_LOG_POLICY_URL, 'run with dnsid local run');
  const directory = path.resolve(configDir, 'rotation-ts');
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await syncDirectory(path.dirname(directory));
  const keyPath = path.join(directory, 'keys.json');
  const journalPath = path.join(directory, 'rotation.json');
  let rotation = await readRotation();
  let keyProvider: LocalKeyProvider;
  try {
    keyProvider = await LocalKeyProvider.load(keyPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT' || rotation) throw error;
    const active = JSON.parse(await fs.readFile(path.join(configDir, 'private.jwk'), 'utf8'));
    await save(keyPath, { active, retained: [], pending: [] });
    keyProvider = await LocalKeyProvider.load(keyPath);
  }
  const loaded = await loadEnvironment();
  assert(loaded.dnsid?.identity?.domain?.endsWith('.test')
    && loaded.dnsid.identity.logRef?.startsWith('c2sp-tlog:testnet:'), 'this example only rotates testnet identities');
  // Inject the saved provider: recovery must not select a different deployment key.
  const manager = await constructIdentityManager(loaded, { keyProvider });
  const domain = manager.config.identity!.domain;
  const logReference = manager.config.identity!.logRef;
  const registryClient = await createRegistryClientFromEnvironment();
  let paused = true; // Signing starts closed and opens only after rotation completes.
  const profile = createJoseProfile({ domain, keyProvider, identityResolver: manager });
  async function sign() {
    assert(!paused, 'application signing is paused');
    return profile.createJWS(new TextEncoder().encode('rotation example'));
  }
  const coordination = {
    async persistRotation(state: ManagedKeyRotationResult) {
      if (rotation) {
        assert.equal(state.entryHash, rotation.entryHash);
        assert.equal(state.idempotencyKey, rotation.idempotencyKey);
      }
      await save(journalPath, { ...state, entryBytes: Buffer.from(state.entryBytes).toString('base64') });
      rotation = state;
      console.log(`saved: ${state.submission?.state ?? 'prepared'}, activated=${state.activated}, paused=${state.applicationSigningPaused}`);
    },
    async setApplicationSigningPaused(value: boolean) {
      if (!value) assert(rotation?.activated, 'activation must be durable before unpausing');
      paused = value; // All example signing goes through sign(); no concurrent requests to drain.
    },
    async setApplicationSigner(provider: KeyProvider, kid: string) {
      assert.equal(provider, keyProvider);
      assert.equal((await provider.signingKey()).kid, kid);
    },
    identityManager: manager,
  };

  if (!rotation) {
    const before = await manager.refreshDomain(domain);
    assert.equal(before.record.lr, logReference, 'CLI log reference does not match publication');
    assert.equal((await keyProvider.signingKey()).kid, before.jwks.currentOperationalSigningKey().kid);
    paused = false;
    const oldMessage = await sign();
    await profile.verifyJWS(oldMessage);
    await save(path.join(directory, 'old-message.json'), oldMessage);
    console.log('old key signs and verifies');
    rotation = await rotateManagedOperationalKey({
      domain, logReference, keyProvider, registryClient, idempotencyKey: randomUUID(),
      previousProviderReference: keyPath, newProviderReference: keyPath, ...coordination,
    });
  } else {
    assert.equal(rotation.domain, domain);
    assert.equal(rotation.logReference, logReference);
    rotation = await resume();
  }
  for (let attempt = 0; !rotation.activated && attempt < 60; attempt++) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    rotation = await resume();
  }
  assert(rotation.activated && !rotation.applicationSigningPaused, 'rotation unresolved; rerun the same command to resume');
  paused = false; // The completed state is terminal; resume does not touch signing.
  const observed = await manager.refreshDomain(domain);
  assert.equal(observed.jwks.keys.length, 1);
  assert.equal(observed.jwks.currentOperationalSigningKey().kid, rotation.newKid);
  assert(!(await keyProvider.listKeyIds()).includes(rotation.previousKid));
  const signed = await sign();
  await profile.verifyJWS(signed);
  const oldMessage = JSON.parse(await fs.readFile(path.join(directory, 'old-message.json'), 'utf8'));
  await assert.rejects(() => profile.verifyJWS(oldMessage), { code: VerificationCode.KeyNotFound });
  console.log(`rotation verified: ${rotation.previousKid} -> ${rotation.newKid}`);
  console.log('new key signs and verifies; old key is absent from the live JWKS and provider');

  async function resume() {
    assert(rotation);
    return resumeManagedOperationalKeyRotation({
      rotation, registryClient, ...coordination,
      async resolveKeyProvider(reference) {
        assert.equal(reference, keyPath, 'unexpected saved provider');
        return keyProvider;
      },
    });
  }

  async function readRotation(): Promise<ManagedKeyRotationResult | undefined> {
    try {
      const saved = JSON.parse(await fs.readFile(journalPath, 'utf8'));
      assert.equal(typeof saved.entryBytes, 'string');
      return { ...saved, entryBytes: Uint8Array.from(Buffer.from(saved.entryBytes, 'base64')) };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }

  async function syncDirectory(directory: string) {
    const handle = await fs.open(directory, 'r');
    try { await handle.sync(); } finally { await handle.close(); }
  }

  async function save(destination: string, value: unknown) {
    const temporary = `${destination}.${randomUUID()}.tmp`;
    const handle = await fs.open(temporary, 'wx', 0o600);
    try {
      await handle.writeFile(JSON.stringify(value, null, 2) + '\n');
      await handle.sync();
    } finally { await handle.close(); }
    await fs.rename(temporary, destination);
    await syncDirectory(path.dirname(destination));
  }
}

main().catch(error => {
  console.error('rotation:', error.message, error.cause?.message ?? '');
  console.error('Rerun the same command to recover; do not delete the saved state.');
  process.exitCode = 1;
});
