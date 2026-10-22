// Testnet setup, durable files, and a single-process signing gate.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import {
  createJoseProfile, validateDnsidConfig, VerificationCode,
  type KeyProvider, type ManagedKeyRotationResult, type VerifiedDomain,
} from '@dnsid-ai/sdk';
import {
  constructIdentityManager, createNodeIdentityManager, createRegistryClientFromEnvironment,
  loadEnvironment, LocalKeyProvider,
} from '@dnsid-ai/sdk/node';

export async function openDemo() {
  const configDir = process.env.DNSID_CONFIG_DIR;
  assert(configDir && process.env.DNSID_LOG_POLICY_URL, 'run with dnsid local run');
  const directory = path.resolve(configDir, 'rotation-ts');
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await syncDirectory(path.dirname(directory));
  const keyPath = path.join(directory, 'keys.json');
  const journalPath = path.join(directory, 'rotation.json');
  let rotation = await readRotation(journalPath);
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
  // Terminal recovery must not run network-backed configuration discovery.
  const manager = rotation?.activated
    ? await createNodeIdentityManager(validateDnsidConfig(loaded.dnsid), { keyProvider })
    : await constructIdentityManager(loaded, { keyProvider });
  const { domain, logRef } = manager.config.identity!;
  if (rotation) {
    assert.equal(rotation.domain, domain);
    assert.equal(rotation.logReference, logRef);
  }
  const registryClient = await createRegistryClientFromEnvironment();

  // shortcut: one process owns this store; add locking and request draining before sharing it.
  let paused = rotation !== undefined;
  let publication: VerifiedDomain;
  const profile = createJoseProfile({ domain, keyProvider, identityResolver: {
    async verifyDomain(requested) {
      assert.equal(requested, domain);
      return publication; // Local self-checks do not apply counterparty policy.
    },
  } });

  return {
    manager, keyProvider, keyPath, registryClient,
    get rotation() { return rotation; },
    async persistRotation(state: ManagedKeyRotationResult) {
      await save(journalPath, { ...state, entryBytes: Buffer.from(state.entryBytes).toString('base64') });
      rotation = state;
      console.log(`saved: ${state.submission?.state ?? 'prepared'}, activated=${state.activated}, paused=${state.applicationSigningPaused}`);
    },
    async setApplicationSigningPaused(value: boolean) {
      if (!value) assert(rotation?.activated, 'activation must be durable before unpausing');
      paused = value;
    },
    async setApplicationSigner(provider: KeyProvider, kid: string) {
      assert.equal(provider, keyProvider);
      assert.equal((await provider.signingKey()).kid, kid);
    },
    async resolveKeyProvider(reference: string) {
      assert.equal(reference, keyPath, 'unexpected saved provider');
      return keyProvider;
    },
    async signAndVerify(evidence: VerifiedDomain) {
      assert(!paused, 'application signing is paused');
      assert.equal(evidence.record.lr, logRef, 'CLI log reference does not match publication');
      publication = evidence;
      const message = await profile.createJWS(new TextEncoder().encode('rotation example'));
      await profile.verifyJWS(message);
      return message;
    },
    async saveOldMessage(message: string) {
      await save(path.join(directory, 'old-message.json'), message);
    },
    async rejectOldMessage() {
      const message = JSON.parse(await fs.readFile(path.join(directory, 'old-message.json'), 'utf8'));
      await assert.rejects(() => profile.verifyJWS(message), { code: VerificationCode.KeyNotFound });
    },
  };
}

async function readRotation(journalPath: string): Promise<ManagedKeyRotationResult | undefined> {
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
