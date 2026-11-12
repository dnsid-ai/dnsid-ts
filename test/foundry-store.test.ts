import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { jwkThumbprint } from '@dnsid-ai/sdk';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
import { canonicalBytes } from '@dnsid-ai/log-c2sp-tlog';
import { Deadline, FileFoundryStore, create, deriveRegistrationKey, deriveIssuanceKey, parseFoundryOperation, type FoundryOperation, type FoundryTransaction } from '@dnsid-ai/foundry';
import { ORG, foundryFixture } from './helpers/foundry.ts';
import { withTemp } from './helpers/cli-directory.ts';

const key = { registryUrl: 'https://registry.example', organizationId: ORG, name: 'agent' };

async function initial(directory: string) {
  const fixture = await foundryFixture(directory);
  await create(key.name, fixture.options);
  return { fixture, store: fixture.options.store as FileFoundryStore };
}

describe('FileFoundryStore', () => {
  it('defaults to the shared Foundry directory', () => {
    expect(new FileFoundryStore().directory).toBe(join(homedir(), '.dnsid', 'foundry'));
  });

  it('exports portable JCS, keeps owner-only files, imports unknown members, and looks up identity IDs', async () => {
    await withTemp(async root => {
      const { store } = await initial(join(root, 'source'));
      const bytes = await store.export(key);
      const document = parseFoundryOperation(bytes);
      expect(bytes).toEqual(canonicalBytes(document));
      document.extension = { arbitrary: ['café', 1] };
      const imported = new FileFoundryStore(join(root, 'destination'));
      await imported.import(canonicalBytes(document));
      const byId = await imported.loadById('agent-1', key);
      expect(byId).toEqual(document);
      expect((await stat(imported.directory)).mode & 0o777).toBe(0o700);
      for (const file of await readdir(imported.directory)) expect((await stat(join(imported.directory, file))).mode & 0o777).toBe(0o600);
      await imported.withLock(key, new Deadline(), async transaction => {
        const saved = (await transaction.load())!;
        saved.registryStatus = 'READY'; await transaction.save(saved);
      });
      expect(JSON.parse(Buffer.from(await imported.export(key)).toString()).extension).toEqual(document.extension);
      await expect(imported.import(bytes)).rejects.toMatchObject({ category: 'storage' });
    });
  });

  it('rejects duplicate members, invalid Unicode, versions, phases, private keys, conflicting input and hashes', async () => {
    await withTemp(async root => {
      const { store } = await initial(root);
      const document = JSON.parse(Buffer.from(await store.export(key)).toString());
      for (const modify of [
        (value: any) => { value.schemaVersion = 1; },
        (value: any) => { value.phase = 'later'; },
        (value: any) => { value.phase = 'proof-pending'; },
        (value: any) => { value.registrationKey = 'wrong'; },
        (value: any) => { value.issuanceKey = 'wrong'; },
        (value: any) => { value.signingPaused = 'false'; },
        (value: any) => { value.extension = '\ud800'; },
        (value: any) => { value.initialPublicKey.d = 'private'; },
        (value: any) => { value.creationInput.name = 'different'; },
        (value: any) => { value.issuance = { entryBytes: 'AA', entryHash: 'wrong' }; },
        (value: any) => { value.phase = 'complete'; },
      ]) {
        const altered = structuredClone(document); modify(altered);
        const bytes = new TextEncoder().encode(JSON.stringify(altered));
        expect(() => parseFoundryOperation(bytes)).toThrow();
        await expect(store.import(bytes)).rejects.toThrow();
        expect(JSON.parse(Buffer.from(await store.export(key)).toString())).toEqual(document);
      }
      expect(() => parseFoundryOperation(new TextEncoder().encode('{"schemaVersion":1,"schemaVersion":1}'))).toThrow();
      expect(() => parseFoundryOperation(new Uint8Array([0xff]))).toThrow();
    });
  });

  it('allows different creation and initial key thumbprints only with current key and verified-history acceptance', async () => {
    await withTemp(async root => {
      const { store } = await initial(root);
      const document = parseFoundryOperation(await store.export(key));
      document.creationInput.public_key = { ...document.initialPublicKey, kid: 'same-material-different-id' };
      expect(parseFoundryOperation(canonicalBytes(document))).toEqual(document);
      document.creationInput.public_key = await (await LocalKeyProvider.generate()).signingKey();
      expect(() => parseFoundryOperation(canonicalBytes(document))).toThrow(new TypeError('conflicting frozen creationInput'));
      document.currentPublicKey = document.creationInput.public_key;
      document.issuance = { acceptance: { source: 'registry' } };
      expect(() => parseFoundryOperation(canonicalBytes(document))).toThrow(new TypeError('conflicting frozen creationInput'));
      document.issuance.acceptance = { source: 'verified-history' };
      document.registrationKey = deriveRegistrationKey(ORG, key.name, await jwkThumbprint(document.creationInput.public_key));
      document.issuanceKey = deriveIssuanceKey(document.registrationKey);
      expect(parseFoundryOperation(canonicalBytes(document))).toEqual(document);
      delete document.currentPublicKey;
      expect(() => parseFoundryOperation(canonicalBytes(document))).toThrow(new TypeError('conflicting frozen creationInput'));
    });
  });

  it('serializes competing instances and rejects writes after releasing the lock', async () => {
    await withTemp(async root => {
      const { store } = await initial(root);
      const other = new FileFoundryStore(root);
      const order: string[] = [];
      let escape: FoundryTransaction | undefined;
      let state: FoundryOperation | undefined;
      let locked!: () => void;
      let release!: () => void;
      const acquired = new Promise<void>(resolve => { locked = resolve; });
      const held = new Promise<void>(resolve => { release = resolve; });
      const first = store.withLock(key, new Deadline(), async transaction => {
        escape = transaction; state = await transaction.load();
        order.push('first');
        locked();
        await held;
        await transaction.save({ ...state!, extension: 'saved' });
      });
      let second: Promise<void>;
      try {
        await acquired;
        await expect(other.withLock(key, new Deadline(25), async () => {})).rejects.toMatchObject({ category: 'busy' });
        second = other.withLock(key, new Deadline(), async transaction => {
          order.push('second'); expect((await transaction.load())!.extension).toBe('saved');
        });
      } finally { release(); }
      await Promise.all([first, second]);
      expect(order).toEqual(['first', 'second']);
      await expect(escape!.save(state!)).rejects.toThrow('closed');
    });
  });

  it('drains an already-started write before releasing its lock', async () => {
    await withTemp(async root => {
      const { store } = await initial(root);
      await store.withLock(key, new Deadline(), async transaction => {
        const state = (await transaction.load())!;
        void transaction.save({ ...state, extension: 'unawaited' });
      });
      const saved = JSON.parse(Buffer.from(await store.export(key)).toString());
      expect(saved.extension).toBe('unawaited');
    });
  });

  it('keeps historical IDs after a name is reused and scopes ID lookup to the account', async () => {
    await withTemp(async root => {
      const { store } = await initial(root);
      await store.withLock(key, new Deadline(), async transaction => {
        const operation = (await transaction.load())!;
        operation.identityId = 'agent-2';
        await transaction.save(operation);
      });
      expect((await store.loadById('agent-1', key))?.identityId).toBe('agent-1');
      expect((await store.loadById('agent-2', key))?.identityId).toBe('agent-2');
      expect(await store.loadById('agent-1', { ...key, organizationId: 'other-org' })).toBeUndefined();
    });
  });

  it('fails closed on corrupt persisted state', async () => {
    await withTemp(async root => {
      const { store } = await initial(root);
      const file = (await readdir(root)).find(file => !file.startsWith('id-') && file.endsWith('.json'))!;
      await writeFile(join(root, file), '{broken');
      await expect(store.export(key)).rejects.toMatchObject({ category: 'storage', resumable: false });
    });
  });

  it('excludes another process and reclaims its lock only after the process dies', async () => {
    await withTemp(async root => {
      const { store } = await initial(root);
      const digest = createHash('sha256').update(canonicalBytes([key.registryUrl, key.organizationId, key.name])).digest('base64url');
      const lock = join(root, `${digest}.lock`);
      const child = spawn(process.execPath, ['--input-type=module', '-e', `
        import * as fs from 'node:fs/promises';
        import { randomUUID } from 'node:crypto';
        const lock = process.argv[1];
        const marker = process.pid + '-' + randomUUID();
        const candidate = lock + '-' + marker;
        await fs.mkdir(candidate); await fs.writeFile(candidate + '/' + marker, '');
        await fs.rename(candidate, lock);
        process.send('locked');
        setInterval(() => {}, 1000);
      `, lock], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
      try {
        await once(child, 'message');
        await expect(store.withLock(key, new Deadline(40), async () => {})).rejects.toMatchObject({ category: 'busy' });
        child.kill('SIGKILL'); await once(child, 'exit');
        const exported = await store.export(key, new Deadline(1000));
        expect(parseFoundryOperation(exported).identityId).toBe('agent-1');
      } finally { child.kill('SIGKILL'); }
    });
  });
});
