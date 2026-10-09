import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { parseJsonNoDuplicateMembers } from '@dnsid-ai/protocol';
import { managedRegistrationScopeId, normalizeManagedRegistrationName, ManagedRegistrationError, type ManagedRegistrationScope, type ManagedRegistrationState, type ManagedRegistrationStore } from './managed-registration.ts';

/**
 * Named operations are isolated by a digest of registry URL, organization ID, and name. Requires a local POSIX filesystem with atomic rename and directory fsync.
 * Locks are never removed automatically: after an interrupted process, establish that no writer is
 * running, back up the directory, then remove `setup.lock`. Back up the state AND key files;
 * ephemeral/container-local disks do not survive host replacement.
 */
export class FileRegistrationStore implements ManagedRegistrationStore {
  readonly keyStorePath: string;
  private readonly directory: string;
  private locked = false;
  private scope?: ManagedRegistrationScope;
  private rootDirectory: string;

  constructor(directory: string) {
    this.directory = path.resolve(directory);
    this.rootDirectory = this.directory;
    this.keyStorePath = path.join(this.directory, 'operational-key.json');
  }

  forIdentity(scope: ManagedRegistrationScope): FileRegistrationStore {
    scope = { ...scope, name: normalizeManagedRegistrationName(scope.name) };
    if (!scope.registryUrl || !scope.organizationId) throw new ManagedRegistrationError('INVALID_SCOPE', 'storage', false);
    if (this.scope) {
      if (managedRegistrationScopeId(this.scope) !== managedRegistrationScopeId(scope)) throw new ManagedRegistrationError('CONFLICTING_STATE', 'storage', false);
      return this;
    }
    const selected = new FileRegistrationStore(path.join(this.directory, managedRegistrationScopeId(scope)));
    selected.scope = scope;
    selected.rootDirectory = this.directory;
    return selected;
  }

  async acquire(signal: AbortSignal): Promise<() => Promise<void>> {
    signal.throwIfAborted();
    if (!this.scope) throw new ManagedRegistrationError('STORE_NOT_SCOPED', 'storage', false);
    await createDirectory(this.rootDirectory);
    // Old single-operation files cannot safely become a new named operation.
    if ((await fs.readdir(this.rootDirectory)).some(name => !/^[0-9a-f]{64}$/.test(name))) throw new ManagedRegistrationError('CORRUPT_STATE', 'storage', false);
    await createDirectory(this.directory);
    const lock = path.join(this.directory, 'setup.lock');
    let handle;
    try { handle = await fs.open(lock, 'wx', 0o600); }
    catch (cause) {
      if ((cause as NodeJS.ErrnoException).code === 'EEXIST') throw new ManagedRegistrationError('STORE_BUSY', 'storage', false);
      throw cause;
    }
    try {
      signal.throwIfAborted();
      await handle.writeFile(JSON.stringify({ pid: process.pid }));
      await handle.sync();
      await syncDirectory(this.directory);
      this.locked = true;
    } catch (error) {
      await handle.close();
      await fs.unlink(lock);
      throw error;
    }
    return async () => {
      this.locked = false;
      await handle.close();
      await fs.unlink(lock);
      await syncDirectory(this.directory);
    };
  }

  async load(): Promise<ManagedRegistrationState | undefined> {
    this.requireLock();
    const statePath = path.join(this.directory, 'setup.json');
    try { await ownerOnly(statePath); }
    catch (cause) {
      if ((cause as NodeJS.ErrnoException).code !== 'ENOENT') throw cause;
      const entries = (await fs.readdir(this.directory)).filter(name => name !== 'setup.lock');
      if (entries.length) throw new ManagedRegistrationError('CORRUPT_STATE', 'storage', false);
      return undefined;
    }
    let state: ManagedRegistrationState | undefined;
    try {
      state = parseJsonNoDuplicateMembers(await fs.readFile(statePath)) as ManagedRegistrationState;
      for (const field of ['preparedEntryBytes', 'entryBytes'] as const) {
        if (state?.issuance?.[field] === undefined) continue;
        const bytes: unknown = state.issuance[field];
        if (!Array.isArray(bytes) || bytes.some(b => !Number.isInteger(b) || b < 0 || b > 255)) throw new Error('invalid issuance bytes');
        state.issuance = { ...state.issuance, [field]: new Uint8Array(bytes) };
      }
      this.assertScope(state);
      return state;
    } catch (cause) {
      if (cause instanceof ManagedRegistrationError) throw cause;
      throw new ManagedRegistrationError('CORRUPT_STATE', 'storage', false, state, cause);
    }
  }

  async persist(state: ManagedRegistrationState): Promise<void> {
    this.requireLock();
    this.assertScope(state);
    const temp = path.join(this.directory, `setup.${crypto.randomUUID()}.tmp`);
    const file = await fs.open(temp, 'wx', 0o600);
    try {
      try {
        await file.writeFile(JSON.stringify(state, (_key, value) => value instanceof Uint8Array ? Array.from(value) : value));
        await file.sync();
      } finally { await file.close(); }
      await fs.rename(temp, path.join(this.directory, 'setup.json'));
      await syncDirectory(this.directory);
    } finally { await fs.rm(temp, { force: true }); }
  }

  private assertScope(state: ManagedRegistrationState): void {
    if (state.version === 3 && (!this.scope || managedRegistrationScopeId(state) !== managedRegistrationScopeId(this.scope))) throw new ManagedRegistrationError('CONFLICTING_STATE', 'storage', false, state);
  }

  private requireLock(): void {
    if (!this.locked) throw new ManagedRegistrationError('STORE_NOT_LOCKED', 'storage', false);
  }
}

async function createDirectory(directory: string): Promise<void> {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await ownerOnly(directory, true);
  // Another named writer may have just created an ancestor; its entries must also be durable.
  for (let dir = directory; ; dir = path.dirname(dir)) {
    await syncDirectory(dir);
    if (path.dirname(dir) === dir) break;
  }
}

async function ownerOnly(file: string, directory = false): Promise<void> {
  const stat = await fs.lstat(file);
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())
    || (stat.mode & 0o077) !== 0 || (process.getuid && stat.uid !== process.getuid())) {
    throw new ManagedRegistrationError('UNSAFE_STORAGE', 'storage', false);
  }
}

async function syncDirectory(directory: string): Promise<void> {
  const handle = await fs.open(directory, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
}
