import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

import {
  C2spCheckpointStoreError,
  C2spTlogVerificationError,
  type TrustedC2spCheckpoint,
  type TrustedC2spCheckpointStore,
} from '@dnsid-ai/log-c2sp-tlog';

import { writeFileAtomically } from './atomic-file.ts';

/** On-disk record for one origin. `rootHash` is base64; `witnessTime` is ISO-8601. */
interface StoredCheckpoint {
  version: 1;
  origin: string;
  treeSize: number;
  rootHash: string;
  witnessTime: string;
}

export interface FileTrustedC2spCheckpointStoreOptions {
  /** How long a writer waits for another process's lock before failing closed. Default 5000 ms. */
  lockTimeoutMs?: number;
  /** A lock file older than this is treated as abandoned by a crashed process and removed. Default 60 000 ms. */
  staleLockMs?: number;
}

/**
 * Durable, file-backed trusted-checkpoint store for Node: one JSON file per log origin under a
 * directory, written atomically (temporary file, fsync, rename, directory fsync) so a crash
 * leaves either the previous checkpoint or the new one, never a torn file. Compare-and-swap is
 * serialized within the process and across processes by an exclusive lock file, so two
 * verifiers cannot each accept a different forked extension of the same trusted checkpoint.
 *
 * Use a local persistent filesystem with working `rename` semantics, not a network filesystem.
 * A missing file is first-contact trust; a corrupt or unreadable file fails closed as
 * {@link C2spCheckpointStoreError} and is never silently replaced, because losing the file
 * loses the rollback defence.
 *
 * `compareAndSwap` refuses to lower a trusted tree size: verification never resets trust. An
 * authorized recovery after a legitimate log restore goes through {@link rebaseline}, which
 * requires the exact current state and is an administrative decision, not a retry.
 */
export class FileTrustedC2spCheckpointStore implements TrustedC2spCheckpointStore {
  private mutations: Promise<unknown> = Promise.resolve();
  private readonly lockTimeoutMs: number;
  private readonly staleLockMs: number;

  private constructor(private readonly directory: string, options: FileTrustedC2spCheckpointStoreOptions) {
    this.lockTimeoutMs = options.lockTimeoutMs ?? 5_000;
    this.staleLockMs = options.staleLockMs ?? 60_000;
  }

  /** Opens `directory`, creating it (mode 0700) when absent. Existing checkpoint files are kept. */
  static async open(directory: string, options: FileTrustedC2spCheckpointStoreOptions = {}): Promise<FileTrustedC2spCheckpointStore> {
    const resolved = path.resolve(directory);
    try {
      await fs.mkdir(resolved, { recursive: true, mode: 0o700 });
    } catch (cause) {
      throw new C2spCheckpointStoreError(`cannot open checkpoint store directory ${resolved}`, cause);
    }
    return new FileTrustedC2spCheckpointStore(resolved, options);
  }

  async load(origin: string, signal?: AbortSignal): Promise<TrustedC2spCheckpoint | undefined> {
    signal?.throwIfAborted();
    return this.read(origin);
  }

  async compareAndSwap(origin: string, expected: TrustedC2spCheckpoint | undefined, candidate: TrustedC2spCheckpoint, signal?: AbortSignal): Promise<boolean> {
    return this.swap(origin, expected, candidate, signal, false);
  }

  /**
   * Replaces the exact current state for `origin` with `replacement` without the monotonic
   * check. This is the authorized recovery path after a legitimate log restore: it accepts a
   * break in continuity on an operator's authority and must never be called by verification.
   * Returns false when the current state is not `expected`, so a concurrent change is noticed.
   */
  async rebaseline(origin: string, expected: TrustedC2spCheckpoint | undefined, replacement: TrustedC2spCheckpoint): Promise<boolean> {
    return this.swap(origin, expected, replacement, undefined, true);
  }

  private async swap(origin: string, expected: TrustedC2spCheckpoint | undefined, candidate: TrustedC2spCheckpoint, signal: AbortSignal | undefined, administrative: boolean): Promise<boolean> {
    if (candidate.origin !== origin) throw new C2spTlogVerificationError('trusted checkpoint origin mismatch');
    signal?.throwIfAborted();
    const operation = this.mutations.then(() => this.withLock(origin, async () => {
      const current = await this.read(origin);
      if (!sameCheckpoint(current, expected)) return false;
      if (!administrative && current && candidate.treeSize < current.treeSize) {
        throw new C2spCheckpointStoreError(
          `refusing to lower the trusted tree size for ${origin} from ${current.treeSize} to ${candidate.treeSize}; an authorized recovery uses rebaseline`,
        );
      }
      // Commit boundary: an abort before this point must prevent the write, not merely reject the promise.
      signal?.throwIfAborted();
      try {
        await writeFileAtomically(this.file(origin), JSON.stringify(encode(candidate), null, 2));
      } catch (cause) {
        throw new C2spCheckpointStoreError(`cannot write trusted checkpoint for ${origin}`, cause);
      }
      return true;
    }));
    this.mutations = operation.catch(() => {});
    return operation;
  }

  private async read(origin: string): Promise<TrustedC2spCheckpoint | undefined> {
    const filePath = this.file(origin);
    let raw: string;
    try {
      raw = await fs.readFile(filePath, 'utf-8');
    } catch (cause) {
      if ((cause as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw new C2spCheckpointStoreError(`cannot read trusted checkpoint for ${origin}`, cause);
    }
    let stored: unknown;
    try {
      stored = JSON.parse(raw);
    } catch (cause) {
      throw new C2spCheckpointStoreError(`trusted checkpoint file for ${origin} is not valid JSON; restore it from backup rather than deleting it`, cause);
    }
    return decode(stored, origin);
  }

  private file(origin: string): string {
    // Origins are URLs; hash them so the file name is safe and bounded.
    return path.join(this.directory, `${createHash('sha256').update(origin).digest('hex')}.json`);
  }

  private async withLock<T>(origin: string, body: () => Promise<T>): Promise<T> {
    const lockPath = `${this.file(origin)}.lock`;
    const deadline = Date.now() + this.lockTimeoutMs;
    for (;;) {
      try {
        const handle = await fs.open(lockPath, 'wx', 0o600);
        try { await handle.writeFile(String(process.pid), 'utf-8'); } finally { await handle.close(); }
        break;
      } catch (cause) {
        if ((cause as NodeJS.ErrnoException).code !== 'EEXIST') {
          throw new C2spCheckpointStoreError(`cannot lock trusted checkpoint for ${origin}`, cause);
        }
        if (await this.removeStaleLock(lockPath)) continue;
        if (Date.now() >= deadline) {
          throw new C2spCheckpointStoreError(`timed out waiting for the trusted checkpoint lock for ${origin}`);
        }
        await new Promise(resolve => setTimeout(resolve, 25));
      }
    }
    try {
      return await body();
    } finally {
      await fs.rm(lockPath, { force: true });
    }
  }

  private async removeStaleLock(lockPath: string): Promise<boolean> {
    try {
      const info = await fs.stat(lockPath);
      if (Date.now() - info.mtimeMs < this.staleLockMs) return false;
      await fs.rm(lockPath, { force: true });
      return true;
    } catch {
      return true; // The holder released it between our attempt and the stat.
    }
  }
}

function encode(checkpoint: TrustedC2spCheckpoint): StoredCheckpoint {
  return {
    version: 1,
    origin: checkpoint.origin,
    treeSize: checkpoint.treeSize,
    rootHash: Buffer.from(checkpoint.rootHash).toString('base64'),
    witnessTime: checkpoint.witnessTime.toISOString(),
  };
}

function decode(stored: unknown, origin: string): TrustedC2spCheckpoint {
  const record = stored as Partial<StoredCheckpoint> | null;
  const witnessTime = typeof record?.witnessTime === 'string' ? new Date(record.witnessTime) : undefined;
  if (
    record === null || typeof record !== 'object' || record.version !== 1 || record.origin !== origin
    || typeof record.treeSize !== 'number' || !Number.isInteger(record.treeSize) || record.treeSize < 0
    || typeof record.rootHash !== 'string' || witnessTime === undefined || Number.isNaN(witnessTime.getTime())
  ) {
    throw new C2spCheckpointStoreError(`trusted checkpoint file for ${origin} is malformed; restore it from backup rather than deleting it`);
  }
  return {
    origin: record.origin,
    treeSize: record.treeSize,
    rootHash: new Uint8Array(Buffer.from(record.rootHash, 'base64')),
    witnessTime,
  };
}

function sameCheckpoint(left: TrustedC2spCheckpoint | undefined, right: TrustedC2spCheckpoint | undefined): boolean {
  if (!left || !right) return left === right;
  return left.origin === right.origin
    && left.treeSize === right.treeSize
    && left.witnessTime.getTime() === right.witnessTime.getTime()
    && left.rootHash.length === right.rootHash.length
    && left.rootHash.every((byte, index) => byte === right.rootHash[index]);
}
