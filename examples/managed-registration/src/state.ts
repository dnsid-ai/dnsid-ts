import { chmod, mkdir, open, readFile, rename } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fromBase64Url, toBase64Url } from '@dnsid-ai/sdk';

async function syncDirectory(directory: string): Promise<void> {
  const handle = await open(directory, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
}

export async function prepareStateDirectory(directory: string): Promise<void> {
  const created = await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
  if (created) {
    const parent = dirname(created);
    for (let current = directory; ; current = dirname(current)) {
      await syncDirectory(current);
      if (current === parent) break;
    }
  }
}

export async function readState<T>(directory: string, name: string): Promise<T | undefined> {
  let text: string;
  try { text = await readFile(join(directory, name), 'utf8'); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
  // JSON has no byte-array type. Restore the exact signed ISSUANCE bytes on resume.
  return JSON.parse(text, (key, value) => key === 'entryBytes' ? fromBase64Url(value) : value) as T;
}

export async function writeState(directory: string, name: string, value: unknown): Promise<void> {
  const text = JSON.stringify(value, (_key, value) => value instanceof Uint8Array ? toBase64Url(value) : value, 2);
  const target = join(directory, name);
  // ponytail: one process per state directory; use a cross-process lock if shared writers are needed.
  const handle = await open(`${target}.tmp`, 'w', 0o600);
  try {
    await handle.writeFile(text + '\n');
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(`${target}.tmp`, target);
  await syncDirectory(directory);
}
