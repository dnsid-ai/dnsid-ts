import * as fs from 'node:fs/promises';
import * as path from 'node:path';

/**
 * Publish `contents` at `filePath` through a fully flushed sibling file: write a temporary file
 * created exclusively with `mode`, fsync it, then rename it into place (or hard-link it when
 * `exclusive`, so an existing destination is never replaced). The destination is never
 * truncated, so a reader sees either the previous complete file or the new one.
 *
 * `committed` runs once the rename has made the new contents visible, before the directory
 * fsync: the rename is the visibility boundary even if the directory sync fails.
 */
export async function writeFileAtomically(
  filePath: string,
  contents: string,
  options: { mode?: number; exclusive?: boolean; committed?: () => void } = {},
): Promise<void> {
  const tempPath = `${filePath}.${crypto.randomUUID()}.tmp`;
  const file = await fs.open(tempPath, 'wx', options.mode ?? 0o600);
  try {
    try {
      await file.writeFile(contents, 'utf-8');
      await file.sync();
    } finally {
      await file.close();
    }
    if (options.exclusive) await fs.link(tempPath, filePath);
    else await fs.rename(tempPath, filePath);
    options.committed?.();
    await syncDirectory(path.dirname(filePath));
  } finally {
    await fs.rm(tempPath, { force: true });
  }
}

/** fsync a directory so a rename or link within it is durable. */
export async function syncDirectory(dir: string): Promise<void> {
  const directory = await fs.open(dir, 'r');
  try { await directory.sync(); } finally { await directory.close(); }
}
