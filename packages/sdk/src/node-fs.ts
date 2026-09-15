import * as fs from 'node:fs/promises';

export async function readJson<T>(filePath: string): Promise<T> {
  const raw = await fs.readFile(filePath, 'utf-8');
  try {
    return JSON.parse(raw) as T;
  } catch (e) {
    throw new Error(`${filePath}: ${(e as Error).message}`);
  }
}
