import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export async function withTemp(fn: (root: string) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), 'dnsid-config-'));
  try { await fn(root); } finally { await rm(root, { recursive: true, force: true }); }
}

export async function writeKeyPair(dir: string, kid: string, filename = 'private.jwk'): Promise<void> {
  const pair = await crypto.subtle.generateKey(
    { name: 'Ed25519' } as AlgorithmIdentifier,
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;
  await writeFile(join(dir, filename), JSON.stringify({
    ...(await crypto.subtle.exportKey('jwk', pair.privateKey)),
    kid,
    alg: 'EdDSA',
    use: 'sig',
  }));
}
