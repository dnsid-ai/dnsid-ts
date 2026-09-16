import { lstat, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it, vi } from 'vitest';

import { jwkThumbprint, verifyWithKey } from '@dnsid-ai/sdk';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';

async function withTemp(prefix: string, fn: (dir: string) => Promise<void>) {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  try { await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

async function writeKeyPair(dir: string, kid = 'registry-key') {
  const pair = await crypto.subtle.generateKey(
    { name: 'Ed25519' } as AlgorithmIdentifier,
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;
  const publicJwk = { ...(await crypto.subtle.exportKey('jwk', pair.publicKey)), kid, alg: 'EdDSA', use: 'sig' };
  const privateJwk = { ...(await crypto.subtle.exportKey('jwk', pair.privateKey)), kid, alg: 'EdDSA', use: 'sig' };
  await writeFile(join(dir, 'public.jwk'), JSON.stringify(publicJwk));
  await writeFile(join(dir, 'private.jwk'), JSON.stringify(privateJwk));
}

async function writeP256KeyPair(dir: string, kid = 'p256-key') {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;
  await writeFile(join(dir, 'private.jwk'), JSON.stringify({
    ...(await crypto.subtle.exportKey('jwk', pair.privateKey)),
    kid,
    alg: 'ES256',
    use: 'sig',
  }));
}

describe('LocalKeyProvider.load', () => {
  it('rotates a symlinked store without replacing the link and backs up the target', () => withTemp('dnsid-keys-', async dir => {
    const target = join(dir, 'store', 'keys.json');
    const link = join(dir, 'keys.json');
    await LocalKeyProvider.load(target, true);
    await symlink('store/keys.json', link);
    const provider = await LocalKeyProvider.fromEnvironment({ DNSID_KEY_STORE: link });
    const original = await provider.signingKey();
    const pending = await provider.generateKey();
    const before = await readFile(target, 'utf8');
    await provider.activate(pending);
    expect(await readFile(`${target}.bak`, 'utf8')).toBe(before);
    expect(await (await LocalKeyProvider.load(target)).listKeyIds()).toEqual([pending, original.kid]);
    expect(await (await LocalKeyProvider.load(link)).listKeyIds()).toEqual([pending, original.kid]);
    expect((await lstat(link)).isSymbolicLink()).toBe(true);
    expect((await readdir(dir)).sort()).toEqual(['keys.json', 'store']);
  }));

  it('serializes mutations and keeps a private, recoverable previous generation', () => withTemp('dnsid-keys-', async dir => {
    const path = join(dir, 'keys.json');
    const provider = await LocalKeyProvider.load(path, true);
    const original = await provider.signingKey();
    const pending = await Promise.all(Array.from({ length: 8 }, () => provider.generateKey()));
    const before = await readFile(path, 'utf8');
    expect(JSON.parse(before).pending.map((key: { kid: string }) => key.kid)).toEqual(pending);
    await provider.activate(pending[0]!);
    expect(await readFile(`${path}.bak`, 'utf8')).toBe(before);
    const reloaded = await LocalKeyProvider.load(path);
    expect(await reloaded.listKeyIds()).toEqual([pending[0], original.kid]);
    await provider.supersede(original.kid);
    expect(await (await LocalKeyProvider.load(path)).listKeyIds()).toEqual([pending[0]]);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect((await stat(`${path}.bak`)).mode & 0o777).toBe(0o600);
    expect((await readdir(dir)).sort()).toEqual(['keys.json', 'keys.json.bak']);
  }));

  it('preserves disk and memory on failed replacement and allows a later retry', () => withTemp('dnsid-keys-', async dir => {
    const path = join(dir, 'keys.json');
    const provider = await LocalKeyProvider.load(path, true);
    const original = await provider.signingKey();
    const pending = await provider.generateKey();
    const before = await readFile(path, 'utf8');
    const rename = fs.rename;
    const fault = vi.spyOn(fs, 'rename').mockImplementation(async (from, to) => {
      if (to === path) throw Object.assign(new Error('injected full disk'), { code: 'ENOSPC' });
      return rename(from, to);
    });
    syncBuiltinESMExports();
    try {
      await expect(provider.activate(pending)).rejects.toMatchObject({ code: 'ENOSPC' });
      await expect(provider.generateKey()).rejects.toMatchObject({ code: 'ENOSPC' });
      expect(await provider.signingKey()).toEqual(original);
      expect(await readFile(path, 'utf8')).toBe(before);
      expect((await readdir(dir)).sort()).toEqual(['keys.json', 'keys.json.bak']);
    } finally {
      fault.mockRestore();
      syncBuiltinESMExports();
    }
    await provider.activate(pending);
    expect((await provider.signingKey()).kid).toBe(pending);
  }));

  it.each(['write', 'file-sync', 'directory-sync'] as const)('handles %s failure at the commit boundary', stage => withTemp('dnsid-keys-', async dir => {
    const path = join(dir, 'keys.json');
    const provider = await LocalKeyProvider.load(path, true);
    const original = await provider.signingKey();
    const pending = await provider.generateKey();
    const before = await readFile(path, 'utf8');
    const open = fs.open;
    let directoryOpens = 0;
    const fault = vi.spyOn(fs, 'open').mockImplementation(async (...args: Parameters<typeof fs.open>) => {
      const file = await open(...args);
      const name = String(args[0]);
      const isTargetTemp = name.startsWith(`${path}.`) && !name.startsWith(`${path}.bak.`);
      const fail = () => { throw new Error(`injected ${stage} failure`); };
      if (isTargetTemp && stage === 'write') {
        vi.spyOn(file, 'writeFile').mockImplementation(async () => {
          await file.write('{'); // A torn temp file must never replace the store.
          fail();
        });
      }
      if (isTargetTemp && stage === 'file-sync') vi.spyOn(file, 'sync').mockImplementation(async () => fail());
      if (name === dir && ++directoryOpens === 2 && stage === 'directory-sync') {
        vi.spyOn(file, 'sync').mockImplementation(async () => fail());
      }
      return file;
    });
    syncBuiltinESMExports();
    try {
      await expect(provider.activate(pending)).rejects.toThrow(`injected ${stage} failure`);
      const expectedKid = stage === 'directory-sync' ? pending : original.kid;
      expect((await provider.signingKey()).kid).toBe(expectedKid);
      expect((await (await LocalKeyProvider.load(path)).signingKey()).kid).toBe(expectedKid);
      if (stage !== 'directory-sync') expect(await readFile(path, 'utf8')).toBe(before);
      expect(await readFile(`${path}.bak`, 'utf8')).toBe(before);
      expect((await readdir(dir)).sort()).toEqual(['keys.json', 'keys.json.bak']);
    } finally {
      fault.mockRestore();
      syncBuiltinESMExports();
    }
  }));

  it('does not overwrite a concurrently created initial store', () => withTemp('dnsid-keys-', async dir => {
    const path = join(dir, 'keys.json');
    const providers = await Promise.all(Array.from({ length: 8 }, () => LocalKeyProvider.load(path, true)));
    const ids = await Promise.all(providers.map(provider => provider.signingKey()));
    expect(new Set(ids.map(key => key.kid)).size).toBe(1);
    expect(await readdir(dir)).toEqual(['keys.json']);
  }));

  it('exposes pending public keys while reserving signing for the active key', () => withTemp('dnsid-keys-', async dir => {
    const keyProvider = await LocalKeyProvider.load(join(dir, 'keys.json'), true);
    const active = await keyProvider.signingKey();
    const pendingKid = await keyProvider.generateKey();
    await expect(keyProvider.jwk(pendingKid)).resolves.toMatchObject({ kid: pendingKid });
    await expect(keyProvider.signKey(pendingKid, new Uint8Array([1]))).resolves.toHaveLength(64);
    await expect(keyProvider.signKey(active.kid, new Uint8Array([1]))).resolves.toHaveLength(64);
  }));

  it('only creates a missing key store when requested', () => withTemp('dnsid-keys-', async dir => {
    const path = join(dir, 'nested', 'identity', 'keys.json');

    await expect(LocalKeyProvider.load(path)).rejects.toMatchObject({ code: 'ENOENT' });

    const keyProvider = await LocalKeyProvider.load(path, true);
    await expect(keyProvider.listKeyIds()).resolves.toHaveLength(1);
  }));

  it('creates and rotates ES256 key stores', () => withTemp('dnsid-keys-', async dir => {
    const keyProvider = await LocalKeyProvider.load(join(dir, 'keys.json'), true, 'ES256');
    const active = await keyProvider.signingKey();
    const pendingKid = await keyProvider.generateKey();
    const pending = await keyProvider.jwk(pendingKid);

    expect(active).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' });
    expect(pending).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' });
    await expect(keyProvider.signKey(pendingKid, new Uint8Array([1]))).resolves.toHaveLength(64);
  }));

  it('ignores public.jwk', () => withTemp('dnsid-domain-', async dir => {
    const domainDir = join(dir, 'agent.example.com');
    await mkdir(domainDir, { recursive: true });
    await writeKeyPair(domainDir, 'private-key');
    await writeFile(join(domainDir, 'public.jwk'), '{');

    const keyProvider = await LocalKeyProvider.fromDomain('agent.example.com', dir);

    await expect(keyProvider.listKeyIds()).resolves.toEqual(['private-key']);
  }));

  it('uses private.jwk metadata when public.jwk is absent', () => withTemp('dnsid-domain-', async dir => {
    const domainDir = join(dir, 'agent.example.com');
    await mkdir(domainDir, { recursive: true });
    await writeKeyPair(domainDir, 'private-key');
    await rm(join(domainDir, 'public.jwk'));

    const keyProvider = await LocalKeyProvider.fromDomain('agent.example.com', dir);

    await expect(readFile(join(domainDir, 'public.jwk'), 'utf-8')).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(keyProvider.listKeyIds()).resolves.toEqual(['private-key']);
  }));

  it('derives missing kid, alg, and use from private.jwk', () => withTemp('dnsid-domain-', async dir => {
    const domainDir = join(dir, 'agent.example.com');
    await mkdir(domainDir, { recursive: true });
    const pair = await crypto.subtle.generateKey(
      { name: 'Ed25519' } as AlgorithmIdentifier,
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;
    await writeFile(join(domainDir, 'private.jwk'), JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey)));

    const keyProvider = await LocalKeyProvider.fromDomain('agent.example.com', dir);
    const signingKey = await keyProvider.signingKey();

    expect(signingKey).toMatchObject({ alg: 'EdDSA', use: 'sig' });
    expect(signingKey).not.toHaveProperty('key_ops');
    expect(signingKey.kid).toBe(await jwkThumbprint(signingKey));
  }));

  it('rejects mismatched private.jwk public and private material', () => withTemp('dnsid-domain-', async dir => {
    const domainDir = join(dir, 'agent.example.com');
    await mkdir(domainDir, { recursive: true });
    const first = await crypto.subtle.generateKey({ name: 'Ed25519' } as AlgorithmIdentifier, true, ['sign', 'verify']) as CryptoKeyPair;
    const second = await crypto.subtle.generateKey({ name: 'Ed25519' } as AlgorithmIdentifier, true, ['sign', 'verify']) as CryptoKeyPair;
    const privateJwk = await crypto.subtle.exportKey('jwk', first.privateKey);
    const publicJwk = await crypto.subtle.exportKey('jwk', second.publicKey);
    await writeFile(join(domainDir, 'private.jwk'), JSON.stringify({ ...privateJwk, x: publicJwk.x, kid: 'bad-key' }));

    await expect(LocalKeyProvider.fromDomain('agent.example.com', dir)).rejects.toThrow('mismatched Ed25519');
  }));

  it('loads and signs with an ECDSA P-256 private.jwk', () => withTemp('dnsid-domain-', async dir => {
    await writeP256KeyPair(dir);

    const keyProvider = await LocalKeyProvider.fromDirectory(dir);
    const payload = new Uint8Array([1, 2, 3]);
    const signingKey = await keyProvider.signingKey();
    const signature = await keyProvider.sign(payload);

    expect(signingKey).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig', kid: 'p256-key' });
    expect(signingKey).not.toHaveProperty('d');
    expect(signature).toHaveLength(64);
    expect(await verifyWithKey(payload, signature, signingKey, 'ES256')).toBe(true);
  }));

  it('rejects mismatched ECDSA public and private material', () => withTemp('dnsid-domain-', async dir => {
    const first = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair;
    const second = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair;
    const privateJwk = await crypto.subtle.exportKey('jwk', first.privateKey);
    const publicJwk = await crypto.subtle.exportKey('jwk', second.publicKey);
    await writeFile(join(dir, 'private.jwk'), JSON.stringify({ ...privateJwk, x: publicJwk.x, y: publicJwk.y }));

    await expect(LocalKeyProvider.fromDirectory(dir)).rejects.toThrow('mismatched ES256');
  }));

  it('rejects private.jwk without public metadata', () => withTemp('dnsid-domain-', async dir => {
    const domainDir = join(dir, 'agent.example.com');
    await mkdir(domainDir, { recursive: true });
    await writeFile(join(domainDir, 'private.jwk'), JSON.stringify({ d: 'private' }));

    await expect(LocalKeyProvider.fromDomain('agent.example.com', dir)).rejects.toThrow('private.jwk');
  }));

  it('loads registry CLI JWKs from .dnsid/<fqdn>', () => withTemp('dnsid-domain-', async dir => {
    const domainDir = join(dir, 'agent.example.com');
    await mkdir(domainDir, { recursive: true });
    await writeKeyPair(domainDir);

    const keyProvider = await LocalKeyProvider.fromDomain('agent.example.com.', dir);

    await expect(keyProvider.listKeyIds()).resolves.toEqual(['registry-key']);
    const payload = new Uint8Array([1, 2, 3]);
    const signingKey = await keyProvider.signingKey();
    const signature = await keyProvider.sign(payload);

    expect(signingKey).not.toHaveProperty('d');
    expect(signingKey).not.toHaveProperty('key_ops');
    expect(await verifyWithKey(payload, signature, signingKey, 'EdDSA')).toBe(true);
  }));
});
