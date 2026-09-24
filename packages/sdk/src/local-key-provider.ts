import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { createPrivateKey } from 'node:crypto';

import { ArgumentError, jwkSignatureAlg, jwkThumbprint, normalizeFQDN, verifyWithKey } from '@dnsid-ai/protocol';
import type { DnsIdJWK, KeyProvider } from '@dnsid-ai/protocol';

import { readJson } from './node-fs.ts';

/** Private JWK stored on disk. `d` holds the private scalar (base64url). */
interface StoredKey extends DnsIdJWK {
  d: string;
}

export type LocalKeyAlgorithm = 'EdDSA' | 'ES256';

interface PrivateJwk extends Partial<DnsIdJWK> {
  d: string;
}

interface KeyStore {
  active: StoredKey;
  retained: StoredKey[];
  pending: StoredKey[];
}

/**
 * File-backed KeyProvider that stores Ed25519 or ECDSA P-256 keys as a JSON file.
 *
 * This concrete key-storage implementation is provided by `@dnsid-ai/sdk` as the default developer/runtime key provider.
 * Use only one provider instance/process per file. Mutations within an instance are serialized.
 * Writes require filesystem support for atomic rename, hard links, and directory fsync.
 * Existing symlinks are resolved at load time; `<resolvedPath>.bak` holds the private previous generation.
 * A failure after replacement may mean the new state is visible but not crash-durable;
 * memory follows the visible file. Inspect the store before retrying a failed mutation.
 */
export class LocalKeyProvider implements KeyProvider {
  private store: KeyStore;
  private readonly filePath: string | null;
  // ponytail: per-instance queue; use a cross-process lock and reload before writes if shared writers are needed.
  private mutations: Promise<unknown> = Promise.resolve();

  private constructor(store: KeyStore, filePath: string | null) {
    this.store = store;
    this.filePath = filePath;
  }

  static async load(filePath: string, createIfMissing = false, algorithm: LocalKeyAlgorithm = 'EdDSA'): Promise<LocalKeyProvider> {
    filePath = path.resolve(filePath);
    let store: KeyStore;
    try {
      filePath = await fs.realpath(filePath);
      store = await readJson<KeyStore>(filePath);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT' || !createIfMissing) throw e;
      store = await buildInitialStore(algorithm);
      const createdDirectory = await fs.mkdir(path.dirname(filePath), { recursive: true });
      try {
        await writeStore(filePath, store, undefined, true);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
        store = await readJson<KeyStore>(filePath);
      }
      // Persist newly created directory entries as well as the key file itself.
      if (createdDirectory) {
        const parent = path.dirname(createdDirectory);
        for (let dir = path.dirname(filePath); ; dir = path.dirname(dir)) {
          await syncDirectory(dir);
          if (dir === parent) break;
        }
      }
    }
    return new LocalKeyProvider(store, filePath);
  }

  static async generate(algorithm: LocalKeyAlgorithm = 'EdDSA'): Promise<LocalKeyProvider> {
    return new LocalKeyProvider(await buildInitialStore(algorithm), null);
  }

  static async fromDirectory(dir: string): Promise<LocalKeyProvider> {
    const jwkPath = path.join(dir, 'private.jwk');
    let key: PrivateJwk;
    let keyPath = jwkPath;
    try {
      key = await readJson<PrivateJwk>(jwkPath);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
      keyPath = path.join(dir, 'private.pem');
      const pem = await fs.readFile(keyPath);
      key = createPrivateKey(pem).export({ format: 'jwk' }) as PrivateJwk;
    }
    const active = await validateAndNormalizePrivateJwk(key, keyPath);
    return new LocalKeyProvider({ active, retained: [], pending: [] }, null);
  }

  /** Loads a single private JWK file, including DNSid CLI `entity_key_path` files. */
  static async fromFile(filePath: string): Promise<LocalKeyProvider> {
    const key = await readJson<PrivateJwk>(filePath);
    const active = await validateAndNormalizePrivateJwk(key, filePath);
    return new LocalKeyProvider({ active, retained: [], pending: [] }, null);
  }

  static async fromDomain(domain: string, dnsidDir = path.join(os.homedir(), '.dnsid')): Promise<LocalKeyProvider> {
    return LocalKeyProvider.fromDirectory(path.join(dnsidDir, normalizeFQDN(domain, true)));
  }

  async signingKey(): Promise<DnsIdJWK> {
    return toPublicJwk(this.store.active);
  }

  async jwk(kid: string): Promise<DnsIdJWK> {
    if (this.store.active.kid === kid) return toPublicJwk(this.store.active);
    const retained = this.store.retained.find(k => k.kid === kid);
    if (retained) return toPublicJwk(retained);
    const pending = this.store.pending.find(k => k.kid === kid);
    if (pending) return toPublicJwk(pending);
    throw new ArgumentError(`key not found: ${kid}`);
  }

  async listKeyIds(): Promise<string[]> {
    return [this.store.active.kid, ...this.store.retained.map(k => k.kid)];
  }

  async sign(payload: Uint8Array): Promise<Uint8Array> {
    return this.signKey(this.store.active.kid, payload);
  }

  async signKey(kid: string, payload: Uint8Array): Promise<Uint8Array> {
    const key = kid === this.store.active.kid ? this.store.active : this.store.pending.find(candidate => candidate.kid === kid);
    if (!key) throw new ArgumentError(`key is not active or pending for signing: ${kid}`);
    const cryptoKey = await importPrivateKey(key);
    const sig = await crypto.subtle.sign(signAlgorithm(key), cryptoKey, toArrayBuffer(payload));
    return new Uint8Array(sig);
  }

  async generateKey(): Promise<string> {
    return this.mutate(async next => {
      const key = await generateStoredKey(localKeyAlgorithm(next.active));
      next.pending.push(key);
      return key.kid;
    });
  }

  async activate(kid: string): Promise<void> {
    await this.mutate(next => {
      const idx = next.pending.findIndex(k => k.kid === kid);
      if (idx === -1) throw new ArgumentError(`no pending key with kid "${kid}"`);
      const [incoming] = next.pending.splice(idx, 1) as [StoredKey];
      next.retained.push(next.active);
      next.active = incoming;
    });
  }

  async supersede(kid: string): Promise<void> {
    await this.mutate(next => {
      if (next.active.kid === kid) {
        throw new ArgumentError('cannot supersede the active key; activate a replacement first');
      }
      const idx = next.retained.findIndex(k => k.kid === kid);
      if (idx === -1) throw new ArgumentError(`no retained key with kid "${kid}"`);
      next.retained.splice(idx, 1);
    });
  }

  /** @deprecated Use supersede(). */
  async purge(kid: string): Promise<void> {
    await this.supersede(kid);
  }

  private mutate<T>(change: (next: KeyStore) => T | Promise<T>): Promise<T> {
    const operation = this.mutations.then(async () => {
      const next = structuredClone(this.store);
      const result = await change(next);
      if (this.filePath) {
        await writeStore(`${this.filePath}.bak`, this.store);
        await writeStore(this.filePath, next, () => { this.store = next; });
      } else {
        this.store = next;
      }
      return result;
    });
    this.mutations = operation.catch(() => {});
    return operation;
  }
}

/** Publish a fully flushed sibling file; never truncate the destination. */
async function writeStore(filePath: string, store: KeyStore, committed?: () => void, exclusive = false): Promise<void> {
  const tempPath = `${filePath}.${crypto.randomUUID()}.tmp`;
  const file = await fs.open(tempPath, 'wx', 0o600);
  try {
    try {
      await file.writeFile(JSON.stringify(store, null, 2), 'utf-8');
      await file.sync();
    } finally {
      await file.close();
    }
    if (exclusive) await fs.link(tempPath, filePath);
    else await fs.rename(tempPath, filePath);
    committed?.(); // Rename is the visibility boundary, even if directory fsync fails.
    await syncDirectory(path.dirname(filePath));
  } finally {
    await fs.rm(tempPath, { force: true });
  }
}

async function syncDirectory(dir: string): Promise<void> {
  const directory = await fs.open(dir, 'r');
  try { await directory.sync(); } finally { await directory.close(); }
}

function toPublicJwk(key: StoredKey): DnsIdJWK {
  const { d: _d, ...pub } = key;
  return pub as DnsIdJWK;
}

async function validateAndNormalizePrivateJwk(key: PrivateJwk, filePath: string): Promise<StoredKey> {
  const isEd25519 = key.kty === 'OKP' && key.crv === 'Ed25519' && typeof key.x === 'string';
  const isP256 = key.kty === 'EC' && key.crv === 'P-256' && typeof key.x === 'string' && typeof key.y === 'string';
  if ((!isEd25519 && !isP256) || typeof key.d !== 'string') {
    throw new Error(`${filePath} must include Ed25519 or ECDSA P-256 private key material`);
  }
  const pub: DnsIdJWK = {
    kty: key.kty as string,
    crv: key.crv,
    x: key.x as string,
    ...(isP256 ? { y: key.y as string } : {}),
    kid: typeof key.kid === 'string' ? key.kid : '',
  };
  const alg = jwkSignatureAlg(pub);
  const normalizedPub = { ...pub, alg, use: 'sig', kid: pub.kid || await jwkThumbprint(pub) };
  const normalized = { ...normalizedPub, d: key.d };
  const probe = new TextEncoder().encode('dnsid-local-key-provider-self-check');
  let verified = false;
  try {
    const signature = await crypto.subtle.sign(signAlgorithm(normalized), await importPrivateKey(normalized), probe);
    verified = await verifyWithKey(probe, new Uint8Array(signature), normalizedPub, alg);
  } catch {
    verified = false;
  }
  if (!verified) throw new Error(`${filePath} has mismatched ${alg === 'EdDSA' ? 'Ed25519' : 'ES256'} public/private key material`);
  return normalized;
}

async function buildInitialStore(algorithm: LocalKeyAlgorithm): Promise<KeyStore> {
  return { active: await generateStoredKey(algorithm), retained: [], pending: [] };
}

async function generateStoredKey(algorithm: LocalKeyAlgorithm): Promise<StoredKey> {
  const generationAlgorithm = algorithm === 'EdDSA'
    ? { name: 'Ed25519' } as AlgorithmIdentifier
    : { name: 'ECDSA', namedCurve: 'P-256' } as EcKeyGenParams;
  const pair = await crypto.subtle.generateKey(generationAlgorithm as AlgorithmIdentifier, true, ['sign', 'verify']) as CryptoKeyPair;
  const priv = await crypto.subtle.exportKey('jwk', pair.privateKey) as PrivateJwk;
  // No kid here: validateAndNormalizePrivateJwk names the key by its RFC 7638
  // thumbprint, as the Go SDK does. The registry refuses a public key whose
  // kid is anything else ("kid does not match computed thumbprint"), and
  // published JWKS are verified the same way, so a UUID kid could never
  // register or rotate in.
  return validateAndNormalizePrivateJwk({ ...priv, kid: '' }, 'generated key');
}

function toArrayBuffer(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  if (bytes.buffer instanceof ArrayBuffer && bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
    return bytes as Uint8Array<ArrayBuffer>;
  }
  return new Uint8Array(bytes);
}

function localKeyAlgorithm(key: DnsIdJWK): LocalKeyAlgorithm {
  const alg = jwkSignatureAlg(key);
  if (alg === 'EdDSA' || alg === 'ES256') return alg;
  throw new ArgumentError(`unsupported local key algorithm: ${alg}`);
}

function signAlgorithm(key: DnsIdJWK): AlgorithmIdentifier | EcdsaParams {
  return localKeyAlgorithm(key) === 'EdDSA'
    ? { name: 'Ed25519' } as AlgorithmIdentifier
    : { name: 'ECDSA', hash: 'SHA-256' };
}

async function importPrivateKey(key: StoredKey): Promise<CryptoKey> {
  const alg = localKeyAlgorithm(key);
  return crypto.subtle.importKey(
    'jwk',
    {
      kty: key.kty,
      crv: key.crv,
      x: key.x,
      ...(alg === 'ES256' ? { y: key.y } : {}),
      d: key.d,
      use: 'sig',
    },
    alg === 'EdDSA'
      ? { name: 'Ed25519' } as AlgorithmIdentifier
      : { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
}
