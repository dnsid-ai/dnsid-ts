import * as fs from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { JWKS, normalizeFQDN, type DnsIdJWK } from '@dnsid-ai/sdk';
import { canonicalBytes, canonicalJson, parseJsonNoDuplicateMembers } from '@dnsid-ai/log-c2sp-tlog';
import { Deadline, FoundryError } from './errors.ts';

export type FoundryPhase = 'creation-pending' | 'identity-known' | 'proof-pending' | 'issuance-accepted' | 'complete';
export interface FoundryOperationKey {
  registryUrl: string;
  organizationId: string;
  name: string;
}

/** Version 1 recovery document. Unknown members survive import, update, and export. */
export interface FoundryOperation extends FoundryOperationKey {
  [member: string]: unknown;
  schemaVersion: 1;
  phase: FoundryPhase;
  governanceId: string;
  keySource: Record<string, unknown>;
  currentKeySource?: Record<string, unknown>;
  initialPublicKey: DnsIdJWK;
  currentPublicKey?: DnsIdJWK;
  creationInput: {
    [member: string]: unknown;
    name: string;
    tier: 'live';
    managed: true;
    public_key: DnsIdJWK;
    environment?: 'production';
  };
  identityId?: string;
  domain?: string;
  requestId?: string;
  registryStatus?: string;
  signingPaused?: boolean;
  proof?: Record<string, unknown>;
  publicationConfig?: Record<string, unknown>;
  entityPublicKey?: DnsIdJWK;
  issuance?: Record<string, unknown>;
}

export interface FoundryTransaction {
  load(): Promise<FoundryOperation | undefined>;
  save(operation: FoundryOperation): Promise<void>;
}

/** The transaction holds an exclusive lock until the callback and all its writes finish. */
export interface FoundryStore {
  withLock<T>(key: FoundryOperationKey, deadline: Deadline, work: (transaction: FoundryTransaction) => Promise<T>): Promise<T>;
  export(key: FoundryOperationKey, deadline?: Deadline): Promise<Uint8Array>;
  import(document: Uint8Array, deadline?: Deadline): Promise<void>;
  loadById(identityId: string, scope: Pick<FoundryOperationKey, 'registryUrl' | 'organizationId'>): Promise<FoundryOperation | undefined>;
}

export function validateName(name: string): string {
  if (typeof name !== 'string' || !name || [...name].length > 255) throw new TypeError('invalid registration name');
  // JCS rejects unpaired UTF-16 surrogates without changing valid Unicode spellings.
  canonicalJson(name);
  return name;
}

export function deriveRegistrationKey(organizationId: string, name: string, initialKeyId: string): string {
  validateName(name);
  return digest(['dnsid-managed-registration-v1', organizationId, name, initialKeyId]);
}

export function deriveIssuanceKey(registrationKey: string): string {
  return digest(['dnsid-managed-issuance-v1', registrationKey]);
}

function digest(value: unknown): string {
  return createHash('sha256').update(canonicalBytes(value)).digest('base64url');
}

export function publicKey(value: unknown): DnsIdJWK {
  const key = object(value, 'public key');
  rejectPrivateMaterial(key);
  if ('keys' in key) throw new TypeError('public key must be a single JWK');
  new JWKS([key as unknown as DnsIdJWK]).validateOperational();
  return key as unknown as DnsIdJWK;
}

function rejectPrivateMaterial(value: unknown): void {
  if (!value || typeof value !== 'object') return;
  for (const [name, child] of Object.entries(value)) {
    if (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'privateKey', 'apiKey', 'token', 'credentials'].includes(name)) {
      throw new TypeError('recovery documents must not contain private keys or credentials');
    }
    rejectPrivateMaterial(child);
  }
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  return value as Record<string, unknown>;
}

/** Validates the portable trust boundary, before any provider or registry mutation. */
export function parseFoundryOperation(bytes: Uint8Array): FoundryOperation {
  const raw = object(parseJsonNoDuplicateMembers(bytes), 'Foundry recovery document');
  canonicalBytes(raw); // Includes Unicode validation for unknown members.
  if (raw.schemaVersion !== 1) throw new TypeError('unsupported Foundry recovery schemaVersion');
  if (!['creation-pending', 'identity-known', 'proof-pending', 'issuance-accepted', 'complete'].includes(String(raw.phase))) {
    throw new TypeError('unsupported Foundry recovery phase');
  }
  for (const member of ['registryUrl', 'organizationId', 'governanceId']) {
    if (typeof raw[member] !== 'string' || !raw[member]) throw new TypeError(`recovery document requires ${member}`);
  }
  validateName(raw.name as string);
  const url = new URL(raw.registryUrl as string);
  if (url.username || url.password || url.search || url.hash) throw new TypeError('invalid recovery registryUrl');
  normalizeFQDN(raw.governanceId as string, true);
  object(raw.keySource, 'keySource');
  rejectPrivateMaterial(raw.keySource);
  if (raw.currentKeySource !== undefined) rejectPrivateMaterial(object(raw.currentKeySource, 'currentKeySource'));
  const initial = publicKey(raw.initialPublicKey);
  if (initial.kty !== 'OKP' || initial.crv !== 'Ed25519' || initial.alg !== 'EdDSA') throw new TypeError('Live creation requires Ed25519');
  if (raw.currentPublicKey !== undefined) publicKey(raw.currentPublicKey);
  if (raw.entityPublicKey !== undefined) publicKey(raw.entityPublicKey);
  if (raw.signingPaused !== undefined && typeof raw.signingPaused !== 'boolean') throw new TypeError('invalid recovery signingPaused');
  const input = object(raw.creationInput, 'creationInput');
  const creationKey = publicKey(input.public_key);
  if (creationKey.kty !== 'OKP' || creationKey.crv !== 'Ed25519' || creationKey.alg !== 'EdDSA') throw new TypeError('Live creation requires Ed25519');
  if (input.name !== raw.name || input.tier !== 'live' || input.managed !== true
    || input.environment !== undefined && input.environment !== 'production'
    || ['domain', 'zone_id', 'governance_domain', 'root_domain'].some(field => field in input)) throw new TypeError('conflicting frozen creationInput');
  for (const member of ['identityId', 'domain', 'requestId', 'registryStatus', 'oidcIssuerUrl']) {
    if (raw[member] !== undefined && (typeof raw[member] !== 'string' || !raw[member])) throw new TypeError(`invalid recovery ${member}`);
  }
  if (raw.domain !== undefined) normalizeFQDN(raw.domain as string, true);
  if (raw.phase !== 'creation-pending' && (!raw.identityId || !raw.domain || !raw.requestId)) throw new TypeError('known identity requires ID, domain, and requestId');
  if (raw.phase === 'proof-pending' && !raw.proof) throw new TypeError('proof-pending requires proof');
  if (raw.proof !== undefined) {
    const proof = object(raw.proof, 'proof');
    if (typeof proof.challenge !== 'string' || !proof.challenge || typeof proof.challengeMessage !== 'string'
      || typeof proof.expiresAt !== 'string' || !Number.isFinite(Date.parse(proof.expiresAt))) throw new TypeError('invalid saved proof');
    decodeBytes(proof.challengeMessage);
    if (proof.submissionState !== undefined && !['prepared', 'submitting'].includes(String(proof.submissionState))) throw new TypeError('unknown proof submission state');
    if (proof.request !== undefined) {
      const request = object(proof.request, 'proof.request');
      if (request.requestId !== raw.requestId || request.challenge !== proof.challenge
        || canonicalJson(publicKey(request.publicKeyJwk)) !== canonicalJson(creationKey)) throw new TypeError('conflicting proof signature request');
      if (decodeBytes(request.signature).length !== 64) throw new TypeError('invalid proof signature');
    }
  }
  if (raw.publicationConfig !== undefined) {
    const publication = object(raw.publicationConfig, 'publicationConfig');
    for (const member of ['publishProfile', 'governanceId', 'kuUrl', 'ekUrl', 'logRef', 'statusUrl']) {
      if (typeof publication[member] !== 'string' || !publication[member]) throw new TypeError(`publicationConfig requires ${member}`);
    }
  }
  if (raw.issuance !== undefined) {
    const issuance = object(raw.issuance, 'issuance');
    for (const member of ['preparedEntryBytes', 'entryBytes']) {
      if (issuance[member] !== undefined) decodeBytes(issuance[member]);
    }
    if (issuance.entryBytes !== undefined && issuance.entryHash !== createHash('sha256').update(decodeBytes(issuance.entryBytes)).digest('hex')) {
      throw new TypeError('issuance entryHash does not match completed bytes');
    }
  }
  if (raw.phase === 'complete' || raw.phase === 'issuance-accepted') {
    if (!raw.publicationConfig || !raw.entityPublicKey || !raw.issuance) throw new TypeError('accepted issuance requires publication, entity key, and acceptance facts');
    const issuance = raw.issuance as Record<string, unknown>;
    const submission = issuance.submission as Record<string, unknown> | undefined;
    if (submission?.state !== 'accepted' && !issuance.acceptance) throw new TypeError('missing issuance acceptance');
  }
  return raw as unknown as FoundryOperation;
}

export function decodeBytes(value: unknown): Uint8Array {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) throw new TypeError('invalid unpadded base64url');
  const result = Buffer.from(value, 'base64url');
  if (result.toString('base64url') !== value) throw new TypeError('non-canonical base64url');
  return new Uint8Array(result);
}

function sameKey(a: FoundryOperationKey, b: FoundryOperationKey): boolean {
  return a.registryUrl === b.registryUrl && a.organizationId === b.organizationId && a.name === b.name;
}

/**
 * Owner-only, atomic, fsync-backed storage on a local filesystem. Locks do not expire while
 * their process lives. Dead processes are reclaimed by their unique marker, not by a lease.
 */
export class FileFoundryStore implements FoundryStore {
  readonly directory: string;
  constructor(directory = join(homedir(), '.dnsid', 'foundry')) { this.directory = resolve(directory); }

  private path(key: FoundryOperationKey): string {
    return join(this.directory, digest([key.registryUrl, key.organizationId, validateName(key.name)]));
  }

  async withLock<T>(key: FoundryOperationKey, deadline: Deadline, work: (transaction: FoundryTransaction) => Promise<T>): Promise<T> {
    deadline.check();
    const created = await fs.mkdir(this.directory, { recursive: true, mode: 0o700 });
    if (created) {
      const parent = resolve(created, '..');
      for (let directory = this.directory; ; directory = resolve(directory, '..')) {
        const handle = await fs.open(directory, 'r');
        try { await handle.sync(); } finally { await handle.close(); }
        if (directory === parent) break;
      }
    }
    await fs.chmod(this.directory, 0o700);
    const location = this.path(key);
    const lock = `${location}.lock`;
    const marker = `${process.pid}-${randomUUID()}`;
    const candidate = `${location}.${marker}.lock`;
    await fs.mkdir(candidate, { mode: 0o700 });
    await fs.writeFile(join(candidate, marker), '', { flag: 'wx', mode: 0o600 });
    let acquired = false;
    let active = true;
    const writes = new Set<Promise<void>>();
    try {
      for (;;) {
        try {
          // Pre-populating the directory makes rename an atomic exclusive claim: an
          // existing live lock is never empty and cannot be replaced by rename.
          await fs.rename(candidate, lock);
          acquired = true;
          break;
        } catch (cause) {
          if (!['EEXIST', 'ENOTEMPTY', 'EACCES'].includes((cause as NodeJS.ErrnoException).code!)) throw cause;
          await reclaimDeadLock(lock);
          try { await deadline.wait(25); }
          catch (cause) {
            if (cause instanceof FoundryError && cause.category === 'cancelled') throw cause;
            throw new FoundryError('busy', 'named operation is busy; retry after the other caller releases its lock', { resumable: true, cause });
          }
        }
      }
      deadline.check();
      return await work({
        load: async () => {
          if (!active) throw new Error('Foundry transaction is closed');
          try {
            const operation = parseFoundryOperation(await fs.readFile(`${location}.json`));
            if (!sameKey(key, operation)) throw new TypeError('recovery operation key mismatch');
            return operation;
          } catch (cause) {
            if ((cause as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
            throw new FoundryError('storage', 'invalid Foundry recovery state', { resumable: false, cause });
          }
        },
        save: operation => {
          const write = (async () => {
            if (!active) throw new Error('Foundry transaction is closed');
            deadline.check();
            if (!sameKey(key, operation)) throw new TypeError('recovery operation key mismatch');
            const bytes = canonicalBytes(operation);
            parseFoundryOperation(bytes);
            await atomicWrite(`${location}.json`, bytes, deadline);
            // Retain each identity's latest snapshot even when its name is later reused.
            if (operation.identityId) await atomicWrite(this.identityPath(operation.identityId, operation), bytes, deadline);
          })();
          writes.add(write);
          void write.finally(() => writes.delete(write)).catch(() => {});
          return write;
        },
      });
    } finally {
      active = false;
      await Promise.allSettled(writes);
      if (acquired) await releaseLock(lock, marker);
      else await fs.rm(candidate, { recursive: true, force: true });
    }
  }

  async export(key: FoundryOperationKey, deadline = new Deadline()): Promise<Uint8Array> {
    return this.withLock(key, deadline, async transaction => {
      const operation = await transaction.load();
      if (!operation) throw new FoundryError('storage', 'no named operation exists', { resumable: false });
      return canonicalBytes(operation);
    });
  }

  async import(document: Uint8Array, deadline = new Deadline()): Promise<void> {
    const operation = parseFoundryOperation(document);
    await this.withLock(operation, deadline, async transaction => {
      const existing = await transaction.load();
      if (existing && canonicalJson(existing) !== canonicalJson(operation)) throw new FoundryError('storage', 'import conflicts with existing named state', { resumable: false });
      await transaction.save(operation);
    });
  }

  private identityPath(identityId: string, scope: Pick<FoundryOperationKey, 'registryUrl' | 'organizationId'>): string {
    return join(this.directory, `id-${digest([scope.registryUrl, scope.organizationId, identityId])}.json`);
  }

  async loadById(identityId: string, scope: Pick<FoundryOperationKey, 'registryUrl' | 'organizationId'>): Promise<FoundryOperation | undefined> {
    const location = this.identityPath(identityId, scope);
    let operation: FoundryOperation;
    try { operation = parseFoundryOperation(await fs.readFile(location)); }
    catch (cause) { if ((cause as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw cause; }
    return this.withLock(operation, new Deadline(), async () => {
      const saved = parseFoundryOperation(await fs.readFile(location));
      if (saved.identityId !== identityId || saved.registryUrl !== scope.registryUrl || saved.organizationId !== scope.organizationId) throw new TypeError('historical identity binding mismatch');
      return saved;
    });
  }
}

async function releaseLock(lock: string, marker: string): Promise<void> {
  try { await fs.unlink(join(lock, marker)); }
  catch (cause) { if ((cause as NodeJS.ErrnoException).code === 'ENOENT') return; throw cause; }
  try { await fs.rmdir(lock); }
  catch (cause) { if (!['ENOENT', 'ENOTEMPTY', 'EEXIST'].includes((cause as NodeJS.ErrnoException).code!)) throw cause; }
}

async function reclaimDeadLock(lock: string): Promise<void> {
  let markers: string[];
  try { markers = await fs.readdir(lock); }
  catch (cause) { if ((cause as NodeJS.ErrnoException).code === 'ENOENT') return; throw cause; }
  if (markers.length !== 1 || !/^\d+-[0-9a-f-]+$/.test(markers[0]!)) return;
  const marker = markers[0]!;
  // shortcut: PID liveness is local to one host/PID namespace; inject a store for shared storage.
  try { process.kill(Number(marker.split('-')[0]), 0); }
  catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === 'ESRCH') await releaseLock(lock, marker);
  }
}

async function atomicWrite(file: string, bytes: Uint8Array, deadline: Deadline): Promise<void> {
  const temporary = `${file}.${randomUUID()}.tmp`;
  const handle = await fs.open(temporary, 'wx', 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
    deadline.check();
    await fs.rename(temporary, file);
    const directory = await fs.open(resolve(file, '..'), 'r');
    try { await directory.sync(); } finally { await directory.close(); }
  } finally {
    await handle.close();
    await fs.rm(temporary, { force: true });
  }
}
