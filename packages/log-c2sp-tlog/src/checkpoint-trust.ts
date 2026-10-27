import { ArgumentError, withVerificationBudget, waitForVerification, type VerificationOptions } from '@dnsid-ai/protocol';
import type { Checkpoint } from './checkpoint.ts';
import { C2spTlogVerificationError, c2spLogError } from './errors.ts';
import type { ParsedC2spTlogLr } from './lr.ts';
import { merkleRootFromEntries, nodeHash } from './merkle.ts';
import type { IndexedEntry } from './stream-source.ts';

/** Latest policy-accepted checkpoint remembered for a log origin, with its witnessed time. */
export interface TrustedC2spCheckpoint {
  origin: string;
  treeSize: number;
  rootHash: Uint8Array;
  witnessTime: Date;
}

/**
 * Persistence for per-origin trusted checkpoints. Compare all four fields, including
 * witnessed time. Validate inputs, return independent snapshots, and fail closed on
 * lost/corrupt storage; undefined means a genuinely unseen origin, not storage loss.
 * Durable adapters must explicitly initialize namespaces and acknowledge durable
 * commits. An error after publication requires read-back reconciliation, not retry
 * on the assumption that the old state remains. See the package storage contract.
 */
export interface TrustedC2spCheckpointStore {
  /** Returns the currently trusted checkpoint for `origin`, if any. */
  load(origin: string, signal?: AbortSignal): Promise<TrustedC2spCheckpoint | undefined>;
  /**
   * Atomically replaces `expected` with `candidate`; returns false on a lost race.
   * Implementations must honor cancellation at the commit boundary: an aborted
   * signal must prevent a pending write, not merely reject its returned promise.
   */
  compareAndSwap(
    origin: string,
    expected: TrustedC2spCheckpoint | undefined,
    candidate: TrustedC2spCheckpoint,
    signal?: AbortSignal,
  ): Promise<boolean>;
}

/** Fetches RFC 6962 consistency proofs between two tree sizes of a log. */
export interface C2spConsistencyProofSource {
  fetchConsistencyProof(reference: ParsedC2spTlogLr, fromSize: number, toSize: number, signal?: AbortSignal): Promise<Uint8Array[]>;
}

/** Signals that a valid newer checkpoint needs independent consistency evidence. */
export class MissingC2spConsistencyEvidenceError extends C2spTlogVerificationError {}

/** An authenticated checkpoint contradicts remembered log history; never authorizes a reset. */
export class C2spCheckpointConsistencyError extends C2spTlogVerificationError {
  readonly origin: string;
  readonly trustedTreeSize: number;
  readonly observedTreeSize: number;
  readonly trustedRootHash: Uint8Array;
  readonly observedRootHash: Uint8Array;

  constructor(message: string, category: 'LOG_ROLLBACK' | 'LOG_FORK' | 'LOG_INCONSISTENT', trusted: TrustedC2spCheckpoint, observed: TrustedC2spCheckpoint, cause?: unknown) {
    super(message, category, cause);
    this.name = 'C2spCheckpointConsistencyError';
    this.origin = observed.origin;
    this.trustedTreeSize = trusted.treeSize;
    this.observedTreeSize = observed.treeSize;
    this.trustedRootHash = new Uint8Array(trusted.rootHash);
    this.observedRootHash = new Uint8Array(observed.rootHash);
  }
}

/** Storage failed. A failed CAS may already have published; reconcile before recovery. */
export class C2spCheckpointStoreError extends C2spTlogVerificationError {
  constructor(message: string, cause?: unknown) {
    super(message, 'CHECKPOINT_STORE_ERROR', cause);
    this.name = 'C2spCheckpointStoreError';
  }
}

/** Non-persistent, per-process trusted checkpoint store. */
export class InMemoryTrustedC2spCheckpointStore implements TrustedC2spCheckpointStore {
  private readonly checkpoints = new Map<string, TrustedC2spCheckpoint>();

  async load(origin: string, signal?: AbortSignal): Promise<TrustedC2spCheckpoint | undefined> {
    signal?.throwIfAborted();
    validateOrigin(origin);
    return cloneCheckpoint(this.checkpoints.get(origin));
  }

  async compareAndSwap(origin: string, expected: TrustedC2spCheckpoint | undefined, candidate: TrustedC2spCheckpoint, signal?: AbortSignal): Promise<boolean> {
    signal?.throwIfAborted();
    validateOrigin(origin);
    if (expected !== undefined) validateCheckpoint(expected, origin);
    validateCheckpoint(candidate, origin);
    const current = this.checkpoints.get(origin);
    if (!sameCheckpoint(current, expected)) return false;
    const replacement = cloneCheckpoint(candidate)!;
    signal?.throwIfAborted();
    this.checkpoints.set(origin, replacement);
    return true;
  }
}

type AdvanceOptions = VerificationOptions & { consistencyProofSource?: C2spConsistencyProofSource; completeEntries?: IndexedEntry[] };
type TilePrefixRoot = (candidate: TrustedC2spCheckpoint, trustedSize: number, signal: AbortSignal) => Promise<Uint8Array>;

/**
 * Advances the stored trusted checkpoint for a log origin to `checkpoint`,
 * guarding against split-view and rollback attacks: a same-size checkpoint
 * must have the same root, and a larger one must be proven consistent by a
 * consistency proof or a complete scan matching both checkpoint prefixes.
 *
 * @returns A defensive copy of the newly trusted checkpoint.
 * @throws ArgumentError for invalid checkpoint fields or origin mismatch.
 * @throws C2spCheckpointConsistencyError for rollback, forks, or inconsistent growth.
 * @throws C2spCheckpointStoreError for storage failure or malformed stored state.
 * @throws C2spTlogVerificationError for missing/invalid candidate evidence.
 */
export async function advanceTrustedC2spCheckpoint(
  store: TrustedC2spCheckpointStore,
  reference: ParsedC2spTlogLr,
  checkpoint: Checkpoint,
  witnessTime: Date,
  options: VerificationOptions & { consistencyProofSource?: C2spConsistencyProofSource; completeEntries?: IndexedEntry[] } = {},
): Promise<TrustedC2spCheckpoint> {
  return advanceC2spCheckpoint(store, reference, checkpoint, witnessTime, options);
}

/** @internal Network readers supply tile capability without adding public options. */
export async function advanceC2spCheckpoint(
  store: TrustedC2spCheckpointStore,
  reference: ParsedC2spTlogLr,
  checkpoint: Checkpoint,
  witnessTime: Date,
  options: AdvanceOptions = {},
  tilePrefixRoot?: TilePrefixRoot,
): Promise<TrustedC2spCheckpoint> {
  if (checkpoint.treeSize === 0 && !equalBytes(checkpoint.rootHash, merkleRootFromEntries([]))) {
    throw new C2spTlogVerificationError('empty C2SP checkpoint must have the empty-tree root');
  }
  const input = { origin: checkpoint.origin, treeSize: checkpoint.treeSize, rootHash: checkpoint.rootHash, witnessTime };
  validateCheckpoint(input, reference.origin);
  const candidate = cloneCheckpoint(input)!;
  const completeEntries = options.completeEntries?.map(entry => ({ ...entry, bytes: new Uint8Array(entry.bytes) }));
  return withVerificationBudget(async signal => {
    for (;;) {
      const previous = await storeOperation(async () => {
        const loaded = await store.load(reference.origin, signal);
        if (loaded !== undefined) validateCheckpoint(loaded, reference.origin);
        return cloneCheckpoint(loaded);
      }, signal);
      await waitForVerification(() => verifyCheckpointAdvance(previous, candidate, reference, { ...options, completeEntries, signal }, tilePrefixRoot), signal);
      const swapped = await storeOperation(() => store.compareAndSwap(reference.origin, cloneCheckpoint(previous), cloneCheckpoint(candidate)!, signal), signal);
      if (typeof swapped !== 'boolean') throw new C2spCheckpointStoreError('checkpoint store returned an invalid CAS result');
      if (swapped) return cloneCheckpoint(candidate)!;
      // Immediately resolved CAS conflicts must not starve the deadline timer.
      await waitForVerification(() => new Promise<void>(resolve => setTimeout(resolve, 0)), signal);
    }
  }, options);
}

/**
 * Verifies an RFC 6962 consistency proof that the tree of size `fromSize` with
 * root `fromRoot` is a prefix of the tree of size `toSize` with root `toRoot`.
 * Returns false rather than throwing on invalid input.
 */
export function verifyC2spConsistencyProof(
  fromSize: number,
  toSize: number,
  fromRoot: Uint8Array,
  toRoot: Uint8Array,
  proof: Uint8Array[],
): boolean {
  if (!Number.isSafeInteger(fromSize) || !Number.isSafeInteger(toSize) || fromSize < 0 || toSize < 0) return false;
  if (fromRoot.length !== 32 || toRoot.length !== 32 || !Array.isArray(proof)
    || proof.some(node => !(node instanceof Uint8Array) || node.length !== 32)) return false;
  if (fromSize === 0) return proof.length === 0 && equalBytes(fromRoot, merkleRootFromEntries([]))
    && (toSize !== 0 || equalBytes(fromRoot, toRoot));
  if (fromSize === toSize) return proof.length === 0 && equalBytes(fromRoot, toRoot);
  if (toSize < fromSize) return false;
  let oldIndex = fromSize - 1;
  let newIndex = toSize - 1;
  while ((oldIndex & 1) === 1) {
    oldIndex = Math.floor(oldIndex / 2);
    newIndex = Math.floor(newIndex / 2);
  }
  let cursor = 0;
  let oldHash: Uint8Array;
  let newHash: Uint8Array;
  if (oldIndex === 0) {
    oldHash = fromRoot;
    newHash = fromRoot;
  } else {
    if (proof.length === 0) return false;
    oldHash = proof[cursor]!;
    newHash = proof[cursor++]!;
  }
  while (cursor < proof.length) {
    if (newIndex === 0) return false;
    const node = proof[cursor++]!;
    if ((oldIndex & 1) === 1 || oldIndex === newIndex) {
      oldHash = nodeHash(node, oldHash);
      newHash = nodeHash(node, newHash);
      while (oldIndex !== 0 && (oldIndex & 1) === 0) {
        oldIndex = Math.floor(oldIndex / 2);
        newIndex = Math.floor(newIndex / 2);
      }
    } else {
      newHash = nodeHash(newHash, node);
    }
    oldIndex = Math.floor(oldIndex / 2);
    newIndex = Math.floor(newIndex / 2);
  }
  return newIndex === 0 && equalBytes(oldHash, fromRoot) && equalBytes(newHash, toRoot);
}

/** Asserts that `candidate` is a safe successor of the previously trusted checkpoint. */
async function verifyCheckpointAdvance(
  previous: TrustedC2spCheckpoint | undefined,
  candidate: TrustedC2spCheckpoint,
  reference: ParsedC2spTlogLr,
  options: { consistencyProofSource?: C2spConsistencyProofSource; completeEntries?: IndexedEntry[]; signal: AbortSignal },
  tilePrefixRoot?: TilePrefixRoot,
): Promise<void> {
  const completeEntries = options.completeEntries?.slice().sort((a, b) => a.index - b.index);
  if (completeEntries) verifyCompleteEntriesPrefix(completeEntries, candidate, 'candidate');
  if (!previous) return;
  if (candidate.treeSize < previous.treeSize) throw new C2spCheckpointConsistencyError('C2SP checkpoint rollback detected', 'LOG_ROLLBACK', previous, candidate);
  if (candidate.treeSize === previous.treeSize) {
    if (!equalBytes(candidate.rootHash, previous.rootHash)) throw new C2spCheckpointConsistencyError('equal-size C2SP checkpoint has a different root', 'LOG_FORK', previous, candidate);
    return;
  }
  if (previous.treeSize === 0) return;
  if (completeEntries) {
    try {
      verifyCompleteEntriesPrefix(completeEntries, previous, 'previously trusted');
    } catch (cause) {
      throw new C2spCheckpointConsistencyError('complete scan contradicts the previously trusted checkpoint', 'LOG_INCONSISTENT', previous, candidate, cause);
    }
    return;
  }
  if (options.consistencyProofSource) {
    let proof: Uint8Array[];
    try {
      proof = await options.consistencyProofSource.fetchConsistencyProof(reference, previous.treeSize, candidate.treeSize, options.signal);
    } catch (cause) {
      throw c2spLogError('C2SP consistency proof is unavailable', cause, true);
    }
    if (!verifyC2spConsistencyProof(previous.treeSize, candidate.treeSize, previous.rootHash, candidate.rootHash, proof)) {
      throw new C2spCheckpointConsistencyError('invalid C2SP checkpoint consistency proof', 'LOG_INCONSISTENT', previous, candidate);
    }
    return;
  }
  if (tilePrefixRoot) {
    const root = await tilePrefixRoot(candidate, previous.treeSize, options.signal);
    if (!equalBytes(root, previous.rootHash)) {
      throw new C2spCheckpointConsistencyError('candidate-authenticated hash tiles contradict the previously trusted checkpoint', 'LOG_INCONSISTENT', previous, candidate);
    }
    return;
  }
  throw new MissingC2spConsistencyEvidenceError('newer C2SP checkpoint requires consistency proof or verified complete-scan prefix');
}

function verifyCompleteEntriesPrefix(entries: IndexedEntry[], checkpoint: TrustedC2spCheckpoint, name: string): void {
  const prefix = entries.slice(0, checkpoint.treeSize);
  if (prefix.length !== checkpoint.treeSize || prefix.some((entry, index) => entry.index !== index)) {
    throw new C2spTlogVerificationError(`complete scan does not contain the ${name} checkpoint prefix`);
  }
  if (!equalBytes(merkleRootFromEntries(prefix.map(entry => entry.bytes)), checkpoint.rootHash)) {
    throw new C2spTlogVerificationError(`complete scan prefix does not match the ${name} checkpoint`);
  }
}

function sameCheckpoint(left: TrustedC2spCheckpoint | undefined, right: TrustedC2spCheckpoint | undefined): boolean {
  if (!left || !right) return left === right;
  return left.origin === right.origin
    && left.treeSize === right.treeSize
    && left.witnessTime.getTime() === right.witnessTime.getTime()
    && equalBytes(left.rootHash, right.rootHash);
}

function cloneCheckpoint(value: TrustedC2spCheckpoint | undefined): TrustedC2spCheckpoint | undefined {
  return value && { ...value, rootHash: new Uint8Array(value.rootHash), witnessTime: new Date(value.witnessTime) };
}

function validateOrigin(origin: string): void {
  if (typeof origin !== 'string' || !origin.trim()) throw new ArgumentError('trusted checkpoint origin must be nonempty');
}

function validateCheckpoint(value: TrustedC2spCheckpoint, origin: string): void {
  validateOrigin(origin);
  if (!value || value.origin !== origin) throw new ArgumentError('trusted checkpoint origin mismatch');
  if (!Number.isSafeInteger(value.treeSize) || value.treeSize < 0) throw new ArgumentError('trusted checkpoint tree size must be a non-negative safe integer');
  if (!(value.rootHash instanceof Uint8Array) || value.rootHash.length !== 32) throw new ArgumentError('trusted checkpoint root must be 32 bytes');
  if (value.treeSize === 0 && !equalBytes(value.rootHash, merkleRootFromEntries([]))) throw new ArgumentError('empty trusted checkpoint must have the empty-tree root');
  if (!(value.witnessTime instanceof Date) || !Number.isSafeInteger(value.witnessTime.getTime())) throw new ArgumentError('trusted checkpoint witnessed time must be a valid Date');
}

async function storeOperation<T>(operation: () => Promise<T>, signal: AbortSignal): Promise<T> {
  return waitForVerification(async () => {
    try {
      return await operation();
    } catch (cause) {
      if (signal.aborted && cause === signal.reason) throw c2spLogError('checkpoint operation canceled', cause, true);
      throw cause instanceof C2spCheckpointStoreError ? cause : new C2spCheckpointStoreError('trusted checkpoint storage failed', cause);
    }
  }, signal);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return Buffer.from(left).equals(Buffer.from(right));
}
