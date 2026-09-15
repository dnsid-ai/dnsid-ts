import { withVerificationBudget, waitForVerification, type VerificationOptions } from '@identity-digital/dnsid-protocol';
import type { Checkpoint } from './checkpoint.ts';
import { C2spTlogVerificationError } from './errors.ts';
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

/** Persistence for per-origin trusted checkpoints, updated with optimistic compare-and-swap semantics. */
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

/** Non-persistent, per-process trusted checkpoint store. */
export class InMemoryTrustedC2spCheckpointStore implements TrustedC2spCheckpointStore {
  private readonly checkpoints = new Map<string, TrustedC2spCheckpoint>();

  async load(origin: string, signal?: AbortSignal): Promise<TrustedC2spCheckpoint | undefined> {
    signal?.throwIfAborted();
    return cloneCheckpoint(this.checkpoints.get(origin));
  }

  async compareAndSwap(origin: string, expected: TrustedC2spCheckpoint | undefined, candidate: TrustedC2spCheckpoint, signal?: AbortSignal): Promise<boolean> {
    signal?.throwIfAborted();
    const current = this.checkpoints.get(origin);
    if (!sameCheckpoint(current, expected)) return false;
    if (candidate.origin !== origin) throw new C2spTlogVerificationError('trusted checkpoint origin mismatch');
    this.checkpoints.set(origin, cloneCheckpoint(candidate)!);
    return true;
  }
}

/**
 * Advances the stored trusted checkpoint for a log origin to `checkpoint`,
 * guarding against split-view and rollback attacks: a same-size checkpoint
 * must have the same root, and a larger one must be proven consistent by a
 * consistency proof or a complete scan matching both checkpoint prefixes.
 *
 * @returns A defensive copy of the newly trusted checkpoint.
 * @throws C2spTlogVerificationError on origin mismatch, rollback, root
 *   divergence, or missing/invalid consistency evidence.
 */
export async function advanceTrustedC2spCheckpoint(
  store: TrustedC2spCheckpointStore,
  reference: ParsedC2spTlogLr,
  checkpoint: Checkpoint,
  witnessTime: Date,
  options: VerificationOptions & { consistencyProofSource?: C2spConsistencyProofSource; completeEntries?: IndexedEntry[] } = {},
): Promise<TrustedC2spCheckpoint> {
  const candidate: TrustedC2spCheckpoint = {
    origin: checkpoint.origin,
    treeSize: checkpoint.treeSize,
    rootHash: checkpoint.rootHash.slice(),
    witnessTime: new Date(witnessTime),
  };
  if (candidate.origin !== reference.origin) throw new C2spTlogVerificationError('trusted checkpoint origin mismatch');
  return withVerificationBudget(async signal => {
    for (;;) {
      const previous = await waitForVerification(() => store.load(reference.origin, signal), signal);
      await waitForVerification(() => verifyCheckpointAdvance(previous, candidate, reference, { ...options, signal }), signal);
      if (await waitForVerification(() => store.compareAndSwap(reference.origin, previous, candidate, signal), signal)) return cloneCheckpoint(candidate)!;
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
  if (!Number.isSafeInteger(fromSize) || !Number.isSafeInteger(toSize) || fromSize <= 0 || toSize <= 0) return false;
  if (fromRoot.length !== 32 || toRoot.length !== 32 || proof.some(node => node.length !== 32)) return false;
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
): Promise<void> {
  const completeEntries = options.completeEntries?.slice().sort((a, b) => a.index - b.index);
  if (completeEntries) verifyCompleteEntriesPrefix(completeEntries, candidate, 'candidate');
  if (!previous) return;
  if (previous.origin !== candidate.origin) throw new C2spTlogVerificationError('trusted checkpoint origin mismatch');
  if (candidate.treeSize < previous.treeSize) throw new C2spTlogVerificationError('C2SP checkpoint rollback detected');
  if (candidate.treeSize === previous.treeSize) {
    if (!equalBytes(candidate.rootHash, previous.rootHash)) throw new C2spTlogVerificationError('equal-size C2SP checkpoint has a different root');
    return;
  }
  if (options.consistencyProofSource) {
    const proof = await options.consistencyProofSource.fetchConsistencyProof(reference, previous.treeSize, candidate.treeSize, options.signal);
    if (!verifyC2spConsistencyProof(previous.treeSize, candidate.treeSize, previous.rootHash, candidate.rootHash, proof)) {
      throw new C2spTlogVerificationError('invalid C2SP checkpoint consistency proof');
    }
    return;
  }
  if (completeEntries) {
    verifyCompleteEntriesPrefix(completeEntries, previous, 'previously trusted');
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
  return value && { ...value, rootHash: value.rootHash.slice(), witnessTime: new Date(value.witnessTime) };
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return Buffer.from(left).equals(Buffer.from(right));
}
