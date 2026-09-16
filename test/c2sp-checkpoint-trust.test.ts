import { describe, expect, it, vi } from 'vitest';

import {
  advanceTrustedC2spCheckpoint,
  InMemoryTrustedC2spCheckpointStore,
  leafHash,
  merkleRootFromEntries,
  parseC2spTlogLr,
  verifyC2spConsistencyProof,
  type TrustedC2spCheckpoint,
  type TrustedC2spCheckpointStore,
} from '@dnsid-ai/log-c2sp-tlog';

const reference = parseC2spTlogLr('c2sp-tlog:testnet:https://log.example/dnsid#agent.example');
const witnessTime = new Date('2026-07-24T12:00:00Z');
const encoder = new TextEncoder();
const firstEntry = encoder.encode('first');
const secondEntry = encoder.encode('second');
const firstRoot = merkleRootFromEntries([firstEntry]);
const secondRoot = merkleRootFromEntries([firstEntry, secondEntry]);
const checkpoint = (treeSize: number, rootHash: Uint8Array) => ({
  origin: reference.origin,
  treeSize,
  rootHash,
  signatures: [],
  signedText: '',
});

describe('trusted C2SP checkpoints', () => {
  it.each(['load', 'proof', 'commit'] as const)('prevents late mutation when canceled during %s', async stage => {
    const backing = new InMemoryTrustedC2spCheckpointStore();
    await advanceTrustedC2spCheckpoint(backing, reference, checkpoint(1, firstRoot), witnessTime);
    let release!: () => void;
    let started!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const ready = new Promise<void>(resolve => { started = resolve; });
    const pause = async (current: typeof stage, signal?: AbortSignal) => {
      expect(signal).toBeInstanceOf(AbortSignal);
      if (current === stage) { started(); await gate; }
    };
    const store: TrustedC2spCheckpointStore = {
      load: async (origin, signal) => { await pause('load', signal); return backing.load(origin, signal); },
      compareAndSwap: vi.fn(async (origin, previous, candidate, signal) => {
        await pause('commit', signal);
        return backing.compareAndSwap(origin, previous, candidate, signal);
      }),
    };
    const controller = new AbortController();
    const pending = advanceTrustedC2spCheckpoint(store, reference, checkpoint(2, secondRoot), witnessTime, {
      signal: controller.signal,
      consistencyProofSource: { fetchConsistencyProof: async (_ref, _from, _to, signal) => {
        await pause('proof', signal);
        return [leafHash(secondEntry)];
      } },
    });
    await ready;
    controller.abort();
    await expect(pending).rejects.toThrow('canceled');
    release();
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(store.compareAndSwap).toHaveBeenCalledTimes(stage === 'commit' ? 1 : 0);
    await expect(backing.load(reference.origin)).resolves.toMatchObject({ treeSize: 1 });
  });

  it('advances from TOFU using a verified complete-scan prefix', async () => {
    const store = new InMemoryTrustedC2spCheckpointStore();
    await advanceTrustedC2spCheckpoint(store, reference, checkpoint(1, firstRoot), witnessTime);
    await advanceTrustedC2spCheckpoint(store, reference, checkpoint(2, secondRoot), witnessTime, {
      completeEntries: [{ index: 0, bytes: firstEntry }, { index: 1, bytes: secondEntry }],
    });
    await expect(store.load(reference.origin)).resolves.toMatchObject({ treeSize: 2 });
  });

  it('rejects rollback, equal-size forks, and a wrong complete prefix', async () => {
    const store = new InMemoryTrustedC2spCheckpointStore();
    await advanceTrustedC2spCheckpoint(store, reference, checkpoint(1, firstRoot), witnessTime);
    await advanceTrustedC2spCheckpoint(store, reference, checkpoint(2, secondRoot), witnessTime, {
      completeEntries: [{ index: 0, bytes: firstEntry }, { index: 1, bytes: secondEntry }],
    });
    await expect(advanceTrustedC2spCheckpoint(store, reference, checkpoint(1, firstRoot), witnessTime))
      .rejects.toThrow('rollback');
    await expect(advanceTrustedC2spCheckpoint(store, reference, checkpoint(2, new Uint8Array(32)), witnessTime))
      .rejects.toThrow('different root');

    const other = new InMemoryTrustedC2spCheckpointStore();
    await advanceTrustedC2spCheckpoint(other, reference, checkpoint(1, firstRoot), witnessTime);
    await expect(advanceTrustedC2spCheckpoint(other, reference, checkpoint(2, secondRoot), witnessTime, {
      completeEntries: [{ index: 0, bytes: encoder.encode('wrong') }, { index: 1, bytes: secondEntry }],
    })).rejects.toThrow('prefix');
  });

  it('verifies RFC 6962 consistency proofs and retries a lost CAS race', async () => {
    expect(verifyC2spConsistencyProof(1, 2, firstRoot, secondRoot, [leafHash(secondEntry)])).toBe(true);
    expect(verifyC2spConsistencyProof(1, 2, firstRoot, secondRoot, [new Uint8Array(32)])).toBe(false);
    expect(verifyC2spConsistencyProof(1, 1, firstRoot, firstRoot, [])).toBe(true);
    expect(verifyC2spConsistencyProof(1, 1, firstRoot, new Uint8Array(32), [])).toBe(false);
    expect(verifyC2spConsistencyProof(1, 1, firstRoot, firstRoot, [new Uint8Array(32)])).toBe(false);

    const backing = new InMemoryTrustedC2spCheckpointStore();
    await advanceTrustedC2spCheckpoint(backing, reference, checkpoint(1, firstRoot), witnessTime);
    let calls = 0;
    const racingStore: TrustedC2spCheckpointStore = {
      load: origin => backing.load(origin),
      compareAndSwap: async (origin, expected, candidate) => {
        calls++;
        if (calls === 1) return false;
        return backing.compareAndSwap(origin, expected, candidate);
      },
    };
    await advanceTrustedC2spCheckpoint(racingStore, reference, checkpoint(2, secondRoot), witnessTime, {
      consistencyProofSource: { fetchConsistencyProof: async () => [leafHash(secondEntry)] },
    });
    expect(calls).toBe(2);
  });

  it('bounds repeated immediately resolved CAS conflicts', async () => {
    vi.useFakeTimers();
    try {
      const store: TrustedC2spCheckpointStore = {
        load: async () => undefined,
        compareAndSwap: vi.fn(async () => false),
      };
      const pending = advanceTrustedC2spCheckpoint(store, reference, checkpoint(1, firstRoot), witnessTime, { timeoutMs: 10 });
      const rejected = expect(pending).rejects.toThrow('deadline');
      await vi.advanceTimersByTimeAsync(10);
      await rejected;
      const attempts = vi.mocked(store.compareAndSwap).mock.calls.length;
      expect(attempts).toBeGreaterThan(1);
      await vi.advanceTimersByTimeAsync(10);
      expect(store.compareAndSwap).toHaveBeenCalledTimes(attempts);
    } finally { vi.useRealTimers(); }
  });

  it('verifies RFC 6962 consistency proofs across uneven tree sizes', () => {
    const leaves = Array.from({ length: 12 }, (_, index) => encoder.encode(`leaf-${index}`));
    for (let toSize = 2; toSize <= leaves.length; toSize++) {
      for (let fromSize = 1; fromSize < toSize; fromSize++) {
        const proof = consistencyProof(leaves.slice(0, toSize), fromSize);
        expect(verifyC2spConsistencyProof(
          fromSize,
          toSize,
          merkleRootFromEntries(leaves.slice(0, fromSize)),
          merkleRootFromEntries(leaves.slice(0, toSize)),
          proof,
        ), `${fromSize}->${toSize}`).toBe(true);
      }
    }
  });

  it('uses atomic origin-scoped compare-and-swap snapshots', async () => {
    const store = new InMemoryTrustedC2spCheckpointStore();
    const initial: TrustedC2spCheckpoint = { origin: reference.origin, treeSize: 1, rootHash: firstRoot, witnessTime };
    await expect(store.compareAndSwap(reference.origin, undefined, initial)).resolves.toBe(true);
    const stale = { ...initial, rootHash: new Uint8Array(32) };
    await expect(store.compareAndSwap(reference.origin, stale, { ...initial, treeSize: 2, rootHash: secondRoot })).resolves.toBe(false);
  });
});

function consistencyProof(leaves: Uint8Array[], fromSize: number): Uint8Array[] {
  return subproof(leaves, fromSize, true);
}

function subproof(leaves: Uint8Array[], fromSize: number, complete: boolean): Uint8Array[] {
  if (fromSize === leaves.length) return complete ? [] : [merkleRootFromEntries(leaves)];
  let split = 1;
  while (split * 2 < leaves.length) split *= 2;
  if (fromSize <= split) {
    return [...subproof(leaves.slice(0, split), fromSize, complete), merkleRootFromEntries(leaves.slice(split))];
  }
  return [...subproof(leaves.slice(split), fromSize - split, false), merkleRootFromEntries(leaves.slice(0, split))];
}
