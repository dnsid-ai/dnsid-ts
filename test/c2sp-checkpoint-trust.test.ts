import { describe, expect, it, vi } from 'vitest';
import { ArgumentError } from '@dnsid-ai/protocol';

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
    let finished!: () => void;
    const done = new Promise<void>(resolve => { finished = resolve; });
    const pause = async (current: typeof stage, signal?: AbortSignal) => {
      expect(signal).toBeInstanceOf(AbortSignal);
      if (current === stage) { started(); await gate; }
    };
    const store: TrustedC2spCheckpointStore = {
      load: async (origin, signal) => {
        try { await pause('load', signal); return await backing.load(origin, signal); }
        finally { if (stage === 'load') finished(); }
      },
      compareAndSwap: vi.fn(async (origin, previous, candidate, signal) => {
        try { await pause('commit', signal); return await backing.compareAndSwap(origin, previous, candidate, signal); }
        finally { if (stage === 'commit') finished(); }
      }),
    };
    const controller = new AbortController();
    const pending = advanceTrustedC2spCheckpoint(store, reference, checkpoint(2, secondRoot), witnessTime, {
      signal: controller.signal,
      consistencyProofSource: { fetchConsistencyProof: async (_ref, _from, _to, signal) => {
        try { await pause('proof', signal); return [leafHash(secondEntry)]; }
        finally { if (stage === 'proof') finished(); }
      } },
    });
    await ready;
    const reason = new Error('caller stopped verification');
    controller.abort(reason);
    await expect(pending).rejects.toMatchObject({ transient: true, cause: reason });
    release();
    await done;
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
    expect(verifyC2spConsistencyProof(1, 2, firstRoot, secondRoot, undefined as unknown as Uint8Array[])).toBe(false);
    expect(verifyC2spConsistencyProof(1, 2, firstRoot, secondRoot, [{ length: 32 }] as Uint8Array[])).toBe(false);
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

  it.each([
    { origin: '' }, { origin: 'other.example' }, { treeSize: 0, rootHash: firstRoot },
    ...[-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '1', true].map(treeSize => ({ treeSize })),
    ...[new Uint8Array(31), new Uint8Array(33), 'root'].map(rootHash => ({ rootHash })),
    ...[new Date(NaN), '2026-07-24T12:00:00Z', 0].map(witnessTime => ({ witnessTime })),
  ])('rejects invalid store input %o without changing trust', async invalid => {
    const store = new InMemoryTrustedC2spCheckpointStore();
    const valid = { origin: reference.origin, treeSize: 1, rootHash: firstRoot, witnessTime };
    await store.compareAndSwap(reference.origin, undefined, valid);
    const malformed = { ...valid, ...invalid } as TrustedC2spCheckpoint;
    await expect(store.compareAndSwap(reference.origin, valid, malformed)).rejects.toBeInstanceOf(ArgumentError);
    await expect(store.compareAndSwap(reference.origin, malformed, valid)).rejects.toBeInstanceOf(ArgumentError);
    await expect(store.load(reference.origin)).resolves.toEqual(valid);
  });

  it('validates origins and advance inputs before calling storage', async () => {
    const store = new InMemoryTrustedC2spCheckpointStore();
    await expect(store.load(' ')).rejects.toBeInstanceOf(ArgumentError);
    const load = vi.spyOn(store, 'load');
    await expect(advanceTrustedC2spCheckpoint(store, reference, checkpoint(-1, firstRoot), witnessTime)).rejects.toBeInstanceOf(ArgumentError);
    await expect(advanceTrustedC2spCheckpoint(store, reference, checkpoint(1, firstRoot), new Date(NaN))).rejects.toBeInstanceOf(ArgumentError);
    expect(load).not.toHaveBeenCalled();
  });

  it('copies Buffer roots and Date values on both store boundaries', async () => {
    const store = new InMemoryTrustedC2spCheckpointStore();
    const input = { origin: reference.origin, treeSize: 1, rootHash: Buffer.from(firstRoot), witnessTime: new Date(witnessTime) };
    await store.compareAndSwap(reference.origin, undefined, input);
    input.rootHash.fill(0);
    input.witnessTime.setTime(0);
    const loaded = (await store.load(reference.origin))!;
    expect(loaded.rootHash).toEqual(firstRoot);
    expect(loaded.witnessTime).toEqual(witnessTime);
    loaded.rootHash.fill(0);
    loaded.witnessTime.setTime(0);
    await expect(store.load(reference.origin)).resolves.toMatchObject({ rootHash: firstRoot, witnessTime });
  });

  it('snapshots Buffer-backed candidate and scan bytes before asynchronous storage', async () => {
    const backing = new InMemoryTrustedC2spCheckpointStore();
    let release!: () => void;
    let started!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const ready = new Promise<void>(resolve => { started = resolve; });
    const store: TrustedC2spCheckpointStore = {
      load: async (...args) => { started(); await gate; return backing.load(...args); },
      compareAndSwap: (...args) => backing.compareAndSwap(...args),
    };
    const root = Buffer.from(firstRoot);
    const bytes = Buffer.from(firstEntry);
    const time = new Date(witnessTime);
    const pending = advanceTrustedC2spCheckpoint(store, reference, checkpoint(1, root), time, {
      completeEntries: [{ index: 0, bytes }],
    });
    await ready;
    root.fill(0);
    bytes.fill(0);
    time.setTime(0);
    release();
    const result = await pending;
    expect(result).toMatchObject({ rootHash: firstRoot, witnessTime });
    result.rootHash.fill(0);
    result.witnessTime.setTime(0);
    await expect(backing.load(reference.origin)).resolves.toMatchObject({ rootHash: firstRoot, witnessTime });
  });

  it('verifies empty-tree consistency without accepting extra proof nodes', async () => {
    const empty = merkleRootFromEntries([]);
    expect(verifyC2spConsistencyProof(0, 1, empty, firstRoot, [])).toBe(true);
    expect(verifyC2spConsistencyProof(0, 1, empty, firstRoot, [firstRoot])).toBe(false);
    expect(verifyC2spConsistencyProof(0, 1, firstRoot, firstRoot, [])).toBe(false);
    expect(verifyC2spConsistencyProof(0, 0, empty, empty, [])).toBe(true);
    const store = new InMemoryTrustedC2spCheckpointStore();
    await advanceTrustedC2spCheckpoint(store, reference, checkpoint(0, empty), witnessTime);
    const fetchConsistencyProof = vi.fn(async () => { throw new Error('empty growth needs no proof'); });
    await advanceTrustedC2spCheckpoint(store, reference, checkpoint(1, firstRoot), witnessTime, {
      consistencyProofSource: { fetchConsistencyProof },
    });
    expect(fetchConsistencyProof).not.toHaveBeenCalled();
    await expect(store.load(reference.origin)).resolves.toMatchObject({ treeSize: 1 });
  });

  it('rejects an empty candidate with the wrong root before storage', async () => {
    const store = new InMemoryTrustedC2spCheckpointStore();
    const load = vi.spyOn(store, 'load');
    await expect(advanceTrustedC2spCheckpoint(store, reference, checkpoint(0, firstRoot), witnessTime))
      .rejects.toMatchObject({ errorCategory: 'INVALID_EVIDENCE', transient: false });
    expect(load).not.toHaveBeenCalled();
  });

  it('uses atomic origin-scoped compare-and-swap snapshots', async () => {
    const store = new InMemoryTrustedC2spCheckpointStore();
    const initial: TrustedC2spCheckpoint = { origin: reference.origin, treeSize: 1, rootHash: firstRoot, witnessTime };
    await expect(store.compareAndSwap(reference.origin, undefined, initial)).resolves.toBe(true);
    for (const stale of [{ ...initial, rootHash: new Uint8Array(32) }, { ...initial, witnessTime: new Date(witnessTime.getTime() + 1) }]) {
      await expect(store.compareAndSwap(reference.origin, stale, { ...initial, treeSize: 2, rootHash: secondRoot })).resolves.toBe(false);
    }
    await expect(store.compareAndSwap(reference.origin, undefined, initial)).resolves.toBe(false);
    await expect(store.load(reference.origin)).resolves.toEqual(initial);
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
