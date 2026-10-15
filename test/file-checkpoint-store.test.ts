import { mkdtemp, readdir, readFile, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  advanceTrustedC2spCheckpoint,
  C2spCheckpointConsistencyError,
  C2spCheckpointStoreError,
  merkleRootFromEntries,
  parseC2spTlogLr,
  type TrustedC2spCheckpoint,
} from '@dnsid-ai/log-c2sp-tlog';
import { FileTrustedC2spCheckpointStore } from '@dnsid-ai/sdk/node';

const reference = parseC2spTlogLr('c2sp-tlog:testnet:https://log.example/dnsid#agent.example');
const origin = reference.origin;
const encoder = new TextEncoder();
const firstEntry = encoder.encode('first');
const secondEntry = encoder.encode('second');
const firstRoot = merkleRootFromEntries([firstEntry]);
const secondRoot = merkleRootFromEntries([firstEntry, secondEntry]);
const witnessTime = new Date('2026-07-24T12:00:00Z');
const trusted = (treeSize: number, rootHash: Uint8Array): TrustedC2spCheckpoint => ({ origin, treeSize, rootHash, witnessTime });
const checkpoint = (treeSize: number, rootHash: Uint8Array) => ({ origin, treeSize, rootHash, signatures: [], signedText: '' });

async function withDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), 'dnsid-checkpoints-'));
  try { await fn(join(dir, 'store')); } finally { await rm(dir, { recursive: true, force: true }); }
}

describe('FileTrustedC2spCheckpointStore', () => {
  it('persists trusted checkpoints across instances and keeps the rollback defence after a restart', () => withDir(async dir => {
    const first = await FileTrustedC2spCheckpointStore.open(dir);
    await advanceTrustedC2spCheckpoint(first, reference, checkpoint(2, secondRoot), witnessTime, {
      completeEntries: [{ index: 0, bytes: firstEntry }, { index: 1, bytes: secondEntry }],
    });

    const restarted = await FileTrustedC2spCheckpointStore.open(dir);
    await expect(restarted.load(origin)).resolves.toEqual(trusted(2, secondRoot));
    const rollback = await advanceTrustedC2spCheckpoint(restarted, reference, checkpoint(1, firstRoot), witnessTime).catch(e => e);
    expect(rollback).toBeInstanceOf(C2spCheckpointConsistencyError);
    expect(rollback.errorCategory).toBe('LOG_ROLLBACK');

    const files = await readdir(dir);
    expect(files.filter(name => name.endsWith('.json'))).toHaveLength(1);
    expect(files.filter(name => name.endsWith('.lock') || name.endsWith('.tmp'))).toHaveLength(0);
  }));

  it('compare-and-swap reports a lost race and refuses to lower the trusted size', () => withDir(async dir => {
    const store = await FileTrustedC2spCheckpointStore.open(dir);
    await expect(store.compareAndSwap(origin, undefined, trusted(1, firstRoot))).resolves.toBe(true);
    await expect(store.compareAndSwap(origin, undefined, trusted(2, secondRoot))).resolves.toBe(false);
    await expect(store.compareAndSwap(origin, trusted(1, new Uint8Array(32)), trusted(2, secondRoot))).resolves.toBe(false);
    await expect(store.compareAndSwap(origin, trusted(1, firstRoot), trusted(2, secondRoot))).resolves.toBe(true);

    const lowered = await store.compareAndSwap(origin, trusted(2, secondRoot), trusted(1, firstRoot)).catch(e => e);
    expect(lowered).toBeInstanceOf(C2spCheckpointStoreError);
    expect(lowered.errorCategory).toBe('CHECKPOINT_STORE_ERROR');
    expect(lowered.transient).toBe(false);
    await expect(store.load(origin)).resolves.toEqual(trusted(2, secondRoot));
  }));

  it('rebaseline replaces exact current state on an operator decision, never by verification', () => withDir(async dir => {
    const store = await FileTrustedC2spCheckpointStore.open(dir);
    await store.compareAndSwap(origin, undefined, trusted(2, secondRoot));
    await expect(store.rebaseline(origin, trusted(1, firstRoot), trusted(1, firstRoot))).resolves.toBe(false);
    await expect(store.rebaseline(origin, trusted(2, secondRoot), trusted(1, firstRoot))).resolves.toBe(true);
    await expect(store.load(origin)).resolves.toEqual(trusted(1, firstRoot));
  }));

  it('serializes concurrent compare-and-swap so only one of two forked extensions is accepted', () => withDir(async dir => {
    const a = await FileTrustedC2spCheckpointStore.open(dir);
    const b = await FileTrustedC2spCheckpointStore.open(dir);
    await a.compareAndSwap(origin, undefined, trusted(1, firstRoot));
    const forkRoot = new Uint8Array(32).fill(7);
    const [left, right] = await Promise.all([
      a.compareAndSwap(origin, trusted(1, firstRoot), trusted(2, secondRoot)),
      b.compareAndSwap(origin, trusted(1, firstRoot), trusted(2, forkRoot)),
    ]);
    expect([left, right].filter(Boolean)).toHaveLength(1);
    const current = await a.load(origin);
    expect(current?.treeSize).toBe(2);
    expect([secondRoot, forkRoot].some(root => current!.rootHash.every((byte, i) => byte === root[i]))).toBe(true);
  }));

  it('fails closed on a corrupt or foreign file instead of substituting empty trust', () => withDir(async dir => {
    const store = await FileTrustedC2spCheckpointStore.open(dir);
    await store.compareAndSwap(origin, undefined, trusted(1, firstRoot));
    const [file] = (await readdir(dir)).filter(name => name.endsWith('.json'));
    const filePath = join(dir, file!);

    await writeFile(filePath, '{not json', 'utf-8');
    const corrupt = await store.load(origin).catch(e => e);
    expect(corrupt).toBeInstanceOf(C2spCheckpointStoreError);
    expect(corrupt.message).toContain('restore it from backup');
    await expect(store.compareAndSwap(origin, undefined, trusted(2, secondRoot))).rejects.toBeInstanceOf(C2spCheckpointStoreError);

    // The corrupt file is left in place for the operator; it is never deleted or overwritten.
    await expect(readFile(filePath, 'utf-8')).resolves.toBe('{not json');
    await writeFile(filePath, JSON.stringify({ version: 1, origin: 'https://other.example/log', treeSize: 1, rootHash: '', witnessTime: witnessTime.toISOString() }), 'utf-8');
    await expect(store.load(origin)).rejects.toBeInstanceOf(C2spCheckpointStoreError);
  }));

  it('honors cancellation at the commit boundary and rejects an origin mismatch', () => withDir(async dir => {
    const store = await FileTrustedC2spCheckpointStore.open(dir);
    const controller = new AbortController();
    controller.abort();
    await expect(store.compareAndSwap(origin, undefined, trusted(1, firstRoot), controller.signal)).rejects.toThrow();
    await expect(store.load(origin)).resolves.toBeUndefined();
    await expect(store.compareAndSwap(origin, undefined, { ...trusted(1, firstRoot), origin: 'https://other.example/log' })).rejects.toThrow('origin mismatch');
  }));

  it('times out on a live lock and removes a stale one', () => withDir(async dir => {
    const store = await FileTrustedC2spCheckpointStore.open(dir, { lockTimeoutMs: 100, staleLockMs: 60_000 });
    await store.compareAndSwap(origin, undefined, trusted(1, firstRoot));
    const [file] = (await readdir(dir)).filter(name => name.endsWith('.json'));
    const lockPath = join(dir, `${file!}.lock`);

    await writeFile(lockPath, '99999', 'utf-8');
    const blocked = await store.compareAndSwap(origin, trusted(1, firstRoot), trusted(2, secondRoot)).catch(e => e);
    expect(blocked).toBeInstanceOf(C2spCheckpointStoreError);
    expect(blocked.message).toContain('timed out');
    await expect(store.load(origin)).resolves.toEqual(trusted(1, firstRoot));

    const stale = new Date(Date.now() - 120_000);
    await utimes(lockPath, stale, stale);
    await expect(store.compareAndSwap(origin, trusted(1, firstRoot), trusted(2, secondRoot))).resolves.toBe(true);
    await expect(store.load(origin)).resolves.toEqual(trusted(2, secondRoot));
  }));
});
