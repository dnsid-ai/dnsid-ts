import { describe, expect, it, vi } from 'vitest';
import {
  advanceTrustedC2spCheckpoint, C2spTlogError, InMemoryTrustedC2spCheckpointStore,
  leafHash, nodeHash, parseC2spTlogLr, requiredC2spResourceFetchGuarantees,
  ScanStreamSource, tilePath, type TrustedC2spCheckpointStore,
} from '@dnsid-ai/log-c2sp-tlog';
import { sha256 } from '../packages/log-c2sp-tlog/src/merkle.ts';
import { authenticatedTilePrefixRoot } from '../packages/log-c2sp-tlog/src/hash-tiles.ts';
import { advanceC2spCheckpoint } from '../packages/log-c2sp-tlog/src/checkpoint-trust.ts';

const prefix = 'https://log.example/dnsid';
const reference = parseC2spTlogLr(`c2sp-tlog:testnet:${prefix}#stream`);
const witnessTime = new Date('2026-07-24T12:00:00Z');

// Independent in-memory RFC 6962 tree, including every binary subtree level.
const layers: Uint8Array[][] = [Array.from({ length: 131_073 }, (_, i) => leafHash(Buffer.from(`entry ${i}`)))];
while (layers.at(-1)!.length > 1) {
  const previous = layers.at(-1)!;
  layers.push(Array.from({ length: Math.floor(previous.length / 2) }, (_, i) => nodeHash(previous[2 * i]!, previous[2 * i + 1]!)));
}
function root(size: number, start = 0): Uint8Array {
  if (!size) return sha256();
  const height = Math.floor(Math.log2(size));
  const split = 2 ** height;
  const left = layers[height]![start / split]!;
  return size === split ? left : nodeHash(left, root(size - split, start + split));
}
const checkpoint = (size: number, hash = root(size)) => ({
  origin: reference.origin, treeSize: size, rootHash: hash, signatures: [], signedText: '',
});
function tileReader(size: number) {
  return vi.fn(async (url: string, maximum: number) => {
    const match = /^\/tile\/(\d+)\/((?:x\d{3}\/)*\d{3})(?:\.p\/(\d+))?$/.exec(new URL(url).pathname.slice('/dnsid'.length));
    if (!match) throw new Error(`unexpected resource ${url}`);
    const level = Number(match[1]);
    const index = Number(match[2]!.replaceAll('x', '').replaceAll('/', ''));
    const width = match[3] ? Number(match[3]) : 256;
    const available = Math.min(256, Math.floor(size / 256 ** level) - index * 256);
    expect(width).toBe(available);
    expect(maximum).toBe(width * 32);
    return new Uint8Array(Buffer.concat(layers[level * 8]!.slice(index * 256, index * 256 + width)));
  });
}

function boundedSource(read: (url: string, maximum: number, options: { signal?: AbortSignal }) => Promise<Uint8Array>, maxTreeSize?: number) {
  return new ScanStreamSource({ authenticateCheckpoint: () => {}, maxTreeSize }, {
    fetchBounded: read, securityGuarantees: requiredC2spResourceFetchGuarantees,
  });
}
async function seeded(size: number, hash = root(size)) {
  const store = new InMemoryTrustedC2spCheckpointStore();
  await advanceTrustedC2spCheckpoint(store, reference, checkpoint(size, hash), witnessTime);
  return store;
}
async function advance(store: TrustedC2spCheckpointStore, m: number, n: number, read: (url: string, maximum: number) => Promise<Uint8Array> = tileReader(n)) {
  const source = boundedSource(read);
  return advanceC2spCheckpoint(store, reference, checkpoint(n), witnessTime, {}, (candidate, size, signal) => {
    expect(size).toBe(m);
    return source.consistencyRoot(prefix, candidate, size, signal);
  });
}

describe('candidate-authenticated C2SP hash tiles', () => {
  it('matches brute-force RFC 6962 roots within two tiles per level across boundary and uneven sizes', async () => {
    const sizes = new Set<number>([1, 3, 255, 256, 257, 511, 512, 513, 65535, 65536, 65537, 70000, 131071, 131072, 131073]);
    for (let power = 1; power <= 65536; power *= 2) for (const delta of [-1, 0, 1]) if (power + delta > 0) sizes.add(power + delta);
    const pairs: [number, number][] = [];
    for (let n = 2; n <= 40; n++) for (let m = 1; m < n; m++) pairs.push([m, n]);
    for (const n of sizes) {
      for (const m of new Set([1, n - 1, ...sizes])) if (m > 0 && m < n) pairs.push([m, n]);
    }
    let random = 123;
    for (let i = 0; i < 100; i++) {
      random = (random * 1664525 + 1013904223) >>> 0;
      const n = 2 + random % 131072;
      pairs.push([1 + (random >>> 5) % (n - 1), n]);
    }
    for (const [m, n] of pairs) {
      const read = tileReader(n);
      expect(await authenticatedTilePrefixRoot(prefix, checkpoint(n), m, read), `${m}->${n}`).toEqual(root(m));
      const levels = new Map<string, number>();
      for (const [url] of read.mock.calls) {
        const level = url.split('/tile/')[1]!.split('/')[0]!;
        levels.set(level, (levels.get(level) ?? 0) + 1);
      }
      for (const count of levels.values()) expect(count, `${m}->${n}`).toBeLessThanOrEqual(2);
      expect(new Set(read.mock.calls.map(([url]) => url)).size).toBe(read.mock.calls.length);
    }
    const read = tileReader(70000);
    await expect(authenticatedTilePrefixRoot(prefix, checkpoint(70000), 300, read)).resolves.toEqual(root(300));
    expect(read).toHaveBeenCalledTimes(5);
  }, 30_000);

  it('reuses a complete scan before either configured consistency capability', async () => {
    const store = await seeded(1);
    const fetchConsistencyProof = vi.fn(async () => { throw new Error('scan must win'); });
    const tiles = vi.fn(async () => { throw new Error('scan must win'); });
    const completeEntries = [0, 1].map(index => ({ index, bytes: Buffer.from(`entry ${index}`) }));
    await expect(advanceC2spCheckpoint(store, reference, checkpoint(2), witnessTime, {
      completeEntries, consistencyProofSource: { fetchConsistencyProof },
    }, tiles)).resolves.toMatchObject({ treeSize: 2 });
    expect(fetchConsistencyProof).not.toHaveBeenCalled();
    expect(tiles).not.toHaveBeenCalled();
  });

  it('uses the standard base-1000 tile path encoding', () => {
    expect(tilePath(prefix, 0, 1234, 17)).toBe(`${prefix}/tile/0/x001/234.p/17`);
    expect(tilePath(prefix, 2, 1234067)).toBe(`${prefix}/tile/2/x001/x234/067`);
  });

  it.each([1, 2, 256, 65536, 300])('classifies a wrong trusted root at %i only after candidate authentication', async m => {
    const store = await seeded(m, new Uint8Array(32));
    const previous = await store.load(reference.origin);
    await expect(advance(store, m, 70000)).rejects.toMatchObject({
      errorCategory: 'LOG_INCONSISTENT', origin: reference.origin, trustedTreeSize: m, observedTreeSize: 70000,
      trustedRootHash: new Uint8Array(32), observedRootHash: root(70000), transient: false,
    });
    await expect(store.load(reference.origin)).resolves.toEqual(previous);
  });

  it.each([
    '/tile/0/273.p/112', '/tile/1/001.p/17', '/tile/2/000.p/1',
    '/tile/0/001', '/tile/1/000',
  ])('rejects a changed tile %s, including full tiles used only for the trusted prefix', async path => {
    const honest = tileReader(70000);
    const read = vi.fn(async (url: string, maximum: number) => {
      const bytes = await honest(url, maximum);
      if (url === `${prefix}${path}`) bytes[0]! ^= 1;
      return bytes;
    });
    // An incorrect trusted root must not mask corrupt candidate evidence.
    const store = await seeded(300, new Uint8Array(32));
    await expect(advance(store, 300, 70000, read)).rejects.toMatchObject({ errorCategory: 'INVALID_EVIDENCE', transient: false });
    await expect(store.load(reference.origin)).resolves.toMatchObject({ treeSize: 300 });
  });

  it('authenticates all entries of a non-edge tile, including hashes outside the trusted prefix', async () => {
    const honest = tileReader(70000);
    const read = async (url: string, maximum: number) => {
      const bytes = await honest(url, maximum);
      if (url === tilePath(prefix, 0, 1)) bytes[8191]! ^= 1;
      return bytes;
    };
    await expect(advance(await seeded(300), 300, 70000, read)).rejects.toMatchObject({ errorCategory: 'INVALID_EVIDENCE' });
  });

  it.each([-32, -1, 1, 32])('rejects tile length off by %i bytes without changing trust', async delta => {
    const store = await seeded(1);
    const read = vi.fn(async () => new Uint8Array(64 + delta));
    await expect(advance(store, 1, 2, read)).rejects.toMatchObject({ errorCategory: 'INVALID_EVIDENCE', transient: false });
    expect(read).toHaveBeenCalledOnce();
    await expect(store.load(reference.origin)).resolves.toMatchObject({ treeSize: 1 });
  });

  it('retries a deleted partial tile as a full tile once, using only its authenticated prefix', async () => {
    const read = vi.fn(async (url: string, maximum: number) => {
      if (url.endsWith('.p/2')) throw new C2spTlogError('deleted partial', { status: 404 });
      expect(url).toBe(tilePath(prefix, 0, 0));
      expect(maximum).toBe(8192);
      return new Uint8Array(Buffer.concat(layers[0]!.slice(0, 256)));
    });
    const store = await seeded(1);
    await expect(advance(store, 1, 2, read)).resolves.toMatchObject({ treeSize: 2 });
    expect(read).toHaveBeenCalledTimes(2);
  });

  it('bounds reads when every candidate partial tile needs its one full-tile retry', async () => {
    const read = vi.fn(async (url: string, maximum: number) => {
      if (url.includes('.p/')) throw new C2spTlogError('partial deleted', { status: 404 });
      const match = /\/tile\/(\d+)\/(\d+)$/.exec(url)!;
      const level = Number(match[1]);
      const index = Number(match[2]);
      expect(maximum).toBe(8192);
      const bytes = Buffer.alloc(8192);
      Buffer.concat(layers[level * 8]!.slice(index * 256, (index + 1) * 256)).copy(bytes);
      return new Uint8Array(bytes);
    });
    await expect(advance(await seeded(300), 300, 70000, read)).resolves.toMatchObject({ treeSize: 70000 });
    expect(read).toHaveBeenCalledTimes(8);
    expect(read.mock.calls.filter(([url]) => url.includes('.p/'))).toHaveLength(3);
  });

  it.each(['missing', 'short', 'long', 'corrupt'] as const)('fails closed when the full-tile retry is %s', async fault => {
    const failure = new C2spTlogError('missing full tile', { status: 503, transient: true });
    const read = vi.fn(async (url: string) => {
      if (url.endsWith('.p/2')) throw new C2spTlogError('missing partial', { status: 404 });
      if (fault === 'missing') throw failure;
      if (fault === 'short') return new Uint8Array(64);
      if (fault === 'long') return new Uint8Array(8193);
      return new Uint8Array(8192);
    });
    const store = await seeded(1);
    await expect(advance(store, 1, 2, read)).rejects.toMatchObject(fault === 'missing'
      ? { status: 503, transient: true } : { errorCategory: 'INVALID_EVIDENCE', transient: false });
    expect(read).toHaveBeenCalledTimes(2);
    await expect(store.load(reference.origin)).resolves.toMatchObject({ treeSize: 1 });
  });

  it('keeps non-404 transport failures and their retry classification', async () => {
    for (const status of [403, 408, 429, 500]) {
      const failure = new C2spTlogError('tile unavailable', { status, transient: status !== 403 });
      const read = vi.fn(async () => { throw failure; });
      await expect(advance(await seeded(1), 1, 2, read)).rejects.toBe(failure);
      expect(read).toHaveBeenCalledOnce();
    }
  });

  it('bounds tree size before fetching tiles and does not apply the aggregate entry-byte cap', async () => {
    const read = tileReader(70000);
    const source = boundedSource(read, 69999);
    await expect(source.consistencyRoot(prefix, checkpoint(70000), 300, new AbortController().signal)).rejects.toMatchObject({ errorCategory: 'INVALID_EVIDENCE' });
    expect(read).not.toHaveBeenCalled();
    const tinyEntryCap = new ScanStreamSource({ authenticateCheckpoint: () => {}, maxTotalEntryBytes: 1 }, {
      fetchBounded: read, securityGuarantees: requiredC2spResourceFetchGuarantees,
    });
    await expect(tinyEntryCap.consistencyRoot(prefix, checkpoint(70000), 300, new AbortController().signal)).resolves.toEqual(root(300));
  });

  it.each([false, true])('shares cancellation and the overall deadline with tile reads (retry=%s)', async retry => {
    vi.useFakeTimers();
    try {
      const store = await seeded(1);
      let received: AbortSignal | undefined;
      const fetchBounded = vi.fn(async (url: string, _maximum: number, options: { signal?: AbortSignal }) => {
        received = options.signal;
        if (retry && url.endsWith('.p/2')) throw new C2spTlogError('missing partial', { status: 404 });
        return new Promise<Uint8Array>(() => {});
      });
      const source = boundedSource(fetchBounded);
      const controller = new AbortController();
      const reason = new Error('caller canceled');
      const run = (timeoutMs: number) => advanceC2spCheckpoint(store, reference, checkpoint(2), witnessTime,
        { signal: controller.signal, timeoutMs }, (candidate, size, signal) => source.consistencyRoot(prefix, candidate, size, signal));
      const timed = expect(run(10)).rejects.toMatchObject({ transient: true });
      await vi.advanceTimersByTimeAsync(10);
      await timed;
      expect(received?.aborted).toBe(true);
      const canceled = expect(run(100)).rejects.toMatchObject({ transient: true, cause: reason });
      await vi.advanceTimersByTimeAsync(0);
      controller.abort(reason);
      await canceled;
      await expect(store.load(reference.origin)).resolves.toMatchObject({ treeSize: 1 });
    } finally { vi.useRealTimers(); }
  });

  it('reloads a lost CAS race and checks the winner using fresh authenticated tiles', async () => {
    const backing = await seeded(1);
    const winner = { ...checkpoint(256, new Uint8Array(32)), witnessTime };
    const compareAndSwap = vi.fn(async (origin, expected, candidate, signal) => {
      await backing.compareAndSwap(origin, expected, winner, signal);
      return false;
    });
    const store = { load: backing.load.bind(backing), compareAndSwap };
    const source = boundedSource(tileReader(70000));
    const checked: number[] = [];
    await expect(advanceC2spCheckpoint(store, reference, checkpoint(70000), witnessTime, {}, (candidate, size, signal) => {
      checked.push(size);
      return source.consistencyRoot(prefix, candidate, size, signal);
    })).rejects.toMatchObject({ errorCategory: 'LOG_INCONSISTENT', trustedTreeSize: 256 });
    expect(checked).toEqual([1, 256]);
    expect(compareAndSwap).toHaveBeenCalledOnce();
    await expect(backing.load(reference.origin)).resolves.toMatchObject(winner);
  });
});
