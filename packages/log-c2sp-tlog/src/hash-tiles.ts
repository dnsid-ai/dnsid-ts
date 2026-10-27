import type { Checkpoint } from './checkpoint.ts';
import { C2spTlogError, C2spTlogVerificationError } from './errors.ts';
import { nodeHash } from './merkle.ts';
import { tilePath } from './tiles.ts';

interface Tile { level: number; index: number; hashes: Uint8Array[] }

/** @internal Computes a trusted prefix using only candidate-authenticated tiles. */
export async function authenticatedTilePrefixRoot(
  prefix: string,
  candidate: Pick<Checkpoint, 'treeSize' | 'rootHash'>,
  trustedSize: number,
  read: (url: string, maximum: number) => Promise<Uint8Array>,
): Promise<Uint8Array> {
  const tiles = new Map<string, Tile>();
  const authenticated = new Set<Tile>();
  const key = (level: number, index: number) => `${level}/${index}`;
  const get = async (level: number, index: number): Promise<Tile> => {
    const cached = tiles.get(key(level, index));
    if (cached) return cached;
    const width = Math.min(256, Math.floor(candidate.treeSize / 256 ** level) - index * 256);
    let bytes: Uint8Array;
    let responseWidth = width;
    try {
      bytes = await read(tilePath(prefix, level, index, width === 256 ? undefined : width), width * 32);
    } catch (cause) {
      if (width === 256 || !(cause instanceof C2spTlogError) || cause.status !== 404) throw cause;
      responseWidth = 256;
      bytes = await read(tilePath(prefix, level, index), 8192);
    }
    if (!(bytes instanceof Uint8Array) || bytes.length !== responseWidth * 32) {
      throw new C2spTlogVerificationError('C2SP hash tile width mismatch');
    }
    const hashes = Array.from({ length: width }, (_, i) => new Uint8Array(bytes.subarray(i * 32, (i + 1) * 32)));
    const tile = { level, index, hashes };
    tiles.set(key(level, index), tile);
    return tile;
  };

  // Base-256 digits select at most one frontier tile per level for each size.
  const root = async (size: number): Promise<Uint8Array> => {
    let suffix: Uint8Array | undefined;
    for (let level = 0, count = size; count > 0; level++, count = Math.floor(count / 256)) {
      const width = count % 256;
      if (!width) continue;
      const tile = await get(level, Math.floor(count / 256));
      suffix = fold(tile.hashes.slice(0, width), suffix);
    }
    return suffix!;
  };
  const candidateRoot = await root(candidate.treeSize);
  if (!equal(candidateRoot, candidate.rootHash)) throw new C2spTlogVerificationError('C2SP hash tiles do not reproduce the candidate root');
  for (const tile of tiles.values()) authenticated.add(tile);

  const trustedRoot = await root(trustedSize);
  const authenticate = async (tile: Tile): Promise<void> => {
    if (authenticated.has(tile)) return;
    const parent = await get(tile.level + 1, Math.floor(tile.index / 256));
    await authenticate(parent);
    // Hash the tile itself, never a subtree helper that returns its parent entry.
    if (tile.hashes.length !== 256 || !equal(fold(tile.hashes), parent.hashes[tile.index % 256]!)) {
      throw new C2spTlogVerificationError('C2SP hash tile does not authenticate against the candidate root');
    }
    authenticated.add(tile);
  };
  for (const tile of tiles.values()) await authenticate(tile);
  return trustedRoot;
}

/** Folds equal-height hashes with an optional smaller right-hand subtree. */
function fold(hashes: Uint8Array[], suffix?: Uint8Array): Uint8Array {
  if (hashes.length === 1) return suffix ? nodeHash(hashes[0]!, suffix) : hashes[0]!;
  let split = 1;
  while (split * 2 < hashes.length) split *= 2;
  if (suffix && split * 2 === hashes.length) return nodeHash(fold(hashes), suffix);
  return nodeHash(fold(hashes.slice(0, split)), fold(hashes.slice(split), suffix));
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return Buffer.from(left).equals(Buffer.from(right));
}
