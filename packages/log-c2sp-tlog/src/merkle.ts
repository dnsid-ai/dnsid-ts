import { createHash } from 'node:crypto';

/** SHA-256 over the concatenation of the given chunks. */
export function sha256(...chunks: Uint8Array[]): Uint8Array {
  const h = createHash('sha256');
  for (const c of chunks) h.update(c);
  return new Uint8Array(h.digest());
}

/** RFC 6962 leaf hash: SHA-256(0x00 || entry bytes). */
export function leafHash(entryBytes: Uint8Array): Uint8Array {
  return sha256(new Uint8Array([0]), entryBytes);
}

/** RFC 6962 interior node hash: SHA-256(0x01 || left || right). */
export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(new Uint8Array([1]), left, right);
}

/**
 * Recomputes the Merkle tree root implied by a leaf hash, its index, the tree
 * size, and an RFC 6962 inclusion proof path.
 *
 * @throws Error when the index or tree size is out of range.
 */
export function inclusionRoot(leaf: Uint8Array, index: number, treeSize: number, proof: Uint8Array[]): Uint8Array {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(treeSize) || index < 0 || treeSize <= index) {
    throw new Error('invalid inclusion index or tree size');
  }
  let hash = leaf;
  let i = index;
  let n = treeSize;
  for (const sibling of proof) {
    if (i % 2 === 1) hash = nodeHash(sibling, hash);
    else if (i < n - 1) hash = nodeHash(hash, sibling);
    else hash = nodeHash(sibling, hash);
    i = Math.floor(i / 2);
    n = Math.floor((n + 1) / 2);
  }
  return hash;
}

/** Checks an RFC 6962 inclusion proof for `entryBytes` at `index` against the expected tree root. */
export function verifyInclusion(entryBytes: Uint8Array, index: number, treeSize: number, rootHash: Uint8Array, proof: Uint8Array[]): boolean {
  return Buffer.from(inclusionRoot(leafHash(entryBytes), index, treeSize, proof)).equals(Buffer.from(rootHash));
}

/** Computes the RFC 6962 Merkle root of an ordered list of entries (empty-tree root for no entries). */
export function merkleRootFromEntries(entries: Uint8Array[]): Uint8Array {
  if (entries.length === 0) return sha256();
  let level = entries.map(leafHash);
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? nodeHash(level[i]!, level[i + 1]!) : level[i]!);
    }
    level = next;
  }
  return level[0]!;
}
