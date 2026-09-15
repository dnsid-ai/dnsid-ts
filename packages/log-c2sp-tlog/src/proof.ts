import { fromB64 } from './base64.ts';
import { parseCheckpoint, type Checkpoint } from './checkpoint.ts';
import { verifyInclusion } from './merkle.ts';
import { C2spTlogParseError, C2spTlogVerificationError } from './errors.ts';
import { enforceCheckpointPolicy, type C2spTlogPolicy } from './policy.ts';

/** Parsed C2SP tlog-proof@v1: entry index, inclusion proof hashes, and the checkpoint the proof leads to. */
export interface TlogProofV1 { index: number; hashes: Uint8Array[]; checkpoint: Checkpoint; extra?: string[] }

/**
 * Parses a `c2sp.org/tlog-proof@v1` document: magic line, optional `extra`
 * line, `index` line, inclusion proof hashes, then a blank line and the
 * embedded checkpoint.
 *
 * @throws C2spTlogParseError when any line or the embedded checkpoint is malformed.
 */
export function parseTlogProofV1(text: string): TlogProofV1 {
  if (text.includes('\r')) throw new C2spTlogParseError('tlog proof must use LF line endings');
  const normalized = text;
  const split = normalized.indexOf('\n\n');
  if (split === -1) throw new C2spTlogParseError('tlog-proof@v1 missing checkpoint separator');
  const header = normalized.slice(0, split).split('\n');
  if (header[0] !== 'c2sp.org/tlog-proof@v1') throw new C2spTlogParseError('missing c2sp.org/tlog-proof@v1 magic');
  const hashes: Uint8Array[] = [];
  const extra: string[] = [];
  let cursor = 1;
  if (header[cursor]?.startsWith('extra ')) {
    const encoded = header[cursor]!.slice(6);
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) throw new C2spTlogParseError('invalid proof extra data');
    extra.push(encoded);
    cursor++;
  }
  const indexLine = header[cursor++];
  if (!indexLine?.startsWith('index ')) throw new C2spTlogParseError('tlog proof missing index');
  const index = parseSafeInt(indexLine.slice(6), 'proof index');
  for (const line of header.slice(cursor)) {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(line)) throw new C2spTlogParseError('invalid inclusion proof hash');
    const hash = fromB64(line);
    if (hash.length !== 32) throw new C2spTlogParseError('inclusion proof hash must be SHA-256 sized');
    hashes.push(hash);
  }
  return { index, hashes, extra, checkpoint: parseCheckpoint(normalized.slice(split + 2)) };
}

/**
 * Verifies an entry's inclusion proof: enforces the local checkpoint policy
 * (log signature and witness quorum) and checks the RFC 6962 inclusion path
 * against the checkpoint root.
 *
 * @param proof Parsed proof or raw tlog-proof@v1 text.
 * @returns The parsed, verified proof.
 * @throws C2spTlogParseError when a textual proof is malformed.
 * @throws C2spTlogVerificationError when policy enforcement or the inclusion proof fails.
 */
export function verifyC2spTlogProof(entryBytes: Uint8Array, proof: TlogProofV1 | string, policy: C2spTlogPolicy, origin?: string, scope = 'testnet', nowMs = Date.now(), maxClockSkewMs = 0): TlogProofV1 {
  const p = typeof proof === 'string' ? parseTlogProofV1(proof) : proof;
  enforceCheckpointPolicy(p.checkpoint, origin ?? p.checkpoint.origin, policy, scope, nowMs, maxClockSkewMs);
  if (!verifyInclusion(entryBytes, p.index, p.checkpoint.treeSize, p.checkpoint.rootHash, p.hashes)) {
    throw new C2spTlogVerificationError('invalid C2SP inclusion proof');
  }
  return p;
}

function parseSafeInt(s: string, name: string): number {
  if (!/^(0|[1-9][0-9]*)$/.test(s)) throw new C2spTlogParseError(`invalid ${name}`);
  const n = Number(s);
  if (!Number.isSafeInteger(n)) throw new C2spTlogParseError(`${name} outside safe integer range`);
  return n;
}
