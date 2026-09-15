import { C2spTlogParseError } from './errors.ts';

/** URL of a log's current checkpoint under the C2SP tlog-tiles layout. */
export function checkpointPath(prefix: string): string { return `${prefix}/checkpoint`; }
/** URL of hash tile `n` at `level` under the C2SP tlog-tiles layout; `width` selects a partial tile. */
export function tilePath(prefix: string, level: number, n: number, width?: number): string { return `${prefix}/tile/${level}/${tileN(n)}${width === undefined ? '' : `.p/${width}`}`; }
/** URL of entry bundle `n` under the C2SP tlog-tiles layout; `width` selects a partial bundle. */
export function entryBundlePath(prefix: string, n: number, width?: number): string { return `${prefix}/tile/entries/${tileN(n)}${width === undefined ? '' : `.p/${width}`}`; }

/** Formats a tile number as the tlog-tiles x-prefixed base-1000 path segments. */
function tileN(n: number): string {
  if (!Number.isSafeInteger(n) || n < 0) throw new C2spTlogParseError('invalid C2SP tile number');
  const groups = String(n).padStart(3, '0').replace(/\B(?=(?:\d{3})+$)/g, '/').split('/');
  return groups.map((g, i) => `${i === groups.length - 1 ? '' : 'x'}${g.padStart(3, '0')}`).join('/');
}

/**
 * Splits a C2SP tlog-tiles entry bundle (16-bit big-endian length prefix per
 * entry) into individual entry byte strings.
 *
 * @throws C2spTlogParseError when a length prefix or entry is truncated.
 */
export function parseEntryBundle(bytes: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  let off = 0;
  while (off < bytes.length) {
    if (off + 2 > bytes.length) throw new C2spTlogParseError('truncated entry bundle length');
    const len = (bytes[off]! << 8) | bytes[off + 1]!;
    off += 2;
    if (off + len > bytes.length) throw new C2spTlogParseError('truncated entry bundle entry');
    out.push(bytes.slice(off, off + len));
    off += len;
  }
  return out;
}

/**
 * Encodes entries as a C2SP tlog-tiles entry bundle with 16-bit big-endian
 * length prefixes.
 *
 * @throws C2spTlogParseError when an entry exceeds 65535 bytes.
 */
export function encodeEntryBundle(entries: Uint8Array[]): Uint8Array {
  const size = entries.reduce((n, e) => n + 2 + e.length, 0);
  const out = new Uint8Array(size);
  let off = 0;
  for (const e of entries) {
    if (e.length > 0xffff) throw new C2spTlogParseError('entry too large for bundle');
    out[off++] = e.length >> 8;
    out[off++] = e.length & 0xff;
    out.set(e, off);
    off += e.length;
  }
  return out;
}
