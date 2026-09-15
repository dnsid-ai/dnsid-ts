import { fromB64 } from './base64.ts';
import { C2spTlogParseError } from './errors.ts';

/** One C2SP signed-note signature line: signer name, optional 4-byte key hash, and raw signature bytes. */
export interface NoteSignature { name: string; keyHash?: Uint8Array; signature: Uint8Array; raw: string }
/** Parsed C2SP tlog-checkpoint: origin, tree size, SHA-256 root hash, and the signed-note signatures over `signedText`. */
export interface Checkpoint { origin: string; treeSize: number; rootHash: Uint8Array; signatures: NoteSignature[]; signedText: string }

/**
 * Parses a C2SP checkpoint (c2sp.org/tlog-checkpoint) carried in a signed note:
 * an origin line, decimal tree size, base64 root hash, then a blank line and
 * signature lines. Signatures are parsed but not verified.
 *
 * @throws C2spTlogParseError when the note body or a signature line is malformed.
 */
export function parseCheckpoint(text: string): Checkpoint {
  const normalized = text.replace(/\r\n/g, '\n');
  const sigStart = normalized.indexOf('\n\n');
  const signedText = sigStart === -1 ? normalized.trimEnd() + '\n' : normalized.slice(0, sigStart + 1);
  const body = signedText.trimEnd().split('\n');
  if (body.length < 3) throw new C2spTlogParseError('checkpoint must contain origin, size, and root hash');
  const [origin, sizeText, rootText] = body;
  if (!origin) throw new C2spTlogParseError('checkpoint missing origin');
  if (!/^(0|[1-9][0-9]*)$/.test(sizeText ?? '')) throw new C2spTlogParseError('checkpoint has invalid tree size');
  const treeSize = Number(sizeText);
  if (!Number.isSafeInteger(treeSize)) throw new C2spTlogParseError('checkpoint tree size outside safe integer range');
  const rootHash = fromB64(rootText ?? '');
  if (rootHash.length !== 32) throw new C2spTlogParseError('checkpoint root hash must be SHA-256 sized');
  const sigText = sigStart === -1 ? '' : normalized.slice(sigStart + 2).trim();
  const signatures = sigText ? sigText.split('\n').filter(Boolean).map(parseNoteSignature) : [];
  return { origin, treeSize, rootHash, signatures, signedText };
}

/**
 * Parses a single C2SP signed-note signature line (`— name base64`), splitting
 * the leading 4-byte key hash from the signature when present.
 *
 * @throws C2spTlogParseError when the line does not match the signed-note format.
 */
export function parseNoteSignature(line: string): NoteSignature {
  const m = /^— ([^\s]+)\s+([A-Za-z0-9+/=]+)$/.exec(line) ?? /^-- ([^\s]+)\s+([A-Za-z0-9+/=]+)$/.exec(line);
  if (!m) throw new C2spTlogParseError('invalid signed-note signature line');
  const bytes = fromB64(m[2]!);
  return bytes.length > 4
    ? { name: m[1]!, keyHash: bytes.slice(0, 4), signature: bytes.slice(4), raw: line }
    : { name: m[1]!, signature: bytes, raw: line };
}
