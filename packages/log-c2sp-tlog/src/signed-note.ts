import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { fromB64 } from './base64.ts';
import { C2spTlogParseError } from './errors.ts';
import type { Checkpoint, NoteSignature } from './checkpoint.ts';

/** Trusted C2SP signed-note verifier key: Ed25519 public key with optional 4-byte key ID and signature-type byte. */
export interface SignedNoteKey { name: string; kind: 'ed25519'; keyBytes: Uint8Array; keyId?: Uint8Array; signatureType?: Uint8Array }

/**
 * Parses a C2SP signed-note (c2sp.org/signed-note) verifier key in either the
 * `name+keyid+base64` vkey form or the whitespace-separated `name [ed25519] base64`
 * form. The base64 payload may carry a leading signature-type byte before the
 * 32-byte Ed25519 key.
 *
 * @throws C2spTlogParseError when the key text is malformed.
 */
export function parseSignedNoteVerifierKey(text: string): SignedNoteKey {
  const trimmed = text.trim();
  const firstPlus = trimmed.indexOf('+');
  const secondPlus = firstPlus === -1 ? -1 : trimmed.indexOf('+', firstPlus + 1);
  if (firstPlus > 0 && secondPlus > firstPlus + 1) {
    const name = trimmed.slice(0, firstPlus);
    const keyId = fromHex(trimmed.slice(firstPlus + 1, secondPlus));
    if (keyId.length !== 4) throw new C2spTlogParseError('signed-note key ID must be four bytes');
    return { name, keyId, kind: 'ed25519', ...decodeKey(trimmed.slice(secondPlus + 1)) };
  }
  const parts = trimmed.split(/\s+/);
  if (parts.length === 2) return { name: parts[0]!, kind: 'ed25519', ...decodeKey(parts[1]!) };
  if (parts.length === 3 && /^ed25519$/i.test(parts[1]!)) return { name: parts[0]!, kind: 'ed25519', ...decodeKey(parts[2]!) };
  throw new C2spTlogParseError('unsupported signed-note verifier key');
}

/** Returns true when any checkpoint signature matches `key` by name/key ID and verifies over the signed note text. */
export function verifyCheckpointSignature(checkpoint: Checkpoint, key: SignedNoteKey): boolean {
  return checkpoint.signatures.some((sig) => sig.name === key.name && keyIdMatches(sig, key) && verifyNoteSignature(checkpoint.signedText, sig, key));
}

/**
 * Finds a valid C2SP tlog-cosignature (type 0x04) by `key` on the checkpoint
 * and returns its witnessed timestamp in epoch seconds.
 *
 * @returns The cosignature timestamp, or undefined when the key is not a
 *   cosignature key or no valid cosignature is present.
 */
export function verifiedCosignatureTimestamp(checkpoint: Checkpoint, key: SignedNoteKey): number | undefined {
  if (key.signatureType?.length !== 1 || key.signatureType[0] !== 0x04) return undefined;
  for (const sig of checkpoint.signatures) {
    if (sig.name !== key.name || !keyIdMatches(sig, key) || !verifyNoteSignature(checkpoint.signedText, sig, key) || sig.signature.length !== 72) continue;
    const timestamp = Buffer.from(sig.signature.slice(0, 8)).readBigUInt64BE();
    if (timestamp <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(timestamp);
  }
  return undefined;
}

/**
 * Verifies one signed-note signature over `message` with an Ed25519 key.
 * Supports plain log signatures (type 0x01) and timestamped C2SP cosignatures
 * (type 0x04, `cosignature/v1` preimage). Returns false rather than throwing.
 */
export function verifyNoteSignature(message: string, sig: NoteSignature, key: SignedNoteKey): boolean {
  if (key.kind !== 'ed25519' || key.keyBytes.length !== 32) return false;
  const signatureType = key.signatureType?.[0] ?? 0x01;
  if (key.signatureType && key.signatureType.length !== 1) return false;
  let signedMessage = message;
  let signature = sig.signature;
  if (signatureType === 0x01) {
    if (signature.length !== 64) return false;
  } else if (signatureType === 0x04) {
    if (signature.length !== 72) return false;
    const timestamp = Buffer.from(signature.slice(0, 8)).readBigUInt64BE();
    if (timestamp > 0x7fff_ffff_ffff_ffffn) return false;
    signedMessage = `cosignature/v1\ntime ${timestamp}\n${message}`;
    signature = signature.slice(8);
  } else {
    return false;
  }
  try {
    const publicKey = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(key.keyBytes)]), format: 'der', type: 'spki' });
    return cryptoVerify(null, Buffer.from(signedMessage), publicKey, Buffer.from(signature));
  } catch {
    return false;
  }
}

function keyIdMatches(sig: NoteSignature, key: SignedNoteKey): boolean {
  if (!key.keyId) return true;
  if (!sig.keyHash) return false;
  return Buffer.from(sig.keyHash).equals(Buffer.from(key.keyId));
}

function decodeKey(s: string): { keyBytes: Uint8Array; signatureType?: Uint8Array } {
  const b = fromB64(s);
  if (b.length === 32) return { keyBytes: b };
  if (b.length === 33) return { signatureType: b.slice(0, 1), keyBytes: b.slice(1) };
  throw new C2spTlogParseError('Ed25519 verifier key must contain a signature type and 32-byte key');
}

function fromHex(s: string): Uint8Array {
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(s)) throw new C2spTlogParseError('invalid signed-note key ID');
  return Uint8Array.from(Buffer.from(s, 'hex'));
}
