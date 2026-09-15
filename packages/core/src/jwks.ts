import { calculateJwkThumbprint, importJWK } from 'jose';
import type { JWK } from 'jose';
import { ValidationError } from './errors.ts';
import type { DnsIdJWK } from './types.ts';

export const SIGNING_ALGS = new Set([
  'EdDSA', 'ES256', 'ES384', 'ES512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
]);
const DRAFT01_SIGNING_ALGS = new Set(['EdDSA', 'ES256']);

/** True if alg is permitted for draft-01 record or operational signing. */
export function isDraft01SigningAlg(alg: string): boolean {
  return DRAFT01_SIGNING_ALGS.has(alg);
}

function derivedSignatureAlg(key: DnsIdJWK): string {
  if (key.kty === 'OKP' && key.crv === 'Ed25519') return 'EdDSA';
  if (key.kty === 'EC' && key.crv === 'P-256') return 'ES256';
  if (key.kty === 'EC' && key.crv === 'P-384') return 'ES384';
  if (key.kty === 'EC' && key.crv === 'P-521') return 'ES512';
  throw new ValidationError(`unsupported JWK signature key type${key.kid ? `: ${key.kid}` : ''}`);
}

function isAlgConsistentWithKey(alg: string, key: DnsIdJWK): boolean {
  if (key.kty === 'OKP') return key.crv === 'Ed25519' && alg === 'EdDSA';
  if (key.kty === 'EC') {
    return (key.crv === 'P-256' && alg === 'ES256')
      || (key.crv === 'P-384' && alg === 'ES384')
      || (key.crv === 'P-521' && alg === 'ES512');
  }
  if (key.kty === 'RSA') return /^RS(256|384|512)$/.test(alg) || /^PS(256|384|512)$/.test(alg);
  return false;
}

export function jwkSignatureAlg(key: DnsIdJWK): string {
  if (key.use !== undefined && key.use !== 'sig') {
    throw new ValidationError(`JWK use is not valid for signing${key.kid ? ` for ${key.kid}` : ''}: ${key.use}`);
  }
  if (key.alg !== undefined) {
    if (!SIGNING_ALGS.has(key.alg)) {
      throw new ValidationError(`unsupported JWK alg${key.kid ? ` for ${key.kid}` : ''}: ${key.alg}`);
    }
    if (!isAlgConsistentWithKey(key.alg, key)) {
      throw new ValidationError(`JWK alg is inconsistent with kty/crv${key.kid ? ` for ${key.kid}` : ''}: ${key.alg}`);
    }
    return key.alg;
  }
  return derivedSignatureAlg(key);
}

function isSigningUse(key: DnsIdJWK): boolean {
  return key.use === undefined || key.use === 'sig';
}

/** True if this key satisfies the draft-01 record-signing key policy. */
function isDraft01RecordSigningCandidate(key: DnsIdJWK): boolean {
  if (!isSigningUse(key) || !key.alg) return false;
  try {
    return isDraft01SigningAlg(jwkSignatureAlg(key));
  } catch {
    return false;
  }
}

/** Rejects a selectable public JWK that lacks the material needed to verify a signature. */
function assertPublicKeyMaterial(key: DnsIdJWK): void {
  const at = key.kid ? ` for ${key.kid}` : '';
  if (key.kty === 'EC') {
    if (typeof key.x !== 'string' || !key.x || typeof key.y !== 'string' || !key.y) {
      throw new ValidationError(`EC JWK missing public coordinates${at}`);
    }
  } else if (key.kty === 'OKP') {
    if (typeof key.x !== 'string' || !key.x) throw new ValidationError(`OKP JWK missing public key${at}`);
  } else if (key.kty === 'RSA') {
    if (typeof key.n !== 'string' || !key.n || typeof key.e !== 'string' || !key.e) {
      throw new ValidationError(`RSA JWK missing public parameters${at}`);
    }
  }
}

/**
 * Confirms a selectable public JWK actually imports as a verification key. Present-but-invalid
 * coordinate text (bad base64url, a point off the curve) passes the shape check above but fails
 * here, so it is rejected at record-validation time rather than surfacing later as a misleading
 * SignatureInvalid when the sg kid selects it.
 */
async function assertImportablePublicKey(key: DnsIdJWK): Promise<void> {
  assertPublicKeyMaterial(key);
  try {
    await importJWK(key as unknown as JWK, jwkSignatureAlg(key));
  } catch (e) {
    const at = key.kid ? ` for ${key.kid}` : '';
    throw new ValidationError(`record-signing JWK is not importable${at}: ${(e as Error).message}`);
  }
}

/** Wrapper around a JWK Set document. */
export class JWKS {
  readonly keys: DnsIdJWK[];

  constructor(keys: DnsIdJWK[]) {
    this.keys = keys;
  }

  /**
   * Returns all keys suitable for signature verification.
   * A key qualifies if use is absent/sig and it has a supported signature algorithm binding.
   * @throws ValidationError if no signing keys are present.
   */
  signingKeys(): DnsIdJWK[] {
    const keys = this.keys.filter(k => {
      if (!isSigningUse(k)) return false;
      try {
        jwkSignatureAlg(k);
        return true;
      } catch {
        return false;
      }
    });
    if (keys.length === 0) {
      throw new ValidationError('JWKS contains no signing keys');
    }
    return keys;
  }

  /**
   * Returns the key matching the given kid, or null if not found.
   */
  keyById(kid: string): DnsIdJWK | null {
    return this.keys.find(k => k.kid === kid) ?? null;
  }

  /** Returns the draft-01-compatible record-signing key matching kid, or null if none. */
  draft01RecordSigningKeyById(kid: string): DnsIdJWK | null {
    return this.keys.find(k => k.kid === kid && isDraft01RecordSigningCandidate(k)) ?? null;
  }

  /**
   * Validates the key set.
   * @throws ValidationError if:
   *   - no signing key has a kid field
   *   - any present alg field is inconsistent with the key's kty/crv binding
   *   - no key is suitable for signing
   */
  validate(): void {
    for (const key of this.keys) {
      if (key.alg !== undefined) jwkSignatureAlg(key);
    }

    const signing = this.signingKeys();

    const hasKid = signing.some(k => !!k.kid);
    if (!hasKid) {
      throw new ValidationError('no signing key in JWKS has a kid field');
    }

    this.assertUniqueKids();
  }

  /** Rejects a JWKS carrying duplicate kid values so key selection is unambiguous. */
  private assertUniqueKids(): void {
    const kids = this.keys.map(k => k.kid).filter(Boolean);
    if (new Set(kids).size !== kids.length) {
      throw new ValidationError('JWKS contains duplicate kid values');
    }
  }

  currentRecordSigningKey(): DnsIdJWK {
    return this.currentDraft01SigningKey('record-signing');
  }

  currentOperationalSigningKey(): DnsIdJWK {
    return this.currentDraft01SigningKey('operational');
  }

  validateRecordSigning(): void {
    this.assertUniqueKids();
    this.currentRecordSigningKey();
  }

  /** Validates the single current draft-01 ek key and its importable public material. */
  async validateRecordSigningKeyset(): Promise<void> {
    this.assertUniqueKids();
    const key = this.currentRecordSigningKey();
    await assertImportablePublicKey(key);
  }

  validateOperational(): void {
    this.assertUniqueKids();
    this.currentOperationalSigningKey();
  }

  private currentDraft01SigningKey(role: string): DnsIdJWK {
    const signing = this.keys.filter(isSigningUse);
    if (signing.length !== 1) throw new ValidationError(`draft-01 ${role} JWKS must contain exactly one current signing key`);
    const key = signing[0]!;
    if (!key.kid) throw new ValidationError(`draft-01 ${role} key missing kid`);
    if (!key.alg) throw new ValidationError(`draft-01 ${role} key missing alg`);
    const alg = jwkSignatureAlg(key);
    if (!DRAFT01_SIGNING_ALGS.has(alg)) throw new ValidationError(`unsupported draft-01 ${role} key alg: ${alg}`);
    return key;
  }

  /** Returns the JWKS as a plain JSON-serializable object. */
  toJSON(): { keys: DnsIdJWK[] } {
    return { keys: this.keys };
  }
}

/**
 * Computes the RFC 7638 JWK thumbprint of a key.
 * Returns unpadded base64url (RFC 7515 §2).
 *
 * Lifecycle log bindings MUST use thumbprints, not kid values, as the durable key identifier.
 */
export async function jwkThumbprint(key: DnsIdJWK): Promise<string> {
  return calculateJwkThumbprint(key as unknown as JWK, 'sha256');
}

/**
 * Computes a JWK thumbprint, normalizing errors for malformed keys into a
 * ValidationError with a consistent message identifying the originating set.
 */
async function safeThumbprint(key: DnsIdJWK, setLabel: string): Promise<string> {
  try {
    return await jwkThumbprint(key);
  } catch (e) {
    throw new ValidationError(
      `malformed key in ${setLabel} JWK Set: unable to compute RFC 7638 thumbprint` +
      (key.kid ? ` for kid "${key.kid}"` : '') +
      `: ${(e as Error).message}`,
    );
  }
}

/**
 * Returns true if any key in `a` shares an RFC 7638 JWK thumbprint with any key in `b`.
 *
 * draft-01 §Two-Key Separation requires the ek and ku JWK Sets to be pairwise thumbprint-disjoint,
 * even for self-accounted DNSids — a verifier MUST NOT infer self-accounting from key equality,
 * so this check does not special-case any relationship between the two sets.
 *
 * Throws a normalized ValidationError if any key in either set is too malformed to thumbprint.
 */
export async function keySetsShareKeyMaterial(a: JWKS, b: JWKS): Promise<boolean> {
  if (a.keys.length === 0 || b.keys.length === 0) return false;
  const [thumbprintsA, thumbprintsB] = await Promise.all([
    Promise.all(a.keys.map(k => safeThumbprint(k, 'ek'))),
    Promise.all(b.keys.map(k => safeThumbprint(k, 'ku'))),
  ]);
  const setA = new Set(thumbprintsA);
  return thumbprintsB.some(t => setA.has(t));
}
