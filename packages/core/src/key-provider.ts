import type { DnsIdJWK } from './types.ts';

/**
 * Standardized interface for Key Management Systems.
 *
 * Implementations may wrap local key files, cloud KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault), or HSMs.
 * The SDK never handles private key material directly.
 *
 * Key states:
 * - Pending: generated but not yet promoted (excluded from ListKeyIds / JWKS)
 * - Active:  current signing key (in JWKS; used for signing)
 * - Retained: rotated out; kept for verification/audit (not used for new signing)
 */
export interface KeyProvider {
  // ---- Runtime methods (called internally by the SDK) ----

  /**
   * Returns the JWK representation of the current active public signing key.
   * The returned kid MUST NOT contain '#'.
   */
  signingKey(): Promise<DnsIdJWK>;

  /**
   * Returns the JWK representation of a key by ID (active, pending, or retained).
   * Raises if not found.
   */
  jwk(kid: string): Promise<DnsIdJWK>;

  /**
   * Returns the IDs of all active and retained keys (pending keys excluded).
   * The active key ID MUST appear first; retained keys follow in any order.
   */
  listKeyIds(): Promise<string[]>;

  /**
   * Signs the given payload with the current active signing key.
   * Returns raw signature bytes.
   */
  sign(payload: Uint8Array): Promise<Uint8Array>;

  /** Signs with a specified active or pending key. */
  signKey(kid: string, payload: Uint8Array): Promise<Uint8Array>;

  // ---- Management methods (called by operator code during key rotation) ----

  /**
   * Generates a new key pair in the pending state.
   * Returns the new key's kid.
   */
  generateKey(): Promise<string>;

  /**
   * Promotes a pending key to active. The previously active key transitions to retained.
   */
  activate(kid: string): Promise<void>;

  /**
   * Supersedes and removes a retained key from this provider's published key set.
   */
  supersede(kid: string): Promise<void>;

  /** @deprecated Use supersede(). */
  purge?(kid: string): Promise<void>;
}
