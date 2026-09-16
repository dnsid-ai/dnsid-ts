import type { VerifiedDomain } from './verified-domain.ts';

/**
 * Cache for verified domain results. Held by IdentityManager and consulted at the start of every verifyDomain call.
 *
 * Implementation requirements:
 * - Get MUST return null for any entry whose VerifiedDomain.expiry() has passed.
 * - Put MUST derive the entry TTL from result.expiry() and evict automatically when that time arrives.
 * - Implementations MUST be safe for concurrent use.
 */
export interface IdentityCache {
  /** Returns the cached VerifiedDomain for a domain, or null if not cached or expired. */
  get(domain: string): VerifiedDomain | null;

  /** Stores a verified domain result. Entry expires at result.expiry(). */
  put(domain: string, result: VerifiedDomain): void;

  /** Removes a domain from the cache immediately. */
  evict(domain: string): void;
}

interface CacheEntry {
  result: VerifiedDomain;
  expiresAt: Date;
  timer: ReturnType<typeof setTimeout>;
}

/** Default in-memory cache implementation. */
export class InMemoryIdentityCache implements IdentityCache {
  private readonly store = new Map<string, CacheEntry>();

  get(domain: string): VerifiedDomain | null {
    const entry = this.store.get(domain);
    if (!entry) return null;
    if (new Date() >= entry.expiresAt) {
      this.store.delete(domain);
      return null;
    }
    return entry.result;
  }

  put(domain: string, result: VerifiedDomain): void {
    const expiresAt = result.expiry();
    this.evict(domain);
    const ttlMs = expiresAt.getTime() - Date.now();
    if (result.dnsTTL <= 0 || !Number.isFinite(ttlMs) || ttlMs <= 0) return;
    const timer = setTimeout(() => this.store.delete(domain), Math.max(0, ttlMs));
    // Allow the process to exit even if the timer is still pending
    if (typeof timer === 'object' && 'unref' in timer) timer.unref();

    this.store.set(domain, { result, expiresAt, timer });
  }

  evict(domain: string): void {
    const entry = this.store.get(domain);
    if (entry) {
      clearTimeout(entry.timer);
      this.store.delete(domain);
    }
  }
}
