import type { TXTRecord, DNSSECState } from './types.ts';

/**
 * Pluggable DNS resolver dependency.
 * Decouples verifyDomain from the system resolver.
 */
export interface DNSResolver {
  /**
   * Fetches TXT records for the given DNS owner name.
   * @param name Normalized FQDN without trailing dot (e.g. "_dnsid.agent.example.com").
   *             MUST be treated as an absolute name — no search-domain expansion.
   * @returns The record set and the DNSSEC validation state of the response.
   */
  fetchTXT(name: string, options?: { signal?: AbortSignal }): Promise<[TXTRecord[], DNSSECState]>;
}
