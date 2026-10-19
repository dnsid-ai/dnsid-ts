import type { TXTRecord, DNSSECState } from './types.ts';

/**
 * Pluggable DNS resolver dependency.
 * Decouples verifyDomain from the system resolver.
 */
export interface DNSResolver {
  /**
   * Fetches TXT records for the given DNS owner name.
   * NXDOMAIN and NOERROR/NODATA return an empty record set with the response's
   * DNSSEC state (UNKNOWN if unavailable). Node-style ENOTFOUND/ENODATA exceptions
   * are normalized by IdentityManager to empty records with UNKNOWN state.
   * Known DNSSEC validation failures return FAILED, including for empty answers.
   * Timeouts, network failures, and ordinary SERVFAIL must reject instead.
   * IdentityManager applies DNSSEC policy before classifying absence as RecordNotFound.
   * @param name Normalized FQDN without trailing dot (e.g. "_dnsid.agent.example").
   *             MUST be treated as an absolute name — no search-domain expansion.
   * @returns The record set and the DNSSEC validation state of the response.
   */
  fetchTXT(name: string, options?: { signal?: AbortSignal }): Promise<[TXTRecord[], DNSSECState]>;
}
