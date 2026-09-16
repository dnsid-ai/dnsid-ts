/**
 * Node.js DNS and HTTPS transport for the DNSid protocol.
 *
 * Provides the concrete network layer consumed by `@dnsid-ai/core`:
 * DNS TXT resolvers for fetching identity records, SSRF-safe HTTPS JSON fetching
 * that captures the peer TLS certificate, and `fetch` factories that route
 * requests through a custom DNS server and/or CA bundle. Built on Node
 * built-ins (`node:dns`, `node:https`, `node:tls`, `node:net`) plus undici;
 * this package is Node-only and not usable in browsers.
 *
 * IMPORTANT limitation: the resolvers here use the system DNS APIs, which
 * cannot determine DNSSEC validation state. TXT lookups report
 * `DNSSECState.UNKNOWN` (or `FAILED` on SERVFAIL) — this package is not a
 * production DNSSEC validator. DNS-over-HTTPS (DoH) is not supported.
 *
 * @packageDocumentation
 */
import * as dnsPromises from 'node:dns/promises';
import * as fs from 'node:fs';
import * as https from 'node:https';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { Agent, fetch as undiciFetch } from 'undici';
import type { Dispatcher } from 'undici';

import type { DNSResolver, TLSCertificate, TransportConfig, TXTRecord } from '@dnsid-ai/protocol';
import { DNSSECState, VerificationCode, VerificationError } from '@dnsid-ai/protocol';

/** Minimal WHATWG-fetch-compatible function signature returned by the fetch factories. */
export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/** Result of {@link fetchJson}: the parsed body plus the TLS certificate presented by the peer. */
export interface FetchResult {
  /** JSON-decoded response body. */
  data: unknown;
  /** Peer certificate details (expiry and DNS SANs) captured from the TLS session. */
  tlsCert: TLSCertificate;
}

/** Options controlling {@link fetchJson}. */
export interface HTTPSFetchOptions {
  /** Shared verification deadline/cancellation, including redirects. */
  signal?: AbortSignal;
  /** If set, the URL host (and every redirect host) must match this host exactly. */
  allowedHost?: string;
  /** With `allowedHost`, also accept subdomains of the allowed host (`*.allowedHost`). */
  domainBoundary?: boolean;
  /** Request timeout in milliseconds. Defaults to 10 000. */
  timeoutMs?: number;
  /** Path to a PEM CA bundle appended to the system root certificates. */
  caBundlePath?: string;
  /** Custom DNS server (`host`, `host:port`, or `[ipv6]:port`) used to resolve the target. */
  dnsServer?: string;
  /** Maximum accepted response body size in bytes. Defaults to 1 MiB. */
  maxResponseBytes?: number;
  /**
   * Hostnames whose resolved private or loopback addresses may be contacted. For trusted test and
   * private deployments only; public defaults use none.
   */
  allowedUnsafeHosts?: readonly string[];
}

const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1 * 1024 * 1024;
const DNSID_USER_AGENT = 'dnsid-ts';

type RequestInitWithDuplex = RequestInit & { duplex?: 'half' };
type RequestInitWithDispatcher = RequestInitWithDuplex & { dispatcher: Dispatcher };

/** Shared configuration for the fetch and DNS resolver factories; the same type as `DnsidConfig.transport`. */
export type { TransportConfig };

/** Explicit exceptions for trusted test/private deployments using {@link createSsrfSafeFetch}. */
export interface SsrfSafeFetchOptions {
  /**
   * Hostnames whose resolved RFC 1918/ULA private or loopback addresses may be contacted.
   * Link-local and other unsafe ranges remain blocked. Matching is exact after
   * URL hostname normalization; public defaults use no exceptions.
   */
  allowedUnsafeHosts?: readonly string[];
}

/**
 * Creates a fetch function honoring the transport configuration.
 *
 * With no custom DNS server or CA bundle this returns the global `fetch`
 * unchanged. Otherwise it returns an undici-backed fetch whose connections
 * resolve hostnames via the configured DNS server and/or trust the extra CA
 * bundle in addition to the system roots. Unlike {@link createSsrfSafeFetch},
 * the returned fetch applies no private-address filtering.
 *
 * @param config - DNS server and/or CA bundle overrides.
 * @returns A {@link FetchLike} suitable for passing to core verification APIs.
 *
 * @example
 * ```ts
 * import { createDnsidFetch, createDefaultDnsResolver } from '@dnsid-ai/transport';
 *
 * const config = { dnsServer: '1.1.1.1' };
 * const fetchImpl = createDnsidFetch(config);
 * const dnsResolver = createDefaultDnsResolver(config);
 *
 * const res = await fetchImpl('https://agent.example.com/.well-known/jwks.json');
 * const [records, dnssec] = await dnsResolver.fetchTXT('_dnsid.agent.example.com');
 * ```
 */
export function createDnsidFetch(config: TransportConfig): FetchLike {
  if (!config.dnsServer && !config.caBundlePath) {
    return globalThis.fetch.bind(globalThis);
  }

  const connect: Record<string, unknown> = {};
  if (config.dnsServer) connect.lookup = createLookup(config.dnsServer);
  if (config.caBundlePath) connect.ca = [...tls.rootCertificates, fs.readFileSync(config.caBundlePath, 'utf8')];

  return createFetchWithDispatcher(new Agent({ connect }) as Dispatcher);
}

/**
 * Creates a fetch function that rejects connections to private, loopback,
 * link-local, and other non-routable addresses (SSRF protection).
 *
 * Every hostname is resolved (via the configured DNS server, or the system
 * resolver otherwise) and each resulting address is checked with
 * {@link isUnsafeIp} before connecting; requests resolving to an unsafe
 * address fail with a VerificationError (TLSError, surfaced through the
 * fetch rejection). Redirects are returned to the caller instead of followed
 * automatically so each destination can be explicitly policy-checked.
 *
 * @param config - Optional DNS server and/or CA bundle overrides.
 * @param options - Explicit hostname-scoped private-address exceptions for trusted test/private deployments.
 * @returns A {@link FetchLike} with address filtering applied on every lookup.
 */
export function createSsrfSafeFetch(config: TransportConfig = {}, options: SsrfSafeFetchOptions = {}): FetchLike {
  const allowedUnsafeHosts = new Set((options.allowedUnsafeHosts ?? []).map(normalizeAllowedUnsafeHost));
  const connect: Record<string, unknown> = { lookup: createSsrfSafeLookup(config.dnsServer, allowedUnsafeHosts) };
  if (config.caBundlePath) connect.ca = [...tls.rootCertificates, fs.readFileSync(config.caBundlePath, 'utf8')];
  const fetchWithSafeLookup = createFetchWithDispatcher(new Agent({ connect }) as Dispatcher);
  return async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : input);
    if (isUnsafeIp(url.hostname)
      && !(allowedUnsafeHosts.has(url.hostname) && isPrivateOrLoopbackIp(url.hostname))) {
      throw new VerificationError(`unsafe target IP address: ${url.hostname}`, {
        code: VerificationCode.TLSError,
      });
    }
    return fetchWithSafeLookup(input, { ...init, redirect: 'manual' });
  };
}

/** Wraps undici fetch so every request uses the given dispatcher (normalizing Request inputs). */
function createFetchWithDispatcher(dispatcher: Dispatcher): FetchLike {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const { url, init: normalizedInit } = normalizeFetchArgs(input, init);
    const fetchInit: RequestInitWithDispatcher = { ...normalizedInit, dispatcher };
    const fetchWithDispatcher = undiciFetch as unknown as typeof globalThis.fetch;
    return fetchWithDispatcher(url, fetchInit as RequestInit);
  };
}

/**
 * Creates the DNS resolver used to fetch DNSid identity records (TXT).
 *
 * Uses the configured DNS server when present, otherwise the system resolver.
 * Either way the underlying lookup cannot observe DNSSEC validation, so
 * results carry `DNSSECState.UNKNOWN` (or `FAILED` when the query SERVFAILs).
 * Node's TXT API omits TTLs, so results use TTL 0 to disable SDK caching.
 */
export function createDefaultDnsResolver(config: Pick<TransportConfig, 'dnsServer'>): DNSResolver {
  return config.dnsServer ? createDnsResolverFromServer(config.dnsServer) : createSystemDnsResolver();
}

/**
 * Creates a {@link DNSResolver} that queries a specific DNS server.
 *
 * Accepts `host`, `host:port`, or `[ipv6]:port`. A hostname (rather than an
 * IP literal) is resolved once via the system resolver on first use, then
 * cached for the resolver's lifetime. TXT answers are returned with TTL 0
 * (no SDK caching) and `DNSSECState.UNKNOWN`; `ENODATA`/`ENOTFOUND` yield an empty
 * record set, `ESERVFAIL` yields `DNSSECState.FAILED`, and other DNS errors
 * are rethrown as-is.
 *
 * @param server - DNS server address, optionally with port.
 */
export function createDnsResolverFromServer(server: string): DNSResolver {
  const parsed = parseDnsServer(server);
  if (!parsed || net.isIP(parsed.host)) {
    const resolver = new dnsPromises.Resolver();
    resolver.setServers([server]);
    return createSystemDnsResolver(resolver);
  }

  let resolverPromise: Promise<dnsPromises.Resolver> | null = null;
  return {
    async fetchTXT(name: string): Promise<[TXTRecord[], DNSSECState]> {
      resolverPromise ??= (async () => {
        const { address } = await dnsPromises.lookup(parsed.host);
        const resolver = new dnsPromises.Resolver();
        resolver.setServers([formatDnsServer(address, parsed.port)]);
        return resolver;
      })();
      return fetchTxtViaSystem(name, await resolverPromise);
    },
  };
}

/**
 * Fetches a JSON document over HTTPS with strict transport checks, returning
 * the parsed body together with the peer TLS certificate.
 *
 * Enforces: HTTPS-only URLs, optional host pinning via `allowedHost` (with
 * optional subdomain boundary), SSRF-safe address resolution, at most 5
 * same-policy HTTPS redirects, an expected 200 status, and a bounded response
 * body size. All lookups route through `opts.dnsServer` when provided.
 *
 * @param url - Absolute HTTPS URL to fetch.
 * @param opts - Transport constraints; see {@link HTTPSFetchOptions}.
 * @returns The parsed JSON body and captured TLS certificate.
 * @throws VerificationError with `VerificationCode.TLSError` for policy or
 *   transport failures (non-HTTPS URL, disallowed or unsafe host, redirect
 *   violations, non-200 status, oversized body, timeout, TLS/connection
 *   errors); with `VerificationCode.RecordInvalid` when the body is not valid
 *   JSON. Network-shaped failures are marked `transient`.
 */
export function fetchJson(url: string, opts?: HTTPSFetchOptions): Promise<FetchResult> {
  return fetchWithRedirects(url, opts ?? {}, 0);
}

/**
 * Splits a DNS server string into host and optional port.
 *
 * Supports `host`, `host:port`, and `[ipv6]:port`. Unbracketed strings
 * containing multiple colons (bare IPv6 literals) are returned whole as
 * `host`, which callers pass through to Node unchanged.
 */
export function parseDnsServer(server: string): { host: string; port?: string } | null {
  const bracket = server.match(/^\[([^\]]+)](?::(\d+))?$/);
  if (bracket) return { host: bracket[1]!, port: bracket[2] };
  const idx = server.lastIndexOf(':');
  if (idx > -1 && server.indexOf(':') === idx) {
    return { host: server.slice(0, idx), port: server.slice(idx + 1) };
  }
  return { host: server };
}

/** Formats a resolved address (bracketing IPv6) with an optional port for `Resolver.setServers`. */
export function formatDnsServer(address: string, port?: string): string {
  const host = net.isIP(address) === 6 ? `[${address}]` : address;
  return port ? `${host}:${port}` : host;
}

/**
 * Creates a Node `lookup` function that resolves A/AAAA records via the given
 * DNS server instead of the system resolver.
 *
 * A hostname-form server is itself resolved once via the system resolver and
 * cached. Suitable for `https.RequestOptions.lookup` or an undici connect
 * option. The callback receives an `Error` when no A/AAAA records exist.
 *
 * @param dnsServer - DNS server address (`host`, `host:port`, or `[ipv6]:port`).
 */
export function createLookup(dnsServer: string): NonNullable<https.RequestOptions['lookup']> {
  let resolverPromise: Promise<dnsPromises.Resolver> | null = null;
  async function resolver(): Promise<dnsPromises.Resolver> {
    resolverPromise ??= (async () => {
      const parsed = parseDnsServer(dnsServer);
      const server = parsed && !net.isIP(parsed.host)
        ? formatDnsServer((await dnsPromises.lookup(parsed.host)).address, parsed.port)
        : dnsServer;
      const r = new dnsPromises.Resolver();
      r.setServers([server]);
      return r;
    })();
    return resolverPromise;
  }

  return (hostname, opts, cb) => {
    const family = typeof opts === 'object' ? opts.family : opts;
    const all = typeof opts === 'object' && opts.all;
    void (async () => {
      const r = await resolver();
      const addresses = family === 6
        ? (await r.resolve6(hostname)).map(address => ({ address, family: 6 as const }))
        : family === 4
          ? (await r.resolve4(hostname)).map(address => ({ address, family: 4 as const }))
          : [
              ...(await r.resolve4(hostname).catch(() => [])).map(address => ({ address, family: 4 as const })),
              ...(await r.resolve6(hostname).catch(() => [])).map(address => ({ address, family: 6 as const })),
            ];
      if (addresses.length === 0) throw new Error(`no A/AAAA records for ${hostname}`);
      if (all) cb(null, addresses);
      else {
        const first = addresses[0]!;
        cb(null, first.address, first.family);
      }
    })().catch(err => cb(err as NodeJS.ErrnoException, '', 0));
  };
}

/**
 * Like {@link createLookup} but rejects any resolved address that
 * {@link isUnsafeIp} flags, surfacing a VerificationError (TLSError) through
 * the lookup callback. Falls back to the system resolver when no DNS server
 * is configured.
 */
function createSsrfSafeLookup(
  dnsServer?: string,
  allowedUnsafeHosts: ReadonlySet<string> = new Set(),
): NonNullable<https.RequestOptions['lookup']> {
  let resolverPromise: Promise<dnsPromises.Resolver> | null = null;
  async function customResolver(): Promise<dnsPromises.Resolver> {
    if (!dnsServer) throw new Error('no custom DNS server configured');
    resolverPromise ??= (async () => {
      const parsed = parseDnsServer(dnsServer);
      const server = parsed && !net.isIP(parsed.host)
        ? formatDnsServer((await dnsPromises.lookup(parsed.host)).address, parsed.port)
        : dnsServer;
      const r = new dnsPromises.Resolver();
      r.setServers([server]);
      return r;
    })();
    return resolverPromise;
  }

  return (hostname, opts, cb) => {
    const rawFamily = typeof opts === 'object' ? opts.family : opts;
    const family = rawFamily === 'IPv4' ? 4 : rawFamily === 'IPv6' ? 6 : rawFamily;
    const all = typeof opts === 'object' && opts.all;
    void (async () => {
      const addresses = await resolveAddresses(hostname, family, dnsServer ? await customResolver() : undefined);
      const unsafe = addresses.find(({ address }) => isUnsafeIp(address));
      if (unsafe && !(allowedUnsafeHosts.has(hostname) && addresses.every(({ address }) => isPrivateOrLoopbackIp(address)))) {
        throw new VerificationError(`unsafe resolved IP address for ${hostname}: ${unsafe.address}`, {
          code: VerificationCode.TLSError,
        });
      }
      if (all) cb(null, addresses);
      else {
        const first = addresses[0]!;
        cb(null, first.address, first.family);
      }
    })().catch(err => cb(err as NodeJS.ErrnoException, '', 0));
  };
}

function normalizeAllowedUnsafeHost(host: string): string {
  let parsed: URL;
  try {
    parsed = new URL(`https://${host}`);
  } catch {
    throw new TypeError(`invalid allowed unsafe hostname: ${host}`);
  }
  if (!host || parsed.username || parsed.password || parsed.port || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new TypeError(`invalid allowed unsafe hostname: ${host}`);
  }
  return parsed.hostname;
}

/** Resolves a hostname to A/AAAA addresses (passing IP literals through), throwing when none exist. */
async function resolveAddresses(
  hostname: string,
  family: number | undefined,
  resolver?: dnsPromises.Resolver,
): Promise<Array<{ address: string; family: 4 | 6 }>> {
  const ipFamily = net.isIP(hostname);
  if (ipFamily === 4 || ipFamily === 6) return [{ address: hostname, family: ipFamily }];

  if (!resolver) {
    const records = await dnsPromises.lookup(hostname, { all: true, family: family === 4 || family === 6 ? family : 0 });
    if (records.length === 0) throw new Error(`no A/AAAA records for ${hostname}`);
    return records.map(({ address, family: recordFamily }) => ({ address, family: recordFamily as 4 | 6 }));
  }

  const addresses = family === 6
    ? (await resolver.resolve6(hostname)).map(address => ({ address, family: 6 as const }))
    : family === 4
      ? (await resolver.resolve4(hostname)).map(address => ({ address, family: 4 as const }))
      : [
          ...(await resolver.resolve4(hostname).catch(() => [])).map(address => ({ address, family: 4 as const })),
          ...(await resolver.resolve6(hostname).catch(() => [])).map(address => ({ address, family: 6 as const })),
        ];
  if (addresses.length === 0) throw new Error(`no A/AAAA records for ${hostname}`);
  return addresses;
}

/**
 * True if an IP address must not be contacted by SSRF-safe transports:
 * private, loopback, link-local, CGN, documentation, multicast, reserved,
 * 6to4/Teredo, and IPv4-mapped/compatible IPv6 forms of any of these.
 * Malformed IP-shaped input is treated as unsafe; non-IP strings return false.
 */
export function isUnsafeIp(address: string): boolean {
  let host = address;
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  const zoneIndex = host.indexOf('%');
  const normalized = zoneIndex === -1 ? host : host.slice(0, zoneIndex);
  const family = net.isIP(normalized);
  if (family === 4) return isUnsafeIpv4(normalized);
  if (family === 6) return isUnsafeIpv6(normalized);
  return false;
}

function isPrivateOrLoopbackIp(address: string): boolean {
  let host = address;
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  const zoneIndex = host.indexOf('%');
  const normalized = zoneIndex === -1 ? host : host.slice(0, zoneIndex);
  const family = net.isIP(normalized);
  if (family === 4) {
    const [a, b] = normalized.split('.').map(Number) as [number, number, number, number];
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  if (family !== 6) return false;
  const bytes = ipv6ToBytes(normalized);
  if (!bytes) return false;
  const mapped = ipv4FromMappedIpv6(bytes) ?? ipv4FromCompatibleIpv6(bytes);
  if (mapped) return isPrivateOrLoopbackIp(mapped);
  const loopback = bytes.slice(0, 15).every(byte => byte === 0) && bytes[15] === 1;
  return loopback || (bytes[0]! & 0xfe) === 0xfc;
}

/** True if a dotted-quad IPv4 address is malformed or in a non-routable/reserved range. */
function isUnsafeIpv4(address: string): boolean {
  const octets = address.split('.').map(part => Number(part));
  if (octets.length !== 4 || octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)) return true;
  const [a, b, c] = octets as [number, number, number, number];
  return a === 0
    || a === 10
    || a === 127
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 192 && b === 0 && c === 0)
    || (a === 192 && b === 0 && c === 2)
    || (a === 198 && (b === 18 || b === 19))
    || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113)
    || (a >= 224 && a <= 239)
    || a >= 240;
}

/** True if an IPv6 address is malformed, non-routable, or wraps an unsafe IPv4 address. */
function isUnsafeIpv6(address: string): boolean {
  const bytes = ipv6ToBytes(address);
  if (!bytes) return true;

  const mapped = ipv4FromMappedIpv6(bytes);
  if (mapped) return isUnsafeIpv4(mapped);
  const compatible = ipv4FromCompatibleIpv6(bytes);
  if (compatible) return isUnsafeIpv4(compatible);

  const first = bytes[0]!;
  const second = bytes[1]!;
  const allZero = bytes.every(byte => byte === 0);
  const loopback = bytes.slice(0, 15).every(byte => byte === 0) && bytes[15] === 1;
  return allZero
    || loopback
    || (first & 0xfe) === 0xfc // unique local fc00::/7
    || (first === 0xfe && (second & 0xc0) === 0x80) // link-local fe80::/10
    || first === 0xff // multicast ff00::/8
    || (first === 0x20 && second === 0x01 && bytes[2] === 0x0d && bytes[3] === 0xb8) // documentation
    || (first === 0x20 && second === 0x02) // 6to4
    || (first === 0x20 && second === 0x01 && bytes[2] === 0x00 && bytes[3] === 0x00); // Teredo
}

/** Extracts the embedded IPv4 address from an IPv4-mapped IPv6 address (::ffff:a.b.c.d), if any. */
function ipv4FromMappedIpv6(bytes: number[]): string | null {
  const isMapped = bytes.slice(0, 10).every(byte => byte === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
  if (!isMapped) return null;
  return bytes.slice(12, 16).join('.');
}

/** Extracts the embedded IPv4 address from an IPv4-compatible IPv6 address (::a.b.c.d), if any. */
function ipv4FromCompatibleIpv6(bytes: number[]): string | null {
  const isCompatible = bytes.slice(0, 12).every(byte => byte === 0);
  if (!isCompatible) return null;
  return bytes.slice(12, 16).join('.');
}

/** Parses an IPv6 literal (including `::` compression and embedded IPv4) into 16 bytes, or null. */
function ipv6ToBytes(address: string): number[] | null {
  let normalized = address;
  const embeddedIpv4Start = address.lastIndexOf(':');
  if (embeddedIpv4Start !== -1) {
    const embeddedIpv4 = address.slice(embeddedIpv4Start + 1);
    if (embeddedIpv4.includes('.')) {
      const octets = embeddedIpv4.split('.').map(part => Number(part));
      if (octets.length !== 4 || octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)) return null;
      normalized = `${address.slice(0, embeddedIpv4Start + 1)}${((octets[0]! << 8) | octets[1]!).toString(16)}:${((octets[2]! << 8) | octets[3]!).toString(16)}`;
    }
  }

  const halves = normalized.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const right = halves[1] ? halves[1].split(':').filter(Boolean) : [];
  const missing = halves.length === 2 ? 8 - left.length - right.length : 0;
  const groups = halves.length === 2 ? [...left, ...Array(missing).fill('0'), ...right] : left;
  if (missing < 0 || groups.length !== 8) return null;

  const bytes: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    const value = Number.parseInt(group, 16);
    bytes.push((value >> 8) & 0xff, value & 0xff);
  }
  return bytes;
}

/** Flattens a Request input into url + init (setting duplex for bodies) so undici accepts it. */
function normalizeFetchArgs(input: RequestInfo | URL, init?: RequestInit): { url: string | URL; init: RequestInitWithDuplex } {
  if (input instanceof Request) {
    const normalized: RequestInitWithDuplex = {
      method: input.method,
      headers: input.headers,
      body: input.body,
      cache: input.cache,
      credentials: input.credentials,
      integrity: input.integrity,
      keepalive: input.keepalive,
      mode: input.mode,
      redirect: input.redirect,
      referrer: input.referrer,
      referrerPolicy: input.referrerPolicy,
      signal: input.signal,
      ...init,
    };
    if (normalized.body) normalized.duplex = 'half';
    return { url: input.url, init: normalized };
  }
  return { url: input, init: init ?? {} };
}

/** Wraps a `resolveTxt`-capable resolver (system by default) as a {@link DNSResolver}. */
function createSystemDnsResolver(resolver: Pick<typeof dnsPromises, 'resolveTxt'> = dnsPromises): DNSResolver {
  return {
    async fetchTXT(name: string): Promise<[TXTRecord[], DNSSECState]> {
      return fetchTxtViaSystem(name, resolver);
    },
  };
}

/**
 * Fetches TXT records for a name without inventing a cache lifetime.
 *
 * The system DNS API exposes no DNSSEC information, so the state is always
 * `UNKNOWN` except on SERVFAIL, which maps to `FAILED`. Missing names/records
 * (`ENODATA`/`ENOTFOUND`) yield an empty set; other DNS errors are rethrown.
 */
async function fetchTxtViaSystem(
  name: string,
  resolver: Pick<typeof dnsPromises, 'resolveTxt'>,
): Promise<[TXTRecord[], DNSSECState]> {
  try {
    const records = await resolver.resolveTxt(name);
    // ponytail: resolveTxt omits remaining TTLs; use a TTL-aware resolver to enable SDK caching.
    return [records.map(strings => ({ strings, ttl: 0 })), DNSSECState.UNKNOWN];
  } catch (err) {
    const nodeErr = err as NodeJS.ErrnoException;
    switch (nodeErr.code) {
      case 'ENODATA':
      case 'ENOTFOUND':
        return [[], DNSSECState.UNKNOWN];
      case 'ESERVFAIL':
        return [[], DNSSECState.FAILED];
      default:
        throw err;
    }
  }
}

/** True if host equals allowedHost, or is a subdomain of it when domainBoundary is set. */
function hostAllowed(host: string, allowedHost: string, domainBoundary = false): boolean {
  return host === allowedHost || (domainBoundary && host.endsWith(`.${allowedHost}`));
}

/**
 * Agent for protocol fetches (JWKS, entity key set, status). It never caches
 * TLS sessions: on a resumed TLS 1.3 session the server sends no Certificate
 * message and Node's `getPeerCertificate()` returns `{}`, so a verifier that
 * reconnects after an idle keep-alive socket closes (typical of a process
 * that verifies every few seconds) would record an empty certificate and
 * treat the identity evidence as expired. A full handshake on each new
 * connection is the price of always seeing the peer certificate.
 */
const protocolAgent = new https.Agent({ keepAlive: true, maxCachedSessions: 0 });

/**
 * Recursive worker behind {@link fetchJson}: validates the URL against the
 * transport policy, performs the HTTPS GET with an SSRF-safe lookup, follows
 * up to 5 policy-checked HTTPS redirects, enforces the body size limit, and
 * captures the peer certificate. All failures reject with VerificationError.
 */

function fetchWithRedirects(url: string, opts: HTTPSFetchOptions, depth: number): Promise<FetchResult> {
  if (depth > 5) {
    return Promise.reject(new VerificationError('too many redirects', { code: VerificationCode.TLSError }));
  }

  let urlObj: URL;
  try {
    urlObj = new URL(url);
  } catch {
    return Promise.reject(new VerificationError(`invalid URL: ${url}`, { code: VerificationCode.TLSError }));
  }

  if (urlObj.protocol !== 'https:') {
    return Promise.reject(new VerificationError('only HTTPS URLs are permitted', { code: VerificationCode.TLSError }));
  }
  if (opts.allowedHost && !hostAllowed(urlObj.hostname, opts.allowedHost, opts.domainBoundary)) {
    return Promise.reject(new VerificationError(
      `URL host not permitted: expected ${opts.allowedHost}, got ${urlObj.hostname}`,
      { code: VerificationCode.TLSError },
    ));
  }
  if (isUnsafeIp(urlObj.hostname)) {
    return Promise.reject(new VerificationError(`unsafe HTTPS target IP address: ${urlObj.hostname}`, {
      code: VerificationCode.TLSError,
    }));
  }

  return new Promise<FetchResult>((resolve, reject) => {
    const requestOptions: https.RequestOptions = {
      agent: protocolAgent,
      signal: opts.signal,
      rejectUnauthorized: true,
      headers: {
        'User-Agent': DNSID_USER_AGENT,
      },
      lookup: createSsrfSafeLookup(opts.dnsServer, new Set((opts.allowedUnsafeHosts ?? []).map(normalizeAllowedUnsafeHost))),
    };
    if (opts.caBundlePath) requestOptions.ca = [...tls.rootCertificates, fs.readFileSync(opts.caBundlePath, 'utf8')];

    const req = https.get(url, requestOptions, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400) {
        const location = res.headers.location;
        if (!location) {
          res.resume();
          return reject(new VerificationError('redirect with no Location header', { code: VerificationCode.TLSError }));
        }
        let redirectUrl: URL;
        try {
          redirectUrl = new URL(location, url);
        } catch {
          res.resume();
          return reject(new VerificationError(`invalid redirect URL: ${location}`, { code: VerificationCode.TLSError }));
        }
        if (redirectUrl.protocol !== 'https:') {
          res.resume();
          return reject(new VerificationError('redirect to non-HTTPS URL', { code: VerificationCode.TLSError }));
        }
        if (opts.allowedHost && !hostAllowed(redirectUrl.hostname, opts.allowedHost, opts.domainBoundary)) {
          res.resume();
          return reject(new VerificationError(
            `redirect changes host: expected ${opts.allowedHost}, got ${redirectUrl.hostname}`,
            { code: VerificationCode.TLSError },
          ));
        }
        res.resume();
        return fetchWithRedirects(redirectUrl.toString(), opts, depth + 1).then(resolve, reject);
      }

      if (res.statusCode !== 200) {
        res.resume();
        return reject(new VerificationError(
          `unexpected HTTP status ${res.statusCode}`,
          { code: VerificationCode.TLSError, transient: (res.statusCode ?? 0) >= 500 },
        ));
      }

      const socket = res.socket as tls.TLSSocket;
      const peerCert = socket.getPeerCertificate();
      const san: string[] = [];
      if (peerCert.subjectaltname) {
        for (const part of peerCert.subjectaltname.split(', ')) {
          if (part.startsWith('DNS:')) san.push(part.slice(4));
        }
      }
      const tlsCert: TLSCertificate = { notAfter: new Date(peerCert.valid_to), san };

      const maxBodyBytes = opts.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
      const contentLength = Number(res.headers['content-length']);
      if (Number.isFinite(contentLength) && contentLength > maxBodyBytes) {
        res.resume();
        return reject(new VerificationError(
          `response body exceeds ${maxBodyBytes} byte limit`,
          { code: VerificationCode.TLSError },
        ));
      }

      let body = '';
      let bodyBytes = 0;
      let tooLarge = false;
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => {
        if (tooLarge) return;
        bodyBytes += Buffer.byteLength(chunk, 'utf8');
        if (bodyBytes > maxBodyBytes) {
          tooLarge = true;
          req.destroy();
          return reject(new VerificationError(
            `response body exceeds ${maxBodyBytes} byte limit`,
            { code: VerificationCode.TLSError },
          ));
        }
        body += chunk;
      });
      res.on('end', () => {
        try {
          resolve({ data: JSON.parse(body), tlsCert });
        } catch {
          reject(new VerificationError('response body is not valid JSON', { code: VerificationCode.RecordInvalid }));
        }
      });
      res.on('error', (err: Error) => {
        reject(new VerificationError(`response stream error: ${err.message}`, {
          code: VerificationCode.TLSError,
          transient: true,
        }));
      });
    });

    const timeoutMs = opts.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    req.setTimeout(timeoutMs, () => {
      req.destroy();
      reject(new VerificationError(`request timed out after ${timeoutMs}ms`, {
        code: VerificationCode.TLSError,
        transient: true,
      }));
    });

    req.on('error', (err: Error) => {
      const nodeErr = err as NodeJS.ErrnoException;
      const isTls = nodeErr.code === 'DEPTH_ZERO_SELF_SIGNED_CERT'
        || nodeErr.code === 'CERT_HAS_EXPIRED'
        || nodeErr.code === 'ERR_TLS_CERT_ALTNAME_INVALID'
        || nodeErr.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE';
      reject(new VerificationError(`HTTPS fetch failed: ${err.message}`, {
        code: VerificationCode.TLSError,
        transient: !isTls,
      }));
    });
  });
}
