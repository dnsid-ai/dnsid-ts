import type { DNSResolver, DnsidConfig, IdentityManagerDependencies, JsonFetcher, TransportConfig } from '@dnsid-ai/protocol';
import { IdentityManager, ArgumentError, validateDnsidConfig } from '@dnsid-ai/protocol';

interface NodeTransportModule {
  fetchJson: JsonFetcherWithNodeOptions;
  createDefaultDnsResolver(config: { dnsServer?: string }): DNSResolver;
}

type JsonFetcherWithNodeOptions = (
  url: string,
  opts?: { allowedHost?: string; maxResponseBytes?: number; dnsServer?: string; caBundlePath?: string; privateAddressHosts?: readonly string[] },
) => ReturnType<JsonFetcher>;

/**
 * Creates an IdentityManager with Node.js DNS and HTTPS defaults.
 *
 * `config.transport` configures only the SDK-managed defaults: `dnsServer` applies to whichever of
 * `dnsResolver`/`fetchJson` is not injected and is rejected when both are; `caBundlePath` and
 * `privateAddressHosts` apply to the default fetcher and are rejected when `fetchJson` is injected. Injected dependencies are never
 * inspected or modified. `@dnsid-ai/transport` is an optional peer; install it or inject both
 * dependencies. The system resolver reports `UNKNOWN`; `validated`/`required` DNSSEC modes need a
 * DNSSEC-aware resolver.
 *
 * @example
 * ```ts
 * import { createNodeIdentityManager, LocalKeyProvider } from '@dnsid-ai/sdk/node';
 *
 * const keyProvider = await LocalKeyProvider.load('.dnsid/keys.json', true);
 * const idm = await createNodeIdentityManager({ identity, verification }, { keyProvider, entityKeyProvider });
 * ```
 */
export async function createNodeIdentityManager(config: DnsidConfig, deps: IdentityManagerDependencies = {}): Promise<IdentityManager> {
  // Validate everything (including nested lists) before touching the filesystem or network.
  const { transport, ...core } = validateDnsidConfig(config);
  const { dnsServer, caBundlePath, privateAddressHosts } = transport as TransportConfig;
  if (dnsServer !== undefined && deps.dnsResolver && deps.fetchJson) {
    throw new ArgumentError('config.transport.dnsServer has no SDK-managed consumer when both dnsResolver and fetchJson are injected');
  }
  if (caBundlePath !== undefined && deps.fetchJson) {
    throw new ArgumentError('config.transport.caBundlePath has no SDK-managed consumer when fetchJson is injected');
  }
  if (privateAddressHosts !== undefined && deps.fetchJson) {
    throw new ArgumentError('config.transport.privateAddressHosts has no SDK-managed consumer when fetchJson is injected');
  }
  const transportModule = deps.fetchJson && deps.dnsResolver ? null : await loadNodeTransport();
  const fetchJson: JsonFetcher = deps.fetchJson
    ?? ((url, fetchOptions) => transportModule!.fetchJson(url, { ...fetchOptions, dnsServer, caBundlePath, privateAddressHosts }));
  const dnsResolver = deps.dnsResolver ?? transportModule!.createDefaultDnsResolver({ dnsServer });
  return new IdentityManager(core, { ...deps, dnsResolver, fetchJson });
}

/** Creates a verification-only IdentityManager with Node.js DNS and HTTPS defaults (`config.identity` omitted). */
export async function createNodeIdentityVerifier(
  config: Omit<DnsidConfig, 'identity'> = {},
  deps: Omit<IdentityManagerDependencies, 'keyProvider' | 'entityKeyProvider'> = {},
): Promise<IdentityManager> {
  return createNodeIdentityManager(config, deps);
}

async function loadNodeTransport(): Promise<NodeTransportModule> {
  try {
    return await import('@dnsid-ai/transport') as NodeTransportModule;
  } catch (e) {
    const err = e as NodeJS.ErrnoException & { code?: string };
    if (err.code === 'ERR_MODULE_NOT_FOUND' || err.code === 'MODULE_NOT_FOUND') {
      throw new Error('`@dnsid-ai/sdk/node` HTTPS defaults require optional peer `@dnsid-ai/transport`; install it or inject fetchJson.');
    }
    throw e;
  }
}
