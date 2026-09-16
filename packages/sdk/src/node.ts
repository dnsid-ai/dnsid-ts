/**
 * Node.js conveniences for DNSid — the `@dnsid-ai/sdk/node` subpath.
 *
 * Provides `LocalKeyProvider` (filesystem-backed key storage), `configFromEnvironment`
 * (DNSid config from environment variables), and the {@link createNodeIdentityManager} /
 * {@link createNodeIdentityManagerFromDnsid} factories, which default DNS resolution
 * and HTTPS JSON fetching to the optional `@dnsid-ai/transport` peer.
 * The system resolver reports DNSSEC state `UNKNOWN`; the default `auto` policy accepts
 * and preserves that state, while stricter policies require a DNSSEC-aware resolver.
 *
 * @packageDocumentation
 */
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import type { DNSResolver, DnsidConfig, IdentityConfig, IdentityManagerDependencies, JsonFetcher, KeyProvider, MaxKeyAge, TransportConfig } from '@dnsid-ai/protocol';
import { IdentityManager, ArgumentError, normalizeFQDN, validateDnsidConfig } from '@dnsid-ai/protocol';
import { DEFAULT_REGISTRY_URL } from '@dnsid-ai/registry';

import { LocalKeyProvider } from './local-key-provider.ts';
import { readJson } from './node-fs.ts';
export type { CreateIdentityManagerDependencies } from './index.ts';
export { LocalKeyProvider, keyStorePathFromEnvironment } from './local-key-provider.ts';
export type { LocalKeyAlgorithm, LocalKeyProviderEnvironmentOptions } from './local-key-provider.ts';
export {
  configFromEnvironment,
  dnsidEnvironmentVariables,
} from './environment.ts';
export type {
  ConfigFromEnvironmentOptions,
  DnsidEnvironment,
  EnvironmentConfigResult,
  EnvironmentFieldName,
} from './environment.ts';

/** Explicit inputs for {@link createNodeIdentityManagerFromDnsid}. */
export interface CreateNodeIdentityManagerFromDnsidOptions {
  /** Root DNSid directory containing config.json and <fqdn>/{private,public}.jwk. Defaults to `DNSID_CONFIG_DIR` or ~/.dnsid. */
  dnsidDir?: string;
  /** Environment used to discover DNSID_CONFIG_DIR. Defaults to process.env. */
  env?: Record<string, string | undefined>;
  /**
   * Caller settings. `identity` fields overlay the persisted publication fields before any
   * normalization or derivation; `verification` and `transport` are never read from the CLI files.
   */
  config?: Omit<DnsidConfig, 'identity'> & { identity?: Partial<IdentityConfig> };
}

interface NodeTransportModule {
  fetchJson: JsonFetcherWithNodeOptions;
  createDefaultDnsResolver(config: { dnsServer?: string }): DNSResolver;
}

type JsonFetcherWithNodeOptions = (
  url: string,
  opts?: { allowedHost?: string; maxResponseBytes?: number; dnsServer?: string; caBundlePath?: string; allowedUnsafeHosts?: readonly string[] },
) => ReturnType<JsonFetcher>;

/**
 * Creates an IdentityManager with Node.js DNS and HTTPS defaults.
 *
 * `config.transport` configures only the SDK-managed defaults: `dnsServer` applies to whichever of
 * `dnsResolver`/`fetchJson` is not injected and is rejected when both are; `caBundlePath` and
 * `allowedUnsafeHosts` apply to the default fetcher and are rejected when `fetchJson` is injected. Injected dependencies are never
 * inspected or modified. `@dnsid-ai/transport` is an optional peer; install it or inject both
 * dependencies. The system resolver reports `UNKNOWN`; `validated`/`required` DNSSEC modes need a
 * DNSSEC-aware resolver.
 *
 * @example
 * ```ts
 * import { configFromEnvironment, createNodeIdentityManager, LocalKeyProvider } from '@dnsid-ai/sdk/node';
 *
 * const { config, keyStorePath } = configFromEnvironment();
 * const keyProvider = await LocalKeyProvider.load(keyStorePath ?? '.dnsid/keys.json', true);
 * const idm = await createNodeIdentityManager(config, { keyProvider, entityKeyProvider });
 * ```
 */
export async function createNodeIdentityManager(config: DnsidConfig, deps: IdentityManagerDependencies = {}): Promise<IdentityManager> {
  // Validate everything (including nested lists) before touching the filesystem or network.
  const { transport, ...core } = validateDnsidConfig(config);
  const { dnsServer, caBundlePath, allowedUnsafeHosts } = transport as TransportConfig;
  if (dnsServer !== undefined && deps.dnsResolver && deps.fetchJson) {
    throw new ArgumentError('config.transport.dnsServer has no SDK-managed consumer when both dnsResolver and fetchJson are injected');
  }
  if (caBundlePath !== undefined && deps.fetchJson) {
    throw new ArgumentError('config.transport.caBundlePath has no SDK-managed consumer when fetchJson is injected');
  }
  if (allowedUnsafeHosts !== undefined && deps.fetchJson) {
    throw new ArgumentError('config.transport.allowedUnsafeHosts has no SDK-managed consumer when fetchJson is injected');
  }
  const transportModule = deps.fetchJson && deps.dnsResolver ? null : await loadNodeTransport();
  const fetchJson: JsonFetcher = deps.fetchJson
    ?? ((url, fetchOptions) => transportModule!.fetchJson(url, { ...fetchOptions, dnsServer, caBundlePath, allowedUnsafeHosts }));
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

/**
 * Creates an IdentityManager from a DNSid CLI directory layout (`~/.dnsid` by default).
 *
 * Reads `config.json` (following a `domain` pointer to a per-identity config when present) and
 * maps its publication fields into `config.identity`; caller `options.config.identity` values win
 * and are applied before normalization or `status_url` derivation. Key files are located by the
 * effective domain. Verification and transport settings come only from `options.config`. Supplied
 * `deps.keyProvider`/`deps.entityKeyProvider` win over loaded key files. The result is identical to
 * calling {@link createNodeIdentityManager} with the assembled configuration.
 *
 * @example
 * ```ts
 * import { createNodeIdentityManagerFromDnsid } from '@dnsid-ai/sdk/node';
 *
 * // Reads ~/.dnsid (or DNSID_CONFIG_DIR) for config.json and key files.
 * const idm = await createNodeIdentityManagerFromDnsid();
 * ```
 */
export async function createNodeIdentityManagerFromDnsid(
  options: CreateNodeIdentityManagerFromDnsidOptions = {},
  deps: IdentityManagerDependencies = {},
): Promise<IdentityManager> {
  const dnsidDir = options.dnsidDir ?? options.env?.['DNSID_CONFIG_DIR'] ?? process.env['DNSID_CONFIG_DIR'] ?? path.join(os.homedir(), '.dnsid');
  let configPath = path.join(dnsidDir, 'config.json');
  let raw = await readConfig(configPath);
  const pointerDomain = stringField(raw, 'domain', 'fqdn');
  if (pointerDomain) {
    const identityConfigPath = path.join(dnsidDir, normalizeFQDN(pointerDomain, true), 'config.json');
    try {
      raw = await readJson<Record<string, unknown>>(identityConfigPath);
      configPath = identityConfigPath;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    }
  }
  const field = (...keys: string[]) => stringField(raw, ...keys);
  const loaded: Partial<IdentityConfig> = {
    domain: field('domain', 'fqdn'),
    governanceId: field('governanceId', 'governance_id'),
    logRef: field('logRef', 'log_ref'),
    statusUrl: field('statusUrl', 'status_url'),
    ekUrl: field('ekUrl', 'ek_url'),
    kuUrl: field('kuUrl', 'ku_url'),
    capabilitiesUrl: field('capabilitiesUrl', 'capabilities_url'),
    publishProfile: field('publishProfile', 'publish_profile'),
    maxKeyAge: maxKeyAgeValue(raw.maxKeyAge ?? raw.max_key_age, configPath),
  };
  // Caller values win; omitted caller fields fall back to persisted values. Overlay precedes derivation.
  const identity = { ...definedOnly(loaded), ...definedOnly(options.config?.identity ?? {}) } as Partial<IdentityConfig>;
  if (!identity.domain) throw new Error(`${configPath} must include domain`);
  if (!identity.governanceId) throw new Error(`${configPath} must include governanceId or governance_id`);
  identity.logRef ??= 'noop:0';
  identity.statusUrl ??= protocolStatusUrl(field('registryUrl', 'registry_url', 'server_url') ?? DEFAULT_REGISTRY_URL, identity.domain);

  const keyProvider = deps.keyProvider ?? await LocalKeyProvider.fromDirectory(await identityKeyDir(dnsidDir, identity.domain));
  const entityKeyProvider = deps.entityKeyProvider ?? await optionalEntityKeyProvider(
    path.dirname(configPath),
    field('entityKeyPath', 'entity_key_path'),
    field('entityKeyDir', 'entity_key_dir'),
  );
  return createNodeIdentityManager(
    { identity: identity as IdentityConfig, verification: options.config?.verification, transport: options.config?.transport },
    { ...deps, keyProvider, entityKeyProvider },
  );
}

function definedOnly<T extends object>(value: T): Partial<T> {
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as Partial<T>;
}

async function readConfig(configPath: string): Promise<Record<string, unknown>> {
  return readJson<Record<string, unknown>>(configPath).catch((e: unknown) => {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(`${configPath} not found; run the DNSid CLI to register your domain first`);
    }
    throw e;
  });
}

async function optionalEntityKeyProvider(root: string, file?: string, legacyDir?: string): Promise<KeyProvider | undefined> {
  if (file) {
    return LocalKeyProvider.fromFile(path.isAbsolute(file) ? file : path.resolve(root, file));
  }
  if (!legacyDir) return undefined;
  return LocalKeyProvider.fromDirectory(path.isAbsolute(legacyDir) ? legacyDir : path.resolve(root, legacyDir));
}

async function identityKeyDir(dnsidDir: string, domain: string): Promise<string> {
  for (const filename of ['private.jwk', 'private.pem']) {
    try {
      await fs.access(path.join(dnsidDir, filename));
      return dnsidDir;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    }
  }
  return path.join(dnsidDir, normalizeFQDN(domain, true));
}

function requiredString(raw: Record<string, unknown>, configPath: string, ...keys: string[]): string {
  const value = stringField(raw, ...keys);
  if (value) return value;
  throw new Error(`${configPath} must include ${keys.join(' or ')}`);
}

function stringField(raw: Record<string, unknown>, ...keys: string[]): string | undefined {
  return keys.map(key => raw[key]).find(value => typeof value === 'string' && value !== '') as string | undefined;
}

function maxKeyAgeValue(value: unknown, configPath: string): MaxKeyAge | undefined {
  if (value == null || value === '') return undefined;
  if (['24h', '7d', '30d', '90d'].includes(String(value))) return value as MaxKeyAge;
  throw new Error(`${configPath} has invalid maxKeyAge "${String(value)}"`);
}

function protocolStatusUrl(registryUrl: string, domain: string): string {
  return `${registryUrl.replace(/\/$/, '')}/v1/status/${encodeURIComponent(normalizeFQDN(domain, true))}`;
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
