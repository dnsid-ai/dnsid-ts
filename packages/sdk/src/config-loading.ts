/**
 * Configuration loading (design 12): loaders parse, constructors default.
 *
 * Each loader returns only the fields present in its source. Nothing here defaults, derives,
 * or reads a second source; {@link constructIdentityManager} hands the merged result to the
 * ordinary constructors, which apply every default and validation.
 */
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  ArgumentError,
  DNSSECMode,
  normalizeFQDN,
  parseJsonNoDuplicateMembers,
  validateDnsidConfig,
  type DnsidConfig,
  type IdentityConfig,
  type IdentityManagerDependencies,
  type KeyProvider,
  type LogRegistry,
  type TransportConfig,
} from '@dnsid-ai/protocol';
import {
  createC2spTlogVerificationRegistry,
  createDnsidManagedVerificationRegistry,
  parseC2spTlogTrustProfile,
} from '@dnsid-ai/log-c2sp-tlog';
import { RegistryClient } from '@dnsid-ai/registry';

import { LocalKeyProvider } from './local-key-provider.ts';
import { createNodeIdentityManager } from './node-identity-manager.ts';

export type EnvironmentSource = Readonly<Record<string, string | undefined>>;

/** Log trust for `deps.logRegistry`; exactly one variant is required at construction. */
export interface LogTrust {
  /** `true` selects the embedded DNSid-managed catalog. */
  managed?: boolean;
  /** `dnsid-c2sp-tlog-trust-profile@v1` document (parsed JSON). */
  profile?: Record<string, unknown>;
  /** Trusted C2SP `tlog-policy` bytes. */
  policyDocument?: Uint8Array;
  /** Trusted C2SP `tlog-policy` HTTPS URL. */
  policyUrl?: string;
}

export interface KeySource {
  /** DNSid CLI identity directory; key files are located under the effective identity domain. */
  cliDirectory?: string;
  /** Accountable-entity private JWK file. */
  entityKeyPath?: string;
  /** `LocalKeyProvider` key-store file; used only when `cliDirectory` is absent. */
  keyStorePath?: string;
}

export interface LoadedRegistryConfig {
  registryUrl?: string;
}

/** `DnsidConfig` with a partial `identity`: sources may supply some publication fields and leave the rest to an overlay. */
export interface LoadedDnsidConfig extends Omit<DnsidConfig, 'identity'> {
  identity?: Partial<IdentityConfig>;
}

/** Partial configuration from one source. Every field is present only when sourced. */
export interface LoadedConfig {
  dnsid?: LoadedDnsidConfig;
  logTrust?: LogTrust;
  registry?: LoadedRegistryConfig;
  keySource?: KeySource;
}

// ---------------------------------------------------------------------------------------------
// Environment

const IDENTITY_VARIABLES: Record<string, keyof IdentityConfig> = {
  DNSID_DOMAIN: 'domain',
  DNSID_GOVERNANCE_ID: 'governanceId',
  DNSID_STATUS_URL: 'statusUrl',
  DNSID_LOG_REF: 'logRef',
  DNSID_EK_URL: 'ekUrl',
  DNSID_KU_URL: 'kuUrl',
  DNSID_PUBLISH_PROFILE: 'publishProfile',
  DNSID_CAPABILITIES_URL: 'capabilitiesUrl',
};

/** Reads configuration from `DNSID_*`. Secrets such as `DNSID_API_KEY` stay out of `LoadedConfig`. */
export async function loadEnvironment(env: EnvironmentSource = process.env): Promise<LoadedConfig> {
  const get = (name: string): string | undefined => {
    const value = env[name]?.trim();
    return value ? value : undefined;
  };

  const identity = compact(Object.fromEntries(
    Object.entries(IDENTITY_VARIABLES).map(([variable, field]) => [field, get(variable)]),
  ));
  const dnssecMode = get('DNSID_DNSSEC_MODE');
  if (dnssecMode !== undefined && !Object.values(DNSSECMode).includes(dnssecMode as DNSSECMode)) {
    throw new ArgumentError(`invalid DNSID_DNSSEC_MODE "${dnssecMode}"; expected one of: ${Object.values(DNSSECMode).join(', ')}`);
  }
  const hosts = get('DNSID_PRIVATE_HOSTS')?.split(',').map(h => h.trim()).filter(Boolean);
  const dnsid = compact({
    identity,
    verification: compact({ dnssecMode: dnssecMode as DNSSECMode | undefined }),
    transport: compact({
      dnsServer: get('DNSID_DNS_SERVER'),
      caBundlePath: get('DNSID_CA_BUNDLE'),
      privateAddressHosts: hosts?.length ? hosts : undefined,
    }),
  });

  const policyFile = get('DNSID_LOG_POLICY_FILE');
  const profileFile = get('DNSID_LOG_TRUST_PROFILE_FILE');
  const logTrust = compact({
    policyUrl: get('DNSID_LOG_POLICY_URL'),
    policyDocument: policyFile === undefined ? undefined : new Uint8Array(await fs.readFile(policyFile)),
    profile: profileFile === undefined ? undefined : jsonObject(await fs.readFile(profileFile), profileFile),
  });

  return top({
    dnsid,
    logTrust,
    registry: compact({ registryUrl: get('DNSID_REGISTRY_URL') }),
    keySource: compact({ cliDirectory: get('DNSID_CONFIG_DIR'), keyStorePath: get('DNSID_KEY_STORE') }),
  });
}

// ---------------------------------------------------------------------------------------------
// Deployment file

/**
 * Reads a JSON deployment file: `{ dnsid?, logTrust?, registry? }`. Unknown members, mistyped
 * values, and duplicate members are rejected; `dnsid` contents are validated by the constructor.
 */
export async function loadFile(filePath: string): Promise<LoadedConfig> {
  const root = jsonObject(await fs.readFile(filePath), filePath);
  rejectUnknown(root, filePath, ['dnsid', 'logTrust', 'registry']);
  const loaded: LoadedConfig = {};
  if (root.dnsid !== undefined) loaded.dnsid = object(root.dnsid, `${filePath}: dnsid`) as LoadedDnsidConfig;
  if (root.logTrust !== undefined) {
    const trust = object(root.logTrust, `${filePath}: logTrust`);
    rejectUnknown(trust, `${filePath}: logTrust`, ['managed', 'profile', 'policyUrl']);
    loaded.logTrust = compact({
      managed: optional(trust, 'managed', 'boolean', `${filePath}: logTrust`),
      profile: trust.profile === undefined ? undefined : object(trust.profile, `${filePath}: logTrust.profile`),
      policyUrl: optional(trust, 'policyUrl', 'string', `${filePath}: logTrust`),
    });
  }
  if (root.registry !== undefined) {
    const registry = object(root.registry, `${filePath}: registry`);
    rejectUnknown(registry, `${filePath}: registry`, ['registryUrl']);
    loaded.registry = compact({ registryUrl: optional(registry, 'registryUrl', 'string', `${filePath}: registry`) });
  }
  return loaded;
}

// ---------------------------------------------------------------------------------------------
// DNSid CLI directory

const CLI_IDENTITY_FIELDS: Record<string, keyof IdentityConfig> = {
  domain: 'domain',
  governance_id: 'governanceId',
  status_url: 'statusUrl',
  log_ref: 'logRef',
  ek_url: 'ekUrl',
  ku_url: 'kuUrl',
  capabilities_url: 'capabilitiesUrl',
  publish_profile: 'publishProfile',
  max_key_age: 'maxKeyAge',
};

/**
 * Reads a DNSid CLI directory (`~/.dnsid` by default): `config.json`, following a root `domain`
 * pointer to `<domain>/config.json` when that file exists. Maps the snake_case publication fields
 * into `dnsid.identity` and records the directory (and resolved `entity_key_path`) as `keySource`.
 * Never consults `DNSID_CONFIG_DIR`.
 */
export async function loadCliDirectory(dnsidDir = path.join(os.homedir(), '.dnsid')): Promise<LoadedConfig> {
  let configPath = path.join(dnsidDir, 'config.json');
  let raw: Record<string, unknown>;
  try {
    raw = jsonObject(await fs.readFile(configPath), configPath);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    throw new Error(`${configPath} not found; run the DNSid CLI to register your domain first`);
  }
  if (typeof raw.domain === 'string' && raw.domain !== '') {
    const identityConfigPath = path.join(dnsidDir, normalizeFQDN(raw.domain, true), 'config.json');
    try {
      raw = jsonObject(await fs.readFile(identityConfigPath), identityConfigPath);
      configPath = identityConfigPath;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    }
  }
  const str = (key: string) => optional(raw, key, 'string', configPath) || undefined; // empty is absent
  const identity = compact(Object.fromEntries(
    Object.entries(CLI_IDENTITY_FIELDS).map(([key, field]) => [field, str(key)]),
  ));
  const entityKeyPath = str('entity_key_path');
  return top({
    dnsid: compact({ identity }),
    keySource: compact({
      cliDirectory: dnsidDir,
      entityKeyPath: entityKeyPath === undefined ? undefined : path.resolve(path.dirname(configPath), entityKeyPath),
    }),
  });
}

// ---------------------------------------------------------------------------------------------
// Merge

/**
 * Field-wise merge; presence wins, not truthiness. Lists replace. `logTrust` is replaced as a
 * whole section when `overlay` sets any variant.
 */
export function mergeLoadedConfig(base: LoadedConfig, overlay: LoadedConfig): LoadedConfig {
  return top({
    dnsid: mergeDnsid(base.dnsid, overlay.dnsid),
    logTrust: overlay.logTrust ?? base.logTrust,
    registry: mergeSection(base.registry, overlay.registry),
    keySource: mergeSection(base.keySource, overlay.keySource),
  });
}

function mergeDnsid(base?: LoadedDnsidConfig, overlay?: LoadedDnsidConfig): LoadedDnsidConfig | undefined {
  if (!base || !overlay) return overlay ?? base;
  return compact({
    identity: mergeSection(base.identity, overlay.identity),
    verification: mergeSection(base.verification, overlay.verification),
    transport: mergeSection(base.transport, overlay.transport),
  });
}

function mergeSection<T extends object>(base?: T, overlay?: T): T | undefined {
  if (!base || !overlay) return overlay ?? base;
  return { ...base, ...definedEntries(overlay) };
}

// ---------------------------------------------------------------------------------------------
// Construction

const MANAGED_DEFAULTS_MS = 10 * 60 * 1000;

/**
 * Fills `deps.logRegistry` from `logTrust` and key providers from `keySource` only when the caller
 * did not supply them, then calls {@link createNodeIdentityManager}. Adds no configuration values.
 */
export async function constructIdentityManager(loaded: LoadedConfig, deps: IdentityManagerDependencies = {}) {
  validateDnsidConfig(loaded.dnsid ?? {}); // surface config errors before touching key files or policy URLs
  const filled = { ...deps };
  if (!filled.logRegistry && loaded.logTrust) {
    filled.logRegistry = await logRegistryFromTrust(loaded.logTrust, loaded.dnsid?.transport);
  }
  const identity = loaded.dnsid?.identity;
  if (identity && loaded.keySource) {
    if (!filled.keyProvider) filled.keyProvider = await operationalKeyProvider(loaded.keySource, identity.domain!);
    if (!filled.entityKeyProvider && loaded.keySource.entityKeyPath !== undefined) {
      filled.entityKeyProvider = await LocalKeyProvider.fromFile(loaded.keySource.entityKeyPath);
    }
  }
  return createNodeIdentityManager((loaded.dnsid ?? {}) as DnsidConfig, filled);
}

async function logRegistryFromTrust(trust: LogTrust, transport: TransportConfig | undefined): Promise<LogRegistry> {
  const variants = (['managed', 'profile', 'policyDocument', 'policyUrl'] as const).filter(k => trust[k] !== undefined);
  if (variants.length !== 1) {
    throw new ArgumentError(`logTrust requires exactly one of managed, profile, policyDocument, policyUrl; got ${variants.length}`);
  }
  if (trust.managed !== undefined) {
    if (trust.managed !== true) throw new ArgumentError('logTrust.managed must be true when present');
    return createDnsidManagedVerificationRegistry();
  }
  return createC2spTlogVerificationRegistry({
    trustProfile: trust.profile && parseC2spTlogTrustProfile(new TextEncoder().encode(JSON.stringify(trust.profile))),
    policyDocument: trust.policyDocument,
    policyUrl: trust.policyUrl,
    transport,
    checkpointMaxAge: MANAGED_DEFAULTS_MS,
    maxBundleLifetimeMs: trust.profile ? MANAGED_DEFAULTS_MS : undefined,
    allowedClockSkew: 0,
  });
}

/** `cliDirectory` wins over `keyStorePath`; neither leaves `deps.keyProvider` absent for the constructor to reject. */
async function operationalKeyProvider(source: KeySource, domain: string): Promise<KeyProvider | undefined> {
  if (source.cliDirectory !== undefined) {
    return LocalKeyProvider.fromDirectory(await identityKeyDir(source.cliDirectory, domain));
  }
  if (source.keyStorePath !== undefined) return LocalKeyProvider.load(source.keyStorePath);
  return undefined;
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

// ---------------------------------------------------------------------------------------------
// Convenience constructors: Load → Merge → Construct, nothing else.

export function createNodeIdentityManagerFromEnvironment(env?: EnvironmentSource, overlay?: LoadedDnsidConfig, deps?: IdentityManagerDependencies) {
  return loadEnvironment(env).then(loaded => constructIdentityManager(mergeLoadedConfig(loaded, top({ dnsid: overlay })), deps));
}

export function createNodeIdentityManagerFromDnsid(dnsidDir?: string, overlay?: LoadedDnsidConfig, deps?: IdentityManagerDependencies) {
  return loadCliDirectory(dnsidDir).then(loaded => constructIdentityManager(mergeLoadedConfig(loaded, top({ dnsid: overlay })), deps));
}

export function createNodeIdentityManagerFromFile(filePath: string, overlay?: LoadedDnsidConfig, deps?: IdentityManagerDependencies) {
  return loadFile(filePath).then(loaded => constructIdentityManager(mergeLoadedConfig(loaded, top({ dnsid: overlay })), deps));
}

/** `RegistryClient` from `DNSID_REGISTRY_URL` and `DNSID_API_KEY`; the constructor defaults to the local registry. */
export async function createRegistryClientFromEnvironment(env?: EnvironmentSource): Promise<RegistryClient> {
  const source = env ?? process.env;
  const loaded = await loadEnvironment(source);
  return new RegistryClient(compact({ baseUrl: loaded.registry?.registryUrl, token: source.DNSID_API_KEY?.trim() || undefined }));
}

// ---------------------------------------------------------------------------------------------

function definedEntries<T extends object>(value: T): Partial<T> {
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as Partial<T>;
}

function top(value: { [K in keyof LoadedConfig]: unknown }): LoadedConfig {
  return definedEntries(value) as LoadedConfig;
}

/** Drops undefined fields; returns undefined when nothing remains so absent sections stay absent. */
function compact<T extends object>(value: T): T | undefined {
  const defined = definedEntries(value);
  return Object.keys(defined).length > 0 ? defined as T : undefined;
}

function jsonObject(bytes: Uint8Array, source: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = parseJsonNoDuplicateMembers(bytes);
  } catch (e) {
    throw new ArgumentError(`${source}: ${(e as Error).message}`);
  }
  return object(value, source);
}

function object(value: unknown, source: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ArgumentError(`${source} must be a JSON object`);
  return value as Record<string, unknown>;
}

function rejectUnknown(raw: Record<string, unknown>, source: string, allowed: string[]): void {
  for (const key of Object.keys(raw)) {
    if (!allowed.includes(key)) throw new ArgumentError(`${source} has unknown member "${key}"`);
  }
}

function optional<K extends 'string' | 'boolean'>(
  raw: Record<string, unknown>,
  key: string,
  type: K,
  source: string,
): (K extends 'string' ? string : boolean) | undefined {
  const value = raw[key];
  if (value === undefined) return undefined;
  if (typeof value !== type) throw new ArgumentError(`${source}.${key} must be a ${type}`);
  return value as never;
}
