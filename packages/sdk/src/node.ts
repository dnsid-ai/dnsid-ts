/**
 * Node.js conveniences for DNSid — the `@dnsid-ai/sdk/node` subpath.
 *
 * Provides `LocalKeyProvider` (filesystem-backed key storage), the configuration loaders
 * (`loadEnvironment`, `loadFile`, `loadCliDirectory` → `mergeLoadedConfig` → `constructIdentityManager`),
 * the one-call {@link createNodeIdentityManagerFromEnvironment} / {@link createNodeIdentityManagerFromDnsid} /
 * {@link createNodeIdentityManagerFromFile} constructors, and {@link createNodeIdentityManager}, which
 * defaults DNS resolution and HTTPS JSON fetching to the optional `@dnsid-ai/transport` peer.
 * Loaders parse; constructors default. No constructor reads the environment or files.
 * The system resolver reports DNSSEC state `UNKNOWN`; the default `auto` policy accepts
 * and preserves that state, while stricter policies require a DNSSEC-aware resolver.
 *
 * @packageDocumentation
 */
export type { CreateIdentityManagerDependencies } from './index.ts';
export { LocalKeyProvider } from './local-key-provider.ts';
export type { LocalKeyAlgorithm } from './local-key-provider.ts';
export { createNodeIdentityManager, createNodeIdentityVerifier } from './node-identity-manager.ts';
export {
  loadEnvironment,
  loadFile,
  loadCliDirectory,
  mergeLoadedConfig,
  constructIdentityManager,
  createNodeIdentityManagerFromEnvironment,
  createNodeIdentityManagerFromDnsid,
  createNodeIdentityManagerFromFile,
  createRegistryClientFromEnvironment,
} from './config-loading.ts';
export type { EnvironmentSource, KeySource, LoadedConfig, LoadedDnsidConfig, LoadedRegistryConfig, LogTrust } from './config-loading.ts';
