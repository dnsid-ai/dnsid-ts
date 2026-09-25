import { ArgumentError, LogRegistry } from '@dnsid-ai/protocol';
import { InMemoryTrustedC2spCheckpointStore, type TrustedC2spCheckpointStore } from './checkpoint-trust.ts';
import { C2spTlogParseError } from './errors.ts';
import { parseC2spTlogLr } from './lr.ts';
import {
  createDefaultC2spBoundedResourceFetcher,
  type C2spBoundedResourceFetcher,
} from './stream-source.ts';
import { parseC2spTlogTrustProfile } from './trust-profile.ts';
import { createC2spTlogVerificationRegistry } from './verification-registry.ts';

const TEN_MINUTES_MS = 10 * 60 * 1000;
const DEVELOPMENT_TRUST_PROFILE = new TextEncoder().encode(`{
  "version": 1,
  "scope": "public",
  "log_prefix": "https://log.dev.dnsid.ai",
  "tlog_policy": "log log.dev.dnsid.ai+cad12acd+Afnd3sdzfp8nCXzDQchrnWn9QOox5AglR147bURESRqu\\nwitness dnsid-witness-1 witness.dev.dnsid.ai/w1+50822ded+BAH9KuulelD3yZBDTneG46gKZY+OWwdUPBmLmq/YjOkO\\nquorum dnsid-witness-1\\n",
  "bundle_verifier_keys": [
    "dnsid-stream-bundle+0c241174+AeuT9PKyiewb9hkzygvki7UuOs5ly2kfY/C4Tfh7/ix0"
  ]
}`);
const PRODUCTION_TRUST_PROFILE = new TextEncoder().encode(`{
  "version": 1,
  "scope": "public",
  "log_prefix": "https://log.dnsid.ai",
  "tlog_policy": "log log.dnsid.ai+c4683585+AWZYC4OLE9KeRnpaI9xaHWwHUKoxgp/24ukzgVYlDwIt\\nwitness dnsid-witness-1 witness.dnsid.ai/w1+b5ea211e+BH0nGTkjF4tYpkefsQhHNg0YagPvQ6H96Y3UBbXo7a/b\\nquorum dnsid-witness-1\\n",
  "bundle_verifier_keys": [
    "dnsid-stream-bundle+ee2b26d2+AWGLBe4LhJKumyDpH8VJ0vyATB081i1HseVeETu4TONR"
  ]
}`);

const MANAGED_CATALOG = [
  { scope: 'public', logPrefix: 'https://log.dev.dnsid.ai', trustProfileDocument: DEVELOPMENT_TRUST_PROFILE },
  { scope: 'public', logPrefix: 'https://log.dnsid.ai', trustProfileDocument: PRODUCTION_TRUST_PROFILE },
] as const;

/** Shared infrastructure for {@link createDnsidManagedVerificationRegistry}. */
export interface DnsidManagedVerificationOptions {
  /** Bounded transport shared by every managed log reader. */
  resourceFetcher?: C2spBoundedResourceFetcher;
  /** Persistence shared by every managed log reader. The default is restart-ephemeral. */
  trustedCheckpointStore?: TrustedC2spCheckpointStore;
  /** Cancels reads made by readers from this registry. */
  signal?: AbortSignal;
}

/**
 * Creates a registry for the reviewed trust roots of DNSid-managed
 * DNSid logs. Calling this separately named factory is an explicit application
 * trust decision; the generic factory never selects these roots implicitly.
 *
 * Trust snapshots are bundled with the SDK and selected only after parsing an
 * exact canonical `(scope, logPrefix)` pair. Managed verification prefers
 * signed stream bundles with safe raw-scan fallback.
 */
export async function createDnsidManagedVerificationRegistry(
  options: DnsidManagedVerificationOptions = {},
): Promise<LogRegistry> {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new ArgumentError('DNSid managed verification options must be an object');
  }
  const resourceFetcher = options.resourceFetcher ?? createDefaultC2spBoundedResourceFetcher();
  const trustedCheckpointStore = options.trustedCheckpointStore ?? new InMemoryTrustedC2spCheckpointStore();
  const readers = new Map<string, LogRegistry>();

  for (const entry of MANAGED_CATALOG) {
    const catalogReference = parseC2spTlogLr(`c2sp-tlog:${entry.scope}:${entry.logPrefix}#catalog`);
    const key = selector(catalogReference.scope, catalogReference.logPrefix);
    if (readers.has(key)) throw new C2spTlogParseError('duplicate DNSid managed trust selector');

    const trustProfile = parseC2spTlogTrustProfile(entry.trustProfileDocument);
    if (trustProfile.scope !== entry.scope || trustProfile.logPrefix !== entry.logPrefix) {
      throw new C2spTlogParseError('DNSid managed trust profile selector mismatch');
    }
    readers.set(key, await createC2spTlogVerificationRegistry({
      trustProfile,
      resourceFetcher,
      trustedCheckpointStore,
      checkpointMaxAge: TEN_MINUTES_MS,
      maxBundleLifetimeMs: TEN_MINUTES_MS,
      allowedClockSkew: 0,
      signal: options.signal,
    }));
  }

  const registry = new LogRegistry();
  registry.register('c2sp-tlog', (lr, invocation) => {
    const reference = parseC2spTlogLr(lr);
    const selected = readers.get(selector(reference.scope, reference.logPrefix));
    if (!selected) throw new C2spTlogParseError('unknown DNSid managed trust selector');
    return selected.newReader(lr, invocation);
  });
  return registry;
}

function selector(scope: string, logPrefix: string): string {
  return `${scope}\0${logPrefix}`;
}
