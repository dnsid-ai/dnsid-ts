import { ArgumentError, LogRegistry, VerificationError } from '@identity-digital/dnsid-protocol';
import { InMemoryTrustedC2spCheckpointStore, type TrustedC2spCheckpointStore } from './checkpoint-trust.ts';
import { C2spTlogError, C2spTlogParseError } from './errors.ts';
import { normalizedOriginPolicy, parseC2spPolicyFile } from './policy.ts';
import { C2spTlogReader } from './reader.ts';
import { parseC2spTlogLr } from './lr.ts';
import type { SignedNoteKey } from './signed-note.ts';
import { validateC2spBundleVerifierKeys, validateC2spTlogTrustProfile, type C2spTlogTrustProfile } from './trust-profile.ts';
import {
  createDefaultC2spBoundedResourceFetcher,
  DEFAULT_C2SP_MAX_CHECKPOINT_BYTES,
  DEFAULT_C2SP_MAX_ENTRY_BUNDLE_BYTES,
  DEFAULT_C2SP_MAX_TOTAL_ENTRY_BYTES,
  DEFAULT_C2SP_MAX_TREE_SIZE,
  DEFAULT_C2SP_REQUEST_TIMEOUT_MS,
  validateC2spResourceFetcher,
  type C2spBoundedResourceFetcher,
} from './stream-source.ts';

const DEFAULT_MAX_POLICY_BYTES = 1_048_576;

/** Resource limits for the complete standard tlog-tiles scan. Bundle geometry is fixed at 256 entries. */
export interface C2spScanLimits {
  /** Maximum accepted checkpoint tree size (default 1,000,000). */
  maxTreeSize?: number;
  /** Maximum checkpoint response size in bytes (default 1,048,576). */
  maxCheckpointBytes?: number;
  /** Maximum size of one entry-bundle response (default exactly 16,777,472 bytes). */
  maxEntryBundleBytes?: number;
  /** Maximum combined size of all entry bundles (default 268,435,456 bytes). */
  maxTotalEntryBytes?: number;
}

/**
 * Options for {@link createC2spTlogVerificationRegistry}. Exactly one of
 * `trustProfile`, `policyDocument`, and `policyUrl` is required.
 */
export interface C2spTlogVerificationOptions {
  /** Independently distributed trust profile for one exact log. */
  trustProfile?: C2spTlogTrustProfile;
  /** Independently trusted C2SP `tlog-policy` bytes, parsed locally. */
  policyDocument?: Uint8Array;
  /** Independently trusted absolute HTTPS URL of a C2SP `tlog-policy` document. */
  policyUrl?: string;
  /** Bounded transport used for both policy and standard log resources. */
  resourceFetcher?: C2spBoundedResourceFetcher;
  /** Optional overrides for the built-in complete scanner's secure limits. */
  scanLimits?: C2spScanLimits;
  /** Independently trusted stream-bundle signer keys. Mutually exclusive with `trustProfile`. */
  bundleVerifierKeys?: SignedNoteKey[];
  /** Maximum bundle expiry distance from its witnessed checkpoint. Required with bundle verifier keys. */
  maxBundleLifetimeMs?: number;
  /** Maximum decoded stream-bundle response size (default 8 MiB). */
  maxStreamBundleBytes?: number;
  /** Maximum lifecycle events in one stream bundle (default 10,000). */
  maxStreamBundleEvents?: number;
  /** Fail instead of using the bounded raw scanner when the bundle endpoint is unavailable. */
  requireStreamBundle?: boolean;
  /**
   * Maximum accepted checkpoint age in milliseconds for fresh logged-state and
   * non-revocation checks. Omission intentionally makes those operations fail closed.
   */
  checkpointMaxAge?: number;
  /** Accepted timestamp clock skew in milliseconds (default zero). */
  allowedClockSkew?: number;
  /** Persistence for accepted checkpoints. The default is process-lifetime only. */
  trustedCheckpointStore?: TrustedC2spCheckpointStore;
  /** Maximum policy size in bytes (default 1,048,576). */
  maxPolicyBytes?: number;
  /** Finite timeout for each policy/log resource request (default 10 seconds). */
  requestTimeoutMs?: number;
  /** Cancels policy retrieval and later reads made by readers from this registry. */
  signal?: AbortSignal;
}

/**
 * Creates a {@link LogRegistry} ready to verify `c2sp-tlog` lifecycle
 * references. Trust policy is explicit and never inferred from an identity
 * record, its `lr`, or the log prefix.
 *
 * The default resource fetcher rejects unsafe destinations and redirects,
 * connects through the validated DNS result, requires HTTP 200, bounds decoded
 * bodies while reading, and applies finite request deadlines. The default
 * checkpoint store is restart-ephemeral; inject durable storage when rollback
 * protection must survive process restarts.
 */
export async function createC2spTlogVerificationRegistry(
  options: C2spTlogVerificationOptions,
): Promise<LogRegistry> {
  if (!options || typeof options !== 'object') throw new ArgumentError('C2SP tlog verification options are required');
  const hasProfile = options.trustProfile !== undefined;
  const hasDocument = options.policyDocument !== undefined;
  const hasUrl = options.policyUrl !== undefined;
  if (Number(hasProfile) + Number(hasDocument) + Number(hasUrl) !== 1) {
    throw new ArgumentError('exactly one C2SP tlog trust profile, policy document, or URL is required');
  }
  if (hasProfile) validateC2spTlogTrustProfile(options.trustProfile!);
  if (hasProfile && options.bundleVerifierKeys !== undefined) {
    throw new ArgumentError('trustProfile is mutually exclusive with direct bundleVerifierKeys');
  }
  if (options.bundleVerifierKeys !== undefined) validateDirectBundleVerifierKeys(options.bundleVerifierKeys);
  const bundleVerifierKeys = options.trustProfile?.bundleVerifierKeys ?? options.bundleVerifierKeys ?? [];
  const hasBundleTrust = bundleVerifierKeys.length > 0;

  const maximum = positiveInteger(options.maxPolicyBytes ?? DEFAULT_MAX_POLICY_BYTES, 'maxPolicyBytes');
  const checkpointMaxAge = optionalPositiveInteger(options.checkpointMaxAge, 'checkpointMaxAge');
  const maxBundleLifetimeMs = optionalPositiveInteger(options.maxBundleLifetimeMs, 'maxBundleLifetimeMs');
  const maxStreamBundleBytes = optionalPositiveInteger(options.maxStreamBundleBytes, 'maxStreamBundleBytes');
  const maxStreamBundleEvents = optionalPositiveInteger(options.maxStreamBundleEvents, 'maxStreamBundleEvents');
  if (hasBundleTrust && maxBundleLifetimeMs === undefined) {
    throw new ArgumentError('bundle verifier keys require positive maxBundleLifetimeMs for stream-bundle verification');
  }
  if (!hasBundleTrust && (options.maxBundleLifetimeMs !== undefined || options.maxStreamBundleBytes !== undefined
    || options.maxStreamBundleEvents !== undefined || options.requireStreamBundle !== undefined)) {
    throw new ArgumentError('stream-bundle options require trusted bundle verifier keys');
  }
  const allowedClockSkew = nonNegativeInteger(options.allowedClockSkew ?? 0, 'allowedClockSkew');
  const requestTimeoutMs = positiveInteger(options.requestTimeoutMs ?? DEFAULT_C2SP_REQUEST_TIMEOUT_MS, 'requestTimeoutMs');
  const limits = validatedLimits(options.scanLimits);
  const policyUrl = hasUrl ? validatePolicyUrl(options.policyUrl!) : undefined;

  const resourceFetcher = options.resourceFetcher ?? createDefaultC2spBoundedResourceFetcher();
  try {
    validateC2spResourceFetcher(resourceFetcher);
  } catch (cause) {
    throw new ArgumentError(cause instanceof Error ? cause.message : String(cause));
  }

  let document: Uint8Array;
  if (options.trustProfile !== undefined) {
    document = boundedPolicy(options.trustProfile.policyDocument, maximum);
  } else if (options.policyDocument !== undefined) {
    if (!(options.policyDocument instanceof Uint8Array)) throw new ArgumentError('policyDocument must be a Uint8Array');
    document = boundedPolicy(options.policyDocument, maximum);
  } else {
    try {
      document = await resourceFetcher.fetchBounded(policyUrl!, maximum, {
        signal: options.signal,
        timeoutMs: requestTimeoutMs,
      });
    } catch (cause) {
      if (cause instanceof VerificationError) throw cause;
      throw new C2spTlogError(`failed to fetch C2SP tlog policy ${policyUrl}`, { cause, transient: true });
    }
    if (!(document instanceof Uint8Array)) throw new C2spTlogParseError('C2SP policy resource fetcher returned a non-byte response');
    document = boundedPolicy(document, maximum);
  }

  const policy = parseC2spPolicyDocument(document);
  if (options.bundleVerifierKeys?.length) {
    const checkpointKeys = Object.keys(policy.origins).flatMap((origin) => {
      const originPolicy = normalizedOriginPolicy(policy, origin);
      return [...originPolicy.logKeys, ...originPolicy.witnessKeys];
    });
    validateDirectBundleVerifierKeys(bundleVerifierKeys, checkpointKeys);
  }
  const trustedCheckpointStore = options.trustedCheckpointStore
    ?? new InMemoryTrustedC2spCheckpointStore();
  const trustedScope = options.trustProfile?.scope;
  const trustedLogPrefix = options.trustProfile?.logPrefix;

  const registry = new LogRegistry();
  registry.register('c2sp-tlog', (lr, invocation) => {
    if (trustedScope !== undefined) {
      const reference = parseC2spTlogLr(lr);
      if (reference.scope !== trustedScope || reference.logPrefix !== trustedLogPrefix) {
        throw new C2spTlogParseError('C2SP tlog reference is not accepted by the trust profile');
      }
    }
    return new C2spTlogReader(lr, {
      policy,
      resourceFetcher,
      trustedCheckpointStore,
      maxTreeSize: limits.maxTreeSize,
      maxCheckpointBytes: limits.maxCheckpointBytes,
      maxEntryBundleBytes: limits.maxEntryBundleBytes,
      maxTotalEntryBytes: limits.maxTotalEntryBytes,
      checkpointMaxAge,
      allowedClockSkew,
      requestTimeoutMs,
      signal: invocation?.signal && options.signal ? AbortSignal.any([invocation.signal, options.signal]) : invocation?.signal ?? options.signal,
      streamBundle: hasBundleTrust ? {
        policyDocument: document,
        bundleKeys: bundleVerifierKeys,
        maxBundleLifetimeMs: maxBundleLifetimeMs!,
        checkpointFreshnessMs: checkpointMaxAge ?? maxBundleLifetimeMs!,
        maxBundleBytes: maxStreamBundleBytes,
        maxEvents: maxStreamBundleEvents,
        required: options.requireStreamBundle,
      } : undefined,
    });
  });
  return registry;
}

function validateDirectBundleVerifierKeys(keys: SignedNoteKey[], checkpointKeys?: SignedNoteKey[]): void {
  try {
    validateC2spBundleVerifierKeys(keys, checkpointKeys);
  } catch (cause) {
    throw new ArgumentError(`invalid bundleVerifierKeys: ${cause instanceof Error ? cause.message : String(cause)}`);
  }
}

function parseC2spPolicyDocument(document: Uint8Array): ReturnType<typeof parseC2spPolicyFile> {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(document);
  } catch (cause) {
    throw new C2spTlogParseError('C2SP policy document must be valid UTF-8', cause);
  }
  return parseC2spPolicyFile(text);
}

function validatePolicyUrl(rawUrl: string): string {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch (cause) {
    throw new ArgumentError(`invalid C2SP tlog policy URL: ${(cause as Error).message}`);
  }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.hash) {
    throw new ArgumentError('C2SP tlog policy URL must be an absolute HTTPS URL without userinfo or fragment');
  }
  return url.toString();
}

function validatedLimits(limits: C2spScanLimits = {}): Required<C2spScanLimits> {
  return {
    maxTreeSize: positiveInteger(limits.maxTreeSize ?? DEFAULT_C2SP_MAX_TREE_SIZE, 'scanLimits.maxTreeSize'),
    maxCheckpointBytes: positiveInteger(limits.maxCheckpointBytes ?? DEFAULT_C2SP_MAX_CHECKPOINT_BYTES, 'scanLimits.maxCheckpointBytes'),
    maxEntryBundleBytes: positiveInteger(limits.maxEntryBundleBytes ?? DEFAULT_C2SP_MAX_ENTRY_BUNDLE_BYTES, 'scanLimits.maxEntryBundleBytes'),
    maxTotalEntryBytes: positiveInteger(limits.maxTotalEntryBytes ?? DEFAULT_C2SP_MAX_TOTAL_ENTRY_BYTES, 'scanLimits.maxTotalEntryBytes'),
  };
}

function boundedPolicy(document: Uint8Array, maximum: number): Uint8Array {
  if (document.length > maximum) throw new C2spTlogParseError(`C2SP tlog policy exceeds configured byte maximum ${maximum}`);
  return document;
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new ArgumentError(`${name} must be a positive safe integer`);
  return value;
}

function optionalPositiveInteger(value: number | undefined, name: string): number | undefined {
  return value === undefined ? undefined : positiveInteger(value, name);
}

function nonNegativeInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new ArgumentError(`${name} must be a non-negative safe integer`);
  return value;
}
