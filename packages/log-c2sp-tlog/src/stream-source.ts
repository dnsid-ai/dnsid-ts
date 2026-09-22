import { VerificationError, withVerificationBudget, waitForVerification } from '@dnsid-ai/protocol';
import { createSsrfSafeFetch, type FetchLike, type TransportConfig } from '@dnsid-ai/transport';
import { parseCheckpoint, type Checkpoint } from './checkpoint.ts';
import { C2spTlogError, C2spTlogVerificationError } from './errors.ts';
import { checkpointPath, entryBundlePath, parseEntryBundle } from './tiles.ts';

/** Security properties required by the standard-resource verification factory. */
export interface C2spResourceFetchGuarantees {
  httpsOnly: boolean;
  rejectsRedirects: boolean;
  validatesAllResolvedAddresses: boolean;
  connectsToValidatedAddress: boolean;
  boundsResponseDuringRead: boolean;
}

/** Cancellation and deadline controls for one bounded resource read. */
export interface C2spResourceFetchOptions {
  signal?: AbortSignal;
  /** Finite timeout in milliseconds. */
  timeoutMs: number;
}

/**
 * Fetches one C2SP resource while enforcing the supplied decoded-byte limit
 * during the read. Implementations must require HTTP 200, reject redirects,
 * honor cancellation and the finite timeout, and provide truthful security
 * capabilities.
 */
export interface C2spBoundedResourceFetcher {
  fetchBounded(url: string, maxBytes: number, options: C2spResourceFetchOptions): Promise<Uint8Array>;
  securityGuarantees(): C2spResourceFetchGuarantees;
}

/** A raw log entry together with its index in the tree. */
export interface IndexedEntry { index: number; bytes: Uint8Array }
/** Log evidence loaded from a source: the checkpoint, entries, and whether every entry up to the tree size is present. */
export interface StreamEvidence { checkpoint: Checkpoint; entries: IndexedEntry[]; complete: boolean }

/** Supplies checkpoint-plus-entries evidence for a log prefix. */
export interface StreamSource { load(prefix: string, options?: { signal?: AbortSignal }): Promise<StreamEvidence> }

/** Configuration for {@link ScanStreamSource}; the byte/size limits bound untrusted responses. */
export interface ScanStreamSourceOptions {
  /** Called with the parsed checkpoint before any entries are fetched; throw to reject it. */
  authenticateCheckpoint: (checkpoint: Checkpoint) => void | Promise<void>;
  maxTreeSize?: number;
  maxCheckpointBytes?: number;
  maxEntryBundleBytes?: number;
  maxTotalEntryBytes?: number;
  /** Finite deadline for each resource read (default 10 seconds). */
  requestTimeoutMs?: number;
  /** Cancels current and subsequent resource reads. */
  signal?: AbortSignal;
}

/** C2SP tlog-tiles fixes full entry bundles at 256 entries. */
export const C2SP_ENTRIES_PER_BUNDLE = 256;
export const DEFAULT_C2SP_MAX_TREE_SIZE = 1_000_000;
export const DEFAULT_C2SP_MAX_CHECKPOINT_BYTES = 1_048_576;
/** 256 * (2-byte prefix + 65,535-byte entry). */
export const DEFAULT_C2SP_MAX_ENTRY_BUNDLE_BYTES = 16_777_472;
export const DEFAULT_C2SP_MAX_TOTAL_ENTRY_BYTES = 268_435_456;
export const DEFAULT_C2SP_REQUEST_TIMEOUT_MS = 10_000;

const REQUIRED_FETCH_GUARANTEES: Readonly<C2spResourceFetchGuarantees> = Object.freeze({
  httpsOnly: true,
  rejectsRedirects: true,
  validatesAllResolvedAddresses: true,
  connectsToValidatedAddress: true,
  boundsResponseDuringRead: true,
});

/** Returns a copy of the capabilities required by the safe standard-resource factory. */
export function requiredC2spResourceFetchGuarantees(): C2spResourceFetchGuarantees {
  return { ...REQUIRED_FETCH_GUARANTEES };
}

/**
 * Creates the default public-resource fetcher. It uses connection-time SSRF
 * checks, rejects redirects, requires HTTP 200, and bounds the decoded body
 * while reading it. `transport` applies the same DNS server, CA bundle, and
 * private-address exceptions as `DnsidConfig.transport`, so a private registry
 * such as `dnsid local` is reachable for policy and log reads.
 */
export function createDefaultC2spBoundedResourceFetcher(transport: TransportConfig = {}): C2spBoundedResourceFetcher {
  const { allowedUnsafeHosts, ...config } = transport;
  return createFetchBackedC2spResourceFetcher(createSsrfSafeFetch(config, { allowedUnsafeHosts }), REQUIRED_FETCH_GUARANTEES);
}

/**
 * Adapts trusted deployment fetch infrastructure to the bounded C2SP contract.
 * The caller is responsible for truthfully declaring DNS/connection security;
 * the adapter itself enforces HTTPS, status, redirect, timeout, cancellation,
 * and response-size behavior.
 */
export function createFetchBackedC2spResourceFetcher(
  fetchImpl: FetchLike,
  guarantees: C2spResourceFetchGuarantees,
): C2spBoundedResourceFetcher {
  const declared = Object.freeze({ ...guarantees });
  return {
    securityGuarantees: () => ({ ...declared }),
    fetchBounded: (url, maxBytes, options) => fetchBoundedResponse(fetchImpl, url, maxBytes, options),
  };
}

/** Throws a deterministic error when a fetcher cannot safely read public standard resources. */
export function validateC2spResourceFetcher(fetcher: C2spBoundedResourceFetcher): void {
  if (!fetcher || typeof fetcher.fetchBounded !== 'function' || typeof fetcher.securityGuarantees !== 'function') {
    throw new C2spTlogVerificationError('C2SP resourceFetcher must implement fetchBounded and securityGuarantees');
  }
  let guarantees: C2spResourceFetchGuarantees;
  try {
    guarantees = fetcher.securityGuarantees();
  } catch (cause) {
    throw new C2spTlogVerificationError(`failed to inspect C2SP resourceFetcher capabilities: ${errorMessage(cause)}`);
  }
  for (const name of Object.keys(REQUIRED_FETCH_GUARANTEES) as Array<keyof C2spResourceFetchGuarantees>) {
    if (guarantees?.[name] !== true) {
      throw new C2spTlogVerificationError(`C2SP resourceFetcher lacks required security guarantee: ${name}`);
    }
  }
}

/**
 * StreamSource that performs a complete scan of a C2SP tlog-tiles log: it
 * fetches the checkpoint, authenticates it via the configured callback, then
 * downloads every fixed-geometry entry bundle up to the checkpoint tree size.
 */
export class ScanStreamSource implements StreamSource {
  private readonly maxTreeSize: number;
  private readonly maxCheckpointBytes: number;
  private readonly maxEntryBundleBytes: number;
  private readonly maxTotalEntryBytes: number;
  private readonly requestTimeoutMs: number;

  constructor(
    private readonly options: ScanStreamSourceOptions,
    private readonly resourceFetcher: C2spBoundedResourceFetcher = createDefaultC2spBoundedResourceFetcher(),
  ) {
    validateC2spResourceFetcher(resourceFetcher);
    this.maxTreeSize = positiveInteger(options.maxTreeSize ?? DEFAULT_C2SP_MAX_TREE_SIZE, 'maxTreeSize');
    this.maxCheckpointBytes = positiveInteger(options.maxCheckpointBytes ?? DEFAULT_C2SP_MAX_CHECKPOINT_BYTES, 'maxCheckpointBytes');
    this.maxEntryBundleBytes = positiveInteger(options.maxEntryBundleBytes ?? DEFAULT_C2SP_MAX_ENTRY_BUNDLE_BYTES, 'maxEntryBundleBytes');
    this.maxTotalEntryBytes = positiveInteger(options.maxTotalEntryBytes ?? DEFAULT_C2SP_MAX_TOTAL_ENTRY_BYTES, 'maxTotalEntryBytes');
    this.requestTimeoutMs = positiveInteger(options.requestTimeoutMs ?? DEFAULT_C2SP_REQUEST_TIMEOUT_MS, 'requestTimeoutMs');
  }

  /** Loads and authenticates the checkpoint, then every entry of the log at `prefix` (`complete` is always true). */
  async load(prefix: string, options: { signal?: AbortSignal } = {}): Promise<StreamEvidence> {
    const signal = options.signal && this.options.signal ? AbortSignal.any([options.signal, this.options.signal]) : options.signal ?? this.options.signal;
    return withVerificationBudget(child => this.loadWithinBudget(prefix, child), { signal });
  }

  private async loadWithinBudget(prefix: string, signal: AbortSignal): Promise<StreamEvidence> {
    const checkpointBytes = await this.bytes(checkpointPath(prefix), this.maxCheckpointBytes, signal);
    const checkpoint = parseCheckpoint(new TextDecoder().decode(checkpointBytes));
    await this.options.authenticateCheckpoint(checkpoint);
    if (checkpoint.treeSize > this.maxTreeSize) throw new C2spTlogVerificationError(`checkpoint tree size exceeds configured maximum ${this.maxTreeSize}`);

    const entries: IndexedEntry[] = [];
    let totalEntryBytes = 0;
    for (let bundleIndex = 0; bundleIndex * C2SP_ENTRIES_PER_BUNDLE < checkpoint.treeSize; bundleIndex++) {
      const want = Math.min(C2SP_ENTRIES_PER_BUNDLE, checkpoint.treeSize - bundleIndex * C2SP_ENTRIES_PER_BUNDLE);
      const path = entryBundlePath(prefix, bundleIndex, want === C2SP_ENTRIES_PER_BUNDLE ? undefined : want);
      const bundleBytes = await this.bytes(path, this.maxEntryBundleBytes, signal);
      totalEntryBytes += bundleBytes.length;
      if (totalEntryBytes > this.maxTotalEntryBytes) throw new C2spTlogVerificationError(`entry bundles exceed configured total byte maximum ${this.maxTotalEntryBytes}`);
      const bundle = parseEntryBundle(bundleBytes);
      if (bundle.length !== want) throw new C2spTlogVerificationError('entry bundle width mismatch');
      for (let i = 0; i < bundle.length; i++) {
        entries.push({ index: bundleIndex * C2SP_ENTRIES_PER_BUNDLE + i, bytes: bundle[i]! });
      }
    }
    return { checkpoint, entries, complete: true };
  }

  private async bytes(url: string, maximum: number, signal: AbortSignal): Promise<Uint8Array> {
    let bytes: Uint8Array;
    try {
      bytes = await waitForVerification(() => this.resourceFetcher.fetchBounded(url, maximum, {
        signal,
        timeoutMs: this.requestTimeoutMs,
      }), signal);
    } catch (cause) {
      if (cause instanceof VerificationError) throw cause;
      throw new C2spTlogError(`C2SP resource fetch failed: ${url}`, { cause, transient: true });
    }
    // Defense in depth: the fetcher contract must enforce this during reading.
    if (!(bytes instanceof Uint8Array)) throw new C2spTlogVerificationError(`C2SP resourceFetcher returned a non-byte response: ${url}`);
    if (bytes.length > maximum) throw responseTooLarge(maximum, url);
    return bytes;
  }
}

async function fetchBoundedResponse(
  fetchImpl: FetchLike,
  rawUrl: string,
  maximum: number,
  options: C2spResourceFetchOptions,
): Promise<Uint8Array> {
  positiveInteger(maximum, 'maxBytes');
  positiveInteger(options.timeoutMs, 'timeoutMs');
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch (cause) {
    throw new C2spTlogVerificationError(`invalid C2SP resource URL: ${errorMessage(cause)}`);
  }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.hash) {
    throw new C2spTlogVerificationError('C2SP resource URL must be absolute HTTPS without userinfo or fragment');
  }

  const controller = new AbortController();
  const abort = () => controller.abort(options.signal?.reason);
  if (options.signal?.aborted) abort();
  else options.signal?.addEventListener('abort', abort, { once: true });
  const timeout = setTimeout(() => controller.abort(new Error(`C2SP resource request timed out after ${options.timeoutMs}ms`)), options.timeoutMs);

  try {
    let response: Response;
    try {
      response = await fetchImpl(url, { method: 'GET', redirect: 'manual', signal: controller.signal });
    } catch (cause) {
      if (cause instanceof VerificationError) {
        throw new C2spTlogError(`C2SP resource fetch failed: ${rawUrl}`, { cause, transient: cause.transient });
      }
      throw new C2spTlogError(`C2SP resource fetch failed: ${rawUrl}`, { cause, transient: true });
    }

    if (response.redirected || (response.status >= 300 && response.status < 400)) {
      await cancelBody(response);
      throw new C2spTlogVerificationError(`C2SP resource redirects are not allowed: ${rawUrl}`);
    }
    if (response.status !== 200) {
      await cancelBody(response);
      throw new C2spTlogError(`C2SP resource fetch failed ${response.status}: ${rawUrl}`, {
        transient: response.status === 408 || response.status === 429 || (response.status >= 500 && response.status <= 599),
        status: response.status,
      });
    }

    const contentLength = response.headers.get('content-length');
    if (contentLength !== null && /^\d+$/.test(contentLength) && Number(contentLength) > maximum) {
      await cancelBody(response);
      throw responseTooLarge(maximum, rawUrl);
    }
    if (!response.body) return new Uint8Array();

    const chunks: Uint8Array[] = [];
    let size = 0;
    const reader = response.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > maximum) {
          await reader.cancel();
          throw responseTooLarge(maximum, rawUrl);
        }
        chunks.push(value);
      }
    } catch (cause) {
      if (cause instanceof VerificationError) throw cause;
      throw new C2spTlogError(`failed to read C2SP resource: ${rawUrl}`, { cause, transient: true });
    } finally {
      reader.releaseLock();
    }

    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return bytes;
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener('abort', abort);
  }
}

async function cancelBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // Cancellation is best effort after a deterministic response rejection.
  }
}

function responseTooLarge(maximum: number, url: string): C2spTlogVerificationError {
  return new C2spTlogVerificationError(`C2SP response exceeds configured byte maximum ${maximum}: ${url}`);
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new C2spTlogVerificationError(`${name} must be a positive safe integer`);
  return value;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
