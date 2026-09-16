import { describe, expect, it, vi } from 'vitest';
import { ArgumentError } from '@dnsid-ai/protocol';
import {
  C2spTlogReader,
  DEFAULT_C2SP_MAX_ENTRY_BUNDLE_BYTES,
  InMemoryTrustedC2spCheckpointStore,
  ScanStreamSource,
  createC2spTlogVerificationRegistry,
  createFetchBackedC2spResourceFetcher,
  encodeEntryBundle,
  entryBundlePath,
  parseSignedNoteVerifierKey,
  requiredC2spResourceFetchGuarantees,
  type C2spBoundedResourceFetcher,
} from '@dnsid-ai/log-c2sp-tlog';

const policyDocument = new TextEncoder().encode(`log testnet.dnsid.example/log+63868553+Ae1JKMYo0cLG6ukDOJBZlWEpWSc6XGP5NjbBRhSshzfR
quorum none
`);
const firstLr = 'c2sp-tlog:testnet:https://testnet.dnsid.example/log#first-stream';
const secondLr = 'c2sp-tlog:testnet:https://testnet.dnsid.example/log#second-stream';
const bundleVerifierKey = parseSignedNoteVerifierKey(
  'bundle.example+b0fef33a+AYqHX/8es4RRV3rNWv7kBUVlaN18ieCQhjoFV7x69J8X',
);

type ReaderInternals = {
  source: { resourceFetcher: C2spBoundedResourceFetcher; maxEntryBundleBytes: number };
  checkpointStore: unknown;
  options: {
    checkpointMaxAge?: number;
    allowedClockSkew?: number;
    streamBundle?: { bundleKeys: unknown[]; maxBundleLifetimeMs: number; required?: boolean };
  };
};

function internals(reader: C2spTlogReader): ReaderInternals {
  return reader as unknown as ReaderInternals;
}

function safeFetcher(fetchImpl: typeof fetch): C2spBoundedResourceFetcher {
  return createFetchBackedC2spResourceFetcher(fetchImpl, requiredC2spResourceFetchGuarantees());
}

describe('createC2spTlogVerificationRegistry', () => {
  it('registers fixed scanner limits, freshness/skew policy, and one shared process-lifetime checkpoint store', async () => {
    const registry = await createC2spTlogVerificationRegistry({
      policyDocument,
      checkpointMaxAge: 5 * 60 * 1000,
      allowedClockSkew: 2_000,
    });
    const first = registry.newReader(firstLr);
    const second = registry.newReader(secondLr);

    expect(first).toBeInstanceOf(C2spTlogReader);
    expect(internals(first as C2spTlogReader).checkpointStore).toBeInstanceOf(InMemoryTrustedC2spCheckpointStore);
    expect(internals(first as C2spTlogReader).options).toMatchObject({
      checkpointMaxAge: 5 * 60 * 1000,
      allowedClockSkew: 2_000,
    });
    expect(internals(first as C2spTlogReader).source.maxEntryBundleBytes)
      .toBe(DEFAULT_C2SP_MAX_ENTRY_BUNDLE_BYTES);
    expect(DEFAULT_C2SP_MAX_ENTRY_BUNDLE_BYTES).toBe(16_777_472);
    expect(internals(second as C2spTlogReader).checkpointStore)
      .toBe(internals(first as C2spTlogReader).checkpointStore);
  });

  it('uses fixed 256-entry standard bundle geometry and the exact default scanner limits', async () => {
    const prefix = 'https://log.example/tlog';
    const checkpoint = new TextEncoder().encode(`origin\n257\n${Buffer.alloc(32).toString('base64')}\n`);
    const fullBundle = encodeEntryBundle(Array.from({ length: 256 }, () => new Uint8Array([1])));
    const partialBundle = encodeEntryBundle([new Uint8Array([2])]);
    const fetchBounded = vi.fn(async (url: string) => {
      if (url.endsWith('/checkpoint')) return checkpoint;
      if (url === entryBundlePath(prefix, 0)) return fullBundle;
      if (url === entryBundlePath(prefix, 1, 1)) return partialBundle;
      throw new Error(`unexpected URL ${url}`);
    });
    const source = new ScanStreamSource(
      { authenticateCheckpoint: () => undefined },
      { fetchBounded, securityGuarantees: requiredC2spResourceFetchGuarantees },
    );

    await expect(source.load(prefix)).resolves.toMatchObject({ complete: true, entries: { length: 257 } });
    expect(fetchBounded.mock.calls).toEqual([
      [prefix + '/checkpoint', 1_048_576, expect.objectContaining({ timeoutMs: 10_000 })],
      [entryBundlePath(prefix, 0), 16_777_472, expect.objectContaining({ timeoutMs: 10_000 })],
      [entryBundlePath(prefix, 1, 1), 16_777_472, expect.objectContaining({ timeoutMs: 10_000 })],
    ]);
  });

  it('keeps non-revocation fail-closed when checkpoint maximum age is omitted', async () => {
    const registry = await createC2spTlogVerificationRegistry({ policyDocument });
    const reader = registry.newReader(firstLr) as C2spTlogReader;
    const privateReader = reader as unknown as {
      loadCompleteHistory(domain: string): Promise<{ events: []; checkpointWitnessTime: Date }>;
    };
    vi.spyOn(privateReader, 'loadCompleteHistory').mockResolvedValue({
      events: [],
      checkpointWitnessTime: new Date(),
    });

    await expect(reader.verifyNonRevocation('agent.example', new Date()))
      .rejects.toMatchObject({ transient: false, message: expect.stringContaining('checkpointMaxAge') });
  });

  it('uses the same bounded fetcher for policy retrieval and log scans', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(policyDocument, { status: 200 }));
    const resourceFetcher = safeFetcher(fetchMock as unknown as typeof fetch);
    const registry = await createC2spTlogVerificationRegistry({
      policyUrl: 'https://policy.example:8443/dnsid-policy',
      bundleVerifierKeys: [bundleVerifierKey],
      maxBundleLifetimeMs: 60_000,
      requireStreamBundle: true,
      resourceFetcher,
    });
    const reader = registry.newReader(firstLr) as C2spTlogReader;

    expect(String(fetchMock.mock.calls[0]![0])).toBe('https://policy.example:8443/dnsid-policy');
    expect(fetchMock.mock.calls[0]![1]).toEqual(expect.objectContaining({
      method: 'GET',
      redirect: 'manual',
      signal: expect.any(AbortSignal),
    }));
    expect(internals(reader).source.resourceFetcher).toBe(resourceFetcher);
    expect(internals(reader).options.streamBundle).toMatchObject({
      bundleKeys: [bundleVerifierKey],
      maxBundleLifetimeMs: 60_000,
      required: true,
    });
  });

  it('eagerly rejects invalid policy, duration, timeout, limit, and fetcher options', async () => {
    await expect(createC2spTlogVerificationRegistry({})).rejects.toBeInstanceOf(ArgumentError);
    await expect(createC2spTlogVerificationRegistry({
      policyDocument,
      policyUrl: 'https://policy.example/dnsid-policy',
    })).rejects.toBeInstanceOf(ArgumentError);

    for (const policyUrl of [
      'http://policy.example/dnsid-policy',
      'https://user@policy.example/dnsid-policy',
      'https://policy.example/dnsid-policy#fragment',
      'not a URL',
    ]) {
      await expect(createC2spTlogVerificationRegistry({ policyUrl }))
        .rejects.toBeInstanceOf(ArgumentError);
    }
    for (const options of [
      { maxPolicyBytes: 0 },
      { checkpointMaxAge: 0 },
      { allowedClockSkew: -1 },
      { requestTimeoutMs: 0 },
      { bundleVerifierKeys: [bundleVerifierKey] },
      { maxBundleLifetimeMs: 60_000 },
      { maxStreamBundleBytes: 1024 },
      { maxStreamBundleEvents: 10 },
      { requireStreamBundle: true },
      { scanLimits: { maxTreeSize: 0 } },
      { scanLimits: { maxCheckpointBytes: 1.5 } },
      { scanLimits: { maxEntryBundleBytes: -1 } },
      { scanLimits: { maxTotalEntryBytes: Number.MAX_SAFE_INTEGER + 1 } },
    ]) {
      await expect(createC2spTlogVerificationRegistry({ policyDocument, ...options }))
        .rejects.toBeInstanceOf(ArgumentError);
    }

    await expect(createC2spTlogVerificationRegistry({
      policyDocument,
      bundleVerifierKeys: 'invalid' as never,
    })).rejects.toBeInstanceOf(ArgumentError);

    const insufficient: C2spBoundedResourceFetcher = {
      fetchBounded: async () => policyDocument,
      securityGuarantees: () => ({
        ...requiredC2spResourceFetchGuarantees(),
        connectsToValidatedAddress: false,
      }),
    };
    await expect(createC2spTlogVerificationRegistry({ policyDocument, resourceFetcher: insufficient }))
      .rejects.toMatchObject({ name: 'ArgumentError', message: expect.stringContaining('connectsToValidatedAddress') });
  });

  it('rejects redirects and oversized responses as non-transient and cancels oversized declared bodies', async () => {
    const redirected = safeFetcher(vi.fn(async () => new Response(null, {
      status: 302,
      headers: { location: 'https://other.example/policy' },
    })) as unknown as typeof fetch);
    await expect(createC2spTlogVerificationRegistry({
      policyUrl: 'https://policy.example/dnsid-policy',
      resourceFetcher: redirected,
    })).rejects.toMatchObject({ transient: false, message: expect.stringContaining('redirects are not allowed') });

    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({ cancel });
    const oversized = safeFetcher(vi.fn(async () => new Response(body, {
      status: 200,
      headers: { 'content-length': '5' },
    })) as unknown as typeof fetch);
    await expect(createC2spTlogVerificationRegistry({
      policyUrl: 'https://policy.example/dnsid-policy',
      maxPolicyBytes: 4,
      resourceFetcher: oversized,
    })).rejects.toMatchObject({ transient: false, message: expect.stringContaining('byte maximum 4') });
    expect(cancel).toHaveBeenCalledOnce();
  });

  it('bounds streamed decoded bodies and supports timeout/abort signals', async () => {
    const streamed = safeFetcher(vi.fn(async () => new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('123'));
        controller.enqueue(new TextEncoder().encode('45'));
      },
    }))) as unknown as typeof fetch);
    await expect(createC2spTlogVerificationRegistry({
      policyUrl: 'https://policy.example/dnsid-policy',
      maxPolicyBytes: 4,
      resourceFetcher: streamed,
    })).rejects.toMatchObject({ transient: false, message: expect.stringContaining('byte maximum 4') });

    const hangingFetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      await new Promise((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true }));
      throw new Error('unreachable');
    }) as unknown as typeof fetch;
    await expect(createC2spTlogVerificationRegistry({
      policyUrl: 'https://policy.example/dnsid-policy',
      resourceFetcher: safeFetcher(hangingFetch),
      requestTimeoutMs: 1,
    })).rejects.toMatchObject({ transient: true, message: expect.stringContaining('resource fetch failed') });
  });

  it('classifies the default SSRF block as non-transient', async () => {
    await expect(createC2spTlogVerificationRegistry({
      policyUrl: 'https://127.0.0.1/dnsid-policy',
    })).rejects.toMatchObject({
      transient: false,
      message: expect.stringContaining('C2SP resource fetch failed'),
      cause: expect.objectContaining({ message: expect.stringContaining('unsafe target IP address') }),
    });
  });
});
