import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import {
  C2spTlogReader,
  InMemoryTrustedC2spCheckpointStore,
  ScanStreamSource,
  createDnsidManagedVerificationRegistry,
  parseSignedNoteVerifierKey,
  requiredC2spResourceFetchGuarantees,
  type C2spBoundedResourceFetcher,
  type SignedNoteKey,
} from '@identity-digital/dnsid-log-c2sp-tlog';

const vector = JSON.parse(readFileSync(
  new URL('./vectors/c2sp-managed-trust-selection.json', import.meta.url),
  'utf8',
)) as {
  cases: Array<{
    id: string;
    lr: string;
    expected: { accepted: boolean; trustMode?: 'trust-profile' | 'policy' };
  }>;
};

const PRODUCTION_POLICY = `log log.dnsid.ai+c4683585+AWZYC4OLE9KeRnpaI9xaHWwHUKoxgp/24ukzgVYlDwIt
witness dnsid-witness-1 witness.dnsid.ai/w1+b5ea211e+BH0nGTkjF4tYpkefsQhHNg0YagPvQ6H96Y3UBbXo7a/b
quorum dnsid-witness-1
`;
const PRODUCTION_BUNDLE_KEY = 'dnsid-stream-bundle+ee2b26d2+AWGLBe4LhJKumyDpH8VJ0vyATB081i1HseVeETu4TONR';

type ReaderInternals = {
  checkpointStore: unknown;
  source: { resourceFetcher: C2spBoundedResourceFetcher };
  options: {
    checkpointMaxAge?: number;
    allowedClockSkew?: number;
    streamBundle?: {
      policyDocument: Uint8Array;
      bundleKeys: SignedNoteKey[];
      maxBundleLifetimeMs: number;
      checkpointFreshnessMs: number;
      required?: boolean;
    };
  };
};

const internals = (reader: C2spTlogReader): ReaderInternals => reader as unknown as ReaderInternals;

describe('Identity Digital-managed C2SP trust', () => {
  it('implements the managed trust selection conformance vectors', async () => {
    const registry = await createDnsidManagedVerificationRegistry();

    for (const testCase of vector.cases) {
      if (!testCase.expected.accepted) {
        expect(() => registry.newReader(testCase.lr), testCase.id).toThrow();
        continue;
      }
      const reader = registry.newReader(testCase.lr);
      expect(reader, testCase.id).toBeInstanceOf(C2spTlogReader);
      expect(Boolean(internals(reader as C2spTlogReader).options.streamBundle), testCase.id)
        .toBe(testCase.expected.trustMode === 'trust-profile');
    }
  });

  it('parses the exact production profile and shares injected infrastructure and managed defaults', async () => {
    const fetcher: C2spBoundedResourceFetcher = {
      fetchBounded: vi.fn(async () => { throw new Error('not called during catalog construction'); }),
      securityGuarantees: requiredC2spResourceFetchGuarantees,
    };
    const store = new InMemoryTrustedC2spCheckpointStore();
    const registry = await createDnsidManagedVerificationRegistry({
      resourceFetcher: fetcher,
      trustedCheckpointStore: store,
    });
    const development = internals(registry.newReader(
      'c2sp-tlog:public:https://log.dnsid.dev#EREREREREREREREREREREQ',
    ) as C2spTlogReader);
    const production = internals(registry.newReader(
      'c2sp-tlog:public:https://log.dnsid.ai#EREREREREREREREREREREQ',
    ) as C2spTlogReader);

    expect(development.checkpointStore).toBe(store);
    expect(production.checkpointStore).toBe(store);
    expect(development.source.resourceFetcher).toBe(fetcher);
    expect(production.source.resourceFetcher).toBe(fetcher);
    expect(development.options).toMatchObject({ checkpointMaxAge: 600_000, allowedClockSkew: 0 });
    expect(production.options).toMatchObject({ checkpointMaxAge: 600_000, allowedClockSkew: 0 });
    expect(development.options.streamBundle).toMatchObject({
      maxBundleLifetimeMs: 600_000,
      checkpointFreshnessMs: 600_000,
    });
    expect(production.source).toBeInstanceOf(ScanStreamSource);
    expect(production.options.streamBundle).toMatchObject({
      policyDocument: new TextEncoder().encode(PRODUCTION_POLICY),
      bundleKeys: [parseSignedNoteVerifierKey(PRODUCTION_BUNDLE_KEY)],
      maxBundleLifetimeMs: 600_000,
      checkpointFreshnessMs: 600_000,
      required: undefined,
    });
  });
});
