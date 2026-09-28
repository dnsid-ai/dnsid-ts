import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import {
  C2spTlogReader,
  InMemoryTrustedC2spCheckpointStore,
  ScanStreamSource,
  createDnsidManagedVerificationRegistry,
  enforceCheckpointPolicy,
  parseC2spPolicyFile,
  parseCheckpoint,
  parseSignedNoteVerifierKey,
  requiredC2spResourceFetchGuarantees,
  type C2spBoundedResourceFetcher,
  type SignedNoteKey,
} from '@dnsid-ai/log-c2sp-tlog';

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

const DEVELOPMENT_POLICY = `log log.dev.dnsid.ai+cad12acd+Afnd3sdzfp8nCXzDQchrnWn9QOox5AglR147bURESRqu
witness dnsid-witness-1 witness.dev.dnsid.ai/w1+50822ded+BAH9KuulelD3yZBDTneG46gKZY+OWwdUPBmLmq/YjOkO
quorum dnsid-witness-1
`;
const DEVELOPMENT_BUNDLE_KEY = 'dnsid-stream-bundle+0c241174+AeuT9PKyiewb9hkzygvki7UuOs5ly2kfY/C4Tfh7/ix0';
const PRODUCTION_POLICY = `log log.dnsid.ai+f10a26bc+Aeo6u4o1XvQlcRczgY462ZdIGpm/ejBC2G3vSbyYYqqY
witness dnsid-witness-1 witness.dnsid.ai/w1+706fd4fb+BLqX21Sx9xG5+5vK7kSK5omcu9+2il20PLdfpOp8lQOJ
quorum dnsid-witness-1
`;
const PRODUCTION_BUNDLE_KEY = 'dnsid-stream-bundle+2e77a3f1+AbKj/zrAfK04/NM07Zj7kxP2YXbM5neT8ym6juXC2PXG';

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

const PARTNERS_POLICY = `log log.partners.dnsid.ai+52d6a7c3+ASsAuEkXpM63Qh2yh0q7DvueHqITfWGvcpWCOQfaDz5m
witness dnsid-witness-1 witness.partners.dnsid.ai/w1+a115eb67+BB0avWVeSelUBk2w8FtTbT+orf2i826q9VemA0jaXxg4
quorum dnsid-witness-1
`;
const PARTNERS_BUNDLE_KEY = 'dnsid-stream-bundle+b12677d8+AWOB3PQPuFoGK66bqsFRcNh4n4q2DaAcauBijHymUUWH';

describe('DNSid-managed C2SP trust', () => {
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
      'c2sp-tlog:public:https://log.dev.dnsid.ai#EREREREREREREREREREREREQ',
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
      policyDocument: new TextEncoder().encode(DEVELOPMENT_POLICY),
      bundleKeys: [parseSignedNoteVerifierKey(DEVELOPMENT_BUNDLE_KEY)],
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

  it('selects the exact partners profile with the managed defaults', async () => {
    const fetcher: C2spBoundedResourceFetcher = {
      fetchBounded: vi.fn(async () => { throw new Error('not called during catalog construction'); }),
      securityGuarantees: requiredC2spResourceFetchGuarantees,
    };
    const store = new InMemoryTrustedC2spCheckpointStore();
    const registry = await createDnsidManagedVerificationRegistry({
      resourceFetcher: fetcher,
      trustedCheckpointStore: store,
    });
    const partners = internals(registry.newReader(
      'c2sp-tlog:public:https://log.partners.dnsid.ai#EREREREREREREREREREREQ',
    ) as C2spTlogReader);

    expect(partners.checkpointStore).toBe(store);
    expect(partners.source.resourceFetcher).toBe(fetcher);
    expect(partners.options).toMatchObject({ checkpointMaxAge: 600_000, allowedClockSkew: 0 });
    expect(partners.options.streamBundle).toMatchObject({
      policyDocument: new TextEncoder().encode(PARTNERS_POLICY),
      bundleKeys: [parseSignedNoteVerifierKey(PARTNERS_BUNDLE_KEY)],
      maxBundleLifetimeMs: 600_000,
      checkpointFreshnessMs: 600_000,
      required: undefined,
    });
  });

  // The fixture is the size-1 checkpoint https://log.partners.dnsid.ai served
  // on 2026-09-28. The pinned keys must be the ones the partner log and its
  // witness actually sign with.
  it('verifies the partner log checkpoint under the pinned partners policy', () => {
    const checkpoint = parseCheckpoint(readFileSync(
      new URL('./vectors/c2sp-partners-checkpoint-size1.txt', import.meta.url),
      'utf8',
    ));
    const result = enforceCheckpointPolicy(
      checkpoint,
      'log.partners.dnsid.ai',
      parseC2spPolicyFile(PARTNERS_POLICY),
      'public',
    );
    expect(checkpoint.treeSize).toBe(1);
    expect(result.acceptedWitnessTimestamps).toHaveLength(1);
  });
});
