import { createHash } from 'node:crypto';
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
  verifyC2spStreamBundle,
  type C2spBoundedResourceFetcher,
  type C2spTlogReaderOptions,
  type SignedNoteKey,
} from '@dnsid-ai/log-c2sp-tlog';

const vector = JSON.parse(readFileSync(
  new URL('./vectors/c2sp-managed-trust-selection.json', import.meta.url),
  'utf8',
)) as {
  catalog: Array<{ id: string; scope: string; logPrefix: string }>;
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
// Signs dev bundles over the 4096-byte KMS limit (Identity-Digital/dnsid#3286).
const DEVELOPMENT_OVERFLOW_BUNDLE_KEY = 'dnsid-stream-bundle+62f7f9fa+ATdOWF5P759HgvDod9mIC0r1nXhTtJ7x1Ws0fjTvqwDV';
const PRODUCTION_POLICY = `log log.dnsid.ai+f10a26bc+Aeo6u4o1XvQlcRczgY462ZdIGpm/ejBC2G3vSbyYYqqY
witness dnsid-witness-1 witness.dnsid.ai/w1+706fd4fb+BLqX21Sx9xG5+5vK7kSK5omcu9+2il20PLdfpOp8lQOJ
quorum dnsid-witness-1
`;
const PRODUCTION_BUNDLE_KEY = 'dnsid-stream-bundle+2e77a3f1+AbKj/zrAfK04/NM07Zj7kxP2YXbM5neT8ym6juXC2PXG';
// Signs production bundles over the 4096-byte KMS limit (Identity-Digital/dnsid#3286).
const PRODUCTION_OVERFLOW_BUNDLE_KEY = 'dnsid-stream-bundle+0f5a76a0+AXavEa0+EGj/qZFH4QuAOeomigSukspWQHC7PrVJa7pj';

type ReaderInternals = {
  checkpointStore: unknown;
  source: { resourceFetcher: C2spBoundedResourceFetcher };
  options: {
    checkpointMaxAge?: number;
    allowedClockSkew?: number;
    migrationReaderFactory?: C2spTlogReaderOptions['migrationReaderFactory'];
    migrationLimits?: C2spTlogReaderOptions['migrationLimits'];
    revalidate?: boolean;
    signal?: AbortSignal;
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

const STAGING_POLICY = `log log.stg.dnsid.ai+f6ad3bd8+ARl6baGOUzNIH2QvsnlqA8C71WM4SYecXE7eAwmytAsL
witness dnsid-witness-1 witness.stg.dnsid.ai/w1+11a84cde+BEKB6hwsWXOm+PMnS7/JvO4i6bazjzJ8ojECphOTB3gt
quorum dnsid-witness-1
`;
const STAGING_BUNDLE_KEY = 'dnsid-stream-bundle+65c31b14+AXCMTPR4I/fqOgSHge4AEMp+1pWcflDqC1YEDaHDe3Ps';
// Signs staging bundles over the 4096-byte KMS limit (Identity-Digital/dnsid#3286).
const STAGING_OVERFLOW_BUNDLE_KEY = 'dnsid-stream-bundle+cdd64875+ATu1SYXvRiZPBUzrUJAfKHeMH3eHr3T22jKez/C3Yl1m';
const KNOWN_DEVELOPMENT_POLICY = `log log.dev.knownsystems.ai+78742e4f+AWJIIC/ZPaSwAprXLHT+JZ7lbTipE3MciQOdUGqG1T3j
witness dnsid-witness-1 witness.dev.knownsystems.ai/w1+21be2f43+BLsio+pQhADB8grceyZnOVERcoq+V6oJuUNy/IEfhsgt
quorum dnsid-witness-1
`;
const KNOWN_DEVELOPMENT_BUNDLE_KEY = 'dnsid-stream-bundle+138e0d41+AXy9jwvH7hY3LgjqoZn3GmNllKTj2TyNApRLKbt/2WSU';
// Signs Known dev bundles over the 4096-byte KMS limit.
const KNOWN_DEVELOPMENT_OVERFLOW_BUNDLE_KEY = 'dnsid-stream-bundle+ad87852b+AWWyHhKGf9oKqaRCQfrk9kixjuz4fmhI5P08W5bsYxzj';
const KNOWN_STAGING_POLICY = `log log.stg.knownsystems.ai+d3504618+AaUJP26XksZKcjmWHs7Cyq244q2efKUH1geUNb6bK5G7
witness dnsid-witness-1 witness.stg.knownsystems.ai/w1+e3954927+BA8QcWZ+kIuuakqhAbltJ1lFAYeuEqE98AYWyG9eKTil
quorum dnsid-witness-1
`;
const KNOWN_STAGING_BUNDLE_KEY = 'dnsid-stream-bundle+85bbbf6c+AQEr6kb1rP1ZUJxEUl5ai5KxD86uHDRhHoF9rGewVgvC';
// Signs Known staging bundles over the 4096-byte KMS limit.
const KNOWN_STAGING_OVERFLOW_BUNDLE_KEY = 'dnsid-stream-bundle+64bf74b3+Aa0M4XaiO7BzP4fn7gLnWOw570/ml9x8xnEiv5fUqIW1';
const KNOWN_PRODUCTION_POLICY = `log log.knownsystems.ai+ffa9d1c9+Ad/NRlpkBsb9RjFstpUI2V38LF0G9DaJgHWtx5UtS6a7
witness dnsid-witness-1 witness.knownsystems.ai/w1+f726713e+BPq3DkSLKz0bMwDnwhwb9yhsGKT/0g0iPKZYekuumLfV
quorum dnsid-witness-1
`;
const KNOWN_PRODUCTION_BUNDLE_KEY = 'dnsid-stream-bundle+4c5de6cf+AeoiHt6HX3fniAPFeNMerJ52HKAlfLxbwFnxvyVM8GPj';
// Signs Known production bundles over the 4096-byte KMS limit.
const KNOWN_PRODUCTION_OVERFLOW_BUNDLE_KEY = 'dnsid-stream-bundle+4296adc5+AX8gHt0vQT0mICUKU2svFWcdcIhcQmGHYuR2kk/EsXex';
const PARTNERS_POLICY = `log log.partners.dnsid.ai+f0143e09+Ae5vrTVQUr0h2GKbeHq70ml37N+uVBsU4NpZD4qMqAu1
witness dnsid-witness-1 witness.partners.dnsid.ai/w1+a115eb67+BB0avWVeSelUBk2w8FtTbT+orf2i826q9VemA0jaXxg4
quorum dnsid-witness-1
`;
const PARTNERS_BUNDLE_KEY = 'dnsid-stream-bundle+b1e0b597+AQt9ol4cfwPHxdH4NHNRidsAvU2bYE7KVItOlBG/bsaZ';
// Signs partner bundles over the 4096-byte KMS limit (Identity-Digital/dnsid#3286).
const PARTNERS_OVERFLOW_BUNDLE_KEY = 'dnsid-stream-bundle+bc0d8136+AVfizbWWQD+s2N7OfpOeP7IaWF8nAeTqT4JpD03vKqc6';

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
      bundleKeys: [
        parseSignedNoteVerifierKey(DEVELOPMENT_BUNDLE_KEY),
        parseSignedNoteVerifierKey(DEVELOPMENT_OVERFLOW_BUNDLE_KEY),
      ],
      maxBundleLifetimeMs: 600_000,
      checkpointFreshnessMs: 600_000,
    });
    expect(production.source).toBeInstanceOf(ScanStreamSource);
    expect(production.options.streamBundle).toMatchObject({
      policyDocument: new TextEncoder().encode(PRODUCTION_POLICY),
      bundleKeys: [
        parseSignedNoteVerifierKey(PRODUCTION_BUNDLE_KEY),
        parseSignedNoteVerifierKey(PRODUCTION_OVERFLOW_BUNDLE_KEY),
      ],
      maxBundleLifetimeMs: 600_000,
      checkpointFreshnessMs: 600_000,
      required: undefined,
    });
  });

  it('dispatches migration predecessors across managed log profiles', async () => {
    const registry = await createDnsidManagedVerificationRegistry({ migrationLimits: { maxDepth: 2 } });
    const development = registry.newReader('c2sp-tlog:public:https://log.dev.dnsid.ai#EREREREREREREREREREREQ') as C2spTlogReader;
    const factory = internals(development).options.migrationReaderFactory!;
    const signal = new AbortController().signal;
    const production = await factory('c2sp-tlog:public:https://log.dnsid.ai#EREREREREREREREREREREQ', { signal, revalidate: true }) as C2spTlogReader;
    expect(internals(production).options).toMatchObject({ migrationLimits: { maxDepth: 2 }, revalidate: true, signal });
    expect(internals(production).options.streamBundle!.policyDocument).toEqual(new TextEncoder().encode(PRODUCTION_POLICY));
    expect(() => factory('c2sp-tlog:public:https://unknown.example#EREREREREREREREREREREQ')).toThrow('unknown DNSid managed trust selector');
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
      bundleKeys: [
        parseSignedNoteVerifierKey(PARTNERS_BUNDLE_KEY),
        parseSignedNoteVerifierKey(PARTNERS_OVERFLOW_BUNDLE_KEY),
      ],
      maxBundleLifetimeMs: 600_000,
      checkpointFreshnessMs: 600_000,
      required: undefined,
    });
  });

  // Live checkpoint captured on 2026-10-16, signed by the log and its witness.
  it('verifies the partner log checkpoint under the pinned partners policy', () => {
    const checkpoint = parseCheckpoint(readFileSync(
      new URL('./vectors/c2sp-partners-checkpoint.txt', import.meta.url),
      'utf8',
    ));
    const result = enforceCheckpointPolicy(
      checkpoint,
      'log.partners.dnsid.ai',
      parseC2spPolicyFile(PARTNERS_POLICY),
      'public',
    );
    expect(checkpoint.treeSize).toBe(172);
    expect(result.acceptedWitnessTimestamps).toHaveLength(1);
  });

  // Reviewed service fixture from Identity-Digital/dnsid#2639, captured 2026-10-02.
  it('verifies a partner-signed stream bundle under the pinned partners profile', async () => {
    const bytes = readFileSync(new URL('./vectors/c2sp-partners-stream-bundle.json', import.meta.url));
    const bundle = JSON.parse(bytes.toString('utf8'));
    const issuance = JSON.parse(Buffer.from(bundle.events[0].entry, 'base64url').toString('utf8'));
    const result = await verifyC2spStreamBundle(bytes, {
      expectedFqdn: bundle.fqdn,
      expectedLogReference: bundle.lr,
      policyBytes: new TextEncoder().encode(PARTNERS_POLICY),
      bundleKeys: [parseSignedNoteVerifierKey(PARTNERS_BUNDLE_KEY)],
      entityKey: issuance.ek,
      maxBundleBytes: 128 * 1024,
      maxEvents: 16,
      maxBundleLifetimeMs: 600_000,
      checkpointFreshnessMs: 600_000,
      nowMs: (bundle.expires - 60) * 1000,
      trustedCheckpointStore: new InMemoryTrustedC2spCheckpointStore(),
    });
    expect(result.bundle.signature.kid).toBe('dnsid-stream-bundle+b1e0b597');
    expect(result.bundle.state.loggedState).toBe('ACTIVE');
    expect(result.events).toHaveLength(1);
  });

  // Reviewed service fixtures from Identity-Digital/dnsid#3286, captured 2026-11-10.
  // The dev log signs a bundle of at most 4096 signed bytes with its KMS key and a
  // larger one with a secret-held key, so the managed development reader must
  // accept both: a two-event stream signed by the KMS key and a three-event stream
  // (issuance, key rotation, revocation) signed by the secret-held key.
  it.each([
    ['c2sp-dev-stream-bundle-kms-key.json', 'dnsid-stream-bundle+0c241174', 2],
    ['c2sp-dev-stream-bundle-overflow-key.json', 'dnsid-stream-bundle+62f7f9fa', 3],
  ] as const)('verifies the dev bundle %s under the managed development profile', async (fixture, kid, events) => {
    const registry = await createDnsidManagedVerificationRegistry();
    const development = internals(registry.newReader(
      'c2sp-tlog:public:https://log.dev.dnsid.ai#EREREREREREREREREREREQ',
    ) as C2spTlogReader);
    const trust = development.options.streamBundle!;
    const bytes = readFileSync(new URL(`./vectors/${fixture}`, import.meta.url));
    const bundle = JSON.parse(bytes.toString('utf8'));
    const issuance = JSON.parse(Buffer.from(bundle.events[0].entry, 'base64url').toString('utf8'));
    const result = await verifyC2spStreamBundle(bytes, {
      expectedFqdn: bundle.fqdn,
      expectedLogReference: bundle.lr,
      policyBytes: trust.policyDocument,
      bundleKeys: trust.bundleKeys,
      entityKey: issuance.ek,
      maxBundleBytes: 128 * 1024,
      maxEvents: 16,
      maxBundleLifetimeMs: 600_000,
      checkpointFreshnessMs: 600_000,
      nowMs: (bundle.expires - 60) * 1000,
      trustedCheckpointStore: new InMemoryTrustedC2spCheckpointStore(),
    });
    expect(result.bundle.signature.kid).toBe(kid);
    expect(result.bundle.state.loggedState).toBe('REVOKED');
    expect(result.events).toHaveLength(events);
  });

  it('selects the exact staging profile with the managed defaults', async () => {
    const fetcher: C2spBoundedResourceFetcher = {
      fetchBounded: vi.fn(async () => { throw new Error('not called during catalog construction'); }),
      securityGuarantees: requiredC2spResourceFetchGuarantees,
    };
    const store = new InMemoryTrustedC2spCheckpointStore();
    const registry = await createDnsidManagedVerificationRegistry({
      resourceFetcher: fetcher,
      trustedCheckpointStore: store,
    });
    const staging = internals(registry.newReader(
      'c2sp-tlog:public:https://log.stg.dnsid.ai#EREREREREREREREREREREQ',
    ) as C2spTlogReader);

    expect(staging.checkpointStore).toBe(store);
    expect(staging.source.resourceFetcher).toBe(fetcher);
    expect(staging.options).toMatchObject({ checkpointMaxAge: 600_000, allowedClockSkew: 0 });
    expect(staging.options.streamBundle).toMatchObject({
      policyDocument: new TextEncoder().encode(STAGING_POLICY),
      bundleKeys: [
        parseSignedNoteVerifierKey(STAGING_BUNDLE_KEY),
        parseSignedNoteVerifierKey(STAGING_OVERFLOW_BUNDLE_KEY),
      ],
      maxBundleLifetimeMs: 600_000,
      checkpointFreshnessMs: 600_000,
      required: undefined,
    });
  });

  // Reviewed service fixtures captured from log.stg.dnsid.ai on 2026-11-11
  // (Identity-Digital/dnsid#3286): a one-event stream small enough for the KMS bundle
  // key and a three-event stream (issuance, key rotation, revocation) over the
  // 4096-byte KMS limit, signed by the secret-held key.
  it.each([
    ['c2sp-staging-stream-bundle-kms-key.json', 'dnsid-stream-bundle+65c31b14', 'ACTIVE', 1],
    ['c2sp-staging-stream-bundle-overflow-key.json', 'dnsid-stream-bundle+cdd64875', 'REVOKED', 3],
  ] as const)('verifies the staging bundle %s under the managed staging profile', async (fixture, kid, state, events) => {
    const registry = await createDnsidManagedVerificationRegistry();
    const staging = internals(registry.newReader(
      'c2sp-tlog:public:https://log.stg.dnsid.ai#EREREREREREREREREREREQ',
    ) as C2spTlogReader);
    const trust = staging.options.streamBundle!;
    const bytes = readFileSync(new URL(`./vectors/${fixture}`, import.meta.url));
    const bundle = JSON.parse(bytes.toString('utf8'));
    const issuance = JSON.parse(Buffer.from(bundle.events[0].entry, 'base64url').toString('utf8'));
    const result = await verifyC2spStreamBundle(bytes, {
      expectedFqdn: bundle.fqdn,
      expectedLogReference: bundle.lr,
      policyBytes: trust.policyDocument,
      bundleKeys: trust.bundleKeys,
      entityKey: issuance.ek,
      maxBundleBytes: 128 * 1024,
      maxEvents: 16,
      maxBundleLifetimeMs: 600_000,
      checkpointFreshnessMs: 600_000,
      nowMs: (bundle.expires - 60) * 1000,
      trustedCheckpointStore: new InMemoryTrustedC2spCheckpointStore(),
    });
    expect(result.bundle.signature.kid).toBe(kid);
    expect(result.bundle.state.loggedState).toBe(state);
    expect(result.events).toHaveLength(events);
  });

  it.each([
    ['https://log.dev.knownsystems.ai', KNOWN_DEVELOPMENT_POLICY, KNOWN_DEVELOPMENT_BUNDLE_KEY, KNOWN_DEVELOPMENT_OVERFLOW_BUNDLE_KEY],
    ['https://log.stg.knownsystems.ai', KNOWN_STAGING_POLICY, KNOWN_STAGING_BUNDLE_KEY, KNOWN_STAGING_OVERFLOW_BUNDLE_KEY],
    ['https://log.knownsystems.ai', KNOWN_PRODUCTION_POLICY, KNOWN_PRODUCTION_BUNDLE_KEY, KNOWN_PRODUCTION_OVERFLOW_BUNDLE_KEY],
  ] as const)('selects the exact Known profile for %s with the managed defaults', async (logPrefix, policy, bundleKey, overflowBundleKey) => {
    const fetcher: C2spBoundedResourceFetcher = {
      fetchBounded: vi.fn(async () => { throw new Error('not called during catalog construction'); }),
      securityGuarantees: requiredC2spResourceFetchGuarantees,
    };
    const store = new InMemoryTrustedC2spCheckpointStore();
    const registry = await createDnsidManagedVerificationRegistry({
      resourceFetcher: fetcher,
      trustedCheckpointStore: store,
    });
    const known = internals(registry.newReader(
      `c2sp-tlog:public:${logPrefix}#EREREREREREREREREREREQ`,
    ) as C2spTlogReader);

    expect(known.checkpointStore).toBe(store);
    expect(known.source.resourceFetcher).toBe(fetcher);
    expect(known.options).toMatchObject({ checkpointMaxAge: 600_000, allowedClockSkew: 0 });
    expect(known.options.streamBundle).toMatchObject({
      policyDocument: new TextEncoder().encode(policy),
      bundleKeys: [
        parseSignedNoteVerifierKey(bundleKey),
        parseSignedNoteVerifierKey(overflowBundleKey),
      ],
      maxBundleLifetimeMs: 600_000,
      checkpointFreshnessMs: 600_000,
      required: undefined,
    });
  });

  // Reviewed service fixtures captured from the Known logs on 2026-11-11 and 2026-11-12:
  // three-event streams (issuance, key rotation, revocation) over the 4096-byte KMS limit,
  // signed by each log's secret-held key, and a two-event staging stream small enough for
  // the KMS bundle key.
  it.each([
    ['https://log.dev.knownsystems.ai', 'c2sp-known-dev-stream-bundle-overflow-key.json', 'dnsid-stream-bundle+ad87852b', 3],
    ['https://log.stg.knownsystems.ai', 'c2sp-known-staging-stream-bundle-kms-key.json', 'dnsid-stream-bundle+85bbbf6c', 2],
    ['https://log.stg.knownsystems.ai', 'c2sp-known-staging-stream-bundle-overflow-key.json', 'dnsid-stream-bundle+64bf74b3', 3],
    ['https://log.knownsystems.ai', 'c2sp-known-production-stream-bundle-overflow-key.json', 'dnsid-stream-bundle+4296adc5', 3],
  ] as const)('verifies the Known bundle from %s (%s) under its managed profile', async (logPrefix, fixture, kid, events) => {
    const registry = await createDnsidManagedVerificationRegistry();
    const known = internals(registry.newReader(
      `c2sp-tlog:public:${logPrefix}#EREREREREREREREREREREQ`,
    ) as C2spTlogReader);
    const trust = known.options.streamBundle!;
    const bytes = readFileSync(new URL(`./vectors/${fixture}`, import.meta.url));
    const bundle = JSON.parse(bytes.toString('utf8'));
    const issuance = JSON.parse(Buffer.from(bundle.events[0].entry, 'base64url').toString('utf8'));
    const result = await verifyC2spStreamBundle(bytes, {
      expectedFqdn: bundle.fqdn,
      expectedLogReference: bundle.lr,
      policyBytes: trust.policyDocument,
      bundleKeys: trust.bundleKeys,
      entityKey: issuance.ek,
      maxBundleBytes: 128 * 1024,
      maxEvents: 16,
      maxBundleLifetimeMs: 600_000,
      checkpointFreshnessMs: 600_000,
      nowMs: (bundle.expires - 60) * 1000,
      trustedCheckpointStore: new InMemoryTrustedC2spCheckpointStore(),
    });
    expect(result.bundle.signature.kid).toBe(kid);
    expect(result.bundle.state.loggedState).toBe('REVOKED');
    expect(result.events).toHaveLength(events);
  });

  // Parsing checks only the key ID's length, so recompute each signed-note key ID
  // (the first four bytes of SHA-256 over name, newline, type byte and key) for every
  // managed bundle key, to catch a key copied with the wrong ID before its log uses it.
  it('pins managed bundle keys whose IDs match their key bytes', async () => {
    const registry = await createDnsidManagedVerificationRegistry();
    for (const entry of vector.catalog) {
      const reader = internals(registry.newReader(
        `c2sp-tlog:${entry.scope}:${entry.logPrefix}#EREREREREREREREREREREQ`,
      ) as C2spTlogReader);
      const keys = reader.options.streamBundle!.bundleKeys;
      expect(keys.length, entry.logPrefix).toBeGreaterThan(0);
      for (const key of keys) {
        const computed = createHash('sha256')
          .update(`${key.name}\n`)
          .update(key.signatureType ?? new Uint8Array([1]))
          .update(key.keyBytes)
          .digest()
          .subarray(0, 4);
        expect(Buffer.from(computed).toString('hex'), entry.logPrefix).toBe(Buffer.from(key.keyId!).toString('hex'));
      }
    }
  });
});
