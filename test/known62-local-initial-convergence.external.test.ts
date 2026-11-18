import { describe, expect, it } from 'vitest';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
import { createPublicKey, verify, type webcrypto } from 'node:crypto';
import { lstat, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';

type Algorithm = 'EdDSA' | 'ES256';
type PublicJwk = Awaited<ReturnType<LocalKeyProvider['signingKey']>>;
const cases: { label: string; algorithm: Algorithm; omit: boolean }[] = [
  { label: 'default EdDSA', algorithm: 'EdDSA', omit: true },
  { label: 'explicit EdDSA', algorithm: 'EdDSA', omit: false },
  { label: 'explicit ES256', algorithm: 'ES256', omit: false },
];

async function absent(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true;
    throw error;
  }
}

async function isolated(run: (store: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), 'known62-local-proof-'));
  // Exact ownership receipt also supports parent cleanup after an external timeout.
  console.info('known62 owned-directory', directory);
  try {
    await run(join(directory, 'keys.json'));
  } finally {
    // No cleanup retry, and no deletion of anything outside this allocated directory.
    await rm(directory, { recursive: true, force: true, maxRetries: 0 });
    expect(await absent(directory), 'owned directory cleanup').toBe(true);
    console.info('known62 cleaned-directory', directory);
  }
}

function identity(jwk: PublicJwk, algorithm: Algorithm) {
  expect(jwk.alg).toBe(algorithm);
  expect(typeof jwk.kid).toBe('string');
  expect(jwk.kid).not.toContain('#');
  for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']) {
    expect(Object.prototype.hasOwnProperty.call(jwk, field), `public JWK excludes ${field}`).toBe(false);
  }
  expect(jwk.kty).toBe(algorithm === 'EdDSA' ? 'OKP' : 'EC');
  expect(jwk.crv).toBe(algorithm === 'EdDSA' ? 'Ed25519' : 'P-256');
  expect(typeof jwk.x).toBe('string');
  if (algorithm === 'ES256') expect(typeof jwk.y).toBe('string');
  // Compare public identity, not incidental JWK metadata or object property order.
  return { kid: jwk.kid, alg: jwk.alg, kty: jwk.kty, crv: jwk.crv, x: jwk.x,
    ...(algorithm === 'ES256' ? { y: jwk.y } : {}) };
}

async function signedByCommonIdentity(
  provider: LocalKeyProvider, common: PublicJwk, algorithm: Algorithm, label: string,
): Promise<void> {
  const payload = Buffer.from(`known62 independent signature: ${label}`, 'utf8');
  const signature = await provider.sign(payload);
  const key = createPublicKey({ key: common as webcrypto.JsonWebKey, format: 'jwk' });
  if (algorithm === 'EdDSA') {
    expect(verify(null, payload, key, signature), label).toBe(true);
  } else {
    // Public API says raw bytes, not which ECDSA encoding. Accept either standard.
    const accepted: string[] = [];
    for (const dsaEncoding of ['der', 'ieee-p1363'] as const) {
      try {
        if (verify('sha256', payload, { key, dsaEncoding }, signature)) accepted.push(dsaEncoding);
      } catch {
        // A format decoder can reject bytes belonging to the other encoding.
      }
    }
    console.info('known62 ES256 verification', { label, accepted });
    expect(accepted.length, `${label}: valid DER or IEEE-P1363 signature`).toBeGreaterThan(0);
  }
}

function create(store: string, selection: (typeof cases)[number]) {
  return selection.omit
    ? LocalKeyProvider.load(store, true)
    : LocalKeyProvider.load(store, true, selection.algorithm);
}

describe('local initial create/reuse — public API, real filesystem and Node crypto', () => {
  for (const selection of cases) {
    it(`${selection.label}: initial overlap converges and ordinary reopen signs [Mode: real-capable]`, async () => {
      await isolated(async (store) => {
        // GIVEN an allocated absent store and six explicit opt-in callers.
        expect(await absent(store)).toBe(true);
        let release!: () => void;
        const gate = new Promise<void>((resolve) => { release = resolve; });
        let ready = 0;
        const attempts = Array.from({ length: 6 }, (_, index) => (async () => {
          ready += 1;
          await gate;
          console.info('known62 load-start', { selection: selection.label, index });
          return create(store, selection);
        })());
        // WHEN all six callers are waiting, release one deterministic async gate.
        // No sleeps, retries, private hooks, or signing until every load settles.
        expect(ready).toBe(6);
        release();
        const outcomes = await Promise.allSettled(attempts);
        const successes: { index: number; provider: LocalKeyProvider }[] = [];
        for (const [index, outcome] of outcomes.entries()) {
          if (outcome.status === 'fulfilled') {
            console.info('known62 load-outcome', { selection: selection.label, index, status: 'fulfilled' });
            successes.push({ index, provider: outcome.value });
          } else {
            console.info('known62 load-outcome', { selection: selection.label, index,
              status: 'rejected', reason: inspect(outcome.reason, { depth: 4 }) });
          }
        }
        // THEN no failures disappear, and zero successes cannot establish convergence.
        expect(outcomes).toHaveLength(6);
        expect(successes.length, 'at least one initial create must succeed').toBeGreaterThan(0);
        const common = await successes[0]!.provider.signingKey();
        const expected = identity(common, selection.algorithm);
        for (const { index, provider } of successes) {
          expect(identity(await provider.signingKey(), selection.algorithm)).toEqual(expected);
          await signedByCommonIdentity(provider, common, selection.algorithm, `${selection.label}/attempt-${index}`);
        }
        const reopened = await LocalKeyProvider.load(store);
        expect(identity(await reopened.signingKey(), selection.algorithm)).toEqual(expected);
        await signedByCommonIdentity(reopened, common, selection.algorithm, `${selection.label}/ordinary-reopen`);
      });
    }, 20_000);

    it(`${selection.label}: established store reuses identity [Mode: real-capable]`, async () => {
      await isolated(async (store) => {
        // GIVEN an established identity created with an explicit opt-in.
        const initial = await create(store, selection);
        const common = await initial.signingKey();
        const expected = identity(common, selection.algorithm);
        await signedByCommonIdentity(initial, common, selection.algorithm, `${selection.label}/established-initial`);
        // WHEN create-if-missing is used again with matching or omitted selection.
        const reused = await create(store, selection);
        // THEN it reuses the identity and remains usable; no mutation is requested.
        expect(identity(await reused.signingKey(), selection.algorithm)).toEqual(expected);
        await signedByCommonIdentity(reused, common, selection.algorithm, `${selection.label}/explicit-reuse`);
        const reopened = await LocalKeyProvider.load(store);
        expect(identity(await reopened.signingKey(), selection.algorithm)).toEqual(expected);
        await signedByCommonIdentity(reopened, common, selection.algorithm, `${selection.label}/reuse-reopen`);
      });
    }, 20_000);
  }

  it('ordinary absent-store load rejects without creating the store [Mode: real-capable]', async () => {
    await isolated(async (store) => {
      // GIVEN an absent store; WHEN loading without creation permission.
      expect(await absent(store)).toBe(true);
      const [outcome] = await Promise.allSettled([LocalKeyProvider.load(store)]);
      console.info('known62 ordinary-absent outcome', outcome?.status === 'rejected'
        ? { status: outcome.status, reason: inspect(outcome.reason, { depth: 4 }) }
        : { status: outcome?.status });
      // THEN reject, with no exception class/message or incidental-file assertion.
      expect(outcome?.status).toBe('rejected');
      expect(await absent(store)).toBe(true);
    });
  }, 20_000);
});
