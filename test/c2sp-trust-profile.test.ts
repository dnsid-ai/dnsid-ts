import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  c2spTlogTrustEpochs,
  c2spTlogTrustProfilePolicy,
  createC2spTlogEpochPolicy,
  createC2spTlogVerificationRegistry,
  parseC2spTlogTrustProfile,
  parseSignedNoteVerifierKey,
} from '@dnsid-ai/log-c2sp-tlog';

const POLICY = 'log log.example+3db4ee08+AcqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\n'
  + 'witness primary witness.example+da76602f+BG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx\n'
  + 'quorum primary\n';
const KEYS = [
  'dnsid-stream-bundle+dfa43feb+AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  'dnsid-stream-bundle+85e03385+AQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
];

function bytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

function verifierKey(name: string, type: number, publicKey: Uint8Array): string {
  const payload = Buffer.concat([Buffer.from([type]), Buffer.from(publicKey)]);
  const keyId = createHash('sha256').update(name).update('\n').update(payload).digest('hex').slice(0, 8);
  return `${name}+${keyId}+${payload.toString('base64')}`;
}

function profile(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 1,
    scope: 'public',
    log_prefix: 'https://log.example',
    tlog_policy: POLICY,
    bundle_verifier_keys: KEYS,
    ...overrides,
  };
}

describe('C2SP tlog trust profiles', () => {
  it('accepts rotation keys and constrains registry readers to the exact log', async () => {
    const trust = parseC2spTlogTrustProfile(bytes(profile()));
    if (trust.version !== 1) throw new Error("expected a version 1 profile");
    expect(trust.bundleVerifierKeys).toHaveLength(2);
    await expect(createC2spTlogVerificationRegistry({ trustProfile: trust }))
      .rejects.toThrow(/maxBundleLifetimeMs/);
    const registry = await createC2spTlogVerificationRegistry({
      trustProfile: trust,
      checkpointMaxAge: 60_000,
      maxBundleLifetimeMs: 60_000,
    });
    expect(() => registry.newReader('c2sp-tlog:public:https://log.example#stream')).not.toThrow();
    expect(() => registry.newReader('c2sp-tlog:public:https://other.example#stream')).toThrow(/trust profile/);
    await expect(createC2spTlogVerificationRegistry({
      trustProfile: trust,
      policyDocument: trust.policyDocument,
    })).rejects.toThrow(/exactly one/);
    await expect(createC2spTlogVerificationRegistry({
      trustProfile: trust,
      bundleVerifierKeys: trust.bundleVerifierKeys,
      maxBundleLifetimeMs: 60_000,
    })).rejects.toThrow(/mutually exclusive/);
  });

  it.each([
    ['unknown member', bytes(profile({ extra: true }))],
    ['policy origin mismatch', bytes(profile({ log_prefix: 'https://other.example' }))],
    ['wrong signer name', bytes(profile({ bundle_verifier_keys: [KEYS[0]!.replace('dnsid-stream-bundle', 'other')] }))],
    ['invalid key hash', bytes(profile({ bundle_verifier_keys: [KEYS[0]!.replace('dfa43feb', '00000000')] }))],
    ['duplicate signer', bytes(profile({ bundle_verifier_keys: [KEYS[0], KEYS[0]] }))],
    ['checkpoint key overlap', bytes(profile({
      tlog_policy: POLICY.replace(/^log .+$/m, `log ${verifierKey('log.example', 1, parseSignedNoteVerifierKey(KEYS[0]!).keyBytes)}`),
      bundle_verifier_keys: [KEYS[0]],
    }))],
    ['unsupported version', bytes(profile({ version: 2 }))],
    ['noncanonical prefix', bytes(profile({ log_prefix: 'https://log.example/' }))],
    ['duplicate member', new TextEncoder().encode(`{"version":1,"version":1,"scope":"public","log_prefix":"https://log.example","tlog_policy":${JSON.stringify(POLICY)},"bundle_verifier_keys":["${KEYS[0]}"]}`)],
  ])('rejects %s', (_name, document) => {
    expect(() => parseC2spTlogTrustProfile(document)).toThrow();
  });

  it('rejects malformed programmatic profiles without throwing a runtime type error', async () => {
    await expect(createC2spTlogVerificationRegistry({
      trustProfile: { version: 1, scope: 'public', logPrefix: 'https://log.example', policyDocument: new Uint8Array(), bundleVerifierKeys: 1 } as never,
    })).rejects.toThrow('invalid C2SP tlog trust profile');
  });
});

describe('C2SP tlog trust profile version 2 limits', () => {
  const SECOND_LOG = verifierKey('log.example', 1, Buffer.alloc(32, 7));
  function epoch(id: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return { id, tlog_policy: POLICY, bundle_verifier_keys: [KEYS[0]], ...overrides };
  }
  function v2(epochs: unknown[]): Uint8Array {
    return bytes({ version: 2, scope: 'public', log_prefix: 'https://log.example', epochs });
  }
  // Epochs that differ in policy bytes only, so none shares both kid and policy.
  const distinct = (count: number) => Array.from({ length: count }, (_, index) => epoch(`e${index}`, { tlog_policy: `${POLICY}#${index}\n` }));

  it('accepts up to 8 epochs and rejects 9', () => {
    expect(c2spTlogTrustEpochs(parseC2spTlogTrustProfile(v2(distinct(8)))).map(e => e.id)).toHaveLength(8);
    expect(() => parseC2spTlogTrustProfile(v2(distinct(9)))).toThrow(/between 1 and 8 epochs/);
  });

  it('bounds epoch ids at 64 characters', () => {
    expect(() => parseC2spTlogTrustProfile(v2([epoch('a'.repeat(64))]))).not.toThrow();
    expect(() => parseC2spTlogTrustProfile(v2([epoch('a'.repeat(65))]))).toThrow(/epoch id/);
    expect(() => parseC2spTlogTrustProfile(v2([epoch('')]))).toThrow(/epoch id/);
    expect(() => parseC2spTlogTrustProfile(v2([epoch('legacy/1')]))).toThrow(/epoch id/);
  });

  it('keeps version 1 multi-log-line policies and rejects them inside an epoch', () => {
    const twoLogs = POLICY.replace(/^(log .+)$/m, `$1\nlog ${SECOND_LOG}`);
    const v1 = parseC2spTlogTrustProfile(bytes(profile({ tlog_policy: twoLogs })));
    expect(c2spTlogTrustProfilePolicy(v1).origins['log.example']!.logKeys).toHaveLength(2);
    expect(() => parseC2spTlogTrustProfile(v2([epoch('e', { tlog_policy: twoLogs })]))).toThrow(/exactly one log key/);
  });

  it('rejects an epoch log key whose key hash does not match the key', () => {
    const [, hash] = POLICY.split('\n')[0]!.split('+');
    expect(() => parseC2spTlogTrustProfile(v2([epoch('e', { tlog_policy: POLICY.replace(hash!, '00000000') })]))).toThrow(/key hash/);
  });

  it('rejects mixed origins in a programmatic epoch set', () => {
    const other = POLICY.replace(/^log log\.example\+\S+/m, `log ${verifierKey('other.example', 1, Buffer.alloc(32, 9))}`);
    const [first] = c2spTlogTrustEpochs(parseC2spTlogTrustProfile(v2([epoch('a')])));
    expect(() => createC2spTlogEpochPolicy([first!, { ...first!, id: 'b', policyDocument: new TextEncoder().encode(other) }]))
      .toThrow(/exactly one log key, named for the log origin/);
  });

  it('rejects a version 2 profile that also carries top-level single-policy fields programmatically', async () => {
    const trust = parseC2spTlogTrustProfile(v2([epoch('a')]));
    await expect(createC2spTlogVerificationRegistry({
      trustProfile: { ...trust, policyDocument: new Uint8Array() } as never,
      maxBundleLifetimeMs: 60_000,
    })).rejects.toThrow(/in epochs/);
  });
});
