import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
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
