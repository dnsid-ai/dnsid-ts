import { generateKeyPairSync, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  createOrReuseAwsKmsKeyProvider,
  type AwsKmsBootstrapFacade,
} from '@dnsid-ai/key-aws';

// Authority: clean-test-handoff.md frozen canonical-ID contract and public README.
// Mode: fake-only (scripted KMS responses); real local Node cryptography.
// No network, AWS client, private package imports, lifecycle or publication calls.
const ALIAS = 'alias/canonical-regression';
const UUID = '12345678-1234-4abc-8def-1234567890ab';
const OTHER_UUID = '87654321-4321-4def-8abc-ba0987654321';
const ARN = `arn:aws:kms:us-east-1:123456789012:key/${UUID}`;
const OTHER_ARN = `arn:aws:kms:us-east-1:123456789012:key/${OTHER_UUID}`;
const CONFIG = { aliasName: ALIAS, algorithm: 'ED25519_SHA_512' as const };
const IDENTITIES = [
  { label: 'UUID', id: UUID, other: OTHER_UUID },
  { label: 'ARN', id: ARN, other: OTHER_ARN },
] as const;
const ENDINGS = [
  { label: 'LF', value: '\n' },
  { label: 'CR', value: '\r' },
  { label: 'CRLF', value: '\r\n' },
  { label: 'LINE SEPARATOR', value: '\u2028' },
  { label: 'PARAGRAPH SEPARATOR', value: '\u2029' },
] as const;
type Route = 'existing' | 'create' | 'conflict';
type PublicResponse = Awaited<ReturnType<AwsKmsBootstrapFacade['getPublicKey']>>;

function fixture() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spki = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));
  const publicJwk = publicKey.export({ format: 'jwk' });
  return {
    publicKey,
    publicJwk,
    response(keyId: string): PublicResponse {
      return {
        keyId,
        publicKey: spki,
        keySpec: 'ECC_NIST_EDWARDS25519',
        keyUsage: 'SIGN_VERIFY',
        signingAlgorithms: ['ED25519_SHA_512'],
      };
    },
    sign(message: Uint8Array) {
      return new Uint8Array(nodeSign(null, message, privateKey));
    },
  };
}

function harness(options: {
  route: Route;
  candidateId: string;
  candidatePublicId?: string;
  winnerId: string;
}) {
  const crypto = fixture();
  const calls = {
    reads: [] as string[],
    creates: [] as unknown[],
    acquisitions: [] as { aliasName: string; targetKeyId: string }[],
    signs: [] as string[],
  };
  let aliasReads = 0;
  const client: AwsKmsBootstrapFacade = {
    async getPublicKey(input) {
      calls.reads.push(input.keyId);
      if (input.keyId === ALIAS) {
        aliasReads += 1;
        if (options.route !== 'existing' && aliasReads === 1) {
          throw Object.assign(new Error('Scripted missing alias'), { name: 'NotFoundException' });
        }
        return crypto.response(options.winnerId);
      }
      if (input.keyId === options.candidateId) {
        return crypto.response(options.candidatePublicId ?? options.candidateId);
      }
      if (input.keyId === options.winnerId) return crypto.response(options.winnerId);
      throw new Error('Unexpected public-key reference');
    },
    async createSigningKey(input) {
      calls.creates.push(input);
      return { keyId: options.candidateId };
    },
    async createAlias(input) {
      calls.acquisitions.push({ ...input });
      if (options.route === 'conflict') {
        throw Object.assign(new Error('Scripted alias race'), { name: 'AlreadyExistsException' });
      }
    },
    async sign(input) {
      calls.signs.push(input.keyId);
      return {
        keyId: input.keyId,
        signature: crypto.sign(input.message),
        signingAlgorithm: 'ED25519_SHA_512',
      };
    },
  };
  return { client, calls, crypto };
}

const INVALID_CASES = IDENTITIES.flatMap((identity) =>
  ENDINGS.map((ending) => ({
    name: `${identity.label} + ${ending.label}`,
    canonical: identity.id,
    other: identity.other,
    invalid: identity.id + ending.value,
  })),
);

describe('bootstrap canonical key identity boundaries (code-blind regression)', () => {
  it.each(INVALID_CASES)('E: existing alias rejects $name without creating', async ({ invalid, other }) => {
    // Given valid SPKI/signing metadata and a noncanonical existing identity.
    const h = harness({ route: 'existing', candidateId: other, winnerId: invalid });
    // When opening the exact caller-selected alias, then reject rather than trim/return it.
    await expect(createOrReuseAwsKmsKeyProvider(h.client, CONFIG)).rejects.toMatchObject({ name: 'ArgumentError' });
    expect(h.calls.creates).toEqual([]);
    expect(h.calls.acquisitions).toEqual([]);
    expect(h.calls.signs).toEqual([]);
  });

  it.each(INVALID_CASES)('C: creation response rejects $name before acquisition', async ({ invalid, canonical }) => {
    // Given an initially missing alias and a noncanonical candidate allocation ID.
    const h = harness({ route: 'create', candidateId: invalid, winnerId: canonical });
    // When bootstrapping, then fail before attempting alias acquisition.
    await expect(createOrReuseAwsKmsKeyProvider(h.client, CONFIG)).rejects.toMatchObject({ name: 'ArgumentError' });
    expect(h.calls.creates).toHaveLength(1);
    expect(h.calls.acquisitions).toEqual([]);
    expect(h.calls.signs).toEqual([]);
  });

  it.each(INVALID_CASES)('P: candidate public response rejects $name before acquisition', async ({ invalid, canonical }) => {
    // Given a canonical allocated candidate but noncanonical public response identity.
    const h = harness({ route: 'create', candidateId: canonical, candidatePublicId: invalid, winnerId: canonical });
    // When validating candidate public material, then reject without normalization/acquisition.
    await expect(createOrReuseAwsKmsKeyProvider(h.client, CONFIG)).rejects.toMatchObject({ name: 'ArgumentError' });
    expect(h.calls.creates).toHaveLength(1);
    expect(h.calls.reads).toContain(canonical);
    expect(h.calls.acquisitions).toEqual([]);
    expect(h.calls.signs).toEqual([]);
  });

  it.each(INVALID_CASES)('W: conflict winner rejects $name without candidate fallback', async ({ invalid, other }) => {
    // Given a valid candidate, a lost acquisition race and an invalid resolved winner.
    const h = harness({ route: 'conflict', candidateId: other, winnerId: invalid });
    // When resolving the winner, then reject, never return the valid losing candidate.
    await expect(createOrReuseAwsKmsKeyProvider(h.client, CONFIG)).rejects.toMatchObject({ name: 'ArgumentError' });
    expect(h.calls.creates).toHaveLength(1);
    expect(h.calls.acquisitions).toEqual([{ aliasName: ALIAS, targetKeyId: other }]);
    expect(h.calls.reads.filter((id) => id === ALIAS)).toHaveLength(2);
    expect(h.calls.signs).toEqual([]);
  });

  it.each(IDENTITIES)('B: distinct canonical $label candidate/public identities reject before acquisition', async ({ id, other }) => {
    // Given independently canonical but different allocation/public response identities.
    const h = harness({ route: 'create', candidateId: id, candidatePublicId: other, winnerId: id });
    // When validating identity binding, then reject rather than publish a different key.
    await expect(createOrReuseAwsKmsKeyProvider(h.client, CONFIG)).rejects.toMatchObject({ name: 'ArgumentError' });
    expect(h.calls.creates).toHaveLength(1);
    expect(h.calls.reads).toContain(id);
    expect(h.calls.acquisitions).toEqual([]);
    expect(h.calls.signs).toEqual([]);
  });

  const SUCCESS_CASES = IDENTITIES.flatMap((identity) =>
    (['existing', 'create', 'conflict'] as const).map((route) => ({ ...identity, route, name: `${identity.label}/${route}` })),
  );
  it.each(SUCCESS_CASES)('V: exact canonical $name remains usable unchanged', async ({ id, other, route }) => {
    // Given exact valid canonical IDs and independently generated real signing material.
    const candidateId = route === 'conflict' ? other : id;
    const h = harness({ route, candidateId, winnerId: id });
    // When bootstrapping, then expose the exact winner and a matching usable standalone signer.
    const result = await createOrReuseAwsKmsKeyProvider(h.client, CONFIG);
    expect(result.keyRef).toBe(id);
    expect(result.keyProvider.stateSnapshot().activeKeyId).toBe(id);
    const jwk = await result.keyProvider.signingKey();
    expect(jwk).toMatchObject({ kid: id, alg: 'EdDSA', kty: h.crypto.publicJwk.kty, crv: h.crypto.publicJwk.crv, x: h.crypto.publicJwk.x });
    const payload = new TextEncoder().encode('canonical bootstrap identity regression');
    const signature = await result.keyProvider.sign(payload);
    expect(nodeVerify(null, payload, h.crypto.publicKey, signature)).toBe(true);
    expect(h.calls.signs).toContain(id);
    expect(h.calls.signs.every((keyId) => keyId === id)).toBe(true);
    if (route === 'existing') {
      expect(h.calls.creates).toEqual([]);
      expect(h.calls.acquisitions).toEqual([]);
    } else {
      expect(h.calls.creates).toHaveLength(1);
      expect(h.calls.acquisitions).toEqual([{ aliasName: ALIAS, targetKeyId: candidateId }]);
    }
  });
});
