import { generateKeyPairSync, sign, verify, createPublicKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createOrReuseAwsKmsKeyProvider, type AwsKmsBootstrapFacade } from '@dnsid-ai/key-aws';

// Mode: fake-only KMS; real local Ed25519 crypto. Public API only.
// Contract: docs/reference/dnsid-key-aws.md, AwsKmsFacade.getPublicKey and
// AwsKmsBootstrapFacade inheritance; packages/key-aws/README.md, Explicit create or reuse.
const UUID = '12345678-1234-4abc-8def-1234567890ab';
const ARN = `arn:aws:kms:us-east-1:123456789012:key/${UUID}`;
const OTHER = 'arn:aws:kms:us-east-1:123456789012:key/87654321-4321-4def-8abc-ba0987654321';
const ALIAS = 'alias/public-facade-identity';
const CONFIG = { aliasName: ALIAS, algorithm: 'ED25519_SHA_512' as const };
const fault = (name: string) => Object.assign(new Error(`scripted ${name}`), { name });
type PublicResponse = Awaited<ReturnType<AwsKmsBootstrapFacade['getPublicKey']>>;

function fixture(created: string, responseId: string | undefined, options: {
  conflict?: boolean;
  failure?: { stage: 'candidate' | 'acquire' | 'winner'; error: Error };
} = {}) {
  const candidate = generateKeyPairSync('ed25519');
  const winner = options.conflict ? generateKeyPairSync('ed25519') : candidate;
  const winnerId = options.conflict ? OTHER : responseId;
  const ledger: { action: string; id?: string }[] = [];
  let aliasReads = 0;
  const fixtureErrors: unknown[] = [];
  const violations: string[] = [];
  const candidateRequests: string[] = [];
  let candidateDelivered = 0;
  const guard = (message: string): never => {
    const error = new Error(message); fixtureErrors.push(error); throw error;
  };
  const record = (action: string, id?: string) => {
    ledger.push({ action, id });
    if (ledger.length > 12) guard('fixture finite-call budget exceeded');
  };
  const response = (keyId: string | undefined, key: typeof candidate): PublicResponse => ({
    keyId, publicKey: key.publicKey.export({ type: 'spki', format: 'der' }),
    keySpec: 'ECC_NIST_EDWARDS25519', keyUsage: 'SIGN_VERIFY', signingAlgorithms: ['ED25519_SHA_512'],
  });
  const candidateResponse = response(responseId, candidate);
  const winnerResponse = response(winnerId, winner);
  const client: AwsKmsBootstrapFacade & {
    disableKey(): Promise<void>; updateAlias(): Promise<void>; deleteAlias(): Promise<void>;
  } = {
    async getPublicKey(input) {
      record('get', input.keyId);
      if (input.keyId === ALIAS) {
        if (++aliasReads === 1) throw fault('NotFoundException');
        if (options.failure?.stage === 'winner') throw options.failure.error;
        return winnerResponse;
      }
      if (options.failure?.stage === 'candidate') throw options.failure.error;
      if (![created, responseId, winnerId].includes(input.keyId)) guard('unexpected reference');
      if (input.keyId === winnerId && options.conflict) return winnerResponse;
      candidateRequests.push(input.keyId);
      candidateDelivered++;
      return candidateResponse;
    },
    async createSigningKey() { record('create'); return { keyId: created }; },
    async createAlias(input) {
      record('acquire', input.targetKeyId);
      if (input.aliasName !== ALIAS) violations.push('unexpected alias name');
      if (options.failure?.stage === 'acquire') throw options.failure.error;
      if (options.conflict) throw fault('AlreadyExistsException');
    },
    async sign(input) {
      record('sign', input.keyId);
      if (input.keyId !== winnerId) violations.push('unexpected signing reference');
      if (input.signingAlgorithm !== 'ED25519_SHA_512') violations.push('unexpected signing algorithm');
      if (input.messageType !== 'RAW') violations.push('unexpected message type');
      return { keyId: winnerId, signingAlgorithm: 'ED25519_SHA_512', signature: sign(null, input.message, winner.privateKey) };
    },
    async scheduleKeyDeletion() { record('delete'); },
    async disableKey() { record('disable'); },
    async updateAlias() { record('retarget'); },
    async deleteAlias() { record('deleteAlias'); },
  };
  return { client, ledger, winner, candidate, winnerId, candidateResponse, candidateRequests,
    fixtureErrors, violations, get candidateDelivered() { return candidateDelivered; } };
}
function safe(h: ReturnType<typeof fixture>) {
  expect(h.fixtureErrors).toEqual([]);
  expect(h.violations).toEqual([]);
  expect(h.ledger.filter((x) => ['delete', 'disable', 'retarget', 'deleteAlias'].includes(x.action))).toEqual([]);
  expect(h.ledger.filter((x) => x.action === 'create')).toHaveLength(1);
  expect(h.ledger.length).toBeLessThanOrEqual(12);
}

describe('public bootstrap facade identity contract [fake-only]', () => {
  it.each([
    { label: 'permitted UUID to matching ARN', created: UUID, returned: ARN },
    { label: 'unchanged UUID to UUID', created: UUID, returned: UUID },
    { label: 'unchanged ARN to ARN', created: ARN, returned: ARN },
  ])('Given $label, when acquired, then canonical winner remains usable', async ({ created, returned }) => {
    const h = fixture(created, returned);
    const pending = createOrReuseAwsKmsKeyProvider(h.client, CONFIG);
    // Assertion red must be rejection of this permitted public-contract success, not setup failure.
    await expect(pending).resolves.toMatchObject({ keyRef: returned });
    const { keyProvider } = await pending;
    expect(keyProvider.stateSnapshot().activeKeyId).toBe(returned);
    expect(await keyProvider.listKeyIds()).toEqual([returned]);
    expect(await keyProvider.signingKey()).toMatchObject({ ...h.winner.publicKey.export({ format: 'jwk' }), kid: returned, alg: 'EdDSA' });
    const payload = Buffer.from('public facade identity binding');
    expect(verify(null, payload, h.winner.publicKey, await keyProvider.sign(payload))).toBe(true);
    expect(h.ledger.filter((x) => x.action === 'acquire')).toHaveLength(1);
    expect(h.ledger.filter((x) => x.action === 'get' && x.id === ALIAS).length).toBeLessThanOrEqual(2);
    safe(h);
  });

  it('Given a permitted mixed-form candidate losing acquisition, when reread, then only the unrelated winner signs', async () => {
    const h = fixture(UUID, ARN, { conflict: true });
    const pending = createOrReuseAwsKmsKeyProvider(h.client, CONFIG);
    await expect(pending).resolves.toMatchObject({ keyRef: OTHER });
    const { keyProvider } = await pending;
    expect(keyProvider.stateSnapshot().activeKeyId).toBe(OTHER);
    expect(await keyProvider.signingKey()).toMatchObject({ ...h.winner.publicKey.export({ format: 'jwk' }), kid: OTHER });
    const payload = Buffer.from('winner is not the losing mixed-form candidate');
    const signature = await keyProvider.sign(payload);
    expect(verify(null, payload, h.winner.publicKey, signature)).toBe(true);
    expect(verify(null, payload, h.candidate.publicKey, signature)).toBe(false);
    expect(h.ledger.filter((x) => x.action === 'get' && x.id === ALIAS)).toHaveLength(2);
    expect(h.ledger.filter((x) => x.action === 'acquire')).toHaveLength(1);
    safe(h);
  });

  it.each([
    { label: 'unrelated canonical ARN', id: OTHER },
    { label: 'missing ID', id: undefined },
    { label: 'empty ID', id: '' },
    { label: 'mutable alias', id: ALIAS },
    { label: 'mutable alias ARN', id: 'arn:aws:kms:us-east-1:123456789012:alias/public-facade-identity' },
  ])('Given $label in candidate response, when bootstrapping, then reject before acquisition', async ({ label, id }) => {
    const h = fixture(UUID, id);
    // GIVEN a prepared identity defect with otherwise valid independently parsed SPKI.
    expect(h.candidateResponse.keyId).toBe(id);
    const publicKey = createPublicKey({ key: Buffer.from(h.candidateResponse.publicKey), type: 'spki', format: 'der' });
    expect(publicKey.asymmetricKeyType).toBe('ed25519');
    expect(publicKey.export({ format: 'jwk' })).toEqual(h.candidate.publicKey.export({ format: 'jwk' }));
    expect(h.candidateResponse).toMatchObject({ keySpec: 'ECC_NIST_EDWARDS25519',
      keyUsage: 'SIGN_VERIFY', signingAlgorithms: ['ED25519_SHA_512'] });
    let rejected = false;
    let caught: unknown;
    try { await createOrReuseAwsKmsKeyProvider(h.client, CONFIG); }
    catch (error) { rejected = true; caught = error; }
    expect(rejected).toBe(true);
    for (const error of h.fixtureErrors) expect(caught).not.toBe(error);
    expect(h.candidateDelivered).toBe(1);
    expect(h.candidateRequests).toEqual([UUID]);
    console.info(JSON.stringify({ proof: 'candidate-response-delivery', label, id: id ?? null,
      delivered: h.candidateDelivered, requests: h.candidateRequests,
      fixtureErrors: h.fixtureErrors.length, violations: h.violations }));
    expect(h.ledger.map((x) => x.action)).toEqual(['get', 'create', 'get']);
    safe(h);
  });

  it.each(['candidate', 'acquire', 'winner'] as const)(
    'Given native failure at %s, when bootstrapping, then preserve exact error without retry or destructive action', async (stage) => {
      const error = fault(stage === 'acquire' ? 'TimeoutError' : 'AccessDeniedException');
      const h = fixture(UUID, ARN, { conflict: stage === 'winner', failure: { stage, error } });
      await expect(createOrReuseAwsKmsKeyProvider(h.client, CONFIG)).rejects.toBe(error);
      const actions = stage === 'candidate' ? ['get', 'create', 'get']
        : stage === 'acquire' ? ['get', 'create', 'get', 'acquire']
        : ['get', 'create', 'get', 'acquire', 'get'];
      expect(h.ledger.map((x) => x.action)).toEqual(actions);
      safe(h);
    },
  );
});
