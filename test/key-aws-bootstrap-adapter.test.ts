import { createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  AlreadyExistsException, CreateAliasCommand, CreateKeyCommand,
  DependencyTimeoutException, GetPublicKeyCommand, KMSInternalException,
  NotFoundException, SignCommand,
  type CreateKeyCommandOutput, type GetPublicKeyCommandOutput,
  type KMSClient, type SignCommandOutput,
} from '@aws-sdk/client-kms';
import {
  AwsSdkKmsFacade, createOrReuseAwsKmsKeyProvider,
  type AwsKmsSigningAlgorithm,
} from '@dnsid-ai/key-aws';

// Explicit alias bootstrap preserves native AWS errors and winner identity.
// Contract: packages/key-aws/README.md; AWS SDK v3 public KMS declarations.
// Mode: fake-only (KMS send boundary).
// Crypto and AWS command objects are real; no cloud client or credentials are used.
const aliasName = 'alias/dnsid-bootstrap-adapter';
const candidateId = '1234abcd-12ab-34cd-56ef-1234567890ab';
const winnerId = '0987dcba-09fe-87dc-65ba-ab0987654321';
const arn = (id: string) => `arn:aws:kms:us-east-1:111122223333:key/${id}`;
type Command = CreateAliasCommand | CreateKeyCommand | GetPublicKeyCommand | SignCommand;

function facade(send: (command: Command) => Promise<unknown>): AwsSdkKmsFacade {
  // Only the SDK send boundary is substituted; commands are not mocked.
  return new AwsSdkKmsFacade({ send } as unknown as KMSClient);
}

function fixture(algorithm: AwsKmsSigningAlgorithm) {
  const pair = algorithm === 'ECDSA_SHA_256'
    ? generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    : generateKeyPairSync('ed25519');
  return {
    ...pair,
    keySpec: algorithm === 'ECDSA_SHA_256' ? 'ECC_NIST_P256' as const : 'ECC_NIST_EDWARDS25519' as const,
    publicKeyDer: pair.publicKey.export({ type: 'spki', format: 'der' }),
    digest: algorithm === 'ECDSA_SHA_256' ? 'sha256' : null,
    jwsAlg: algorithm === 'ECDSA_SHA_256' ? 'ES256' : 'EdDSA',
  };
}

function serviceError(kind: 'exists' | 'internal' | 'timeout' | 'missing') {
  const options = { message: 'native SDK rejection fixture', $metadata: { requestId: 'offline-fixture' } };
  switch (kind) {
    case 'exists': return new AlreadyExistsException(options);
    case 'internal': return new KMSInternalException(options);
    case 'timeout': return new DependencyTimeoutException(options);
    case 'missing': return new NotFoundException(options);
  }
}

function kmsScenario(algorithm: AwsKmsSigningAlgorithm, mode: 'existing' | 'missing' | 'conflict', resolutionError?: Error) {
  const candidate = fixture(algorithm);
  const winner = fixture(algorithm);
  const commands: Command[] = [];
  let aliasReads = 0;
  let aliasTarget = mode === 'existing' ? winnerId : undefined;
  const client = facade(async (command) => {
    commands.push(command);
    if (command instanceof GetPublicKeyCommand) {
      let id = command.input.KeyId;
      if (id === aliasName) {
        aliasReads++;
        if (aliasReads === 1 && mode !== 'existing') throw serviceError('missing');
        if (mode === 'conflict' && resolutionError) throw resolutionError;
        id = aliasTarget;
      }
      // AWS accepts either a key UUID or key ARN as input, but GetPublicKey's
      // output KeyId is the key ARN, not an alias or bare UUID.
      if (id === arn(candidateId)) id = candidateId;
      if (id === arn(winnerId)) id = winnerId;
      expect([candidateId, winnerId]).toContain(id);
      const material = id === candidateId ? candidate : winner;
      return {
        $metadata: {}, KeyId: arn(id!), PublicKey: material.publicKeyDer,
        KeyUsage: 'SIGN_VERIFY', KeySpec: material.keySpec, SigningAlgorithms: [algorithm],
      } satisfies GetPublicKeyCommandOutput;
    }
    if (command instanceof CreateKeyCommand) {
      expect(command.input).toMatchObject({ KeyUsage: 'SIGN_VERIFY', KeySpec: candidate.keySpec });
      // These distinct fields intentionally model the native AWS response.
      return {
        $metadata: {}, KeyMetadata: {
          KeyId: candidateId, Arn: arn(candidateId), KeyUsage: 'SIGN_VERIFY', KeySpec: candidate.keySpec,
        },
      } satisfies CreateKeyCommandOutput;
    }
    if (command instanceof CreateAliasCommand) {
      expect(command.input.AliasName).toBe(aliasName);
      expect([candidateId, arn(candidateId)]).toContain(command.input.TargetKeyId);
      aliasTarget = mode === 'conflict' ? winnerId : candidateId;
      if (mode === 'conflict') throw serviceError('exists');
      return { $metadata: {} };
    }
    if (command instanceof SignCommand) {
      const expectedId = mode === 'missing' ? candidateId : winnerId;
      expect(command.input.KeyId).toBe(arn(expectedId));
      expect(command.input.SigningAlgorithm).toBe(algorithm);
      expect(command.input.MessageType).toBe('RAW');
      const material = mode === 'missing' ? candidate : winner;
      return {
        $metadata: {}, KeyId: arn(expectedId), SigningAlgorithm: algorithm,
        // Node returns DER ECDSA (the native KMS encoding), or raw Ed25519.
        Signature: sign(material.digest, command.input.Message!, material.privateKey),
      } satisfies SignCommandOutput;
    }
    throw new Error('Unexpected SDK operation: no deletion, disable, or retarget is permitted');
  });
  return { client, commands, candidate, winner, aliasReads: () => aliasReads };
}

describe('AwsSdkKmsFacade bootstrap adapter (offline supplemental proof)', () => {
  it('maps public createAlias input to a native CreateAliasCommand', async () => {
    // Given an injected SDK send boundary; When using the public facade;
    // Then native AWS field casing and exact caller values are preserved.
    const commands: Command[] = [];
    const client = facade(async (command) => { commands.push(command); return { $metadata: {} }; });
    await expect(client.createAlias({ aliasName, targetKeyId: arn(candidateId) })).resolves.toBeUndefined();
    expect(commands).toHaveLength(1);
    expect(commands[0]).toBeInstanceOf(CreateAliasCommand);
    expect(commands[0].input).toEqual({ AliasName: aliasName, TargetKeyId: arn(candidateId) });
  });

  it.each(['exists', 'internal', 'timeout'] as const)('preserves native %s createAlias rejection identity', async (kind) => {
    // Given a native service rejection; When alias acquisition fails;
    // Then callers receive the exact rejection object, not a wrapper.
    const error = serviceError(kind);
    let calls = 0;
    const client = facade(async (command) => {
      calls++;
      expect(command).toBeInstanceOf(CreateAliasCommand);
      throw error;
    });
    await expect(client.createAlias({ aliasName, targetKeyId: candidateId })).rejects.toBe(error);
    expect(calls).toBe(1);
  });

  describe.each(['ECDSA_SHA_256', 'ED25519_SHA_512'] as const)('%s through concrete facade', (algorithm) => {
    it.each(['existing', 'missing', 'conflict'] as const)('returns and signs with the %s alias winner', async (mode) => {
      // Given existing, absent, or concurrently acquired alias state;
      // When bootstrapping through the concrete adapter;
      // Then the public standalone provider identifies and signs as the winner.
      const scenario = kmsScenario(algorithm, mode);
      const result = await createOrReuseAwsKmsKeyProvider(scenario.client, { aliasName, algorithm });
      const expectedId = mode === 'missing' ? candidateId : winnerId;
      const material = mode === 'missing' ? scenario.candidate : scenario.winner;
      expect(result.keyRef).toBe(arn(expectedId));
      expect(result.keyProvider.stateSnapshot().activeKeyId).toBe(result.keyRef);
      const jwk = await result.keyProvider.signingKey();
      expect(jwk.kid).toBe(result.keyRef);
      expect(jwk.alg).toBe(material.jwsAlg);
      const exported = material.publicKey.export({ format: 'jwk' });
      expect(jwk).toMatchObject(exported);
      expect(jwk).not.toHaveProperty('d');
      const payload = Buffer.from('bootstrap adapter winner proof');
      const signature = await result.keyProvider.sign(payload);
      const publicKey = createPublicKey({ key: jwk, format: 'jwk' });
      const verificationKey = algorithm === 'ECDSA_SHA_256'
        ? { key: publicKey, dsaEncoding: 'ieee-p1363' as const } : publicKey;
      expect(verify(material.digest, payload, verificationKey, signature)).toBe(true);
      expect(verify(material.digest, Buffer.from('different payload'), verificationKey, signature)).toBe(false);
      if (mode === 'conflict') {
        const loserKey = algorithm === 'ECDSA_SHA_256'
          ? { key: scenario.candidate.publicKey, dsaEncoding: 'ieee-p1363' as const } : scenario.candidate.publicKey;
        expect(verify(material.digest, payload, loserKey, signature)).toBe(false);
      }
      expect(scenario.commands.filter((c) => c instanceof CreateKeyCommand)).toHaveLength(mode === 'existing' ? 0 : 1);
      expect(scenario.commands.filter((c) => c instanceof CreateAliasCommand)).toHaveLength(mode === 'existing' ? 0 : 1);
      if (mode === 'conflict') expect(scenario.aliasReads()).toBe(2);
    });
  });

  it.each(['missing', 'internal'] as const)('bounds conflict winner resolution and preserves native %s read failure', async (kind) => {
    // Given a conflict followed by a still-missing or unreadable winner;
    // When resolving the winner once; Then no polling or second allocation occurs.
    const error = serviceError(kind);
    const scenario = kmsScenario('ECDSA_SHA_256', 'conflict', error);
    await expect(createOrReuseAwsKmsKeyProvider(scenario.client, {
      aliasName, algorithm: 'ECDSA_SHA_256',
    })).rejects.toBe(error);
    expect(scenario.aliasReads()).toBe(2);
    expect(scenario.commands.filter((c) => c instanceof CreateKeyCommand)).toHaveLength(1);
    expect(scenario.commands.filter((c) => c instanceof CreateAliasCommand)).toHaveLength(1);
    expect(scenario.commands.some((c) => c instanceof SignCommand)).toBe(false);
  });
});
