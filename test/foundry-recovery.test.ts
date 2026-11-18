import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { create, Deadline, FileFoundryStore, SigningPaused, type FoundryOperation, type FoundryPhase, type FoundryStore } from '@dnsid-ai/foundry';
import { jwkThumbprint, VerificationCode, VerificationError } from '@dnsid-ai/sdk';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
import { RegistryRequestError } from '@dnsid-ai/registry';
import { DOMAIN, ORG, foundryFixture } from './helpers/foundry.ts';
import { withTemp } from './helpers/cli-directory.ts';

const key = { registryUrl: 'https://registry.example', organizationId: ORG, name: 'agent' };

afterEach(() => { vi.restoreAllMocks(); });

describe('Foundry restart and replica recovery', () => {
  it.each(['creation-pending', 'proof-pending', 'identity-known', 'issuance-accepted', 'complete'] as FoundryPhase[])(
    'resumes after a crash at phase %s without creating another identity', async phase => {
      await withTemp(async root => {
        const f = await foundryFixture(root);
        if (phase === 'proof-pending') { f.proofRequired = true; f.registryStatus = 'PENDING'; }
        const store = f.options.store!;
        let crashed = false;
        const crashStore: FoundryStore = {
          export: (...args) => store.export(...args), import: (...args) => store.import(...args), loadById: (id, scope) => store.loadById(id, scope),
          withLock: (operationKey, deadline, work) => store.withLock(operationKey, deadline, transaction => work({
            load: () => transaction.load(),
            save: async operation => {
              await transaction.save(operation);
              if (operation.phase === phase) { crashed = true; throw new Error('process stopped'); }
            },
          })),
        };
        await expect(create('agent', { ...f.options, store: crashStore }).then(identity => identity.active())).rejects.toThrow('process stopped');
        expect(crashed).toBe(true);
        const id = await create('agent', f.options); await id.active();
        await expect(id.sign(new Uint8Array())).resolves.toHaveLength(64);
        expect(f.registry.registerLiveAgent).toHaveBeenCalledOnce();
        expect(f.registry.submitPreparedEvent).toHaveBeenCalledOnce();
      });
    });

  it('saves the proof outcome as identity-known and keeps that phase through issuance after a restart', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.proofRequired = true; f.registryStatus = 'PENDING';
      const store = f.options.store!;
      const writes: FoundryOperation[] = [];
      let interrupted = false;
      const tracedStore: FoundryStore = {
        export: (...args) => store.export(...args), import: (...args) => store.import(...args), loadById: (id, scope) => store.loadById(id, scope),
        withLock: (operationKey, deadline, work) => store.withLock(operationKey, deadline, transaction => work({
          load: () => transaction.load(),
          save: async operation => {
            await transaction.save(operation);
            writes.push(structuredClone(operation));
            if (operation.proof?.outcome && !interrupted) { interrupted = true; throw new Error('process stopped after proof'); }
          },
        })),
      };
      const options = { ...f.options, store: tracedStore };
      await expect((await create('agent', options)).active()).rejects.toThrow('process stopped after proof');
      const saved = JSON.parse(Buffer.from(await store.export(key)).toString());
      expect(saved.phase).toBe('identity-known');
      expect(saved.proof.outcome).toMatchObject({ agentId: 'agent-1' });
      await (await create('agent', options)).active();
      expect(f.registry.submitLiveProof).toHaveBeenCalledOnce();
      expect(writes.filter(operation => operation.phase === 'proof-pending').every(operation => !operation.proof?.outcome)).toBe(true);
      const preparing = writes.filter(operation => operation.issuance && !operation.issuance.submission);
      expect(preparing.length).toBeGreaterThan(0);
      expect(preparing.every(operation => operation.phase === 'identity-known')).toBe(true);
      expect(writes.at(-1)!.phase).toBe('complete');
    });
  });

  it('recovers a replica without saved state from the server identity and accepted lifecycle', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(join(root, 'replica-a'));
      await (await create('agent', f.options)).active();
      const replica = await create('agent', { ...f.options, store: new FileFoundryStore(join(root, 'replica-b')) });
      await replica.active();
      expect(replica.domain).toBe(DOMAIN);
      expect(f.registry.registerLiveAgent).toHaveBeenCalledTimes(2);
      expect(f.registry.prepareIssuance).toHaveBeenCalledOnce();
      expect(f.registry.submitPreparedEvent).toHaveBeenCalledOnce();
    });
  });

  it('reopens complete rotated state with only its saved current provider, without using the initial private key', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      await (await create('agent', f.options)).active();
      const successor = await LocalKeyProvider.generate();
      const current = await successor.signingKey();
      await f.options.store!.withLock(key, new Deadline(), async transaction => {
        const saved = (await transaction.load())!;
        saved.currentPublicKey = current; saved.currentKeySource = { provider: 'file', keyRef: '/operator/successor.json' };
        await transaction.save(saved);
      });
      const initialKeyLookup = vi.spyOn(f.provider, 'signingKey').mockRejectedValue(new Error('initial key removed'));
      f.publicKey = current;
      const id = await create('agent', { ...f.options, keyProvider: successor });
      await expect(id.sign(new Uint8Array())).resolves.toHaveLength(64);
      await id.active();
      expect(initialKeyLookup).not.toHaveBeenCalled();
      expect(f.registry.prepareIssuance).toHaveBeenCalledOnce();
      expect(f.registry.submitPreparedEvent).toHaveBeenCalledOnce();
    });
  });

  it.each([false, true])('recovers a replica without saved state after rotation using the current key (invalid continuity=%s)', async invalid => {
    await withTemp(async root => {
      const f = await foundryFixture(join(root, 'original'));
      await (await create('agent', f.options)).active();
      const successor = await LocalKeyProvider.generate();
      f.publicKey = await successor.signingKey();
      const initialThumbprint = await jwkThumbprint(f.operationalKey);
      const currentThumbprint = await jwkThumbprint(f.publicKey);
      const history = await f.reader.rebuildHistory(DOMAIN);
      vi.mocked(f.reader.rebuildHistory).mockResolvedValue([...history, {
        type: 'KEY_ROTATION', domain: DOMAIN, timestamp: new Date(), previousOperationalKid: f.operationalKey.kid,
        previousOperationalThumbprint: initialThumbprint, newOperationalKid: f.publicKey.kid,
        newOperationalAlg: f.publicKey.alg!, newOperationalPublicKey: f.publicKey, newOperationalThumbprint: currentThumbprint,
      }]);
      vi.mocked(f.reader.verifyOperationalContinuity).mockImplementation(async (domain, initial, current) => {
        expect([domain, initial, current]).toEqual([DOMAIN, initialThumbprint, currentThumbprint]);
        if (invalid) throw new VerificationError('rotation evidence invalid', { code: VerificationCode.LogError });
      });
      const register = vi.mocked(f.registry.registerLiveAgent).getMockImplementation()!;
      vi.mocked(f.registry.registerLiveAgent).mockImplementationOnce(async (...args) => ({ ...await register(...args), status: 'provider_deferred' }));
      const store = new FileFoundryStore(join(root, 'replica'));
      const options = { ...f.options, keyProvider: successor, store };
      const replica = await create('agent', options);
      await expect(replica.sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
      if (invalid) {
        await expect(replica.active()).rejects.toMatchObject({ category: 'binding' });
        await expect(replica.sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
      } else {
        await replica.active();
        await expect(replica.sign(new Uint8Array())).resolves.toHaveLength(64);
        const saved = JSON.parse(Buffer.from(await store.export(key)).toString());
        expect(saved.initialPublicKey).toEqual(f.operationalKey);
        expect(saved.currentPublicKey).toEqual(f.publicKey);
        expect(saved.creationInput.public_key).toEqual(f.publicKey);
        await expect((await create('agent', options)).sign(new Uint8Array())).resolves.toHaveLength(64);
        await expect(create('agent', { ...options, keyProvider: f.provider })).rejects.toMatchObject({ category: 'KEY_MISMATCH' });
      }
      const creates = vi.mocked(f.registry.registerLiveAgent).mock.calls;
      expect(creates).toHaveLength(2);
      expect(creates[1]![1]).not.toBe(creates[0]![1]);
      expect(f.reader.verifyOperationalContinuity).toHaveBeenCalledWith(DOMAIN, initialThumbprint, currentThumbprint);
      expect(f.registry.prepareIssuance).toHaveBeenCalledOnce();
      expect(f.registry.submitPreparedEvent).toHaveBeenCalledOnce();
    });
  });

  it.each(['REVOKED', 'RETIRED'])('never re-enables a complete operation with saved registry status %s, even without a pause flag', async status => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      const id = await create('agent', f.options); await id.active();
      await f.options.store!.withLock(key, new Deadline(), async transaction => {
        const saved = (await transaction.load())!;
        saved.registryStatus = status;
        delete saved.signingPaused;
        await transaction.save(saved);
      });
      await expect(create('agent', f.options)).rejects.toMatchObject({ category: 'terminal', registryStatus: status });
      await expect(id.active()).rejects.toMatchObject({ category: 'terminal' });
      await expect(id.sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
      const saved = JSON.parse(Buffer.from(await f.options.store!.export(key)).toString());
      expect(saved.signingPaused).toBe(true);
      expect(saved.registryStatus).toBe(status);
      await expect(create('agent', f.options)).rejects.toMatchObject({ category: 'terminal' });
    });
  });

  it('retries an indeterminate proof with the same bytes before expiry', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.proofRequired = true; f.registryStatus = 'PENDING';
      vi.mocked(f.registry.submitLiveProof).mockRejectedValueOnce(new Error('lost proof response'));
      const id = await create('agent', f.options);
      await expect(id.active()).rejects.toMatchObject({ resumable: true });
      await (await create('agent', f.options)).active();
      expect(f.registry.reissueLiveProof).not.toHaveBeenCalled();
      const calls = vi.mocked(f.registry.submitLiveProof).mock.calls;
      expect(calls[0]!.slice(0, 2)).toEqual(calls[1]!.slice(0, 2));
    });
  });

  it.each(['reissued', 'used'] as const)('reconciles an expired unsettled proof: %s', async outcome => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.proofRequired = true; f.registryStatus = 'PENDING';
      vi.mocked(f.registry.submitLiveProof).mockRejectedValueOnce(new Error('proof outcome unknown'));
      const id = await create('agent', f.options);
      await expect(id.active()).rejects.toMatchObject({ resumable: true });
      await f.options.store!.withLock(key, new Deadline(), async transaction => {
        const saved = (await transaction.load())!; saved.proof!.expiresAt = new Date(Date.now() - 1000).toISOString();
        expect(saved.proof!.submissionState).toBe('submitting');
        await transaction.save(saved);
      });
      const reissue = vi.mocked(f.registry.reissueLiveProof).getMockImplementation()!;
      vi.mocked(f.registry.reissueLiveProof).mockImplementationOnce(async (...args) => {
        expect(args.slice(0, 3)).toEqual([DOMAIN, vi.mocked(f.registry.registerLiveAgent).mock.calls[0]![1], f.operationalKey]);
        if (outcome === 'used') throw new RegistryRequestError(409, undefined, 'challenge was used');
        const replacement = await reissue(...args);
        const transcript = JSON.parse(Buffer.from(replacement.challengeMessage, 'base64url').toString());
        transcript.nonce = 'bmV3LW5vbmNl';
        return { ...replacement, challenge: transcript.nonce, challengeMessage: Buffer.from(JSON.stringify(transcript)).toString('base64url') };
      });
      const read = vi.mocked(f.registry.getRegistration).getMockImplementation()!;
      let reads = 0;
      vi.mocked(f.registry.getRegistration).mockImplementation(async (...args) => {
        if (++reads === 3 && outcome === 'used') f.registryStatus = 'VERIFIED';
        return read(...args);
      });
      vi.spyOn(Deadline.prototype, 'wait').mockResolvedValue();
      await (await create('agent', f.options)).active();
      expect(f.registry.reissueLiveProof).toHaveBeenCalledOnce();
      const submissions = vi.mocked(f.registry.submitLiveProof).mock.calls;
      const saved = JSON.parse(Buffer.from(await f.options.store!.export(key)).toString());
      if (outcome === 'used') {
        expect(submissions).toHaveLength(1);
        expect(reads).toBeGreaterThanOrEqual(3);
        expect(saved.proof.outcome).toEqual({ httpStatus: 409 });
        expect(saved.proof.request).toEqual(submissions[0]![1]);
      } else {
        expect(submissions).toHaveLength(2);
        expect(submissions[1]![1].signature).not.toBe(submissions[0]![1].signature);
        expect(saved.proof.challenge).toBe('bmV3LW5vbmNl');
        expect(saved.proof.request).toEqual(submissions[1]![1]);
      }
      expect(saved.phase).toBe('complete');
      await expect((await create('agent', f.options)).sign(new Uint8Array())).resolves.toHaveLength(64);
    });
  });

  it('settles an uncertain proof before issuance even when the registry is already VERIFIED', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.proofRequired = true; f.registryStatus = 'PENDING';
      const proof = vi.mocked(f.registry.submitLiveProof).getMockImplementation()!;
      vi.mocked(f.registry.submitLiveProof).mockImplementationOnce(async (...args) => {
        await proof(...args);
        throw new Error('accepted proof response lost');
      });
      const id = await create('agent', f.options);
      await expect(id.active()).rejects.toMatchObject({ resumable: true });
      const prepare = vi.mocked(f.registry.prepareIssuance).getMockImplementation()!;
      vi.mocked(f.registry.prepareIssuance).mockImplementationOnce(async (...args) => {
        expect(f.registry.submitLiveProof).toHaveBeenCalledTimes(2);
        return prepare(...args);
      });
      await id.active();
      const calls = vi.mocked(f.registry.submitLiveProof).mock.calls;
      expect(calls[1]!.slice(0, 2)).toEqual(calls[0]!.slice(0, 2));
      const saved = JSON.parse(Buffer.from(await f.options.store!.export(key)).toString());
      expect(saved.proof.outcome).toBeDefined();
      expect(saved.phase).toBe('complete');
    });
  });

  it('serializes simultaneous create calls on the same operation', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      const [first, second] = await Promise.all([create('agent', f.options), create('agent', f.options)]);
      expect(first.domain).toBe(second.domain);
      expect(f.registry.registerLiveAgent).toHaveBeenCalledOnce();
      await expect(first.sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
    });
  });
});
