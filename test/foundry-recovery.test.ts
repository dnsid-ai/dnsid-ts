import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { create, Deadline, FileFoundryStore, SigningPaused, type FoundryOperation, type FoundryPhase, type FoundryStore } from '@dnsid-ai/foundry';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
import { DOMAIN, ORG, foundryFixture } from './helpers/foundry.ts';
import { withTemp } from './helpers/cli-directory.ts';

const key = { registryUrl: 'https://registry.example', organizationId: ORG, name: 'agent' };

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
      expect(f.registry.prepareIssuance).toHaveBeenCalledTimes(2);
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

  it('returns KEY_MISMATCH for a replica without saved state after rotation, without resolving or issuing', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(join(root, 'original'));
      await (await create('agent', f.options)).active();
      const successor = await LocalKeyProvider.generate();
      f.publicKey = await successor.signingKey();
      await f.options.store!.withLock(key, new Deadline(), async transaction => {
        const saved = (await transaction.load())!;
        saved.currentPublicKey = f.publicKey; saved.currentKeySource = { provider: 'file', keyRef: '/operator/successor.json' };
        await transaction.save(saved);
      });
      const reads = vi.mocked(f.registry.getRegistration).mock.calls.length;
      await expect(create('agent', { ...f.options, keyProvider: successor, store: new FileFoundryStore(join(root, 'replica')) }))
        .rejects.toMatchObject({ category: 'KEY_MISMATCH', code: 'KEY_MISMATCH', httpStatus: 409 });
      const creates = vi.mocked(f.registry.registerLiveAgent).mock.calls;
      expect(creates).toHaveLength(2);
      expect(creates[1]![1]).not.toBe(creates[0]![1]);
      expect(f.registry.getRegistration).toHaveBeenCalledTimes(reads);
      expect(f.registry.prepareIssuance).toHaveBeenCalledOnce();
      expect(f.registry.submitPreparedEvent).toHaveBeenCalledOnce();
    });
  });

  it('does not reissue a challenge after an indeterminate proof submission, even after expiry', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.proofRequired = true; f.registryStatus = 'PENDING';
      vi.mocked(f.registry.submitLiveProof).mockRejectedValueOnce(new Error('lost proof response'));
      const id = await create('agent', f.options);
      await expect(id.active()).rejects.toMatchObject({ resumable: true });
      await f.options.store!.withLock(key, new Deadline(), async transaction => {
        const saved = (await transaction.load())!; saved.proof!.expiresAt = new Date(Date.now() - 1000).toISOString();
        await transaction.save(saved);
      });
      await (await create('agent', f.options)).active();
      expect(f.registry.reissueLiveProof).not.toHaveBeenCalled();
      const calls = vi.mocked(f.registry.submitLiveProof).mock.calls;
      expect(calls[0]!.slice(0, 2)).toEqual(calls[1]!.slice(0, 2));
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
