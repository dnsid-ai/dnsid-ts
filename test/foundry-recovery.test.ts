import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { create, Deadline, FileFoundryStore, SigningPaused, type FoundryPhase, type FoundryStore } from '@dnsid-ai/foundry';
import { jwkThumbprint, VerificationCode, VerificationError } from '@dnsid-ai/sdk';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
import { DOMAIN, ORG, foundryFixture } from './helpers/foundry.ts';
import { withTemp } from './helpers/cli-directory.ts';

const key = { registryUrl: 'https://registry.example', organizationId: ORG, name: 'agent' };

afterEach(() => { vi.restoreAllMocks(); });

describe('Foundry restart and replica recovery', () => {
  it.each(['creation-pending', 'identity-known', 'issuance-accepted', 'complete'] as FoundryPhase[])(
    'resumes after a crash at phase %s without creating another identity', async phase => {
      await withTemp(async root => {
        const f = await foundryFixture(root);
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
      vi.mocked(f.registry.registerLiveAgent).mockImplementationOnce(async (...args) => ({ ...await register(...args), registryStatus: 'PROVISIONING' }));
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
