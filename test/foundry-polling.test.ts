import { afterEach, describe, expect, it, vi } from 'vitest';
import { create, Deadline } from '@dnsid-ai/foundry';
import { RegistryRequestError } from '@dnsid-ai/registry';
import { foundryFixture } from './helpers/foundry.ts';
import { withTemp } from './helpers/cli-directory.ts';

const delays = [1000, 2000, 4000, 8000, 15_000, 15_000];
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

describe('Foundry polling budgets', () => {
  it.each(['PENDING', 'publication'])('backs off readiness polling from 1 second to a 15-second cap: %s', async gate => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      if (gate === 'PENDING') f.registryStatus = 'PENDING'; else f.dnsPublished = false;
      const read = vi.mocked(f.registry.getRegistration).getMockImplementation()!;
      let observations = 0;
      vi.mocked(f.registry.getRegistration).mockImplementation(async (...args) => {
        if (++observations === delays.length + 1) { f.registryStatus = 'PROVISIONING'; f.dnsPublished = true; }
        if (observations <= delays.length) expect(f.registry.prepareIssuance).not.toHaveBeenCalled();
        return read(...args);
      });
      const wait = vi.spyOn(Deadline.prototype, 'wait').mockResolvedValue();
      await (await create('agent', f.options)).active();
      expect(wait.mock.calls.map(call => call[0])).toEqual(delays);
    });
  });

  it('backs off full public readiness passes', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.dnsMissing = true;
      const wait = vi.spyOn(Deadline.prototype, 'wait').mockImplementation(async () => {
        if (wait.mock.calls.length === delays.length) f.dnsMissing = false;
      });
      await (await create('agent', f.options)).active();
      expect(wait.mock.calls.map(call => call[0])).toEqual(delays);
      expect(f.options.dnsResolver!.fetchTXT).toHaveBeenCalledTimes(delays.length + 1);
    });
  });

  it('backs off transient registry retries', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      for (const _ of delays) vi.mocked(f.registry.getOrganizationOnboarding).mockRejectedValueOnce(new RegistryRequestError(503, 'UNAVAILABLE', 'try later'));
      const wait = vi.spyOn(Deadline.prototype, 'wait').mockResolvedValue();
      await create('agent', f.options);
      expect(wait.mock.calls.map(call => call[0])).toEqual(delays);
    });
  });

  it('backs off uncertain issuance retries without changing the submitted bytes', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      for (const _ of delays) vi.mocked(f.registry.submitPreparedEvent).mockRejectedValueOnce(new Error('response lost'));
      const wait = vi.spyOn(Deadline.prototype, 'wait').mockResolvedValue();
      await (await create('agent', f.options)).active();
      expect(wait.mock.calls.map(call => call[0])).toEqual(delays);
      const calls = vi.mocked(f.registry.submitPreparedEvent).mock.calls;
      for (const call of calls) expect(call.slice(0, 3)).toEqual(calls[0]!.slice(0, 3));
    });
  });

  it.each(['issuance', 'public'])('stops on management failure during %s polling and retains bytes', async phase => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      if (phase === 'issuance') vi.mocked(f.registry.submitPreparedEvent).mockRejectedValueOnce(new Error('outcome unknown'));
      else f.dnsMissing = true;
      vi.spyOn(Deadline.prototype, 'wait').mockImplementation(async () => { f.registryStatus = 'ERROR'; });
      const id = await create('agent', f.options);
      await expect(id.active()).rejects.toMatchObject({ category: 'workflow-outcome', registryStatus: 'ERROR' });
      expect(f.registry.submitPreparedEvent).toHaveBeenCalledOnce();
      const saved = JSON.parse(Buffer.from(await f.options.store!.export({ registryUrl: 'https://registry.example', organizationId: f.organizationId, name: 'agent' })).toString());
      expect(saved.issuance.entryBytes).toBeDefined();
      expect(saved.issuanceKey).toBeDefined();
      expect(f.registry.registerLiveAgent).toHaveBeenCalledOnce();
    });
  });

  it('defaults create to 30 seconds and active to 10 minutes, and accepts an override', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      const lock = vi.spyOn(f.options.store!, 'withLock');
      const createStarted = Date.now();
      const id = await create('agent', { ...f.options, timeoutMs: undefined });
      expect(lock.mock.calls[0]![1].end).toBeGreaterThanOrEqual(createStarted + 30_000);
      expect(lock.mock.calls[0]![1].end).toBeLessThanOrEqual(Date.now() + 30_000);
      const activeStarted = Date.now();
      await id.active();
      expect(lock.mock.calls[1]![1].end).toBeGreaterThanOrEqual(activeStarted + 600_000);
      expect(lock.mock.calls[1]![1].end).toBeLessThanOrEqual(Date.now() + 600_000);
      const overrideStarted = Date.now();
      await id.active({ timeoutMs: 2500 });
      expect(lock.mock.calls[2]![1].end).toBeGreaterThanOrEqual(overrideStarted + 2500);
      expect(lock.mock.calls[2]![1].end).toBeLessThanOrEqual(Date.now() + 2500);
    });
  });

  it('caps a backoff wait at the remaining deadline', async () => {
    vi.useFakeTimers();
    const deadline = new Deadline(2500);
    const timer = vi.spyOn(globalThis, 'setTimeout');
    const waited = expect(deadline.wait(15_000)).rejects.toMatchObject({ category: 'deadline', resumable: true });
    expect(timer).toHaveBeenLastCalledWith(expect.any(Function), 2500);
    await vi.advanceTimersByTimeAsync(2500);
    await waited;
  });
});
