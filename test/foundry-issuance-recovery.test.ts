import { describe, expect, it, vi } from 'vitest';
import { create, SigningPaused } from '@dnsid-ai/foundry';
import { VerificationCode, VerificationError, jwkThumbprint } from '@dnsid-ai/sdk';
import { PreparedEventSubmissionError, RegistryRequestError } from '@dnsid-ai/registry';
import { DOMAIN, ORG, foundryFixture } from './helpers/foundry.ts';
import { withTemp } from './helpers/cli-directory.ts';

const key = { registryUrl: 'https://registry.example', organizationId: ORG, name: 'agent' };

describe('Foundry issuance recovery order (665aa67)', () => {
  it('does not scan lifecycle history before preparation or submission', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      const prepare = vi.mocked(f.registry.prepareIssuance).getMockImplementation()!;
      const submit = vi.mocked(f.registry.submitPreparedEvent).getMockImplementation()!;
      vi.mocked(f.registry.prepareIssuance).mockImplementation(async (...args) => {
        expect(f.reader.verifyBilateralBinding).not.toHaveBeenCalled();
        expect(f.reader.rebuildHistory).not.toHaveBeenCalled();
        return prepare(...args);
      });
      vi.mocked(f.registry.submitPreparedEvent).mockImplementation(async (...args) => {
        expect(f.reader.verifyBilateralBinding).not.toHaveBeenCalled();
        expect(f.reader.rebuildHistory).not.toHaveBeenCalled();
        return submit(...args);
      });
      await (await create('agent', f.options)).active();
      expect(f.reader.rebuildHistory).toHaveBeenCalled();
    });
  });

  it.each(['preparation', 'submission'] as const)('returns a resumable error when %s is rejected before an ISSUANCE is visible', async stage => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      if (stage === 'preparation') vi.mocked(f.registry.prepareIssuance).mockRejectedValue(new RegistryRequestError(409, 'TLOG_PREPARATION_MISMATCH', 'already in progress'));
      else f.submitMode = 'rejected';
      const id = await create('agent', f.options);
      await expect(id.active()).rejects.toMatchObject({ category: 'resumable', resumable: true, identityId: 'agent-1', domain: DOMAIN });
      const prepares = vi.mocked(f.registry.prepareIssuance).mock.calls.length;
      const submits = vi.mocked(f.registry.submitPreparedEvent).mock.calls.length;
      await expect(id.active()).rejects.toMatchObject({ category: 'resumable', resumable: true });
      expect(f.registry.prepareIssuance).toHaveBeenCalledTimes(prepares);
      expect(f.registry.submitPreparedEvent).toHaveBeenCalledTimes(submits);
      expect(f.reader.verifyBilateralBinding).toHaveBeenCalledTimes(2);
      const document = JSON.parse(Buffer.from(await f.options.store!.export(key)).toString());
      expect(document.issuance.rejection.stage).toBe(stage);
      expect(document.issuance.terminalFailure).toBeUndefined();
      await expect(id.sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
    });
  });

  it.each([false, true])('does not interpret missing ISSUANCE in returned history as absence (%s)', async nonempty => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.submitMode = 'rejected';
      vi.mocked(f.reader.verifyBilateralBinding).mockResolvedValue({ initialOperationalThumbprint: await jwkThumbprint(f.operationalKey),
        initialEntityThumbprint: await jwkThumbprint(f.entityKey), timestamp: new Date() });
      vi.mocked(f.reader.rebuildHistory).mockResolvedValue(nonempty ? [{ type: 'RETIREMENT', domain: DOMAIN, timestamp: new Date() }] : []);
      const id = await create('agent', f.options);
      await expect(id.active()).rejects.toMatchObject({ category: 'resumable', resumable: true });
      expect(f.registry.prepareIssuance).toHaveBeenCalledOnce();
      expect(f.registry.submitPreparedEvent).toHaveBeenCalledOnce();
    });
  });

  it.each([false, true])('keeps invalid or unavailable recovery evidence as an error (%s)', async unavailable => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.submitMode = 'rejected';
      const evidenceError = new VerificationError('evidence failed', { code: VerificationCode.LogError, transient: unavailable });
      vi.mocked(f.reader.verifyBilateralBinding).mockRejectedValue(evidenceError);
      const id = await create('agent', f.options);
      await expect(id.active()).rejects.toMatchObject({ category: unavailable ? 'resumable' : 'binding' });
      expect(f.registry.prepareIssuance).toHaveBeenCalledOnce();
      expect(f.registry.submitPreparedEvent).toHaveBeenCalledOnce();
      await expect(id.sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
    });
  });

  it('does not scan history after an unknown append outcome; it retries exact bytes', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.submitMode = 'lost';
      const submit = vi.mocked(f.registry.submitPreparedEvent).getMockImplementation()!;
      vi.mocked(f.registry.submitPreparedEvent).mockImplementation(async (...args) => {
        expect(f.reader.rebuildHistory).not.toHaveBeenCalled();
        expect(f.reader.verifyBilateralBinding).not.toHaveBeenCalled();
        return submit(...args);
      });
      await (await create('agent', f.options)).active();
      const calls = vi.mocked(f.registry.submitPreparedEvent).mock.calls;
      expect(calls).toHaveLength(2);
      expect(calls[1]!.slice(0, 3)).toEqual(calls[0]!.slice(0, 3));
    });
  });

  it.each([401, 403, 404, 409, 422])('does not record an ordinary HTTP %s preparation failure and resumes on the next active()', async httpStatus => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      vi.mocked(f.registry.prepareIssuance).mockRejectedValueOnce(new RegistryRequestError(httpStatus, 'REQUEST_FAILED', 'request failed'));
      const id = await create('agent', f.options);
      await expect(id.active()).rejects.toMatchObject({ httpStatus, code: 'REQUEST_FAILED' });
      expect(f.registry.prepareIssuance).toHaveBeenCalledOnce();
      expect(f.reader.rebuildHistory).not.toHaveBeenCalled();
      const document = JSON.parse(Buffer.from(await f.options.store!.export(key)).toString());
      expect(document.issuance.rejection).toBeUndefined();
      expect(document.issuance.terminalFailure).toBeUndefined();
      expect(document.issuance.submission).toBeUndefined();
      await id.active();
      expect(f.registry.prepareIssuance).toHaveBeenCalledTimes(2);
      await expect(id.sign(new Uint8Array())).resolves.toHaveLength(64);
    });
  });

  it.each([401, 403, 404, 409, 422])('does not persist terminal coordinator state after an ordinary HTTP %s submission failure', async httpStatus => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      vi.mocked(f.registry.submitPreparedEvent).mockRejectedValueOnce(new PreparedEventSubmissionError({ httpStatus, code: 'REQUEST_FAILED',
        state: 'rejected', retryable: false, retryWithSameBytes: false, message: 'request failed' }));
      const id = await create('agent', f.options);
      await expect(id.active()).rejects.toMatchObject({ httpStatus, code: 'REQUEST_FAILED' });
      expect(f.registry.submitPreparedEvent).toHaveBeenCalledOnce();
      expect(f.reader.rebuildHistory).not.toHaveBeenCalled();
      const document = JSON.parse(Buffer.from(await f.options.store!.export(key)).toString());
      expect(document.issuance.rejection).toBeUndefined();
      expect(document.issuance.terminalFailure).toBeUndefined();
      expect(document.issuance.submission).toBeUndefined();
      await id.active();
      const calls = vi.mocked(f.registry.submitPreparedEvent).mock.calls;
      expect(calls).toHaveLength(2);
      expect(calls[1]!.slice(0, 3)).toEqual(calls[0]!.slice(0, 3));
      expect(f.registry.prepareIssuance).toHaveBeenCalledOnce();
    });
  });

  it('does not turn local preparation validation failure into a history lookup', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      vi.mocked(f.registry.prepareIssuance).mockResolvedValue({ entryBytes: new TextEncoder().encode('{}') });
      const id = await create('agent', f.options);
      await expect(id.active()).rejects.toMatchObject({ category: 'workflow-outcome' });
      expect(f.reader.verifyBilateralBinding).not.toHaveBeenCalled();
      expect(f.reader.rebuildHistory).not.toHaveBeenCalled();
      expect(f.registry.submitPreparedEvent).not.toHaveBeenCalled();
    });
  });
});
