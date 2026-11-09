import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { create, SigningPaused, deriveRegistrationKey, deriveIssuanceKey, validateName, FoundryError } from '@dnsid-ai/foundry';
import { ArgumentError, IdentityManager, JoseProfile, LogRegistry, VerificationCode, VerificationError, jwkThumbprint } from '@dnsid-ai/sdk';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
import { RegistryRequestError } from '@dnsid-ai/registry';
import { withTemp } from './helpers/cli-directory.ts';
import { DOMAIN, GI, ORG, foundryFixture } from './helpers/foundry.ts';

const vectors = JSON.parse(readFileSync(new URL('./vectors/foundry-registration.json', import.meta.url), 'utf8')) as {
  organizationId: string; initialKeyId: string;
  registration: Array<{ name: string; registrationKey: string }>;
  issuance: Array<{ registrationKey: string; issuanceKey: string }>;
  rejectedNames: string[];
};

const key = { registryUrl: 'https://registry.example', organizationId: ORG, name: 'agent' };
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

describe('Known Foundry create', () => {
  it('passes every shared RFC 8785 name and hash vector without normalization', () => {
    expect(vectors.registration.length + vectors.issuance.length).toBe(17);
    for (const { name, registrationKey } of vectors.registration) {
      expect(validateName(name)).toBe(name);
      expect(deriveRegistrationKey(vectors.organizationId, name, vectors.initialKeyId)).toBe(registrationKey);
    }
    for (const { registrationKey, issuanceKey } of vectors.issuance) expect(deriveIssuanceKey(registrationKey)).toBe(issuanceKey);
    for (const invalid of vectors.rejectedNames) expect(() => validateName(invalid)).toThrow();
  });

  it('durably creates, pauses signing, completes the shared issuance flow and verifies public readiness', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      const id = await create('agent', f.options);
      expect(id.domain).toBe(DOMAIN);
      expect(id.state).toBeUndefined();
      expect(id.registryStatus).toBe('VERIFIED');
      await expect(id.sign(new Uint8Array([1]))).rejects.toBeInstanceOf(SigningPaused);
      expect(() => id.identityManager()).toThrow(SigningPaused);
      expect(await id.active()).toBe(id);
      expect(id.state).toBe('ACTIVE');
      const manager = id.identityManager();
      expect(id.identityManager()).toBe(manager);
      await expect(id.sign(new Uint8Array([1]))).resolves.toHaveLength(64);
      await expect(JoseProfile.fromIdentityManager(manager).createJWT({ audience: DOMAIN })).resolves.toBeTypeOf('string');
      expect(f.registry.prepareIssuance).toHaveBeenCalledOnce();
      const submitted = vi.mocked(f.registry.submitPreparedEvent).mock.calls[0]!;
      expect(submitted[2]).toBe(deriveIssuanceKey(deriveRegistrationKey(ORG, 'agent', await jwkThumbprint(f.operationalKey))));
      const document = JSON.parse(Buffer.from(await f.options.store!.export(key)).toString());
      expect(document.phase).toBe('complete');
      expect(document.oidcIssuerUrl).toBe('https://issuer.example/exact');
      expect(document.issuance.entryBytes).toBe(Buffer.from(submitted[1]).toString('base64url'));
      expect(document.issuance.preparedEntryBytes).toBe(Buffer.from(f.prepared()!).toString('base64url'));
      expect(JSON.stringify(document)).not.toMatch(/"d":|credential|secret/);
    });
  });

  it('reopens completed state without public network calls or reissuance and caches the signing binding', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      await (await create('agent', f.options)).active();
      const fetcher = vi.mocked(f.options.fetchJson!);
      const resolver = vi.mocked(f.options.dnsResolver!.fetchTXT);
      fetcher.mockClear(); resolver.mockClear();
      const providerCheck = vi.spyOn(f.provider, 'signingKey');
      const reopened = await create('agent', f.options);
      const checks = providerCheck.mock.calls.length;
      await reopened.sign(new Uint8Array([1]));
      await reopened.sign(new Uint8Array([2]));
      expect(providerCheck).toHaveBeenCalledTimes(checks);
      expect(fetcher).not.toHaveBeenCalled(); expect(resolver).not.toHaveBeenCalled();
      expect(f.registry.registerLiveAgent).toHaveBeenCalledOnce();
      expect(f.registry.submitPreparedEvent).toHaveBeenCalledOnce();
      await reopened.active();
      expect(fetcher).toHaveBeenCalled(); expect(resolver).toHaveBeenCalled();
    });
  });

  it('saves known facts and returns a resumable error when replay omits the domain', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.replayWithoutDomain = true;
      await expect(create('agent', f.options)).rejects.toMatchObject({ category: 'resumable', identityId: 'agent-1', registryStatus: 'VERIFIED', resumable: true });
      const state = JSON.parse(Buffer.from(await f.options.store!.export(key)).toString());
      expect(state.identityId).toBe('agent-1'); expect(state.domain).toBeUndefined();
      await expect(create('agent', f.options)).rejects.toMatchObject({ category: 'resumable' });
      expect(f.registry.registerLiveAgent).toHaveBeenCalledTimes(2);
      const calls = vi.mocked(f.registry.registerLiveAgent).mock.calls;
      expect(calls[1]!.slice(0, 2)).toEqual(calls[0]!.slice(0, 2));
      expect(f.registry.getRegistration).not.toHaveBeenCalled();
    });
  });

  it('resolves a saved ID when the next identical creation replay returns a domain', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.replayWithoutDomain = true;
      await expect(create('agent', f.options)).rejects.toMatchObject({ category: 'resumable', identityId: 'agent-1' });
      f.replayWithoutDomain = false;
      const id = await create('agent', f.options);
      expect(id.domain).toBe(DOMAIN);
      const calls = vi.mocked(f.registry.registerLiveAgent).mock.calls;
      expect(calls).toHaveLength(2);
      expect(calls[1]!.slice(0, 2)).toEqual(calls[0]!.slice(0, 2));
      await id.active();
      await expect(id.sign(new Uint8Array())).resolves.toHaveLength(64);
      await create('agent', f.options);
      expect(f.registry.registerLiveAgent).toHaveBeenCalledTimes(2);
    });
  });

  it('rejects a creation replay that changes the saved ID', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.replayWithoutDomain = true;
      await expect(create('agent', f.options)).rejects.toMatchObject({ category: 'resumable' });
      const replay = vi.mocked(f.registry.registerLiveAgent).getMockImplementation()!;
      vi.mocked(f.registry.registerLiveAgent).mockImplementationOnce(async (...args) => ({ ...await replay(...args), agentId: 'other-agent' }));
      await expect(create('agent', f.options)).rejects.toMatchObject({ category: 'binding', identityId: 'agent-1' });
    });
  });

  it('replays an unknown creation with the same frozen input and registration key', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      vi.mocked(f.registry.registerLiveAgent).mockRejectedValueOnce(new Error('lost response'));
      await expect(create('agent', f.options)).rejects.toMatchObject({ resumable: true });
      const id = await create('agent', f.options);
      expect(id.domain).toBe(DOMAIN);
      const calls = vi.mocked(f.registry.registerLiveAgent).mock.calls;
      expect(calls[1]!.slice(0, 2)).toEqual(calls[0]!.slice(0, 2));
    });
  });

  it.each([false, true])('persists exact proof bytes before submission and reissues only unused expired proof (%s)', async expired => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.proofRequired = true; f.registryStatus = 'PENDING'; f.expiredProof = expired;
      const submit = f.registry.submitLiveProof;
      vi.mocked(f.registry.submitLiveProof).mockImplementationOnce(async (domain, request, options) => {
        const saved = await import('node:fs/promises').then(async fs => {
          const files = await fs.readdir(root);
          const document = files.find(file => !file.startsWith('id-') && file.endsWith('.json'))!;
          return JSON.parse(await fs.readFile(join(root, document), 'utf8'));
        });
        expect(saved.proof.request.signature).toBe(request.signature);
        expect(saved.proof.submissionState).toBe('submitting');
        f.registryStatus = 'VERIFIED';
        return { requestId: request.requestId, agentId: 'agent-1', status: 'accepted' };
      });
      await (await create('agent', f.options)).active();
      expect(submit).toHaveBeenCalledOnce();
      expect(f.registry.reissueLiveProof).toHaveBeenCalledTimes(expired ? 1 : 0);
    });
  });

  it.each(['lost', 'reject-winner'] as const)('resumes accepted ISSUANCE after %s', async mode => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.submitMode = mode;
      const id = await create('agent', f.options);
      await id.active();
      expect(f.registry.submitPreparedEvent).toHaveBeenCalledTimes(mode === 'lost' ? 2 : 1);
      const saved = JSON.parse(Buffer.from(await f.options.store!.export(key)).toString());
      expect(saved.phase).toBe('complete');
      if (mode === 'reject-winner') {
        expect(saved.issuance.acceptance.source).toBe('verified-history');
        expect(saved.issuance.submission.state).toBe('rejected');
        expect(Buffer.from(f.acceptedBytes!).toString('base64url')).not.toBe(saved.issuance.entryBytes);
      }
      await expect(id.sign(new Uint8Array())).resolves.toHaveLength(64);
    });
  });

  it('retries indeterminate submissions with identical persisted bytes', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      vi.mocked(f.registry.submitPreparedEvent).mockRejectedValueOnce(new Error('lost before admission'));
      await (await create('agent', f.options)).active();
      const calls = vi.mocked(f.registry.submitPreparedEvent).mock.calls;
      expect(calls).toHaveLength(2);
      expect(calls[0]!.slice(0, 3)).toEqual(calls[1]!.slice(0, 3));
      expect(f.registry.prepareIssuance).toHaveBeenCalledOnce();
    });
  });

  it('preserves rejected bytes and wire code without preparing another issuance', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.submitMode = 'rejected';
      const id = await create('agent', f.options);
      await expect(id.active()).rejects.toMatchObject({ category: 'resumable', resumable: true, code: 'TLOG_INVALID_ENTRY', httpStatus: 422 });
      await expect(id.sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
      expect(f.registry.prepareIssuance).toHaveBeenCalledOnce();
      const saved = JSON.parse(Buffer.from(await f.options.store!.export(key)).toString());
      expect(saved.issuance.submission.errorCode).toBe('TLOG_INVALID_ENTRY');
    });
  });

  it.each([false, true])('rejects an empty provider without selecting or provisioning a key (saved=%s)', async saved => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      if (saved) await create('agent', f.options);
      vi.mocked(f.registry.registerLiveAgent).mockClear();
      vi.spyOn(f.provider, 'listKeyIds').mockResolvedValue([]);
      const signingKey = vi.spyOn(f.provider, 'signingKey');
      const generate = vi.spyOn(f.provider, 'generateKey');
      const activate = vi.spyOn(f.provider, 'activate');
      await expect(create('agent', f.options)).rejects.toMatchObject({ category: 'KEY_MISSING', resumable: true, message: expect.stringContaining('create the key first') });
      expect(signingKey).not.toHaveBeenCalled();
      expect(generate).not.toHaveBeenCalled();
      expect(activate).not.toHaveBeenCalled();
      expect(f.registry.registerLiveAgent).not.toHaveBeenCalled();
    });
  });

  it('rejects a different provider key without generating or replacing anything', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      await create('agent', f.options);
      const other = await LocalKeyProvider.generate(); const generate = vi.spyOn(other, 'generateKey');
      await expect(create('agent', { ...f.options, keyProvider: other })).rejects.toMatchObject({ category: 'KEY_MISMATCH', identityId: 'agent-1', domain: DOMAIN,
        message: 'use the provider key this identity was created with; run one identity per cloud provider' });
      expect(generate).not.toHaveBeenCalled(); expect(f.registry.registerLiveAgent).toHaveBeenCalledOnce();
    });
  });

  it.each(['ERROR', 'REJECTED', 'CANCELLED', 'REVOKED', 'RETIRED'])('keeps %s name ownership and never creates a replacement', async status => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      const id = await create('agent', f.options); f.registryStatus = status;
      await expect(id.active()).rejects.toMatchObject({ category: ['REVOKED', 'RETIRED'].includes(status) ? 'terminal' : 'workflow-outcome', registryStatus: status });
      await expect(create('agent', f.options)).rejects.toMatchObject({ registryStatus: status });
      expect(f.registry.registerLiveAgent).toHaveBeenCalledOnce();
      await expect(id.sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
    });
  });

  it.each(['PENDING', 'UNRECOGNIZED'])('bounds waiting for registry %s and preserves it for diagnostics', async status => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.registryStatus = status;
      const id = await create('agent', f.options);
      await expect(id.active({ timeoutMs: 35 })).rejects.toMatchObject({ category: 'deadline', registryStatus: status, resumable: true });
      expect(id.state).toBeUndefined(); expect(f.registry.prepareIssuance).not.toHaveBeenCalled();
    });
  });

  it.each(['missing-dns', 'pending-status'])('READY without public ACTIVE cannot enable signing (%s)', async fault => {
    await withTemp(async root => {
      const f = await foundryFixture(root); const id = await create('agent', f.options);
      if (fault === 'missing-dns') f.dnsMissing = true; else f.publicState = 'PENDING';
      const controller = new AbortController();
      const verify = IdentityManager.prototype.verifyLocalPublication;
      const check = vi.spyOn(IdentityManager.prototype, 'verifyLocalPublication').mockImplementationOnce(async function (this: IdentityManager, options) {
        try { return await verify.call(this, options); }
        finally { controller.abort(new DOMException('public readiness deadline', 'TimeoutError')); }
      });
      await expect(id.active({ signal: controller.signal })).rejects.toMatchObject({ category: 'deadline', resumable: true });
      expect(check).toHaveBeenCalledOnce();
      check.mockRestore();
      await expect(id.sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
      await expect(JoseProfile.fromIdentityManager(id.identityManager()).createJWT({ audience: DOMAIN })).rejects.toBeInstanceOf(SigningPaused);
      f.dnsMissing = false; f.publicState = 'ACTIVE'; await id.active();
      expect(f.registry.prepareIssuance).toHaveBeenCalledOnce();
      const submissions = vi.mocked(f.registry.submitPreparedEvent).mock.calls;
      for (const call of submissions) expect(call.slice(0, 3)).toEqual(submissions[0]!.slice(0, 3));
    });
  });

  it.each(['deadline', 'cancelled'])('keeps completed signing enabled when public refresh ends with %s', async category => {
    await withTemp(async root => {
      const f = await foundryFixture(root); const id = await create('agent', f.options); await id.active();
      const controller = new AbortController();
      const check = vi.spyOn(IdentityManager.prototype, 'verifyLocalPublication').mockImplementationOnce(async () => {
        controller.abort(category === 'deadline' ? new DOMException('budget expired', 'TimeoutError') : undefined);
        throw controller.signal.reason;
      });
      await expect(id.active({ signal: controller.signal })).rejects.toMatchObject({ category });
      expect(check).toHaveBeenCalledOnce();
      await expect(id.sign(new Uint8Array())).resolves.toHaveLength(64);
      await expect(JoseProfile.fromIdentityManager(id.identityManager()).createJWT({ audience: DOMAIN })).resolves.toBeTypeOf('string');
      const saved = JSON.parse(Buffer.from(await f.options.store!.export(key)).toString());
      expect(saved.phase).toBe('complete');
      expect(saved.signingPaused).not.toBe(true);
      await expect((await create('agent', f.options)).sign(new Uint8Array())).resolves.toHaveLength(64);
    });
  });

  it('refreshes complete state, pauses on a terminal public state, and retains it across restart', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root); const id = await create('agent', f.options); await id.active();
      f.publicState = 'RETIRED';
      await expect(id.active()).rejects.toMatchObject({ category: 'terminal' });
      expect(id.state).toBe('RETIRED');
      await expect(id.sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
      await expect(create('agent', f.options)).rejects.toMatchObject({ category: 'terminal' });
    });
  });

  it.each(['key', 'gi', 'log'])('fails public binding mismatch: %s', async fault => {
    await withTemp(async root => {
      const f = await foundryFixture(root); const id = await create('agent', f.options); await id.active();
      if (fault === 'key') f.publicKey = await (await LocalKeyProvider.generate()).signingKey();
      if (fault === 'gi') f.publicGovernance = 'other.example';
      if (fault === 'log') f.publicLog = f.publicLog.replace('log.example', 'other.example');
      await expect(id.active()).rejects.toMatchObject({ category: fault === 'key' ? 'KEY_MISMATCH' : 'binding' });
      await expect(id.sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
      await expect((await create('agent', f.options)).sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
    });
  });

  it.each(['publication', 'provider-key', 'onboarding', 'terminal'])('persists a signing pause for %s failure outside the public loop', async fault => {
    await withTemp(async root => {
      const f = await foundryFixture(root); const id = await create('agent', f.options); await id.active();
      if (fault === 'publication') {
        const read = vi.mocked(f.registry.getRegistration).getMockImplementation()!;
        vi.mocked(f.registry.getRegistration).mockImplementationOnce(async (...args) => {
          const registration = (await read(...args))!;
          return { ...registration, publicationConfig: { ...registration.publicationConfig!, logRef: registration.publicationConfig!.logRef.replace('log.example', 'other.example') } };
        });
      }
      const keyCheck = fault === 'provider-key'
        ? vi.spyOn(f.provider, 'signingKey').mockResolvedValue(await (await LocalKeyProvider.generate()).signingKey()) : undefined;
      if (fault === 'onboarding') f.organizationId = 'different-organization';
      if (fault === 'terminal') f.registryStatus = 'RETIRED';
      const category = fault === 'provider-key' ? 'KEY_MISMATCH' : fault === 'terminal' ? 'terminal' : 'binding';
      await expect(id.active()).rejects.toMatchObject({ category });
      await expect(id.sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
      const saved = JSON.parse(Buffer.from(await f.options.store!.export(key)).toString());
      expect(saved.signingPaused).toBe(true);
      keyCheck?.mockRestore(); f.organizationId = ORG;
      if (fault === 'terminal') await expect(create('agent', f.options)).rejects.toMatchObject({ category: 'terminal' });
      else {
        const reopened = await create('agent', f.options);
        await expect(reopened.sign(new Uint8Array())).rejects.toBeInstanceOf(SigningPaused);
        await reopened.active();
        await expect(reopened.sign(new Uint8Array())).resolves.toHaveLength(64);
      }
    });
  });

  it('uses isolated readiness without changing application acceptance policy', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root); f.options.config!.dnsid = { verification: { trustedEntities: [] } };
      const id = await create('agent', f.options); await id.active();
      expect(id.identityManager().config.verification.trustedEntities).toEqual([]);
      await expect(id.identityManager().verifyDomain(DOMAIN)).rejects.toMatchObject({ code: VerificationCode.CounterpartyNotAccepted });
    });
  });

  it.each([404, 405])('rejects unsupported onboarding HTTP %s before mutation', async httpStatus => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      vi.mocked(f.registry.getOrganizationOnboarding).mockRejectedValue(new RegistryRequestError(httpStatus, 'NOT_FOUND', 'no endpoint'));
      await expect(create('agent', f.options)).rejects.toMatchObject({ category: 'UnsupportedRegistry', httpStatus });
      expect(f.registry.registerLiveAgent).not.toHaveBeenCalled();
    });
  });

  it.each(['DNSID_DOMAIN', 'DNSID_GOVERNANCE_ID'])('rejects ordinary identity environment variable %s before any registry call', async variable => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      vi.stubEnv(variable, GI);
      await expect(create('agent', { ...f.options, config: undefined })).rejects.toMatchObject({
        cause: expect.any(ArgumentError), message: 'Foundry create does not accept ordinary identity selectors',
      });
      for (const method of Object.values(f.registry)) expect(method).not.toHaveBeenCalled();
    });
  });

  it.each(['wrong-org', 'not-ready', 'missing-fields', 'algorithm', 'selectors', 'no-trust'])('rejects invalid setup before mutation: %s', async fault => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      if (fault === 'wrong-org') f.organizationId = 'OTHER';
      if (fault === 'not-ready') f.ready = false;
      if (fault === 'missing-fields') vi.mocked(f.registry.getOrganizationOnboarding).mockResolvedValue({ organizationId: ORG, ready: false });
      if (fault === 'algorithm') f.options.keyProvider = await LocalKeyProvider.generate('ES256');
      if (fault === 'selectors') f.options.config!.dnsid = { identity: { domain: DOMAIN } };
      if (fault === 'no-trust') f.options.logRegistry = undefined;
      await expect(create('agent', f.options)).rejects.toBeInstanceOf(FoundryError);
      expect(f.registry.registerLiveAgent).not.toHaveBeenCalled();
    });
  });

  it.each(['KEY_REVOKED', 'KEY_MISMATCH', 'IDEMPOTENCY_CONFLICT', 'IDEMPOTENCY_MISMATCH', 'FORBIDDEN'])('retains wire status and code %s without inferring revocation', async code => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      vi.mocked(f.registry.registerLiveAgent).mockRejectedValue(new RegistryRequestError(code === 'IDEMPOTENCY_MISMATCH' ? 422 : code === 'FORBIDDEN' ? 403 : 409, code, 'rejected'));
      await expect(create('agent', f.options)).rejects.toMatchObject({ code, category: ['KEY_REVOKED', 'KEY_MISMATCH'].includes(code) ? code : 'resumable' });
    });
  });

  it('checks deadlines around providers without changing their interface', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      vi.spyOn(f.provider, 'signingKey').mockImplementation(async () => { await new Promise(resolve => setTimeout(resolve, 50)); return f.operationalKey; });
      await expect(create('agent', { ...f.options, timeoutMs: 20 })).rejects.toMatchObject({ category: 'deadline' });
      expect(f.registry.registerLiveAgent).not.toHaveBeenCalled();
    });
  });

  it('cancels without cancelling the server identity and releases the named lock', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root); const id = await create('agent', f.options);
      const abort = new AbortController(); abort.abort();
      await expect(id.active({ signal: abort.signal })).rejects.toMatchObject({ category: 'cancelled' });
      await id.active(); expect(f.registry.registerLiveAgent).toHaveBeenCalledOnce();
    });
  });

  it('propagates a log trust failure during public readiness without scanning before preparation', async () => {
    await withTemp(async root => {
      const f = await foundryFixture(root);
      vi.mocked(f.reader.verifyBilateralBinding).mockRejectedValue(new VerificationError('bad checkpoint', { code: VerificationCode.LogError, transient: false }));
      const id = await create('agent', f.options);
      await expect(id.active()).rejects.toMatchObject({ category: 'binding' });
      expect(f.registry.prepareIssuance).toHaveBeenCalledOnce();
      expect(f.registry.submitPreparedEvent).toHaveBeenCalledOnce();
    });
  });
});
