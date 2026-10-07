import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import * as nodeSdk from '@dnsid-ai/sdk/node';
import { jwkThumbprint, VerificationCode, VerificationError } from '@dnsid-ai/sdk';
import { runRegistration } from '../examples/managed-registration/src/registration.ts';
import { writeState } from '../examples/managed-registration/src/state.ts';

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

it.each([false, true])('resumes setup (legacy=%s), loads SDK config, and checks fresh evidence', async legacy => {
  const directory = await mkdtemp(join(tmpdir(), 'dnsid-managed-flow-'));
  try {
    const keys = await nodeSdk.LocalKeyProvider.load(join(directory, 'keys.json'), true);
    const entity = await nodeSdk.LocalKeyProvider.generate();
    const entityKey = await entity.signingKey();
    const operational = await keys.signingKey();
    const domain = 'agent.sandbox.dev.dnsid.ai';
    const logRef = 'c2sp-tlog:public:https://log.dev.dnsid.ai#agent-123';
    const publicationConfig = {
      governanceId: 'dev.dnsid.ai', logRef, publishProfile: 'dnsid-draft-01',
      ekUrl: 'https://dnsid.dev.dnsid.ai/.well-known/dnsid-ek.json',
      kuUrl: `https://${domain}/.well-known/dnsid-ku.json`,
      statusUrl: `https://${domain}/.well-known/dnsid-status.json`,
    };
    const registration = { id: 'agent-123', domain, publicationAuthority: 'registry', registryStatus: 'READY', publicationConfig };
    const state = {
      request: { registryUrl: 'https://api.dev.dnsid.ai', input: { environment: 'sandbox', publicKeyJwk: operational }, idempotencyKey: 'register-1' },
      registration, entityKey,
      issuance: { domain, governanceId: 'dev.dnsid.ai', idempotencyKey: 'issue-1', activated: true,
        entityKid: entityKey.kid, entityThumbprint: await jwkThumbprint(entityKey),
        operationalKid: operational.kid, operationalThumbprint: await jwkThumbprint(operational) },
    };
    if (legacy) {
      await writeState(directory, 'request.json', state.request);
      await writeState(directory, 'registration.json', state.registration);
      await writeState(directory, 'entity-key.json', state.entityKey);
      await writeState(directory, 'issuance.json', state.issuance);
    } else {
      await writeState(directory, 'recovery.json', state);
    }
    const client = { registerAgent: vi.fn(), waitForStatus: vi.fn(async () => registration) };
    const factory = vi.spyOn(nodeSdk, 'createRegistryClientFromEnvironment').mockResolvedValue(client as never);
    const evidence = vi.fn(async () => ({}));
    const verifier = { verifyDomain: vi.fn(async () => ({
      domain, record: { lr: logRef }, registryStatus: { state: 'ACTIVE' }, dnssecState: 'UNKNOWN', verifyNonRevocation: evidence,
    })) };
    const construct = vi.spyOn(nodeSdk, 'constructIdentityManager').mockImplementation(async config => (
      config.dnsid?.identity ? {} : verifier
    ) as never);
    vi.stubEnv('DNSID_DNS_SERVER', '8.8.8.8');
    vi.stubEnv('DNSID_DOMAIN', 'old.example.com');
    await runRegistration(directory, 'owner-token');
    expect(client.registerAgent).not.toHaveBeenCalled();
    expect(evidence).toHaveBeenCalledOnce();
    expect(factory.mock.calls[0][0]?.DNSID_API_KEY).toBe('owner-token');
    const config = construct.mock.calls.at(-1)![0];
    expect(config.dnsid?.identity).toBeUndefined();
    expect(config.keySource).toBeUndefined();
    expect(config.dnsid?.transport?.dnsServer).toBe('8.8.8.8');
    expect(config.logTrust).toEqual({ managed: true });
    expect(config.dnsid?.verification?.trustedEntities?.[0].entityKeyThumbprints).toEqual([await jwkThumbprint(entityKey)]);
    const files = await readdir(directory);
    expect(files).toContain('recovery.json');
    if (!legacy) expect(files.sort()).toEqual(['keys.json', 'recovery.json']);
    const failure = new VerificationError('invalid signature', { code: VerificationCode.RecordInvalid, transient: false });
    verifier.verifyDomain.mockRejectedValue(failure);
    await expect(runRegistration(directory, 'owner-token')).rejects.toBe(failure);
    expect(verifier.verifyDomain).toHaveBeenCalledTimes(2);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
