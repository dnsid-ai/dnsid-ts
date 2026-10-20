import { describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import {
  JWKS,
  type VerifiedDomain,
  jwkThumbprint,
  toArrayBuffer,
  type DnsIdJWK,
  type KeyProvider,
  type KeyRotationEvent,
} from '@dnsid-ai/protocol';
import {
  canonicalBytes,
  parseC2spEventEntry,
  prepareC2spTlogEventForSigning,
} from '@dnsid-ai/log-c2sp-tlog';
import {
  ManagedKeyRotationActivationError,
  ManagedKeyRotationSubmissionError,
  resumeManagedOperationalKeyRotation,
  rotateManagedOperationalKey,
  type ManagedKeyRotationRegistry,
  type ManagedKeyRotationResult,
} from '@dnsid-ai/sdk';
import {
  PreparedEventSubmissionError,
  type KeyRotationPreparationRequest,
  type PreparedRegistryEvent,
  type SubmissionResult,
} from '@dnsid-ai/registry';

const DOMAIN = 'agent.example.com';
const STREAM_ID = 'ERERERERERERERERERERER';
const LR = `c2sp-tlog:public:https://log.example/dnsid#${STREAM_ID}`;

function coordinator() {
  let saved: ManagedKeyRotationResult;
  return {
    previousProviderReference: 'provider',
    newProviderReference: 'provider',
    persistRotation: vi.fn(async (rotation: ManagedKeyRotationResult) => { saved = rotation; }),
    setApplicationSigningPaused: vi.fn(async (_paused: boolean) => undefined),
    setApplicationSigner: vi.fn(async (_provider: KeyProvider, _kid: string) => undefined),
    verifyPublicationEvidence: vi.fn(async () => ({
      domain: DOMAIN, record: { lr: LR },
      jwks: new JWKS([JSON.parse(new TextDecoder().decode(saved.entryBytes)).new_ku]),
      logReader: { readEvent: async () => parseC2spEventEntry(saved.entryBytes, {
        scope: 'public', logOrigin: 'log.example/dnsid', streamId: STREAM_ID, lr: LR,
      }) },
    } as unknown as VerifiedDomain)),
  };
}

async function key(kid: string, algorithm = 'ES256'): Promise<{ publicJwk: DnsIdJWK; privateKey: CryptoKey }> {
  const pair = await generateKeyPair(algorithm, { extractable: true });
  return {
    publicJwk: { ...await exportJWK(pair.publicKey), kid, alg: algorithm, use: 'sig' } as DnsIdJWK,
    privateKey: pair.privateKey as CryptoKey,
  };
}

class RotationKeyProvider implements KeyProvider {
  private activeKid: string | null;
  private pendingKid?: string;
  private readonly retained = new Set<string>();
  activateCalls = 0;
  failNextSupersede = false;

  constructor(
    private readonly previous: Awaited<ReturnType<typeof key>>,
    private readonly next: Awaited<ReturnType<typeof key>>,
  ) {
    this.activeKid = previous.publicJwk.kid;
  }

  async signingKey(): Promise<DnsIdJWK> {
    if (!this.activeKid) throw new Error('no active signing key');
    return this.jwk(this.activeKid);
  }
  async activeSigningKey(): Promise<DnsIdJWK | null> { return this.activeKid ? this.signingKey() : null; }
  async jwk(kid: string): Promise<DnsIdJWK> {
    if (kid === this.previous.publicJwk.kid) return this.previous.publicJwk;
    if (kid === this.next.publicJwk.kid) return this.next.publicJwk;
    throw new Error(`key not found: ${kid}`);
  }
  async listKeyIds(): Promise<string[]> { return [...(this.activeKid ? [this.activeKid] : []), ...this.retained]; }
  async sign(payload: Uint8Array): Promise<Uint8Array> { return this.signKey((await this.signingKey()).kid, payload); }
  async signKey(kid: string, payload: Uint8Array): Promise<Uint8Array> {
    if (kid !== this.activeKid && kid !== this.pendingKid) throw new Error(`key is not available for signing: ${kid}`);
    const privateKey = kid === this.previous.publicJwk.kid ? this.previous.privateKey : this.next.privateKey;
    return new Uint8Array(await crypto.subtle.sign(
      privateKey.algorithm.name === 'Ed25519' ? 'Ed25519' : { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      toArrayBuffer(payload),
    ));
  }
  async validateKeyGeneration(algorithm: string): Promise<void> {
    if (algorithm !== this.next.publicJwk.alg) throw new Error('unsupported generation algorithm');
  }
  async generateKey(): Promise<string> {
    this.pendingKid = this.next.publicJwk.kid;
    return this.pendingKid;
  }
  async activate(kid: string): Promise<void> {
    this.activateCalls++;
    if (kid !== this.pendingKid) throw new Error(`key is not pending: ${kid}`);
    if (this.activeKid) this.retained.add(this.activeKid);
    this.activeKid = kid;
    this.pendingKid = undefined;
  }
  async supersede(kid: string): Promise<void> {
    if (this.failNextSupersede) {
      this.failNextSupersede = false;
      throw new Error('transient supersede failure');
    }
    if (kid === this.activeKid) this.activeKid = null;
    else if (!this.retained.delete(kid)) throw new Error(`key is not retained: ${kid}`);
  }
}

class RotationRegistry implements ManagedKeyRotationRegistry {
  readonly submissions: Array<{ bytes: Uint8Array; idempotencyKey: string }> = [];
  request?: KeyRotationPreparationRequest;
  state: SubmissionResult['state'] = 'accepted';
  submitError?: unknown;
  entryHashOverride?: string;

  constructor(private readonly previousKid: string) {}

  async prepareKeyRotation(
    domain: string,
    request: KeyRotationPreparationRequest,
    _idempotencyKey: string,
  ): Promise<PreparedRegistryEvent> {
    this.request = request;
    const event: KeyRotationEvent = {
      type: 'KEY_ROTATION',
      domain,
      previousOperationalKid: this.previousKid,
      previousOperationalThumbprint: request.previousKeyId,
      newOperationalKid: request.publicKey.kid,
      newOperationalAlg: request.publicKey.alg!,
      newOperationalPublicKey: request.publicKey,
      newOperationalThumbprint: await jwkThumbprint(request.publicKey),
      timestamp: new Date('2026-07-27T12:00:00Z'),
    };
    const prepared = prepareC2spTlogEventForSigning(event, LR, {
      sequence: 1,
      previousEventId: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      previousStateHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    });
    return { entryBytes: canonicalBytes(prepared.envelope), logReference: LR };
  }

  async submitPreparedEvent(
    _domain: string,
    entryBytes: Uint8Array,
    idempotencyKey: string,
  ): Promise<SubmissionResult> {
    this.submissions.push({ bytes: entryBytes.slice(), idempotencyKey });
    if (this.submitError) throw this.submitError;
    return {
      state: this.state,
      entryHash: this.entryHashOverride ?? await sha256Hex(entryBytes),
      index: this.state === 'accepted' ? 1 : undefined,
      logRef: this.state === 'accepted' ? `${LR}@1` : undefined,
      keyId: this.state === 'accepted' ? this.request!.publicKey.kid : undefined,
    };
  }
}

describe('managed registry operational-key rotation', () => {
  it.each([false, true])('rejects an absent previous key without saved acceptance (activated=%s)', async activated => {
    const provider = new RotationKeyProvider(await key('op-1'), await key('op-2'));
    const registry = new RotationRegistry('op-1');
    registry.state = 'pending';
    const coordination = coordinator();
    const pending = await rotateManagedOperationalKey({
      domain: DOMAIN, logReference: LR, keyProvider: provider, registryClient: registry,
      idempotencyKey: 'rotation-1', ...coordination,
    });
    await provider.activate('op-2');
    await provider.supersede('op-1');
    await expect(resumeManagedOperationalKeyRotation({
      rotation: { ...pending, activated }, resolveKeyProvider: async () => provider,
      registryClient: registry, ...coordination,
    })).rejects.toMatchObject({ cause: { message: expect.stringContaining('without saved acceptance') } });
    expect(registry.submissions).toHaveLength(1);
    expect(coordination.setApplicationSigningPaused).not.toHaveBeenCalledWith(false);
  });

  it.each(['retained', 'absent', 'unavailable'] as const)('rejects invalid source state: %s', async state => {
    const old = new RotationKeyProvider(await key('op-1'), await key('unrelated'));
    const target = new RotationKeyProvider(await key('initial'), await key('op-2'));
    const registry = new RotationRegistry('op-1');
    registry.state = 'pending';
    const coordination = coordinator();
    const pending = await rotateManagedOperationalKey({
      domain: DOMAIN, logReference: LR, keyProvider: old, targetKeyProvider: target,
      registryClient: registry, idempotencyKey: 'rotation-1', ...coordination,
      previousProviderReference: 'old', newProviderReference: 'target',
    });
    let source = old;
    if (state === 'retained') {
      await old.generateKey();
      await old.activate('unrelated');
    } else if (state === 'absent') {
      source = new RotationKeyProvider(await key('unrelated'), await key('unused'));
    } else {
      vi.spyOn(old, 'activeSigningKey').mockResolvedValue(null);
      vi.spyOn(old, 'jwk').mockRejectedValue(new Error('listed key unavailable'));
    }
    // Saved acceptance allows absent-key recovery only for a genuinely retired source.
    const submission = { state: 'accepted' as const, entryHash: pending.entryHash, index: 1, logRef: `${LR}@1`, keyId: 'op-2' };
    await target.activate('op-2');
    await expect(resumeManagedOperationalKeyRotation({
      rotation: { ...pending, submission }, resolveKeyProvider: async reference => reference === 'old' ? source : target,
      registryClient: registry, ...coordination,
    })).rejects.toBeInstanceOf(ManagedKeyRotationActivationError);
    expect(registry.submissions).toHaveLength(1);
    expect(coordination.setApplicationSigningPaused).not.toHaveBeenCalledWith(false);
  });

  it('keeps signing paused if cross-provider supersession leaves an active source key', async () => {
    const old = new RotationKeyProvider(await key('op-1'), await key('unused'));
    const target = new RotationKeyProvider(await key('initial'), await key('op-2'));
    vi.spyOn(old, 'supersede').mockResolvedValue();
    const coordination = coordinator();
    await expect(rotateManagedOperationalKey({
      domain: DOMAIN, logReference: LR, keyProvider: old, targetKeyProvider: target,
      registryClient: new RotationRegistry('op-1'), idempotencyKey: 'rotation-1', ...coordination,
      previousProviderReference: 'old', newProviderReference: 'target',
    })).rejects.toMatchObject({ cause: { message: expect.stringContaining('still has an active signing key') } });
    expect(coordination.setApplicationSigningPaused).not.toHaveBeenCalledWith(false);
  });

  it('requires the exact active target binding after the previous key is removed', async () => {
    const provider = new RotationKeyProvider(await key('op-1'), await key('op-2'));
    const registry = new RotationRegistry('op-1');
    const coordination = coordinator();
    const completed = await rotateManagedOperationalKey({
      domain: DOMAIN, logReference: LR, keyProvider: provider, registryClient: registry,
      idempotencyKey: 'rotation-1', ...coordination,
    });
    coordination.setApplicationSigningPaused.mockClear();
    vi.spyOn(provider, 'signingKey').mockResolvedValue((await key('op-2')).publicJwk);
    await expect(resumeManagedOperationalKeyRotation({
      rotation: completed, resolveKeyProvider: async () => provider, registryClient: registry, ...coordination,
    })).rejects.toMatchObject({ cause: { message: expect.stringContaining('key binding mismatch') } });
    expect(coordination.setApplicationSigningPaused).not.toHaveBeenCalledWith(false);
  });

  it('explicitly changes algorithms and restores the accepted signer', async () => {
    const provider = new RotationKeyProvider(await key('op-1'), await key('op-2', 'EdDSA'));
    const registry = new RotationRegistry('op-1');
    const coordination = coordinator();
    const completed = await rotateManagedOperationalKey({
      domain: DOMAIN, logReference: LR, keyProvider: provider, registryClient: registry,
      idempotencyKey: 'rotation-1', targetAlgorithm: 'EdDSA', ...coordination,
    });
    expect((await provider.signingKey()).alg).toBe('EdDSA');
    await expect(resumeManagedOperationalKeyRotation({
      rotation: completed, resolveKeyProvider: async () => provider, registryClient: registry, ...coordination,
    })).resolves.toMatchObject({ activated: true, applicationSigningPaused: false });
    expect(registry.submissions).toHaveLength(1);
  });

  it.each(['ES256', 'EdDSA'] as const)('validates legacy providers using their active algorithm: %s', async targetAlgorithm => {
    const provider = new RotationKeyProvider(await key('op-1'), await key('op-2'));
    const legacy: KeyProvider = provider;
    legacy.validateKeyGeneration = undefined;
    const generate = vi.spyOn(provider, 'generateKey');
    const options = {
      domain: DOMAIN, logReference: LR, keyProvider: legacy, registryClient: new RotationRegistry('op-1'),
      idempotencyKey: 'rotation-1', targetAlgorithm, ...coordinator(),
    };
    if (targetAlgorithm === 'ES256') {
      await expect(rotateManagedOperationalKey(options)).resolves.toMatchObject({ activated: true });
    } else {
      await expect(rotateManagedOperationalKey(options)).rejects.toThrow('must validate support');
      expect(generate).not.toHaveBeenCalled();
    }
  });

  it('rejects unsupported selection before generation', async () => {
    const provider = new RotationKeyProvider(await key('op-1'), await key('op-2'));
    const generate = vi.spyOn(provider, 'generateKey');
    await expect(rotateManagedOperationalKey({
      domain: DOMAIN, logReference: LR, keyProvider: provider, registryClient: new RotationRegistry('op-1'),
      idempotencyKey: 'rotation-1', targetAlgorithm: 'EdDSA', ...coordinator(),
    })).rejects.toThrow('unsupported generation algorithm');
    expect(generate).not.toHaveBeenCalled();
  });

  it('rejects an unselected algorithm change before generation', async () => {
    const provider = new RotationKeyProvider(await key('op-1'), await key('op-2', 'EdDSA'));
    const generate = vi.spyOn(provider, 'generateKey');
    await expect(rotateManagedOperationalKey({
      domain: DOMAIN, logReference: LR, keyProvider: provider, registryClient: new RotationRegistry('op-1'),
      idempotencyKey: 'rotation-1', ...coordinator(),
    })).rejects.toThrow('unsupported generation algorithm');
    expect(generate).not.toHaveBeenCalled();
  });

  it('checks the generated algorithm before registry preparation', async () => {
    const provider = new RotationKeyProvider(await key('op-1'), await key('op-2'));
    vi.spyOn(provider, 'validateKeyGeneration').mockResolvedValue();
    const registry = new RotationRegistry('op-1');
    const prepare = vi.spyOn(registry, 'prepareKeyRotation');
    await expect(rotateManagedOperationalKey({
      domain: DOMAIN, logReference: LR, keyProvider: provider, registryClient: registry,
      idempotencyKey: 'rotation-1', targetAlgorithm: 'EdDSA', ...coordinator(),
    })).rejects.toThrow('generated key does not use the selected algorithm');
    expect(prepare).not.toHaveBeenCalled();
    expect(registry.submissions).toHaveLength(0);
  });

  it.each(['signer', 'persistence'] as const)('restores the saved target signer after a %s crash while configuration still selects the old provider', async crash => {
    const previous = await key('op-1');
    const next = await key('op-2');
    const old = new RotationKeyProvider(previous, await key('unused'));
    const target = new RotationKeyProvider(await key('target-initial'), next);
    const registry = new RotationRegistry('op-1');
    const coordination = coordinator();
    if (crash === 'signer') {
      coordination.setApplicationSigner.mockRejectedValueOnce(new Error('crash before signer wiring'));
    } else {
      const persist = coordination.persistRotation.getMockImplementation()!;
      coordination.persistRotation.mockImplementation(async rotation => {
        if (rotation.activated) {
          coordination.persistRotation.mockImplementation(persist);
          throw new Error('crash before activation persistence');
        }
        await persist(rotation);
      });
    }
    let failure: ManagedKeyRotationActivationError | undefined;
    try {
      await rotateManagedOperationalKey({
        domain: DOMAIN, logReference: LR, keyProvider: old, targetKeyProvider: target,
        registryClient: registry, idempotencyKey: 'cross-provider',
        ...coordination, previousProviderReference: 'old-config', newProviderReference: 'saved-target',
      });
    } catch (error) { failure = error as ManagedKeyRotationActivationError; }
    expect(failure).toBeInstanceOf(ManagedKeyRotationActivationError);
    expect(failure!.rotation).toMatchObject({ activated: crash === 'signer', applicationSigningPaused: true });
    expect(coordination.setApplicationSigningPaused).not.toHaveBeenCalledWith(false);
    const resolve = vi.fn(async (reference: string) => reference === 'saved-target' ? target : old);
    const restored = await resumeManagedOperationalKeyRotation({
      rotation: failure!.rotation, resolveKeyProvider: resolve, registryClient: registry, ...coordination,
    });
    expect(resolve.mock.calls).toEqual([['old-config'], ['saved-target']]);
    expect(coordination.setApplicationSigner).toHaveBeenLastCalledWith(target, 'op-2');
    expect(coordination.setApplicationSigner.mock.invocationCallOrder.at(-1))
      .toBeLessThan(coordination.setApplicationSigningPaused.mock.invocationCallOrder.at(-1)!);
    expect(restored.applicationSigningPaused).toBe(false);
    expect(registry.submissions).toHaveLength(1);
    expect(target.activateCalls).toBe(1);
  });

  it.each(['newThumbprint', 'previousThumbprint', 'entryHash', 'logReference'] as const)(
    'rejects a mismatched saved %s before replay or unpause', async field => {
      const previous = await key('op-1');
      const provider = new RotationKeyProvider(previous, await key('op-2'));
      const registry = new RotationRegistry('op-1');
      registry.state = 'pending';
      const coordination = coordinator();
      const pending = await rotateManagedOperationalKey({
        domain: DOMAIN, logReference: LR, keyProvider: provider, registryClient: registry,
        idempotencyKey: 'rotation-1', ...coordination,
      });
      await expect(resumeManagedOperationalKeyRotation({
        rotation: { ...pending, [field]: field === 'logReference' ? LR.replace(STREAM_ID, 'IiIiIiIiIiIiIiIiIiIiIi') : 'wrong' },
        resolveKeyProvider: async () => provider, registryClient: registry, ...coordination,
      })).rejects.toBeInstanceOf(ManagedKeyRotationActivationError);
      expect(registry.submissions).toHaveLength(1);
      expect(coordination.setApplicationSigningPaused).not.toHaveBeenCalledWith(false);
      expect(provider.activateCalls).toBe(0);
    },
  );

  it.each(['publication', 'continuity'])('does not activate with mismatched %s', async mismatch => {
    const previous = await key('op-1');
    const provider = new RotationKeyProvider(previous, await key('op-2'));
    const registry = new RotationRegistry('op-1');
    const coordination = coordinator();
    const verify = coordination.verifyPublicationEvidence.getMockImplementation()!;
    coordination.verifyPublicationEvidence.mockImplementation(async () => {
      const evidence = await verify();
      if (mismatch === 'publication') return { ...evidence, jwks: new JWKS([previous.publicJwk]) } as VerifiedDomain;
      return { ...evidence, logReader: { ...evidence.logReader, readEvent: async () => ({ type: 'RETIREMENT' }) } } as unknown as VerifiedDomain;
    });
    await expect(rotateManagedOperationalKey({
      domain: DOMAIN, logReference: LR, keyProvider: provider, registryClient: registry,
      idempotencyKey: 'rotation-1', ...coordination,
    })).rejects.toBeInstanceOf(ManagedKeyRotationActivationError);
    expect(provider.activateCalls).toBe(0);
    expect(coordination.setApplicationSigningPaused).not.toHaveBeenCalledWith(false);
  });

  it.each(['persistRotation', 'setApplicationSigningPaused', 'setApplicationSigner', 'verifyPublicationEvidence'] as const)(
    'requires %s before key generation', async dependency => {
      const provider = new RotationKeyProvider(await key('op-1'), await key('op-2'));
      const generate = vi.spyOn(provider, 'generateKey');
      await expect(rotateManagedOperationalKey({
        domain: DOMAIN, logReference: LR, keyProvider: provider,
        registryClient: new RotationRegistry('op-1'), idempotencyKey: 'rotation-1',
        ...coordinator(), [dependency]: undefined,
      } as unknown as Parameters<typeof rotateManagedOperationalKey>[0])).rejects.toThrow(dependency);
      expect(generate).not.toHaveBeenCalled();
    },
  );

  it.each(['persistRotation', 'setApplicationSigningPaused'] as const)(
    'preserves exact recovery state and does not submit when %s fails', async dependency => {
      const provider = new RotationKeyProvider(await key('op-1'), await key('op-2'));
      const registry = new RotationRegistry('op-1');
      const coordination = coordinator();
      coordination[dependency].mockRejectedValueOnce(new Error('controller unavailable'));
      let failure: ManagedKeyRotationSubmissionError | undefined;
      try {
        await rotateManagedOperationalKey({
          domain: DOMAIN, logReference: LR, keyProvider: provider, registryClient: registry,
          idempotencyKey: 'rotation-1', ...coordination,
        });
      } catch (error) { failure = error as ManagedKeyRotationSubmissionError; }
      expect(failure).toBeInstanceOf(ManagedKeyRotationSubmissionError);
      expect(failure!.rotation).toMatchObject({ entryHash: await sha256Hex(failure!.rotation.entryBytes), applicationSigningPaused: true });
      expect(registry.submissions).toHaveLength(0);
      const submit = vi.spyOn(registry, 'submitPreparedEvent');
      const resume = {
        rotation: failure!.rotation, resolveKeyProvider: async () => provider, registryClient: registry, ...coordination,
      };
      coordination.persistRotation.mockRejectedValueOnce(new Error('recovery storage unavailable'));
      await expect(resumeManagedOperationalKeyRotation(resume)).rejects.toMatchObject({
        name: 'ManagedKeyRotationActivationError', rotation: failure!.rotation,
        cause: { message: 'recovery storage unavailable' },
      });
      expect(registry.submissions).toHaveLength(0);
      expect(coordination.setApplicationSigningPaused).not.toHaveBeenCalledWith(false);
      coordination.persistRotation.mockClear();
      await expect(resumeManagedOperationalKeyRotation(resume)).resolves.toMatchObject({ activated: true });
      expect(coordination.persistRotation.mock.calls[0]![0]).toEqual(failure!.rotation);
      expect(coordination.persistRotation.mock.invocationCallOrder[0])
        .toBeLessThan(submit.mock.invocationCallOrder[0]!);
      expect(registry.submissions[0]!.bytes).toEqual(failure!.rotation.entryBytes);
      expect(registry.submissions[0]!.idempotencyKey).toBe(failure!.rotation.idempotencyKey);
    },
  );

  it('returns a typed terminal rejection without resubmission', async () => {
    const provider = new RotationKeyProvider(await key('op-1'), await key('op-2'));
    const registry = new RotationRegistry('op-1');
    registry.state = 'rejected';
    const coordination = coordinator();
    let failure: ManagedKeyRotationSubmissionError | undefined;
    try {
      await rotateManagedOperationalKey({
        domain: DOMAIN, logReference: LR, keyProvider: provider, registryClient: registry,
        idempotencyKey: 'rotation-1', ...coordination,
      });
    } catch (error) { failure = error as ManagedKeyRotationSubmissionError; }
    await expect(resumeManagedOperationalKeyRotation({
      rotation: failure!.rotation, resolveKeyProvider: async () => provider, registryClient: registry, ...coordination,
    })).rejects.toMatchObject({ name: 'ManagedKeyRotationSubmissionError', retryWithSameBytes: false });
    expect(registry.submissions).toHaveLength(1);
  });

  it('signs exact prepared bytes and activates only after registry acceptance', async () => {
    const previous = await key('op-1');
    const next = await key('op-2');
    const provider = new RotationKeyProvider(previous, next);
    const registry = new RotationRegistry(previous.publicJwk.kid);
    const submit = vi.spyOn(registry, 'submitPreparedEvent');
    const coordination = coordinator();

    const result = await rotateManagedOperationalKey({
      domain: DOMAIN,
      logReference: LR,
      keyProvider: provider,
      registryClient: registry,
      idempotencyKey: 'rotation-1',
      ...coordination,
    });

    expect(registry.request).toEqual({
      previousKeyId: await jwkThumbprint(previous.publicJwk),
      publicKey: next.publicJwk,
    });
    expect(result).toMatchObject({ previousKid: 'op-1', newKid: 'op-2', activated: true, applicationSigningPaused: false });
    expect(coordination.persistRotation.mock.calls[0]![0]).toMatchObject({ activated: false, applicationSigningPaused: true });
    expect(coordination.persistRotation.mock.calls[0]![0].submission).toBeUndefined();
    expect(coordination.setApplicationSigningPaused.mock.calls).toEqual([[true], [false]]);
    expect(coordination.persistRotation.mock.invocationCallOrder[0])
      .toBeLessThan(coordination.setApplicationSigningPaused.mock.invocationCallOrder[0]!);
    expect(coordination.setApplicationSigningPaused.mock.invocationCallOrder[0])
      .toBeLessThan(submit.mock.invocationCallOrder[0]!);
    expect((await provider.signingKey()).kid).toBe('op-2');
    expect(await provider.listKeyIds()).toEqual(['op-2']);
    await expect(parseC2spEventEntry(result.entryBytes, {
      scope: 'public', logOrigin: 'log.example/dnsid', streamId: STREAM_ID, lr: LR,
    })).resolves.toMatchObject({
      type: 'KEY_ROTATION',
      domain: DOMAIN,
      signingKid: 'op-1',
      newOperationalKid: 'op-2',
    });
  });

  it('does not activate while pending and resumes the same bytes', async () => {
    const previous = await key('op-1');
    const next = await key('op-2');
    const provider = new RotationKeyProvider(previous, next);
    const registry = new RotationRegistry(previous.publicJwk.kid);
    const coordination = coordinator();
    registry.state = 'pending';

    const pending = await rotateManagedOperationalKey({
      domain: DOMAIN,
      logReference: LR,
      keyProvider: provider,
      registryClient: registry,
      idempotencyKey: 'rotation-1',
      ...coordination,
    });
    expect(pending.activated).toBe(false);
    expect((await provider.signingKey()).kid).toBe('op-1');

    registry.state = 'accepted';
    const accepted = await resumeManagedOperationalKeyRotation({ resolveKeyProvider: async () => provider, registryClient: registry, rotation: pending, ...coordination });
    expect(accepted.activated).toBe(true);
    expect(registry.submissions).toHaveLength(2);
    expect(registry.submissions[1]!.bytes).toEqual(registry.submissions[0]!.bytes);
    expect(registry.submissions.map(item => item.idempotencyKey)).toEqual(['rotation-1', 'rotation-1']);
  });

  it('resumes after activation succeeds but superseding the previous key fails', async () => {
    const previous = await key('op-1');
    const next = await key('op-2');
    const provider = new RotationKeyProvider(previous, next);
    const registry = new RotationRegistry(previous.publicJwk.kid);
    const coordination = coordinator();
    provider.failNextSupersede = true;

    let failure: ManagedKeyRotationActivationError | undefined;
    try {
      await rotateManagedOperationalKey({
        domain: DOMAIN,
        logReference: LR,
        keyProvider: provider,
        registryClient: registry,
        idempotencyKey: 'rotation-1',
        ...coordination,
      });
    } catch (error) {
      failure = error as ManagedKeyRotationActivationError;
    }

    expect(failure).toBeInstanceOf(ManagedKeyRotationActivationError);
    expect(failure!.rotation).toMatchObject({ activated: false, submission: { state: 'accepted' } });
    expect((await provider.signingKey()).kid).toBe('op-2');
    expect(await provider.listKeyIds()).toEqual(['op-2', 'op-1']);

    const accepted = await resumeManagedOperationalKeyRotation({
      resolveKeyProvider: async () => provider,
      registryClient: registry,
      rotation: failure!.rotation,
      ...coordination,
    });
    expect(accepted.activated).toBe(true);
    expect(provider.activateCalls).toBe(1);
    expect(await provider.listKeyIds()).toEqual(['op-2']);
    expect(registry.submissions).toHaveLength(1);
  });

  it('preserves exact retry state for an indeterminate submission', async () => {
    const previous = await key('op-1');
    const next = await key('op-2');
    const provider = new RotationKeyProvider(previous, next);
    const registry = new RotationRegistry(previous.publicJwk.kid);
    const coordination = coordinator();
    registry.submitError = new PreparedEventSubmissionError({
      code: 'TLOG_SUBMISSION_INDETERMINATE',
      httpStatus: 503,
      message: 'retry exact bytes',
      state: 'indeterminate',
      retryable: true,
      retryWithSameBytes: true,
    });

    let failure: ManagedKeyRotationSubmissionError | undefined;
    try {
      await rotateManagedOperationalKey({
        domain: DOMAIN,
        logReference: LR,
        keyProvider: provider,
        registryClient: registry,
        idempotencyKey: 'rotation-1',
        ...coordination,
      });
    } catch (error) {
      failure = error as ManagedKeyRotationSubmissionError;
    }
    expect(failure).toBeInstanceOf(ManagedKeyRotationSubmissionError);
    expect(failure!.retryWithSameBytes).toBe(true);
    expect(failure!.rotation.activated).toBe(false);
    expect((await provider.signingKey()).kid).toBe('op-1');

    registry.submitError = undefined;
    const accepted = await resumeManagedOperationalKeyRotation({
      resolveKeyProvider: async () => provider,
      registryClient: registry,
      rotation: failure!.rotation,
      ...coordination,
    });
    expect(accepted.activated).toBe(true);
    expect(registry.submissions[1]!.bytes).toEqual(registry.submissions[0]!.bytes);
  });

  it('does not activate when acceptance names a different entry hash', async () => {
    const previous = await key('op-1');
    const next = await key('op-2');
    const provider = new RotationKeyProvider(previous, next);
    const registry = new RotationRegistry(previous.publicJwk.kid);
    const coordination = coordinator();
    registry.entryHashOverride = '0'.repeat(64);

    await expect(rotateManagedOperationalKey({
      domain: DOMAIN,
      logReference: LR,
      keyProvider: provider,
      registryClient: registry,
      idempotencyKey: 'rotation-1',
      ...coordination,
    })).rejects.toMatchObject({ cause: { message: expect.stringContaining('entry hash does not match') } });
    expect((await provider.signingKey()).kid).toBe('op-1');
  });
});

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', toArrayBuffer(bytes));
  return Buffer.from(digest).toString('hex');
}
