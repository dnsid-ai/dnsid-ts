import { describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import {
  jwkThumbprint,
  toArrayBuffer,
  type DnsIdJWK,
  type KeyProvider,
  type KeyRotationEvent,
} from '@identity-digital/dnsid-protocol';
import {
  canonicalBytes,
  parseC2spEventEntry,
  prepareC2spTlogEventForSigning,
} from '@identity-digital/dnsid-log-c2sp-tlog';
import {
  ManagedKeyRotationActivationError,
  ManagedKeyRotationSubmissionError,
  resumeManagedOperationalKeyRotation,
  rotateManagedOperationalKey,
  type ManagedKeyRotationRegistry,
  type ManagedKeyRotationResult,
} from '@identity-digital/dnsid';
import {
  PreparedEventSubmissionError,
  type KeyRotationPreparationRequest,
  type PreparedRegistryEvent,
  type SubmissionResult,
} from '@identity-digital/dnsid-registry';

const DOMAIN = 'agent.example.com';
const STREAM_ID = 'ERERERERERERERERERERER';
const LR = `c2sp-tlog:public:https://log.example/dnsid#${STREAM_ID}`;

function coordinator() {
  return {
    persistRotation: vi.fn(async (_rotation: ManagedKeyRotationResult) => undefined),
    setApplicationSigningPaused: vi.fn(async (_paused: boolean) => undefined),
  };
}

async function key(kid: string): Promise<{ publicJwk: DnsIdJWK; privateKey: CryptoKey }> {
  const pair = await generateKeyPair('ES256', { extractable: true });
  return {
    publicJwk: { ...await exportJWK(pair.publicKey), kid, alg: 'ES256', use: 'sig' } as DnsIdJWK,
    privateKey: pair.privateKey as CryptoKey,
  };
}

class RotationKeyProvider implements KeyProvider {
  private activeKid: string;
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

  async signingKey(): Promise<DnsIdJWK> { return this.jwk(this.activeKid); }
  async jwk(kid: string): Promise<DnsIdJWK> {
    if (kid === this.previous.publicJwk.kid) return this.previous.publicJwk;
    if (kid === this.next.publicJwk.kid) return this.next.publicJwk;
    throw new Error(`key not found: ${kid}`);
  }
  async listKeyIds(): Promise<string[]> { return [this.activeKid, ...this.retained]; }
  async sign(payload: Uint8Array): Promise<Uint8Array> { return this.signKey(this.activeKid, payload); }
  async signKey(kid: string, payload: Uint8Array): Promise<Uint8Array> {
    if (kid !== this.activeKid && kid !== this.pendingKid) throw new Error(`key is not available for signing: ${kid}`);
    const privateKey = kid === this.previous.publicJwk.kid ? this.previous.privateKey : this.next.privateKey;
    return new Uint8Array(await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      toArrayBuffer(payload),
    ));
  }
  async generateKey(): Promise<string> {
    this.pendingKid = this.next.publicJwk.kid;
    return this.pendingKid;
  }
  async activate(kid: string): Promise<void> {
    this.activateCalls++;
    if (kid !== this.pendingKid) throw new Error(`key is not pending: ${kid}`);
    this.retained.add(this.activeKid);
    this.activeKid = kid;
    this.pendingKid = undefined;
  }
  async supersede(kid: string): Promise<void> {
    if (this.failNextSupersede) {
      this.failNextSupersede = false;
      throw new Error('transient supersede failure');
    }
    if (!this.retained.delete(kid)) throw new Error(`key is not retained: ${kid}`);
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
    const accepted = await resumeManagedOperationalKeyRotation({ keyProvider: provider, registryClient: registry, rotation: pending, ...coordination });
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
      keyProvider: provider,
      registryClient: registry,
      rotation: failure!.rotation,
      ...coordination,
    });
    expect(accepted.activated).toBe(true);
    expect(provider.activateCalls).toBe(1);
    expect(await provider.listKeyIds()).toEqual(['op-2']);
    expect(registry.submissions).toHaveLength(2);
    expect(registry.submissions[1]!.bytes).toEqual(registry.submissions[0]!.bytes);
    expect(registry.submissions.map(item => item.idempotencyKey)).toEqual(['rotation-1', 'rotation-1']);
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
      keyProvider: provider,
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
    })).rejects.toThrow('entry hash does not match');
    expect((await provider.signingKey()).kid).toBe('op-1');
  });
});

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', toArrayBuffer(bytes));
  return Buffer.from(digest).toString('hex');
}
