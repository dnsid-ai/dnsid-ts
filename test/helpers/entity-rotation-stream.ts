import { generateKeyPair, exportJWK } from 'jose';
import { jwkThumbprint, toArrayBuffer, toBase64Url, type DnsIdJWK, type LogEvent } from '@dnsid-ai/protocol';
import { canonicalBytes, c2spEventId, eventToC2spEnvelope, signedC2spEntryBytes, stateHash, type C2spEventContext } from '@dnsid-ai/log-c2sp-tlog';

/** ES256 lifecycle key with its private half, for building signed test streams. */
export interface TestKey { publicJwk: DnsIdJWK; privateKey: CryptoKey; thumbprint: string }

export async function testKey(kid: string, alg: 'ES256' | 'EdDSA' = 'ES256'): Promise<TestKey> {
  const pair = await generateKeyPair(alg, { extractable: true });
  const publicJwk = { ...await exportJWK(pair.publicKey), kid, alg } as DnsIdJWK;
  return { publicJwk, privateKey: pair.privateKey as CryptoKey, thumbprint: await jwkThumbprint(publicJwk) };
}

export async function signBytes(bytes: Uint8Array, key: TestKey): Promise<string> {
  const algorithm = key.publicJwk.alg === 'EdDSA' ? { name: 'Ed25519' } : { name: 'ECDSA', hash: 'SHA-256' };
  return toBase64Url(new Uint8Array(await crypto.subtle.sign(algorithm, key.privateKey, toArrayBuffer(bytes))));
}

type Context = Required<Pick<C2spEventContext, 'scope' | 'logOrigin' | 'streamId' | 'lr'>>;

/** Signature override for one role: a different signing key, an explicit kid, or omission. */
export interface RoleOverride { signer?: TestKey; kid?: string; omit?: boolean }

/** Options shared by every appended event. */
export interface AppendOptions {
  /** Whether the builder's chain/authority state advances (false for events a verifier must skip). */
  apply?: boolean;
  /** Mutates the unsigned envelope before signing (structural negatives). */
  mutate?: (envelope: Record<string, unknown>) => void;
}

/**
 * Builds a chained, signed c2sp-tlog lifecycle stream for one identity. Each
 * appended event chains from the last applied event; `apply: false` appends a
 * signed entry without advancing the chain, as for a candidate the verifier
 * must skip or reject.
 */
export class LifecycleStreamBuilder {
  readonly entries: Uint8Array[] = [];
  entity!: TestKey;
  operational!: TestKey;
  private lastApplied?: Uint8Array;
  private sequence = -1;
  private state?: Record<string, unknown>;
  private seconds = 1;

  constructor(readonly fqdn: string, readonly context: Context, readonly governanceId = 'example.com') {}

  /** Lifecycle state hash input after the last applied event. */
  currentState(): Record<string, unknown> | undefined { return this.state; }

  async issuance(entity: TestKey, operational: TestKey, options: AppendOptions = {}): Promise<Uint8Array> {
    const event: LogEvent = {
      type: 'ISSUANCE', domain: this.fqdn, governanceId: this.governanceId, timestamp: this.nextTimestamp(),
      initialEntityKid: entity.publicJwk.kid, initialEntityAlg: entity.publicJwk.alg!, initialEntityPublicKey: entity.publicJwk, initialEntityThumbprint: entity.thumbprint,
      initialOperationalKid: operational.publicJwk.kid, initialOperationalAlg: operational.publicJwk.alg!, initialOperationalPublicKey: operational.publicJwk, initialOperationalThumbprint: operational.thumbprint,
    };
    const bytes = await this.append(event, { seq: 0 }, { ae: [entity], op: [operational] }, options);
    if (options.apply !== false) {
      this.entity = entity;
      this.operational = operational;
      this.sequence = 0;
      this.lastApplied = bytes;
      this.state = { fqdn: this.fqdn, status: 'ACTIVE', entity_thumb: entity.thumbprint, operational_thumb: operational.thumbprint };
    }
    return bytes;
  }

  /** Destination-stream MIGRATION genesis, signed by the entity key current at the end of the prior history. */
  async migration(entity: TestKey, operational: TestKey, previousLog: string, finalEntryRef: string): Promise<Uint8Array> {
    const event: LogEvent = {
      type: 'MIGRATION', domain: this.fqdn, timestamp: this.nextTimestamp(),
      previousLog, newLog: this.context.lr, finalEntryRef,
    };
    const bytes = await this.append(event, { seq: 0 }, { ae: [entity] }, {});
    this.entity = entity;
    this.operational = operational;
    this.sequence = 0;
    this.lastApplied = bytes;
    this.state = { fqdn: this.fqdn, status: 'ACTIVE', entity_thumb: entity.thumbprint, operational_thumb: operational.thumbprint };
    return bytes;
  }

  async entityKeyRotation(newEntity: TestKey, options: AppendOptions & {
    previous?: RoleOverride; next?: RoleOverride; previousThumbprint?: string;
  } = {}): Promise<Uint8Array> {
    const event: LogEvent = {
      type: 'ENTITY_KEY_ROTATION', domain: this.fqdn, timestamp: this.nextTimestamp(),
      previousEntityKid: this.entity.publicJwk.kid,
      previousEntityThumbprint: options.previousThumbprint ?? this.entity.thumbprint,
      newEntityKid: newEntity.publicJwk.kid, newEntityAlg: newEntity.publicJwk.alg!,
      newEntityPublicKey: newEntity.publicJwk, newEntityThumbprint: newEntity.thumbprint,
    };
    const bytes = await this.append(event, this.chain(), {
      prev_ae: [this.entity, options.previous], new_ae: [newEntity, options.next],
    }, options);
    if (options.apply !== false) this.advance(bytes, { entity_thumb: newEntity.thumbprint }, () => { this.entity = newEntity; });
    return bytes;
  }

  async keyRotation(newOperational: TestKey, options: AppendOptions = {}): Promise<Uint8Array> {
    const event: LogEvent = {
      type: 'KEY_ROTATION', domain: this.fqdn, timestamp: this.nextTimestamp(),
      previousOperationalKid: this.operational.publicJwk.kid, previousOperationalThumbprint: this.operational.thumbprint,
      newOperationalKid: newOperational.publicJwk.kid, newOperationalAlg: newOperational.publicJwk.alg!,
      newOperationalPublicKey: newOperational.publicJwk, newOperationalThumbprint: newOperational.thumbprint,
    };
    const bytes = await this.append(event, this.chain(), { prev_op: [this.operational], new_op: [newOperational] }, options);
    if (options.apply !== false) this.advance(bytes, { operational_thumb: newOperational.thumbprint }, () => { this.operational = newOperational; });
    return bytes;
  }

  async revocation(options: AppendOptions & { signer?: TestKey } = {}): Promise<Uint8Array> {
    const event: LogEvent = { type: 'REVOCATION', domain: this.fqdn, timestamp: this.nextTimestamp(), reason: 'superseded' };
    const signer = options.signer ?? this.entity;
    const bytes = await this.append(event, this.chain(), { ae: [signer] }, options);
    if (options.apply !== false) this.advance(bytes, { status: 'REVOKED' });
    return bytes;
  }

  async retirement(options: AppendOptions = {}): Promise<Uint8Array> {
    const event: LogEvent = { type: 'RETIREMENT', domain: this.fqdn, timestamp: this.nextTimestamp() };
    const bytes = await this.append(event, this.chain(), { ae: [this.entity] }, options);
    if (options.apply !== false) this.advance(bytes, { status: 'RETIRED' });
    return bytes;
  }

  /** Chain fields for the next event after the last applied one. */
  chain(): C2spEventContext {
    if (!this.lastApplied || !this.state) return { seq: 0 };
    return { seq: this.sequence + 1, prevEventId: c2spEventId(signedC2spEntryBytes(this.lastApplied)), prevStateHash: stateHash(this.state) };
  }

  private advance(bytes: Uint8Array, state: Record<string, unknown>, apply?: () => void): void {
    apply?.();
    this.sequence += 1;
    this.lastApplied = bytes;
    this.state = { ...this.state, ...state };
  }

  private nextTimestamp(): Date {
    return new Date((this.seconds++) * 1000);
  }

  private async append(
    event: LogEvent,
    chain: C2spEventContext,
    roles: Record<string, [TestKey, RoleOverride?]>,
    options: AppendOptions,
  ): Promise<Uint8Array> {
    const envelope = eventToC2spEnvelope(event, { ...this.context, ...chain }, false);
    options.mutate?.(envelope);
    const signed = canonicalBytes(envelope);
    const sigs: Record<string, { kid: string; sig: string }> = {};
    for (const [role, [key, override]] of Object.entries(roles)) {
      if (override?.omit) continue;
      sigs[role] = { kid: override?.kid ?? key.publicJwk.kid, sig: await signBytes(signed, override?.signer ?? key) };
    }
    const bytes = canonicalBytes({ ...envelope, sigs });
    this.entries.push(bytes);
    return bytes;
  }
}
