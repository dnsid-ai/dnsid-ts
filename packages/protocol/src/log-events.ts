import type { DnsIdJWK } from './types.ts';

// ---- Common Base ----

interface BaseLogEvent {
  /** Set by IdentityManager.signAndWriteEvent; leave undefined when constructing. */
  signingKid?: string;
  /** Base64url signature. Set by IdentityManager.signAndWriteEvent; leave undefined when constructing. */
  sig?: string;
  /** Base64url operational-key countersignature. Required for draft-01 ISSUANCE. */
  operationalCountersig?: string;
  /** Base64url new-operational-key proof of possession. Required for c2sp-tlog KEY_ROTATION. */
  newOperationalProof?: string;
  /** Base64url new-entity-key proof of possession. Required for c2sp-tlog ENTITY_KEY_ROTATION. */
  newEntityProof?: string;
}

// ---- Core Events ----

/** A key slot recorded in a draft-01 bilateral ISSUANCE event (ek or ku). */
export interface IssuanceKeySlot {
  jwk: DnsIdJWK;
  /** RFC 7638 JWK thumbprint of `jwk`. */
  thumbprint: string;
  kid?: string;
  /** JWS `alg` the slot's signature is produced/verified under. */
  alg: string;
}

export interface IssuanceEvent extends BaseLogEvent {
  type: 'ISSUANCE';
  domain: string;
  governanceId: string;
  /** c2sp-tlog encoding of the initial operational key. */
  initialOperationalKid?: string;
  initialOperationalAlg?: string;
  initialOperationalPublicKey?: DnsIdJWK;
  initialOperationalThumbprint?: string;
  /** c2sp-tlog encoding of the accountable entity key. */
  initialEntityKid?: string;
  initialEntityAlg?: string;
  initialEntityPublicKey?: DnsIdJWK;
  initialEntityThumbprint?: string;
  timestamp: Date;

  // ---- draft-01: ISSUANCE is a bilateral event (two keys, two signatures) ----
  /** Accountable-entity record-signing key (ek) recorded in the event. */
  entityKey?: IssuanceKeySlot;
  /** Initial operational key (ku) recorded in the event. */
  operationalKey?: IssuanceKeySlot;
  /** Entity-key signature over the canonical binding (base64url). */
  entitySig?: string;
  /** Operational-key countersignature over the same canonical binding (base64url). */
  operationalSig?: string;

  // ---- pre-draft-01 single-key fields; retained for back-compat ----
  /** @deprecated superseded by {@link operationalKey}/{@link entityKey}. */
  kid?: string;
  /** @deprecated superseded by {@link operationalKey}/{@link entityKey}. */
  publicKey?: DnsIdJWK;
  /** @deprecated superseded by the slot thumbprints. */
  thumbprint?: string;
}

/** ISSUANCE shape required by the c2sp-tlog codec and verifier. */
export interface C2spIssuanceEvent extends IssuanceEvent {
  initialOperationalKid: string;
  initialOperationalAlg: string;
  initialOperationalPublicKey: DnsIdJWK;
  initialOperationalThumbprint: string;
  initialEntityKid: string;
  initialEntityAlg: string;
  initialEntityPublicKey: DnsIdJWK;
  initialEntityThumbprint: string;
}

export interface KeyRotationEvent extends BaseLogEvent {
  type: 'KEY_ROTATION';
  domain: string;
  previousOperationalKid: string;
  previousOperationalThumbprint: string;
  newOperationalKid: string;
  newOperationalAlg: string;
  newOperationalThumbprint: string;
  newOperationalPublicKey: DnsIdJWK;
  timestamp: Date;
}

/**
 * Rotation to a new accountable-entity (record-signing) key. Continuity from
 * the entity key active before the event, mirroring {@link KeyRotationEvent}
 * for operational keys. `signingKid`/`sig` carry the previous entity key's
 * authorization (`prev_ae`); `newEntityProof` carries the new entity key's
 * proof of possession (`new_ae`).
 */
export interface EntityKeyRotationEvent extends BaseLogEvent {
  type: 'ENTITY_KEY_ROTATION';
  domain: string;
  previousEntityKid: string;
  previousEntityThumbprint: string;
  newEntityKid: string;
  newEntityAlg: string;
  newEntityThumbprint: string;
  newEntityPublicKey: DnsIdJWK;
  timestamp: Date;
}

export interface RevocationEvent extends BaseLogEvent {
  type: 'REVOCATION';
  domain: string;
  timestamp: Date;
  reason: 'keyCompromise' | 'policyViolation' | 'superseded' | 'cessationOfOperation';
}

export interface RetirementEvent extends BaseLogEvent {
  type: 'RETIREMENT';
  domain: string;
  timestamp: Date;
}

export interface MigrationEvent extends BaseLogEvent {
  type: 'MIGRATION';
  domain: string;
  previousLog: string;
  newLog: string;
  finalEntryRef: string;
  timestamp: Date;
}

// ---- Optional Events ----

export interface DelegationEvent extends BaseLogEvent {
  type: 'DELEGATION';
  domain: string;
  delegatee: string;
  scope: string;
  expiry: Date;
  timestamp: Date;
}

// ---- Union ----

export type LogEvent =
  | IssuanceEvent
  | KeyRotationEvent
  | EntityKeyRotationEvent
  | RevocationEvent
  | RetirementEvent
  | MigrationEvent
  | DelegationEvent;

export type LogEventType = LogEvent['type'];
