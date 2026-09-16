import { sha256 } from '@noble/hashes/sha2.js';
import type { AgentStatus, AgentStatusState, DnsIdJWK, DNSSECState } from './types.ts';
import type { DnsIdTxtRecord } from './txt-record.ts';
import type { JWKS } from './jwks.ts';
import type { TLSCertificate } from './types.ts';
import type { LoggedStateEvidence, LogReader } from './log.ts';
import type { LogEvent } from './log-events.ts';
import { VerificationError, VerificationCode, type LifecycleErrorCategory } from './errors.ts';
import { parseKaDuration, toBase64Url } from './utils.ts';

/** Result of a successful verifyDomain call. Contains all verified data for the domain. */
export class VerifiedDomain {
  readonly domain: string;
  readonly record: DnsIdTxtRecord;
  readonly jwks: JWKS;
  readonly recordSigningJwks: JWKS;
  readonly signingKey: DnsIdJWK;
  /** RFC 7638 SHA-256 thumbprint of `signingKey`, computed once at verification and reused by acceptance checks. */
  readonly signingKeyThumbprint: string;
  readonly tlsCert: TLSCertificate;
  readonly recordSigningTlsCert: TLSCertificate;
  registryStatus: AgentStatus;
  readonly verifiedAt: Date;
  readonly dnsTTL: number;
  readonly dnsExpiresAt: Date;
  readonly keyBoundAt: Date;
  lastStatusCheckAt: Date;
  readonly dnssecState: DNSSECState;
  readonly logReader: LogReader;

  constructor(fields: {
    domain: string;
    record: DnsIdTxtRecord;
    jwks: JWKS;
    recordSigningJwks?: JWKS;
    signingKey: DnsIdJWK;
    signingKeyThumbprint: string;
    tlsCert: TLSCertificate;
    recordSigningTlsCert?: TLSCertificate;
    registryStatus: AgentStatus;
    verifiedAt: Date;
    dnsTTL: number;
    dnsExpiresAt?: Date;
    keyBoundAt: Date;
    lastStatusCheckAt: Date;
    dnssecState: DNSSECState;
    logReader: LogReader;
  }) {
    this.domain = fields.domain;
    this.record = fields.record;
    this.jwks = fields.jwks;
    this.recordSigningJwks = fields.recordSigningJwks ?? fields.jwks;
    this.signingKey = fields.signingKey;
    this.signingKeyThumbprint = fields.signingKeyThumbprint;
    this.tlsCert = fields.tlsCert;
    this.recordSigningTlsCert = fields.recordSigningTlsCert ?? fields.tlsCert;
    this.registryStatus = fields.registryStatus;
    this.verifiedAt = fields.verifiedAt;
    this.dnsTTL = fields.dnsTTL;
    this.dnsExpiresAt = fields.dnsExpiresAt ?? new Date(fields.verifiedAt.getTime() + fields.dnsTTL * 1000);
    this.keyBoundAt = fields.keyBoundAt;
    this.lastStatusCheckAt = fields.lastStatusCheckAt;
    this.dnssecState = fields.dnssecState;
    this.logReader = fields.logReader;
  }

  /**
   * Returns the agent state from the most recent su fetch.
   * Reflects the state at lastStatusCheckAt, not necessarily right now.
   */
  cachedState(): AgentStatusState {
    return this.registryStatus.state;
  }

  /** Whether the record requests a current log check for high-value operations. */
  requiresLogCheck(): boolean {
    return this.record.policyFlags().has('logchk');
  }

  /**
   * Performs the authoritative lifecycle-log non-revocation check used for a
   * high-value or irreversible operation. Callers decide which operations are
   * high value; local policy may also require this check when `fl=logchk` is
   * absent. Log unavailability and stale evidence fail closed.
   */
  async verifyNonRevocation(at = new Date()): Promise<LoggedStateEvidence> {
    return await this.logReader.verifyNonRevocation(this.domain, at);
  }

  /**
   * Returns the earliest time at which this verified result should be considered stale.
   * Candidates: DNS TTL, TLS cert NotAfter, key age bound (ka).
   */
  expiry(): Date {
    const candidates: number[] = [];

    // DNS TTL: record may have changed (key rotation, re-sign, policy update)
    candidates.push(this.dnsExpiresAt.getTime());

    // TLS certificate validity end
    candidates.push(this.tlsCert.notAfter.getTime());
    candidates.push(this.recordSigningTlsCert.notAfter.getTime());

    // Key age bound: if ka is set and keyBoundAt is non-zero
    if (this.record.ka) {
      candidates.push(this.keyBoundAt.getTime() + parseKaDuration(this.record.ka));
    }

    return new Date(Math.min(...candidates));
  }
}

// ---- DomainLog ----

/** The full verified event history for a domain, loaded from the lifecycle log. */
export class DomainLog {
  readonly domain: string;
  readonly events: LogEvent[];

  constructor(domain: string, events: LogEvent[]) {
    this.domain = domain;
    this.events = events;
  }

  /**
   * Materializes the domain state at a specific point in time.
   * Pure computation — no I/O.
   * @throws VerificationError if no events exist at or before `at`, or no ISSUANCE event found.
   */
  snapshotAt(at: Date): DomainSnapshot {
    if (this.events.length === 0) {
      throw lifecycleError(`no lifecycle events for ${this.domain} at or before ${at.toISOString()}`, 'SNAPSHOT_EMPTY');
    }

    let state: AgentStatusState | '' = '';
    let activeKey: DnsIdJWK | null = null;
    let activeKeyThumbprint = '';
    let keyBoundAt = new Date(0);
    let governanceId = '';
    const eventsUpTo: LogEvent[] = [];
    let pastSnapshotBoundary = false;

    for (const event of this.events) {
      if (event.domain !== this.domain) {
        throw lifecycleError(`lifecycle event domain mismatch for ${this.domain}`, 'DOMAIN_MISMATCH');
      }
      if (!Number.isFinite(event.timestamp.getTime())) {
        throw lifecycleError('invalid lifecycle timestamp', 'INVALID_EVIDENCE');
      }
      // Event order is supplied by the verified log. Return only a prefix: a
      // boundary that skips an event but includes a later log entry is invalid.
      if (event.timestamp > at) {
        pastSnapshotBoundary = true;
        continue;
      }
      if (pastSnapshotBoundary) {
        throw lifecycleError(`snapshot time is not a verified lifecycle prefix for ${this.domain}`, 'SNAPSHOT_NON_PREFIX');
      }
      eventsUpTo.push(event);

      if (state === '') {
        if (event.type !== 'ISSUANCE') {
          throw lifecycleError('first lifecycle event must be ISSUANCE', 'GENESIS_REQUIRED');
        }
      } else if (state === 'REVOKED' || state === 'RETIRED') {
        throw lifecycleError('event after terminal identity state', 'TERMINAL_STATE');
      }

      switch (event.type) {
        case 'ISSUANCE':
          if (state !== '') {
            throw lifecycleError('duplicate ISSUANCE in one identity history', 'DUPLICATE_ISSUANCE');
          }
          // Prefer draft-01's operational slot, then the c2sp-tlog representation,
          // with the pre-draft-01 fields retained as a final compatibility fallback.
          const entityKey = event.entityKey?.jwk ?? event.initialEntityPublicKey ?? null;
          const entityKeyThumbprint = event.entityKey?.thumbprint ?? event.initialEntityThumbprint ?? '';
          activeKey = event.operationalKey?.jwk ?? event.initialOperationalPublicKey ?? event.publicKey ?? null;
          activeKeyThumbprint = event.operationalKey?.thumbprint ?? event.initialOperationalThumbprint ?? event.thumbprint ?? '';
          if (!entityKey || !activeKey || !entityKeyThumbprint || !activeKeyThumbprint
            || entityKeyThumbprint !== synchronousJwkThumbprint(entityKey, 'INVALID_ISSUANCE')
            || activeKeyThumbprint !== synchronousJwkThumbprint(activeKey, 'INVALID_ISSUANCE')
            || entityKeyThumbprint === activeKeyThumbprint || sameJwkMaterial(entityKey, activeKey)) {
            throw lifecycleError('ISSUANCE key binding is invalid', 'INVALID_ISSUANCE');
          }
          state = 'ACTIVE';
          keyBoundAt = event.timestamp;
          governanceId = event.governanceId;
          break;
        case 'KEY_ROTATION':
          if (state !== 'ACTIVE') {
            throw lifecycleError('KEY_ROTATION outside an ACTIVE issuance', 'KEY_CONTINUITY');
          }
          if (event.previousOperationalThumbprint !== activeKeyThumbprint) {
            throw lifecycleError('KEY_ROTATION does not continue from the active key', 'KEY_CONTINUITY');
          }
          if (!event.newOperationalPublicKey || !event.newOperationalThumbprint
            || event.newOperationalThumbprint !== synchronousJwkThumbprint(event.newOperationalPublicKey, 'KEY_CONTINUITY')
            || event.newOperationalThumbprint === activeKeyThumbprint
            || (activeKey && sameJwkMaterial(activeKey, event.newOperationalPublicKey))) {
            throw lifecycleError('KEY_ROTATION new key is invalid', 'KEY_CONTINUITY');
          }
          activeKey = event.newOperationalPublicKey;
          activeKeyThumbprint = event.newOperationalThumbprint;
          keyBoundAt = event.timestamp;
          break;
        case 'REVOCATION':
          if (state !== 'ACTIVE') {
            throw new VerificationError('REVOCATION outside an ACTIVE issuance', {
              code: VerificationCode.LogError,
            });
          }
          if (!REVOCATION_REASONS.has(event.reason)) {
            throw lifecycleError('invalid REVOCATION reason', 'INVALID_REVOCATION_REASON');
          }
          state = 'REVOKED';
          break;
        case 'RETIREMENT':
          if (state !== 'ACTIVE') {
            throw new VerificationError('RETIREMENT outside an ACTIVE issuance', {
              code: VerificationCode.LogError,
            });
          }
          state = 'RETIRED';
          break;
        case 'MIGRATION':
          if (state !== 'ACTIVE' || !event.previousLog || !event.newLog
            || event.previousLog === event.newLog || !event.finalEntryRef) {
            throw lifecycleError('invalid MIGRATION', 'INVALID_MIGRATION');
          }
          break;
        case 'DELEGATION':
          if (state !== 'ACTIVE') {
            throw new VerificationError('DELEGATION outside an ACTIVE issuance', {
              code: VerificationCode.LogError,
            });
          }
          break;
        default:
          throw lifecycleError('unsupported lifecycle event type', 'UNSUPPORTED_EVENT');
      }
    }

    if (state === '' || !activeKey) {
      throw lifecycleError(`no ISSUANCE event found for ${this.domain} at or before ${at.toISOString()}`, 'SNAPSHOT_EMPTY');
    }

    return new DomainSnapshot({
      domain: this.domain,
      historicalState: state,
      activeKey: activeKey!,
      activeKeyThumbprint,
      keyBoundAt,
      governanceId,
      snapshotAt: at,
      events: eventsUpTo,
    });
  }
}

const REVOCATION_REASONS = new Set([
  'keyCompromise',
  'policyViolation',
  'superseded',
  'cessationOfOperation',
]);

function lifecycleError(message: string, errorCategory: LifecycleErrorCategory): VerificationError {
  return new VerificationError(message, { code: VerificationCode.LogError, errorCategory });
}

function synchronousJwkThumbprint(key: DnsIdJWK, errorCategory: LifecycleErrorCategory): string {
  let material: Record<string, string>;
  switch (key.kty) {
    case 'EC': material = { crv: key.crv!, kty: key.kty, x: key.x!, y: key.y! }; break;
    case 'OKP': material = { crv: key.crv!, kty: key.kty, x: key.x! }; break;
    case 'RSA': material = { e: key.e!, kty: key.kty, n: key.n! }; break;
    default: throw lifecycleError('unsupported lifecycle JWK type', errorCategory);
  }
  if (Object.values(material).some(value => typeof value !== 'string' || value.length === 0)) {
    throw lifecycleError('lifecycle JWK is missing public key material', errorCategory);
  }
  return toBase64Url(sha256(new TextEncoder().encode(JSON.stringify(material))));
}

function sameJwkMaterial(a: DnsIdJWK, b: DnsIdJWK): boolean {
  if (a.kty !== b.kty) return false;
  switch (a.kty) {
    case 'EC':
      return a.crv === b.crv && a.x === b.x && a.y === b.y;
    case 'OKP':
      return a.crv === b.crv && a.x === b.x;
    case 'RSA':
      return a.n === b.n && a.e === b.e;
    case 'oct':
      return typeof a.k === 'string' && a.k === b.k;
    default:
      return false;
  }
}

// ---- DomainSnapshot ----

/** The materialized state of a domain at a specific point in time. */
export class DomainSnapshot {
  readonly domain: string;
  /** Lifecycle state materialized from the verified log history at `snapshotAt`. */
  readonly historicalState: AgentStatusState;
  readonly activeKey: DnsIdJWK;
  readonly activeKeyThumbprint: string;
  readonly keyBoundAt: Date;
  readonly governanceId: string;
  readonly snapshotAt: Date;
  readonly events: LogEvent[];

  constructor(fields: {
    domain: string;
    historicalState: AgentStatusState;
    activeKey: DnsIdJWK;
    activeKeyThumbprint: string;
    keyBoundAt: Date;
    governanceId: string;
    snapshotAt: Date;
    events: LogEvent[];
  }) {
    this.domain = fields.domain;
    this.historicalState = fields.historicalState;
    this.activeKey = fields.activeKey;
    this.activeKeyThumbprint = fields.activeKeyThumbprint;
    this.keyBoundAt = fields.keyBoundAt;
    this.governanceId = fields.governanceId;
    this.snapshotAt = fields.snapshotAt;
    this.events = fields.events;
  }
}
