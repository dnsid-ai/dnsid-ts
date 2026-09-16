import { withVerificationBudget, waitForVerification, DomainLog, jwkThumbprint, normalizeFQDN, VerificationCode, VerificationError, type C2spIssuanceEvent, type DnsIdJWK, type DnsIdTxtRecord, type KeyProvider, type Log, type LoggedStateEvidence, type LogEvent, type LogReader, type LogRef, type LogSignerRole } from '@dnsid-ai/protocol';
import { parseC2spTlogLr, type ParsedC2spTlogLr } from './lr.ts';
import { parseC2spEventEntry, signedC2spEventBytes, signedC2spEntryBytes, c2spEventId, type C2spEventContext } from './event-codec.ts';
import { enforceCheckpointPolicy, type C2spTlogPolicy } from './policy.ts';
import { createDefaultC2spBoundedResourceFetcher, DEFAULT_C2SP_REQUEST_TIMEOUT_MS, ScanStreamSource, validateC2spResourceFetcher, type C2spBoundedResourceFetcher, type StreamEvidence, type StreamSource } from './stream-source.ts';
import { leafHash, merkleRootFromEntries } from './merkle.ts';
import { stitchVerifiedMigrationHistory, stitchVerifiedMigrationReferences, verifyStreamLifecycle, verifyLifecycle, type VerifiedLifecycleEvent, type MigrationVerificationResult, type StreamVerifierOptions } from './stream-verifier.ts';
import { C2spTlogError, C2spTlogVerificationError, c2spLogError } from './errors.ts';
import { verifyC2spTlogProof, type TlogProofV1 } from './proof.ts';
import { advanceTrustedC2spCheckpoint, InMemoryTrustedC2spCheckpointStore, MissingC2spConsistencyEvidenceError, type C2spConsistencyProofSource, type TrustedC2spCheckpointStore } from './checkpoint-trust.ts';
import { DEFAULT_C2SP_MAX_STREAM_BUNDLE_BYTES, DEFAULT_C2SP_MAX_STREAM_BUNDLE_EVENTS, verifyC2spStreamBundleContents } from './stream-bundle.ts';
import type { SignedNoteKey } from './signed-note.ts';
import type { Checkpoint } from './checkpoint.ts';
import {
  c2spTlogEntryBytes,
  parsePreparedC2spTlogEvent,
  prepareC2spTlogEventForSigning,
  signPreparedC2spTlogEvent,
  writePreparedEvent,
  type C2spChain,
  type C2spSignerRole,
  type C2spTlogAppendOptions,
  type PreparedC2spTlogEvent,
  type PreparedC2spVerificationContext,
  type SignPreparedC2spOptions,
} from './writer.ts';

/** Independently trusted inputs and limits for preferred stream-bundle reads. */
export interface C2spStreamBundleReaderOptions {
  policyDocument: Uint8Array;
  bundleKeys: SignedNoteKey[];
  maxBundleLifetimeMs: number;
  checkpointFreshnessMs: number;
  maxBundleBytes?: number;
  maxEvents?: number;
  /** Disables raw-scan fallback when the bundle endpoint is unavailable. */
  required?: boolean;
}

/** Configuration for {@link C2spTlogReader}; only `policy` is required. */
export interface C2spTlogReaderOptions {
  /** Local trust policy: accepted log keys and witness quorum per origin. */
  policy: C2spTlogPolicy;
  /** Bounded resource fetcher for the default {@link ScanStreamSource}; ignored when `streamSource` is set. */
  resourceFetcher?: C2spBoundedResourceFetcher;
  /** Alternative raw evidence source; defaults to a complete tlog-tiles scan. */
  streamSource?: StreamSource;
  /** Preferred verified per-domain bundle source. Raw scans remain the bounded unavailable-path fallback. */
  streamBundle?: C2spStreamBundleReaderOptions;
  /** Inclusion proofs by entry index, required by `readEvent` for historical refs. */
  proofs?: Record<string, TlogProofV1 | string>;
  /** @deprecated Ignored: all scopes require logical predecessor chains. */
  unchained?: boolean;
  /** Trusted accountable-entity key for lifecycle verification. */
  entityKey?: DnsIdJWK;
  /** Accepted timestamp clock skew in milliseconds (default zero). */
  allowedClockSkew?: number;
  /** Maximum checkpoint age in milliseconds; required by `verifyNonRevocation`. */
  checkpointMaxAge?: number;
  maxTreeSize?: number;
  maxCheckpointBytes?: number;
  maxEntryBundleBytes?: number;
  maxTotalEntryBytes?: number;
  requestTimeoutMs?: number;
  signal?: AbortSignal;
  verifyMigration?: StreamVerifierOptions['verifyMigration'];
  trustedCheckpointStore?: TrustedC2spCheckpointStore;
  consistencyProofSource?: C2spConsistencyProofSource;
}

interface VerifiedHistory {
  events: LogEvent[];
  checkpointWitnessTime: Date;
  checkpoint: Uint8Array;
  completeThrough: string;
  completenessMode: string;
  indexedEvents: VerifiedLifecycleEvent[];
  /** Verified reference aligned with each stitched event; absent when a migration callback omitted prior boundaries. */
  historyReferences?: LogRef[];
  validUntilMs?: number;
}

interface CachedHistory {
  domain: string;
  entityKey: DnsIdJWK;
  promise: Promise<VerifiedHistory>;
  validUntilMs?: number;
}

/**
 * LogReader for the `c2sp-tlog` method: verifies an agent's identity-record
 * lifecycle against a C2SP tlog-tiles log. Evidence is loaded through the
 * configured stream source, checkpoints are policy-enforced and advanced in a
 * trusted checkpoint store. One verified lifecycle snapshot is shared by the
 * binding, continuity, and key-age checks performed by one reader.
 *
 * @throws VerificationError (LogError) from every LogReader boundary.
 */
export class C2spTlogReader implements LogReader {
  readonly parsed: ParsedC2spTlogLr;
  private readonly source: StreamSource;
  private readonly proofs: Record<string, TlogProofV1 | string>;
  private readonly checkpointStore: TrustedC2spCheckpointStore;
  private readonly resourceFetcher?: C2spBoundedResourceFetcher;
  private trustedEntityKey?: DnsIdJWK;
  private cachedHistory?: CachedHistory;

  constructor(readonly lr: string, private readonly options: C2spTlogReaderOptions) {
    this.parsed = parseC2spTlogLr(lr);
    this.validateTimeOptions();
    this.resourceFetcher = options.resourceFetcher ?? (options.streamBundle ? createDefaultC2spBoundedResourceFetcher() : undefined);
    if (this.resourceFetcher) validateC2spResourceFetcher(this.resourceFetcher);
    this.source = options.streamSource ?? new ScanStreamSource({
      authenticateCheckpoint: (checkpoint) => {
        enforceCheckpointPolicy(checkpoint, this.parsed.origin, options.policy, this.parsed.scope, Date.now(), this.allowedClockSkew());
      },
      maxTreeSize: options.maxTreeSize,
      maxCheckpointBytes: options.maxCheckpointBytes,
      maxEntryBundleBytes: options.maxEntryBundleBytes,
      maxTotalEntryBytes: options.maxTotalEntryBytes,
      requestTimeoutMs: options.requestTimeoutMs,
      signal: options.signal,
    }, this.resourceFetcher);
    this.proofs = options.proofs ?? {};
    this.checkpointStore = options.trustedCheckpointStore ?? new InMemoryTrustedC2spCheckpointStore();
  }

  async canonical(event: LogEvent): Promise<Uint8Array> {
    if (event.type !== 'ISSUANCE') throw new VerificationError('c2sp-tlog events after ISSUANCE require the prepared-event API', { code: VerificationCode.LogError });
    return signedC2spEventBytes(event, { ...this.context(), seq: 0 });
  }

  additionalSignerRoles(event: LogEvent): LogSignerRole[] {
    return event.type === 'KEY_ROTATION' ? ['NewOperational'] : [];
  }

  async keyTimestamp(domain: string, keyThumbprint: string): Promise<Date> {
    for (const e of await this.rebuildHistory(domain)) {
      if (e.type === 'ISSUANCE' && e.initialOperationalThumbprint === keyThumbprint) return e.timestamp;
      if (e.type === 'KEY_ROTATION' && e.newOperationalThumbprint === keyThumbprint) return e.timestamp;
    }
    throw new VerificationError('key thumbprint not found in C2SP lifecycle history', { code: VerificationCode.LogError });
  }

  async verifyBilateralBinding(record: unknown, entityKey: unknown, operationalKey: unknown): Promise<{ initialOperationalThumbprint: string; initialEntityThumbprint: string; timestamp: Date }> {
    const dnsRecord = record as Partial<DnsIdTxtRecord> & { domain?: string; fqdn?: string };
    const domain = dnsRecord.domain ?? dnsRecord.fqdn ?? dnsRecord.agentFQDN;
    if (!domain) throw new VerificationError('cannot infer domain for bilateral binding', { code: VerificationCode.LogError });
    if (!entityKey || !operationalKey) throw new VerificationError('entity and operational keys are required for C2SP bilateral binding', { code: VerificationCode.LogError });
    const entity = entityKey as DnsIdJWK;
    const initialEntityThumbprint = await jwkThumbprint(entity);
    const verifiedHistory = await this.loadCompleteHistory(domain, entity);
    const history = verifiedHistory.events;
    this.trustedEntityKey = entity;
    const issuance = history.find((e) => e.type === 'ISSUANCE');
    if (!issuance || issuance.type !== 'ISSUANCE') throw new VerificationError('ISSUANCE not found', { code: VerificationCode.LogError });
    assertC2spIssuanceEvent(issuance);
    if (issuance.domain !== domain || issuance.governanceId !== dnsRecord.gi) throw new VerificationError('ISSUANCE does not match current domain and governance ID', { code: VerificationCode.LogError });
    if (issuance.initialEntityThumbprint !== initialEntityThumbprint) throw new VerificationError('ISSUANCE entity key does not match current ek key', { code: VerificationCode.LogError });
    const currentOperationalThumbprint = await jwkThumbprint(operationalKey as DnsIdJWK);
    const recordedOperational = history.some((e) => e.type === 'ISSUANCE'
      ? e.initialOperationalThumbprint === currentOperationalThumbprint
      : e.type === 'KEY_ROTATION' && e.newOperationalThumbprint === currentOperationalThumbprint);
    if (!recordedOperational) throw new VerificationError('current operational key is not recorded in lifecycle history', { code: VerificationCode.LogError });
    const snapshot = latestSnapshot(domain, history);
    if (snapshot.historicalState !== 'ACTIVE') throw new VerificationError(`domain ${domain} is ${snapshot.historicalState}`, { code: VerificationCode.LogError });
    if (snapshot.activeKeyThumbprint !== currentOperationalThumbprint) throw new VerificationError('current operational key mismatch', { code: VerificationCode.LogError });
    return { initialOperationalThumbprint: issuance.initialOperationalThumbprint, initialEntityThumbprint: issuance.initialEntityThumbprint, timestamp: issuance.timestamp };
  }

  async verifyOperationalContinuity(domain: string, initialOperationalThumbprint: string, currentOperationalThumbprint: string): Promise<void> {
    const verifiedHistory = await this.loadCompleteHistory(domain);
    const history = verifiedHistory.events;
    const first = history.find((e) => e.type === 'ISSUANCE');
    if (!first || first.type !== 'ISSUANCE' || first.initialOperationalThumbprint !== initialOperationalThumbprint) throw new VerificationError('initial operational key mismatch', { code: VerificationCode.LogError });
    assertC2spIssuanceEvent(first);
    const snap = latestSnapshot(domain, history);
    if (snap.historicalState !== 'ACTIVE') throw new VerificationError(`domain ${domain} is ${snap.historicalState}`, { code: VerificationCode.LogError });
    if (snap.activeKeyThumbprint !== currentOperationalThumbprint) throw new VerificationError('current operational key mismatch', { code: VerificationCode.LogError });
  }

  async verifyNonRevocation(domain: string, at: Date): Promise<LoggedStateEvidence> {
    if (this.options.checkpointMaxAge === undefined) throw new VerificationError('non-revocation verification requires checkpointMaxAge', { code: VerificationCode.LogError });
    const trustedEntityKey = this.options.entityKey ?? this.trustedEntityKey;
    if (!trustedEntityKey) throw new VerificationError('C2SP lifecycle verification requires a trusted entity key', { code: VerificationCode.LogError });
    const verified = await withVerificationBudget(signal => this.loadAndVerifyHistory(domain, trustedEntityKey, signal), { signal: this.options.signal });
    this.assertFresh(verified.checkpointWitnessTime);
    const snapshot = new DomainLog(domain, verified.events).snapshotAt(at);
    if (snapshot.historicalState === 'REVOKED' || snapshot.historicalState === 'RETIRED') {
      throw new VerificationError(`domain ${domain} was ${snapshot.historicalState.toLowerCase()}`, { code: VerificationCode.LogError });
    }
    const references = verified.historyReferences;
    const start = references?.[0];
    const end = references?.[snapshot.events.length - 1];
    if (!start || !end || references.length !== verified.events.length) throw new VerificationError('C2SP non-revocation evidence has no verified history bounds', { code: VerificationCode.LogError, errorCategory: 'INVALID_EVIDENCE' });
    return {
      logReference: this.parsed.lr,
      loggedState: snapshot.historicalState,
      historyStart: start,
      historyEnd: end,
      completeThrough: verified.completeThrough,
      completenessMode: verified.completenessMode,
      checkpoint: verified.checkpoint.slice(),
      freshnessTime: new Date(verified.checkpointWitnessTime),
    };
  }

  async readEvent(ref: LogRef): Promise<LogEvent> {
    return withVerificationBudget(signal => this.readEventWithinBudget(ref, signal), { signal: this.options.signal });
  }

  private async readEventWithinBudget(ref: LogRef, signal: AbortSignal): Promise<LogEvent> {
    const parsed = parseC2spTlogLr(ref);
    if (parsed.scope !== this.parsed.scope || parsed.logPrefix !== this.parsed.logPrefix || parsed.streamId !== this.parsed.streamId) {
      throw new VerificationError('C2SP event ref does not belong to this reader', { code: VerificationCode.LogError });
    }
    if (parsed.entryIndex === undefined) throw new VerificationError('C2SP event ref missing @index', { code: VerificationCode.LogError });
    const proof = this.proofs[String(parsed.entryIndex)];
    if (!proof) throw new VerificationError('C2SP readEvent requires a proof/source for historical inclusion', { code: VerificationCode.LogError });
    const evidence = await this.loadEvidence(parsed.logPrefix, signal);
    const entry = evidence.entries.find((e) => e.index === parsed.entryIndex);
    if (!entry) throw new VerificationError('C2SP entry not found in source', { code: VerificationCode.LogError });
    const verifiedProof = verifyC2spTlogProof(entry.bytes, proof, this.options.policy, parsed.origin, parsed.scope, Date.now(), this.allowedClockSkew());
    if (verifiedProof.index !== parsed.entryIndex) throw new VerificationError('C2SP proof index mismatch', { code: VerificationCode.LogError });
    const event = await parseC2spEventEntry(entry.bytes, this.context(parsed));
    const proofPolicyResult = enforceCheckpointPolicy(verifiedProof.checkpoint, parsed.origin, this.options.policy, parsed.scope, Date.now(), this.allowedClockSkew());
    if (!proofPolicyResult.checkpointWitnessTime) throw new VerificationError('C2SP proof timestamp requires an accepted timestamped witness quorum', { code: VerificationCode.LogError, errorCategory: 'INVALID_EVIDENCE' });
    if (event.timestamp.getTime() > proofPolicyResult.checkpointWitnessTime.getTime() + this.allowedClockSkew()) {
      throw new VerificationError('C2SP event timestamp is later than its proof checkpoint integration time', { code: VerificationCode.LogError, errorCategory: 'INVALID_EVIDENCE' });
    }
    const entityKey = this.options.entityKey ?? this.trustedEntityKey;
    if (!entityKey) throw new VerificationError('C2SP readEvent requires a trusted entity key', { code: VerificationCode.LogError });
    if (this.options.streamBundle) {
      const bundled = await this.loadBundleHistory(event.domain, entityKey, signal);
      if (bundled) {
        return this.verifyOccurrence(entry, event, bundled.indexedEvents, entityKey, bundled.checkpointWitnessTime, signal);
      }
    }
    if (!evidence.complete) throw new VerificationError('C2SP readEvent requires complete lifecycle evidence for event authorization', { code: VerificationCode.LogError, errorCategory: 'INCOMPLETE_STREAM' });
    const policyResult = enforceCheckpointPolicy(evidence.checkpoint, parsed.origin, this.options.policy, parsed.scope, Date.now(), this.allowedClockSkew());
    if (!policyResult.checkpointWitnessTime) throw new VerificationError('C2SP event timestamp requires an accepted timestamped witness quorum', { code: VerificationCode.LogError, errorCategory: 'INVALID_EVIDENCE' });
    assertCompleteScan(evidence);
    await advanceTrustedC2spCheckpoint(this.checkpointStore, parsed, evidence.checkpoint, policyResult.checkpointWitnessTime, {
      signal,
      consistencyProofSource: this.options.consistencyProofSource,
      completeEntries: evidence.entries,
    });
    const verified = await verifyStreamLifecycle(evidence.entries, event.domain, { ...this.verifierOptions(parsed, entityKey, policyResult.checkpointWitnessTime), signal });
    return this.verifyOccurrence(entry, event, verified, entityKey, policyResult.checkpointWitnessTime, signal);
  }

  private async verifyOccurrence(entry: { index: number; bytes: Uint8Array }, event: LogEvent, history: VerifiedLifecycleEvent[], entityKey: DnsIdJWK, witnessTime: Date, signal: AbortSignal): Promise<LogEvent> {
    const signed = signedC2spEntryBytes(entry.bytes);
    const position = history.findIndex(item => c2spEventId(signedC2spEntryBytes(item.bytes)) === c2spEventId(signed));
    if (position < 0 || history[position]!.index > entry.index || !Buffer.from(signedC2spEntryBytes(history[position]!.bytes)).equals(Buffer.from(signed))) {
      throw new VerificationError('C2SP event is not authorized by its lifecycle history', { code: VerificationCode.LogError });
    }
    await verifyLifecycle([...history.slice(0, position), { ...entry, event, leafHash: leafHash(entry.bytes) }], { ...this.verifierOptions(this.parsed, entityKey, witnessTime), signal });
    return event;
  }

  async rebuildHistory(domain: string): Promise<LogEvent[]> { return (await this.loadCompleteHistory(domain)).events; }

  private async loadCompleteHistory(domain: string, entityKey?: DnsIdJWK): Promise<VerifiedHistory> {
    return withVerificationBudget(signal => this.loadCompleteHistoryWithinBudget(domain, entityKey, signal), { signal: this.options.signal });
  }

  private async loadCompleteHistoryWithinBudget(domain: string, entityKey: DnsIdJWK | undefined, signal: AbortSignal): Promise<VerifiedHistory> {
    const trustedEntityKey = entityKey ?? this.options.entityKey ?? this.trustedEntityKey;
    if (!trustedEntityKey) throw new VerificationError('C2SP lifecycle verification requires a trusted entity key', { code: VerificationCode.LogError });
    const cached = this.cachedHistory;
    if (cached?.domain === domain && cached.entityKey === trustedEntityKey
      && (cached.validUntilMs === undefined || Date.now() < cached.validUntilMs)) return await cached.promise;

    const promise = this.loadAndVerifyHistory(domain, trustedEntityKey, signal);
    const next: CachedHistory = { domain, entityKey: trustedEntityKey, promise };
    this.cachedHistory = next;
    try {
      const history = await promise;
      next.validUntilMs = history.validUntilMs ?? Number.POSITIVE_INFINITY;
      return history;
    } catch (cause) {
      if (this.cachedHistory === next) this.cachedHistory = undefined;
      throw cause;
    }
  }

  private async loadAndVerifyHistory(domain: string, trustedEntityKey: DnsIdJWK, signal: AbortSignal): Promise<VerifiedHistory> {
    const bundled = await this.loadBundleHistory(domain, trustedEntityKey, signal);
    if (bundled) return bundled;
    const evidence = await this.loadEvidence(this.parsed.logPrefix, signal);
    if (!evidence.complete) throw new VerificationError('C2SP stream source is incomplete for current-state verification', { code: VerificationCode.LogError, errorCategory: 'INCOMPLETE_STREAM' });
    const policyResult = enforceCheckpointPolicy(evidence.checkpoint, this.parsed.origin, this.options.policy, this.parsed.scope, Date.now(), this.allowedClockSkew());
    if (!policyResult.checkpointWitnessTime) throw new VerificationError('C2SP lifecycle timestamps require an accepted timestamped witness quorum', { code: VerificationCode.LogError, errorCategory: 'INVALID_EVIDENCE' });
    assertCompleteScan(evidence);
    await advanceTrustedC2spCheckpoint(this.checkpointStore, this.parsed, evidence.checkpoint, policyResult.checkpointWitnessTime, {
      signal,
      consistencyProofSource: this.options.consistencyProofSource,
      completeEntries: evidence.entries,
    });
    let migration: MigrationVerificationResult | undefined;
    const verifierOptions = { ...this.verifierOptions(this.parsed, trustedEntityKey, policyResult.checkpointWitnessTime), signal };
    if (verifierOptions.verifyMigration) {
      const verifyMigration = verifierOptions.verifyMigration;
      verifierOptions.verifyMigration = async (event) => {
        migration = await waitForVerification(() => verifyMigration(event, { signal }), signal);
        return migration;
      };
    }
    const verified = await verifyStreamLifecycle(evidence.entries, domain, verifierOptions);
    let events = verified.map((v) => v.event);
    const currentReferences = verified.map(item => `${this.parsed.lr}@${item.index}`);
    let historyReferences: LogRef[] | undefined = currentReferences;
    if (events[0]?.type === 'MIGRATION') {
      if (!migration) {
        throw new C2spTlogVerificationError('MIGRATION requires stitched verified prior-log history', 'INVALID_MIGRATION');
      }
      if (migration.priorHistoryReferences) historyReferences = stitchVerifiedMigrationReferences(events, currentReferences, migration);
      else historyReferences = undefined;
      events = await stitchVerifiedMigrationHistory(domain, events, migration);
    }
    return {
      events,
      checkpointWitnessTime: policyResult.checkpointWitnessTime,
      checkpoint: checkpointEvidenceBytes(evidence.checkpoint),
      completeThrough: String(evidence.checkpoint.treeSize),
      completenessMode: 'full-scan',
      indexedEvents: verified,
      historyReferences,
    };
  }

  private async loadBundleHistory(domain: string, trustedEntityKey: DnsIdJWK, signal: AbortSignal): Promise<VerifiedHistory | undefined> {
    const config = this.options.streamBundle;
    if (!config) return undefined;
    const fqdn = normalizeFQDN(domain, true);
    const endpoint = `${this.parsed.logPrefix}/streams/${encodeURIComponent(fqdn)}?format=bundle`;
    const maximum = config.maxBundleBytes ?? DEFAULT_C2SP_MAX_STREAM_BUNDLE_BYTES;
    let bytes: Uint8Array;
    try {
      bytes = await waitForVerification(() => this.resourceFetcher!.fetchBounded(endpoint, maximum, {
        signal,
        timeoutMs: this.options.requestTimeoutMs ?? DEFAULT_C2SP_REQUEST_TIMEOUT_MS,
      }), signal);
      if (!(bytes instanceof Uint8Array) || bytes.length > maximum) throw new C2spTlogVerificationError(`C2SP response exceeds configured byte maximum ${maximum}: ${endpoint}`);
    } catch (cause) {
      if (!config.required && bundleFallbackAllowed(cause)) return undefined;
      throw c2spLogError('C2SP stream bundle is unavailable', cause, cause instanceof VerificationError ? cause.transient : true);
    }
    const verified = await verifyC2spStreamBundleContents(bytes, {
      expectedFqdn: fqdn,
      expectedLogReference: this.lr,
      policyBytes: config.policyDocument,
      bundleKeys: config.bundleKeys,
      entityKey: trustedEntityKey,
      maxBundleBytes: maximum,
      maxEvents: config.maxEvents ?? DEFAULT_C2SP_MAX_STREAM_BUNDLE_EVENTS,
      maxBundleLifetimeMs: config.maxBundleLifetimeMs,
      checkpointFreshnessMs: config.checkpointFreshnessMs,
      maxTreeSize: this.options.maxTreeSize,
      maxClockSkewMs: this.allowedClockSkew(),
      verifyMigration: this.options.verifyMigration && (event => waitForVerification(() => this.options.verifyMigration!(event, { signal }), signal)),
      signal,
    });
    try {
      await advanceTrustedC2spCheckpoint(this.checkpointStore, verified.bundle.reference, verified.bundle.checkpoint, verified.checkpointWitnessTime, {
        signal,
        consistencyProofSource: this.options.consistencyProofSource,
      });
    } catch (cause) {
      if (config.required || !(cause instanceof MissingC2spConsistencyEvidenceError)) throw cause;
      const evidence = await this.loadEvidence(this.parsed.logPrefix, signal);
      if (!evidence.complete) throw new C2spTlogVerificationError('C2SP consistency fallback requires a complete raw scan', 'INCOMPLETE_STREAM');
      const policyResult = enforceCheckpointPolicy(evidence.checkpoint, this.parsed.origin, this.options.policy, this.parsed.scope, Date.now(), this.allowedClockSkew());
      if (!policyResult.checkpointWitnessTime) throw new C2spTlogVerificationError('C2SP consistency fallback requires an accepted timestamped witness quorum');
      assertCompleteScan(evidence);
      await advanceTrustedC2spCheckpoint(this.checkpointStore, verified.bundle.reference, verified.bundle.checkpoint, verified.checkpointWitnessTime, {
        signal,
        completeEntries: evidence.entries,
      });
    }
    return {
      events: verified.lifecycle,
      indexedEvents: verified.events,
      checkpointWitnessTime: verified.checkpointWitnessTime,
      checkpoint: verified.bundle.checkpointBytes.slice(),
      completeThrough: String(verified.bundle.completeThroughSize),
      completenessMode: verified.bundle.completenessMode,
      historyReferences: verified.historyReferences,
      validUntilMs: Math.min(
        verified.bundle.expires * 1000,
        verified.checkpointWitnessTime.getTime() + config.checkpointFreshnessMs,
      ),
    };
  }

  private async loadEvidence(logPrefix: string, signal: AbortSignal): Promise<StreamEvidence> {
    try {
      return await waitForVerification(() => this.source.load(logPrefix, { signal }), signal);
    } catch (cause) {
      throw c2spLogError('C2SP stream evidence is unavailable', cause, true);
    }
  }

  private verifierOptions(parsed: ParsedC2spTlogLr, signerKey: DnsIdJWK, checkpointWitnessTime: Date): StreamVerifierOptions {
    return {
      ...this.context(parsed),
      signerKey,
      checkpointIntegrationTimeMs: checkpointWitnessTime.getTime() + this.allowedClockSkew(),
      verifyMigration: this.options.verifyMigration,
    };
  }

  private validateTimeOptions(): void {
    const skew = this.options.allowedClockSkew ?? 0;
    if (!Number.isSafeInteger(skew) || skew < 0) {
      throw new VerificationError('allowedClockSkew must be a non-negative safe integer', { code: VerificationCode.LogError });
    }
    const maximumAge = this.options.checkpointMaxAge;
    if (maximumAge !== undefined && (!Number.isSafeInteger(maximumAge) || maximumAge < 1)) {
      throw new VerificationError('checkpointMaxAge must be a positive safe integer', { code: VerificationCode.LogError });
    }
    const bundle = this.options.streamBundle;
    if (bundle && (!(bundle.policyDocument instanceof Uint8Array) || !Array.isArray(bundle.bundleKeys) || bundle.bundleKeys.length === 0
      || !Number.isSafeInteger(bundle.maxBundleLifetimeMs) || bundle.maxBundleLifetimeMs < 1
      || !Number.isSafeInteger(bundle.checkpointFreshnessMs) || bundle.checkpointFreshnessMs < 1
      || (bundle.maxBundleBytes !== undefined && (!Number.isSafeInteger(bundle.maxBundleBytes) || bundle.maxBundleBytes < 1))
      || (bundle.maxEvents !== undefined && (!Number.isSafeInteger(bundle.maxEvents) || bundle.maxEvents < 1)))) {
      throw new VerificationError('invalid C2SP stream bundle reader options', { code: VerificationCode.LogError });
    }
  }

  private allowedClockSkew(): number {
    return this.options.allowedClockSkew ?? 0;
  }

  private assertFresh(checkpointWitnessTime: Date): void {
    const maximumAge = this.options.checkpointMaxAge;
    if (maximumAge === undefined) throw new VerificationError('non-revocation verification requires checkpointMaxAge', { code: VerificationCode.LogError });
    if (Date.now() - checkpointWitnessTime.getTime() > maximumAge) throw new VerificationError('C2SP checkpoint is too stale for non-revocation verification', { code: VerificationCode.LogError });
  }

  private context(parsed = this.parsed): C2spEventContext {
    return { scope: parsed.scope, logOrigin: parsed.origin, streamId: parsed.streamId, lr: this.lr };
  }
}

function checkpointEvidenceBytes(checkpoint: Checkpoint): Uint8Array {
  const signatures = checkpoint.signatures.map(signature => signature.raw
    || `— ${signature.name} ${Buffer.concat([signature.keyHash ?? new Uint8Array(), signature.signature]).toString('base64')}`);
  return new TextEncoder().encode(`${checkpoint.signedText}\n${signatures.join('\n')}\n`);
}

function assertC2spIssuanceEvent(event: Extract<LogEvent, { type: 'ISSUANCE' }>): asserts event is C2spIssuanceEvent {
  if (!event.initialOperationalKid
    || !event.initialOperationalAlg
    || !event.initialOperationalPublicKey
    || !event.initialOperationalThumbprint
    || !event.initialEntityKid
    || !event.initialEntityAlg
    || !event.initialEntityPublicKey
    || !event.initialEntityThumbprint) {
    throw new VerificationError('ISSUANCE is missing c2sp-tlog key metadata', { code: VerificationCode.LogError });
  }
}

function latestSnapshot(domain: string, history: LogEvent[]) {
  const latestTimestamp = history.reduce((latest, event) => Math.max(latest, event.timestamp.getTime()), 0);
  return new DomainLog(domain, history).snapshotAt(new Date(latestTimestamp));
}

function bundleFallbackAllowed(cause: unknown): boolean {
  if (!(cause instanceof VerificationError)) return false;
  if (cause instanceof C2spTlogError && cause.status !== undefined) {
    return cause.status === 404 || cause.status === 408 || cause.status === 429 || (cause.status >= 500 && cause.status <= 599);
  }
  return cause.transient;
}

function assertCompleteScan(evidence: StreamEvidence): void {
  const entries = evidence.entries.slice().sort((a, b) => a.index - b.index);
  if (entries.length !== evidence.checkpoint.treeSize) throw new C2spTlogVerificationError('complete C2SP scan length does not match checkpoint tree size', 'INVALID_EVIDENCE');
  for (let index = 0; index < entries.length; index++) {
    if (entries[index]!.index !== index) throw new C2spTlogVerificationError('complete C2SP scan must contain every index exactly once', 'INVALID_EVIDENCE');
  }
  const root = merkleRootFromEntries(entries.map(entry => entry.bytes));
  if (!Buffer.from(root).equals(Buffer.from(evidence.checkpoint.rootHash))) throw new C2spTlogVerificationError('scanned C2SP entries do not match checkpoint root', 'INVALID_EVIDENCE');
}

/**
 * Read/write binding for a c2sp-tlog stream: extends {@link C2spTlogReader}
 * with the prepared-event workflow (prepare, sign per role, finalize, append).
 * The generic `writeEvent` is intentionally unimplemented; appends go through
 * {@link C2spTlogBinding.writePreparedEvent} with a deployment-specific submitter.
 */
export class C2spTlogBinding extends C2spTlogReader implements Log {
  prepareEvent(event: LogEvent, chain?: C2spChain): PreparedC2spTlogEvent {
    return prepareC2spTlogEventForSigning(event, this.parsed.lr, chain);
  }

  parsePreparedEvent(bytes: Uint8Array, context?: PreparedC2spVerificationContext): Promise<PreparedC2spTlogEvent> {
    return parsePreparedC2spTlogEvent(bytes, this.parsed.lr, context);
  }

  signPreparedEvent(prepared: PreparedC2spTlogEvent, role: C2spSignerRole, keyProvider: KeyProvider, options?: SignPreparedC2spOptions): Promise<PreparedC2spTlogEvent> {
    return signPreparedC2spTlogEvent(prepared, role, keyProvider, options);
  }

  entryBytes(prepared: PreparedC2spTlogEvent, context?: PreparedC2spVerificationContext): Promise<Uint8Array> {
    return c2spTlogEntryBytes(prepared, context);
  }

  writePreparedEvent(prepared: PreparedC2spTlogEvent, options: C2spTlogAppendOptions): Promise<LogRef> {
    return writePreparedEvent(prepared, options);
  }

  async writeEvent(_event: LogEvent): Promise<LogRef> {
    throw new VerificationError('c2sp-tlog public write API is not implemented; use prepareC2spTlogEvent/writePreparedEvent for a deployment-specific appender', { code: VerificationCode.LogError });
  }
}

/** @deprecated Use C2spTlogBinding. */
export class C2spTlogClient extends C2spTlogBinding {}
