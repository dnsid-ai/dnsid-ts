import { withVerificationBudget, waitForVerification, type VerificationOptions, DomainLog, verifyWithKey, fromBase64Url, jwkThumbprint, VerificationError, VerificationCode, type C2spIssuanceEvent, type LogEvent, type DnsIdJWK, type LogRef } from '@dnsid-ai/protocol';
import { parseC2spTlogLr } from './lr.ts';
import { assertStrictLifecycleJwk, assertSupportedLifecycleJwk, c2spEventId, parseC2spSignatures, parseC2spAuthorization, parseC2spEventEntry, signedC2spEntryBytes, type C2spEventContext } from './event-codec.ts';
import { leafHash, sha256 } from './merkle.ts';
import { canonicalBytes } from './canonical.ts';
import { b64url } from './base64.ts';
import type { IndexedEntry } from './stream-source.ts';
import { C2spTlogVerificationError } from './errors.ts';

/** A lifecycle event accepted by stream verification, with its log index, leaf hash, and raw entry bytes. */
export interface VerifiedLifecycleEvent { index: number; leafHash: Uint8Array; bytes: Uint8Array; event: LogEvent }
/** Keys and history established by verifying an inbound MIGRATION against the prior log. */
export interface MigrationVerificationResult {
  /** Accountable-entity key established by the prior log's lifecycle. */
  entityKey: DnsIdJWK;
  /** Operational key active at the prior log's final entry. */
  activeOperationalKey: DnsIdJWK;
  /** Fully verified prior-log lifecycle through the migration's finalEntryRef. */
  priorHistory: LogEvent[];
  /** Verified log reference for each priorHistory event, in the same order. Required for logged-state evidence. */
  priorHistoryReferences?: LogRef[];
}
/** Options controlling lifecycle verification of a stream's entries. */
export interface StreamVerifierOptions extends C2spEventContext, VerificationOptions {
  /** @deprecated Ignored: every scope requires the logical predecessor chain. */
  unchained?: boolean;
  /**
   * Trusted accountable-entity key (the record `ek`). The entity key current at
   * the end of the verified lifecycle (the genesis key, or the key installed by
   * the latest ENTITY_KEY_ROTATION) must match it; stream verification lets
   * the first eligible authenticated genesis decide.
   */
  signerKey?: DnsIdJWK;
  /** Latest acceptable event timestamp (checkpoint witness time plus skew), in epoch milliseconds. Required. */
  checkpointIntegrationTimeMs?: number;
  /** Verifies an inbound MIGRATION's prior-log history and returns the migrated keys. */
  verifyMigration?: (event: Extract<LogEvent, { type: 'MIGRATION' }>, options?: VerificationOptions) => Promise<MigrationVerificationResult>;
}

/**
 * Stitches a verified prior-log history onto the current log's events for an
 * inbound MIGRATION: the current events must begin with the MIGRATION, the
 * prior history must establish the imported active operational key and, as
 * its end-of-history entity key, the imported entity key (and contain the
 * ISSUANCE genesis), and the combined lifecycle must
 * snapshot cleanly.
 *
 * @returns The prior history followed by the current events, in order.
 * @throws C2spTlogVerificationError (`INVALID_MIGRATION`) when the prior
 *   history does not establish the imported keys or the MIGRATION is
 *   duplicated or missing.
 */
export async function stitchVerifiedMigrationHistory(
  domain: string,
  currentEvents: LogEvent[],
  migration: MigrationVerificationResult,
): Promise<LogEvent[]> {
  const inbound = currentEvents[0];
  if (!inbound || inbound.type !== 'MIGRATION' || migration.priorHistory.length === 0) {
    throw new C2spTlogVerificationError('MIGRATION requires stitched verified prior-log history', 'INVALID_MIGRATION');
  }
  if (migration.priorHistory.some((event) => event.type === 'MIGRATION'
    && event.previousLog === inbound.previousLog
    && event.newLog === inbound.newLog
    && event.finalEntryRef === inbound.finalEntryRef)) {
    throw new C2spTlogVerificationError('MIGRATION event must appear exactly once in stitched history', 'INVALID_MIGRATION');
  }
  if (migration.priorHistoryReferences) validatePriorHistoryReferences(inbound, migration);
  const priorLatestTimestamp = migration.priorHistory.reduce(
    (latest, event) => Math.max(latest, event.timestamp.getTime()),
    0,
  );
  const priorSnapshot = new DomainLog(domain, migration.priorHistory).snapshotAt(new Date(priorLatestTimestamp));
  if (priorSnapshot.historicalState !== 'ACTIVE'
    || priorSnapshot.activeKeyThumbprint !== await jwkThumbprint(migration.activeOperationalKey)) {
    throw new C2spTlogVerificationError('MIGRATION prior history does not establish the imported active key', 'INVALID_MIGRATION');
  }
  const priorIssuance = migration.priorHistory.find((event) => event.type === 'ISSUANCE');
  if (!priorIssuance || priorIssuance.type !== 'ISSUANCE') {
    throw new C2spTlogVerificationError('MIGRATION prior history has no ISSUANCE genesis', 'INVALID_MIGRATION');
  }
  // The MIGRATION imports the entity key current at the END of the prior history
  // (the ISSUANCE key unless an ENTITY_KEY_ROTATION moved it).
  if (!priorSnapshot.entityKeyThumbprint || priorSnapshot.entityKeyThumbprint !== await jwkThumbprint(migration.entityKey)) {
    throw new C2spTlogVerificationError('MIGRATION prior history does not establish the imported entity key', 'INVALID_MIGRATION');
  }
  const stitched = [...migration.priorHistory, ...currentEvents];
  const latestTimestamp = stitched.reduce((latest, event) => Math.max(latest, event.timestamp.getTime()), 0);
  new DomainLog(domain, stitched).snapshotAt(new Date(latestTimestamp));
  return stitched;
}

/** Stitches aligned verified references without deriving prior-log refs from destination indexes. */
export function stitchVerifiedMigrationReferences(
  currentEvents: LogEvent[],
  currentReferences: LogRef[],
  migration: MigrationVerificationResult,
): LogRef[] {
  const inbound = currentEvents[0];
  if (!inbound || inbound.type !== 'MIGRATION' || currentEvents.length !== currentReferences.length) {
    throw new C2spTlogVerificationError('MIGRATION has mismatched destination history references', 'INVALID_MIGRATION');
  }
  validatePriorHistoryReferences(inbound, migration);
  currentReferences.forEach(reference => assertReferenceBelongsToLog(reference, inbound.newLog));
  return [...migration.priorHistoryReferences!, ...currentReferences];
}

function validatePriorHistoryReferences(
  inbound: Extract<LogEvent, { type: 'MIGRATION' }>,
  migration: MigrationVerificationResult,
): void {
  const references = migration.priorHistoryReferences;
  if (!references || references.length !== migration.priorHistory.length || references.length === 0) {
    throw new C2spTlogVerificationError('MIGRATION prior history has missing or mismatched verified references', 'INVALID_MIGRATION');
  }
  references.forEach(assertLogReference);
  if (references.at(-1) !== inbound.finalEntryRef) {
    throw new C2spTlogVerificationError('MIGRATION prior history does not end at signed prev_ref', 'INVALID_MIGRATION');
  }
  let expectedLog = inbound.previousLog;
  for (let index = references.length - 1; index >= 0; index--) {
    const event = migration.priorHistory[index]!;
    assertReferenceBelongsToLog(references[index]!, expectedLog);
    if (event.type !== 'MIGRATION') continue;
    if (event.newLog !== expectedLog || index === 0 || references[index - 1] !== event.finalEntryRef) {
      throw new C2spTlogVerificationError('nested MIGRATION prior history does not end at signed prev_ref', 'INVALID_MIGRATION');
    }
    assertReferenceBelongsToLog(event.finalEntryRef, event.previousLog);
    expectedLog = event.previousLog;
  }
}

function assertLogReference(reference: LogRef): void {
  if (typeof reference !== 'string' || !/^[a-z][a-z0-9-]*:.+/.test(reference)) {
    throw new C2spTlogVerificationError('MIGRATION prior history contains a malformed log reference', 'INVALID_MIGRATION');
  }
}

function assertReferenceBelongsToLog(reference: LogRef, logReference: LogRef): void {
  assertLogReference(reference);
  assertLogReference(logReference);
  if (reference.split(':', 1)[0] !== logReference.split(':', 1)[0]) {
    throw new C2spTlogVerificationError('MIGRATION event reference does not belong to its signed log', 'INVALID_MIGRATION');
  }
  if (reference.startsWith('c2sp-tlog:') || logReference.startsWith('c2sp-tlog:')) {
    try {
      const event = parseC2spTlogLr(reference);
      const log = parseC2spTlogLr(logReference);
      if (log.entryIndex !== undefined || event.entryIndex === undefined || event.lr !== log.lr) throw new Error();
    } catch {
      throw new C2spTlogVerificationError('MIGRATION C2SP event reference does not belong to its signed log', 'INVALID_MIGRATION');
    }
  }
}

/**
 * Extracts and verifies the lifecycle history for one agent domain from
 * entries already authenticated by the accepted completeness mechanism:
 * entries are processed in index order, other domains are skipped, identical
 * signed payloads are deduplicated, and each candidate must keep the accumulated lifecycle valid
 * under {@link verifyLifecycle}. A malformed entry that nevertheless carries a
 * valid signatures for every role under verified predecessor authority is
 * treated as a lifecycle violation, not skipped.
 *
 * With `signerKey` (the record `ek`), genesis selection is anchored on it. A
 * genesis candidate is eligible when it self-authenticates and its entity key
 * is `signerKey` or the root of an authenticated ENTITY_KEY_ROTATION chain
 * that reaches it; other candidates are skipped as noise. The first eligible
 * candidate in log order decides: an authenticated but malformed eligible
 * ISSUANCE is fatal, and if its history ends at another entity key
 * verification fails; later candidates are never tried. Without
 * ENTITY_KEY_ROTATION this selects the genesis whose own entity key is
 * `signerKey`, as before.
 *
 * @returns The accepted events in log order.
 * @throws C2spTlogVerificationError when the resulting lifecycle is invalid
 *   (for example no ISSUANCE event survives).
 */
export async function verifyStreamLifecycle(entries: IndexedEntry[], domain: string, options: StreamVerifierOptions = {}): Promise<VerifiedLifecycleEvent[]> {
  return withVerificationBudget(signal => verifyStreamWithinBudget(entries, domain, { ...options, signal }), options);
}

async function verifyStreamWithinBudget(entries: IndexedEntry[], domain: string, options: StreamVerifierOptions): Promise<VerifiedLifecycleEvent[]> {
  if (entries.length > 1_000_000 || entries.reduce((total, entry) => total + entry.bytes.length, 0) > 256 * 1024 * 1024) throw new C2spTlogVerificationError('lifecycle input exceeds resource limits');
  const sorted = entries.slice().sort((a, b) => a.index - b.index);
  const trustedThumbprint = options.signerKey ? await jwkThumbprint(options.signerKey) : undefined;
  const migrationState: MigrationSelectionState = { failed: false, verified: new Map() };
  const lifecycleOptions: StreamVerifierOptions = options.verifyMigration ? {
    ...options,
    verifyMigration: async (event) => {
      // Re-parsed copies of one MIGRATION reuse a single prior-log verification.
      const cacheKey = JSON.stringify([event.domain, event.previousLog, event.newLog, event.finalEntryRef, event.signingKid, event.sig]);
      const cached = migrationState.verified.get(cacheKey);
      if (cached) {
        migrationState.event = event;
        migrationState.result = cached;
        return cached;
      }
      migrationState.event = event;
      migrationState.result = undefined;
      try {
        migrationState.result = await waitForVerification(() => options.verifyMigration!(event, { signal: options.signal }), options.signal!);
        migrationState.verified.set(cacheKey, migrationState.result);
        return migrationState.result;
      } catch (error) {
        migrationState.failed = true;
        throw error;
      }
    },
  } : options;
  const reachable = trustedThumbprint === undefined ? undefined : await entityKeysReaching(sorted, domain, options, trustedThumbprint);
  const selected = await selectStreamLifecycle(sorted, domain, options, lifecycleOptions, migrationState, trustedThumbprint, reachable);
  // An empty selection reports the pre-existing "no ISSUANCE" failure.
  await verifyLifecycle(selected, lifecycleOptions);
  return selected;
}

/**
 * Thumbprints of every entity key from which a chain of ENTITY_KEY_ROTATION
 * entries (each carrying a valid `new_ae` by its new key) can lead to the
 * trusted key, including the trusted key itself. A replay can only end at the
 * trusted key from a genesis whose entity key is in this set, so any other
 * genesis is skipped without replay, exactly as the pinned filter skipped it.
 */
async function entityKeysReaching(entries: IndexedEntry[], domain: string, options: StreamVerifierOptions, trustedThumbprint: string): Promise<Set<string>> {
  const rotations: Array<{ previous: string; next: string }> = [];
  for (const entry of entries) {
    if (options.signal!.aborted) throw new C2spTlogVerificationError('lifecycle verification canceled');
    try {
      const authorization = parseC2spAuthorization(entry.bytes, options);
      if (authorization.domain !== domain || authorization.type !== 'ENTITY_KEY_ROTATION') continue;
      const envelope = JSON.parse(new TextDecoder().decode(entry.bytes)) as Record<string, unknown>;
      const signatures = parseC2spSignatures(envelope.sigs, 'ENTITY_KEY_ROTATION');
      const newKey = newEntityVerificationKey(envelope.new_ek);
      if (!newKey) continue;
      const next = await jwkThumbprint(newKey);
      if (typeof envelope.prev_ek_thumb !== 'string' || envelope.new_ek_thumb !== next || signatures.new_ae!.kid !== newKey.kid) continue;
      if (!await verifyWithKey(signedC2spEntryBytes(entry.bytes), fromBase64Url(signatures.new_ae!.sig), newKey)) continue;
      rotations.push({ previous: envelope.prev_ek_thumb, next });
    } catch { continue; }
  }
  const reachable = new Set([trustedThumbprint]);
  for (let changed = true; changed;) {
    changed = false;
    for (const rotation of rotations) {
      if (reachable.has(rotation.next) && !reachable.has(rotation.previous)) {
        reachable.add(rotation.previous);
        changed = true;
      }
    }
  }
  return reachable;
}

interface MigrationSelectionState {
  event?: Extract<LogEvent, { type: 'MIGRATION' }>;
  result?: MigrationVerificationResult;
  failed: boolean;
  verified: Map<string, MigrationVerificationResult>;
}

async function selectStreamLifecycle(
  sorted: IndexedEntry[],
  domain: string,
  options: StreamVerifierOptions,
  anchoredOptions: StreamVerifierOptions,
  migrationState: MigrationSelectionState,
  trustedThumbprint: string | undefined,
  reachable: Set<string> | undefined,
): Promise<VerifiedLifecycleEvent[]> {
  // Prefix replays never anchor on the trusted key; only the complete history does.
  const lifecycleOptions: StreamVerifierOptions = { ...anchoredOptions, signerKey: undefined };
  const selected: VerifiedLifecycleEvent[] = [];
  const appliedEntries = new Map<string, { signed: string; entityKey: DnsIdJWK; operationalKey: DnsIdJWK }>();
  let entityKey: DnsIdJWK | undefined;
  let activeOperationalKey: DnsIdJWK | undefined;
  // Entity keys the identity holds or has held: those that reach the trusted
  // key, plus the selected genesis key and every key rotated in after it.
  const chainKeys = new Set(reachable ?? []);
  for (const entry of sorted) {
    if (options.signal!.aborted) throw new C2spTlogVerificationError('lifecycle verification canceled');
    let signedBytes: Uint8Array;
    let envelope: Record<string, unknown>;
    try {
      if (parseC2spAuthorization(entry.bytes, options).domain !== domain) continue;
      signedBytes = signedC2spEntryBytes(entry.bytes);
      envelope = JSON.parse(new TextDecoder().decode(signedBytes));
    } catch { continue; }
    const entryId = c2spEventId(signedBytes);
    const signed = b64url(signedBytes);
    const applied = appliedEntries.get(entryId);
    if (applied) {
      if (applied.signed !== signed) throw new C2spTlogVerificationError('logical event ID collision');
      continue;
    }
    // An ISSUANCE that self-authenticates and can reach the trusted key is the
    // eligible root: from here on its failures are fatal, not noise.
    let eligibleIssuance = false;
    if (selected.length === 0 && envelope.type === 'ISSUANCE') {
      if (!await hasAllRoleSignatures(entry.bytes, envelope.ek as DnsIdJWK, envelope.ku as DnsIdJWK)) continue;
      const thumbprint = await envelopeKeyThumbprint(envelope.ek);
      if (reachable && (thumbprint === undefined || !reachable.has(thumbprint))) continue;
      eligibleIssuance = true;
    }
    if (selected.length > 0 && envelope.type === 'ISSUANCE') {
      // A malformed ISSUANCE authenticated by any entity key of the chain is
      // invalid evidence from the identity itself; an unrelated key's is noise.
      const thumbprint = await envelopeKeyThumbprint(envelope.ek);
      if (thumbprint !== undefined && chainKeys.has(thumbprint)
        && await hasAllRoleSignatures(entry.bytes, envelope.ek as DnsIdJWK, envelope.ku as DnsIdJWK)) {
        try { await parseC2spEventEntry(entry.bytes, options); }
        catch (cause) { throw new C2spTlogVerificationError('authenticated lifecycle genesis is malformed', 'INVALID_EVIDENCE', cause); }
      }
    }
    if (selected.length > 0) {
      const prior = appliedEntries.get(envelope.prev_event_id as string);
      if (!await hasAllRoleSignatures(entry.bytes, prior?.entityKey ?? entityKey!, prior?.operationalKey ?? activeOperationalKey!)) continue;
    }
    let event: LogEvent;
    try { event = await parseC2spEventEntry(entry.bytes, options); }
    catch (cause) {
      if (eligibleIssuance) throw new C2spTlogVerificationError('authenticated lifecycle genesis is malformed', 'INVALID_EVIDENCE', cause);
      if (selected.length > 0) throw new C2spTlogVerificationError('authenticated lifecycle candidate is malformed');
      continue;
    }
    if (event.domain !== domain) continue;
    const candidate = { index: entry.index, leafHash: leafHash(entry.bytes), bytes: entry.bytes, event };
    if (selected.length === 0) {
      try {
        await verifyLifecycle([candidate], lifecycleOptions);
      } catch (error) {
        if (eligibleIssuance) throw error;
        if (event.type === 'MIGRATION' && (!options.verifyMigration || migrationState.failed)) {
          if (error instanceof C2spTlogVerificationError && error.errorCategory === 'INVALID_MIGRATION') throw error;
          throw new C2spTlogVerificationError('MIGRATION requires verifiable prior-log history', 'INVALID_MIGRATION');
        }
        continue;
      }
      let genesisEntityKey: DnsIdJWK | undefined;
      let genesisOperationalKey: DnsIdJWK | undefined;
      if (event.type === 'ISSUANCE') {
        assertC2spIssuanceEvent(event);
        genesisEntityKey = event.initialEntityPublicKey;
        genesisOperationalKey = event.initialOperationalPublicKey;
      } else if (event.type === 'MIGRATION' && migrationState.result) {
        genesisEntityKey = migrationState.result.entityKey;
        genesisOperationalKey = migrationState.result.activeOperationalKey;
      }
      const thumbprint = genesisEntityKey ? await jwkThumbprint(genesisEntityKey) : undefined;
      // A genesis that cannot reach the trusted key is noise, skipped as the pinned filter skipped it.
      if (reachable && (thumbprint === undefined || !reachable.has(thumbprint))) continue;
      selected.push(candidate);
      entityKey = genesisEntityKey;
      activeOperationalKey = genesisOperationalKey;
      if (thumbprint !== undefined) chainKeys.add(thumbprint);
      appliedEntries.set(entryId, { signed, entityKey: entityKey!, operationalKey: activeOperationalKey! });
      continue;
    }
    if (!entityKey || !activeOperationalKey) {
      throw new C2spTlogVerificationError('lifecycle keys were not established by genesis', 'INVALID_EVIDENCE');
    }
    // ponytail: replay validation is O(n²), bounded by history/input limits and the shared deadline.
    await verifyLifecycle([...selected, candidate], lifecycleOptions);
    selected.push(candidate);
    if (event.type === 'KEY_ROTATION') activeOperationalKey = event.newOperationalPublicKey;
    if (event.type === 'ENTITY_KEY_ROTATION') {
      entityKey = event.newEntityPublicKey;
      chainKeys.add(event.newEntityThumbprint);
    }
    appliedEntries.set(entryId, { signed, entityKey, operationalKey: activeOperationalKey });
  }
  // The first eligible genesis decides: no later candidate is tried.
  if (selected.length > 0 && trustedThumbprint !== undefined && (!entityKey || await jwkThumbprint(entityKey) !== trustedThumbprint)) {
    throw new C2spTlogVerificationError(`c2sp-tlog current entity key does not match record ek for ${domain}`);
  }
  return selected;
}

const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

/** Public Ed25519 or P-256 key material of `new_ek` for authenticating `new_ae`, or undefined when it cannot authenticate. */
function newEntityVerificationKey(value: unknown): DnsIdJWK | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const key = value as Record<string, unknown>;
  if (typeof key.kid !== 'string' || !key.kid || PRIVATE_JWK_MEMBERS.some(member => key[member] !== undefined)) return undefined;
  if (key.kty === 'OKP' && key.crv === 'Ed25519' && typeof key.x === 'string') return { kty: 'OKP', crv: 'Ed25519', x: key.x, kid: key.kid } as DnsIdJWK;
  if (key.kty === 'EC' && key.crv === 'P-256' && typeof key.x === 'string' && typeof key.y === 'string') return { kty: 'EC', crv: 'P-256', x: key.x, y: key.y, kid: key.kid } as DnsIdJWK;
  return undefined;
}

async function envelopeKeyThumbprint(value: unknown): Promise<string | undefined> {
  try { return await jwkThumbprint(value as DnsIdJWK); } catch { return undefined; }
}

/** All roles authenticate a new payload before signed chain/transition errors become fatal. */
async function hasAllRoleSignatures(bytes: Uint8Array, entityKey: DnsIdJWK, operationalKey: DnsIdJWK): Promise<boolean> {
  try {
    const envelope = JSON.parse(new TextDecoder().decode(bytes));
    const signatures = parseC2spSignatures(envelope.sigs, envelope.type);
    for (const [role, signature] of Object.entries(signatures)) {
      const key = role === 'ae' || role === 'prev_ae' ? entityKey
        : role === 'prev_op' ? operationalKey
          : role === 'op' ? envelope.ku
            : role === 'new_ae' ? envelope.new_ek
              : envelope.new_ku;
      if (role === 'new_ae') {
        // new_ae authenticates with new_ek's key material alone: a new_ek without a kid, with a kid new_ae does not name, or
        // with private members cannot authenticate and is skipped as noise.
        // Its alg/use/coordinate checks are structural, so an authenticated
        // rotation that fails them is fatal invalid evidence, not noise.
        const verificationKey = newEntityVerificationKey(key);
        if (!verificationKey || signature.kid !== key.kid
          || !await verifyWithKey(signedC2spEntryBytes(bytes), fromBase64Url(signature.sig), verificationKey)) return false;
        continue;
      }
      assertSupportedLifecycleJwk(key);
      if (signature.kid !== key.kid || !await verifyWithKey(signedC2spEntryBytes(bytes), fromBase64Url(signature.sig), key)) return false;
    }
    return true;
  } catch { return false; }
}

/**
 * Verifies an ordered lifecycle: it must begin with ISSUANCE (or a verified
 * inbound MIGRATION), every event signature must verify against the entity or
 * operational key active at that point, KEY_ROTATION and ENTITY_KEY_ROTATION
 * must prove possession of the new key, every scope must carry consistent
 * seq/prev_* fields, `signerKey` (when given) must be the entity key current
 * at the end of `events`,
 * and nothing may follow a terminal REVOCATION/RETIREMENT. MIGRATION is valid
 * only as verified inbound genesis in the destination stream.
 *
 * @throws C2spTlogVerificationError on any structural or key-continuity violation.
 * @throws VerificationError (SignatureInvalid) when a signature fails to verify.
 */
export async function verifyLifecycle(events: VerifiedLifecycleEvent[], options: StreamVerifierOptions = {}): Promise<void> {
  return withVerificationBudget(signal => verifyLifecycleWithinBudget(events, { ...options, signal }), options);
}

async function verifyLifecycleWithinBudget(events: VerifiedLifecycleEvent[], options: StreamVerifierOptions): Promise<void> {
  if (events.length > 10_000) throw new C2spTlogVerificationError('lifecycle history exceeds 10000 events');
  if (events.length === 0) throw new C2spTlogVerificationError('lifecycle contains no ISSUANCE event', 'GENESIS_REQUIRED');
  let terminal = false;
  let prevState: unknown = null;
  let entityKey: DnsIdJWK | undefined;
  let activeOperationalKey: DnsIdJWK | undefined;
  // signerKey anchors the entity key current at the END of `events`. Without an
  // ENTITY_KEY_ROTATION that is the genesis key, checked at genesis as before.
  const anchorAtGenesis = !events.some(item => item.event.type === 'ENTITY_KEY_ROTATION');
  for (let pos = 0; pos < events.length; pos++) {
    if (options.signal!.aborted) throw new C2spTlogVerificationError('lifecycle verification canceled');
    const item = events[pos]!;
    const event = item.event;
    if (terminal) throw new C2spTlogVerificationError('event appears after terminal lifecycle event', 'TERMINAL_STATE');
    if (pos === 0 && event.type !== 'ISSUANCE' && event.type !== 'MIGRATION') throw new C2spTlogVerificationError('first lifecycle event must be ISSUANCE or verified MIGRATION', 'GENESIS_REQUIRED');
    if (pos > 0 && event.type === 'ISSUANCE') throw new C2spTlogVerificationError('duplicate ISSUANCE event', 'DUPLICATE_ISSUANCE');
    if (pos > 0 && event.type === 'MIGRATION') throw new C2spTlogVerificationError('MIGRATION must be destination-stream genesis', 'INVALID_MIGRATION');
    const timestamp = event.timestamp.getTime();
    if (!Number.isFinite(timestamp)) throw new C2spTlogVerificationError('invalid lifecycle timestamp');
    if (event.type === 'MIGRATION'
      && (!event.previousLog || !event.newLog || event.previousLog === event.newLog || !event.finalEntryRef)) {
      throw new C2spTlogVerificationError('invalid MIGRATION', 'INVALID_MIGRATION');
    }
    if (options.checkpointIntegrationTimeMs === undefined) throw new C2spTlogVerificationError('accepted checkpoint integration time is required');
    if (timestamp > options.checkpointIntegrationTimeMs) throw new C2spTlogVerificationError('event timestamp is later than checkpoint integration time');
    if (['event_id', 'prev_index', 'prev_leaf_hash'].some(name => name in event)) throw new C2spTlogVerificationError('prohibited chain field', 'CHAIN_CONTINUITY');
    {
      if (pos === 0) assertFirstChainFields(event as unknown as Record<string, unknown>);
      else assertChainFields(event as unknown as Record<string, unknown>, events[pos - 1]!, prevState);
    }
    if (!event.sig) throw new C2spTlogVerificationError(`missing signature for ${event.type}`);
    if (event.type === 'ISSUANCE') {
      assertC2spIssuanceEvent(event);
      await assertIssuanceKeyMetadata(event);
      entityKey = event.initialEntityPublicKey;
      activeOperationalKey = event.initialOperationalPublicKey;
      await assertDistinctLifecycleKeys(entityKey, activeOperationalKey, 'ISSUANCE');
      if (anchorAtGenesis && options.signerKey && await jwkThumbprint(options.signerKey) !== event.initialEntityThumbprint) {
        throw new C2spTlogVerificationError('ISSUANCE entity key does not match trusted entity key');
      }
      await verifyEventSignature(item, event.sig, entityKey, 'invalid ISSUANCE entity signature');
      if (!event.operationalCountersig) throw new C2spTlogVerificationError('ISSUANCE missing operational countersignature');
      await verifyEventSignature(item, event.operationalCountersig, activeOperationalKey, 'invalid ISSUANCE operational countersignature');
      prevState = await issuanceState(event);
    } else if (event.type === 'MIGRATION' && pos === 0) {
      if (!options.verifyMigration) throw new C2spTlogVerificationError('MIGRATION requires verified prior-log history', 'INVALID_MIGRATION');
      if (options.lr && event.newLog !== options.lr) throw new C2spTlogVerificationError('MIGRATION new_lr does not match the current C2SP stream', 'INVALID_MIGRATION');
      const migrated = await waitForVerification(() => options.verifyMigration!(event, { signal: options.signal }), options.signal!);
      entityKey = migrated.entityKey;
      activeOperationalKey = migrated.activeOperationalKey;
      assertSupportedLifecycleJwk(entityKey, 'MIGRATION entity key');
      assertSupportedLifecycleJwk(activeOperationalKey, 'MIGRATION operational key');
      await assertDistinctLifecycleKeys(entityKey, activeOperationalKey, 'MIGRATION');
      if (anchorAtGenesis && options.signerKey && await jwkThumbprint(options.signerKey) !== await jwkThumbprint(entityKey)) throw new C2spTlogVerificationError('MIGRATION entity key does not match trusted entity key');
      if (event.signingKid !== entityKey.kid) throw new C2spTlogVerificationError('MIGRATION signature kid does not match entity key');
      await verifyEventSignature(item, event.sig, entityKey, 'invalid MIGRATION entity signature');
      prevState = await activeState(event.domain, entityKey, activeOperationalKey);
    } else {
      if (!entityKey || !activeOperationalKey) throw new C2spTlogVerificationError('lifecycle keys were not established by ISSUANCE');
      if (event.type === 'KEY_ROTATION') {
        const activeThumbprint = await jwkThumbprint(activeOperationalKey);
        if (event.previousOperationalThumbprint !== activeThumbprint || event.previousOperationalKid !== activeOperationalKey.kid) {
          throw new C2spTlogVerificationError('KEY_ROTATION previous operational key does not match active key', 'KEY_CONTINUITY');
        }
        await assertRotationKeyMetadata(event);
        if (event.newOperationalThumbprint === activeThumbprint) {
          throw new C2spTlogVerificationError('KEY_ROTATION new operational key must differ from active key', 'KEY_CONTINUITY');
        }
        await assertDistinctLifecycleKeys(entityKey, event.newOperationalPublicKey, 'KEY_ROTATION');
        await verifyEventSignature(item, event.sig, activeOperationalKey, 'invalid KEY_ROTATION signature');
        if (!event.newOperationalProof) throw new C2spTlogVerificationError('KEY_ROTATION missing new operational proof of possession');
        await verifyEventSignature(item, event.newOperationalProof, event.newOperationalPublicKey, 'invalid KEY_ROTATION new-key proof of possession');
        activeOperationalKey = event.newOperationalPublicKey;
      } else if (event.type === 'ENTITY_KEY_ROTATION') {
        const entityThumbprint = await jwkThumbprint(entityKey);
        if (event.signingKid !== entityKey.kid) throw new C2spTlogVerificationError('ENTITY_KEY_ROTATION signature kid does not match entity key');
        if (event.previousEntityThumbprint !== entityThumbprint) {
          throw new C2spTlogVerificationError('authenticated ENTITY_KEY_ROTATION does not continue from the active entity key', 'KEY_CONTINUITY');
        }
        await assertEntityRotationKeyMetadata(event);
        if (event.newEntityThumbprint === entityThumbprint || event.newEntityThumbprint === await jwkThumbprint(activeOperationalKey)) {
          throw new C2spTlogVerificationError('authenticated ENTITY_KEY_ROTATION new key binding is invalid', 'KEY_CONTINUITY');
        }
        await verifyEventSignature(item, event.sig, entityKey, 'invalid ENTITY_KEY_ROTATION previous entity signature');
        if (!event.newEntityProof) throw new C2spTlogVerificationError('ENTITY_KEY_ROTATION missing new entity proof of possession');
        await verifyEventSignature(item, event.newEntityProof, event.newEntityPublicKey, 'invalid ENTITY_KEY_ROTATION new entity proof of possession');
        entityKey = event.newEntityPublicKey;
      } else {
        if (event.signingKid !== entityKey.kid) throw new C2spTlogVerificationError(`${event.type} signature kid does not match entity key`);
        await verifyEventSignature(item, event.sig, entityKey, `invalid ${event.type} entity signature`);
        if (event.type === 'REVOCATION' && !['keyCompromise', 'policyViolation', 'superseded', 'cessationOfOperation'].includes(event.reason)) {
          throw new C2spTlogVerificationError('invalid REVOCATION reason', 'INVALID_EVIDENCE');
        }
      }
      prevState = await nextState(prevState, event, entityKey, activeOperationalKey);
    }
    if (event.type === 'REVOCATION' || event.type === 'RETIREMENT') terminal = true;
  }
  if (!anchorAtGenesis && options.signerKey && (!entityKey || await jwkThumbprint(options.signerKey) !== await jwkThumbprint(entityKey))) {
    throw new C2spTlogVerificationError(`c2sp-tlog current entity key does not match record ek for ${events[0]!.event.domain}`);
  }
}

/**
 * Verifies a single logged event's primary signature against `signerKey` over
 * the entry's signed bytes.
 *
 * @throws C2spTlogVerificationError when the event has no signature.
 * @throws VerificationError (SignatureInvalid) when verification fails.
 */
export async function verifyLoggedEventSignature(item: VerifiedLifecycleEvent, signerKey: DnsIdJWK): Promise<void> {
  const sig = item.event.sig;
  if (!sig) throw new C2spTlogVerificationError(`missing signature for ${item.event.type}`);
  await verifyEventSignature(item, sig, signerKey, 'invalid lifecycle event signature');
}

/** Base64url hash of a lifecycle state object (domain-separated SHA-256 over canonical JSON), as used in `prev_state_hash`. */
export function stateHash(state: unknown): string {
  return b64url(sha256(new TextEncoder().encode('dnsid-c2sp-state-v1'), canonicalBytes(state)));
}

async function verifyEventSignature(item: VerifiedLifecycleEvent, signature: string, key: DnsIdJWK, message: string): Promise<void> {
  const ok = await verifyWithKey(signedC2spEntryBytes(item.bytes), fromBase64Url(signature), key);
  if (!ok) throw new VerificationError(message, { code: VerificationCode.SignatureInvalid });
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
    throw new C2spTlogVerificationError('ISSUANCE is missing c2sp-tlog key metadata', 'INVALID_ISSUANCE');
  }
}

async function assertIssuanceKeyMetadata(event: C2spIssuanceEvent): Promise<void> {
  assertSupportedLifecycleJwk(event.initialOperationalPublicKey, 'ISSUANCE operational key');
  assertSupportedLifecycleJwk(event.initialEntityPublicKey, 'ISSUANCE entity key');
  if (event.initialOperationalThumbprint !== await jwkThumbprint(event.initialOperationalPublicKey)) throw new C2spTlogVerificationError('ISSUANCE operational thumbprint does not match public key', 'INVALID_ISSUANCE');
  if (event.initialEntityThumbprint !== await jwkThumbprint(event.initialEntityPublicKey)) throw new C2spTlogVerificationError('ISSUANCE entity thumbprint does not match public key', 'INVALID_ISSUANCE');
  if (event.initialOperationalKid !== event.initialOperationalPublicKey.kid || event.initialOperationalAlg !== event.initialOperationalPublicKey.alg) throw new C2spTlogVerificationError('ISSUANCE operational key metadata mismatch', 'INVALID_ISSUANCE');
  if (event.initialEntityKid !== event.initialEntityPublicKey.kid || event.initialEntityAlg !== event.initialEntityPublicKey.alg) throw new C2spTlogVerificationError('ISSUANCE entity key metadata mismatch', 'INVALID_ISSUANCE');
}

async function assertRotationKeyMetadata(event: Extract<LogEvent, { type: 'KEY_ROTATION' }>): Promise<void> {
  assertSupportedLifecycleJwk(event.newOperationalPublicKey, 'KEY_ROTATION new operational key');
  if (event.newOperationalThumbprint !== await jwkThumbprint(event.newOperationalPublicKey)) throw new C2spTlogVerificationError('KEY_ROTATION new thumbprint does not match public key', 'KEY_CONTINUITY');
  if (event.newOperationalKid !== event.newOperationalPublicKey.kid || event.newOperationalAlg !== event.newOperationalPublicKey.alg) throw new C2spTlogVerificationError('KEY_ROTATION new key metadata mismatch', 'KEY_CONTINUITY');
}

async function assertEntityRotationKeyMetadata(event: Extract<LogEvent, { type: 'ENTITY_KEY_ROTATION' }>): Promise<void> {
  try {
    assertStrictLifecycleJwk(event.newEntityPublicKey, 'ENTITY_KEY_ROTATION new entity key');
  } catch (cause) {
    throw new C2spTlogVerificationError('authenticated ENTITY_KEY_ROTATION new key binding is invalid', 'KEY_CONTINUITY', cause);
  }
  if (event.newEntityThumbprint !== await jwkThumbprint(event.newEntityPublicKey)
    || event.newEntityKid !== event.newEntityPublicKey.kid
    || event.newEntityAlg !== event.newEntityPublicKey.alg) {
    throw new C2spTlogVerificationError('authenticated ENTITY_KEY_ROTATION new key binding is invalid', 'KEY_CONTINUITY');
  }
}

async function assertDistinctLifecycleKeys(entityKey: DnsIdJWK, operationalKey: DnsIdJWK, eventType: string): Promise<void> {
  if (await jwkThumbprint(entityKey) === await jwkThumbprint(operationalKey)) {
    throw new C2spTlogVerificationError(`${eventType} entity and operational keys must be distinct`, eventType === 'ISSUANCE' ? 'INVALID_ISSUANCE' : 'KEY_CONTINUITY');
  }
}

function assertChainFields(event: Record<string, unknown>, prev: VerifiedLifecycleEvent, prevState: unknown): void {
  const prevSeq = (prev.event as unknown as Record<string, unknown>).seq;
  if (!Number.isSafeInteger(prevSeq) || event.seq !== (prevSeq as number) + 1) throw new C2spTlogVerificationError('invalid seq', 'CHAIN_CONTINUITY');
  if (event.prev_event_id !== c2spEventId(signedC2spEntryBytes(prev.bytes))) throw new C2spTlogVerificationError('invalid prev_event_id', 'CHAIN_CONTINUITY');
  if (event.prev_state_hash !== stateHash(prevState)) throw new C2spTlogVerificationError('invalid prev_state_hash', 'CHAIN_CONTINUITY');
}

function assertFirstChainFields(event: Record<string, unknown>): void {
  if (event.seq !== 0) throw new C2spTlogVerificationError('first public lifecycle event must have seq 0', 'CHAIN_CONTINUITY');
  if (event.prev_event_id !== undefined || event.prev_state_hash !== undefined) {
    throw new C2spTlogVerificationError('first public lifecycle event must not contain previous-chain fields', 'CHAIN_CONTINUITY');
  }
}

async function issuanceState(event: Extract<LogEvent, { type: 'ISSUANCE' }>): Promise<unknown> {
  return { fqdn: event.domain, status: 'ACTIVE', entity_thumb: event.initialEntityThumbprint, operational_thumb: event.initialOperationalThumbprint };
}

async function activeState(domain: string, entityKey: DnsIdJWK, operationalKey: DnsIdJWK): Promise<unknown> {
  return { fqdn: domain, status: 'ACTIVE', entity_thumb: await jwkThumbprint(entityKey), operational_thumb: await jwkThumbprint(operationalKey) };
}

async function nextState(previous: unknown, event: LogEvent, entityKey: DnsIdJWK, operationalKey: DnsIdJWK): Promise<unknown> {
  if (event.type === 'DELEGATION') return previous;
  const state = await activeState(event.domain, entityKey, operationalKey) as Record<string, unknown>;
  if (event.type === 'REVOCATION') state.status = 'REVOKED';
  if (event.type === 'RETIREMENT') state.status = 'RETIRED';
  return state;
}
