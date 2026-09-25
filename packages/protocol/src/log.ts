import type { AgentStatusState, LogRef } from './types.ts';
import type { LogEvent } from './log-events.ts';

export type LogSignerRole = 'Entity' | 'Operational' | 'OperationalCountersignature' | 'PreviousOperational' | 'NewOperational';

/** Verified proof boundary accepted for a complete lifecycle-state decision. */
export interface LoggedStateEvidence {
  /** Complete identity-instance log reference verified by the binding. */
  logReference: LogRef;
  /** Verified lifecycle state through historyEnd, not current protocol status. */
  loggedState: AgentStatusState;
  /** Method-specific genesis reference included in the verified history. */
  historyStart: LogRef;
  /** Method-specific final applied event reference, when one exists. */
  historyEnd?: LogRef;
  /** Opaque method-specific position through which completeness was established. */
  completeThrough: string;
  /** Binding-defined completeness mechanism. */
  completenessMode: string;
  /** Opaque accepted checkpoint or equivalent log-state evidence. */
  checkpoint: Uint8Array;
  /** Independently verified freshness time. */
  freshnessTime: Date;
}

/**
 * Write interface for the agent's own immutable log.
 * Implementations may wrap a blockchain, CT-style transparency log, SCITT service, or any append-only log.
 *
 * Implementations may satisfy both Log and LogReader; C2SP uses a separate
 * prepared-event append workflow instead of the generic writeEvent method.
 */
export interface Log {
  /**
   * Returns the canonical byte representation of the event for this log method.
   * Called by IdentityManager.signAndWriteEvent to produce the bytes that are signed.
   * MUST produce identical output to LogReader.canonical for the same event.
   */
  canonical(event: LogEvent): Promise<Uint8Array>;

  /**
   * Appends a signed event to the log.
   * The event MUST already carry the signatures required by its log method before writeEvent is called.
   * Returns a LogRef identifying the recorded entry.
   */
  writeEvent(event: LogEvent): Promise<LogRef>;
}

/**
 * Read and verify interface for a specific log entry.
 * Bound at construction to a full `lr` value (e.g. "algorand:AGENT_ADDR_BASE32").
 *
 * Evidence-returning methods MUST verify the applicable inclusion, timestamp,
 * append-only consistency, and lifecycle signatures before returning success.
 * `canonical` only serializes an event; it does not verify log evidence.
 */
export interface LogReader {
  /**
   * Returns the canonical byte representation of the event for this log method.
   * Used to verify the signatures required by the log method on events read from the log.
   * MUST produce identical output to Log.canonical for the same supported event.
   */
  canonical(event: LogEvent): Promise<Uint8Array>;

  /**
   * Returns the timestamp at which the given key thumbprint was bound to the domain
   * (ISSUANCE or KEY_ROTATION event). Used for ka validation.
   */
  keyTimestamp(domain: string, keyThumbprint: string): Promise<Date>;

  /** Verifies draft-01 bilateral ISSUANCE binding for the current TXT record. */
  verifyBilateralBinding(record: unknown, entityKey: unknown, operationalKey: unknown): Promise<{
    initialOperationalThumbprint: string;
    initialEntityThumbprint: string;
    timestamp: Date;
  }>;

  /** Verifies KEY_ROTATION continuity from ISSUANCE to the current operational key. */
  verifyOperationalContinuity(domain: string, initialOperationalThumbprint: string, currentOperationalThumbprint: string): Promise<void>;

  /**
   * Verifies that the domain is neither REVOKED nor RETIRED at the given timestamp.
   * Raises on a terminal state or if complete, fresh evidence cannot be established.
   * Returns the accepted proof boundary.
   */
  verifyNonRevocation(domain: string, at: Date): Promise<LoggedStateEvidence>;

  /**
   * Reads a single event by its log reference.
   * MUST verify inclusion proof and timestamp proof before returning.
   */
  readEvent(ref: LogRef): Promise<LogEvent>;

  /**
   * Rebuilds the full event history for the domain in authoritative log order.
   * MUST verify inclusion proofs, timestamp proofs, append-only consistency, and
   * required lifecycle signatures on every returned event. Event signature
   * verification MUST use the public keys valid for that event in the
   * reconstructed lifecycle history. Events with invalid signatures MUST NOT be
   * returned.
   */
  rebuildHistory(domain: string): Promise<LogEvent[]>;
}
