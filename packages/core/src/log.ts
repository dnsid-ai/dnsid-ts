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
 * A concrete implementation (e.g. an Algorand client) typically satisfies both Log and LogReader.
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
   * The event MUST already carry the accountable entity's signature before writeEvent is called.
   * Returns a LogRef identifying the recorded entry.
   */
  writeEvent(event: LogEvent): Promise<LogRef>;
}

/**
 * Read and verify interface for a specific log entry.
 * Bound at construction to a full `lr` value (e.g. "algorand:AGENT_ADDR_BASE32").
 *
 * All methods MUST verify cryptographic inclusion proofs, verifiable timestamps,
 * append-only consistency, and accountable-entity signatures before returning success.
 */
export interface LogReader {
  /**
   * Returns the canonical byte representation of the event for this log method.
   * Used to verify the accountable entity's signature on events read from the log.
   * MUST produce identical output to Log.canonical for the same event.
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
   * Verifies that no REVOCATION event exists for the domain at or before the given timestamp.
   * Raises if a REVOCATION entry is found or if complete, fresh evidence cannot be established.
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
   * accountable-entity signatures on every returned event. Event signature
   * verification MUST use the public key that is valid for that event in the
   * reconstructed lifecycle history. Events with invalid signatures MUST NOT be
   * returned.
   */
  rebuildHistory(domain: string): Promise<LogEvent[]>;
}
