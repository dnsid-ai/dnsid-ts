import { VerificationError, VerificationCode, ArgumentError, ParseError } from './errors.ts';
import type { LogRef } from './types.ts';
import type { Log, LoggedStateEvidence, LogReader } from './log.ts';
import type { LogEvent } from './log-events.ts';

/** Factory function that creates a LogReader bound to a specific lr value. */
export type LogReaderFactory = (lr: string, options?: { signal?: AbortSignal }) => LogReader;

const METHOD_RE = /^[a-z][a-z0-9-]*$/;

/**
 * Single injection point for all log interaction.
 * Holds one factory per log method.
 */
export class LogRegistry {
  private readonly factories = new Map<string, LogReaderFactory>();

  /** Copies method selection for an immutable manager verification context. */
  snapshot(): LogRegistry {
    const registry = new LogRegistry();
    for (const [method, factory] of this.factories) registry.register(method, factory);
    return registry;
  }

  /**
   * Registers a factory for the given method name (e.g. "algorand", "ctlog", "scitt").
   * @throws ArgumentError if method does not match [a-z][a-z0-9-]*
   */
  register(method: string, factory: LogReaderFactory): void {
    if (!METHOD_RE.test(method)) {
      throw new ArgumentError(`log method must match [a-z][a-z0-9-]*: ${method}`);
    }
    this.factories.set(method, factory);
  }

  /**
   * Creates a LogReader bound to the given lr string.
   * Returns a NoopLogReader if no factory is registered for the method.
   * @throws ParseError if lr is malformed (no colon, empty method, or method violates pattern).
   */
  newReader(lr: string, options?: { signal?: AbortSignal }): LogReader {
    const colonIdx = lr.indexOf(':');
    if (colonIdx === -1) {
      throw new ParseError(`malformed log reference (no colon): ${lr}`);
    }
    const method = lr.slice(0, colonIdx);
    if (!method || !METHOD_RE.test(method)) {
      throw new ParseError(`malformed log reference (invalid method): ${lr}`);
    }

    const factory = this.factories.get(method);
    if (!factory) {
      return new NoopLogReader(method);
    }
    return factory(lr, options);
  }
}

/**
 * Returned by LogRegistry.newReader when no factory is registered for the method.
 * Every method raises VerificationError{code: LogError}.
 */
export class NoopLogReader implements LogReader {
  private readonly method: string;

  constructor(method: string) {
    this.method = method;
  }

  private _raise(): never {
    throw new VerificationError(
      `no LogReader registered for method '${this.method}'`,
      { code: VerificationCode.LogError, transient: false },
    );
  }

  canonical(_event: LogEvent): Promise<Uint8Array> { return this._raise(); }
  keyTimestamp(_domain: string, _keyThumbprint: string): Promise<Date> { return this._raise(); }
  verifyBilateralBinding(_record: unknown, _entityKey: unknown, _operationalKey: unknown): Promise<{ initialOperationalThumbprint: string; initialEntityThumbprint: string; timestamp: Date }> { return this._raise(); }
  verifyOperationalContinuity(_domain: string, _initialOperationalThumbprint: string, _currentOperationalThumbprint: string): Promise<void> { return this._raise(); }
  verifyNonRevocation(_domain: string, _at: Date): Promise<LoggedStateEvidence> { return this._raise(); }
  readEvent(_ref: LogRef): Promise<LogEvent> { return this._raise(); }
  rebuildHistory(_domain: string): Promise<LogEvent[]> { return this._raise(); }
}
