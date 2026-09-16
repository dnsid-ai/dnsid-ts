import { ArgumentError, VerificationCode, VerificationError } from './errors.ts';

export interface VerificationOptions {
  /** Overall invocation budget, including all discovery and evidence. Default: 30 seconds. */
  timeoutMs?: number;
  signal?: AbortSignal;
}

/** Runs an invocation with a shared cancellation signal; child operations must not restart its budget. */
export async function withVerificationBudget<T>(operation: (signal: AbortSignal) => Promise<T>, options: VerificationOptions = {}): Promise<T> {
  const timeout = options.timeoutMs === undefined ? 30_000 : options.timeoutMs;
  if (!Number.isFinite(timeout) || timeout <= 0 || timeout > 2_147_483_647) throw new ArgumentError('verification timeout must be finite and positive');
  const controller = new AbortController();
  const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
  const deadline = performance.now() + timeout;
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const result = await waitForVerification(operation, signal);
    // Synchronous parsing/crypto may postpone the timer task; never return late success.
    if (performance.now() >= deadline) {
      controller.abort();
      throw new VerificationError('verification deadline exceeded', { code: VerificationCode.RecordInvalid, transient: true });
    }
    return result;
  } finally { clearTimeout(timer); }
}

/** Races cooperative work against cancellation, including already-aborted invocations. */
export async function waitForVerification<T>(operation: (signal: AbortSignal) => Promise<T>, signal: AbortSignal): Promise<T> {
  let onAbort: () => void = () => {};
  const canceled = new Promise<never>((_, reject) => {
    onAbort = () => reject(new VerificationError('verification deadline exceeded or canceled', { code: VerificationCode.RecordInvalid, transient: true }));
    if (signal.aborted) onAbort();
    else signal.addEventListener('abort', onAbort, { once: true });
  });
  try {
    if (signal.aborted) return await canceled;
    const result = await Promise.race([operation(signal), canceled]);
    if (signal.aborted) return await canceled;
    return result;
  } finally { signal.removeEventListener('abort', onAbort); }
}
