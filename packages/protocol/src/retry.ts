import { VerificationError } from './errors.ts';

export interface RetryBackoffOptions {
  /** Total attempts including the initial call. Default: 3. */
  maxAttempts?: number;
  /** Delay before the first retry. Default: 100ms. */
  initialDelayMs?: number;
  /** Maximum delay between attempts. Default: 2000ms. */
  maxDelayMs?: number;
  /** Exponential multiplier applied after each failed attempt. Default: 2. */
  multiplier?: number;
  /** Apply full jitter in the range [0, delay]. Default: true. */
  jitter?: boolean;
  /** Optional policy override. Defaults to retrying transient VerificationError only. */
  shouldRetry?: (error: unknown, attempt: number) => boolean;
  /** Test hook for sleeping. */
  sleep?: (ms: number) => Promise<void>;
}

const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_INITIAL_DELAY_MS = 100;
const DEFAULT_MAX_DELAY_MS = 2_000;
const DEFAULT_MULTIPLIER = 2;

/** Returns true when the error is a transient DNSid verification failure. */
export function isTransientVerificationError(error: unknown): boolean {
  return error instanceof VerificationError && error.transient;
}

/**
 * Retries an operation using exponential backoff, but only for transient
 * VerificationError failures by default. Integrity and policy failures are never
 * retried unless callers explicitly override shouldRetry.
 */
export async function retryTransientVerification<T>(
  operation: () => Promise<T>,
  options: RetryBackoffOptions = {},
): Promise<T> {
  const maxAttempts = positiveInteger(options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS, 'maxAttempts');
  const initialDelayMs = nonNegativeNumber(options.initialDelayMs ?? DEFAULT_INITIAL_DELAY_MS, 'initialDelayMs');
  const maxDelayMs = nonNegativeNumber(options.maxDelayMs ?? DEFAULT_MAX_DELAY_MS, 'maxDelayMs');
  const multiplier = nonNegativeNumber(options.multiplier ?? DEFAULT_MULTIPLIER, 'multiplier');
  const jitter = options.jitter ?? true;
  const shouldRetry = options.shouldRetry ?? ((error: unknown) => isTransientVerificationError(error));
  const sleep = options.sleep ?? defaultSleep;

  let attempt = 1;
  for (;;) {
    try {
      return await operation();
    } catch (error) {
      if (attempt >= maxAttempts || !shouldRetry(error, attempt)) throw error;
      await sleep(delayForAttempt(attempt, initialDelayMs, maxDelayMs, multiplier, jitter));
      attempt += 1;
    }
  }
}

function delayForAttempt(
  attempt: number,
  initialDelayMs: number,
  maxDelayMs: number,
  multiplier: number,
  jitter: boolean,
): number {
  const uncapped = initialDelayMs * Math.pow(multiplier, attempt - 1);
  const capped = Math.min(maxDelayMs, uncapped);
  return jitter ? Math.floor(Math.random() * capped) : capped;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isInteger(value) || value < 1) throw new RangeError(`${name} must be an integer >= 1`);
  return value;
}

function nonNegativeNumber(value: number, name: string): number {
  if (!Number.isFinite(value) || value < 0) throw new RangeError(`${name} must be >= 0`);
  return value;
}
