export type FoundryErrorCategory =
  | 'KEY_MISSING' | 'KEY_MISMATCH' | 'KEY_REVOKED' | 'SigningPaused'
  | 'UnsupportedRegistry' | 'busy' | 'deadline' | 'cancelled'
  | 'unsupported-contract' | 'unsupported-algorithm' | 'workflow-outcome'
  | 'terminal' | 'binding' | 'storage' | 'resumable';

export interface FoundryErrorFacts {
  phase?: string;
  httpStatus?: number;
  code?: string;
  identityId?: string;
  domain?: string;
  registryStatus?: string;
  resumable: boolean;
  cause?: unknown;
}

/** Structured setup failure. Server codes are retained independently of the SDK category. */
export class FoundryError extends Error implements FoundryErrorFacts {
  readonly phase?: string;
  readonly httpStatus?: number;
  readonly code?: string;
  readonly identityId?: string;
  readonly domain?: string;
  readonly registryStatus?: string;
  readonly resumable: boolean;

  constructor(readonly category: FoundryErrorCategory, message: string, facts: FoundryErrorFacts) {
    super(message, { cause: facts.cause });
    this.name = 'FoundryError';
    this.phase = facts.phase;
    this.httpStatus = facts.httpStatus;
    this.code = facts.code;
    this.identityId = facts.identityId;
    this.domain = facts.domain;
    this.registryStatus = facts.registryStatus;
    this.resumable = facts.resumable;
  }
}

export class SigningPaused extends FoundryError {
  constructor() {
    super('SigningPaused', 'application signing is paused; call active() to verify the identity', { resumable: true });
    this.name = 'SigningPaused';
  }
}

export class UnsupportedRegistry extends FoundryError {
  constructor(facts: Omit<FoundryErrorFacts, 'resumable'> = {}) {
    super('UnsupportedRegistry', 'registry does not serve the Identity Digital onboarding contract', { ...facts, resumable: false });
    this.name = 'UnsupportedRegistry';
  }
}

/** One budget per public call; non-cancellable work is awaited before releasing its lock. */
export class Deadline {
  readonly signal: AbortSignal;
  readonly end: number;
  constructor(timeoutMs = 30_000, signal?: AbortSignal) {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2_147_483_647) throw new RangeError('timeoutMs must be finite, positive, and at most 2147483647');
    this.end = Date.now() + timeoutMs;
    this.signal = AbortSignal.any([AbortSignal.timeout(Math.ceil(timeoutMs)), ...(signal ? [signal] : [])]);
  }
  check(): void {
    if (!this.signal.aborted && Date.now() < this.end) return;
    throw new FoundryError(this.signal.aborted && this.signal.reason?.name !== 'TimeoutError' ? 'cancelled' : 'deadline',
      'Foundry call cancelled or deadline exceeded; saved progress can be resumed', { resumable: true, cause: this.signal.reason });
  }
  async call<T>(operation: () => Promise<T>): Promise<T> {
    this.check();
    const result = await operation();
    this.check();
    return result;
  }
  async wait(ms = 1000): Promise<void> {
    this.check();
    await new Promise<void>((resolve, reject) => {
      const abort = () => { clearTimeout(timer); reject(this.signal.reason); };
      const timer = setTimeout(() => { this.signal.removeEventListener('abort', abort); resolve(); }, Math.min(ms, Math.max(1, this.end - Date.now())));
      this.signal.addEventListener('abort', abort, { once: true });
    }).catch(() => this.check());
    this.check();
  }
}
