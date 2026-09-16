import { ValidationError } from './errors.ts';
import type { AgentStatus, AgentStatusState, RevocationReason } from './types.ts';

const VALID_STATES = new Set<AgentStatusState>([
  'PENDING', 'PROVISIONING', 'VERIFYING', 'ACTIVE', 'RETIRED', 'REVOKED',
]);
const VALID_REVOCATION_REASONS = new Set<RevocationReason>([
  'keyCompromise', 'policyViolation', 'superseded', 'cessationOfOperation',
]);
const ZERO_TIMESTAMP_MS = new Date('0001-01-01T00:00:00Z').getTime();

/**
 * Builds a simple ACTIVE status document for demos/tests that do not model
 * lifecycle state.
 */
export function activeStatusDocument(lastTransitionAt: Date = new Date()): AgentStatus {
  return { state: 'ACTIVE', lastTransitionAt };
}

/**
 * Validates the DNSid JSON status profile returned by the `su` endpoint.
 */
export function validateAgentStatus(data: unknown): AgentStatus {
  if (typeof data !== 'object' || data === null) {
    throw new ValidationError('status response is not a JSON object');
  }
  const d = data as Record<string, unknown>;

  const rawState = d['state'];
  const state = normalizeStatusState(rawState);
  if (!state) {
    throw new ValidationError(`unknown agent status state: ${String(rawState)}`);
  }

  const rawLastTransitionAt = d['lastTransitionAt'];
  if (!rawLastTransitionAt) {
    throw new ValidationError('lastTransitionAt is required');
  }
  const lastTransitionAt = new Date(rawLastTransitionAt as string);
  if (isNaN(lastTransitionAt.getTime()) || lastTransitionAt.getTime() === ZERO_TIMESTAMP_MS) {
    throw new ValidationError('lastTransitionAt is not a valid date');
  }

  const rawRevocationReason = d['revocationReason'];
  const revocationReason = normalizeRevocationReason(rawRevocationReason);
  if (state === 'REVOKED' && !revocationReason) {
    throw new ValidationError('valid revocationReason is required when status is REVOKED');
  }

  return { state, lastTransitionAt, revocationReason };
}

function normalizeStatusState(value: unknown): AgentStatusState | undefined {
  if (typeof value !== 'string') return undefined;
  return VALID_STATES.has(value as AgentStatusState) ? value as AgentStatusState : undefined;
}

function normalizeRevocationReason(value: unknown): RevocationReason | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  const reason = String(value);
  return VALID_REVOCATION_REASONS.has(reason as RevocationReason) ? reason as RevocationReason : undefined;
}
