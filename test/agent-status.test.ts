import { describe, expect, it } from 'vitest';
import { validateAgentStatus, ValidationError } from '@dnsid-ai/protocol';

describe('validateAgentStatus', () => {
  it('rejects registry workflow status payloads', () => {
    expect(() => validateAgentStatus({
      status: 'READY',
      updated_at: '2026-05-15T00:00:00.000Z',
    })).toThrow(ValidationError);
  });

  it('accepts protocol-shaped status responses', () => {
    const status = validateAgentStatus({
      state: 'ACTIVE',
      lastTransitionAt: '2026-05-15T00:00:00.000Z',
    });

    expect(status.state).toBe('ACTIVE');
    expect(status.lastTransitionAt.toISOString()).toBe('2026-05-15T00:00:00.000Z');
  });

  it.each([
    '0001-01-01T00:00:00Z',
    '0001-01-01T01:00:00+01:00',
  ])('rejects the zero transition timestamp %s', lastTransitionAt => {
    expect(() => validateAgentStatus({
      state: 'ACTIVE',
      lastTransitionAt,
    })).toThrow(ValidationError);
  });

  it.each(['active', 'Active', 'revoked'])('rejects non-canonical state %s', state => {
    expect(() => validateAgentStatus({
      state,
      lastTransitionAt: '2026-05-15T00:00:00.000Z',
    })).toThrow(ValidationError);
  });

  it('accepts protocol-shaped revocation reasons', () => {
    const status = validateAgentStatus({
      state: 'REVOKED',
      lastTransitionAt: '2026-05-15T00:00:00.000Z',
      revocationReason: 'keyCompromise',
    });

    expect(status.state).toBe('REVOKED');
    expect(status.revocationReason).toBe('keyCompromise');
  });

  it('rejects unknown timestamp aliases', () => {
    expect(() => validateAgentStatus({
      status: 'READY',
      updatedAt: '2026-05-15T00:00:00.000Z',
    })).toThrow(ValidationError);
  });
});
