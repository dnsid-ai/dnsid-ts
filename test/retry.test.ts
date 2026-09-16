import { describe, expect, it, vi } from 'vitest';
import {
  retryTransientVerification,
  VerificationCode,
  VerificationError,
} from '@dnsid-ai/protocol';

describe('retryTransientVerification()', () => {
  it('retries transient VerificationError failures with backoff', async () => {
    const sleep = vi.fn().mockResolvedValue(undefined);
    const op = vi.fn()
      .mockRejectedValueOnce(new VerificationError('dns timeout', {
        code: VerificationCode.DNSResolution,
        transient: true,
      }))
      .mockRejectedValueOnce(new VerificationError('dns timeout again', {
        code: VerificationCode.DNSResolution,
        transient: true,
      }))
      .mockResolvedValue('ok');

    await expect(retryTransientVerification(op, {
      maxAttempts: 3,
      initialDelayMs: 100,
      multiplier: 2,
      jitter: false,
      sleep,
    })).resolves.toBe('ok');

    expect(op).toHaveBeenCalledTimes(3);
    expect(sleep).toHaveBeenNthCalledWith(1, 100);
    expect(sleep).toHaveBeenNthCalledWith(2, 200);
  });

  it('does not retry permanent VerificationError failures', async () => {
    const sleep = vi.fn().mockResolvedValue(undefined);
    const err = new VerificationError('bad signature', { code: VerificationCode.SignatureInvalid });
    const op = vi.fn().mockRejectedValue(err);

    await expect(retryTransientVerification(op, { sleep })).rejects.toBe(err);

    expect(op).toHaveBeenCalledOnce();
    expect(sleep).not.toHaveBeenCalled();
  });

  it('stops at maxAttempts for transient failures', async () => {
    const sleep = vi.fn().mockResolvedValue(undefined);
    const err = new VerificationError('status unavailable', {
      code: VerificationCode.TLSError,
      transient: true,
    });
    const op = vi.fn().mockRejectedValue(err);

    await expect(retryTransientVerification(op, {
      maxAttempts: 2,
      initialDelayMs: 1,
      jitter: false,
      sleep,
    })).rejects.toBe(err);

    expect(op).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledOnce();
  });
});
