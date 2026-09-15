import { describe, expect, it } from 'vitest';
import { requiredTestnetLogPolicyUrl } from '../examples/a2a/src/testnet-config.ts';

describe('A2A trusted testnet configuration', () => {
  it('returns the separately supplied policy URL without consulting the log reference', () => {
    expect(requiredTestnetLogPolicyUrl({
      DNSID_LOG_REF: 'c2sp-tlog:testnet:https://log-reference.invalid#stream',
      DNSID_LOG_POLICY_URL: 'https://trusted-policy.invalid:8443/policy',
    })).toBe('https://trusted-policy.invalid:8443/policy');
  });

  it('fails clearly when DNSID_LOG_POLICY_URL is missing', () => {
    expect(() => requiredTestnetLogPolicyUrl({
      DNSID_LOG_REF: 'c2sp-tlog:testnet:https://log-reference.invalid#stream',
    })).toThrow('DNSID_LOG_POLICY_URL is required');
  });
});
