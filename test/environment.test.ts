import { afterEach, describe, expect, it, vi } from 'vitest';
import { DNSSECMode } from '@identity-digital/dnsid';
import {
  configFromEnvironment,
  dnsidEnvironmentVariables,
  keyStorePathFromEnvironment,
} from '@identity-digital/dnsid/node';
import { DEFAULT_REGISTRY_URL } from '@identity-digital/dnsid';

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('configFromEnvironment()', () => {
  it('builds config and derives protocol status URL', () => {
    const environment = configFromEnvironment({
      [dnsidEnvironmentVariables.domain]: 'alice.example.com',
      [dnsidEnvironmentVariables.governanceId]: 'example.com',
      [dnsidEnvironmentVariables.registryUrl]: 'https://registry.example.com/',
      [dnsidEnvironmentVariables.ekUrl]: 'https://example.com/entity-jwks.json',
      [dnsidEnvironmentVariables.dnssecMode]: DNSSECMode.required,
      [dnsidEnvironmentVariables.agentPort]: '3001',
    }, {
      require: ['registryUrl', 'agentPort'],
    });

    expect(environment.config).toEqual({
      identity: {
        domain: 'alice.example.com',
        governanceId: 'example.com',
        logRef: 'noop:0',
        statusUrl: 'https://registry.example.com/v1/status/alice.example.com',
        ekUrl: 'https://example.com/entity-jwks.json',
      },
      verification: { dnssecMode: DNSSECMode.required },
      transport: {},
    });
    expect(environment.registryUrl).toBe('https://registry.example.com/');
    expect(environment.agentPort).toBe(3001);
  });

  it('defaults registryUrl and derives statusUrl when only domain and governanceId are set', () => {
    const environment = configFromEnvironment({
      [dnsidEnvironmentVariables.domain]: 'alice.example.com',
      [dnsidEnvironmentVariables.governanceId]: 'example.com',
    });

    expect(environment.registryUrl).toBe(DEFAULT_REGISTRY_URL);
    expect(environment.config.identity.statusUrl).toBe(
      `${DEFAULT_REGISTRY_URL}/v1/status/alice.example.com`,
    );
  });

  it('uses explicit status URL when provided', () => {
    const environment = configFromEnvironment({
      [dnsidEnvironmentVariables.domain]: 'alice.example.com',
      [dnsidEnvironmentVariables.governanceId]: 'example.com',
      [dnsidEnvironmentVariables.statusUrl]: 'https://status.example.com/alice',
    });

    expect(environment.config.identity.statusUrl).toBe('https://status.example.com/alice');
  });

  it('rejects missing required schema fields', () => {
    expect(() => configFromEnvironment({
      [dnsidEnvironmentVariables.domain]: 'alice.example.com',
      [dnsidEnvironmentVariables.governanceId]: 'example.com',
      [dnsidEnvironmentVariables.statusUrl]: 'https://status.example.com/alice',
    }, {
      require: ['registryUrl'],
    })).toThrow(`${dnsidEnvironmentVariables.registryUrl} is required`);
  });

  it('rejects invalid typed fields', () => {
    expect(() => configFromEnvironment({
      [dnsidEnvironmentVariables.domain]: 'alice.example.com',
      [dnsidEnvironmentVariables.governanceId]: 'example.com',
      [dnsidEnvironmentVariables.statusUrl]: 'https://status.example.com/alice',
      [dnsidEnvironmentVariables.agentPort]: 'not-a-port',
    })).toThrow(`${dnsidEnvironmentVariables.agentPort} must be a positive integer`);

    expect(() => configFromEnvironment({
      [dnsidEnvironmentVariables.domain]: 'alice.example.com',
      [dnsidEnvironmentVariables.governanceId]: 'example.com',
      [dnsidEnvironmentVariables.statusUrl]: 'https://status.example.com/alice',
      [dnsidEnvironmentVariables.dnssecMode]: 'optional',
    })).toThrow(`invalid ${dnsidEnvironmentVariables.dnssecMode}`);
  });

  it('accepts an empty options object as current-environment options', () => {
    vi.stubEnv(dnsidEnvironmentVariables.domain, 'alice.example.com');
    vi.stubEnv(dnsidEnvironmentVariables.governanceId, 'example.com');
    vi.stubEnv(dnsidEnvironmentVariables.statusUrl, 'https://status.example.com/alice');

    expect(configFromEnvironment({}).config.identity.domain).toBe('alice.example.com');
  });
});

describe('keyStorePathFromEnvironment()', () => {
  it('uses the configured key-store path when present', () => {
    expect(keyStorePathFromEnvironment({
      [dnsidEnvironmentVariables.keyStorePath]: '.testnet/agents/alice.keys.json',
    })).toBe('.testnet/agents/alice.keys.json');
  });

  it('falls back to the supplied default path', () => {
    expect(keyStorePathFromEnvironment({}, '.tmp/keys.json')).toBe('.tmp/keys.json');
  });
});
