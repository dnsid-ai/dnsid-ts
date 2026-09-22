import { afterEach, describe, expect, it, vi } from 'vitest';
import { DNSSECMode } from '@dnsid-ai/sdk';
import {
  configFromEnvironment,
  dnsidEnvironmentVariables,
  keyStorePathFromEnvironment,
  registryClientOptionsFromEnvironment,
} from '@dnsid-ai/sdk/node';
import { DEFAULT_REGISTRY_URL } from '@dnsid-ai/sdk';

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

  it('parses DNSID_PRIVATE_HOSTS as a trimmed comma-separated list, omitted when unset or empty', () => {
    const base = {
      [dnsidEnvironmentVariables.domain]: 'alice.example.com',
      [dnsidEnvironmentVariables.governanceId]: 'example.com',
    };
    const transportFor = (value?: string) => configFromEnvironment(
      value === undefined ? base : { ...base, [dnsidEnvironmentVariables.privateAddressHosts]: value },
    ).config.transport;

    expect(transportFor(' .test, agent.local ,,')).toEqual({ privateAddressHosts: ['.test', 'agent.local'] });
    expect(transportFor()).toEqual({});
    expect(transportFor('')).toEqual({});
    expect(transportFor(' , ')).toEqual({});
  });

  it('exposes the registry API key without touching core config', () => {
    const environment = configFromEnvironment({
      [dnsidEnvironmentVariables.domain]: 'alice.example.com',
      [dnsidEnvironmentVariables.governanceId]: 'example.com',
      [dnsidEnvironmentVariables.apiKey]: 'testnet',
    });
    expect(environment.apiKey).toBe('testnet');
    expect(JSON.stringify(environment.config)).not.toContain('testnet');
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

describe('registryClientOptionsFromEnvironment()', () => {
  it('defaults to the local registry with no credential', () => {
    expect(registryClientOptionsFromEnvironment({})).toEqual({ baseUrl: DEFAULT_REGISTRY_URL });
  });

  it('reads DNSID_REGISTRY_URL and DNSID_API_KEY without requiring identity variables', () => {
    expect(registryClientOptionsFromEnvironment({
      [dnsidEnvironmentVariables.registryUrl]: 'https://api.dnsid.ai',
      [dnsidEnvironmentVariables.apiKey]: 'k',
    })).toEqual({ baseUrl: 'https://api.dnsid.ai', token: 'k' });
  });
});
