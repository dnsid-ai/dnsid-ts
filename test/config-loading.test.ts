import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ArgumentError, DNSSECMode, DNSSECState, LogRegistry } from '@dnsid-ai/sdk';
import type { DNSResolver, JsonFetcher } from '@dnsid-ai/sdk';
import {
  constructIdentityManager,
  createNodeIdentityManager,
  createNodeIdentityManagerFromDnsid,
  createNodeIdentityManagerFromEnvironment,
  createNodeIdentityManagerFromFile,
  createRegistryClientFromEnvironment,
  loadCliDirectory,
  loadEnvironment,
  loadFile,
  mergeLoadedConfig,
} from '@dnsid-ai/sdk/node';
import { withTemp, writeKeyPair } from './helpers/cli-directory.ts';

const dnsResolver: DNSResolver = { fetchTXT: vi.fn().mockResolvedValue([[], DNSSECState.UNSIGNED]) };
const fetchJson: JsonFetcher = vi.fn();
const deps = { dnsResolver, fetchJson };

const IDENTITY_ENV = {
  DNSID_DOMAIN: 'alice.example.com',
  DNSID_GOVERNANCE_ID: 'example.com',
  DNSID_LOG_REF: 'noop:0',
  DNSID_STATUS_URL: 'https://status.example.com/alice',
};

// Fixture from c2sp-trust-profile.test.ts: a valid profile that carries bundle verifier keys.
const TRUST_PROFILE = {
  version: 1,
  scope: 'public',
  log_prefix: 'https://log.example',
  tlog_policy: 'log log.example+3db4ee08+AcqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\n'
    + 'witness primary witness.example+da76602f+BG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx\n'
    + 'quorum primary\n',
  bundle_verifier_keys: [
    'dnsid-stream-bundle+dfa43feb+AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    'dnsid-stream-bundle+85e03385+AQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  ],
};

afterEach(() => vi.unstubAllEnvs());

describe('loadEnvironment()', () => {
  it('returns only sourced fields; empty and whitespace values are absent', async () => {
    expect(await loadEnvironment({})).toEqual({});
    expect(await loadEnvironment({ DNSID_DNS_SERVER: '', DNSID_CA_BUNDLE: '   ', DNSID_PRIVATE_HOSTS: ' , ' })).toEqual({});
    expect(await loadEnvironment({ DNSID_DNS_SERVER: ' 10.0.0.1:53 ' })).toEqual({ dnsid: { transport: { dnsServer: '10.0.0.1:53' } } });
  });

  it('maps the 20-variable schema without deriving or defaulting anything', async () => {
    const loaded = await loadEnvironment({
      ...IDENTITY_ENV,
      DNSID_STATUS_URL: undefined,
      DNSID_EK_URL: 'https://example.com/ek',
      DNSID_KU_URL: 'https://alice.example.com/ku',
      DNSID_PUBLISH_PROFILE: 'dnsid-draft-01',
      DNSID_CAPABILITIES_URL: 'https://alice.example.com/cu',
      DNSID_DNSSEC_MODE: 'required',
      DNSID_PRIVATE_HOSTS: ' .test, agent.local ,,',
      DNSID_LOG_POLICY_URL: 'https://policy.example/p',
      DNSID_REGISTRY_URL: 'https://registry.example',
      DNSID_API_KEY: 'secret',
      DNSID_CONFIG_DIR: '/cli',
      DNSID_KEY_STORE: '/keys.json',
    });
    expect(loaded).toEqual({
      dnsid: {
        identity: {
          domain: 'alice.example.com',
          governanceId: 'example.com',
          logRef: 'noop:0',
          ekUrl: 'https://example.com/ek',
          kuUrl: 'https://alice.example.com/ku',
          publishProfile: 'dnsid-draft-01',
          capabilitiesUrl: 'https://alice.example.com/cu',
        },
        verification: { dnssecMode: DNSSECMode.required },
        transport: { privateAddressHosts: ['.test', 'agent.local'] },
      },
      logTrust: { policyUrl: 'https://policy.example/p' },
      registry: { registryUrl: 'https://registry.example' },
      registryCredential: 'secret',
      keySource: { cliDirectory: '/cli', keyStorePath: '/keys.json' },
    });
    // statusUrl absent; not derived from the registry URL.
    expect(loaded.dnsid!.identity!.statusUrl).toBeUndefined();
    expect(JSON.stringify(loaded.dnsid)).not.toContain('secret');
  });

  it('ignores deployment-tooling variables', async () => {
    expect(await loadEnvironment({
      DNSID_PUBLIC_URL: 'https://alice.example.com',
      DNSID_AGENT_PORT: '3000',
      DNSID_AGENT_NAME: 'alice',
      DNSID_AGENT_UPSTREAM: 'http://127.0.0.1:3001',
      DNSID_SERVER: 'https://api.example',
      DNSID_UNKNOWN: 'x',
    })).toEqual({});
  });

  it('rejects an invalid DNSID_DNSSEC_MODE before construction', async () => {
    await expect(loadEnvironment({ DNSID_DNSSEC_MODE: 'bogus' })).rejects.toThrow(ArgumentError);
  });

  it('reads DNSID_LOG_POLICY_FILE bytes and parses DNSID_LOG_TRUST_PROFILE_FILE', () => withTemp(async root => {
    await writeFile(join(root, 'policy'), 'log x\n');
    await writeFile(join(root, 'profile.json'), JSON.stringify(TRUST_PROFILE));
    expect(await loadEnvironment({ DNSID_LOG_POLICY_FILE: join(root, 'policy') })).toEqual({
      logTrust: { policyDocument: new TextEncoder().encode('log x\n') },
    });
    expect(await loadEnvironment({ DNSID_LOG_TRUST_PROFILE_FILE: join(root, 'profile.json') })).toEqual({
      logTrust: { profile: TRUST_PROFILE },
    });
  }));
});

describe('loadFile()', () => {
  it('reads the three sections and rejects unknown members, mistyped values, and duplicates', () => withTemp(async root => {
    const file = join(root, 'dnsid.json');
    await writeFile(file, JSON.stringify({
      dnsid: { verification: { dnssecMode: 'required', trustedEntities: [{ governanceId: 'acme.example' }] } },
      logTrust: { managed: true },
      registry: { registryUrl: 'https://registry.example' },
    }));
    expect(await loadFile(file)).toEqual({
      dnsid: { verification: { dnssecMode: 'required', trustedEntities: [{ governanceId: 'acme.example' }] } },
      logTrust: { managed: true },
      registry: { registryUrl: 'https://registry.example' },
    });

    await writeFile(file, JSON.stringify({ keySource: { cliDirectory: '/x' } }));
    await expect(loadFile(file)).rejects.toThrow(/unknown member "keySource"/);
    await writeFile(file, JSON.stringify({ logTrust: { policyDocument: 'x' } }));
    await expect(loadFile(file)).rejects.toThrow(/unknown member "policyDocument"/);
    await writeFile(file, JSON.stringify({ logTrust: { managed: 'yes' } }));
    await expect(loadFile(file)).rejects.toThrow(/managed must be a boolean/);
    await writeFile(file, '{"registry":{},"registry":{}}');
    await expect(loadFile(file)).rejects.toThrow(ArgumentError);
  }));

  it('passes unknown dnsid fields through to the constructor, which rejects them', () => withTemp(async root => {
    const file = join(root, 'dnsid.json');
    await writeFile(file, JSON.stringify({ dnsid: { verification: { bogus: 1 } } }));
    await expect(createNodeIdentityManagerFromFile(file, undefined, deps)).rejects.toThrow(/unknown field "bogus"/);
  }));
});

describe('mergeLoadedConfig()', () => {
  it('merges field-wise by presence; lists replace; logTrust is atomic', () => {
    const base = {
      dnsid: {
        identity: { domain: 'a.example.com', governanceId: 'example.com', logRef: 'noop:0', statusUrl: 'https://a/s' },
        verification: { dnssecMode: DNSSECMode.required, trustedEntities: [{ governanceId: 'a.example' }] },
        transport: { privateAddressHosts: ['.test'] },
      },
      logTrust: { managed: true },
      registry: { registryUrl: 'https://base' },
    };
    expect(mergeLoadedConfig(base, {
      dnsid: { verification: { trustedEntities: [] }, transport: { privateAddressHosts: ['.local'], dnsServer: '' } },
      logTrust: { policyUrl: 'https://policy' },
      registryCredential: 'k',
    })).toEqual({
      dnsid: {
        identity: base.dnsid.identity,
        verification: { dnssecMode: DNSSECMode.required, trustedEntities: [] },
        transport: { privateAddressHosts: ['.local'], dnsServer: '' },
      },
      logTrust: { policyUrl: 'https://policy' },
      registry: { registryUrl: 'https://base' },
      registryCredential: 'k',
    });
    expect(mergeLoadedConfig(base, { dnsid: { verification: {} } }).dnsid!.verification!.trustedEntities).toEqual([{ governanceId: 'a.example' }]);
    expect(mergeLoadedConfig({}, {})).toEqual({});
    expect(mergeLoadedConfig({}, { dnsid: { identity: base.dnsid.identity } }).dnsid).toEqual({ identity: base.dnsid.identity });
  });

  it('file logTrust.managed is replaced by environment DNSID_LOG_POLICY_URL', () => withTemp(async root => {
    const file = join(root, 'dnsid.json');
    await writeFile(file, JSON.stringify({ logTrust: { managed: true } }));
    const merged = mergeLoadedConfig(await loadFile(file), await loadEnvironment({ DNSID_LOG_POLICY_URL: 'https://policy.example/p' }));
    expect(merged.logTrust).toEqual({ policyUrl: 'https://policy.example/p' });
  }));
});

describe('constructIdentityManager() and convenience constructors', () => {
  it('only transport and verification variables yield a verification-only manager', async () => {
    const idm = await createNodeIdentityManagerFromEnvironment({ DNSID_DNSSEC_MODE: 'required', DNSID_DNS_SERVER: '10.0.0.1' }, undefined, { fetchJson });
    expect(idm.config.identity).toBeUndefined();
    expect(idm.config.verification.dnssecMode).toBe(DNSSECMode.required);
  });

  it('DNSID_DOMAIN without DNSID_LOG_REF fails with ArgumentError; no placeholder', async () => {
    const { DNSID_LOG_REF: _omit, ...env } = IDENTITY_ENV;
    await expect(createNodeIdentityManagerFromEnvironment(env, undefined, { ...deps, keyProvider: {} as never }))
      .rejects.toThrow(/config\.identity\.logRef is required/);
  });

  it('applies constructor defaults when env transport is whitespace', async () => {
    const idm = await createNodeIdentityManagerFromEnvironment({ DNSID_DNS_SERVER: '  ' }, undefined, deps);
    expect(idm.config.transport).toEqual({});
    expect(idm.config.verification.dnssecMode).toBeUndefined();
  });

  it('logTrust with zero or two variants fails at construction', async () => {
    await expect(constructIdentityManager({ logTrust: {} }, deps)).rejects.toThrow(ArgumentError);
    await expect(constructIdentityManager({ logTrust: { managed: true, policyUrl: 'https://p' } }, deps)).rejects.toThrow(/exactly one/);
    await expect(constructIdentityManager({ logTrust: { managed: false } }, deps)).rejects.toThrow(/must be true/);
  });

  it('DNSID_LOG_POLICY_FILE and DNSID_LOG_POLICY_URL both set fails at construction; the loader keeps both', () => withTemp(async root => {
    await writeFile(join(root, 'policy'), 'log x\n');
    const env = { DNSID_LOG_POLICY_FILE: join(root, 'policy'), DNSID_LOG_POLICY_URL: 'https://policy.example/p' };
    expect(Object.keys((await loadEnvironment(env)).logTrust!).sort()).toEqual(['policyDocument', 'policyUrl']);
    await expect(createNodeIdentityManagerFromEnvironment(env, undefined, deps)).rejects.toThrow(/exactly one/);
  }));

  it('DNSID_LOG_TRUST_PROFILE_FILE with bundle verifier keys constructs with the 10-minute defaults', () => withTemp(async root => {
    await writeFile(join(root, 'profile.json'), JSON.stringify(TRUST_PROFILE));
    const idm = await createNodeIdentityManagerFromEnvironment({ DNSID_LOG_TRUST_PROFILE_FILE: join(root, 'profile.json') }, undefined, deps);
    expect(idm.config.identity).toBeUndefined();
  }));

  it('deps.logRegistry wins over loaded logTrust', async () => {
    const logRegistry = new LogRegistry();
    // An unreachable policy URL would fail construction if the loaded trust were used.
    await expect(constructIdentityManager({ logTrust: { policyUrl: 'https://policy.invalid/p' } }, { ...deps, logRegistry })).resolves.toBeDefined();
  });

  it('cliDirectory wins over keyStorePath for the operational key', () => withTemp(async root => {
    await writeFile(join(root, 'config.json'), JSON.stringify({ domain: 'alice.example.com' }));
    await writeKeyPair(root, 'cli-key');
    const idm = await createNodeIdentityManagerFromEnvironment(
      { ...IDENTITY_ENV, DNSID_CONFIG_DIR: root, DNSID_KEY_STORE: join(root, 'missing-keys.json') },
      undefined,
      deps,
    );
    await expect(idm.getKeyProvider().listKeyIds()).resolves.toEqual(['cli-key']);
  }));

  it('keyStorePath alone supplies the operational key; caller keyProvider wins', () => withTemp(async root => {
    const { LocalKeyProvider } = await import('@dnsid-ai/sdk/node');
    const store = join(root, 'keys.json');
    const created = await LocalKeyProvider.load(store, true);
    const env = { ...IDENTITY_ENV, DNSID_KEY_STORE: store };
    const idm = await createNodeIdentityManagerFromEnvironment(env, undefined, deps);
    await expect(idm.getKeyProvider().listKeyIds()).resolves.toEqual(await created.listKeyIds());

    const own = await LocalKeyProvider.generate();
    const overridden = await createNodeIdentityManagerFromEnvironment(env, undefined, { ...deps, keyProvider: own });
    expect(overridden.getKeyProvider()).toBe(own);
  }));

  it('file trustedEntities [a] with overlay [] denies all; omitted overlay keeps [a]', () => withTemp(async root => {
    const file = join(root, 'dnsid.json');
    await writeFile(file, JSON.stringify({ dnsid: { verification: { trustedEntities: [{ governanceId: 'a.example' }] } } }));
    const denyAll = await createNodeIdentityManagerFromFile(file, { verification: { trustedEntities: [] } }, deps);
    expect(denyAll.config.verification.trustedEntities).toEqual([]);
    const kept = await createNodeIdentityManagerFromFile(file, { verification: { dnssecMode: DNSSECMode.required } }, deps);
    expect(kept.config.verification.trustedEntities).toEqual([{ governanceId: 'a.example' }]);
  }));

  it('convenience constructor and manual Load → Merge → Construct produce identical snapshots', () => withTemp(async root => {
    const dir = join(root, 'alice.example.com');
    await mkdir(dir);
    await writeFile(join(root, 'config.json'), JSON.stringify({ domain: 'alice.example.com' }));
    await writeFile(join(dir, 'config.json'), JSON.stringify({
      domain: 'alice.example.com',
      governance_id: 'example.com',
      log_ref: 'noop:0',
      status_url: 'https://status.example.com/alice',
      server_url: 'https://api.example',
    }));
    await writeKeyPair(dir, 'alice-key');
    const overlay = { verification: { dnssecMode: DNSSECMode.required } };

    const convenient = await createNodeIdentityManagerFromDnsid(root, overlay, deps);
    const manual = await constructIdentityManager(mergeLoadedConfig(await loadCliDirectory(root), { dnsid: overlay }), deps);
    expect(manual.config).toEqual(convenient.config);
    expect(await manual.getKeyProvider().listKeyIds()).toEqual(await convenient.getKeyProvider().listKeyIds());
    expect(convenient.config.identity!.statusUrl).toBe('https://status.example.com/alice');
  }));

  it('createNodeIdentityManagerFromDnsid() reads ~/.dnsid and never DNSID_CONFIG_DIR', () => withTemp(async root => {
    await writeFile(join(root, 'config.json'), JSON.stringify({ ...IDENTITY_ENV }));
    vi.stubEnv('DNSID_CONFIG_DIR', root);
    vi.stubEnv('HOME', root);
    await expect(createNodeIdentityManagerFromDnsid(undefined, undefined, deps)).rejects.toThrow(`${join(root, '.dnsid', 'config.json')} not found`);
  }));

  it('constructors read neither environment nor files', async () => {
    for (const [name, value] of Object.entries(IDENTITY_ENV)) vi.stubEnv(name, value);
    vi.stubEnv('DNSID_DNSSEC_MODE', 'required');
    const idm = await createNodeIdentityManager({}, deps);
    expect(idm.config.identity).toBeUndefined();
    expect(idm.config.verification.dnssecMode).toBeUndefined();
  });
});

describe('createRegistryClientFromEnvironment()', () => {
  it('needs no identity variables and lets the constructor default the URL', async () => {
    const local = await createRegistryClientFromEnvironment({});
    expect((local as unknown as { baseUrl: string }).baseUrl).toBe('http://127.0.0.1:7755');
    const hosted = await createRegistryClientFromEnvironment({ DNSID_REGISTRY_URL: 'https://api.dnsid.ai', DNSID_API_KEY: 'k' });
    expect(hosted as unknown as { baseUrl: string; token: string }).toMatchObject({ baseUrl: 'https://api.dnsid.ai', token: 'k' });
  });
});
