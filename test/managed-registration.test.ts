import { mkdtemp, readFile, rm, stat, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DNSSECState, DnsIdTxtRecord, LogRegistry, VerificationCode, jwkThumbprint, toBase64Url,
  type C2spIssuanceEvent, type DnsIdJWK, type LogReader,
} from '@dnsid-ai/protocol';
import { canonicalBytes, prepareC2spTlogEventForSigning, signPreparedC2spTlogEvent } from '@dnsid-ai/log-c2sp-tlog';
import {
  FileRegistrationStore, LocalKeyProvider, ManagedRegistrationError, loadEnvironment, loadFile, mergeLoadedConfig,
  registerManagedIdentity, type ManagedRegistrationState, type RegisterManagedIdentityOptions,
} from '@dnsid-ai/sdk/node';

import { deriveManagedRegistrationKeys } from '../packages/sdk/src/managed-registration.ts';

const DOMAIN = 'agent.host.example';
const GI = 'example.com';
const LR = 'c2sp-tlog:public:https://log.example/dnsid#ERERERERERERERERERERER';
const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map(dir => rm(dir, { recursive: true, force: true }))); vi.restoreAllMocks(); });
async function directory() { const dir = await mkdtemp(join(tmpdir(), 'dnsid-registration-')); directories.push(dir); return dir; }

async function fixture() {
  const rootDir = await directory();
  const store = new FileRegistrationStore(rootDir).forIdentity({ registryUrl: 'https://registry.example', organizationId: 'org-1', name: 'agent' });
  const dir = dirname(store.keyStorePath);
  const entity = await LocalKeyProvider.generate();
  const entityKey = await entity.signingKey();
  let operational: DnsIdJWK;
  let initialOperational: DnsIdJWK | undefined;
  let registryStatus = 'VERIFIED';
  let protocolState = 'ACTIVE';
  let issuerUrl: string | undefined = 'https://oidc.example';
  let pendingSubmissions = 0;
  let failCreation = 0;
  let failDetail = 0;
  let absentDns = 0;
  let failSubmission = 0;
  let authority = 'dnsid';
  let claim: { key: string; body: string } | undefined;
  let allocations = 0;
  let replayId = 'agent-1';
  let issuanceBytes: Uint8Array | undefined;
  let onboarding = { org_id: 'org-1', governance_domain: GI, gi: { domain: GI, state: 'verified', gate_authorized: true }, ek: { status: 'verified' } };
  const calls: { path: string; body?: string; key?: string | null }[] = [];
  const config = {
    publish_profile: 'dnsid-draft-01', governance_id: GI,
    ek_url: 'https://example.com/entity-jwks.json', ku_url: `https://${DOMAIN}/jwks`,
    status_url: `https://${DOMAIN}/status`, log_ref: LR,
  };
  const record = new DnsIdTxtRecord();
  Object.assign(record, { agentFQDN: DOMAIN, v: config.publish_profile, gi: GI, ek: config.ek_url, ku: config.ku_url, su: config.status_url, lr: LR });
  record.sg = toBase64Url(await entity.sign(new TextEncoder().encode(record.canonical())));
  const reader = {
    canonical: async () => new Uint8Array(), keyTimestamp: async () => new Date(),
    verifyBilateralBinding: async () => ({ initialOperationalThumbprint: await jwkThumbprint(initialOperational!), initialEntityThumbprint: await jwkThumbprint(entityKey), timestamp: new Date() }),
    verifyOperationalContinuity: vi.fn(async () => {}),
    verifyNonRevocation: vi.fn(async () => ({ logReference: config.log_ref, loggedState: 'ACTIVE' as const, historyStart: `${config.log_ref}@0`, historyEnd: `${config.log_ref}@0`,
      completeThrough: '1', completenessMode: 'test', checkpoint: new Uint8Array([1]), freshnessTime: new Date() })),
    readEvent: async () => { throw new Error('unused'); }, rebuildHistory: async () => [],
    readIssuance: async () => {
      if (!issuanceBytes) throw new Error('no accepted issuance');
      return { entryBytes: issuanceBytes.slice(), index: 0, logRef: `${config.log_ref}@0` };
    },
  } as LogReader & { readIssuance: () => Promise<{ entryBytes: Uint8Array; index: number; logRef: string }> };
  const logRegistry = new LogRegistry();
  logRegistry.register('c2sp-tlog', () => reader);
  const cert = { notAfter: new Date('2099-01-01'), san: [DOMAIN, GI] };
  const fetchJson = vi.fn(async (url: string) => ({ data: url === record.su ? { state: protocolState, lastTransitionAt: new Date().toISOString(), ...(protocolState === 'REVOKED' ? { revocationReason: 'keyCompromise' } : {}) }
    : { keys: [url === record.ek ? entityKey : operational] }, tlsCert: cert }));
  const fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const pathname = new URL(String(url)).pathname;
    const headers = new Headers(init?.headers);
    const credential = headers.get('Authorization');
    expect(['Bearer owner-secret', 'Bearer replacement-secret', 'Bearer other-org-secret']).toContain(credential);
    const body = typeof init?.body === 'string' ? init.body : undefined;
    calls.push({ path: pathname, body, key: headers.get('Idempotency-Key') });
    if (credential === 'Bearer other-org-secret') return Response.json({ error: 'FORBIDDEN' }, { status: 403 });
    if (pathname === '/api/v1/org/onboarding') return Response.json(onboarding);
    const saved = JSON.parse(await readFile(join(dir, 'setup.json'), 'utf8'));
    expect(saved).not.toHaveProperty('registrationKey');
    expect(saved).not.toHaveProperty('issuanceKey');
    if (pathname === '/api/v1/agent') {
      const key = headers.get('Idempotency-Key')!;
      if (claim) {
        expect(key).toBe(claim.key);
        expect(body).toBe(claim.body);
      } else {
        claim = { key, body: body! };
        allocations++;
      }
      const request = JSON.parse(body!);
      operational = request.public_key;
      initialOperational ??= operational;
      expect(saved.operationalKey).toEqual(operational);
      expect(request.name).toBe('agent');
      expect(headers.get('Idempotency-Key')).toBe((await deriveManagedRegistrationKeys(saved.organizationId, saved.name, operational)).registrationKey);
      if (saved.providerReference.startsWith('/')) expect(await LocalKeyProvider.load(saved.providerReference).then(p => p.signingKey())).toEqual(operational);
      if (failCreation-- > 0) throw new TypeError('connection lost');
      return Response.json({ id: replayId, domain: record.agentFQDN, publication_config: config, oidc_issuer_url: 'https://oidc.example' }, { status: 201 });
    }
    if (pathname.endsWith('/status')) {
      if (failDetail-- > 0) throw new TypeError('detail unavailable');
      return Response.json({ id: replayId, domain: record.agentFQDN, managed: authority, status: registryStatus, dns_published: true, publication_config: config, oidc_issuer_url: issuerUrl });
    }
    if (pathname.endsWith('/tlog/issuance/prepare')) {
      const event: C2spIssuanceEvent = {
        type: 'ISSUANCE', domain: record.agentFQDN, governanceId: GI, timestamp: new Date(Math.floor(Date.now() / 1000) * 1000),
        initialEntityKid: entityKey.kid, initialEntityAlg: entityKey.alg!, initialEntityPublicKey: entityKey, initialEntityThumbprint: await jwkThumbprint(entityKey),
        initialOperationalKid: operational.kid, initialOperationalAlg: operational.alg!, initialOperationalPublicKey: operational, initialOperationalThumbprint: await jwkThumbprint(operational),
      };
      const prepared = await signPreparedC2spTlogEvent(prepareC2spTlogEventForSigning(event, config.log_ref), 'Entity', entity,
        { expectedFqdn: record.agentFQDN, expectedGovernanceId: GI, entityKey, operationalKey: operational });
      return new Response(canonicalBytes(prepared.envelope).slice().buffer, { headers: { 'DNSid-Log-Reference': config.log_ref } });
    }
    if (pathname.endsWith('/tlog/events')) {
      const bytes = new Uint8Array(init!.body as ArrayBuffer);
      expect(saved.issuance.entryBytes).toEqual(Array.from(bytes));
      const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))).map(b => b.toString(16).padStart(2, '0')).join('');
      if (failSubmission-- > 0) throw new TypeError('unknown append outcome');
      issuanceBytes = bytes.slice();
      registryStatus = 'READY';
      return Response.json({ state: pendingSubmissions-- > 0 ? 'pending' : 'accepted', entry_hash: hash, index: 0, lr: `${config.log_ref}@0` });
    }
    throw new Error(`unexpected endpoint ${pathname}`);
  }) as unknown as typeof globalThis.fetch;
  const options: RegisterManagedIdentityOptions = {
    name: 'agent',
    loaded: { registry: { registryUrl: 'https://registry.example' }, registration: { organizationId: 'org-1', governanceId: GI, entityKeyUrl: config.ek_url },
      dnsid: { verification: { trustedEntities: [] } } },
    credential: 'owner-secret', store, fetch, timeoutMs: 2000, intervalMs: 1, logTrustReference: 'test-log-policy-v1',
    deps: { logRegistry, fetchJson, dnsResolver: { fetchTXT: async () => [absentDns-- > 0 ? [] : [{ strings: [record.serialize()], ttl: 300 }], DNSSECState.UNSIGNED] } },
  };
  return { dir, rootDir, store, options, calls, record, reader, config, fetchJson,
    setOnboarding: (value: typeof onboarding) => { onboarding = value; },
    setReplacementIdentity: async () => {
      claim = undefined;
      replayId = 'agent-2';
      initialOperational = undefined;
      registryStatus = 'VERIFIED';
      record.agentFQDN = 'replacement.host.example';
      config.ku_url = record.ku = 'https://replacement.host.example/jwks';
      config.status_url = record.su = 'https://replacement.host.example/status';
      config.log_ref = record.lr = 'c2sp-tlog:public:https://log.example/dnsid#IiIiIiIiIiIiIiIiIiIiIg';
      cert.san = [record.agentFQDN, GI];
      record.sg = toBase64Url(await entity.sign(new TextEncoder().encode(record.canonical())));
    },
    setRegistryStatus: (value: string) => { registryStatus = value; },
    setIssuerUrl: (value: string | undefined) => { issuerUrl = value; },
    setKuUrl: async (url: string) => {
      config.ku_url = url; record.ku = url;
      record.sg = toBase64Url(await entity.sign(new TextEncoder().encode(record.canonical())));
    },
    allocations: () => allocations, setReplayId: (id: string) => { replayId = id; },
    setFailCreation: (n: number) => { failCreation = n; }, setFailDetail: (n: number) => { failDetail = n; },
    setAbsentDns: (n: number) => { absentDns = n; }, setFailSubmission: (n: number) => { failSubmission = n; },
    setPending: (n: number) => { pendingSubmissions = n; }, setAuthority: (s: string) => { authority = s; },
    setOperational: (key: DnsIdJWK) => { operational = key; }, setProtocolState: (s: string) => { protocolState = s; },
  };
}

async function updateState(f: Awaited<ReturnType<typeof fixture>>, change: (s: ManagedRegistrationState) => void) {
  const release = await f.store.acquire(new AbortController().signal);
  try { const state = (await f.store.load())!; change(state); await f.store.persist(state); } finally { await release(); }
}

describe('durable managed registration', () => {
  it('matches the design replay-key vector and isolates names, organizations and keys', async () => {
    const key = { kty: 'OKP', crv: 'Ed25519', x: Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex').toString('base64url'), kid: 'test', alg: 'EdDSA' };
    const org = '11111111-1111-4111-8111-111111111111';
    const expected = { registrationKey: '2sWNUpI4tnAzJ3quPrT78uJNVdo96m4En3cZsggktcA', issuanceKey: 'pxQMSC0k-V9nn9qLqMRDczyUxyNyQE87LbGuK5SEWGw' };
    expect(await deriveManagedRegistrationKeys(org, ' billing-agent ', key)).toEqual(expected);
    expect(await deriveManagedRegistrationKeys(org, 'billing-agent', { ...key, kid: 'another-provider-alias' })).toEqual(expected);
    expect(await deriveManagedRegistrationKeys(org, 'Billing-agent', key)).not.toEqual(expected);
    expect(await deriveManagedRegistrationKeys('other-org', 'billing-agent', key)).not.toEqual(expected);
  });

  it.each(['', ' ', '😀'.repeat(256), '\ud800'])('rejects invalid name %j before discovery or storage', async name => {
    const f = await fixture();
    await expect(registerManagedIdentity({ ...f.options, name })).rejects.toThrow('name');
    expect(f.calls).toHaveLength(0);
    await expect(stat(f.dir)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('rejects an input.name contradiction before discovery', async () => {
    const f = await fixture();
    await expect(registerManagedIdentity({ ...f.options, input: { name: 'another-name' } })).rejects.toThrow('input.name');
    expect(f.calls).toHaveLength(0);
  });

  it('isolates safe paths and locks for traversal-like names and different tenants', async () => {
    const root = new FileRegistrationStore(await directory());
    const scope = { registryUrl: 'https://registry.example', organizationId: 'org-1', name: '../billing' };
    const stores = [scope, { ...scope, name: 'Billing' }, { ...scope, name: 'billing' },
      { ...scope, organizationId: 'org-2' }, { ...scope, registryUrl: 'https://other.example' }].map(s => root.forIdentity(s));
    expect(new Set(stores.map(s => s.keyStorePath)).size).toBe(stores.length);
    const releases: (() => Promise<void>)[] = [];
    try {
      for (const store of stores) {
        expect(store.keyStorePath).toMatch(/\/[0-9a-f]{64}\/operational-key\.json$/);
        releases.push(await store.acquire(new AbortController().signal));
        expect(await store.load()).toBeUndefined();
      }
      await expect(root.forIdentity(scope).acquire(new AbortController().signal)).rejects.toMatchObject({ code: 'STORE_BUSY' });
    } finally { await Promise.all(releases.map(release => release())); }
  });

  it('discovers verified account bindings before key generation, without inventing an entity endpoint', async () => {
    const f = await fixture();
    f.options.loaded.registration = { entityKeyUrl: f.config.ek_url };
    await registerManagedIdentity(f.options);
    expect(f.calls[0].path).toBe('/api/v1/org/onboarding');
    const state = JSON.parse(await readFile(join(f.dir, 'setup.json'), 'utf8'));
    expect(state.expectations).toEqual({ organizationId: 'org-1', governanceId: GI, entityKeyUrl: f.config.ek_url });
    // Saved GI fills the missing expectation when the organization is supplied.
    f.options.loaded.registration.organizationId = 'org-1';
    const before = f.calls.filter(c => c.path.endsWith('/onboarding')).length;
    await registerManagedIdentity(f.options);
    expect(f.calls.filter(c => c.path.endsWith('/onboarding'))).toHaveLength(before);
  });

  it.each(['proof', 'delegation', 'organization', 'governance'])('rejects unready or conflicting account %s without generation', async problem => {
    const f = await fixture();
    f.options.loaded.registration = { organizationId: 'org-1', entityKeyUrl: f.config.ek_url };
    f.setOnboarding({ org_id: problem === 'organization' ? 'org-2' : 'org-1', governance_domain: GI,
      gi: { domain: problem === 'governance' ? 'other.example' : GI, state: problem === 'proof' ? 'pending' : 'verified', gate_authorized: true },
      ek: { status: problem === 'delegation' ? 'pending' : 'verified' } });
    await expect(registerManagedIdentity(f.options)).rejects.toBeInstanceOf(ManagedRegistrationError);
    expect(f.calls.map(c => c.path)).toEqual(['/api/v1/org/onboarding']);
    await expect(stat(f.store.keyStorePath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('opens an issued identity from independent state with the same derived keys and no second issuance', async () => {
    const f = await fixture();
    await registerManagedIdentity(f.options);
    const root = new FileRegistrationStore(await directory());
    const before = f.calls.filter(c => c.path.includes('/tlog/')).length;
    await registerManagedIdentity({ ...f.options, store: root,
      loaded: { ...f.options.loaded, keySource: { keyRef: f.store.keyStorePath } } });
    expect(f.calls.filter(c => c.path.includes('/tlog/'))).toHaveLength(before);
    const creates = f.calls.filter(c => c.path === '/api/v1/agent');
    expect(creates).toHaveLength(2);
    expect(creates[1]).toEqual(creates[0]);
  });

  it('stops on failed historical retrieval without another preparation or append', async () => {
    const f = await fixture();
    await registerManagedIdentity(f.options);
    const before = f.calls.filter(c => c.path.includes('/tlog/')).length;
    f.reader.readIssuance = async () => { throw new Error('historical retrieval failed'); };
    await expect(registerManagedIdentity(f.options)).rejects.toBeInstanceOf(ManagedRegistrationError);
    expect(f.calls.filter(c => c.path.includes('/tlog/'))).toHaveLength(before);
  });

  it('requires confirmed terminal state and rejects an old key for explicit replacement', async () => {
    const f = await fixture();
    await registerManagedIdentity(f.options);
    const original = await readFile(join(f.dir, 'setup.json'), 'utf8');
    await expect(registerManagedIdentity({ ...f.options, replace: true })).rejects.toMatchObject({ code: 'REPLACEMENT_REQUIRES_TERMINAL_STATE' });
    expect(await readFile(join(f.dir, 'setup.json'), 'utf8')).toBe(original);
    f.setRegistryStatus('RETIRED');
    await expect(registerManagedIdentity({ ...f.options, replace: true,
      loaded: { ...f.options.loaded, keySource: { keyRef: f.store.keyStorePath } } })).rejects.toMatchObject({ code: 'REPLACEMENT_KEY_REUSE' });
    expect(await readFile(join(f.dir, 'setup.json'), 'utf8')).toBe(original);
    expect(f.allocations()).toBe(1);
  });

  it('explicitly replaces a retired identity with a fresh key, ID, domain and stream, retaining history', async () => {
    const f = await fixture();
    await registerManagedIdentity(f.options);
    f.setRegistryStatus('RETIRED');
    const persist = f.store.persist.bind(f.store);
    let switched = false;
    const spy = vi.spyOn(f.store, 'persist').mockImplementation(async state => {
      await persist(state);
      if (state.history?.length && state.operationalKey && !switched) {
        switched = true;
        await f.setReplacementIdentity();
      }
    });
    const result = await registerManagedIdentity({ ...f.options, replace: true });
    spy.mockRestore();
    expect(result.registration).toMatchObject({ id: 'agent-2', domain: 'replacement.host.example' });
    const state = JSON.parse(await readFile(join(f.dir, 'setup.json'), 'utf8'));
    expect(state.history[0].registration).toMatchObject({ id: 'agent-1', domain: DOMAIN });
    expect(state.history[0].operationalKey).not.toEqual(state.operationalKey);
    expect(state.history[0].acceptedIssuance.logRef).not.toBe(state.acceptedIssuance.logRef);
    expect(f.calls.filter(c => c.path === '/api/v1/agent').map(c => c.key)).toHaveLength(2);
    expect(new Set(f.calls.filter(c => c.path === '/api/v1/agent').map(c => c.key)).size).toBe(2);
    expect(await stat(f.store.keyStorePath)).toBeDefined();
  });

  it('preserves terminal history and a fresh locator when replacement generation is interrupted', async () => {
    const f = await fixture();
    await registerManagedIdentity(f.options);
    f.setRegistryStatus('RETIRED');
    const persist = f.store.persist.bind(f.store);
    const spy = vi.spyOn(f.store, 'persist').mockImplementation(async state => {
      await persist(state);
      if (state.history?.length) throw new Error('interrupted replacement');
    });
    await expect(registerManagedIdentity({ ...f.options, replace: true })).rejects.toBeInstanceOf(ManagedRegistrationError);
    spy.mockRestore();
    const state = JSON.parse(await readFile(join(f.dir, 'setup.json'), 'utf8'));
    expect(state.history[0].registration.id).toBe('agent-1');
    expect(state.history[0].observedRegistryStatus).toBe('RETIRED');
    expect(state.providerReference).not.toBe(f.store.keyStorePath);
    expect(state.operationalKey).toBeUndefined();
    expect(await stat(f.store.keyStorePath)).toBeDefined();
  });

  it.each([
    { provider: 'google-kms', keyRef: 'projects/test/keys/key/versions/1' },
    { provider: 'azure-key-vault', keyRef: 'https://vault.example/keys/key/1' },
    { provider: 'aws-kms', generation: { locator: 'alias/test', algorithm: 'EdDSA' } },
    { provider: 'file', keyRef: '/key', generation: { locator: '/another', algorithm: 'EdDSA' } },
  ] as const)('rejects unavailable/conflicting provider selection before discovery: %j', async keySource => {
    const f = await fixture();
    await expect(registerManagedIdentity({ ...f.options, loaded: { ...f.options.loaded, registration: { entityKeyUrl: f.config.ek_url }, keySource } })).rejects.toThrow();
    expect(f.calls).toHaveLength(0);
    await expect(stat(f.dir)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('reports an unavailable optional factory before discovery, without falling back to file custody', async () => {
    const f = await fixture();
    vi.doMock('@dnsid-ai/key-aws', () => ({}));
    try {
      await expect(registerManagedIdentity({ ...f.options, loaded: { ...f.options.loaded,
        registration: { entityKeyUrl: f.config.ek_url }, keySource: { provider: 'aws-kms', keyRef: 'arn:test:key' },
      } })).rejects.toThrow('install a compatible @dnsid-ai/key-aws');
      expect(f.calls).toHaveLength(0);
      await expect(stat(f.dir)).rejects.toMatchObject({ code: 'ENOENT' });
    } finally { vi.doUnmock('@dnsid-ai/key-aws'); }
  });

  it('opens only the selected AWS provider and lets injected providers displace invalid configuration', async () => {
    const f = await fixture();
    const aws = await import('@dnsid-ai/key-aws');
    const provider = await LocalKeyProvider.generate();
    const factory = vi.spyOn(aws, 'createAwsKmsKeyProvider').mockResolvedValue(provider as never);
    f.options.loaded.keySource = { provider: 'aws-kms', keyRef: 'arn:test:stable-key', settings: { region: 'us-east-1' } };
    await registerManagedIdentity(f.options);
    expect(factory).toHaveBeenCalledWith('arn:test:stable-key', { region: 'us-east-1' });
    const g = await fixture();
    g.options.loaded.keySource = { provider: 'google-kms', settings: { secret: 'displaced' } };
    await registerManagedIdentity({ ...g.options, deps: { ...g.options.deps, keyProvider: provider }, providerReference: 'injected-key' });
    expect(factory).toHaveBeenCalledTimes(1);
  });

  it('keeps an explicit initial public-key assertion across an interrupted intent write', async () => {
    const f = await fixture();
    const provider = await LocalKeyProvider.generate();
    const input = { publicKeyJwk: await provider.signingKey() };
    const options = { ...f.options, deps: { ...f.options.deps, keyProvider: provider }, providerReference: 'injected-key' };
    const persist = f.store.persist.bind(f.store);
    const spy = vi.spyOn(f.store, 'persist').mockImplementationOnce(async state => { await persist(state); throw new Error('interrupted intent'); });
    await expect(registerManagedIdentity({ ...options, input })).rejects.toBeInstanceOf(ManagedRegistrationError);
    spy.mockRestore();
    await registerManagedIdentity(options);
    expect(JSON.parse(f.calls.find(c => c.path === '/api/v1/agent')!.body!).public_key).toEqual(input.publicKeyJwk);
  });

  it('generates a supported ES256 file key at a stable, named locator', async () => {
    const f = await fixture();
    const locator = join(await directory(), 'key');
    f.options.loaded.keySource = { provider: 'file', generation: { locator, algorithm: 'ES256' } };
    await registerManagedIdentity(f.options);
    const state = JSON.parse(await readFile(join(f.dir, 'setup.json'), 'utf8'));
    expect(state.providerReference).toBe(`${locator}.${basename(f.dir)}`);
    expect(state.operationalKey.alg).toBe('ES256');
    expect(await LocalKeyProvider.load(state.providerReference).then(p => p.signingKey())).toEqual(state.operationalKey);
  });

  it('requires verified rotation before moving an established local signer to configured KMS custody', async () => {
    const f = await fixture();
    await registerManagedIdentity(f.options);
    const provider = await LocalKeyProvider.load(f.store.keyStorePath);
    const aws = await import('@dnsid-ai/key-aws');
    vi.spyOn(aws, 'createAwsKmsKeyProvider').mockResolvedValue(provider as never);
    const options = { ...f.options, loaded: { ...f.options.loaded, keySource: { provider: 'aws-kms' as const, keyRef: 'arn:test:rotated-key' } } };
    await expect(registerManagedIdentity(options)).rejects.toMatchObject({ code: 'KEY_SOURCE_BINDING' });
    const old = (await provider.signingKey()).kid;
    await provider.activate(await provider.generateKey());
    await provider.supersede(old);
    f.setOperational(await provider.signingKey());
    await f.setKuUrl(`https://${DOMAIN}/.well-known/current-key-jwks.json`);
    await unlink(f.store.keyStorePath);
    await expect(registerManagedIdentity(options)).resolves.toMatchObject({ registration: { id: 'agent-1' } });
    expect(f.calls.filter(c => c.path === '/api/v1/agent')).toHaveLength(1);
  });

  it('rejects corrupt pending bytes before registry calls', async () => {
    const f = await fixture();
    const persist = f.store.persist.bind(f.store);
    const spy = vi.spyOn(f.store, 'persist').mockImplementation(async state => {
      await persist(state);
      if (state.issuance?.entryBytes) throw new Error('interrupted before submission');
    });
    await expect(registerManagedIdentity(f.options)).rejects.toBeInstanceOf(ManagedRegistrationError);
    spy.mockRestore();
    await updateState(f, state => { state.issuance!.entryBytes![0] ^= 1; });
    const before = f.calls.length;
    await expect(registerManagedIdentity(f.options)).rejects.toMatchObject({ code: 'CORRUPT_STATE' });
    expect(f.calls).toHaveLength(before);
  });

  it('persists before mutation, retries exact requests/bytes, verifies publicly and resumes without append', async () => {
    const f = await fixture();
    f.setFailCreation(1); f.setFailDetail(1); f.setFailSubmission(1); f.setPending(1); f.setAbsentDns(1);
    const result = await registerManagedIdentity(f.options);
    expect(result.registration.domain).toBe(DOMAIN);
    expect(f.allocations()).toBe(1);
    expect(result.publishedRecord.protocolStatus?.state).toBe('ACTIVE');
    expect(result.loggedStateEvidence.loggedState).toBe('ACTIVE');
    const creations = f.calls.filter(c => c.path === '/api/v1/agent');
    expect(creations).toHaveLength(2);
    expect(new Set(creations.map(c => c.body)).size).toBe(1);
    expect(new Set(creations.map(c => c.key)).size).toBe(1);
    const submits = f.calls.filter(c => c.path.endsWith('/tlog/events'));
    expect(submits).toHaveLength(3);
    expect(new Set(submits.map(c => c.key)).size).toBe(1);
    expect(submits[0].key).not.toBe(creations[0].key);
    await expect(result.identityManager.verifyDomain(DOMAIN)).rejects.toMatchObject({ code: VerificationCode.CounterpartyNotAccepted });
    const mutations = f.calls.filter(c => !c.path.endsWith('/status')).length;
    f.options.loaded.dnsid = { ...f.options.loaded.dnsid, identity: { ...result.registration.publicationConfig!, domain: DOMAIN } };
    await expect(registerManagedIdentity({ ...f.options, credential: 'owner-secret', input: undefined })).resolves.toMatchObject({ registration: { id: 'agent-1' } });
    expect(f.calls.filter(c => !c.path.endsWith('/status'))).toHaveLength(mutations);
    const recovery = await readFile(join(f.dir, 'setup.json'), 'utf8');
    const compact = JSON.parse(recovery);
    expect(compact).not.toHaveProperty('creationInput');
    expect(compact).not.toHaveProperty('request');
    expect(compact).not.toHaveProperty('issuance');
    expect(compact.acceptedIssuance).toMatchObject({ index: 0, logRef: `${LR}@0` });
    expect(recovery).not.toContain('owner-secret');
    expect(recovery).not.toContain('trustedEntities');
    expect((await stat(join(f.dir, 'setup.json'))).mode & 0o777).toBe(0o600);
    expect((await stat(f.dir)).mode & 0o777).toBe(0o700);
  });

  it('rejects requested GI contradictions and invalid identity configuration before generating keys', async () => {
    const f = await fixture();
    await expect(registerManagedIdentity({ ...f.options, input: { governanceDomain: 'other.example' } })).rejects.toBeInstanceOf(Error);
    await expect(registerManagedIdentity({ ...f.options, loaded: { ...f.options.loaded, dnsid: { identity: { maxKeyAge: 'invalid' as never } } } })).rejects.toThrow('unsupported local maxKeyAge');
    expect(f.calls).toHaveLength(0);
    await expect(stat(f.store.keyStorePath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it.each([false, true])('retains identity context when releasing storage fails (earlier failure=%s)', async earlierFailure => {
    const f = await fixture();
    await registerManagedIdentity(f.options);
    const acquire = f.store.acquire.bind(f.store);
    const spy = vi.spyOn(f.store, 'acquire').mockImplementation(async signal => {
      const release = await acquire(signal);
      return async () => { await release(); throw new Error('lock sync failed'); };
    });
    const error = await registerManagedIdentity({ ...f.options, credential: earlierFailure ? 'other-org-secret' : 'owner-secret' }).catch(e => e);
    expect(error).toMatchObject({ code: 'STORAGE_RELEASE_FAILED', phase: 'storage', registrationId: 'agent-1', domain: DOMAIN, setupCompleted: true, issuanceState: 'accepted' });
    if (earlierFailure) {
      expect(error.cause).toBeInstanceOf(AggregateError);
      expect(error.cause.errors[0]).toMatchObject({ phase: 'creation', cause: { httpStatus: 403, code: 'FORBIDDEN' } });
    }
    spy.mockRestore();
    const release = await f.store.acquire(new AbortController().signal);
    await release();
  });

  it('holds exclusive access and requires manual interrupted-lock recovery', async () => {
    const f = await fixture();
    const release = await f.store.acquire(new AbortController().signal);
    await expect(registerManagedIdentity({ ...f.options, store: new FileRegistrationStore(f.rootDir) })).rejects.toMatchObject({ code: 'STORE_BUSY' });
    await release();
    const cancelled = new AbortController();
    cancelled.abort();
    await expect(registerManagedIdentity({ ...f.options, signal: cancelled.signal })).rejects.toMatchObject({ code: 'CANCELLED_OR_DEADLINE', phase: 'storage' });
    await writeFile(join(f.dir, 'setup.lock'), '{"pid":0}', { mode: 0o600 });
    await expect(registerManagedIdentity(f.options)).rejects.toMatchObject({ code: 'STORE_BUSY' });
    expect(f.calls).toHaveLength(0);
  });

  it.each([365 * 86_400_000, -365 * 86_400_000])('replays retained creation after a clock change of %s ms', async shift => {
    const f = await fixture();
    f.setFailDetail(1);
    const controller = new AbortController();
    const persist = f.store.persist.bind(f.store);
    const spy = vi.spyOn(f.store, 'persist').mockImplementation(async state => {
      await persist(state);
      if (state.creation) controller.abort();
    });
    await expect(registerManagedIdentity({ ...f.options, signal: controller.signal })).rejects.toMatchObject({ code: 'CANCELLED_OR_DEADLINE', domain: DOMAIN, registrationId: 'agent-1' });
    spy.mockRestore();
    f.setFailDetail(0);
    const request = f.calls.find(c => c.path === '/api/v1/agent')!;
    const now = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(now + shift);
    await expect(registerManagedIdentity(f.options)).resolves.toMatchObject({ registration: { id: 'agent-1' } });
    expect(f.calls.filter(c => c.path === '/api/v1/agent')).toEqual([request]);
    expect(f.allocations()).toBe(1);
    const release = await f.store.acquire(new AbortController().signal);
    try { expect(await f.store.load()).not.toHaveProperty('replayDeadline'); }
    finally { await release(); }
  });

  it('refuses a credential from another organization or lost key without allocating a replacement', async () => {
    const f = await fixture();
    await registerManagedIdentity(f.options);
    const before = f.calls.length;
    await expect(registerManagedIdentity({ ...f.options, credential: 'other-org-secret' })).rejects.toMatchObject({ cause: { httpStatus: 403, code: 'FORBIDDEN' } });
    await unlink(f.store.keyStorePath);
    await expect(registerManagedIdentity(f.options)).rejects.toMatchObject({ code: 'MISSING_KEY' });
    expect(f.calls).toHaveLength(before + 1);
    expect(f.allocations()).toBe(1);
  });

  it('recovers a lost creation response with a replacement credential, but refuses another organization', async () => {
    const f = await fixture();
    const controller = new AbortController();
    f.setFailCreation(1);
    const fetch = f.options.fetch!;
    await expect(registerManagedIdentity({ ...f.options, signal: controller.signal,
      fetch: async (url, init) => {
        try { return await fetch(url, init); }
        catch (error) { controller.abort(); throw error; }
      },
    })).rejects.toMatchObject({ code: 'CANCELLED_OR_DEADLINE' });
    const original = await readFile(join(f.dir, 'setup.json'), 'utf8');
    await expect(registerManagedIdentity({ ...f.options, credential: 'other-org-secret' }))
      .rejects.toMatchObject({ cause: { httpStatus: 403, code: 'FORBIDDEN' } });
    expect(await readFile(join(f.dir, 'setup.json'), 'utf8')).toBe(original);
    await expect(registerManagedIdentity({ ...f.options, credential: 'replacement-secret' }))
      .resolves.toMatchObject({ registration: { id: 'agent-1' } });
    expect(f.allocations()).toBe(1);
    const requests = f.calls.filter(c => c.path === '/api/v1/agent');
    expect(new Set(requests.map(c => c.key)).size).toBe(1);
    expect(new Set(requests.map(c => c.body)).size).toBe(1);
  });

  it('rejects a conflicting creation replay without overwriting retained facts', async () => {
    const f = await fixture();
    f.setFailDetail(1);
    const persist = f.store.persist.bind(f.store);
    const spy = vi.spyOn(f.store, 'persist').mockImplementation(async state => {
      await persist(state);
      if (state.creation) throw new Error('interrupted');
    });
    await expect(registerManagedIdentity(f.options)).rejects.toBeInstanceOf(ManagedRegistrationError);
    spy.mockRestore();
    const original = await readFile(join(f.dir, 'setup.json'), 'utf8');
    f.setReplayId('agent-2');
    await expect(registerManagedIdentity(f.options)).rejects.toMatchObject({ code: 'CREATION_BINDING', registrationId: 'agent-1' });
    expect(await readFile(join(f.dir, 'setup.json'), 'utf8')).toBe(original);
    expect(f.allocations()).toBe(1);
  });

  it('refuses old expiring-replay recovery state before any registry call', async () => {
    const f = await fixture();
    await registerManagedIdentity(f.options);
    await updateState(f, state => { (state as { version: number }).version = 1; });
    const before = f.calls.length;
    await expect(registerManagedIdentity(f.options)).rejects.toMatchObject({ code: 'CORRUPT_STATE', registrationId: 'agent-1' });
    expect(f.calls).toHaveLength(before);
  });

  it('retains unsupported authority and rejects it before countersigning', async () => {
    const f = await fixture();
    f.setAuthority('self');
    await expect(registerManagedIdentity(f.options)).rejects.toMatchObject({ code: 'UNSUPPORTED_AUTHORITY', domain: DOMAIN });
    expect(JSON.parse(await readFile(join(f.dir, 'setup.json'), 'utf8')).registration.id).toBe('agent-1');
    expect(f.calls.some(c => c.path.includes('/tlog/'))).toBe(false);
  });

  it('retains an unsupported Live response and does not replay it on resume', async () => {
    const f = await fixture();
    const fetch = f.options.fetch!;
    f.options.fetch = async (url, init) => {
      const response = await fetch(url, init);
      return new URL(String(url)).pathname === '/api/v1/agent'
        ? Response.json({ agent_id: 'agent-1', status: 'CHALLENGE_PENDING' }, { status: 202 }) : response;
    };
    await expect(registerManagedIdentity(f.options)).rejects.toMatchObject({ code: 'UNSUPPORTED_WORKFLOW', registrationId: 'agent-1' });
    const before = f.calls.length;
    await expect(registerManagedIdentity(f.options)).rejects.toMatchObject({ code: 'UNSUPPORTED_WORKFLOW', registrationId: 'agent-1' });
    expect(f.calls).toHaveLength(before);
  });

  it.each(['file', 'environment', 'code'])('uses the same effective setup configuration from %s', async source => {
    const f = await fixture();
    if (source === 'file') {
      const file = join(await directory(), 'deployment.json');
      await writeFile(file, JSON.stringify(f.options.loaded));
      f.options.loaded = await loadFile(file);
    } else if (source === 'environment') {
      const { registry, ...overlay } = f.options.loaded;
      f.options.loaded = mergeLoadedConfig(await loadEnvironment({ DNSID_REGISTRY_URL: registry!.registryUrl, DNSID_API_KEY: 'excluded-secret' }), overlay);
    }
    await expect(registerManagedIdentity(f.options)).resolves.toMatchObject({ registration: { registryUrl: 'https://registry.example', domain: DOMAIN } });
    expect(await readFile(join(f.dir, 'setup.json'), 'utf8')).not.toContain('excluded-secret');
  });

  it('fails closed on invalid signatures and terminal public status without changing application policy', async () => {
    const f = await fixture();
    await registerManagedIdentity(f.options);
    f.record.sg = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const before = f.calls.length;
    const error = await registerManagedIdentity(f.options).catch(e => e);
    expect(error).toBeInstanceOf(ManagedRegistrationError);
    expect(error.cause.code).toBe(VerificationCode.SignatureInvalid);
    expect(f.calls.length - before).toBe(1);
  });

  it('validates historical issuance after rotation without requiring the old private key', async () => {
    const f = await fixture();
    await registerManagedIdentity(f.options);
    const provider = await LocalKeyProvider.load(f.store.keyStorePath);
    const oldKid = (await provider.signingKey()).kid;
    const nextKid = await provider.generateKey();
    await provider.activate(nextKid);
    await provider.supersede(oldKid);
    f.setOperational(await provider.signingKey());
    await f.setKuUrl(`https://${DOMAIN}/.well-known/${await jwkThumbprint(await provider.signingKey())}-jwks.json`);
    const before = f.calls.filter(c => !c.path.endsWith('/status')).length;
    const result = await registerManagedIdentity(f.options);
    expect((await result.identityManager.getKeySet()).keys[0]?.kid).toBe(nextKid);
    expect(f.calls.filter(c => !c.path.endsWith('/status'))).toHaveLength(before);
    expect(f.reader.verifyOperationalContinuity).toHaveBeenCalled();
  });

  it('rejects corrupt accepted bytes before any registry calls', async () => {
    const f = await fixture();
    await registerManagedIdentity(f.options);
    await updateState(f, s => { s.acceptedIssuance!.entryHash = '0'.repeat(64); });
    const before = f.calls.filter(c => !c.path.endsWith('/status')).length;
    await expect(registerManagedIdentity(f.options)).rejects.toMatchObject({ code: 'ISSUANCE_BINDING' });
    expect(f.calls.filter(c => !c.path.endsWith('/status'))).toHaveLength(before);
  });

  it.each(['key', 'creation', 'entity', 'prepared', 'bytes', 'accepted', 'complete'])('resumes an interruption after persisting %s without replacement creation', async boundary => {
    const f = await fixture();
    const persist = f.store.persist.bind(f.store);
    let interrupted = false;
    const spy = vi.spyOn(f.store, 'persist').mockImplementation(async state => {
      await persist(state);
      const hit = boundary === 'key' ? state.phase === 'key' && !!state.operationalKey
        : boundary === 'creation' ? !!state.registration
        : boundary === 'entity' ? !!state.entityKey
        : boundary === 'prepared' ? !!state.issuance?.preparedEntryBytes
        : boundary === 'bytes' ? !!state.issuance?.entryBytes
        : boundary === 'accepted' ? state.issuance?.submission?.state === 'accepted' : state.completed;
      if (hit && !interrupted) { interrupted = true; throw new Error('interrupted process'); }
    });
    await expect(registerManagedIdentity(f.options)).rejects.toBeInstanceOf(ManagedRegistrationError);
    spy.mockRestore();
    await expect(registerManagedIdentity(f.options)).resolves.toMatchObject({ registration: { id: 'agent-1' } });
    expect(f.calls.filter(c => c.path === '/api/v1/agent')).toHaveLength(1);
    expect(f.calls.filter(c => c.path.endsWith('/prepare'))).toHaveLength(1);
    expect(f.calls.filter(c => c.path.endsWith('/events'))).toHaveLength(1);
  });

  it('rejects pending rotation, unexplained public keys, and terminal protocol state', async () => {
    const f = await fixture();
    await registerManagedIdentity(f.options);
    f.setOperational(await LocalKeyProvider.generate().then(p => p.signingKey()));
    await expect(registerManagedIdentity(f.options)).rejects.toMatchObject({ code: 'PUBLIC_KEY_BINDING' });
    const provider = await LocalKeyProvider.load(f.store.keyStorePath);
    f.setOperational(await provider.signingKey());
    f.setProtocolState('REVOKED');
    const terminal = await registerManagedIdentity(f.options).catch(e => e);
    expect(terminal.cause).toMatchObject({ code: VerificationCode.StatusNotActive, agentState: 'REVOKED' });
    await provider.generateKey();
    await expect(registerManagedIdentity(f.options)).rejects.toMatchObject({ code: 'ROTATION_RECOVERY_REQUIRED' });
  });

  it.each([false, true])('rejects a missing saved issuer (completed: %s)', async completed => {
    const f = await fixture();
    if (completed) await registerManagedIdentity(f.options);
    f.setIssuerUrl(undefined);
    await expect(registerManagedIdentity(f.options)).rejects.toMatchObject({ code: 'PUBLICATION_BINDING' });
    expect(f.calls.filter(c => c.path === '/api/v1/agent')).toHaveLength(1);
  });

  it('settles the publication observer write before releasing storage after cancellation', async () => {
    const f = await fixture();
    const controller = new AbortController();
    let finishWrite!: () => void;
    let started!: () => void;
    const writing = new Promise<void>(resolve => { started = resolve; });
    const gate = new Promise<void>(resolve => { finishWrite = resolve; });
    const persist = f.store.persist.bind(f.store);
    vi.spyOn(f.store, 'persist').mockImplementation(async state => {
      if (state.phase === 'publication') {
        started();
        controller.abort();
        await gate;
      }
      await persist(state);
    });
    const run = registerManagedIdentity({ ...f.options, signal: controller.signal });
    let settled = false;
    const result = run.catch(error => { settled = true; return error; });
    await writing;
    await new Promise(resolve => setTimeout(resolve, 10));
    expect(settled).toBe(false);
    await expect(f.store.acquire(new AbortController().signal)).rejects.toMatchObject({ code: 'STORE_BUSY' });
    finishWrite();
    expect(await result).toMatchObject({ code: 'CANCELLED_OR_DEADLINE' });
    const release = await f.store.acquire(new AbortController().signal);
    await release();
  });

  it('applies the overall deadline to log evidence reads and releases storage after cancellation', async () => {
    const f = await fixture();
    await registerManagedIdentity(f.options);
    f.reader.verifyNonRevocation = () => new Promise(() => {});
    await expect(registerManagedIdentity({ ...f.options, timeoutMs: 1000 })).rejects.toMatchObject({ code: 'CANCELLED_OR_DEADLINE', registryStatus: 'READY' });
    const release = await f.store.acquire(new AbortController().signal);
    await release();
    expect(f.calls.filter(c => c.path.endsWith('/events'))).toHaveLength(1);
  });

  it('fails before mutations on incomplete artifacts and ambiguous key initialization', async () => {
    const f = await fixture();
    const persist = f.store.persist.bind(f.store);
    const spy = vi.spyOn(f.store, 'persist').mockImplementation(async state => { await persist(state); throw new Error('interruption before key generation'); });
    await expect(registerManagedIdentity(f.options)).rejects.toBeInstanceOf(ManagedRegistrationError);
    spy.mockRestore();
    await writeFile(`${f.store.keyStorePath}.interrupted.tmp`, 'partial private key', { mode: 0o600 });
    await expect(registerManagedIdentity(f.options)).rejects.toMatchObject({ code: 'AMBIGUOUS_KEY_CREATION' });
    expect(f.calls).toHaveLength(0);
  });

  it('loads and merges setup fields without creating identity or acceptance policy', async () => {
    const dir = await directory();
    const file = join(dir, 'deployment.json');
    await writeFile(file, JSON.stringify({ registration: { governanceId: GI } }));
    const loaded = mergeLoadedConfig(await loadFile(file), { registration: { entityKeyUrl: 'https://example.com/ek' } });
    expect(loaded).toEqual({ registration: { governanceId: GI, entityKeyUrl: 'https://example.com/ek' } });
    await writeFile(file, '{"registration":{"governanceId":false}}');
    await expect(loadFile(file)).rejects.toThrow('must be a string');
    await writeFile(file, '{"registration":{"unknown":"value"}}');
    await expect(loadFile(file)).rejects.toThrow('unknown member');
  });
});
