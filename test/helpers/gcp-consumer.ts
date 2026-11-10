import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { HttpSignaturesProfile, jwkThumbprint } from '@dnsid-ai/sdk';
import { constructIdentityManager, loadFile } from '@dnsid-ai/sdk/node';
import { DNSSECState, DnsIdTxtRecord, type DNSResolver, type DnsIdJWK } from '@dnsid-ai/protocol';
import {
  canonicalBytes, checkpointPath, createC2spTlogVerificationRegistry,
  encodeEntryBundle, entryBundlePath, merkleRootFromEntries, requiredC2spResourceFetchGuarantees,
} from '@dnsid-ai/log-c2sp-tlog';

// Provisional compliance 3e5d4d7: configuration loading and KeyProvider contracts.
// Mode: fake-only external KMS RPCs and DNS/HTTPS bytes; actual C2SP and SDK verification.
// Local eligibility is not authorized public rotation, persistence, or crash recovery.
const parent = 'projects/consumer/locations/global/keyRings/agents/cryptoKeys/signer';
const a = parent + '/cryptoKeyVersions/7'; const b = parent + '/cryptoKeyVersions/8';
const algorithm = 'EC_SIGN_ED25519';
const keys = new Map([a, b].map((version, i) => [version, createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, i + 1)]),
  format: 'der', type: 'pkcs8',
})]));
function crc(bytes: Uint8Array) {
  let c = 0xffffffff;
  for (const byte of bytes) { c ^= byte; for (let i = 0; i < 8; i++) c = (c >>> 1) ^ ((c & 1) ? 0x82f63b78 : 0); }
  return (c ^ 0xffffffff) >>> 0;
}

// External-byte fixture follows c2sp-factory-identity-manager.test.ts (standard
// checkpoint/entry bundle) and c2sp-stream-bundle.test.ts (seeded signed envelope).
// No log-reader methods or verification verdicts are substituted.
async function publicationFixture(domain: string, operationalKey: DnsIdJWK) {
  const privateKey = (seed: number) => createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seed)]),
    format: 'der', type: 'pkcs8',
  });
  const entityPrivate = privateKey(3);
  const entityKey = { ...createPublicKey(entityPrivate).export({ format: 'jwk' }),
    kty: 'OKP', alg: 'EdDSA', use: 'sig', kid: 'entity' } as DnsIdJWK;
  const prefix = 'https://log.example/tlog';
  const origin = 'log.example/tlog';
  const record = new DnsIdTxtRecord();
  Object.assign(record, { v: 'dnsid-draft-01', gi: 'example.com', agentFQDN: domain,
    ek: 'https://example.com/entity.jwks', ku: `https://${domain}/operational.jwks`,
    lr: `c2sp-tlog:testnet:${prefix}#fixture-stream`, su: `https://${domain}/status` });
  record.sg = sign(null, Buffer.from(record.canonical()), entityPrivate).toString('base64url');
  const second = Math.floor(Date.now() / 1000);
  const payload = { v: 1, kind: 'dnsid.lifecycle', type: 'ISSUANCE',
    method: 'c2sp-tlog', log_origin: origin, stream_id: 'fixture-stream', lr: record.lr,
    seq: 0, fqdn: domain, gi: 'example.com', ts: second, ek: entityKey, ku: operationalKey };
  const signed = canonicalBytes(payload);
  const entry = canonicalBytes({ ...payload, sigs: {
    ae: { kid: entityKey.kid, sig: sign(null, signed, entityPrivate).toString('base64url') },
    op: { kid: operationalKey.kid, sig: sign(null, signed, keys.get(a)!).toString('base64url') },
  } });
  const noteKey = (name: string, type: number, seed: number) => {
    const key = privateKey(seed);
    const publicBytes = Buffer.from(createPublicKey(key).export({ format: 'jwk' }).x!, 'base64url');
    const typed = Buffer.concat([Buffer.from([type]), publicBytes]);
    const id = createHash('sha256').update(name).update('\n').update(typed).digest().subarray(0, 4);
    return { key, id, text: `${name}+${id.toString('hex')}+${typed.toString('base64')}` };
  };
  const log = noteKey(origin, 1, 4);
  const witness = noteKey('witness.example', 4, 5);
  const body = `${origin}\n1\n${Buffer.from(merkleRootFromEntries([entry])).toString('base64')}\n`;
  const timestamp = Buffer.alloc(8);
  timestamp.writeBigUInt64BE(BigInt(second));
  const checkpoint = Buffer.from(`${body}\n— ${origin} ${Buffer.concat([
    log.id, sign(null, Buffer.from(body), log.key),
  ]).toString('base64')}\n— witness.example ${Buffer.concat([
    witness.id, timestamp, sign(null, Buffer.from(`cosignature/v1\ntime ${second}\n${body}`), witness.key),
  ]).toString('base64')}\n`);
  const resources = new Map<string, Uint8Array>([
    [checkpointPath(prefix), checkpoint], [entryBundlePath(prefix, 0, 1), encodeEntryBundle([entry])],
  ]);
  const resourceReads: string[] = [];
  const logRegistry = await createC2spTlogVerificationRegistry({
    policyDocument: Buffer.from(`log ${log.text}\nwitness W ${witness.text}\nquorum W\n`),
    checkpointMaxAge: 60_000,
    resourceFetcher: {
      securityGuarantees: requiredC2spResourceFetchGuarantees,
      fetchBounded: async (url, maximum) => {
        resourceReads.push(url);
        const bytes = resources.get(url);
        assert(bytes, `unexpected log resource ${url}`);
        assert(bytes.length <= maximum);
        return bytes;
      },
    },
  });
  const cert = { notAfter: new Date('2099-01-01'), san: [domain, 'example.com'] };
  return { record, logRegistry, resourceReads,
    dnsResolver: { fetchTXT: async () => [[{ strings: [record.serialize()], ttl: 300 }], DNSSECState.UNSIGNED] } satisfies DNSResolver,
    fetchJson: async (url: string) => {
      if (url === record.ek) return { data: { keys: [entityKey] }, tlsCert: cert };
      if (url === record.ku) return { data: { keys: [operationalKey] }, tlsCert: cert };
      assert.equal(url, record.su);
      return { data: { state: 'ACTIVE', lastTransitionAt: new Date().toISOString() }, tlsCert: cert };
    },
  };
}

export async function gcpConsumer(mode: 'EdDSA' | 'existing' = 'EdDSA') {
  // This fixture also runs in plain Node ESM/CJS: freeze Date only, not timers.
  // Capture the enclosing constructor so serial nested scopes restore exactly.
  const OriginalDate = globalThis.Date;
  const fixed = OriginalDate.parse('2026-10-27T12:00:00Z');
  globalThis.Date = new Proxy(OriginalDate, {
    construct(target, args, newTarget) {
      return Reflect.construct(target, args.length ? args : [fixed], newTarget);
    },
    apply() { return new OriginalDate(fixed).toString(); },
    get(target, property, receiver) {
      return property === 'now' ? () => fixed : Reflect.get(target, property, receiver);
    },
  });
  try {
    await runConsumer(mode);
  } finally {
    globalThis.Date = OriginalDate;
  }
}

async function runConsumer(mode: 'EdDSA' | 'existing') {
  // Published A is built independently, never obtained from the selected provider.
  const raw = createPublicKey(keys.get(a)!).export({ format: 'jwk' });
  const published = { kty: 'OKP', crv: 'Ed25519', x: raw.x!, alg: 'EdDSA', use: 'sig', kid: '' };
  published.kid = await jwkThumbprint(published);
  const fixture = await publicationFixture('agent.example.com', published);
  const prototype = KeyManagementServiceClient.prototype;
  const names = ['getPublicKey', 'getCryptoKeyVersion', 'asymmetricSign', 'createCryptoKeyVersion', 'createCryptoKey',
    'importCryptoKeyVersion', 'updateCryptoKeyVersion', 'destroyCryptoKeyVersion', 'updateCryptoKeyPrimaryVersion'] as const;
  const originals = names.map(name => [name, prototype[name]] as const);
  let reads = 0; let creates = 0; let signs = 0;
  let failure: 'create' | 'read' | 'metadata' | undefined;
  // Test-only structural seam accommodates the official client's overloaded RPCs.
  const rpc = prototype as unknown as Record<string, (...args: any[]) => Promise<any>>;
  const dir = await mkdtemp(join(tmpdir(), 'dnsid-gcp-consumer-'));
  try {
    for (const name of names) rpc[name] = async () => assert.fail('forbidden RPC: ' + name);
    rpc.getPublicKey = async ({ name }: { name: string }) => {
      reads++; assert(keys.has(name));
      if (name === b && failure === 'read') throw new Error('read denied');
      const pem = createPublicKey(keys.get(name)!).export({ format: 'pem', type: 'spki' }).toString();
      return [{ name, algorithm, protectionLevel: 'SOFTWARE', pem, pemCrc32c: { value: crc(Buffer.from(pem)) } }];
    };
    rpc.getCryptoKeyVersion = async ({ name }: { name: string }) => {
      assert.equal(name, b);
      return [{ name, algorithm, protectionLevel: 'SOFTWARE', state: failure === 'metadata' ? 'DISABLED' : 'ENABLED' }];
    };
    rpc.createCryptoKeyVersion = async (request: { parent: string }) => {
      creates++; assert.equal(request.parent, parent);
      if (failure === 'create') throw new Error('create denied');
      return [{ name: b, algorithm, protectionLevel: 'SOFTWARE', state: failure === 'metadata' ? 'PENDING_GENERATION' : 'ENABLED' }];
    };
    rpc.asymmetricSign = async (request: { name: string; data: Uint8Array; dataCrc32c: { value: number }; digest?: unknown }) => {
      signs++; assert(keys.has(request.name)); assert.equal(request.digest, undefined);
      assert.equal(Number(request.dataCrc32c.value), crc(request.data));
      const signature = sign(null, request.data, keys.get(request.name)!);
      return [{ name: request.name, signature, signatureCrc32c: { value: crc(signature) }, verifiedDataCrc32c: true }];
    };
    const deps = { dnsResolver: fixture.dnsResolver, fetchJson: fixture.fetchJson, logRegistry: fixture.logRegistry };
    async function open(version = a, deploymentAlgorithm: string | undefined = mode === 'existing' ? undefined : 'EdDSA') {
      const file = join(dir, 'deployment.json');
      await writeFile(file, JSON.stringify({ dnsid: { identity: {
        domain: 'agent.example.com', governanceId: 'example.com', logRef: fixture.record.lr,
        statusUrl: fixture.record.su, ekUrl: fixture.record.ek, kuUrl: fixture.record.ku,
      } }, keySource: { provider: 'google-kms', keyRef: version, settings: { algorithm: deploymentAlgorithm } } }));
      const before = await readFile(file);
      try {
        return await constructIdentityManager(await loadFile(file), deps);
      } finally {
        assert.deepEqual(await readFile(file), before, 'construction must not rewrite deployment settings');
      }
    }
    async function roundTrip(manager: Awaited<ReturnType<typeof open>>) {
      const profile = HttpSignaturesProfile.fromIdentityManager(manager);
      const signed = await profile.createSignedHttpRequest(new Request('https://api.example.com/resource', { method: 'POST', body: 'original' }));
      assert.equal((await profile.verifySignedHttpRequest(signed.clone())).domain, 'agent.example.com');
      const tampered = new Request(signed.url, { method: signed.method, headers: signed.headers, body: 'tampered' });
      await assert.rejects(() => profile.verifySignedHttpRequest(tampered));
    }
    // F1: real selected factory must translate deployment JOSE vocabulary.
    const outcome = await open().then(manager => ({ ok: true as const, manager }), error => ({ ok: false as const, error }));
    assert.equal(outcome.ok, true, 'deployment must construct through the actual selected GCP package');
    const manager = outcome.manager; const provider = manager.getKeyProvider()!;
    assert.equal((await provider.signingKey()).kid, published.kid);
    assert.equal(reads, 1); assert.equal(creates, 0); assert.equal(signs, 0);
    const observed = await manager.verifyLocalPublication();
    assert.equal(observed.domain, 'agent.example.com');
    const history = await manager.loadDomainLog(observed);
    assert.equal(history.events.length, 1);
    assert(fixture.resourceReads.includes(checkpointPath('https://log.example/tlog')));
    assert(fixture.resourceReads.includes(entryBundlePath('https://log.example/tlog', 0, 1)));
    const payloadA = Buffer.from('independent GCP signature check');
    assert(verify(null, payloadA, createPublicKey(keys.get(a)!), await provider.sign(payloadA)));
    await roundTrip(manager);
    const before = creates; const signedBefore = signs;
    await assert.rejects(() => open(b), /configured operational key does not match/);
    assert.equal(creates, before); assert.equal(signs, signedBefore);
    for (const unsupported of mode === 'existing' ? ['ES256', 'unknown'] : ['ES256', 'EC_SIGN_ED25519', 'unknown']) {
      const readsBefore: number = reads;
      await assert.rejects(() => open(a, unsupported));
      assert.equal(reads, readsBefore); assert.equal(creates, before); assert.equal(signs, signedBefore);
    }
    const bRaw = createPublicKey(keys.get(b)!).export({ format: 'jwk' });
    const bKid = await jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: bRaw.x!, kid: '', alg: 'EdDSA' });
    for (failure of ['create', 'read', 'metadata'] as const) {
      await assert.rejects(() => provider.generateKey());
      assert.deepEqual(await provider.listKeyIds(), [published.kid]);
      await assert.rejects(() => provider.jwk(bKid));
      const signCalls: number = signs;
      await assert.rejects(() => provider.signKey(bKid, new Uint8Array([1])));
      assert.equal(signs, signCalls);
      await roundTrip(manager);
    }
    failure = undefined;
    const pending = await provider.generateKey();
    assert.equal(pending, bKid); assert.deepEqual(await provider.listKeyIds(), [published.kid]);
    await roundTrip(manager); // Pending B did not change publication A or consumer signing.
    await provider.activate(pending);
    const payload = Buffer.from('explicit local activation, not public rotation');
    assert(verify(null, payload, createPublicKey(keys.get(b)!), await provider.sign(payload)));
    await assert.rejects(() => provider.signKey(published.kid, payload));
    assert.deepEqual(await provider.listKeyIds(), [pending]);
    await provider.supersede(published.kid);
    assert(verify(null, payload, createPublicKey(keys.get(b)!), await provider.sign(payload)));
  } finally {
    for (const [name, original] of originals) Object.defineProperty(prototype, name, { value: original, writable: true, configurable: true });
    await rm(dir, { recursive: true, force: true });
    await assert.rejects(() => readFile(join(dir, 'deployment.json')), { code: 'ENOENT' });
  }
}
