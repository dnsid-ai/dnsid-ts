import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GetPublicKeyCommand, KMSClient, SignCommand } from '@aws-sdk/client-kms';
import { HttpSignaturesProfile } from '@dnsid-ai/sdk';
import { constructIdentityManager, loadFile } from '@dnsid-ai/sdk/node';
import { it, vi } from 'vitest';
import { DNSSECState, DnsIdTxtRecord, type DNSResolver, type DnsIdJWK } from '@dnsid-ai/protocol';
import {
  canonicalBytes, checkpointPath, createC2spTlogVerificationRegistry,
  encodeEntryBundle, entryBundlePath, merkleRootFromEntries, requiredC2spResourceFetchGuarantees,
} from '@dnsid-ai/log-c2sp-tlog';

// Shared design 12: open-only configuration, exact established signer binding.
// Fake-only AWS/network boundaries; actual loader/factory/provider/facade/verification.
const a = 'arn:aws:kms:us-east-1:111122223333:key/11111111-1111-4111-8111-111111111111';
const b = 'arn:aws:kms:us-east-1:111122223333:key/22222222-2222-4222-8222-222222222222';
const keys = new Map([a, b].map((ref, i) => [ref, createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, i + 1)]),
  format: 'der', type: 'pkcs8',
})]));

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

it.each(['existing A', 'selected B', 'read denied'] as const)('AWS config-open: %s', async mode => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date('2026-10-27T12:00:00Z'));
  try {
    // Expected publication is independent of the selected provider and its reads.
    const raw = createPublicKey(keys.get(a)!).export({ format: 'jwk' });
    const published = { kty: 'OKP', crv: 'Ed25519', x: raw.x!, alg: 'EdDSA', use: 'sig', kid: a };
    const fixture = await publicationFixture('agent.example.com', published);
    const selected = mode === 'selected B' ? b : a;
    const denied = new Error('fixture AWS public read denied');
    const calls: string[] = [];
    let creates = 0;
    // The generated AWS client's send boundary only; no own factory/provider mocks.
    const rpc = vi.spyOn(KMSClient.prototype, 'send').mockImplementation(async command => {
      calls.push(command.constructor.name);
      if (command instanceof GetPublicKeyCommand) {
        assert.equal(command.input.KeyId, selected);
        if (mode === 'read denied') throw denied;
        return { KeyId: selected, PublicKey: createPublicKey(keys.get(selected)!).export({ format: 'der', type: 'spki' }),
          KeySpec: 'ECC_NIST_EDWARDS25519', KeyUsage: 'SIGN_VERIFY', SigningAlgorithms: ['ED25519_SHA_512'] };
      }
      if (command instanceof SignCommand) {
        assert.equal(command.input.KeyId, a);
        assert.equal(command.input.MessageType, 'RAW');
        assert.equal(command.input.SigningAlgorithm, 'ED25519_SHA_512');
        return { KeyId: a, SigningAlgorithm: 'ED25519_SHA_512', Signature: sign(null, command.input.Message!, keys.get(a)!) };
      }
      if (command.constructor.name === 'CreateKeyCommand') creates++;
      assert.fail('unexpected AWS command: ' + command.constructor.name);
    });
    const dir = await mkdtemp(join(tmpdir(), 'dnsid-aws-functional-'));
    try {
      const file = join(dir, 'deployment.json');
      await writeFile(file, JSON.stringify({ dnsid: { identity: {
        domain: 'agent.example.com', governanceId: 'example.com', logRef: fixture.record.lr,
        statusUrl: fixture.record.su, ekUrl: fixture.record.ek, kuUrl: fixture.record.ku,
      } }, keySource: { provider: 'aws-kms', keyRef: selected, settings: { region: 'us-east-1', algorithm: 'EdDSA' } } }));
      const before = await readFile(file);
      const open = async () => constructIdentityManager(await loadFile(file), {
        dnsResolver: fixture.dnsResolver, fetchJson: fixture.fetchJson, logRegistry: fixture.logRegistry,
      });
      if (mode === 'existing A') {
        const manager = await open();
        const signingKey = await manager.getKeyProvider()!.signingKey();
        for (const [field, value] of Object.entries(published)) assert.equal(signingKey[field], value);
        const observed = await manager.verifyLocalPublication();
        assert.equal(observed.domain, 'agent.example.com');
        const history = await manager.loadDomainLog(observed);
        assert.equal(history.events.length, 1);
        assert(fixture.resourceReads.some(url => url.endsWith('/checkpoint')));
        assert(fixture.resourceReads.includes(entryBundlePath('https://log.example/tlog', 0, 1)));
        const payload = Buffer.from('independent AWS signature check');
        assert(verify(null, payload, createPublicKey(keys.get(a)!), await manager.getKeyProvider()!.sign(payload)));
        const profile = HttpSignaturesProfile.fromIdentityManager(manager);
        const signed = await profile.createSignedHttpRequest(new Request('https://api.example.com/resource', { method: 'POST', body: 'original' }));
        assert.equal((await profile.verifySignedHttpRequest(signed.clone())).domain, 'agent.example.com');
        await assert.rejects(() => profile.verifySignedHttpRequest(new Request(signed.url, {
          method: signed.method, headers: signed.headers, body: 'tampered',
        })));
        assert(calls.includes('SignCommand'));
      } else {
        await assert.rejects(open, mode === 'read denied' ? error => error === denied : /configured operational key does not match/);
        assert.deepEqual(calls, ['GetPublicKeyCommand']);
      }
      assert.equal(creates, 0);
      assert.deepEqual(await readFile(file), before);
    } finally {
      rpc.mockRestore();
      await rm(dir, { recursive: true, force: true });
      await assert.rejects(() => readFile(join(dir, 'deployment.json')), { code: 'ENOENT' });
    }
  } finally {
    vi.useRealTimers();
  }
});
