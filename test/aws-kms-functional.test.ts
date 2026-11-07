import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GetPublicKeyCommand, KMSClient, SignCommand } from '@aws-sdk/client-kms';
import { HttpSignaturesProfile } from '@dnsid-ai/sdk';
import { constructIdentityManager, loadFile } from '@dnsid-ai/sdk/node';
import { it, vi } from 'vitest';
import { currentProfileFixture } from './helpers/current-profile.ts';

// Shared design 12: open-only configuration, exact established signer binding.
// Fake-only AWS/network boundaries; actual loader/factory/provider/facade/verification.
const a = 'arn:aws:kms:us-east-1:111122223333:key/11111111-1111-4111-8111-111111111111';
const b = 'arn:aws:kms:us-east-1:111122223333:key/22222222-2222-4222-8222-222222222222';
const keys = new Map([a, b].map((ref, i) => [ref, createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, i + 1)]),
  format: 'der', type: 'pkcs8',
})]));

it.each(['existing A', 'selected B', 'read denied'] as const)('AWS config-open: %s', async mode => {
  // Expected publication is independent of the selected provider and its reads.
  const raw = createPublicKey(keys.get(a)!).export({ format: 'jwk' });
  const published = { kty: 'OKP', crv: 'Ed25519', x: raw.x!, alg: 'EdDSA', use: 'sig', kid: a };
  const fixture = await currentProfileFixture('agent.example.com', published);
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
  }
});
