import { createHash, generateKeyPairSync, sign as signEd25519 } from 'node:crypto';
import { exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import {
  DNSSECState,
  DnsIdTxtRecord,
  createIdentityVerifier,
  jwkThumbprint,
  toArrayBuffer,
  toBase64Url,
  type C2spIssuanceEvent,
  type DnsIdJWK,
  type KeyProvider,
} from '@identity-digital/dnsid';
import {
  checkpointPath,
  createC2spTlogVerificationRegistry,
  c2spTlogEntryBytes,
  encodeEntryBundle,
  entryBundlePath,
  merkleRootFromEntries,
  prepareC2spTlogEventForSigning,
  requiredC2spResourceFetchGuarantees,
  signPreparedC2spTlogEvent,
  type C2spBoundedResourceFetcher,
  type PreparedC2spVerificationContext,
} from '@identity-digital/dnsid-log-c2sp-tlog';

async function es256Key(kid: string): Promise<{ publicJwk: DnsIdJWK; privateKey: CryptoKey }> {
  const pair = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = { ...await exportJWK(pair.publicKey), kid, alg: 'ES256', use: 'sig' } as DnsIdJWK;
  return { publicJwk, privateKey: pair.privateKey as CryptoKey };
}

function provider(key: DnsIdJWK, privateKey: CryptoKey): KeyProvider {
  const sign = async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    toArrayBuffer(bytes),
  ));
  return {
    signingKey: async () => key,
    jwk: async kid => {
      if (kid !== key.kid) throw new Error('key not found');
      return key;
    },
    listKeyIds: async () => [key.kid],
    sign,
    signKey: async (kid, bytes) => {
      if (kid !== key.kid) throw new Error('key not found');
      return sign(bytes);
    },
    generateKey: async () => { throw new Error('not implemented'); },
    activate: async () => { throw new Error('not implemented'); },
    supersede: async () => { throw new Error('not implemented'); },
  };
}

function signedNoteKey(name: string, type: number, publicBytes: Buffer): { text: string; id: Buffer } {
  const typeBytes = Buffer.from([type]);
  const id = createHash('sha256').update(name).update('\n').update(typeBytes).update(publicBytes).digest().subarray(0, 4);
  return {
    text: `${name}+${id.toString('hex')}+${Buffer.concat([typeBytes, publicBytes]).toString('base64')}`,
    id,
  };
}

describe('C2SP verification factory to IdentityManager', () => {
  it('verifies a domain end to end from hermetic standard checkpoint and entry-bundle resources', async () => {
    const domain = 'agent.example.com';
    const logPrefix = 'https://log.example/tlog';
    const lr = `c2sp-tlog:testnet:${logPrefix}#fixture-stream`;
    const origin = 'log.example/tlog';
    const entity = await es256Key('entity');
    const operational = await es256Key('operational');
    const witnessSecond = Math.floor(Date.now() / 1000);
    const event: C2spIssuanceEvent = {
      type: 'ISSUANCE',
      domain,
      governanceId: 'example.com',
      // One second after checkpoint time: accepted only because the factory
      // wires the configured allowedClockSkew into lifecycle verification.
      timestamp: new Date((witnessSecond + 1) * 1000),
      initialOperationalKid: operational.publicJwk.kid,
      initialOperationalAlg: operational.publicJwk.alg!,
      initialOperationalPublicKey: operational.publicJwk,
      initialOperationalThumbprint: await jwkThumbprint(operational.publicJwk),
      initialEntityKid: entity.publicJwk.kid,
      initialEntityAlg: entity.publicJwk.alg!,
      initialEntityPublicKey: entity.publicJwk,
      initialEntityThumbprint: await jwkThumbprint(entity.publicJwk),
    };
    const context: PreparedC2spVerificationContext = {
      expectedFqdn: domain,
      expectedGovernanceId: 'example.com',
      entityKey: entity.publicJwk,
      operationalKey: operational.publicJwk,
    };
    let prepared = prepareC2spTlogEventForSigning(event, lr);
    prepared = await signPreparedC2spTlogEvent(prepared, 'Entity', provider(entity.publicJwk, entity.privateKey), context);
    prepared = await signPreparedC2spTlogEvent(prepared, 'OperationalCountersignature', provider(operational.publicJwk, operational.privateKey), context);
    const entryBytes = await c2spTlogEntryBytes(prepared, context);

    const { publicKey: logPublicKey, privateKey: logPrivateKey } = generateKeyPairSync('ed25519');
    const { publicKey: witnessPublicKey, privateKey: witnessPrivateKey } = generateKeyPairSync('ed25519');
    const logKey = signedNoteKey(origin, 0x01, Buffer.from(logPublicKey.export({ format: 'jwk' }).x!, 'base64url'));
    const witnessName = 'witness.example';
    const witnessKey = signedNoteKey(witnessName, 0x04, Buffer.from(witnessPublicKey.export({ format: 'jwk' }).x!, 'base64url'));
    const policy = new TextEncoder().encode(`log ${logKey.text}\nwitness W ${witnessKey.text}\nquorum W\n`);

    const rootHash = merkleRootFromEntries([entryBytes]);
    const signedText = `${origin}\n1\n${Buffer.from(rootHash).toString('base64')}\n`;
    const logSignature = signEd25519(null, Buffer.from(signedText), logPrivateKey);
    const witnessTimestamp = BigInt(witnessSecond);
    const witnessTimestampBytes = Buffer.alloc(8);
    witnessTimestampBytes.writeBigUInt64BE(witnessTimestamp);
    const witnessSignature = signEd25519(
      null,
      Buffer.from(`cosignature/v1\ntime ${witnessTimestamp}\n${signedText}`),
      witnessPrivateKey,
    );
    const checkpoint = new TextEncoder().encode(
      `${signedText}\n— ${origin} ${Buffer.concat([logKey.id, logSignature]).toString('base64')}\n`
      + `— ${witnessName} ${Buffer.concat([witnessKey.id, witnessTimestampBytes, witnessSignature]).toString('base64')}\n`,
    );
    const entryBundle = encodeEntryBundle([entryBytes]);

    const policyUrl = 'https://policy.example/dnsid-policy';
    const resources = new Map<string, Uint8Array>([
      [policyUrl, policy],
      [checkpointPath(logPrefix), checkpoint],
      [entryBundlePath(logPrefix, 0, 1), entryBundle],
    ]);
    const fetchBounded = vi.fn(async (url: string, maximum: number) => {
      const value = resources.get(url);
      if (!value) throw new Error(`unexpected fixture URL ${url}`);
      if (value.length > maximum) throw new Error('fixture exceeded scanner maximum');
      return value;
    });
    const resourceFetcher: C2spBoundedResourceFetcher = {
      fetchBounded,
      securityGuarantees: requiredC2spResourceFetchGuarantees,
    };
    const logRegistry = await createC2spTlogVerificationRegistry({
      policyUrl,
      resourceFetcher,
      checkpointMaxAge: 60_000,
      allowedClockSkew: 1_000,
    });

    const record = new DnsIdTxtRecord();
    record.v = 'dnsid-draft-01';
    record.gi = 'example.com';
    record.ek = 'https://example.com/entity.jwks';
    record.ku = `https://${domain}/operational.jwks`;
    record.lr = lr;
    record.su = `https://${domain}/status`;
    record.agentFQDN = domain;
    record.sg = toBase64Url(new Uint8Array(await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      entity.privateKey,
      toArrayBuffer(new TextEncoder().encode(record.canonical())),
    )));
    const cert = { notAfter: new Date('2099-01-01'), san: [domain, 'example.com'] };
    const idm = createIdentityVerifier({}, {
      logRegistry,
      dnsResolver: {
        fetchTXT: async () => [[{ strings: [record.serialize()], ttl: 300 }], DNSSECState.UNSIGNED],
      },
      fetchJson: async url => {
        if (url === record.ek) return { data: { keys: [entity.publicJwk] }, tlsCert: cert };
        if (url === record.ku) return { data: { keys: [operational.publicJwk] }, tlsCert: cert };
        if (url === record.su) return { data: { state: 'ACTIVE', lastTransitionAt: new Date().toISOString() }, tlsCert: cert };
        throw new Error(`unexpected JSON URL ${url}`);
      },
    });

    const verified = await idm.verifyDomain(domain);
    expect(verified.domain).toBe(domain);
    expect((await idm.loadDomainLog(verified)).events).toHaveLength(1);
    await expect(verified.logReader.verifyNonRevocation(domain, event.timestamp)).resolves.toMatchObject({
      logReference: record.lr,
      loggedState: 'ACTIVE',
    });
    expect(fetchBounded).toHaveBeenCalledWith(policyUrl, 1_048_576, expect.objectContaining({ timeoutMs: 10_000 }));
    expect(fetchBounded.mock.calls.some(([url, maximum]) => url === entryBundlePath(logPrefix, 0, 1)
      && maximum === 16_777_472)).toBe(true);
  });
});
