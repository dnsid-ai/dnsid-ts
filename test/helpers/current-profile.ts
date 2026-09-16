import { exportJWK, generateKeyPair } from 'jose';
import {
  DNSID_DRAFT01_VERSION,
  DNSSECState,
  DnsIdTxtRecord,
  LogRegistry,
  toArrayBuffer,
  toBase64Url,
} from '@dnsid-ai/protocol';
import type { DNSResolver, DnsIdJWK, JsonFetcher, LoggedStateEvidence, LogReader, TXTRecord } from '@dnsid-ai/protocol';

export async function currentProfileFixture(
  domain: string,
  operationalKey: DnsIdJWK,
  policyFlags?: string,
  selector = DNSID_DRAFT01_VERSION,
  maxKeyAge?: string,
): Promise<{
  record: DnsIdTxtRecord;
  entityKey: DnsIdJWK;
  dnsResolver: DNSResolver;
  fetchJson: JsonFetcher;
  logReader: LogReader;
  logRegistry: LogRegistry;
}> {
  const entityPair = await generateKeyPair('ES256');
  const rawEntity = await exportJWK(entityPair.publicKey);
  const entityKey = { ...rawEntity, kty: rawEntity.kty!, alg: 'ES256', kid: 'entity-key', use: 'sig' } as DnsIdJWK;
  const record = new DnsIdTxtRecord();
  record.v = selector;
  record.gi = 'example.com';
  record.ek = 'https://example.com/entity-jwks.json';
  record.ku = `https://${domain}/.well-known/jwks.json`;
  record.lr = 'microledger:ref';
  record.su = `https://${domain}/status`;
  record.agentFQDN = domain;
  record.fl = policyFlags;
  record.ka = maxKeyAge;
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    entityPair.privateKey,
    toArrayBuffer(new TextEncoder().encode(record.canonical())),
  );
  record.sg = toBase64Url(new Uint8Array(signature));

  const dnsResolver: DNSResolver = {
    fetchTXT: async () => [[{ strings: [record.serialize()], ttl: 300 } satisfies TXTRecord], DNSSECState.UNSIGNED],
  };
  const cert = { notAfter: new Date('2099-01-01'), san: [domain, 'example.com'] };
  const fetchJson: JsonFetcher = async url => {
    if (url.includes('/status')) return { data: { state: 'ACTIVE', lastTransitionAt: new Date().toISOString() }, tlsCert: cert };
    return { data: { keys: [url === record.ek ? entityKey : operationalKey] }, tlsCert: cert };
  };
  const evidence: LoggedStateEvidence = {
    logReference: record.lr,
    loggedState: 'ACTIVE',
    historyStart: `${record.lr}@0`,
    historyEnd: `${record.lr}@0`,
    completeThrough: '1',
    completenessMode: 'test',
    checkpoint: new Uint8Array(),
    freshnessTime: new Date(),
  };
  const logReader: LogReader = {
    canonical: async () => new Uint8Array(),
    keyTimestamp: async () => new Date(),
    verifyBilateralBinding: async () => ({ initialOperationalThumbprint: 'initial', initialEntityThumbprint: 'entity', timestamp: new Date() }),
    verifyOperationalContinuity: async () => {},
    verifyNonRevocation: async () => evidence,
    readEvent: async () => { throw new Error('not implemented'); },
    rebuildHistory: async () => [],
  };
  const logRegistry = new LogRegistry();
  logRegistry.register('microledger', () => logReader);
  return { record, entityKey, dnsResolver, fetchJson, logReader, logRegistry };
}
