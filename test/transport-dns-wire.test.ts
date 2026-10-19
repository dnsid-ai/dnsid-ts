import * as dgram from 'node:dgram';
import * as net from 'node:net';
import * as dns from 'node:dns/promises';
import { generateKeyPairSync } from 'node:crypto';
import packet from 'dns-packet';
import { afterEach, expect, it, vi } from 'vitest';
import { ArgumentError, DNSSECMode, DNSSECState, IdentityManager, InMemoryIdentityCache, VerificationCode, type DnsIdJWK } from '@dnsid-ai/protocol';
import { createDefaultDnsResolver, createDnsResolverFromServer } from '@dnsid-ai/transport';
import { currentProfileFixture } from './helpers/current-profile.ts';

vi.mock('node:dns/promises', async importOriginal => ({
  ...await importOriginal<typeof import('node:dns/promises')>(),
  getServers: vi.fn(),
  resolveTxt: vi.fn(),
}));
afterEach(() => { vi.mocked(dns.getServers).mockReset(); vi.mocked(dns.resolveTxt).mockReset(); });

const name = '_dnsid.example.com';
const reply = (query: packet.Packet, answers: packet.Answer[] = [], flags = 0): Buffer =>
  packet.encode({ type: 'response', id: query.id, flags, questions: query.questions, answers });
const txt = (owner: string, ttl: number, ...strings: string[]): packet.TxtAnswer =>
  ({ type: 'TXT', name: owner, class: 'IN', ttl, data: strings.map(s => Buffer.from(s)) });

async function server(
  udpReply: (query: packet.Packet) => Buffer | undefined,
  tcpReply?: (query: packet.Packet) => Buffer,
): Promise<{ port: number; close: () => Promise<void> }> {
  const udp = dgram.createSocket('udp4');
  await new Promise<void>(resolve => udp.bind(0, '127.0.0.1', resolve));
  const port = (udp.address() as net.AddressInfo).port;
  udp.on('message', (data, remote) => {
    const response = udpReply(packet.decode(data));
    if (response) udp.send(response, remote.port, remote.address);
  });
  const tcp = net.createServer(sock => {
    let data = Buffer.alloc(0);
    sock.on('data', chunk => {
      if (!Buffer.isBuffer(chunk)) return;
      data = Buffer.concat([data, chunk]);
      if (data.length >= 2 && data.length >= 2 + data.readUInt16BE(0)) {
        if (!tcpReply) return sock.end();
        const response = tcpReply(packet.streamDecode(data)!);
        const framed = Buffer.alloc(response.length + 2);
        framed.writeUInt16BE(response.length);
        response.copy(framed, 2);
        for (const byte of framed) sock.write(Buffer.from([byte])); // exercise split TCP reads
        sock.end();
      }
    });
  });
  await new Promise<void>(resolve => tcp.listen(port, '127.0.0.1', resolve));
  return { port, close: async () => {
    udp.close();
    await new Promise<void>(resolve => tcp.close(() => resolve()));
  } };
}

it.each(['configured UDP', 'configured TCP', 'default wire'])(
  'classifies the DNS outcome matrix over %s', async transport => {
    const outcomes = [
      { label: 'NXDOMAIN', flags: 3, answers: [], code: VerificationCode.RecordNotFound, transient: false },
      { label: 'NODATA', flags: 0, answers: [], code: VerificationCode.RecordNotFound, transient: false },
      { label: 'multiple', flags: 0, answers: [txt(name, 60, 'first'), txt(name, 60, 'second')], code: VerificationCode.RecordInvalid, transient: false },
      { label: 'malformed', flags: 0, answers: [txt(name, 60, 'not a DNSid record')], code: VerificationCode.RecordInvalid, transient: false },
      { label: 'SERVFAIL', flags: 2, answers: [], code: VerificationCode.DNSResolution, transient: true },
    ];
    for (const outcome of outcomes) {
      const answer = (q: packet.Packet) => reply(q, outcome.answers, outcome.flags);
      const fake = await server(transport === 'configured TCP' ? q => reply(q, [], packet.TRUNCATED_RESPONSE) : answer, answer);
      const address = `127.0.0.1:${fake.port}`;
      vi.mocked(dns.getServers).mockReturnValue([address]);
      // The default resolver checks native/scoped DNS after an empty wire response or failure.
      vi.mocked(dns.resolveTxt).mockRejectedValue(Object.assign(new Error(outcome.label), {
        code: outcome.flags === 2 ? 'ESERVFAIL' : outcome.flags === 3 ? 'ENOTFOUND' : 'ENODATA',
      }));
      const resolver = transport === 'default wire' ? createDefaultDnsResolver({}) : createDefaultDnsResolver({ dnsServer: address });
      try {
        if (outcome.code === VerificationCode.RecordNotFound) {
          await expect(resolver.fetchTXT(name)).resolves.toEqual([[], DNSSECState.UNKNOWN]);
        }
        const manager = new IdentityManager({}, { dnsResolver: resolver });
        await expect(manager.verifyDomain('example.com'), outcome.label).rejects.toMatchObject({ code: outcome.code, transient: outcome.transient });
        if (outcome.code === VerificationCode.RecordNotFound) {
          for (const dnssecMode of [DNSSECMode.validated, DNSSECMode.required]) {
            const strict = new IdentityManager({ verification: { dnssecMode } }, { dnsResolver: resolver });
            await expect(strict.verifyDomain('example.com')).rejects.toMatchObject({ code: VerificationCode.DNSSECFailed, transient: false });
          }
        }
      } finally { await fake.close(); }
    }
  },
);

it('classifies a configured DNS timeout as transient DNSResolution', async () => {
  const fake = await server(() => undefined);
  try {
    const manager = new IdentityManager({}, { dnsResolver: createDnsResolverFromServer(`127.0.0.1:${fake.port}`) });
    await expect(manager.verifyDomain('example.com')).rejects.toMatchObject({ code: VerificationCode.DNSResolution, transient: true });
  } finally { await fake.close(); }
});

it('rejects an invalid configured server port before any lookup', () => {
  expect(() => createDnsResolverFromServer('127.0.0.1:0')).toThrow(ArgumentError);
});

it('returns remaining TXT TTLs, preserving record and chunk boundaries', async () => {
  const fake = await server(q => reply(q, [txt(name, 90, 'first', 'chunk'), txt(name, 60, 'other')]));
  try {
    await expect(createDnsResolverFromServer(`127.0.0.1:${fake.port}`).fetchTXT(name)).resolves.toEqual([
      [{ strings: ['first', 'chunk'], ttl: 60 }, { strings: ['other'], ttl: 60 }], DNSSECState.UNKNOWN,
    ]);
  } finally { await fake.close(); }
});

it('lets the SDK cache a verified identity until the remaining TTL expires', async () => {
  const domain = 'agent.example.com';
  const pair = generateKeyPairSync('ed25519');
  const key = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'op', alg: 'EdDSA' } as DnsIdJWK;
  const fixture = await currentProfileFixture(domain, key);
  const raw = fixture.record.serialize();
  const strings = raw.match(/.{1,200}/g)!;
  let queries = 0;
  const fake = await server(q => { queries++; return reply(q, [txt(`_dnsid.${domain}`, 120, ...strings)]); });
  vi.mocked(dns.getServers).mockReturnValue([`127.0.0.1:${fake.port}`]);
  try {
    const manager = new IdentityManager({ verification: { statusCheckInterval: 30 } }, {
      logRegistry: fixture.logRegistry, fetchJson: fixture.fetchJson,
      dnsResolver: createDefaultDnsResolver({}), cache: new InMemoryIdentityCache(),
    });
    const first = await manager.verifyDomain(domain);
    const second = await manager.verifyDomain(domain);
    expect(first.dnsTTL).toBe(120);
    expect(second).toBe(first);
    expect(queries).toBe(1);
  } finally { await fake.close(); }
});

it('fails over between system DNS servers in order without a public default', async () => {
  const failing = await server(q => reply(q, [], 2)); // SERVFAIL
  const working = await server(q => reply(q, [txt(name, 42, 'found')]));
  vi.mocked(dns.getServers).mockReturnValue([`127.0.0.1:${failing.port}`, `127.0.0.1:${working.port}`]);
  try {
    await expect(createDefaultDnsResolver({}).fetchTXT(name)).resolves.toEqual([
      [{ strings: ['found'], ttl: 42 }], DNSSECState.UNKNOWN,
    ]);
  } finally { await failing.close(); await working.close(); }
});

it.each([2, 3])('falls back to native TXT with TTL 0 after wire error code %i', async code => {
  const fake = await server(q => reply(q, [], code));
  vi.mocked(dns.getServers).mockReturnValue([`127.0.0.1:${fake.port}`]);
  vi.mocked(dns.resolveTxt).mockResolvedValue([['native']]);
  try {
    await expect(createDefaultDnsResolver({}).fetchTXT(name)).resolves.toEqual([
      [{ strings: ['native'], ttl: 0 }], DNSSECState.UNKNOWN,
    ]);
    expect(dns.resolveTxt).toHaveBeenCalledWith(name);
  } finally { await fake.close(); }
});

it('retries truncation over TCP, follows CNAMEs, and uses the minimum TTL', async () => {
  const alias = '_dnsid.other.example.com';
  const fake = await server(q => reply(q, [], packet.TRUNCATED_RESPONSE), q => reply(q, [
    { type: 'CNAME', name, class: 'IN', ttl: 15, data: alias }, txt(alias, 45, 'value'),
  ]));
  try {
    await expect(createDnsResolverFromServer(`127.0.0.1:${fake.port}`).fetchTXT(name)).resolves.toEqual([
      [{ strings: ['value'], ttl: 15 }], DNSSECState.UNKNOWN,
    ]);
  } finally { await fake.close(); }
});

it('rejects a TCP connection closed before its reply', async () => {
  const fake = await server(q => reply(q, [], packet.TRUNCATED_RESPONSE));
  try {
    await expect(createDnsResolverFromServer(`127.0.0.1:${fake.port}`).fetchTXT(name)).rejects.toThrow('invalid DNS TXT response');
  } finally { await fake.close(); }
});

it('queries a CNAME target omitted from the answer and keeps the alias TTL', async () => {
  const alias = '_dnsid.other.example.com';
  const fake = await server(q => q.questions![0]!.name === name
    ? reply(q, [{ type: 'CNAME', name, class: 'IN', ttl: 9, data: alias }])
    : reply(q, [txt(alias, 100, 'target')]));
  try {
    await expect(createDnsResolverFromServer(`127.0.0.1:${fake.port}`).fetchTXT(name)).resolves.toEqual([
      [{ strings: ['target'], ttl: 9 }], DNSSECState.UNKNOWN,
    ]);
  } finally { await fake.close(); }
});

it('rejects spoofed replies and aborts unanswered queries', async () => {
  const fake = await server(q => reply({ ...q, id: (q.id! + 1) % 65536 }, [txt(name, 120, 'spoof')]));
  try {
    const controller = new AbortController();
    const result = createDnsResolverFromServer(`127.0.0.1:${fake.port}`).fetchTXT(name, { signal: controller.signal });
    setTimeout(() => controller.abort(new Error('cancelled')), 30);
    await expect(result).rejects.toThrow('cancelled');
  } finally { await fake.close(); }
});

it('treats invalid high-bit TTL as zero and does not mistake SERVFAIL for DNSSEC failure', async () => {
  const fake = await server(q => reply(q, [txt(name, 0x80000000, 'value')]));
  try {
    await expect(createDnsResolverFromServer(`127.0.0.1:${fake.port}`).fetchTXT(name)).resolves.toEqual([
      [{ strings: ['value'], ttl: 0 }], DNSSECState.UNKNOWN,
    ]);
  } finally { await fake.close(); }
  const missing = await server(q => reply(q, [], 3));
  try {
    await expect(createDnsResolverFromServer(`127.0.0.1:${missing.port}`).fetchTXT(name)).resolves.toEqual([[], DNSSECState.UNKNOWN]);
  } finally { await missing.close(); }
  const failing = await server(q => reply(q, [], 2));
  try {
    await expect(createDnsResolverFromServer(`127.0.0.1:${failing.port}`).fetchTXT(name)).rejects.toThrow('SERVFAIL');
  } finally { await failing.close(); }
});
