import { randomInt } from 'node:crypto';
import * as dgram from 'node:dgram';
import * as net from 'node:net';
import packet from 'dns-packet';
import { DNSSECState, type TXTRecord } from '@dnsid-ai/protocol';

type WirePacket = packet.DecodedPacket & { opcode: string; rcode: string }; // decoded fields missing from @types/dns-packet
const normalize = (name: string) => name.replace(/\.$/, '').toLowerCase();
const badResponse = () => new Error('invalid DNS TXT response');
const remainingTtl = (ttl: number | undefined) =>
  ttl !== undefined && Number.isInteger(ttl) && ttl >= 0 && ttl <= 0x7fffffff ? ttl : 0;

/** Query a configured recursive server for TXT records with their remaining wire TTLs. */
export async function resolveTxtWithTtl(name: string, host: string, port: number, signal?: AbortSignal): Promise<[TXTRecord[], DNSSECState]> {
  const deadline = AbortSignal.any([signal ?? new AbortController().signal, AbortSignal.timeout(2000)]);
  let owner = normalize(name);
  const seen = new Set([owner]);
  let hops = 0;
  let ttl = Infinity;
  while (true) {
    deadline.throwIfAborted();
    const queried = owner;
    const response = await query(owner, host, port, deadline);
    if (response.rcode === 'NXDOMAIN') return [[], DNSSECState.UNKNOWN];
    // SERVFAIL can be an ordinary upstream failure; it does not prove DNSSEC validation failed.
    if (response.rcode !== 'NOERROR') throw new Error(`DNS query failed: ${response.rcode}`);

    const answers = response.answers ?? [];
    // A recursive resolver can include part or all of the CNAME chain in a single answer.
    while (true) {
      const cnames = answers.filter(a => a.type === 'CNAME' && normalize(a.name) === owner && a.class === 'IN') as packet.StringAnswer[];
      if (!cnames.length) break;
      if (cnames.length !== 1 || ++hops > 8) throw badResponse();
      const cname = cnames[0]!;
      if (typeof cname.data !== 'string') throw badResponse();
      ttl = Math.min(ttl, remainingTtl(cname.ttl));
      owner = normalize(cname.data);
      if (seen.has(owner)) throw badResponse();
      seen.add(owner);
    }
    const txt = answers.filter(a => a.type === 'TXT' && normalize(a.name) === owner && a.class === 'IN') as packet.TxtAnswer[];
    if (txt.length) {
      ttl = Math.min(ttl, ...txt.map(a => remainingTtl(a.ttl)));
      const decoder = new TextDecoder('utf-8', { fatal: true });
      return [txt.map(a => {
        if (!Array.isArray(a.data) || !a.data.every(Buffer.isBuffer)) throw badResponse();
        return { strings: a.data.map(part => decoder.decode(part)), ttl: Math.min(ttl, 86400) };
      }), DNSSECState.UNKNOWN];
    }
    if (owner === queried) return [[], DNSSECState.UNKNOWN];
    // CNAME without an in-answer TXT: resolve the target, retaining the CNAME TTL.
  }
}

async function query(name: string, host: string, port: number, signal: AbortSignal): Promise<WirePacket> {
  const id = randomInt(65536);
  const request: packet.Packet = { type: 'query', id, flags: packet.RECURSION_DESIRED,
    questions: [{ type: 'TXT', class: 'IN', name }],
    additionals: [{ type: 'OPT', name: '.', udpPayloadSize: 1232 } as packet.OptAnswer] };
  const valid = (data: Buffer): WirePacket | null => {
    try {
      const response = packet.decode(data) as WirePacket;
      if (packet.decode.bytes > data.length || response.type !== 'response' || response.id !== id ||
          response.opcode !== 'QUERY' || response.questions?.length !== 1 ||
          response.questions[0]!.type !== 'TXT' || response.questions[0]!.class !== 'IN' ||
          normalize(response.questions[0]!.name) !== name) return null;
      return response;
    } catch { return null; }
  };
  const response = await udp(packet.encode(request), host, port, signal, valid);
  if (!response.flag_tc) return response;
  const tcpResponse = valid(await tcp(packet.streamEncode(request), host, port, signal));
  if (!tcpResponse || tcpResponse.flag_tc) throw badResponse();
  return tcpResponse;
}

function udp(buf: Buffer, host: string, port: number, signal: AbortSignal,
  valid: (data: Buffer) => WirePacket | null): Promise<WirePacket> {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket(net.isIP(host) === 6 ? 'udp6' : 'udp4');
    let finished = false;
    const done = (error?: unknown, response?: WirePacket) => {
      if (finished) return;
      finished = true;
      signal.removeEventListener('abort', onAbort);
      sock.close();
      if (error) reject(error);
      else resolve(response!);
    };
    const onAbort = () => done(signal.reason ?? new Error('DNS query aborted'));
    signal.addEventListener('abort', onAbort, { once: true });
    sock.on('error', done);
    sock.on('message', data => { const response = valid(data); if (response) done(undefined, response); });
    if (signal.aborted) return onAbort();
    // Connected UDP sockets only receive responses from the configured server.
    sock.connect(port, host, () => { if (!finished) sock.send(buf); });
  });
}

function tcp(buf: Buffer, host: string, port: number, signal: AbortSignal): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port });
    let data = Buffer.alloc(0);
    let finished = false;
    const done = (error?: unknown, response?: Buffer) => {
      if (finished) return;
      finished = true;
      signal.removeEventListener('abort', onAbort);
      sock.destroy();
      if (error) reject(error);
      else resolve(response!);
    };
    const onAbort = () => done(signal.reason ?? new Error('DNS query aborted'));
    signal.addEventListener('abort', onAbort, { once: true });
    sock.on('error', done);
    sock.on('end', () => done(badResponse()));
    sock.on('connect', () => sock.write(buf));
    sock.on('data', chunk => {
      if (!Buffer.isBuffer(chunk) || data.length + chunk.length > 65537) return done(badResponse());
      data = Buffer.concat([data, chunk]);
      if (data.length >= 2 && data.length >= data.readUInt16BE(0) + 2) {
        if (data.length !== data.readUInt16BE(0) + 2) return done(badResponse());
        done(undefined, data.subarray(2));
      }
    });
    if (signal.aborted) onAbort();
  });
}
