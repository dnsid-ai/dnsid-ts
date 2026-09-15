import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';

/**
 * Mints a self-signed P-256 certificate for a hostname without shelling out
 * or adding a dependency: Node can sign and export keys but has no X.509
 * builder, so the handful of DER structures a certificate needs are encoded
 * here. Test use only.
 */
export function generateSelfSignedCert(hostname: string): { key: string; cert: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const now = Date.now();
  const tbs = sequence(
    explicit(0, integer(Buffer.from([2]))), // v3
    integer(serial()),
    ecdsaWithSha256(),
    name(hostname),
    sequence(utcTime(new Date(now - 86_400_000)), utcTime(new Date(now + 86_400_000))),
    name(hostname),
    publicKey.export({ type: 'spki', format: 'der' }),
    explicit(3, sequence(sequence(
      oid('2.5.29.17'), // subjectAltName
      octetString(sequence(tagged(2, Buffer.from(hostname, 'ascii')))), // dNSName
    ))),
  );
  const signature = sign('sha256', tbs, { key: privateKey, dsaEncoding: 'der' });
  const cert = sequence(tbs, ecdsaWithSha256(), bitString(signature));
  return {
    key: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    cert: pem('CERTIFICATE', cert),
  };
}

const ecdsaWithSha256 = (): Buffer => sequence(oid('1.2.840.10045.4.3.2'));

function serial(): Buffer {
  // Positive and without a leading zero, as DER's minimal INTEGER encoding requires.
  const bytes = randomBytes(16);
  bytes[0] = (bytes[0]! & 0x7f) | 0x40;
  return bytes;
}

function name(commonName: string): Buffer {
  return sequence(set(sequence(oid('2.5.4.3'), tlv(0x0c, Buffer.from(commonName, 'utf8')))));
}

function tlv(tag: number, body: Buffer): Buffer {
  const len = body.length;
  const header = len < 0x80
    ? Buffer.from([tag, len])
    : len < 0x100
      ? Buffer.from([tag, 0x81, len])
      : Buffer.from([tag, 0x82, len >> 8, len & 0xff]);
  return Buffer.concat([header, body]);
}

const sequence = (...parts: Buffer[]): Buffer => tlv(0x30, Buffer.concat(parts));
const set = (...parts: Buffer[]): Buffer => tlv(0x31, Buffer.concat(parts));
const explicit = (n: number, body: Buffer): Buffer => tlv(0xa0 | n, body);
const tagged = (n: number, body: Buffer): Buffer => tlv(0x80 | n, body);
const octetString = (body: Buffer): Buffer => tlv(0x04, body);
const bitString = (body: Buffer): Buffer => tlv(0x03, Buffer.concat([Buffer.from([0]), body]));

function integer(magnitude: Buffer): Buffer {
  // Prepend a zero when the high bit is set so the value stays positive.
  return tlv(0x02, magnitude[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), magnitude]) : magnitude);
}

function oid(dotted: string): Buffer {
  const [first, second, ...rest] = dotted.split('.').map(Number) as [number, number, ...number[]];
  const bytes = [first * 40 + second];
  for (const arc of rest) {
    const chunk: number[] = [arc & 0x7f];
    for (let v = arc >> 7; v > 0; v >>= 7) chunk.unshift((v & 0x7f) | 0x80);
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}

function utcTime(date: Date): Buffer {
  const s = date.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z'; // YYMMDDHHMMSSZ
  return tlv(0x17, Buffer.from(s, 'ascii'));
}

function pem(label: string, der: Buffer): string {
  const body = der.toString('base64').match(/.{1,64}/g)!.join('\n');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}
