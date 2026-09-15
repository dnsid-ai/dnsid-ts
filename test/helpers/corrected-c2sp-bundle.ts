import { createHash, createPrivateKey, sign } from 'node:crypto';

/** Independently regenerates the two-entry test bundle, not production submissions. */
export function correctedBundle(historical: string): string {
  const bundle = JSON.parse(historical);
  const entries = bundle.events.map((item: { entry: string }) => JSON.parse(Buffer.from(item.entry, 'base64url').toString()));
  const { sigs: _issuanceSignatures, ...issuancePayload } = entries[0];
  delete entries[1].prev_index;
  delete entries[1].prev_leaf_hash;
  entries[1].prev_event_id = hash(Buffer.from('dnsid-c2sp-event-v1\0'), canonical(issuancePayload)).toString('base64url');
  const { sigs, ...rotationPayload } = entries[1];
  sigs.prev_op.sig = signature(2, canonical(rotationPayload)).toString('base64url');
  sigs.new_op.sig = signature(3, canonical(rotationPayload)).toString('base64url');
  const bytes = entries.map(canonical);
  const leaves = bytes.map((entry: Buffer) => hash(Buffer.from([0]), entry));
  const root = hash(Buffer.from([1]), ...leaves).toString('base64');
  bundle.events.forEach((item: { entry: string; proof: string }, index: number) => {
    item.entry = bytes[index].toString('base64url');
    item.proof = leaves[1 - index].toString('base64url');
  });
  const oldCheckpoint = Buffer.from(bundle.checkpoint, 'base64url').toString();
  const lines = oldCheckpoint.split('\n');
  const logKeyId = Buffer.from(lines[4].split(' ')[2], 'base64').subarray(0, 4);
  const witness = Buffer.from(lines[5].split(' ')[2], 'base64');
  const timestamp = witness.readBigUInt64BE(4);
  const body = `log.example\n2\n${root}\n`;
  const checkpoint = `${body}\n— log.example ${Buffer.concat([logKeyId, signature(4, Buffer.from(body))]).toString('base64')}\n— witness.example ${Buffer.concat([witness.subarray(0, 12), signature(5, Buffer.from(`cosignature/v1\ntime ${timestamp}\n${body}`))]).toString('base64')}\n`;
  bundle.checkpoint = Buffer.from(checkpoint).toString('base64url');
  const { sig, ...unsigned } = bundle;
  sig.value = signature(6, canonical(unsigned)).toString('base64url');
  return canonical(bundle).toString();
}

function signature(seed: number, bytes: Buffer): Buffer {
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seed)]), format: 'der', type: 'pkcs8' });
  return sign(null, bytes, key);
}
function hash(...bytes: Buffer[]): Buffer {
  const digest = createHash('sha256');
  bytes.forEach(part => digest.update(part));
  return digest.digest();
}
// This fixture contains only ASCII strings and safe integers.
function canonical(value: unknown): Buffer {
  if (Array.isArray(value)) return Buffer.from(`[${value.map(item => canonical(item).toString()).join(',')}]`);
  if (value && typeof value === 'object') return Buffer.from(`{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, child]) => `${JSON.stringify(key)}:${canonical(child)}`).join(',')}}`);
  return Buffer.from(JSON.stringify(value));
}
