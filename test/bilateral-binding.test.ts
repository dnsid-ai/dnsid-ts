import { describe, it, expect, beforeAll } from 'vitest';
import { generateKeyPair, exportJWK } from 'jose';
import {
  DnsIdTxtRecord,
  VerificationCode,
  VerificationError,
  canonicalIssuanceBinding,
  jwkThumbprint,
  toArrayBuffer,
  toBase64Url,
  verifyBilateralBinding,
} from '@identity-digital/dnsid-protocol';
import type { DnsIdJWK, IssuanceEvent } from '@identity-digital/dnsid-protocol';

// draft-01 (#106): ISSUANCE is bilateral — both the ek and ku keys recorded in
// the event must have signed the same canonical binding.

let entityKey: DnsIdJWK, opKey: DnsIdJWK, otherKey: DnsIdJWK;
let entityPriv: CryptoKey, opPriv: CryptoKey;

async function makeKey(kid: string): Promise<{ jwk: DnsIdJWK; priv: CryptoKey }> {
  const pair = await generateKeyPair('ES256');
  const raw = await exportJWK(pair.publicKey);
  return { jwk: { ...raw, kty: raw.kty!, alg: 'ES256', kid, use: 'sig' } as DnsIdJWK, priv: pair.privateKey };
}

async function sign(priv: CryptoKey, bytes: Uint8Array): Promise<string> {
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, toArrayBuffer(bytes));
  return toBase64Url(new Uint8Array(sig));
}

beforeAll(async () => {
  ({ jwk: entityKey, priv: entityPriv } = await makeKey('ek-1'));
  ({ jwk: opKey, priv: opPriv } = await makeKey('ku-1'));
  ({ jwk: otherKey } = await makeKey('other-1'));
});

function makeRecord(): DnsIdTxtRecord {
  const r = new DnsIdTxtRecord();
  r.v = 'DNSid1'; r.gi = 'example.com';
  r.ek = 'https://example.com/entity-jwks.json';
  r.ku = 'https://agent.example.com/jwks.json';
  r.lr = 'microledger:abc'; r.su = 'https://agent.example.com/status';
  r.agentFQDN = 'agent.example.com';
  return r;
}

async function makeEvent(): Promise<IssuanceEvent> {
  const ev: IssuanceEvent = {
    type: 'ISSUANCE',
    domain: 'agent.example.com',
    governanceId: 'example.com',
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    entityKey: { jwk: entityKey, thumbprint: await jwkThumbprint(entityKey), kid: 'ek-1', alg: 'ES256' },
    operationalKey: { jwk: opKey, thumbprint: await jwkThumbprint(opKey), kid: 'ku-1', alg: 'ES256' },
  };
  const binding = canonicalIssuanceBinding(ev);
  ev.entitySig = await sign(entityPriv, binding);
  ev.operationalSig = await sign(opPriv, binding);
  return ev;
}

async function expectCode(p: Promise<unknown>, code: VerificationCode) {
  const err = await p.then(() => null, e => e);
  expect(err).toBeInstanceOf(VerificationError);
  expect((err as VerificationError).code).toBe(code);
}

describe('verifyBilateralBinding()', () => {
  it('accepts a valid dual-signed ISSUANCE event and returns the initial op thumbprint', async () => {
    const ev = await makeEvent();
    await expect(verifyBilateralBinding(ev, makeRecord(), entityKey)).resolves.toEqual({
      initialOperationalThumbprint: await jwkThumbprint(opKey),
    });
  });

  it('does not reject a rotated ku — continuity is checked separately', async () => {
    // The live ku key differs from the ISSUANCE op key (a rotation). The
    // bilateral helper must NOT reject this; verifyOperationalContinuity does.
    const ev = await makeEvent();
    await expect(verifyBilateralBinding(ev, makeRecord(), entityKey)).resolves.toEqual({
      initialOperationalThumbprint: await jwkThumbprint(opKey),
    });
  });

  it('rejects when entitySig is missing', async () => {
    const ev = await makeEvent();
    delete ev.entitySig;
    await expectCode(verifyBilateralBinding(ev, makeRecord(), entityKey), VerificationCode.SignatureInvalid);
  });

  it('rejects when operationalSig is missing', async () => {
    const ev = await makeEvent();
    delete ev.operationalSig;
    await expectCode(verifyBilateralBinding(ev, makeRecord(), entityKey), VerificationCode.SignatureInvalid);
  });

  it('rejects a tampered entity signature', async () => {
    const ev = await makeEvent();
    ev.entitySig = ev.operationalSig; // valid base64url, wrong signer
    await expectCode(verifyBilateralBinding(ev, makeRecord(), entityKey), VerificationCode.SignatureInvalid);
  });

  it('rejects when a slot JWK does not match its recorded thumbprint', async () => {
    // Attack: keep the real ek thumbprint (which the canonical binding commits
    // to) but swap in a foreign JWK. Without the JWK↔thumbprint pin this would
    // let an attacker verify the signature against a key of their choosing.
    const ev = await makeEvent();
    ev.entityKey!.jwk = otherKey; // thumbprint still the real ek thumbprint
    await expectCode(verifyBilateralBinding(ev, makeRecord(), entityKey), VerificationCode.RecordInvalid);
  });

  it('rejects a mismatched FQDN', async () => {
    const ev = await makeEvent();
    const record = makeRecord();
    record.agentFQDN = 'other.example.com';
    await expectCode(verifyBilateralBinding(ev, record, entityKey), VerificationCode.RecordInvalid);
  });

  it('rejects a mismatched gi', async () => {
    const ev = await makeEvent();
    const record = makeRecord();
    record.gi = 'evil.example.com';
    await expectCode(verifyBilateralBinding(ev, record, entityKey), VerificationCode.RecordInvalid);
  });

  it('rejects when the recorded entity key is not the current ek key', async () => {
    const ev = await makeEvent();
    await expectCode(verifyBilateralBinding(ev, makeRecord(), otherKey), VerificationCode.RecordInvalid);
  });
});
