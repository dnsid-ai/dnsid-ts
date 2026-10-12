import { describe, it, expect } from 'vitest';
import {
  DEFAULT_PUBLISH_PROFILE,
  DNSID_DRAFT01_VERSION,
  DNSID_VERSION,
  DnsIdTxtRecord,
  ParseError,
  SUPPORTED_PUBLISH_PROFILES,
  SUPPORTED_VALIDATION_PROFILES,
  ValidationError,
} from '@dnsid-ai/protocol';

const selectors = [DNSID_DRAFT01_VERSION, DNSID_VERSION] as const;

function raw(v: string, sg = 'dGVzdA'): string {
  return `v=${v};gi=example.com;ek=https://keys.example.com/entity.json;` +
    `ku=https://agent.example.com/jwks.json;lr=microledger:abc;` +
    `su=https://agent.example.com/status;sg=${sg}`;
}

function record(v = DNSID_DRAFT01_VERSION): DnsIdTxtRecord {
  const r = DnsIdTxtRecord.parse(raw(v));
  r.agentFQDN = 'agent.example.com';
  return r;
}

describe('DNSid version profiles', () => {
  it('publishes only the immutable submitted draft selector', () => {
    expect(DEFAULT_PUBLISH_PROFILE).toBe('dnsid-draft-01');
    expect(SUPPORTED_PUBLISH_PROFILES).toEqual(['dnsid-draft-01']);
    expect(SUPPORTED_VALIDATION_PROFILES).toEqual(['dnsid-draft-01', 'DNSid1']);
  });

  it.each(selectors)('parses and preserves %s without rewriting it', v => {
    const r = DnsIdTxtRecord.parse(raw(v));
    expect(r.v).toBe(v);
    expect(r.serialize()).toBe(raw(v));
    expect(r.canonical()).toContain(`v=${v}`);
  });

  it.each([
    'draft-dnsid-01',
    'dnsid-draft-00',
    'dnsid-draft01',
    'dnsid-draft-01-20260504',
    'dnsid-draft-01-20260527',
    'dnsid-draft-01-20260626',
    'dnsid-draft-02',
  ])('rejects unsupported selector %s', v => {
    expect(() => DnsIdTxtRecord.parse(raw(v))).toThrow(ParseError);
  });

  it.each(selectors)('%s uses the same submitted draft-01 behavior', v => {
    const r = record(v);
    expect(() => r.validate()).not.toThrow();
    expect(r.signatureVerificationKeyURI()).toBe('https://keys.example.com/entity.json');
    expect(r.signatureVerificationKeyAllowedHost()).toBe('example.com');
    expect(r.runtimeKeyURI()).toBe('https://agent.example.com/jwks.json');
    expect(r.runtimeKeyAllowedHost()).toBe('agent.example.com');
    expect(r.canonical().split(';').map(p => p.split('=')[0])).toEqual(['ek', 'gi', 'ku', 'lr', 'su', 'v']);
  });

  it('requires the complete two-key draft-01 tag set', () => {
    expect(() => DnsIdTxtRecord.parse(raw(DNSID_DRAFT01_VERSION).replace(/;ek=[^;]+/, '')))
      .toThrow(/required TXT tag: ek/);
  });

  it('preserves obsolete profile tags as unknown signed extensions', () => {
    const r = DnsIdTxtRecord.parse(`${raw(DNSID_DRAFT01_VERSION)};oi=example.com`);
    expect(r.unknownTags.get('oi')).toBe('example.com');
    expect(r.canonical()).toContain('oi=example.com');
    expect(r.serialize()).toContain('oi=example.com');
  });
});

describe('DnsIdTxtRecord wire handling', () => {
  it('requires v first and rejects duplicate tags', () => {
    expect(() => DnsIdTxtRecord.parse(raw(DNSID_VERSION).replace(/^v=[^;]+;/, '') + ';v=DNSid1')).toThrow(/v= tag must be first/);
    expect(() => DnsIdTxtRecord.parse(raw(DNSID_VERSION) + ';gi=other.example')).toThrow(/duplicate TXT tag/);
  });

  it('does not invent a profile when serializing an unset record', () => {
    expect(new DnsIdTxtRecord().serialize()).toBe('v=');
  });

  it('preserves unknown tags in signatures and serialization', () => {
    const r = DnsIdTxtRecord.parse(raw(DNSID_DRAFT01_VERSION) + ';exp=999');
    expect(r.unknownTags.get('exp')).toBe('999');
    expect(r.canonical()).toContain('exp=999');
    expect(r.knownTagsCanonical()).not.toContain('exp=');
    expect(r.serialize()).toContain('exp=999');
  });

  it.each(selectors)('preserves parsed empty optional tags in %s signature input and round trips', v => {
    const r = DnsIdTxtRecord.parse(raw(v) + ';fl=;ka=;cu=;zz=');
    r.agentFQDN = 'agent.example.com';
    expect([r.fl, r.ka, r.cu]).toEqual([undefined, undefined, undefined]);
    expect(() => r.validate()).not.toThrow();
    const canonical = `cu=;ek=https://keys.example.com/entity.json;fl=;gi=example.com;ka=;` +
      `ku=https://agent.example.com/jwks.json;lr=microledger:abc;su=https://agent.example.com/status;v=${v};zz=`;
    expect(r.canonical()).toBe(canonical);
    expect(r.knownTagsCanonical()).toBe(canonical.replace(';zz=', ''));
    expect(r.serialize()).toBe(raw(v) + ';fl=;ka=;cu=;zz=');
    expect(DnsIdTxtRecord.parse(r.serialize()).canonical()).toBe(canonical);
    expect(DnsIdTxtRecord.parseUnsignedCanonical(canonical, r.agentFQDN).canonical()).toBe(canonical);
  });

  it('omits unset optional tags from SDK-created records', () => {
    const r = new DnsIdTxtRecord();
    Object.assign(r, { v: DNSID_DRAFT01_VERSION, gi: 'example.com', ek: 'https://keys.example.com/entity.json',
      ku: 'https://agent.example.com/jwks.json', lr: 'microledger:abc', su: 'https://agent.example.com/status', sg: 'dGVzdA' });
    expect(r.serialize()).toBe(raw(DNSID_DRAFT01_VERSION));
    expect(r.canonical()).toBe(record().canonical());
    r.fl = r.ka = r.cu = '';
    expect(r.serialize()).toBe(raw(DNSID_DRAFT01_VERSION));
    expect(r.canonical()).toBe(record().canonical());
  });

  it('uses current typed values for parsed optional tags', () => {
    const r = DnsIdTxtRecord.parse(raw(DNSID_DRAFT01_VERSION) + ';fl=;ka=;cu=');
    r.fl = 'mtls';
    r.ka = '24h';
    r.cu = 'https://agent.example.com/agents.md';
    expect(r.serialize()).toBe(raw(DNSID_DRAFT01_VERSION) + ';fl=mtls;ka=24h;cu=https://agent.example.com/agents.md');
    expect(r.canonical()).toContain('cu=https://agent.example.com/agents.md;');
    expect(r.canonical()).toContain(';fl=mtls;gi=example.com;ka=24h;');
    r.ka = 'invalid';
    r.agentFQDN = 'agent.example.com';
    expect(() => r.validate()).toThrow(/ka must be one of/);
  });

  it('parses only alphabetically ordered unsigned canonical content', () => {
    const canonical = record().canonical();
    expect(DnsIdTxtRecord.parseUnsignedCanonical(canonical, 'agent.example.com').canonical()).toBe(canonical);
    expect(() => DnsIdTxtRecord.parseUnsignedCanonical(`v=${DNSID_DRAFT01_VERSION};` + canonical.replace(`;v=${DNSID_DRAFT01_VERSION}`, '')))
      .toThrow(/not in canonical form/);
  });

  it('validates hosts, key age, and log reference', () => {
    const r = record();
    r.ku = 'https://other.example.com/jwks.json';
    expect(() => r.validate()).toThrow(ValidationError);
    r.ku = 'https://agent.example.com/jwks.json';
    r.ka = '1d' as '24h';
    expect(() => r.validate()).toThrow(/ka must be one of/);
    r.ka = undefined;
    r.lr = 'invalid';
    expect(() => r.validate()).toThrow(/malformed lr/);
  });

  it('parses policy flags', () => {
    const r = record();
    r.fl = 'mtls, logchk,,mtls';
    expect(r.policyFlags()).toEqual(new Set(['mtls', 'logchk']));
  });
});
