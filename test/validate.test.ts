import { describe, it, expect } from 'vitest';
import { DnsIdTxtRecord, ValidationError } from '@dnsid-ai/protocol';

// ---- helpers ----

function makeRecord(overrides: Partial<{
  gi: string; ek: string; ku: string; su: string; cu: string; ka: string; agentFQDN: string;
}> = {}): DnsIdTxtRecord {
  const r = new DnsIdTxtRecord();
  r.v = 'DNSid1';
  r.gi = overrides.gi ?? 'example.com';
  r.ek = overrides.ek ?? `https://${r.gi}/entity-jwks.json`;
  r.ku = overrides.ku ?? 'https://agent.example.com/.well-known/jwks.json';
  r.lr = 'microledger:abc123';
  r.su = overrides.su ?? 'https://agent.example.com/status';
  r.sg = 'dummysig';
  r.agentFQDN = overrides.agentFQDN ?? 'agent.example.com';
  if (overrides.cu !== undefined) r.cu = overrides.cu;
  if (overrides.ka !== undefined) r.ka = overrides.ka;
  return r;
}

// ---- gi hierarchy ----

describe('DnsIdTxtRecord.validate() — gi hierarchy', () => {
  it('recognizes agentFQDN equal to gi as a structural relationship', () => {
    const r = makeRecord({ gi: 'agent.example.com', agentFQDN: 'agent.example.com' });
    expect(() => r.validate()).not.toThrow();
    expect(r.hasStructuralGovernanceRelationship()).toBe(true);
  });

  it('recognizes a direct subdomain of gi as a structural relationship', () => {
    const r = makeRecord({ gi: 'example.com', agentFQDN: 'agent.example.com' });
    expect(() => r.validate()).not.toThrow();
    expect(r.hasStructuralGovernanceRelationship()).toBe(true);
  });

  it('recognizes a deep subdomain of gi as a structural relationship', () => {
    const r = makeRecord({
      gi: 'example.com',
      agentFQDN: 'billing.agents.example.com',
      ku: 'https://billing.agents.example.com/.well-known/jwks.json',
      su: 'https://billing.agents.example.com/status',
    });
    expect(() => r.validate()).not.toThrow();
    expect(r.hasStructuralGovernanceRelationship()).toBe(true);
  });

  it('classifies an agentFQDN outside gi as delegated pending ISSUANCE evidence', () => {
    const r = makeRecord({ gi: 'other.example', agentFQDN: 'agent.example.com' });
    expect(() => r.validate()).not.toThrow();
    expect(r.hasStructuralGovernanceRelationship()).toBe(false);
  });

  it('classifies parent/sibling FQDN shapes as delegated at TXT validation time', () => {
    const r = makeRecord({ gi: 'sub.example.com', agentFQDN: 'example.com',
      ku: 'https://example.com/.well-known/jwks.json',
      su: 'https://example.com/status',
    });
    expect(() => r.validate()).not.toThrow();
    expect(r.hasStructuralGovernanceRelationship()).toBe(false);
  });

  it('rejects non-domain gi in DNSid1', () => {
    const r = makeRecord({ gi: 'https://registry.example.org/orgs/acme' });
    expect(() => r.validate()).toThrow(ValidationError);
  });
});

// ---- ku validation ----

describe('DnsIdTxtRecord.validate() — ku', () => {
  it('passes when ku host equals agentFQDN', () => {
    const r = makeRecord({ ku: 'https://agent.example.com/.well-known/jwks.json' });
    expect(() => r.validate()).not.toThrow();
  });

  it('passes with a path and query on ku', () => {
    const r = makeRecord({ ku: 'https://agent.example.com/jwks?v=2' });
    expect(() => r.validate()).not.toThrow();
  });

  it('throws ValidationError when ku uses http://', () => {
    const r = makeRecord({ ku: 'http://agent.example.com/.well-known/jwks.json' });
    expect(() => r.validate()).toThrow(ValidationError);
  });

  it('throws ValidationError when ku host differs from agentFQDN', () => {
    const r = makeRecord({ ku: 'https://other.example.com/.well-known/jwks.json' });
    expect(() => r.validate()).toThrow(ValidationError);
  });

  it('throws ValidationError when ku is not a valid URI', () => {
    const r = makeRecord({ ku: 'not a url' });
    expect(() => r.validate()).toThrow(ValidationError);
  });
});

// ---- ek validation ----

describe('DnsIdTxtRecord.validate() — ek host / gi constraint', () => {
  it('passes when ek host equals gi', () => {
    const r = makeRecord({ gi: 'example.com', ek: 'https://example.com/entity-jwks.json' });
    expect(() => r.validate()).not.toThrow();
  });

  it('accepts an ek host below gi', () => {
    const r = makeRecord({ gi: 'example.com', ek: 'https://keys.example.com/entity-jwks.json' });
    expect(() => r.validate()).not.toThrow();
  });

  it('throws when ek host is outside gi', () => {
    const r = makeRecord({ gi: 'example.com', ek: 'https://other.example/entity-jwks.json' });
    expect(() => r.validate()).toThrow(ValidationError);
  });

  it('throws when ek host merely ends with gi as a substring (not a subdomain)', () => {
    const r = makeRecord({ gi: 'example.com', ek: 'https://notexample.test/entity-jwks.json' });
    expect(() => r.validate()).toThrow(ValidationError);
  });

  it('throws when ek uses http://', () => {
    const r = makeRecord({ gi: 'example.com', ek: 'http://example.com/entity-jwks.json' });
    expect(() => r.validate()).toThrow(ValidationError);
  });

  it('constrains the sg-verification fetch to the exact gi host', () => {
    const r = makeRecord({ gi: 'example.com', ek: 'https://example.com/entity-jwks.json' });
    expect(r.signatureVerificationKeyAllowedHost()).toBe('example.com');
  });
});

// ---- su validation ----

describe('DnsIdTxtRecord.validate() — su', () => {
  it('passes when su is a valid HTTPS URL', () => {
    const r = makeRecord({ su: 'https://status.example.com/agent' });
    expect(() => r.validate()).not.toThrow();
  });

  it('throws ValidationError when su uses http://', () => {
    const r = makeRecord({ su: 'http://agent.example.com/status' });
    expect(() => r.validate()).toThrow(ValidationError);
  });

  it('throws ValidationError when su is not a valid URI', () => {
    const r = makeRecord({ su: 'not a url' });
    expect(() => r.validate()).toThrow(ValidationError);
  });
});

// ---- cu validation ----

describe('DnsIdTxtRecord.validate() — cu (optional)', () => {
  it('passes when cu is absent', () => {
    const r = makeRecord();
    expect(() => r.validate()).not.toThrow();
  });

  it('passes when cu is a valid HTTPS URL', () => {
    const r = makeRecord({ cu: 'https://example.com/AGENTS.md' });
    expect(() => r.validate()).not.toThrow();
  });

  it('throws ValidationError when cu uses http://', () => {
    const r = makeRecord({ cu: 'http://example.com/AGENTS.md' });
    expect(() => r.validate()).toThrow(ValidationError);
  });

  it('throws ValidationError when cu is not a valid URI', () => {
    const r = makeRecord({ cu: 'not a url' });
    expect(() => r.validate()).toThrow(ValidationError);
  });
});

// ---- ka validation ----

describe('DnsIdTxtRecord.validate() — ka (optional)', () => {
  it('passes when ka is absent', () => {
    const r = makeRecord();
    expect(() => r.validate()).not.toThrow();
  });

  it.each(['24h', '7d', '30d', '90d'])('passes for ka=%s', (ka) => {
    const r = makeRecord({ ka });
    expect(() => r.validate()).not.toThrow();
  });

  it('throws ValidationError for an invalid ka value', () => {
    const r = makeRecord({ ka: '1d' });
    expect(() => r.validate()).toThrow(ValidationError);
  });

  it('throws ValidationError for ka=48h', () => {
    const r = makeRecord({ ka: '48h' });
    expect(() => r.validate()).toThrow(ValidationError);
  });
});

// ---- lr validation ----

describe('DnsIdTxtRecord.validate() — lr format', () => {
  it('passes for a well-formed lr value', () => {
    const r = makeRecord();
    r.lr = 'microledger:abc123';
    expect(() => r.validate()).not.toThrow();
  });

  it('passes for lr with hyphenated method', () => {
    const r = makeRecord();
    r.lr = 'ct-log:some-ref';
    expect(() => r.validate()).not.toThrow();
  });

  it('throws ValidationError when lr has no colon', () => {
    const r = makeRecord();
    r.lr = 'nocolon';
    expect(() => r.validate()).toThrow(ValidationError);
    expect(() => r.validate()).toThrow(/malformed lr value \(no colon\)/);
  });

  it('throws ValidationError when lr method starts with a digit', () => {
    const r = makeRecord();
    r.lr = '1bad:ref';
    expect(() => r.validate()).toThrow(ValidationError);
    expect(() => r.validate()).toThrow(/malformed lr value \(invalid method\)/);
  });

  it('throws ValidationError when lr method starts with uppercase', () => {
    const r = makeRecord();
    r.lr = 'Bad:ref';
    expect(() => r.validate()).toThrow(ValidationError);
    expect(() => r.validate()).toThrow(/malformed lr value \(invalid method\)/);
  });

  it('throws ValidationError when lr method is empty (colon at start)', () => {
    const r = makeRecord();
    r.lr = ':onlyref';
    expect(() => r.validate()).toThrow(ValidationError);
    expect(() => r.validate()).toThrow(/malformed lr value \(invalid method\)/);
  });

  it('throws ValidationError when lr reference is empty', () => {
    const r = makeRecord();
    r.lr = 'method:';
    expect(() => r.validate()).toThrow(ValidationError);
    expect(() => r.validate()).toThrow(/malformed lr value \(empty reference\)/);
  });

  it('parse accepts malformed lr without throwing', () => {
    // parse should NOT reject malformed lr values; that's validate()'s job
    const raw = 'v=DNSid1;gi=example.com;ek=https://example.com/entity-jwks.json;ku=https://agent.example.com/jwks.json;lr=nocolon;su=https://agent.example.com/status;sg=dGVzdA';
    const r = DnsIdTxtRecord.parse(raw);
    expect(r.lr).toBe('nocolon');
  });
});

// ---- agentFQDN requirement ----

describe('DnsIdTxtRecord.validate() — agentFQDN', () => {
  it('throws when agentFQDN is not set', () => {
    const r = makeRecord();
    r.agentFQDN = '';
    expect(() => r.validate()).toThrow(ValidationError);
  });
});

describe('DnsIdTxtRecord.validate() — lr format', () => {
  it('passes for a well-formed method:entryRef', () => {
    const r = makeRecord();
    r.lr = 'microledger:abc123';
    expect(() => r.validate()).not.toThrow();
  });

  it('throws ValidationError when lr has no separator', () => {
    const r = makeRecord();
    r.lr = 'not-a-log-ref';
    expect(() => r.validate()).toThrow(/malformed lr/);
  });

  it('throws ValidationError when lr has an empty method', () => {
    const r = makeRecord();
    r.lr = ':abc123';
    expect(() => r.validate()).toThrow(ValidationError);
  });

  it('throws ValidationError when the lr method violates [a-z][a-z0-9-]*', () => {
    const r = makeRecord();
    r.lr = 'Micro_Ledger:abc123';
    expect(() => r.validate()).toThrow(ValidationError);
  });
});

// ---- host boundary: canonical comparison ----
//
// These pin the host-boundary checks that bind a record's key endpoints to DNS
// names (ku= equals the agent FQDN, ek= is at or under gi=) to the same
// outcomes as the other DNSid SDKs. Hosts are compared in normalizeFQDN form,
// the exact name the transport resolves and presents as TLS SNI. U+0130 (LATIN
// CAPITAL LETTER I WITH DOT ABOVE) is the probe: a simple case fold maps it to
// ASCII "i", while UTS 46 maps it to "i̇" and punycode-encodes the label
// into a different registrable domain. TXT values are printable ASCII, so it
// reaches a record only percent-encoded, which the URL parser decodes in the
// host; such hosts are rejected outright.

describe('DnsIdTxtRecord.validate() — ku host compared in canonical form', () => {
  const cases: [string, string, string | undefined][] = [
    ['canonical', 'https://agent.example.com/ku.json', undefined],
    ['with port', 'https://agent.example.com:8443/ku.json', undefined],
    ['uppercase', 'https://AGENT.Example.COM/ku.json', undefined],
    ['trailing dot', 'https://agent.example.com./ku.json', 'must not end with a root dot'],
    ['other host', 'https://other.example.com/ku.json', 'must equal agent FQDN'],
    ['parent domain', 'https://example.com/ku.json', 'must equal agent FQDN'],
    ['identity as suffix', 'https://agent.example.com.attacker.example/ku.json', 'must equal agent FQDN'],
    ['percent-encoded U+0130', 'https://agent.%C4%B0xample.com/ku.json', 'without percent-escapes'],
    ['raw U+0130', 'https://agent.İxample.com/ku.json', 'without percent-escapes'],
    ['percent-encoded ASCII', 'https://agent.example%2Ecom/ku.json', 'without percent-escapes'],
    ['leading hyphen label', 'https://-agent.example.com/ku.json', 'hyphen'],
  ];
  for (const [name, ku, wantErr] of cases) {
    it(name, () => {
      const r = makeRecord({ ku });
      if (wantErr === undefined) expect(() => r.validate()).not.toThrow();
      else expect(() => r.validate()).toThrow(wantErr);
    });
  }
});

describe('DnsIdTxtRecord.validate() — ek host compared in canonical form', () => {
  const cases: [string, string, string | undefined][] = [
    ['at gi', 'https://bigcorp.com/ek.json', undefined],
    ['under gi', 'https://keys.bigcorp.com/ek.json', undefined],
    ['deeper under gi', 'https://a.b.keys.bigcorp.com/ek.json', undefined],
    ['uppercase', 'https://KEYS.BigCorp.COM/ek.json', undefined],
    ['trailing dot', 'https://keys.bigcorp.com./ek.json', 'must not end with a root dot'],
    ['sibling domain', 'https://keys.other.example/ek.json', 'must equal or be beneath gi'],
    ['gi as prefix', 'https://bigcorp.com.attacker.example/ek.json', 'must equal or be beneath gi'],
    ['gi as label suffix', 'https://notbigcorp.com/ek.json', 'must equal or be beneath gi'],
    ['percent-encoded U+0130', 'https://keys.b%C4%B0gcorp.com/ek.json', 'without percent-escapes'],
    ['raw U+0130', 'https://keys.bİgcorp.com/ek.json', 'without percent-escapes'],
    ['percent-encoded ASCII', 'https://keys.bigcorp%2Ecom/ek.json', 'without percent-escapes'],
    ['literal percent via %25', 'https://keys.bigcorp.com%25/ek.json', 'without percent-escapes'],
    ['ipv6 zone', 'https://[fe80::1%25eth0]/ek.json', 'without percent-escapes'],
    ['leading hyphen label', 'https://-keys.bigcorp.com/ek.json', 'hyphen'],
  ];
  for (const [name, ek, wantErr] of cases) {
    it(name, () => {
      const r = makeRecord({ gi: 'bigcorp.com', ek });
      if (wantErr === undefined) expect(() => r.validate()).not.toThrow();
      else expect(() => r.validate()).toThrow(wantErr);
    });
  }
});

describe('DnsIdTxtRecord.validate() — su/cu hosts without percent-escapes', () => {
  it('rejects a percent-escaped su host but keeps percent-encoding in the path', () => {
    expect(() => makeRecord({ su: 'https://status.example%2Ecom/agent' }).validate()).toThrow(/without percent-escapes/);
    expect(() => makeRecord({ su: 'https://status.example.com/a%20b?q=%41' }).validate()).not.toThrow();
  });

  it('rejects a percent-escaped cu host', () => {
    expect(() => makeRecord({ cu: 'https://docs.example%2Ecom/AGENTS.md' }).validate()).toThrow(/without percent-escapes/);
  });
});
