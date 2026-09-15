import { ParseError, ValidationError } from './errors.ts';
import { normalizeFQDN } from './utils.ts';

/** Pre-RFC moving verification selector. Never published while version 1 is a draft. */
export const DNSID_VERSION = 'DNSid1';
/** Immutable selector for submitted draft-ihsanullah-dnsid-01. */
export const DNSID_DRAFT01_VERSION = 'dnsid-draft-01';
export const DEFAULT_PUBLISH_PROFILE = DNSID_DRAFT01_VERSION;
export const SUPPORTED_PUBLISH_PROFILES = [DNSID_DRAFT01_VERSION] as const;
export const SUPPORTED_VALIDATION_PROFILES = [DNSID_DRAFT01_VERSION, DNSID_VERSION] as const;

const SUPPORTED_DNSID_VERSIONS = new Set<string>(SUPPORTED_VALIDATION_PROFILES);
const VALID_KA_VALUES = new Set(['24h', '7d', '30d', '90d']);
const LR_METHOD_RE = /^[a-z][a-z0-9-]*$/;
const TAG_NAME_RE = /^[A-Za-z][A-Za-z0-9_]*$/;
const TAG_VALUE_RE = /^[\x21-\x3A\x3C-\x7E]*$/;
const REQUIRED_TAGS = ['v', 'gi', 'ek', 'ku', 'lr', 'su', 'sg'] as const;
const REQUIRED_UNSIGNED_TAGS = ['v', 'gi', 'ek', 'ku', 'lr', 'su'] as const;
const KNOWN_TAGS = new Set(['v', 'gi', 'ek', 'ku', 'lr', 'su', 'sg', 'fl', 'ka', 'cu']);

export class DnsIdTxtRecord {
  v = '';
  gi = '';
  ek = '';
  ku = '';
  lr = '';
  su = '';
  sg = '';
  fl?: string;
  ka?: string;
  cu?: string;
  unknownTags: Map<string, string> = new Map();
  agentFQDN = '';

  static parse(raw: string): DnsIdTxtRecord {
    return DnsIdTxtRecord.parseTagPairs(raw, true, true);
  }

  static parseUnsignedCanonical(raw: string, agentFQDN?: string): DnsIdTxtRecord {
    const record = DnsIdTxtRecord.parseTagPairs(raw, false, false);
    if (record.canonical() !== raw) throw new ParseError('unsigned TXT record is not in canonical form');
    if (agentFQDN) {
      record.agentFQDN = agentFQDN;
      record.validate();
    }
    return record;
  }

  get isDnsid1(): boolean { return this.v === DNSID_VERSION; }
  get isTwoKey(): boolean { return SUPPORTED_DNSID_VERSIONS.has(this.v); }
  get usesEntityKey(): boolean { return this.isTwoKey; }

  /** Profile-selected accountable-entity identifier for relationship and acceptance checks; draft 01 uses `gi` as signed. */
  governanceId(): string { return this.gi; }
  signatureVerificationKeyURI(): string { return this.ek; }
  signatureVerificationKeyAllowedHost(): string { return normalizeFQDN(this.gi); }
  runtimeKeyURI(): string { return this.ku; }
  runtimeKeyAllowedHost(): string { return normalizeFQDN(this.agentFQDN); }

  /**
   * Whether the agent FQDN is equal to or beneath the accountable entity's
   * governance domain. A false result is valid only for delegated identities,
   * whose relationship MUST be established by verified ISSUANCE evidence.
   */
  hasStructuralGovernanceRelationship(): boolean {
    const agentFQDN = normalizeFQDN(this.agentFQDN, true);
    const giDomain = normalizeFQDN(this.gi);
    return agentFQDN === giDomain || agentFQDN.endsWith(`.${giDomain}`);
  }

  private static parseTagPairs(raw: string, requireSignature: boolean, requireVFirst: boolean): DnsIdTxtRecord {
    const pairs = raw.split(';');
    const versionPair = requireVFirst ? pairs[0] : pairs.find(pair => pair.startsWith('v='));
    if (!versionPair?.startsWith('v=')) throw new ParseError(requireVFirst ? 'v= tag must be first' : 'unsigned TXT record missing v tag');
    const version = versionPair.slice(2);
    if (!SUPPORTED_DNSID_VERSIONS.has(version)) throw new ParseError(`unsupported DNSid TXT record profile: ${version}`);

    const record = new DnsIdTxtRecord();
    const seenTags = new Set<string>();
    for (let i = 0; i < pairs.length; i++) {
      let pair = pairs[i]!;
      if (pair === '') {
        if (i === pairs.length - 1) continue;
        throw new ParseError('empty TXT tag element');
      }
      if (i > 0 && pair.startsWith(' ')) pair = pair.slice(1);
      const eqIdx = pair.indexOf('=');
      if (eqIdx === -1) throw new ParseError(`TXT tag element missing '=': ${pair}`);
      const tag = pair.slice(0, eqIdx);
      const value = pair.slice(eqIdx + 1);
      if (!TAG_NAME_RE.test(tag)) throw new ParseError(`invalid TXT tag name: ${tag}`);
      if (!TAG_VALUE_RE.test(value)) throw new ParseError(`invalid TXT tag value for tag: ${tag}`);
      if (seenTags.has(tag)) throw new ParseError(`duplicate TXT tag: ${tag}`);
      if (!requireSignature && tag === 'sg') throw new ParseError('unsigned TXT record must not contain sg');
      seenTags.add(tag);
      if (KNOWN_TAGS.has(tag)) record.setKnownTag(tag, value);
      else record.unknownTags.set(tag, value);
    }

    const requiredTags = requireSignature ? REQUIRED_TAGS : REQUIRED_UNSIGNED_TAGS;
    for (const req of requiredTags) if (!(record as unknown as Record<string, string>)[req]) throw new ParseError(`missing or empty required TXT tag: ${req}`);
    return record;
  }

  private setKnownTag(tag: string, value: string): void {
    switch (tag) {
      case 'v':  this.v  = value; break;
      case 'gi': this.gi = value; break;
      case 'ek': this.ek = value; break;
      case 'ku': this.ku = value; break;
      case 'lr': this.lr = value; break;
      case 'su': this.su = value; break;
      case 'sg': this.sg = value; break;
      case 'fl': if (value) this.fl = value; break;
      case 'ka': if (value) this.ka = value; break;
      case 'cu': if (value) this.cu = value; break;
    }
  }

  validate(): void {
    if (!SUPPORTED_DNSID_VERSIONS.has(this.v)) throw new ValidationError(`unsupported DNSid profile: ${this.v}`);
    if (!this.agentFQDN) throw new ValidationError('agentFQDN must be set before calling validate()');
    const agentFQDN = normalizeFQDN(this.agentFQDN, true);

    const giDomain = normalizeFQDN(this.gi);
    if (this.gi !== giDomain) throw new ValidationError('gi must be lowercase ASCII A-label domain');
    validateEkHost(this.ek, giDomain);
    validateHttpsUrlHost(this.ku, 'ku', agentFQDN);
    validateLrFormat(this.lr);
    validateHttpsUrl(this.su, 'su');
    if (this.cu) validateHttpsUrl(this.cu, 'cu');
    if (this.ka && !VALID_KA_VALUES.has(this.ka)) throw new ValidationError('ka must be one of: 24h, 7d, 30d, 90d');
  }

  canonical(): string {
    return canonicalJoin([...this.knownCanonicalPairs(), ...this.unknownTags]);
  }

  knownTagsCanonical(): string {
    return canonicalJoin(this.knownCanonicalPairs());
  }

  private knownCanonicalPairs(): [string, string][] {
    const pairs: [string, string][] = [];
    if (this.v) pairs.push(['v', this.v]);
    if (this.gi) pairs.push(['gi', this.gi]);
    if (this.ek) pairs.push(['ek', this.ek]);
    if (this.ku) pairs.push(['ku', this.ku]);
    if (this.lr) pairs.push(['lr', this.lr]);
    if (this.su) pairs.push(['su', this.su]);
    if (this.fl) pairs.push(['fl', this.fl]);
    if (this.ka) pairs.push(['ka', this.ka]);
    if (this.cu) pairs.push(['cu', this.cu]);
    return pairs;
  }

  serialize(): string {
    const parts = [`v=${this.v}`];
    if (this.gi) parts.push(`gi=${this.gi}`);
    if (this.ek) parts.push(`ek=${this.ek}`);
    if (this.ku) parts.push(`ku=${this.ku}`);
    if (this.lr) parts.push(`lr=${this.lr}`);
    if (this.su) parts.push(`su=${this.su}`);
    if (this.sg) parts.push(`sg=${this.sg}`);
    if (this.fl) parts.push(`fl=${this.fl}`);
    if (this.ka) parts.push(`ka=${this.ka}`);
    if (this.cu) parts.push(`cu=${this.cu}`);
    for (const [k, v] of this.unknownTags) parts.push(`${k}=${v}`);
    return parts.join(';');
  }

  policyFlags(): Set<string> {
    const flags = new Set<string>();
    if (!this.fl) return flags;
    for (const token of this.fl.split(',')) {
      const name = token.trim();
      if (name) flags.add(name);
    }
    return flags;
  }
}

function validateLrFormat(lr: string): void {
  const colonIdx = lr.indexOf(':');
  if (colonIdx === -1) throw new ValidationError(`malformed lr value (no colon): ${lr}`);
  const method = lr.slice(0, colonIdx);
  if (!method || !LR_METHOD_RE.test(method)) throw new ValidationError(`malformed lr value (invalid method): ${lr}`);
  if (!lr.slice(colonIdx + 1)) throw new ValidationError(`malformed lr value (empty reference): ${lr}`);
}

function validateHttpsUrl(value: string, field: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new ValidationError(`${field} is not a valid URI: ${value}`); }
  if (url.protocol !== 'https:' || !url.hostname) throw new ValidationError(`${field} must be a valid HTTPS URI with a host`);
  return url;
}

function validateHttpsUrlHost(value: string, field: string, expectedHost: string): void {
  const url = validateHttpsUrl(value, field);
  if (normalizeFQDN(url.hostname) !== expectedHost) throw new ValidationError(`${field} host must equal agent FQDN`);
}

function validateEkHost(value: string, giDomain: string): void {
  const host = normalizeFQDN(validateHttpsUrl(value, 'ek').hostname);
  if (host !== giDomain && !host.endsWith('.' + giDomain)) throw new ValidationError('ek host must equal or be beneath gi');
}

function canonicalJoin(pairs: [string, string][]): string {
  return pairs.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, v]) => `${k}=${v}`).join(';');
}
