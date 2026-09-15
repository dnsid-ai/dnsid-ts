/**
 * DNSid JOSE profile helpers for JWT/JWS workflows.
 *
 * Builds on the narrow contracts from `@identity-digital/dnsid-protocol`
 * ({@link KeyProvider}, {@link IdentityResolver}) to sign and verify compact
 * JWTs and detached-style JWS objects whose signers are identified by DNSid
 * agent domains. This package performs no DNS or HTTPS transport itself —
 * callers supply an identity resolver and key provider, or build the profile
 * from a signing IdentityManager via {@link JoseProfile.fromIdentityManager}.
 *
 * @packageDocumentation
 */

import type { IdentityResolver, KeyProvider, SigningIdentityManager, VerifiedDomain } from '@identity-digital/dnsid-protocol';
import { requireLocalDomain } from '@identity-digital/dnsid-protocol';
import {
  ArgumentError,
  ValidationError,
  VerificationError,
  VerificationCode,
  normalizeFQDN,
  parseKeyId,
  toBase64Url,
  fromBase64Url,
  verifyWithKey,
  jwkSignatureAlg,
  parseCompactJose,
  parseJoseObject,
  type TLSCertificate,
  type VerificationOptions,
  withVerificationBudget,
  waitForVerification,
} from '@identity-digital/dnsid-protocol';

/** Options controlling the claims of a JWT created by {@link JoseProfile.createJWT}. */
export interface JWTOptions {
  /** Intended recipient's DNSid agent FQDN. Becomes the `aud` claim (normalized). */
  audience: string;
  /**
   * Token lifetime in seconds (`exp = iat + expiry`).
   * Default: {@link DEFAULT_JWT_EXPIRY_SECONDS}. Must not exceed the profile's `maxLifetime`.
   */
  expiry?: number;
  /**
   * Extra claims merged into the payload.
   * Must not override the reserved claims `iss`, `sub`, `aud`, `iat`, `exp`, or `jti`.
   */
  additionalClaims?: Record<string, unknown>;
}

/**
 * JOSE signature algorithms accepted at the application layer.
 * A JWT/JWS whose `alg` header is outside this allowlist is rejected during
 * verification (notably `none` and all HMAC algorithms are excluded).
 */
export const APPLICATION_JOSE_ALGS = [
  'EdDSA', 'ES256', 'ES384', 'ES512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
] as const;
/** Union of the algorithm identifiers in {@link APPLICATION_JOSE_ALGS}. */
export type ApplicationJoseAlg = (typeof APPLICATION_JOSE_ALGS)[number];

/** Default JWT lifetime in seconds (15 minutes) when {@link JWTOptions.expiry} is omitted. */
export const DEFAULT_JWT_EXPIRY_SECONDS = 15 * 60;
const DEFAULT_JWT_MAX_LIFETIME_SECONDS = 15 * 60;
const DEFAULT_JWT_CLOCK_SKEW_SECONDS = 60;

/** Convenience re-exports of protocol-layer helpers used with JOSE compact serialization. */
export { parseKeyId, toBase64Url, fromBase64Url } from '@identity-digital/dnsid-protocol';

/** Tunable verification and issuance limits for a {@link JoseProfile}. */
export interface JoseProfileConfig {
  /** Maximum accepted JWT lifetime (`exp - iat`) in seconds. Default: 900. */
  maxLifetime?: number;
  /** Allowed clock skew in seconds when checking JWT `iat` and `nbf`. Default: 60. */
  clockSkew?: number;
}

/** Construction options for {@link JoseProfile} / {@link createJoseProfile}. */
export interface JoseProfileOptions {
  /** Local DNSid identity FQDN. */
  domain?: string;
  /** Signs outgoing JWTs/JWS. Omit for a verification-only profile. */
  keyProvider?: KeyProvider;
  /** Resolves and verifies remote DNSid identities when verifying inbound JWTs/JWS. */
  identityResolver: IdentityResolver;
  /** Optional JOSE-specific limits. Defaults: 900s max lifetime, 60s clock skew. */
  jose?: JoseProfileConfig;
}

/** Input to {@link JoseProfile.createJWT}. Alias of {@link JWTOptions}. */
export interface CreateJWTInput extends JWTOptions {}

/** Result of a successful {@link JoseProfile.verifyJWS} call. */
export interface VerifyJWSResult {
  /** The decoded (base64url) JWS payload bytes, exactly as signed. */
  payload: Uint8Array;
  /** The signer's verified DNSid identity, resolved from the `kid` header's domain. */
  verifiedDomain: VerifiedDomain;
}

/**
 * JOSE JWT/JWS helpers built on narrow DNSid core contracts.
 *
 * Signs on behalf of the local agent domain (via its {@link KeyProvider}) and
 * verifies inbound tokens by resolving the issuer's DNSid identity (via its
 * {@link IdentityResolver}). Performs no DNS or HTTPS transport itself.
 */
export class JoseProfile {
  /**
   * Builds a profile from a signing IdentityManager, reusing its domain,
   * key provider, and identity resolution.
   * @param jose Optional JOSE-specific limits (max lifetime, clock skew).
   */
  static fromIdentityManager(
    identityManager: SigningIdentityManager,
    jose?: JoseProfileConfig,
  ): JoseProfile {
    return new JoseProfile({
      domain: requireLocalDomain(identityManager),
      keyProvider: identityManager.getKeyProvider(),
      identityResolver: identityManager,
      jose,
    });
  }

  private readonly domain: string | undefined;
  private readonly keyProvider: KeyProvider | null;
  private readonly identityResolver: IdentityResolver;
  private readonly config: JoseProfileConfig;

  /** @throws ArgumentError if `opts.domain` is not a valid agent FQDN. */
  constructor(opts: JoseProfileOptions) {
    try {
      this.domain = opts.domain === undefined ? undefined : normalizeFQDN(opts.domain, true);
    } catch (e) {
      throw new ArgumentError(`domain is not a valid agent FQDN: ${(e as Error).message}`);
    }
    this.keyProvider = opts.keyProvider ?? null;
    this.identityResolver = opts.identityResolver;
    this.config = Object.freeze({ ...opts.jose });
    const max = this.config.maxLifetime === undefined ? DEFAULT_JWT_MAX_LIFETIME_SECONDS : this.config.maxLifetime;
    const skew = this.config.clockSkew === undefined ? DEFAULT_JWT_CLOCK_SKEW_SECONDS : this.config.clockSkew;
    if (!Number.isFinite(max) || max <= 0 || !Number.isFinite(skew) || skew < 0) throw new ArgumentError('invalid JOSE lifetime or clock skew');
  }

  /**
   * Creates a signed compact JWT with `iss`/`sub` set to the local domain,
   * `aud` set to the normalized audience, and a fresh `jti`. The header carries
   * the operational key's `alg` and bare `kid` (no domain prefix).
   * @returns The compact JWT serialization (`header.payload.signature`).
   * @throws ArgumentError if the audience is missing or not a valid FQDN, if
   *   `expiry` exceeds the configured max lifetime, or if `additionalClaims`
   *   would override a reserved claim.
   */
  async createJWT(opts: CreateJWTInput): Promise<string> {
    const keyProvider = this.requireKeyProvider();
    if (!opts.audience) {
      throw new ArgumentError('audience is required');
    }
    let audience: string;
    try {
      audience = normalizeFQDN(opts.audience);
    } catch (e) {
      throw new ArgumentError(`audience is not a valid FQDN: ${(e as Error).message}`);
    }
    const expiry = opts.expiry === undefined ? DEFAULT_JWT_EXPIRY_SECONDS : opts.expiry;
    const maxLifetime = this.config.maxLifetime ?? DEFAULT_JWT_MAX_LIFETIME_SECONDS;
    if (!Number.isFinite(expiry) || expiry <= 0 || expiry > maxLifetime) {
      throw new ArgumentError('JWT expiry exceeds maximum lifetime');
    }

    const signingKey = await keyProvider.signingKey();
    const now = Math.floor(Date.now() / 1000);
    if (now + expiry <= now) throw new ArgumentError('JWT expiry is below timestamp resolution');

    const claims: Record<string, unknown> = {
      iss: this.domain,
      sub: this.domain,
      aud: audience,
      iat: now,
      exp: now + expiry,
      jti: crypto.randomUUID(),
    };

    const RESERVED = new Set(['iss', 'sub', 'aud', 'iat', 'exp', 'jti']);
    if (opts.additionalClaims) {
      for (const [k, v] of Object.entries(opts.additionalClaims)) {
        if (RESERVED.has(k)) {
          throw new ArgumentError(`additionalClaims must not override reserved claim: ${k}`);
        }
        claims[k] = v;
      }
    }

    const header = { alg: jwkSignatureAlg(signingKey), kid: signingKey.kid, typ: 'JWT' };
    return signCompact(header, claims, keyProvider);
  }

  /**
   * Verifies an inbound compact JWT issued by a remote DNSid agent.
   *
   * Checks structure, `sub === iss`, that the local domain appears in `aud`,
   * time claims (`iat` required and not in the future, `exp` required, within
   * the max lifetime, not expired, optional `nbf`), then resolves the issuer's
   * DNSid identity, matches the header `kid` against the issuer's JWKS,
   * enforces the {@link APPLICATION_JOSE_ALGS} allowlist and alg/key
   * consistency, and verifies the signature.
   * @returns The issuer's verified DNSid identity.
   * @throws VerificationError with `VerificationCode.RecordInvalid` for
   *   malformed tokens, claim violations, or issuer resolution argument
   *   failures; with `VerificationCode.SignatureInvalid` for missing/unknown
   *   `kid`, disallowed or mismatched `alg`, or a bad signature. Resolver
   *   errors other than ArgumentError propagate unchanged.
   */
  async verifyJWT(jwt: string, options: VerificationOptions & { expectedAudience?: string; peerCert?: TLSCertificate } = {}): Promise<VerifiedDomain> {
    return withVerificationBudget(signal => this.verifyJWTWithinBudget(jwt, { ...options, signal }), options);
  }

  private async verifyJWTWithinBudget(jwt: string, options: VerificationOptions & { expectedAudience?: string; peerCert?: TLSCertificate }): Promise<VerifiedDomain> {
    const audience = options.expectedAudience ?? this.domain;
    if (!audience) throw new ArgumentError('expected audience is required');
    let expectedAudience: string;
    try { expectedAudience = normalizeFQDN(audience); }
    catch { throw new ArgumentError('expected audience must be an FQDN'); }
    const { parts, header, payload } = parseCompactJose(jwt);
    validateAlgorithm(header);
    const claims = parseJoseObject(payload);

    if (typeof claims['iss'] !== 'string' || !claims['iss']) {
      throw new VerificationError('JWT iss claim must be a non-empty string', { code: VerificationCode.RecordInvalid });
    }
    const iss = claims['iss'];
    const sub = claims['sub'];
    if (typeof sub !== 'string') {
      throw new VerificationError('JWT sub must equal iss', { code: VerificationCode.RecordInvalid });
    }
    try {
      if (normalizeFQDN(sub) !== normalizeFQDN(iss)) {
        throw new VerificationError('JWT sub must equal iss', { code: VerificationCode.RecordInvalid });
      }
    } catch (e) {
      if (e instanceof VerificationError) throw e;
      throw new VerificationError('JWT sub must equal iss', { code: VerificationCode.RecordInvalid });
    }

    const rawAud = claims['aud'];
    const audList = Array.isArray(rawAud) ? rawAud : [rawAud];
    const normalizedAuds = audList.map(a => {
      if (typeof a !== 'string') return null;
      try { return normalizeFQDN(a); } catch { return null; }
    });
    if (normalizedAuds.length === 0 || normalizedAuds.includes(null) || !normalizedAuds.includes(expectedAudience)) {
      throw new VerificationError(
        `JWT audience mismatch: ${this.domain} not in aud`,
        { code: VerificationCode.RecordInvalid },
      );
    }

    const now = Date.now() / 1000;
    const iat = claims['iat'];
    const jwtClockSkew = this.config.clockSkew ?? DEFAULT_JWT_CLOCK_SKEW_SECONDS;
    const jwtMaxLifetime = this.config.maxLifetime ?? DEFAULT_JWT_MAX_LIFETIME_SECONDS;

    if (typeof iat !== 'number' || !Number.isFinite(iat)) {
      throw new VerificationError('JWT missing required iat claim', { code: VerificationCode.RecordInvalid });
    }
    if (iat > now + jwtClockSkew) {
      throw new VerificationError('JWT issued-at time is in the future', { code: VerificationCode.RecordInvalid });
    }

    const exp = claims['exp'];
    if (typeof exp !== 'number' || !Number.isFinite(exp)) {
      throw new VerificationError('JWT missing required exp claim', { code: VerificationCode.RecordInvalid });
    }
    if (exp <= iat) {
      throw new VerificationError('JWT exp must be after iat', { code: VerificationCode.RecordInvalid });
    }
    if (exp - iat > jwtMaxLifetime) {
      throw new VerificationError('JWT lifetime exceeds maximum', { code: VerificationCode.RecordInvalid });
    }
    if (exp <= now) {
      throw new VerificationError('JWT is expired', { code: VerificationCode.RecordInvalid });
    }
    const nbf = claims['nbf'];
    if (nbf !== undefined && (typeof nbf !== 'number' || !Number.isFinite(nbf))) {
      throw new VerificationError('JWT nbf claim must be a number', { code: VerificationCode.RecordInvalid });
    }
    if (typeof nbf === 'number' && now + jwtClockSkew < nbf) {
      throw new VerificationError('JWT not yet valid (nbf)', { code: VerificationCode.RecordInvalid });
    }

    let vd: VerifiedDomain;
    try {
      vd = await waitForVerification(() => this.identityResolver.verifyDomain(iss, options.peerCert, { signal: options.signal }), options.signal!);
    } catch (e) {
      if (e instanceof ArgumentError) {
        throw new VerificationError(e.message, { code: VerificationCode.RecordInvalid });
      }
      throw e;
    }

    const kid = header['kid'] as string | undefined;
    if (!kid) {
      throw new VerificationError('JWT missing kid header', { code: VerificationCode.SignatureInvalid });
    }
    const sigKey = vd.jwks.keyById(kid);
    if (!sigKey) {
      throw new VerificationError('JWT kid not found in issuer JWKS', { code: VerificationCode.SignatureInvalid });
    }

    const alg = header['alg'] as string | undefined;
    if (!alg || !(APPLICATION_JOSE_ALGS as readonly string[]).includes(alg)) {
      throw new VerificationError(`JWT alg not in application-layer allowlist: ${alg}`, {
        code: VerificationCode.SignatureInvalid,
      });
    }
    const keyAlg = jwkSignatureAlg(sigKey);
    if (alg !== keyAlg) {
      throw new VerificationError(`JWT alg mismatch: header declares ${alg} but key is ${keyAlg}`, {
        code: VerificationCode.SignatureInvalid,
      });
    }

    const signingInput = `${parts[0]}.${parts[1]}`;
    const sig = fromBase64Url(parts[2]!);
    if (!(await verifyWithKey(signingInput, sig, sigKey, alg))) {
      throw new VerificationError('JWT signature invalid', { code: VerificationCode.SignatureInvalid });
    }

    if (exp <= Date.now() / 1000) throw new VerificationError('JWT expired during verification', { code: VerificationCode.RecordInvalid });
    return vd;
  }

  /**
   * Signs an arbitrary byte payload as a compact JWS with `typ: "jose"`.
   * The header `kid` is the compound form `<domain>#<kid>` so verifiers can
   * locate the signer without out-of-band context.
   * @returns The compact JWS serialization (`header.payload.signature`).
   * @throws ArgumentError if the operational signing key's kid contains `#`.
   */
  async createJWS(payload: Uint8Array): Promise<string> {
    const keyProvider = this.requireKeyProvider();
    const signingKey = await keyProvider.signingKey();
    if (signingKey.kid.includes('#')) {
      throw new ArgumentError("signing key kid must not contain '#'");
    }
    const header = {
      alg: jwkSignatureAlg(signingKey),
      kid: `${this.domain}#${signingKey.kid}`,
      typ: 'jose',
    };
    const headerB64 = toBase64Url(new TextEncoder().encode(JSON.stringify(header)));
    const payloadB64 = toBase64Url(payload);
    const signingInput = `${headerB64}.${payloadB64}`;
    const sig = await keyProvider.sign(new TextEncoder().encode(signingInput));
    return `${signingInput}.${toBase64Url(sig)}`;
  }

  private requireKeyProvider(): KeyProvider {
    if (!this.keyProvider || !this.domain) throw new ArgumentError('JOSE signing requires a keyProvider and local domain');
    return this.keyProvider;
  }

  /**
   * Verifies a compact JWS whose header `kid` is the compound
   * `<domain>#<kid>` form produced by {@link createJWS}.
   *
   * Parses the compound kid, resolves and verifies the signer's DNSid
   * identity, matches the key in the signer's JWKS, enforces the
   * {@link APPLICATION_JOSE_ALGS} allowlist and alg/key consistency, and
   * verifies the signature. Unlike {@link verifyJWT}, the payload is opaque —
   * no claims are inspected.
   * @returns The raw payload bytes and the signer's verified identity.
   * @throws VerificationError with `VerificationCode.RecordInvalid` for a
   *   malformed JWS; with `VerificationCode.SignatureInvalid` for a
   *   missing/invalid `kid`, unknown key, disallowed or mismatched `alg`, or
   *   a bad signature. Identity resolution errors propagate unchanged.
   */
  async verifyJWS(jws: string, options: VerificationOptions & { peerCert?: TLSCertificate } = {}): Promise<VerifyJWSResult> {
    return withVerificationBudget(signal => this.verifyJWSWithinBudget(jws, { ...options, signal }), options);
  }

  private async verifyJWSWithinBudget(jws: string, options: VerificationOptions & { peerCert?: TLSCertificate }): Promise<VerifyJWSResult> {
    const { parts, header, payload } = parseCompactJose(jws);
    validateAlgorithm(header);
    const [headerB64, payloadB64, sigB64] = parts;

    const compoundKid = header['kid'] as string | undefined;
    if (!compoundKid) {
      throw new VerificationError('JWS missing kid header parameter', { code: VerificationCode.SignatureInvalid });
    }
    let domain: string, kid: string;
    try {
      ({ domain, kid } = parseKeyId(compoundKid));
    } catch (e) {
      if (e instanceof ArgumentError || e instanceof ValidationError) {
        throw new VerificationError(`invalid kid in JWS header: ${(e as Error).message}`, {
          code: VerificationCode.SignatureInvalid,
        });
      }
      throw e;
    }

    const vd = await waitForVerification(() => this.identityResolver.verifyDomain(domain, options.peerCert, { signal: options.signal }), options.signal!);
    const sigKey = vd.jwks.keyById(kid);
    if (!sigKey) {
      throw new VerificationError('JWS kid not found in signer JWKS', { code: VerificationCode.SignatureInvalid });
    }

    const alg = header['alg'] as string | undefined;
    if (!alg || !(APPLICATION_JOSE_ALGS as readonly string[]).includes(alg)) {
      throw new VerificationError(`JWS alg not in application-layer allowlist: ${alg}`, {
        code: VerificationCode.SignatureInvalid,
      });
    }
    const keyAlg = jwkSignatureAlg(sigKey);
    if (alg !== keyAlg) {
      throw new VerificationError(`JWS alg mismatch: header declares ${alg} but key is ${keyAlg}`, {
        code: VerificationCode.SignatureInvalid,
      });
    }

    const signingInput = `${headerB64}.${payloadB64}`;
    const sig = fromBase64Url(sigB64);
    if (!(await verifyWithKey(signingInput, sig, sigKey, alg))) {
      throw new VerificationError('JWS signature invalid', { code: VerificationCode.SignatureInvalid });
    }

    return { payload, verifiedDomain: vd };
  }
}

/**
 * Creates a {@link JoseProfile} for DNSid JWT/JWS workflows.
 *
 * Primary entry point of this package. Equivalent to `new JoseProfile(opts)`;
 * use {@link JoseProfile.fromIdentityManager} to build from a signing
 * IdentityManager instead.
 *
 * @throws ArgumentError if `opts.domain` is not a valid agent FQDN.
 * @example
 * ```ts
 * import { createJoseProfile } from '@identity-digital/dnsid-jose';
 *
 * const joseProfile = createJoseProfile({
 *   domain: 'agent.example.com',
 *   keyProvider,
 *   identityResolver,
 * });
 *
 * const jwt = await joseProfile.createJWT({ audience: 'peer.example.org' });
 * const verifiedDomain = await peerProfile.verifyJWT(jwt);
 * console.log(verifiedDomain.domain); // 'agent.example.com'
 * ```
 */
export function createJoseProfile(opts: JoseProfileOptions): JoseProfile {
  return new JoseProfile(opts);
}


function validateAlgorithm(header: Record<string, unknown>): void {
  if (!(APPLICATION_JOSE_ALGS as readonly unknown[]).includes(header.alg)) throw new VerificationError('JOSE alg not in application-layer allowlist', { code: VerificationCode.SignatureInvalid });
}

/** Serializes and signs a JOSE compact structure (`b64(header).b64(payload).b64(sig)`). */
async function signCompact(
  header: object,
  payload: object,
  keyProvider: KeyProvider,
): Promise<string> {
  const headerB64 = toBase64Url(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = toBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = await keyProvider.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${toBase64Url(sig)}`;
}
