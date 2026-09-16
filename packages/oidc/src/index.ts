/**
 * DNSid OIDC federation profile: minting OIDC access tokens from a DNSid
 * identity (JWT bearer client assertions signed with the agent's operational
 * key) and verifying OIDC tokens back to DNSid identity records.
 *
 * This package is deliberately NOT re-exported by the runtime-neutral root
 * `@dnsid-ai/sdk` export because its default transport is Node-bound
 * (SSRF-safe fetch backed by `node:dns` lookups). Import it directly from
 * `@dnsid-ai/oidc`.
 *
 * Security notes:
 * - Never mint OIDC tokens in browser/client code — private keys stay
 *   server-side.
 * - Passing a custom `fetch` replaces the safe default transport, so only
 *   inject trusted transports that enforce equivalent DNS/SSRF checks.
 *
 * @packageDocumentation
 */
import * as dnsPromises from 'node:dns/promises';
import * as net from 'node:net';

import { createSsrfSafeFetch, isUnsafeIp } from '@dnsid-ai/transport';
import { decodeJwt, decodeProtectedHeader, importJWK, compactVerify } from 'jose';
import type { JWK, JWTPayload } from 'jose';

import type { DnsIdJWK, IdentityResolver, KeyProvider, SigningIdentityManager, VerifiedDomain } from '@dnsid-ai/protocol';
import { requireLocalDomain } from '@dnsid-ai/protocol';
import {
  ArgumentError,
  VerificationCode,
  VerificationError,
  SIGNING_ALGS,
  fromBase64Url,
  jwkThumbprint,
  jwkSignatureAlg,
  normalizeFQDN,
  toArrayBuffer,
  toBase64Url,
  verifyWithKey,
  parseCompactJose,
  parseJoseObject,
  type TLSCertificate,
  type VerificationOptions,
  withVerificationBudget,
  waitForVerification,
} from '@dnsid-ai/protocol';

/** Tunable OIDC policy for an {@link OIDCProfile}. All members are optional; defaults noted per member. */
export interface OIDCProfileConfig {
  /** Scope requested when a token exchange does not specify one. Defaults to 'openid'. */
  defaultScope?: string;
  /** Lifetime of minted client assertions, in seconds. Defaults to 300. */
  assertionLifetime?: number;
  /** Upper bound on any requested assertion lifetime, in seconds. Defaults to 900. */
  maxAssertionLifetime?: number;
  /** Clock skew tolerated when validating token timestamps, in seconds. Defaults to 30. */
  clockSkew?: number;
  /** Timeout for discovery, JWKS, and token-endpoint requests, in milliseconds. Defaults to 10000. */
  fetchTimeoutMs?: number;
  /** Exact issuer URLs `verifyOIDCToken()` accepts. When absent or empty, verification always fails. */
  allowedIssuers?: string[];
  /** JWS algorithms accepted on inbound OIDC tokens. Defaults to ['RS256']. */
  allowedTokenAlgorithms?: string[];
  /** Permit plain-HTTP loopback issuers (localhost, 127.x, ::1) for local testing. Defaults to false. */
  allowHttpLoopbackIssuer?: boolean;
}

/** Constructor options for {@link OIDCProfile}. */
export interface OIDCProfileOptions {
  /** Agent FQDN; becomes the iss/sub/fqdn claims of minted assertions. */
  domain: string;
  /** Provider used to sign client assertions. Omit for a verification-only profile. */
  keyProvider?: KeyProvider;
  /** Resolver used by `verifyOIDCToken()` to verify token subjects as DNSid identity records. */
  identityResolver?: IdentityResolver;
  /** Custom fetch replaces the SSRF-safe Node default; inject only trusted/test transports with equivalent DNS safety. */
  fetch?: typeof globalThis.fetch;
  /** OIDC policy overrides; see {@link OIDCProfileConfig}. */
  oidc?: OIDCProfileConfig;
}

/** Options for minting a JWT bearer client assertion. */
export interface OIDCAssertionOptions {
  /** OIDC issuer the assertion is addressed to; becomes the aud claim. */
  issuer: string;
  /** Assertion lifetime in seconds; overrides the configured default, capped by maxAssertionLifetime. */
  expiry?: number;
  /** Extra claims to embed. Must not override reserved claims (iss, sub, aud, iat, exp, jti, fqdn). */
  additionalClaims?: Record<string, unknown>;
}

/**
 * The subset of an OIDC discovery document (`.well-known/openid-configuration`)
 * this package relies on. Additional members are preserved as-is.
 */
export interface OIDCDiscoveryDocument {
  issuer: string;
  token_endpoint: string;
  jwks_uri: string;
  [key: string]: unknown;
}

/** Options for `OIDCProfile.exchangeOIDCToken()` and `getOIDCToken()`. */
export interface OIDCTokenExchangeOptions {
  /** Exact OIDC issuer URL to exchange against. */
  issuer: string;
  /** Audience (aud) requested for the access token. */
  audience: string;
  /** Space-delimited scope; defaults to the configured defaultScope, then 'openid'. */
  scope?: string;
  /** Pre-minted client assertion to present; its aud must exactly match the issuer. Minted fresh when absent. */
  assertion?: string;
}

/** A successful token-endpoint response, normalized to camelCase members. */
export interface OIDCTokenResponse {
  /** The issued access token. */
  accessToken: string;
  /** ID token, when the issuer returned one. */
  idToken?: string;
  /** Token type as reported by the issuer; always Bearer (case preserved). */
  tokenType: string;
  /** Token lifetime in seconds, when the issuer provided one. */
  expiresIn?: number;
  /** Scope actually granted, when the issuer reported it. */
  scope?: string;
  /** Issuer the token was obtained from. */
  issuer?: string;
  /** Token endpoint the exchange was performed against. */
  tokenEndpoint?: string;
  /** Raw JSON body of the token response. */
  raw: unknown;
}

/**
 * A private JWK used to sign client assertions without a full key provider.
 * Must carry the private `d` member; keep it server-side only.
 */
export interface OIDCPrivateJWK extends Omit<DnsIdJWK, 'kid'> {
  kty: string;
  /** Private key material (base64url). */
  d: string;
  /** Key id published on the derived public key; defaults to the RFC 7638 thumbprint. */
  kid?: string;
}

/**
 * Selects how the token endpoint is located. Exactly one mode applies:
 * `issuer` (discovery at the issuer root), `serverUrl` (discovery relative to a
 * base URL, token endpoint at `serverUrl` + '/token'), or `tokenEndpoint`
 * (explicit endpoint; requires `issuer`, must share its origin, skips discovery).
 */
export interface OIDCTokenEndpointOptions {
  /** Exact HTTPS issuer root URL — no path, query, fragment, or trailing slash. Mutually exclusive with serverUrl. */
  issuer?: string;
  /** Base server URL used to derive the discovery document and token endpoint. Mutually exclusive with issuer. */
  serverUrl?: string;
  /** Explicit discovery document URL; only valid alongside issuer or serverUrl. */
  discoveryUrl?: string;
  /** Explicit token endpoint URL; requires issuer, must share its origin, and bypasses discovery. */
  tokenEndpoint?: string;
}

/** Constructor options for {@link OIDCTokenMinter}. */
export interface OIDCTokenMinterOptions extends OIDCTokenEndpointOptions {
  /** Agent FQDN; becomes the iss/sub/fqdn claims of minted assertions. */
  domain: string;
  /** Provider of the agent's operational key, used to sign client assertions. */
  keyProvider: KeyProvider;
  /** Custom fetch replaces the SSRF-safe Node default; inject only trusted/test transports with equivalent DNS safety. */
  fetch?: typeof globalThis.fetch;
  /** Scope used when a mint call does not specify one. Defaults to 'openid'. */
  defaultScope?: string;
  /** Lifetime of minted client assertions, in seconds. Defaults to 300. */
  assertionLifetime?: number;
  /** Upper bound on any requested assertion lifetime, in seconds. Defaults to 900. */
  maxAssertionLifetime?: number;
  /** Timeout for discovery and token-endpoint requests, in milliseconds. Defaults to 10000. */
  timeoutMs?: number;
  /** Permit plain-HTTP loopback issuers (localhost, 127.x, ::1) for local testing. Defaults to false. */
  allowHttpLoopbackIssuer?: boolean;
}

/** Options for {@link createOIDCTokenMinter}: provide exactly one of keyProvider or privateJwk. */
export interface CreateOIDCTokenMinterOptions extends Omit<OIDCTokenMinterOptions, 'keyProvider'> {
  /** Provider of the agent's operational key. Mutually exclusive with privateJwk. */
  keyProvider?: KeyProvider;
  /** Raw private JWK to sign with, wrapped in an in-memory provider. Mutually exclusive with keyProvider. */
  privateJwk?: OIDCPrivateJWK;
}

/** Per-call options for `OIDCTokenMinter.mintToken()`. Endpoint members override the minter's defaults. */
export interface OIDCTokenMintOptions extends OIDCTokenEndpointOptions {
  /** Audience (aud) requested for the access token. */
  audience: string;
  /** Space-delimited scope string. Mutually exclusive with scopes. */
  scope?: string;
  /** Individual scope values, joined with spaces. Mutually exclusive with scope. */
  scopes?: readonly string[];
  /** Extra claims for the client assertion. Must not override reserved claims (iss, sub, aud, iat, exp, jti, fqdn). */
  additionalAssertionClaims?: Record<string, unknown>;
}

/** Combined options for the one-shot {@link mintOIDCToken}. */
export type MintOIDCTokenOptions = CreateOIDCTokenMinterOptions & OIDCTokenMintOptions;

/** Options for `OIDCProfile.verifyOIDCToken()`. */
export interface VerifyOIDCTokenOptions extends VerificationOptions {
  /** Exact issuer URL the token must have been issued by; must appear in the profile's allowedIssuers. */
  issuer: string;
  /** Audience the token must be addressed to (exact match). */
  audience: string;
  /** Set false to skip verifying the token subject as a DNSid identity record. Defaults to true. */
  verifyDnsidSubject?: boolean;
  peerCert?: TLSCertificate;
}

/** Result of a successful `OIDCProfile.verifyOIDCToken()` call. */
export interface VerifiedOIDCSubject {
  /** Issuer that signed the token. */
  issuer: string;
  /** Token subject — the agent FQDN for DNSid-federated tokens. */
  subject: string;
  /** Audience the token was verified against. */
  audience: string;
  /** DNSid verification result for the subject; absent when verifyDnsidSubject is false. */
  verifiedDomain?: VerifiedDomain;
  /** The signature-verified JWT claims. */
  claims: JWTPayload;
}

/**
 * OAuth 2.0 error returned by a token endpoint (e.g. invalid_grant), carrying
 * the raw `error` and `error_description` members from the response body.
 */
export class OAuthError extends Error {
  /** The RFC 6749 error code, when the endpoint provided one. */
  readonly error?: string;
  /** Human-readable error description, when the endpoint provided one. */
  readonly errorDescription?: string;

  constructor(error?: string, errorDescription?: string) {
    super(errorDescription ? `${error}: ${errorDescription}` : (error ?? 'OIDC token exchange failed'));
    this.name = 'OAuthError';
    this.error = error;
    this.errorDescription = errorDescription;
  }
}

function validateOidcTimes(config: Pick<OIDCProfileConfig, 'assertionLifetime' | 'maxAssertionLifetime' | 'clockSkew'>): void {
  const lifetime = config.assertionLifetime === undefined ? 300 : config.assertionLifetime;
  const maximum = config.maxAssertionLifetime === undefined ? 900 : config.maxAssertionLifetime;
  const skew = config.clockSkew === undefined ? 30 : config.clockSkew;
  if (!Number.isFinite(lifetime) || lifetime <= 0 || !Number.isFinite(maximum) || maximum <= 0 || !Number.isFinite(skew) || skew < 0) throw new ArgumentError('invalid OIDC lifetime or clock skew');
}

function validateTokenTimes(claims: JWTPayload, skew: number): void {
  const now = Date.now() / 1000;
  const fail = (message: string): never => { throw new VerificationError(message, { code: VerificationCode.RecordInvalid }); };
  if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp)) fail('OIDC token missing exp');
  if (typeof claims.iat !== 'number' || !Number.isFinite(claims.iat)) fail('OIDC token missing iat');
  if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || !Number.isFinite(claims.nbf))) fail('OIDC token invalid nbf');
  if (claims.exp! <= claims.iat!) fail('OIDC token exp must be after iat');
  if (now >= claims.exp!) fail('OIDC token is expired');
  if (claims.iat! > now + skew || (claims.nbf !== undefined && claims.nbf > now + skew)) fail('OIDC token not yet valid');
}

const DEFAULT_SCOPE = 'openid';
const DEFAULT_ASSERTION_LIFETIME_SECONDS = 300;
const DEFAULT_MAX_ASSERTION_LIFETIME_SECONDS = 900;
const DEFAULT_CLOCK_SKEW_SECONDS = 30;
const DEFAULT_TOKEN_ALGS = ['RS256'];
const DEFAULT_FETCH_TIMEOUT_MS = 10_000;
const MAX_OIDC_JSON_BYTES = 1_048_576;
const RESERVED_ASSERTION_CLAIMS = new Set(['iss', 'sub', 'aud', 'iat', 'exp', 'jti', 'fqdn']);

/** Outcome of endpoint resolution: the validated issuer and the token endpoint to POST to. */
interface ResolvedOIDCTokenEndpoint {
  issuer: string;
  tokenEndpoint: string;
  discoveryDocument?: OIDCDiscoveryDocument;
}

/**
 * Mints OIDC access tokens for a DNSid agent via the RFC 7523 JWT bearer
 * grant: signs a client assertion with the agent's operational key, then
 * exchanges it at the issuer's token endpoint.
 *
 * Server-side only — requires the agent's private operational key. Prefer a
 * long-lived minter over repeated {@link mintOIDCToken} calls when minting
 * more than once against the same issuer.
 */
export class OIDCTokenMinter {
  private readonly domain: string;
  private readonly keyProvider: KeyProvider;
  private readonly fetch: typeof globalThis.fetch;
  private readonly defaultEndpointOptions: OIDCTokenEndpointOptions;
  private readonly defaultScope?: string;
  private readonly assertionLifetime?: number;
  private readonly maxAssertionLifetime?: number;
  private readonly timeoutMs: number;
  private readonly allowHttpLoopbackIssuer: boolean;

  /**
   * @throws ArgumentError if domain is not a valid agent FQDN, the endpoint
   *   options mix modes (see {@link OIDCTokenEndpointOptions}), or timeoutMs
   *   is not a positive number.
   */
  constructor(opts: OIDCTokenMinterOptions) {
    try {
      this.domain = normalizeFQDN(opts.domain, true);
    } catch (e) {
      throw new ArgumentError(`domain is not a valid agent FQDN: ${(e as Error).message}`);
    }
    this.keyProvider = opts.keyProvider;
    this.fetch = opts.fetch ?? createSsrfSafeFetch();
    this.defaultEndpointOptions = validateEndpointMode({
      issuer: opts.issuer,
      serverUrl: opts.serverUrl,
      discoveryUrl: opts.discoveryUrl,
      tokenEndpoint: opts.tokenEndpoint,
    });
    this.defaultScope = opts.defaultScope;
    validateOidcTimes(opts);
    this.assertionLifetime = opts.assertionLifetime;
    this.maxAssertionLifetime = opts.maxAssertionLifetime;
    this.timeoutMs = validateTimeoutMs(opts.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS);
    this.allowHttpLoopbackIssuer = opts.allowHttpLoopbackIssuer ?? false;
  }

  /**
   * Mints a signed JWT bearer client assertion for the given issuer
   * (iss/sub/fqdn = agent domain, aud = issuer, fresh jti).
   *
   * @throws ArgumentError if the issuer URL is invalid, the expiry is not
   *   positive or exceeds the maximum lifetime, or additionalClaims override
   *   a reserved claim.
   * @throws ValidationError if the operational signing key is unsupported for JWS.
   * @throws VerificationError (SignatureInvalid) if the produced signature does
   *   not verify against the active operational key.
   */
  async createAssertion(opts: OIDCAssertionOptions): Promise<string> {
    return createOIDCAssertionJWT(this.domain, this.keyProvider, opts, {
      assertionLifetime: this.assertionLifetime,
      maxAssertionLifetime: this.maxAssertionLifetime,
      allowHttpLoopbackIssuer: this.allowHttpLoopbackIssuer,
    });
  }

  /**
   * Resolves the token endpoint (per the configured or per-call endpoint mode),
   * mints a fresh assertion, and performs the JWT bearer token exchange.
   *
   * @returns The normalized token response.
   * @throws ArgumentError if audience is missing or the options are inconsistent.
   * @throws VerificationError if discovery or transport fails, the target
   *   resolves to an unsafe address, or the response is malformed.
   * @throws OAuthError if the token endpoint returns an OAuth error response.
   */
  async mintToken(opts: OIDCTokenMintOptions): Promise<OIDCTokenResponse> {
    if (!opts.audience) throw new ArgumentError('audience is required');
    const endpoint = await resolveOIDCTokenEndpoint(this.fetch, endpointOptionsForCall(this.defaultEndpointOptions, opts), {
      allowHttpLoopbackIssuer: this.allowHttpLoopbackIssuer,
      timeoutMs: this.timeoutMs,
    });
    const assertion = await this.createAssertion({
      issuer: endpoint.issuer,
      additionalClaims: opts.additionalAssertionClaims,
    });
    return exchangeOIDCTokenAt(this.fetch, {
      issuer: endpoint.issuer,
      tokenEndpoint: endpoint.tokenEndpoint,
      assertion,
      audience: opts.audience,
      scope: resolveScope(opts.scope, opts.scopes, this.defaultScope),
      allowHttpLoopbackIssuer: this.allowHttpLoopbackIssuer,
      timeoutMs: this.timeoutMs,
    });
  }
}

/**
 * Creates an {@link OIDCTokenMinter}, resolving the signing key from either a
 * KeyProvider or a raw private JWK.
 *
 * @throws ArgumentError if neither or both of keyProvider/privateJwk are
 *   given, the private JWK is invalid, or the minter options are invalid.
 */
export async function createOIDCTokenMinter(opts: CreateOIDCTokenMinterOptions): Promise<OIDCTokenMinter> {
  return new OIDCTokenMinter({
    ...opts,
    keyProvider: await resolveOIDCKeyProvider(opts),
  });
}

/**
 * One-shot convenience: creates a minter and mints a single OIDC access token
 * via the JWT bearer grant. Server-side only — never mint tokens in
 * browser/client code. See `OIDCTokenMinter.mintToken()` for thrown errors.
 *
 * @example
 * ```ts
 * import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
 * import { mintOIDCToken } from '@dnsid-ai/oidc';
 *
 * const keyProvider = await LocalKeyProvider.load('.dnsid/keys.json', true);
 * const token = await mintOIDCToken({
 *   domain: 'agent.example.com',
 *   keyProvider,
 *   issuer: 'https://issuer.example.com',
 *   audience: 'https://api.example.com',
 *   scopes: ['openid', 'dnsid'],
 * });
 * console.log(token.accessToken);
 * ```
 */
export async function mintOIDCToken(opts: MintOIDCTokenOptions): Promise<OIDCTokenResponse> {
  const minter = await createOIDCTokenMinter(opts);
  return minter.mintToken(opts);
}

/**
 * Wraps a raw private JWK in an in-memory KeyProvider suitable for signing
 * OIDC assertions. Derives the public key, kid (RFC 7638 thumbprint), and alg
 * when absent. The provider is signing-only: key generation, activation, and
 * supersession are not supported.
 *
 * @throws ArgumentError if the JWK is not an object with a non-empty d member.
 * @throws ValidationError if the key type/curve is unsupported for signing.
 */
export async function createOIDCKeyProviderFromJWK(privateJwk: OIDCPrivateJWK): Promise<KeyProvider> {
  return PrivateJWKKeyProvider.fromJWK(privateJwk);
}

/**
 * DNSid OIDC federation profile for a single agent: mints client assertions,
 * exchanges them for access tokens, and verifies inbound OIDC tokens back to
 * DNSid identity records.
 *
 * Token minting requires the agent's private operational key — keep it
 * server-side; never construct a profile in browser/client code.
 */
export class OIDCProfile {
  /** Builds a profile sharing an identity manager's domain, operational key provider, and identity resolver. */
  static fromIdentityManager(identityManager: SigningIdentityManager, oidc?: OIDCProfileConfig): OIDCProfile {
    return new OIDCProfile({
      domain: requireLocalDomain(identityManager),
      keyProvider: identityManager.getKeyProvider(),
      identityResolver: identityManager,
      oidc,
    });
  }

  private readonly domain: string;
  private readonly keyProvider: KeyProvider | null;
  private readonly identityResolver?: IdentityResolver;
  private readonly fetch: typeof globalThis.fetch;
  private readonly config: OIDCProfileConfig;

  /** @throws ArgumentError if domain is not a valid agent FQDN. */
  constructor(opts: OIDCProfileOptions) {
    try {
      this.domain = normalizeFQDN(opts.domain, true);
    } catch (e) {
      throw new ArgumentError(`domain is not a valid agent FQDN: ${(e as Error).message}`);
    }
    this.keyProvider = opts.keyProvider ?? null;
    this.identityResolver = opts.identityResolver;
    this.fetch = opts.fetch ?? createSsrfSafeFetch();
    this.config = Object.freeze({ ...opts.oidc });
    validateOidcTimes(this.config);
  }

  /**
   * Mints a signed JWT bearer client assertion for the given issuer
   * (iss/sub/fqdn = agent domain, aud = issuer, fresh jti).
   *
   * @throws ArgumentError if the issuer URL is invalid, the expiry is not
   *   positive or exceeds the maximum lifetime, or additionalClaims override
   *   a reserved claim.
   * @throws ValidationError if the operational signing key is unsupported for JWS.
   * @throws VerificationError (SignatureInvalid) if the produced signature does
   *   not verify against the active operational key.
   */
  async createOIDCAssertion(opts: OIDCAssertionOptions): Promise<string> {
    if (!this.keyProvider) throw new ArgumentError('OIDC assertion signing requires a keyProvider');
    return createOIDCAssertionJWT(this.domain, this.keyProvider, opts, {
      assertionLifetime: this.config.assertionLifetime,
      maxAssertionLifetime: this.config.maxAssertionLifetime,
      allowHttpLoopbackIssuer: this.config.allowHttpLoopbackIssuer,
    });
  }

  /**
   * Fetches and validates the issuer's discovery document. The document's
   * issuer must match exactly, and token_endpoint/jwks_uri must share the
   * issuer's origin.
   *
   * @throws ArgumentError if the issuer is not an exact HTTPS URL.
   * @throws VerificationError if the fetch fails, redirects, or the document is invalid.
   */
  async discoverOIDCIssuer(issuer: string, options: VerificationOptions = {}): Promise<OIDCDiscoveryDocument> {
    return withVerificationBudget(signal => discoverExplicitOIDCIssuer(this.fetch, issuer, undefined, {
      allowHttpLoopbackIssuer: this.config.allowHttpLoopbackIssuer,
      timeoutMs: this.config.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS,
      signal,
    }), options);
  }

  /**
   * Discovers the issuer and performs the RFC 7523 JWT bearer exchange. When
   * `assertion` is supplied it is presented as-is (its aud must exactly match
   * the discovered issuer); otherwise a fresh assertion is minted.
   *
   * @returns The normalized token response.
   * @throws ArgumentError if audience is missing or a supplied assertion is
   *   not a valid JWT addressed to the issuer.
   * @throws VerificationError if discovery or transport fails, or the response is malformed.
   * @throws OAuthError if the token endpoint returns an OAuth error response.
   */
  async exchangeOIDCToken(opts: OIDCTokenExchangeOptions): Promise<OIDCTokenResponse> {
    if (!opts.assertion && !this.keyProvider) {
      throw new ArgumentError('OIDC assertion signing requires a keyProvider');
    }
    if (!opts.audience) throw new ArgumentError('audience is required');
    const doc = await this.discoverOIDCIssuer(opts.issuer);
    const assertion = opts.assertion ?? await this.createOIDCAssertion({ issuer: doc.issuer });
    if (opts.assertion) {
      let assertionClaims: JWTPayload;
      try {
        assertionClaims = decodeJwt(opts.assertion);
      } catch {
        throw new ArgumentError('OIDC assertion must be a valid JWT');
      }
      if (!audienceExactlyMatches(assertionClaims.aud, doc.issuer)) {
        throw new ArgumentError('OIDC assertion audience must exactly match issuer');
      }
    }

    return exchangeOIDCTokenAt(this.fetch, {
      issuer: doc.issuer,
      tokenEndpoint: doc.token_endpoint,
      assertion,
      audience: opts.audience,
      scope: resolveScope(opts.scope, undefined, this.config.defaultScope),
      allowHttpLoopbackIssuer: this.config.allowHttpLoopbackIssuer,
      timeoutMs: this.config.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS,
    });
  }

  /** Like {@link OIDCProfile.exchangeOIDCToken} but always mints a fresh assertion, ignoring any supplied one. */
  getOIDCToken(opts: OIDCTokenExchangeOptions): Promise<OIDCTokenResponse> {
    const { assertion: _assertion, ...fresh } = opts;
    return this.exchangeOIDCToken(fresh);
  }

  /**
   * Verifies an OIDC token end-to-end: issuer allow-list, exact audience
   * match, header and claim hygiene, signature against the issuer's published
   * JWKS (restricted to allowedTokenAlgorithms), and timestamp checks with the
   * configured clock skew. Unless `verifyDnsidSubject` is false, the token
   * subject is then verified as a DNSid identity record via the profile's
   * identityResolver.
   *
   * @returns The verified subject, claims, and (unless skipped) the DNSid
   *   verification result for the subject domain.
   * @throws ArgumentError if the issuer URL is invalid or audience is missing.
   * @throws VerificationError with a VerificationCode (RecordInvalid,
   *   SignatureInvalid, or TLSError) identifying the first check that failed —
   *   including when the issuer is not in allowedIssuers, or when subject
   *   verification is requested without an identityResolver.
   */
  async verifyOIDCToken(token: string, opts: VerifyOIDCTokenOptions): Promise<VerifiedOIDCSubject> {
    return withVerificationBudget(signal => this.verifyTokenWithinBudget(token, { ...opts, signal }), opts);
  }

  private async verifyTokenWithinBudget(token: string, opts: VerifyOIDCTokenOptions): Promise<VerifiedOIDCSubject> {
    const issuer = validateExactOIDCIssuer(opts.issuer, this.config.allowHttpLoopbackIssuer);
    if (!(this.config.allowedIssuers ?? []).includes(issuer)) {
      throw new VerificationError('OIDC issuer is not allowed', { code: VerificationCode.RecordInvalid });
    }
    if (typeof opts.audience !== 'string' || !opts.audience) throw new ArgumentError('audience is required');

    let header: ReturnType<typeof decodeProtectedHeader>;
    let claims: JWTPayload;
    try {
      const compact = parseCompactJose(token);
      header = compact.header as ReturnType<typeof decodeProtectedHeader>;
      claims = parseJoseObject(compact.payload) as JWTPayload;
    } catch {
      throw new VerificationError('malformed JWT', { code: VerificationCode.RecordInvalid });
    }
    if (claims.iss !== issuer) throw new VerificationError('OIDC issuer mismatch', { code: VerificationCode.RecordInvalid });
    if (Object.keys(header).some(k => !['alg', 'kid', 'typ'].includes(k))) {
      throw new VerificationError('unsupported OIDC token header', { code: VerificationCode.RecordInvalid });
    }
    if (!audienceExactlyMatches(claims.aud, opts.audience)) {
      throw new VerificationError('OIDC audience mismatch', { code: VerificationCode.RecordInvalid });
    }

    const allowedAlgs = validateAllowedTokenAlgorithms(this.config.allowedTokenAlgorithms ?? DEFAULT_TOKEN_ALGS);
    if (!allowedAlgs.includes(header.alg!)) throw new VerificationError('OIDC token algorithm is not allowed', { code: VerificationCode.SignatureInvalid });
    validateTokenTimes(claims, this.config.clockSkew ?? DEFAULT_CLOCK_SKEW_SECONDS);
    const doc = await this.discoverOIDCIssuer(issuer, { signal: opts.signal });
    const jwksResponse = await fetchOIDC(this.fetch, doc.jwks_uri, { redirect: 'manual' }, {
      signal: opts.signal,
      allowHttpLoopbackIssuer: this.config.allowHttpLoopbackIssuer,
      timeoutMs: this.config.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS,
    });
    if (jwksResponse.status !== 200) throw new VerificationError('OIDC JWKS fetch failed', { code: VerificationCode.TLSError });
    const jwks = requireRecord(await waitForVerification(() => readLimitedJson(jwksResponse), opts.signal!), 'OIDC JWKS must be a JSON object');
    if (!Array.isArray(jwks.keys)) {
      throw new VerificationError('OIDC JWKS keys must be an array', { code: VerificationCode.RecordInvalid });
    }
    if (typeof header.alg !== 'string') {
      throw new VerificationError('OIDC token missing signing algorithm', { code: VerificationCode.SignatureInvalid });
    }
    if (!allowedAlgs.includes(header.alg)) {
      throw new VerificationError(`OIDC token algorithm is not allowed: ${header.alg}`, { code: VerificationCode.SignatureInvalid });
    }
    const signingKey = jwks.keys.find((k): k is DnsIdJWK => typeof k === 'object' && k !== null && (k as DnsIdJWK).kid === header.kid);
    if (!signingKey || !oidcKeySupportsAlg(signingKey, header.alg)) {
      throw new VerificationError('OIDC signing key mismatch', { code: VerificationCode.SignatureInvalid });
    }
    const clockSkew = this.config.clockSkew ?? DEFAULT_CLOCK_SKEW_SECONDS;
    validateTokenTimes(claims, clockSkew);

    let verifiedClaims: JWTPayload;
    try {
      await compactVerify(token, await importJWK(signingKey as JWK, header.alg), { algorithms: allowedAlgs });
      // Claim policy is checked above and below with an unrounded clock; jwtVerify rounds it down.
      verifiedClaims = claims;
    } catch (e) {
      throw new VerificationError(`OIDC token verification failed: ${(e as Error).message}`, { code: VerificationCode.SignatureInvalid });
    }

    if (typeof verifiedClaims.sub !== 'string' || !verifiedClaims.sub) {
      throw new VerificationError('OIDC token missing sub', { code: VerificationCode.RecordInvalid });
    }
    if (opts.verifyDnsidSubject !== false && !this.identityResolver) {
      throw new VerificationError('OIDC token subject verification requires an identityResolver', { code: VerificationCode.RecordInvalid });
    }
    const verifiedDomain = opts.verifyDnsidSubject === false ? undefined : await waitForVerification(() => this.identityResolver!.verifyDomain(verifiedClaims.sub!, opts.peerCert, { signal: opts.signal }), opts.signal!);
    validateTokenTimes(verifiedClaims, clockSkew);
    return { issuer, subject: verifiedClaims.sub, audience: opts.audience, verifiedDomain, claims: verifiedClaims };
  }
}

/**
 * Creates an {@link OIDCProfile}.
 *
 * @throws ArgumentError if domain is not a valid agent FQDN.
 * @example
 * ```ts
 * import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
 * import { createOIDCProfile } from '@dnsid-ai/oidc';
 *
 * const profile = createOIDCProfile({
 *   domain: 'agent.example.com',
 *   keyProvider: await LocalKeyProvider.load('.dnsid/keys.json', true),
 *   oidc: { allowedIssuers: ['https://issuer.example.com'] },
 * });
 * const token = await profile.getOIDCToken({
 *   issuer: 'https://issuer.example.com',
 *   audience: 'https://api.example.com',
 * });
 * ```
 */
export function createOIDCProfile(opts: OIDCProfileOptions): OIDCProfile {
  return new OIDCProfile(opts);
}

/** Selects the signing key source: exactly one of keyProvider or privateJwk. */
async function resolveOIDCKeyProvider(opts: CreateOIDCTokenMinterOptions): Promise<KeyProvider> {
  if (opts.keyProvider && opts.privateJwk) {
    throw new ArgumentError('provide either keyProvider or privateJwk, not both');
  }
  if (opts.keyProvider) return opts.keyProvider;
  if (opts.privateJwk) return createOIDCKeyProviderFromJWK(opts.privateJwk);
  throw new ArgumentError('keyProvider or privateJwk is required');
}

/**
 * In-memory, signing-only KeyProvider backed by a single non-extractable
 * private key imported from a raw JWK. Lifecycle operations (generate,
 * activate, supersede) are unsupported.
 */
class PrivateJWKKeyProvider implements KeyProvider {
  private constructor(
    private readonly publicJwk: DnsIdJWK,
    private readonly privateKey: CryptoKey,
  ) {}

  static async fromJWK(privateJwk: OIDCPrivateJWK): Promise<PrivateJWKKeyProvider> {
    if (!privateJwk || typeof privateJwk !== 'object' || typeof privateJwk.d !== 'string' || privateJwk.d === '') {
      throw new ArgumentError('privateJwk must be a private JWK with a d member');
    }
    const publicJwk = publicJwkFromPrivateJWK(privateJwk);
    if (!publicJwk.kid) publicJwk.kid = await jwkThumbprint(publicJwk);
    if (!publicJwk.alg) publicJwk.alg = jwkSignatureAlg(publicJwk);
    if (!publicJwk.use) publicJwk.use = 'sig';
    const alg = jwkSignatureAlg(publicJwk);
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      privateJwk as JsonWebKey,
      importAlgorithmForSigningAlg(alg, publicJwk),
      false,
      ['sign'],
    );
    return new PrivateJWKKeyProvider(publicJwk, privateKey);
  }

  async signingKey(): Promise<DnsIdJWK> {
    return { ...this.publicJwk };
  }

  async jwk(kid: string): Promise<DnsIdJWK> {
    if (kid !== this.publicJwk.kid) throw new ArgumentError(`key not found: ${kid}`);
    return this.signingKey();
  }

  async listKeyIds(): Promise<string[]> {
    return [this.publicJwk.kid];
  }

  async sign(payload: Uint8Array): Promise<Uint8Array> {
    const sig = await crypto.subtle.sign(
      signAlgorithmForSigningAlg(jwkSignatureAlg(this.publicJwk)),
      this.privateKey,
      toArrayBuffer(payload),
    );
    return new Uint8Array(sig);
  }

  async signKey(kid: string, payload: Uint8Array): Promise<Uint8Array> {
    if (kid !== this.publicJwk.kid) throw new ArgumentError(`key not found: ${kid}`);
    return this.sign(payload);
  }

  async generateKey(): Promise<string> {
    throw new ArgumentError('private JWK key provider does not support key generation');
  }

  async activate(_kid: string): Promise<void> {
    throw new ArgumentError('private JWK key provider does not support key activation');
  }

  async supersede(_kid: string): Promise<void> {
    throw new ArgumentError('private JWK key provider does not support key purging');
  }

  /** @deprecated Use supersede(). */
  async purge(kid: string): Promise<void> {
    await this.supersede(kid);
  }
}

/** Derives the public JWK from a private JWK by copying only public members (never d). */
function publicJwkFromPrivateJWK(privateJwk: OIDCPrivateJWK): DnsIdJWK {
  const publicJwk: DnsIdJWK = { kty: privateJwk.kty, kid: privateJwk.kid ?? '' };
  copyStringMember(privateJwk, publicJwk, 'alg');
  copyStringMember(privateJwk, publicJwk, 'use');
  copyStringMember(privateJwk, publicJwk, 'crv');
  copyStringMember(privateJwk, publicJwk, 'x');
  copyStringMember(privateJwk, publicJwk, 'y');
  copyStringMember(privateJwk, publicJwk, 'n');
  copyStringMember(privateJwk, publicJwk, 'e');
  return publicJwk;
}

function copyStringMember(source: Record<string, unknown>, target: Record<string, unknown>, key: string): void {
  if (typeof source[key] === 'string') target[key] = source[key];
}

/**
 * Builds and signs the JWT bearer client assertion (iss/sub/fqdn = agent
 * domain, aud = issuer, fresh jti), enforcing lifetime bounds and reserved
 * claims, and verifying the signature against the active operational key
 * before returning it.
 */
async function createOIDCAssertionJWT(
  domain: string,
  keyProvider: KeyProvider,
  opts: OIDCAssertionOptions,
  config: Pick<OIDCProfileConfig, 'assertionLifetime' | 'maxAssertionLifetime' | 'allowHttpLoopbackIssuer'>,
): Promise<string> {
  const issuer = validateExactOIDCIssuer(opts.issuer, config.allowHttpLoopbackIssuer);
  validateOidcTimes(config);
  const expiry = opts.expiry === undefined ? (config.assertionLifetime ?? DEFAULT_ASSERTION_LIFETIME_SECONDS) : opts.expiry;
  const maxLifetime = config.maxAssertionLifetime ?? DEFAULT_MAX_ASSERTION_LIFETIME_SECONDS;
  if (!Number.isFinite(expiry) || expiry <= 0) throw new ArgumentError('OIDC assertion expiry must be positive');
  if (expiry > maxLifetime) throw new ArgumentError('OIDC assertion expiry exceeds maximum lifetime');

  const now = Math.floor(Date.now() / 1000);
  if (now + expiry <= now) throw new ArgumentError('OIDC assertion expiry is below timestamp resolution');
  const claims: Record<string, unknown> = {
    iss: domain,
    sub: domain,
    aud: [issuer],
    iat: now,
    exp: now + expiry,
    jti: crypto.randomUUID(),
    fqdn: domain,
  };
  for (const [k, v] of Object.entries(opts.additionalClaims ?? {})) {
    if (RESERVED_ASSERTION_CLAIMS.has(k)) {
      throw new ArgumentError(`additionalClaims must not override reserved claim: ${k}`);
    }
    claims[k] = v;
  }

  const signingKey = await keyProvider.signingKey();
  const alg = jwkSignatureAlg(signingKey);
  return signCompact({ alg, kid: signingKey.kid, typ: 'JWT' }, claims, keyProvider, signingKey, alg);
}

/**
 * Merges per-call endpoint options over the minter defaults. Any per-call
 * endpoint selector (tokenEndpoint, issuer, or serverUrl) switches modes
 * wholesale rather than mixing with defaults from another mode.
 */
function endpointOptionsForCall(defaults: OIDCTokenEndpointOptions, overrides: OIDCTokenEndpointOptions): OIDCTokenEndpointOptions {
  if (overrides.tokenEndpoint !== undefined) {
    return validateEndpointMode({
      issuer: overrides.issuer ?? (overrides.serverUrl === undefined ? defaults.issuer : undefined),
      serverUrl: overrides.serverUrl,
      discoveryUrl: overrides.discoveryUrl,
      tokenEndpoint: overrides.tokenEndpoint,
    });
  }
  if (overrides.issuer !== undefined || overrides.serverUrl !== undefined) {
    return validateEndpointMode({
      issuer: overrides.issuer,
      serverUrl: overrides.serverUrl,
      discoveryUrl: overrides.discoveryUrl,
    });
  }
  return validateEndpointMode({ ...defaults, discoveryUrl: overrides.discoveryUrl ?? defaults.discoveryUrl });
}

/**
 * Enforces the endpoint-mode contract of {@link OIDCTokenEndpointOptions}.
 * @throws ArgumentError if modes are mixed or a selected member is empty.
 */
function validateEndpointMode(opts: OIDCTokenEndpointOptions): OIDCTokenEndpointOptions {
  if (opts.tokenEndpoint !== undefined) {
    if (opts.tokenEndpoint === '') throw new ArgumentError('tokenEndpoint must not be empty');
    if (opts.issuer === undefined) throw new ArgumentError('issuer is required when tokenEndpoint is configured');
    if (opts.issuer === '') throw new ArgumentError('issuer must not be empty when tokenEndpoint is configured');
    if (opts.serverUrl !== undefined || opts.discoveryUrl !== undefined) {
      throw new ArgumentError('tokenEndpoint mode supports issuer and tokenEndpoint only');
    }
  } else if (opts.issuer !== undefined) {
    if (opts.issuer === '') throw new ArgumentError('issuer must not be empty');
    if (opts.serverUrl !== undefined) throw new ArgumentError('provide either issuer or serverUrl, not both');
  } else if (opts.serverUrl !== undefined) {
    if (opts.serverUrl === '') throw new ArgumentError('serverUrl must not be empty');
  } else if (opts.discoveryUrl !== undefined) {
    throw new ArgumentError('discoveryUrl requires issuer or serverUrl');
  }
  return opts;
}

/** Resolves the issuer and token endpoint for minting, via explicit endpoint, issuer discovery, or serverUrl discovery. */
async function resolveOIDCTokenEndpoint(
  fetch: typeof globalThis.fetch,
  opts: OIDCTokenEndpointOptions,
  fetchOptions: OIDCFetchOptions,
): Promise<ResolvedOIDCTokenEndpoint> {
  if (opts.tokenEndpoint) {
    if (!opts.issuer) throw new ArgumentError('issuer is required when tokenEndpoint is configured');
    const issuer = validateOIDCMintIssuerRoot(opts.issuer, fetchOptions.allowHttpLoopbackIssuer);
    validateSameOriginEndpoint(opts.tokenEndpoint, issuer, 'token_endpoint');
    return { issuer, tokenEndpoint: opts.tokenEndpoint };
  }
  if (opts.issuer) {
    const doc = await discoverMintOIDCIssuer(fetch, opts.issuer, opts.discoveryUrl, fetchOptions);
    return { issuer: doc.issuer, tokenEndpoint: doc.token_endpoint, discoveryDocument: doc };
  }
  if (opts.serverUrl) {
    const serverUrl = validateBaseUrl(opts.serverUrl, 'serverUrl', fetchOptions.allowHttpLoopbackIssuer);
    const doc = await discoverServerOIDCIssuer(fetch, serverUrl, opts.discoveryUrl, fetchOptions);
    return { issuer: doc.issuer, tokenEndpoint: `${serverUrl}/token`, discoveryDocument: doc };
  }
  throw new ArgumentError('issuer, serverUrl, or tokenEndpoint is required');
}

/** Discovery for verification/exchange: issuer must match exactly; token_endpoint and jwks_uri must share the issuer origin. */
async function discoverExplicitOIDCIssuer(
  fetch: typeof globalThis.fetch,
  issuer: string,
  discoveryUrl: string | undefined,
  fetchOptions: OIDCFetchOptions,
): Promise<OIDCDiscoveryDocument> {
  issuer = validateExactOIDCIssuer(issuer, fetchOptions.allowHttpLoopbackIssuer);
  const doc = await fetchOIDCDiscovery(fetch, discoveryUrl ?? `${issuer}/.well-known/openid-configuration`, fetchOptions);
  if (doc.issuer !== issuer) throw new VerificationError('OIDC discovery issuer mismatch', { code: VerificationCode.RecordInvalid });
  validateSameOriginEndpoint(doc.token_endpoint, issuer, 'token_endpoint');
  validateSameOriginEndpoint(doc.jwks_uri, issuer, 'jwks_uri');
  return doc;
}

/** Discovery for minting: issuer must be an exact issuer root and token_endpoint must share its origin. */
async function discoverMintOIDCIssuer(
  fetch: typeof globalThis.fetch,
  issuer: string,
  discoveryUrl: string | undefined,
  fetchOptions: OIDCFetchOptions,
): Promise<OIDCDiscoveryDocument> {
  issuer = validateOIDCMintIssuerRoot(issuer, fetchOptions.allowHttpLoopbackIssuer);
  const doc = await fetchOIDCDiscovery(fetch, discoveryUrl ?? `${issuer}/.well-known/openid-configuration`, fetchOptions);
  if (doc.issuer !== issuer) throw new VerificationError('OIDC discovery issuer mismatch', { code: VerificationCode.RecordInvalid });
  validateSameOriginEndpoint(doc.token_endpoint, issuer, 'token_endpoint');
  return doc;
}

/** Discovery relative to a base server URL; the issuer is taken (and validated) from the document itself. */
async function discoverServerOIDCIssuer(
  fetch: typeof globalThis.fetch,
  serverUrl: string,
  discoveryUrl: string | undefined,
  fetchOptions: OIDCFetchOptions,
): Promise<OIDCDiscoveryDocument> {
  const doc = await fetchOIDCDiscovery(fetch, discoveryUrl ?? `${serverUrl}/.well-known/openid-configuration`, fetchOptions);
  if (typeof doc.issuer !== 'string' || doc.issuer === '') {
    throw new VerificationError('OIDC discovery document missing issuer', { code: VerificationCode.RecordInvalid });
  }
  const issuer = validateExactOIDCIssuer(doc.issuer, fetchOptions.allowHttpLoopbackIssuer);
  return { ...doc, issuer };
}

/** Fetches a discovery document with redirects disallowed and a bounded, JSON-object body. */
async function fetchOIDCDiscovery(
  fetch: typeof globalThis.fetch,
  discoveryUrl: string,
  fetchOptions: OIDCFetchOptions,
): Promise<OIDCDiscoveryDocument> {
  validateAbsoluteUrl(discoveryUrl, 'discoveryUrl', fetchOptions.allowHttpLoopbackIssuer);
  const response = await fetchOIDC(fetch, discoveryUrl, { redirect: 'manual' }, fetchOptions);
  if (response.status >= 300 && response.status < 400) throw new VerificationError('OIDC discovery redirects are not allowed', { code: VerificationCode.TLSError });
  if (response.status !== 200) throw new VerificationError('OIDC discovery failed', { code: VerificationCode.TLSError });
  const doc = requireRecord(await readLimitedJson(response), 'OIDC discovery document must be a JSON object') as Partial<OIDCDiscoveryDocument>;
  if (typeof doc.issuer !== 'string' || doc.issuer === '') {
    throw new VerificationError('OIDC discovery document missing issuer', { code: VerificationCode.RecordInvalid });
  }
  return doc as OIDCDiscoveryDocument;
}

interface ExchangeOIDCTokenAtOptions {
  issuer: string;
  tokenEndpoint: string;
  assertion: string;
  audience: string;
  scope?: string;
  allowHttpLoopbackIssuer?: boolean;
  timeoutMs?: number;
}

/**
 * POSTs the RFC 7523 jwt-bearer grant to the token endpoint and normalizes
 * the response. Redirects are rejected; error bodies surface as OAuthError.
 */
async function exchangeOIDCTokenAt(fetch: typeof globalThis.fetch, opts: ExchangeOIDCTokenAtOptions): Promise<OIDCTokenResponse> {
  const form = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: opts.assertion,
    audience: opts.audience,
  });
  if (opts.scope !== undefined) form.set('scope', opts.scope);
  const response = await fetchOIDC(fetch, opts.tokenEndpoint, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
  }, {
    allowHttpLoopbackIssuer: opts.allowHttpLoopbackIssuer,
    timeoutMs: opts.timeoutMs,
  });
  if (response.status >= 300 && response.status < 400) throw new VerificationError('OIDC token endpoint redirects are not allowed', { code: VerificationCode.TLSError });
  if (response.status !== 200) {
    const body = await readLimitedJson(response).catch(() => ({}));
    if (response.status >= 200 && response.status < 300) {
      throw new VerificationError(`OIDC token endpoint returned unexpected successful status ${response.status}`, { code: VerificationCode.RecordInvalid });
    }
    const raw = requireRecord(body, 'OIDC token response must be a JSON object');
    throw new OAuthError(asString(raw.error), asString(raw.error_description));
  }
  const raw = requireRecord(await readLimitedJson(response), 'OIDC token response must be a JSON object');
  if (typeof raw.access_token !== 'string' || !raw.access_token) {
    throw new VerificationError('OIDC token response missing access_token', { code: VerificationCode.RecordInvalid });
  }
  if (typeof raw.token_type !== 'string' || raw.token_type.toLowerCase() !== 'bearer') {
    throw new VerificationError('OIDC token response token_type must be Bearer', { code: VerificationCode.RecordInvalid });
  }
  return {
    accessToken: raw.access_token,
    idToken: asString(raw.id_token),
    tokenType: raw.token_type,
    expiresIn: typeof raw.expires_in === 'number' ? raw.expires_in : undefined,
    scope: asString(raw.scope),
    issuer: opts.issuer,
    tokenEndpoint: opts.tokenEndpoint,
    raw,
  };
}

/** Resolves the effective scope: scope, else scopes joined with spaces, else the default; empty string omits scope entirely. */
function resolveScope(scope: string | undefined, scopes: readonly string[] | undefined, defaultScope: string | undefined): string | undefined {
  if (scope !== undefined && scopes !== undefined) {
    throw new ArgumentError('provide either scope or scopes, not both');
  }
  const value = scopes !== undefined ? scopes.join(' ') : scope ?? defaultScope ?? DEFAULT_SCOPE;
  return value === '' ? undefined : value;
}

/**
 * Validates that an issuer is an exact absolute URL — no query, fragment, or
 * trailing slash — using HTTPS (or plain-HTTP loopback when explicitly allowed).
 *
 * @returns The validated issuer string, unchanged.
 * @throws ArgumentError if the issuer does not meet these requirements.
 */
export function validateExactOIDCIssuer(issuer: string, allowHttpLoopbackIssuer = false): string {
  let url: URL;
  try { url = new URL(issuer); } catch { throw new ArgumentError('invalid OIDC issuer URL'); }
  const path = url.pathname === '/' ? '' : url.pathname;
  if (issuer !== `${url.protocol}//${url.host}${path}` || issuer.endsWith('/')) {
    throw new ArgumentError('OIDC issuer must be an exact URL without query, fragment, or trailing slash');
  }
  if (url.protocol !== 'https:' && !(allowHttpLoopbackIssuer && url.protocol === 'http:' && isLocalhost(url.hostname))) {
    throw new ArgumentError('OIDC issuer must use HTTPS');
  }
  return issuer;
}

/** Stricter issuer check for minting: an exact origin-only issuer root, with known DNSid API hosts rejected. */
function validateOIDCMintIssuerRoot(issuer: string, allowHttpLoopbackIssuer = false): string {
  let url: URL;
  try { url = new URL(issuer); } catch { throw new ArgumentError('invalid OIDC issuer URL'); }
  if (issuer !== `${url.protocol}//${url.host}`) {
    throw new ArgumentError('OIDC issuer must be an exact issuer root with no path, query, fragment, or trailing slash');
  }
  const host = unbracketHost(url.hostname).toLowerCase().replace(/\.$/, '');
  if (host === 'api.dnsid.dev' || host === 'api.dnsid.ai') {
    throw new ArgumentError(`API host ${host} is not a valid OIDC issuer`);
  }
  if (url.protocol !== 'https:' && !(allowHttpLoopbackIssuer && url.protocol === 'http:' && isLocalhost(url.hostname))) {
    throw new ArgumentError('OIDC issuer must use HTTPS');
  }
  return issuer;
}

/** Normalizes a base URL to origin + path with no query, fragment, or trailing slashes. */
function validateBaseUrl(raw: string, name: string, allowHttpLoopbackIssuer = false): string {
  const url = validateAbsoluteUrl(raw, name, allowHttpLoopbackIssuer);
  if (url.search || url.hash) throw new ArgumentError(`${name} must not include query or fragment`);
  const path = url.pathname === '/' ? '' : url.pathname.replace(/\/+$/, '');
  return `${url.protocol}//${url.host}${path}`;
}

function validateAbsoluteUrl(raw: string, name: string, allowHttpLoopbackIssuer = false): URL {
  let url: URL;
  try { url = new URL(raw); } catch { throw new ArgumentError(`invalid OIDC ${name} URL`); }
  const loopbackHttp = allowHttpLoopbackIssuer && url.protocol === 'http:' && isLocalhost(url.hostname);
  if (url.protocol !== 'https:' && !loopbackHttp) {
    throw new ArgumentError(`OIDC ${name} must use HTTPS`);
  }
  if (url.hash) throw new ArgumentError(`OIDC ${name} must not include a fragment`);
  return url;
}

/** Requires a discovered endpoint to sit on the issuer's origin with a non-root path and no query/fragment. */
function validateSameOriginEndpoint(endpoint: unknown, issuer: string, name: 'token_endpoint' | 'jwks_uri'): void {
  if (typeof endpoint !== 'string') throw new VerificationError(`OIDC ${name} is required`, { code: VerificationCode.RecordInvalid });
  let url: URL;
  try { url = new URL(endpoint); } catch { throw new VerificationError(`invalid OIDC ${name}`, { code: VerificationCode.RecordInvalid }); }
  const issuerURL = new URL(issuer);
  if (url.protocol !== issuerURL.protocol || url.host !== issuerURL.host) {
    throw new VerificationError(`OIDC ${name} must use the issuer origin`, { code: VerificationCode.RecordInvalid });
  }
  if (!url.pathname || url.pathname === '/' || url.search || url.hash) {
    throw new VerificationError(`invalid OIDC ${name}`, { code: VerificationCode.RecordInvalid });
  }
}

function validateTimeoutMs(timeoutMs: number): number {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new ArgumentError('OIDC fetch timeout must be a positive number of milliseconds');
  }
  return timeoutMs;
}

function isLocalhost(hostname: string): boolean {
  const host = unbracketHost(hostname);
  const family = net.isIP(host);
  return host === 'localhost'
    || (family === 4 && host.split('.')[0] === '127')
    || (family === 6 && host === '::1');
}

/** True only for an exact string match or a single-element array containing it. */
function audienceExactlyMatches(value: unknown, expected: string): boolean {
  return value === expected || (Array.isArray(value) && value.length === 1 && value[0] === expected);
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

/** True if a JWKS key can legitimately verify the given JWS algorithm (its own alg, when present, must agree). */
function oidcKeySupportsAlg(key: DnsIdJWK, alg: string): boolean {
  if (key.alg !== undefined && key.alg !== alg) return false;
  if (key.kty === 'RSA') return /^RS(256|384|512)$/.test(alg) || /^PS(256|384|512)$/.test(alg);
  try { return jwkSignatureAlg({ ...key, alg }) === alg; } catch { return false; }
}

/** Rejects a configured token-algorithm allow-list containing algorithms this package does not support. */
function validateAllowedTokenAlgorithms(algs: string[]): string[] {
  for (const alg of algs) {
    if (!SIGNING_ALGS.has(alg)) {
      throw new VerificationError(`unsupported OIDC token algorithm: ${alg}`, { code: VerificationCode.SignatureInvalid });
    }
  }
  return algs;
}

/** Transport policy shared by all OIDC HTTP requests. */
interface OIDCFetchOptions {
  signal?: AbortSignal;
  allowHttpLoopbackIssuer?: boolean;
  timeoutMs?: number;
}

/**
 * Performs an OIDC HTTP request with transport safeguards: HTTPS-only (or
 * allowed HTTP loopback), a pre-flight DNS check rejecting unsafe target
 * addresses, and an overall timeout. Failures surface as VerificationError
 * (TLSError).
 */
async function fetchOIDC(fetch: typeof globalThis.fetch, input: RequestInfo | URL, init: RequestInit, options: OIDCFetchOptions = {}): Promise<Response> {
  const url = typeof input === 'string' ? new URL(input) : input instanceof URL ? input : new URL(input.url);
  const timeoutMs = validateTimeoutMs(options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS);
  const allowHttpLoopbackIssuer = options.allowHttpLoopbackIssuer ?? false;
  const loopbackHttp = allowHttpLoopbackIssuer && url.protocol === 'http:' && isLocalhost(url.hostname);
  if (url.protocol !== 'https:' && !loopbackHttp) {
    throw new VerificationError('OIDC request target is not allowed', { code: VerificationCode.TLSError });
  }
  const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs);
  if (!loopbackHttp) await waitForVerification(() => rejectUnsafeOIDCTarget(url.hostname, timeoutMs), signal);
  try {
    return await waitForVerification(() => fetch(input, { ...init, signal }), signal);
  } catch (e) {
    throw new VerificationError(`OIDC request failed: ${(e as Error).message}`, { code: VerificationCode.TLSError });
  }
}

/** Resolves the hostname (or takes an IP literal) and rejects targets on unsafe/private address ranges. */
async function rejectUnsafeOIDCTarget(hostname: string, timeoutMs: number): Promise<void> {
  try {
    const host = unbracketHost(hostname);
    const literalFamily = net.isIP(host);
    const addresses = literalFamily
      ? [{ address: host, family: literalFamily }]
      : await withTimeout(
        dnsPromises.lookup(host, { all: true }),
        timeoutMs,
        `OIDC issuer DNS lookup timed out after ${timeoutMs}ms`,
      );
    rejectUnsafeOIDCAddresses(addresses);
  } catch (e) {
    if (e instanceof VerificationError) throw e;
    throw new VerificationError(`OIDC issuer DNS lookup failed: ${(e as Error).message}`, { code: VerificationCode.TLSError });
  }
}

async function withTimeout<T>(operation: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => reject(new VerificationError(message, { code: VerificationCode.TLSError })), timeoutMs);
    timeout.unref?.();
  });
  try {
    return await Promise.race([operation, timeoutPromise]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

function rejectUnsafeOIDCAddresses(addresses: Array<{ address: string }>): void {
  const unsafe = addresses.find(({ address }) => isUnsafeIp(address));
  if (unsafe) {
    throw new VerificationError(`OIDC request target resolves to unsafe IP address: ${unsafe.address}`, { code: VerificationCode.TLSError });
  }
}

function unbracketHost(hostname: string): string {
  return hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
}

/** Requires a parsed JSON value to be a plain object, or throws VerificationError (RecordInvalid). */
function requireRecord(value: unknown, message: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new VerificationError(message, { code: VerificationCode.RecordInvalid });
  }
  return value as Record<string, unknown>;
}

/** Reads a response body as JSON, rejecting bodies over 1 MiB before buffering them fully. */
async function readLimitedJson(response: Response): Promise<unknown> {
  const body = response.body;
  if (!body) return null;
  const reader = body.getReader();
  try {
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_OIDC_JSON_BYTES) {
        await reader.cancel();
        throw new VerificationError('OIDC response exceeds maximum size', { code: VerificationCode.TLSError });
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    try {
      return JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      throw new VerificationError('OIDC response is not valid JSON', { code: VerificationCode.RecordInvalid });
    }
  } finally {
    reader.releaseLock();
  }
}

/**
 * Produces a compact JWS via the key provider, then verifies it against the
 * provided public key so a provider signing with stale key material fails
 * fast instead of minting an assertion the issuer will reject.
 */
async function signCompact(
  header: object,
  payload: object,
  keyProvider: KeyProvider,
  signingKey: DnsIdJWK,
  alg: string,
): Promise<string> {
  const headerB64 = toBase64Url(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = toBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = await keyProvider.sign(new TextEncoder().encode(signingInput));
  if (!(await verifyWithKey(signingInput, sig, signingKey, alg))) {
    throw new VerificationError('OIDC assertion signature does not match active signing key', { code: VerificationCode.SignatureInvalid });
  }
  return `${signingInput}.${toBase64Url(sig)}`;
}

/** Maps a JWS algorithm to WebCrypto importKey parameters for the private key. */
function importAlgorithmForSigningAlg(alg: string, key: DnsIdJWK): AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams {
  switch (alg) {
    case 'EdDSA':
      return { name: 'Ed25519' } as AlgorithmIdentifier;
    case 'ES256':
      return { name: 'ECDSA', namedCurve: 'P-256' };
    case 'ES384':
      return { name: 'ECDSA', namedCurve: 'P-384' };
    case 'ES512':
      return { name: 'ECDSA', namedCurve: 'P-521' };
    case 'RS256':
    case 'RS384':
    case 'RS512':
      return { name: 'RSASSA-PKCS1-v1_5', hash: rsaHashForAlg(alg) };
    case 'PS256':
    case 'PS384':
    case 'PS512':
      return { name: 'RSA-PSS', hash: rsaHashForAlg(alg) };
    default:
      throw new VerificationError(`unsupported JWK signature algorithm: ${key.kid ? `${key.kid} ` : ''}${alg}`, {
        code: VerificationCode.SignatureInvalid,
      });
  }
}

/** Maps a JWS algorithm to WebCrypto sign parameters. */
function signAlgorithmForSigningAlg(alg: string): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
  switch (alg) {
    case 'EdDSA':
      return { name: 'Ed25519' } as AlgorithmIdentifier;
    case 'ES256':
      return { name: 'ECDSA', hash: 'SHA-256' };
    case 'ES384':
      return { name: 'ECDSA', hash: 'SHA-384' };
    case 'ES512':
      return { name: 'ECDSA', hash: 'SHA-512' };
    case 'RS256':
    case 'RS384':
    case 'RS512':
      return { name: 'RSASSA-PKCS1-v1_5' };
    case 'PS256':
      return { name: 'RSA-PSS', saltLength: 32 };
    case 'PS384':
      return { name: 'RSA-PSS', saltLength: 48 };
    case 'PS512':
      return { name: 'RSA-PSS', saltLength: 64 };
    default:
      throw new VerificationError(`unsupported JWK signature algorithm: ${alg}`, { code: VerificationCode.SignatureInvalid });
  }
}

function rsaHashForAlg(alg: string): string {
  if (alg.endsWith('256')) return 'SHA-256';
  if (alg.endsWith('384')) return 'SHA-384';
  return 'SHA-512';
}

/**
 * Decodes a JWT's claims WITHOUT verifying its signature. Use only for
 * inspection or logging — never for authorization decisions; use
 * `OIDCProfile.verifyOIDCToken()` for those.
 *
 * @returns The decoded claims object.
 * @throws VerificationError (RecordInvalid) if the token is not a decodable
 *   JWT whose payload is a JSON object.
 */
export function decodeOIDCClaims(token: string): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length < 2) throw new VerificationError('malformed JWT', { code: VerificationCode.RecordInvalid });
  try {
    const claims = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[1]!))) as unknown;
    if (typeof claims !== 'object' || claims === null || Array.isArray(claims)) {
      throw new Error('invalid claims');
    }
    return claims as Record<string, unknown>;
  } catch {
    throw new VerificationError('malformed JWT', { code: VerificationCode.RecordInvalid });
  }
}
