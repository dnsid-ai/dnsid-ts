/**
 * DNSid Web Bot Auth profile.
 *
 * Signs outbound HTTP requests per Web Bot Auth (RFC 9421 HTTP Message Signatures
 * with the `web-bot-auth` tag) and serves the signed
 * `/.well-known/http-message-signatures-directory` document that advertises the
 * agent's public keys.
 *
 * Web Bot Auth requires an Ed25519 operational key; signing with any other key
 * type raises {@link ArgumentError}.
 *
 * @packageDocumentation
 */
import type { KeyProvider, SigningIdentityManager, DnsIdJWK } from '@identity-digital/dnsid-protocol';
import { requireLocalDomain } from '@identity-digital/dnsid-protocol';
import { ArgumentError, jwkSignatureAlg, jwkThumbprint, normalizeFQDN } from '@identity-digital/dnsid-protocol';
import type { ComponentIdentifier } from '@identity-digital/dnsid-http-signatures';
import { generateNonce, joseAlgToHttpSigAlg, sameComponent, serializeStructuredFieldValue, setDictionaryMember, signHttpMessage, validateComponentIdentifier } from '@identity-digital/dnsid-http-signatures';

/** Signature label used for the Web Bot Auth member in the `Signature`/`Signature-Input` dictionaries. */
export const WEB_BOT_AUTH_SIGNATURE_LABEL = 'sig1';
/** RFC 9421 `tag` parameter identifying a Web Bot Auth request signature. */
export const WEB_BOT_AUTH_TAG = 'web-bot-auth';
/** RFC 9421 `tag` parameter identifying a signed key-directory response. */
export const HTTP_MESSAGE_SIGNATURES_DIRECTORY_TAG = 'http-message-signatures-directory';
/** Well-known path where the agent's HTTP message signatures key directory is served. */
export const HTTP_MESSAGE_SIGNATURES_DIRECTORY_PATH = '/.well-known/http-message-signatures-directory';
/** Media type of the key directory document. */
export const HTTP_MESSAGE_SIGNATURES_DIRECTORY_MEDIA_TYPE = 'application/http-message-signatures-directory+json';
/** Default request-signature lifetime (seconds) when no TTL is configured. */
export const DEFAULT_WEB_BOT_AUTH_SIGNATURE_TTL_SECONDS = 60;
/** Default directory-signature lifetime and `Cache-Control` max-age (seconds). */
export const DEFAULT_DIRECTORY_SIGNATURE_TTL_SECONDS = 300;

/** Web Bot Auth key-discovery interpretation for the `Signature-Agent` member. */
export type SignatureAgentType = 'directory' | 'jwks_uri';

/** `Signature-Agent` discovery configuration. */
export interface SignatureAgentConfig {
  /** HTTPS origin for `directory`, or the direct HTTPS endpoint for `jwks_uri`. */
  uri?: string;
  /** Discovery interpretation. Default: `directory`. */
  type?: SignatureAgentType;
}

/** Profile-level Web Bot Auth configuration. All members are optional; defaults are noted per member. */
export interface WebBotAuthConfig {
  /**
   * Signature-Agent URI and discovery type. Defaults to the domain's HTTPS origin
   * with `type=directory`.
   */
  signatureAgent?: SignatureAgentConfig;
  /** @deprecated Use `signatureAgent.uri`. Retained as a direct `jwks_uri` endpoint. */
  directoryURL?: string;
  /** Request-signature lifetime in seconds. Defaults to {@link DEFAULT_WEB_BOT_AUTH_SIGNATURE_TTL_SECONDS}. */
  signatureTTL?: number;
  /** Whether signed requests include (and cover) the `Signature-Agent` header. Defaults to true. */
  includeSignatureAgent?: boolean;
  /** Directory-signature lifetime in seconds; also sets the response `Cache-Control` max-age. Defaults to {@link DEFAULT_DIRECTORY_SIGNATURE_TTL_SECONDS}. */
  directorySignatureTTL?: number;
  /** Allowed verification clock skew in seconds. Reserved for the future verifier API. Default: 5. */
  clockSkew?: number;
}

/** Constructor options for {@link WebBotAuthProfile}. */
export interface WebBotAuthProfileOptions {
  /** Agent FQDN the profile signs for (e.g. `agent.example.com`). Normalized on construction. */
  domain: string;
  /** Key provider holding the agent's Ed25519 operational key. */
  keyProvider: KeyProvider;
  /** Optional Web Bot Auth configuration overrides. */
  webBotAuth?: WebBotAuthConfig;
}

/** Per-request overrides for {@link WebBotAuthProfile.createWebBotAuthSignedRequest}. */
export interface WebBotAuthSigningOptions {
  /** Extra covered components appended to the defaults (`@authority`, plus `content-digest`/`signature-agent` when present). Duplicates are ignored. */
  additionalComponents?: ComponentIdentifier[];
  /** Overrides {@link WebBotAuthConfig.includeSignatureAgent} for this request. */
  signatureAgent?: boolean;
  /** Overrides {@link WebBotAuthConfig.signatureTTL} for this request (seconds). */
  ttl?: number;
}

/**
 * Web Bot Auth signing profile for a single agent domain.
 *
 * Signs outbound requests with the agent's Ed25519 operational key per
 * RFC 9421 (tag `web-bot-auth`) and serves the signed key directory that
 * verifiers fetch to resolve the signature's key.
 *
 * @example
 * ```ts
 * const profile = createWebBotAuthProfile({
 *   domain: 'agent.example.com',
 *   keyProvider: myEd25519KeyProvider,
 * });
 *
 * const signed = await profile.createWebBotAuthSignedRequest(
 *   new Request('https://api.example.net/v1/items', { method: 'GET' }),
 * );
 * await fetch(signed);
 * ```
 */
export class WebBotAuthProfile {
  /**
   * Builds a profile from a signing identity manager, reusing its domain and key provider.
   * @param identityManager Manager whose domain and operational key provider back the profile.
   * @param webBotAuth Optional Web Bot Auth configuration overrides.
   */
  static fromIdentityManager(identityManager: SigningIdentityManager, webBotAuth?: WebBotAuthConfig): WebBotAuthProfile {
    return new WebBotAuthProfile({
      domain: requireLocalDomain(identityManager),
      keyProvider: identityManager.getKeyProvider(),
      webBotAuth,
    });
  }

  private readonly domain: string;
  private readonly keyProvider: KeyProvider;
  private readonly config: WebBotAuthConfig;

  /**
   * @throws ArgumentError If `opts.domain` is not a valid agent FQDN.
   */
  constructor(opts: WebBotAuthProfileOptions) {
    try {
      this.domain = normalizeFQDN(opts.domain, true);
    } catch (e) {
      throw new ArgumentError(`domain is not a valid agent FQDN: ${(e as Error).message}`);
    }
    this.keyProvider = opts.keyProvider;
    this.config = opts.webBotAuth ?? {};
    validateWebBotAuthConfig(this.domain, this.config);
  }

  /**
   * Returns a copy of `req` carrying a Web Bot Auth signature (tag `web-bot-auth`).
   *
   * Covers `@authority` plus, when applicable, `content-digest` (a SHA-256
   * `Content-Digest` header is added for requests with a body) and
   * `signature-agent` (added unless disabled). The signature includes a nonce,
   * `created`/`expires` timestamps, and the operational key's JWK thumbprint as `keyid`.
   * The original request is not modified.
   *
   * @param req Outbound request to sign.
   * @param opts Per-request overrides for covered components, `Signature-Agent`, and TTL.
   * @returns A new signed `Request`.
   * @throws ArgumentError If the operational key is not Ed25519, the resolved
   *   Signature-Agent URI is invalid, or an additional component
   *   identifier is invalid.
   */
  async createWebBotAuthSignedRequest(req: Request, opts: WebBotAuthSigningOptions = {}): Promise<Request> {
    const signingKey = await this.ed25519SigningKey('Web Bot Auth signing requires Ed25519');
    const headers = new Headers(req.headers);
    const components: ComponentIdentifier[] = ['@authority'];
    const body = req.body ? await req.clone().arrayBuffer() : undefined;

    if (body) {
      const digest = await crypto.subtle.digest('SHA-256', body);
      headers.set('Content-Digest', `sha-256=:${toStdBase64(new Uint8Array(digest))}:`);
      components.push('content-digest');
    }

    const includeSignatureAgent = opts.signatureAgent ?? this.config.includeSignatureAgent ?? true;
    if (includeSignatureAgent) {
      const { uri, type } = signatureAgentConfig(this.domain, this.config);
      setDictionaryMember(headers, 'Signature-Agent', WEB_BOT_AUTH_SIGNATURE_LABEL, `${serializeStructuredFieldValue(uri)};type=${type}`);
      components.push({ name: 'signature-agent', params: { key: WEB_BOT_AUTH_SIGNATURE_LABEL } });
    }

    for (const component of opts.additionalComponents ?? []) {
      validateComponentIdentifier(component);
      if (!components.some(c => sameComponent(c, component))) components.push(component);
    }

    const requestWithHeaders = new Request(req, { headers, body });
    const now = Math.floor(Date.now() / 1000);
    const ttl = opts.ttl ?? this.config.signatureTTL ?? DEFAULT_WEB_BOT_AUTH_SIGNATURE_TTL_SECONDS;
    validateTtl(ttl, 'webBotAuth.signatureTTL');

    return signHttpMessage(requestWithHeaders, {
      label: WEB_BOT_AUTH_SIGNATURE_LABEL,
      components,
      keyId: await jwkThumbprint(signingKey),
      alg: joseAlgToHttpSigAlg('EdDSA'),
      created: now,
      expires: now + ttl,
      nonce: generateNonce(64),
      tag: WEB_BOT_AUTH_TAG,
    }, this.keyProvider);
  }

  /**
   * Builds the signed key directory response for
   * {@link HTTP_MESSAGE_SIGNATURES_DIRECTORY_PATH}.
   *
   * The JSON body lists the agent's public operational key as a JWK. The
   * response is signed with tag `http-message-signatures-directory`, covering
   * the requesting authority, `Content-Type`, `Cache-Control`, and `Content-Digest`.
   *
   * @param req Incoming directory request; its `@authority` is bound into the signature.
   * @returns A 200 response with media type {@link HTTP_MESSAGE_SIGNATURES_DIRECTORY_MEDIA_TYPE}.
   * @throws ArgumentError If the operational key is not Ed25519.
   */
  async serveHttpMessageSignaturesDirectory(req: Request): Promise<Response> {
    const signingKey = await this.ed25519SigningKey('Web Bot Auth directory signing requires Ed25519');
    const directoryKey = await wbaDirectoryJwkFromPublicKey(signingKey);
    const body = JSON.stringify({ keys: [directoryKey] });
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body));
    const ttl = this.config.directorySignatureTTL ?? DEFAULT_DIRECTORY_SIGNATURE_TTL_SECONDS;
    validateTtl(ttl, 'webBotAuth.directorySignatureTTL');
    const headers = new Headers({
      'Content-Type': HTTP_MESSAGE_SIGNATURES_DIRECTORY_MEDIA_TYPE,
      'Cache-Control': `max-age=${ttl}`,
      'Content-Digest': `sha-256=:${toStdBase64(new Uint8Array(digest))}:`,
    });
    const res = new Response(body, { status: 200, headers });
    const now = Math.floor(Date.now() / 1000);

    return signHttpMessage({ message: res, request: req }, {
      label: WEB_BOT_AUTH_SIGNATURE_LABEL,
      components: [{ name: '@authority', params: { req: true } }, 'content-type', 'cache-control', 'content-digest'],
      keyId: await jwkThumbprint(signingKey),
      alg: joseAlgToHttpSigAlg('EdDSA'),
      created: now,
      expires: now + ttl,
      nonce: generateNonce(64),
      tag: HTTP_MESSAGE_SIGNATURES_DIRECTORY_TAG,
    }, this.keyProvider);
  }

  /** Fetches the active operational key, throwing ArgumentError with `message` if it is not Ed25519. */
  private async ed25519SigningKey(message: string): Promise<DnsIdJWK> {
    const signingKey = await this.keyProvider.signingKey();
    if (jwkSignatureAlg(signingKey) !== 'EdDSA') throw new ArgumentError(message);
    return signingKey;
  }
}

/**
 * Creates a {@link WebBotAuthProfile} for an agent domain.
 *
 * @example
 * ```ts
 * const profile = createWebBotAuthProfile({
 *   domain: 'agent.example.com',
 *   keyProvider: myEd25519KeyProvider,
 * });
 * const signed = await profile.createWebBotAuthSignedRequest(
 *   new Request('https://api.example.net/v1/items'),
 * );
 * await fetch(signed);
 * ```
 *
 * @throws ArgumentError If `opts.domain` is not a valid agent FQDN.
 */
export function createWebBotAuthProfile(opts: WebBotAuthProfileOptions): WebBotAuthProfile {
  return new WebBotAuthProfile(opts);
}

/**
 * Converts an operational key JWK into its public directory form: private
 * members stripped, `kid` set to the JWK thumbprint, with `alg` and `use: 'sig'`.
 *
 * @param key Ed25519 JWK (public or private) to publish.
 * @returns The public JWK as listed in the key directory's `keys` array.
 * @throws ArgumentError If the key is not Ed25519.
 */
export async function wbaDirectoryJwkFromPublicKey(key: DnsIdJWK): Promise<DnsIdJWK> {
  if (jwkSignatureAlg(key) !== 'EdDSA') throw new ArgumentError('Web Bot Auth directory keys must be Ed25519');
  const pub: DnsIdJWK = { kty: key.kty, kid: key.kid, crv: key.crv, x: key.x };
  return {
    ...pub,
    kid: await jwkThumbprint(pub),
    alg: joseAlgToHttpSigAlg('EdDSA'),
    use: 'sig',
  };
}

function toStdBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

function validateTtl(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value <= 0 || value > 300) {
    throw new ArgumentError(`${name} must be positive and no greater than 300 seconds`);
  }
}

function validateWebBotAuthConfig(domain: string, config: WebBotAuthConfig): void {
  if (config.signatureTTL !== undefined) validateTtl(config.signatureTTL, 'webBotAuth.signatureTTL');
  if (config.directorySignatureTTL !== undefined) validateTtl(config.directorySignatureTTL, 'webBotAuth.directorySignatureTTL');
  if (config.clockSkew !== undefined && (!Number.isFinite(config.clockSkew) || config.clockSkew < 0)) {
    throw new ArgumentError('webBotAuth.clockSkew must be non-negative');
  }
  if (config.signatureAgent || config.directoryURL) signatureAgentConfig(domain, config);
}

function signatureAgentConfig(domain: string, config: WebBotAuthConfig): { uri: string; type: SignatureAgentType } {
  const legacyDirectUri = config.directoryURL;
  const type = config.signatureAgent?.type ?? (legacyDirectUri ? 'jwks_uri' : 'directory');
  if (type !== 'directory' && type !== 'jwks_uri') {
    throw new ArgumentError('Web Bot Auth Signature-Agent type must be directory or jwks_uri');
  }
  const rawUri = config.signatureAgent?.uri ?? legacyDirectUri ?? `https://${domain}`;
  let url: URL;
  try {
    url = new URL(rawUri);
  } catch {
    throw new ArgumentError('Web Bot Auth Signature-Agent must be a valid HTTPS URI');
  }
  if (url.protocol !== 'https:' || url.username || url.password) {
    throw new ArgumentError('Web Bot Auth Signature-Agent must be https');
  }
  if (type === 'directory') {
    if (url.pathname !== '/' || url.search || url.hash) {
      throw new ArgumentError('Web Bot Auth directory Signature-Agent must be an origin URI');
    }
    return { uri: url.origin, type };
  }
  if (url.hash) throw new ArgumentError('Web Bot Auth jwks_uri Signature-Agent must not contain a fragment');
  return { uri: url.href, type };
}
