/**
 * DNSid profile for RFC 9421 HTTP Message Signatures.
 *
 * Signs and verifies HTTP requests/responses with DNSid operational keys. The high-level
 * entry points are {@link createHttpSignaturesProfile} / {@link HttpSignaturesProfile},
 * which bind a signing agent's domain, KeyProvider, and IdentityResolver into a profile
 * that produces and verifies `Signature` / `Signature-Input` headers.
 *
 * The package also exports the low-level RFC 9421 building blocks it is made of —
 * component identifiers, structured-field parsing/serialization, signature-base
 * construction ({@link buildSignatureInput}), {@link signHttpMessage}, and
 * Content-Digest (RFC 9530) helpers — for reuse by other profiles such as
 * `@dnsid-ai/web-bot-auth`.
 *
 * @packageDocumentation
 */
import {
  DisplayString,
  parseDictionary as parseStructuredDictionary,
  serializeInnerList as serializeStructuredInnerList,
  serializeItem as serializeStructuredItem,
  serializeParameters as serializeStructuredParameters,
} from 'structured-headers';
import type { BareItem, Dictionary, InnerList, Item, Parameters } from 'structured-headers';

import type { IdentityResolver, KeyProvider, SigningIdentityManager, VerifiedDomain } from '@dnsid-ai/protocol';
import { requireLocalDomain } from '@dnsid-ai/protocol';
import {
  ArgumentError,
  ValidationError,
  VerificationError,
  VerificationCode,
  normalizeFQDN,
  parseKeyId,
  toBase64Url,
  verifyWithKey,
  jwkSignatureAlg,
  type TLSCertificate,
  type VerificationOptions,
  withVerificationBudget,
  waitForVerification,
} from '@dnsid-ai/protocol';
/**
 * An RFC 9421 covered-component identifier: either a plain component name
 * (a derived component like `"@method"` or a lowercase HTTP field name like
 * `"content-digest"`), or a name plus structured-field parameters
 * (e.g. `{ name: '@query-param', params: { name: 'id' } }` or `{ name: 'x-hdr', params: { req: true } }`).
 */
export type ComponentIdentifier = string | { name: string; params?: Record<string, string | number | boolean> };

/** An ordered RFC 8941 bare-item signature parameter retained during parsing. */
export type SignatureParameter = readonly [name: string, value: BareItem];

/** Options for signing an HTTP request with {@link HttpSignaturesProfile.createSignedHttpRequest}. */
export interface HttpSigningOptions {
  /**
   * Covered components to sign in addition to the profile defaults
   * (`@method`, `@authority`, `@target-uri`, and `content-digest` when a body is present).
   * Duplicates of already-covered components are ignored.
   */
  additionalComponents?: ComponentIdentifier[];
  /** Signature label used as the `Signature` / `Signature-Input` dictionary key. Default: `sig1`. */
  label?: string;
  /** Optional RFC 9421 `tag` signature parameter identifying the application/profile. */
  tag?: string;
  /** If set, adds an `expires` signature parameter this many seconds after `created`. */
  expiresInSeconds?: number;
}

/** Options for verifying an HTTP request with {@link HttpSignaturesProfile.verifySignedHttpRequest}. */
export interface HttpVerificationOptions extends VerificationOptions {
  /** Trusted current application peer, never the JWKS endpoint certificate. */
  peerCert?: TLSCertificate;
  /**
   * Covered components the signature must include, matched exactly (name and params).
   * Default: `@method`, `@authority`, `@target-uri`, matched by name only.
   */
  requiredComponents?: ComponentIdentifier[];
  /** If set, exactly one signature with this `tag` parameter must be present and is the one verified. */
  requiredTag?: string;
}

/**
 * Parsed or to-be-serialized RFC 9421 signature parameters: the covered components plus
 * the parameters of one `Signature-Input` dictionary member.
 */
export interface SignatureParams {
  /** Dictionary key labeling this signature in the `Signature` / `Signature-Input` headers. */
  label: string;
  /** Ordered covered components included in the signature base. */
  components: ComponentIdentifier[];
  /** `keyid` parameter; the DNSid profile uses the compound `"{domain}#{kid}"` convention. */
  keyId?: string;
  /** `alg` parameter (RFC 9421 algorithm identifier, e.g. `ed25519`). */
  alg?: string;
  /** `created` parameter (Unix seconds). */
  created?: number;
  /** `expires` parameter (Unix seconds). */
  expires?: number;
  /**
   * `nonce` parameter. Callers can record seen nonces to implement replay
   * detection; verification itself does not check for reuse.
   */
  nonce?: string;
  /** `tag` parameter identifying the application/profile. */
  tag?: string;
  /**
   * Ordered RFC 8941 signature parameters. Parsed values always populate this list, including
   * unknown extensions. When supplied for a newly constructed value, it is the serialization
   * source of truth; otherwise the typed fields above are serialized in profile order.
   */
  parameters?: SignatureParameter[];
}

/**
 * An HTTP message to sign or verify: a Request, a Response, or a Response paired with the
 * Request it answers (needed to resolve components with the `req` parameter).
 */
export type HttpMessage = Request | Response | { message: Request | Response; request?: Request };

/** Default maximum accepted age of a signature's `created` parameter, in seconds. */
export const DEFAULT_SIGNATURE_MAX_AGE_SECONDS = 300;
/** Default allowed clock skew when checking `created` against the current time, in seconds. */
export const DEFAULT_CLOCK_SKEW_SECONDS = 5;
/** RFC 9421 derived component names accepted by this package (`@query-param` additionally requires a `name` parameter). */
export const KNOWN_DERIVED_COMPONENTS = new Set([
  '@method', '@authority', '@target-uri', '@path', '@query',
  '@query-param', '@status', '@request-target', '@scheme',
]);
/** JOSE algorithm name to RFC 9421 HTTP signature algorithm identifier mapping supported by DNSid. */
export const JOSE_TO_HTTP_SIG_ALG: Readonly<Record<string, string>> = {
  EdDSA: 'ed25519',
  ES256: 'ecdsa-p256-sha256',
};

export { parseKeyId } from '@dnsid-ai/protocol';

/**
 * Maps a JWK/JOSE algorithm name to the corresponding RFC 9421 HTTP Message Signature algorithm identifier.
 *
 * @throws ArgumentError if the JOSE algorithm has no mapping (see {@link JOSE_TO_HTTP_SIG_ALG}).
 */
export function joseAlgToHttpSigAlg(joseAlg: string): string {
  const httpSigAlg = JOSE_TO_HTTP_SIG_ALG[joseAlg];
  if (!httpSigAlg) {
    throw new ArgumentError(`JOSE algorithm '${joseAlg}' has no RFC 9421 HTTP Message Signature mapping`);
  }
  return httpSigAlg;
}

/** Checks whether a string is a valid lowercase HTTP field name (RFC 9110 token). */
export function isLowercaseHttpFieldName(name: string): boolean {
  return /^[a-z0-9!#$%&'*+\-.^_`|~]+$/.test(name);
}

/** Generates a cryptographically random base64url nonce for HTTP message signatures. */
export function generateNonce(byteLength = 32): string {
  if (!Number.isSafeInteger(byteLength) || byteLength <= 0) throw new ArgumentError('nonce byte length must be a positive integer');
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

const SUPPORTED_DIGEST_ALGS = new Set(['sha-256', 'sha-512']);

/**
 * Parses a Content-Digest structured field header value (RFC 9530 Dictionary).
 *
 * Returns the first dictionary entry as a lowercase hash algorithm name and raw digest bytes.
 *
 * @throws ArgumentError if the header is malformed or uses an algorithm other than sha-256/sha-512.
 */
export function parseContentDigest(headerValue: string): { hashAlg: string; digest: Uint8Array } {
  let dict: Dictionary;
  try {
    dict = parseStructuredDictionary(headerValue);
  } catch {
    throw new ArgumentError(`malformed Content-Digest header: ${headerValue}`);
  }

  for (const [rawHashAlg, member] of dict) {
    const hashAlg = rawHashAlg.toLowerCase();
    if (!SUPPORTED_DIGEST_ALGS.has(hashAlg)) {
      throw new ArgumentError(`unsupported hash algorithm in Content-Digest: ${hashAlg}`);
    }
    if (!isItem(member) || !(member[0] instanceof ArrayBuffer)) {
      throw new ArgumentError(`malformed Content-Digest header: ${headerValue}`);
    }

    return { hashAlg, digest: new Uint8Array(member[0]) };
  }

  throw new ArgumentError(`malformed Content-Digest header: ${headerValue}`);
}

/** Constant-time comparison of two Uint8Arrays. Returns true if equal. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i]! ^ b[i]!);
  }
  return diff === 0;
}

const DEFAULT_HTTP_SIGNATURE_LABEL = 'sig1';

/** Tuning knobs for signature freshness checks during verification. */
export interface HttpSignaturesProfileConfig {
  /** Maximum age of an HTTP message signature's `created` parameter in seconds. Default: 300. */
  maxAge?: number;
  /** Allowed clock skew in seconds when checking `created`. Default: 5. */
  clockSkew?: number;
}

/** Constructor options for {@link HttpSignaturesProfile}. */
export interface HttpSignaturesProfileOptions {
  /** The signing agent's FQDN; becomes the domain half of the `keyid` parameter (`"{domain}#{kid}"`). */
  domain: string;
  /** Provides the agent's operational signing key. Omit for a verification-only profile. */
  keyProvider?: KeyProvider;
  /** Resolves and verifies signer domains when verifying inbound requests. */
  identityResolver: IdentityResolver;
  /** Verification freshness tuning; defaults apply when omitted. */
  httpMessageSignatures?: HttpSignaturesProfileConfig;
}

/** A fetch-compatible function, e.g. the global `fetch` or a wrapper around it. */
export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/** Options for {@link HttpSignaturesProfile.createSignedFetch}. */
export interface CreateSignedFetchOptions {
  /** Underlying fetch implementation invoked with the signed request. */
  fetch: FetchLike;
  /** Signing options, or a per-request callback returning them (undefined means profile defaults). */
  signing?: HttpSigningOptions | ((request: Request) => HttpSigningOptions | undefined);
  /** Hook to transform each request (e.g. add headers) before it is signed. */
  prepareRequest?: (request: Request) => Request | Promise<Request>;
}

/**
 * DNSid profile for RFC 9421 HTTP Message Signatures.
 *
 * Signs outbound HTTP requests with the agent's operational key (adding `Signature` /
 * `Signature-Input` headers, plus `Content-Digest` when a body is present) and verifies
 * inbound signed requests by resolving the signer's DNSid identity from the `keyid` parameter.
 *
 * Prefer {@link createHttpSignaturesProfile} or {@link HttpSignaturesProfile.fromIdentityManager}
 * for construction.
 */
export class HttpSignaturesProfile {
  /** Creates a profile from a SigningIdentityManager, reusing its domain, key provider, and resolver. */
  static fromIdentityManager(
    identityManager: SigningIdentityManager,
    httpMessageSignatures?: HttpSignaturesProfileConfig,
  ): HttpSignaturesProfile {
    return new HttpSignaturesProfile({
      domain: requireLocalDomain(identityManager),
      keyProvider: identityManager.getKeyProvider(),
      identityResolver: identityManager,
      httpMessageSignatures,
    });
  }

  private readonly domain: string;
  private readonly keyProvider: KeyProvider | null;
  private readonly identityResolver: IdentityResolver;
  private readonly config: HttpSignaturesProfileConfig;

  /** @throws ArgumentError if `opts.domain` is not a valid agent FQDN. */
  constructor(opts: HttpSignaturesProfileOptions) {
    try {
      this.domain = normalizeFQDN(opts.domain, true);
    } catch (e) {
      throw new ArgumentError(`domain is not a valid agent FQDN: ${(e as Error).message}`);
    }
    this.keyProvider = opts.keyProvider ?? null;
    this.identityResolver = opts.identityResolver;
    this.config = opts.httpMessageSignatures ?? {};
    validateHttpSignaturesConfig(this.config);
  }

  /**
   * Returns a copy of the request signed with the agent's current operational key.
   *
   * Covers `@method`, `@authority`, and `@target-uri` by default; when the request has a body,
   * a SHA-256 `Content-Digest` header is added and covered as well. The `keyid` signature
   * parameter is `"{domain}#{kid}"`, `created` is now, and a fresh nonce is included.
   * The input request is not mutated.
   *
   * @param req - Request to sign; its body (if any) is buffered to compute the digest.
   * @param opts - Extra covered components, label, tag, and expiry.
   * @throws ArgumentError if the signing key kid contains `#` or an additional component is invalid.
   */
  async createSignedHttpRequest(req: Request, opts?: HttpSigningOptions): Promise<Request> {
    const keyProvider = this.requireKeyProvider();
    const signingKey = await keyProvider.signingKey();

    if (signingKey.kid.includes('#')) {
      throw new ArgumentError("signing key kid must not contain '#'");
    }

    const components: ComponentIdentifier[] = ['@method', '@authority', '@target-uri'];
    let bodyBuffer: ArrayBuffer | null = null;
    if (req.body) {
      bodyBuffer = await req.clone().arrayBuffer();
    }

    const newHeaders = new Headers(req.headers);

    if (bodyBuffer) {
      const hashBuffer = await crypto.subtle.digest('SHA-256', bodyBuffer);
      newHeaders.set('Content-Digest', `sha-256=:${toStdBase64(new Uint8Array(hashBuffer))}:`);
      components.push('content-digest');
    }

    if (opts?.additionalComponents) {
      for (const name of opts.additionalComponents) {
        validateComponentIdentifier(name);
        if (!components.some(c => sameComponent(c, name))) components.push(name);
      }
    }

    const requestWithDigest = rebuildRequest(req, newHeaders, bodyBuffer ?? undefined);

    const now = Math.floor(Date.now() / 1000);
    if (opts?.expiresInSeconds !== undefined
      && (!Number.isSafeInteger(opts.expiresInSeconds) || opts.expiresInSeconds <= 0
        || opts.expiresInSeconds > (this.config.maxAge ?? DEFAULT_SIGNATURE_MAX_AGE_SECONDS))) {
      throw new ArgumentError('expiresInSeconds must be a positive integer no greater than maxAge');
    }
    const sigParams: SignatureParams = {
      label: opts?.label ?? DEFAULT_HTTP_SIGNATURE_LABEL,
      keyId: `${this.domain}#${signingKey.kid}`,
      alg: joseAlgToHttpSigAlg(jwkSignatureAlg(signingKey)),
      created: now,
      expires: opts?.expiresInSeconds === undefined ? undefined : now + opts.expiresInSeconds,
      nonce: generateNonce(),
      tag: opts?.tag,
      components,
    };

    const signed = await signHttpMessage(requestWithDigest, sigParams, keyProvider);
    return signed as Request;
  }

  private requireKeyProvider(): KeyProvider {
    if (!this.keyProvider) throw new ArgumentError('HTTP message signing requires a keyProvider');
    return this.keyProvider;
  }

  /**
   * Wraps a fetch implementation so every request is signed before being sent.
   *
   * Streaming (ReadableStream) request bodies are rejected with ArgumentError because
   * signing requires buffering the body to compute its digest.
   */
  createSignedFetch(opts: CreateSignedFetchOptions): FetchLike {
    return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      rejectNonReplayableFetchBody(init?.body);
      const req = init === undefined && input instanceof Request ? input.clone() : new Request(input, init);
      const preparedReq = opts.prepareRequest ? await opts.prepareRequest(req) : req;
      const signingOptions = typeof opts.signing === 'function' ? opts.signing(preparedReq) : opts.signing;
      const signedReq = await this.createSignedHttpRequest(preparedReq, signingOptions);
      return opts.fetch(signedReq);
    };
  }

  /**
   * Verifies an inbound signed request and returns the signer's verified DNSid identity.
   *
   * Selects signatures (optionally by `tag`) and accepts exactly one valid profile candidate,
   * ignoring unrelated or invalid coexisting signatures. Candidate checks cover: required
   * components, presence of `keyid` and `created`, freshness (`created` within maxAge and
   * clock skew, `expires` not passed and within maxAge of `created`), body/`content-digest`
   * consistency (a body must be covered by a matching `Content-Digest`), algorithm
   * consistency between the declared `alg` and the resolved key, and finally the signature
   * itself over the reconstructed signature base.
   *
   * The signer's domain is taken from the `keyid` (`"{domain}#{kid}"`) and resolved via the
   * profile's IdentityResolver; the signing key must appear in the signer's published JWKS.
   *
   * @returns The signer's VerifiedDomain on success.
   * @throws VerificationError with VerificationCode.SignatureInvalid for missing headers,
   *         unmet requirements, stale/future timestamps, digest or signature mismatches;
   *         with VerificationCode.RecordInvalid for malformed `Signature` / `Signature-Input`
   *         headers or ambiguous label/tag selection. Identity resolution failures propagate
   *         from the IdentityResolver.
   */
  async verifySignedHttpRequest(req: Request, opts: HttpVerificationOptions = {}): Promise<VerifiedDomain> {
    return withVerificationBudget(signal => this.verifyRequestWithinBudget(req, { ...opts, signal }), opts);
  }

  private async verifyRequestWithinBudget(req: Request, opts: HttpVerificationOptions): Promise<VerifiedDomain> {
    const sigInputHeader = req.headers.get('Signature-Input');
    const sigHeader = req.headers.get('Signature');
    if (!sigInputHeader || !sigHeader) {
      throw new VerificationError('missing Signature or Signature-Input headers', {
        code: VerificationCode.SignatureInvalid,
      });
    }

    const sigInputs = parseSignatureInput(sigInputHeader);
    const sigs = parseSignature(sigHeader);
    const candidates = selectSignatureCandidates(sigInputs, sigs, opts.requiredTag);
    let verified: VerifiedDomain | undefined;
    let lastError: unknown;
    for (const sigParams of candidates) {
      if (opts.signal?.aborted) throw new VerificationError('HTTP verification canceled', { code: VerificationCode.RecordInvalid });
      let candidate: VerifiedDomain;
      try {
        candidate = await this.verifySignatureCandidate(req, sigParams, sigs.get(sigParams.label)!, opts);
      } catch (error) {
        if (!(error instanceof ArgumentError || error instanceof ValidationError || error instanceof VerificationError)) throw error;
        lastError = error;
        continue;
      }
      if (verified) {
        throw new VerificationError('multiple valid HTTP message signatures', {
          code: VerificationCode.RecordInvalid,
        });
      }
      verified = candidate;
    }
    if (verified) return verified;
    if (lastError) throw lastError;
    throw new VerificationError('no valid HTTP message signature', { code: VerificationCode.SignatureInvalid });
  }

  private async verifySignatureCandidate(
    req: Request,
    sigParams: SignatureParams,
    rawSig: Uint8Array,
    opts: HttpVerificationOptions,
  ): Promise<VerifiedDomain> {
    const requiredComponents = opts.requiredComponents ?? ['@method', '@authority', '@target-uri'];
    for (const component of requiredComponents) {
      if (!sigParams.components.some(c => sameComponent(c, component))) {
        throw new VerificationError(`Signature-Input missing required covered component: ${componentName(component)}`, {
          code: VerificationCode.SignatureInvalid,
        });
      }
    }
    if (!sigParams.keyId) {
      throw new VerificationError('Signature-Input missing required keyid parameter', {
        code: VerificationCode.SignatureInvalid,
      });
    }
    if (sigParams.created === undefined) {
      throw new VerificationError('Signature-Input missing required created parameter', {
        code: VerificationCode.SignatureInvalid,
      });
    }

    let domain: string, kid: string;
    try {
      ({ domain, kid } = parseKeyId(sigParams.keyId));
    } catch (e) {
      if (e instanceof ArgumentError || e instanceof ValidationError) {
        throw new VerificationError(`invalid keyid in Signature-Input: ${(e as Error).message}`, {
          code: VerificationCode.SignatureInvalid,
        });
      }
      throw e;
    }

    const maxAgeSeconds = this.config.maxAge ?? DEFAULT_SIGNATURE_MAX_AGE_SECONDS;
    const clockSkewSeconds = this.config.clockSkew ?? DEFAULT_CLOCK_SKEW_SECONDS;
    const now = Math.floor(Date.now() / 1000);
    const created = sigParams.created;
    const expires = sigParams.expires;

    if (now - created > maxAgeSeconds) {
      throw new VerificationError('HTTP message signature has expired (created too far in the past)', {
        code: VerificationCode.SignatureInvalid,
      });
    }
    if (created > now + clockSkewSeconds) {
      throw new VerificationError('HTTP message signature created time is in the future', {
        code: VerificationCode.SignatureInvalid,
      });
    }
    if (expires !== undefined && expires < created) {
      throw new VerificationError('HTTP message signature expires precedes created', {
        code: VerificationCode.SignatureInvalid,
      });
    }
    if (expires !== undefined && now > expires + clockSkewSeconds) {
      throw new VerificationError('HTTP message signature has expired (expires parameter)', {
        code: VerificationCode.SignatureInvalid,
      });
    }
    if (expires !== undefined && expires - created > maxAgeSeconds) {
      throw new VerificationError('HTTP message signature expires lifetime exceeds maximum', {
        code: VerificationCode.SignatureInvalid,
      });
    }

    const vd = await waitForVerification(() => this.identityResolver.verifyDomain(domain, opts.peerCert, { signal: opts.signal }), opts.signal!);
    const sigKey = vd.jwks.keyById(kid);
    if (!sigKey) {
      throw new VerificationError('request kid not found in signer JWKS', { code: VerificationCode.SignatureInvalid });
    }

    const hasBody = req.body !== null;
    const coversContentDigest = sigParams.components.some(c => sameComponent(c, 'content-digest'));
    if (hasBody && !coversContentDigest) {
      throw new VerificationError('request body is present but content-digest is not covered by the signature', {
        code: VerificationCode.SignatureInvalid,
      });
    }
    if (coversContentDigest) {
      if (!hasBody) {
        throw new VerificationError('content-digest is a covered component but request has no body', {
          code: VerificationCode.SignatureInvalid,
        });
      }
      const digestHeader = req.headers.get('Content-Digest');
      if (!digestHeader) {
        throw new VerificationError('content-digest is covered but Content-Digest header is absent', {
          code: VerificationCode.SignatureInvalid,
        });
      }
      const expectedDigest = parseSha256ContentDigest(digestHeader);
      const bodyBuffer = await readBoundedBody(req, opts.signal!);
      const actualBuffer = await crypto.subtle.digest('SHA-256', bodyBuffer);
      if (!constantTimeEqual(expectedDigest, new Uint8Array(actualBuffer))) {
        throw new VerificationError('Content-Digest does not match request body', {
          code: VerificationCode.SignatureInvalid,
        });
      }
    }

    const keyAlg = jwkSignatureAlg(sigKey);
    const expectedHttpSigAlg = joseAlgToHttpSigAlg(keyAlg);
    if (sigParams.alg && sigParams.alg !== expectedHttpSigAlg) {
      throw new VerificationError(
        `HTTP message signature alg mismatch: Signature-Input declares ${sigParams.alg} but key maps to ${expectedHttpSigAlg}`,
        { code: VerificationCode.SignatureInvalid },
      );
    }

    let sigBase: string;
    try {
      sigBase = new TextDecoder().decode(buildSignatureInput(req, sigParams));
    } catch (e) {
      if (e instanceof ArgumentError) {
        throw new VerificationError(`Signature-Input covers absent component: ${(e as Error).message}`, {
          code: VerificationCode.SignatureInvalid,
        });
      }
      throw e;
    }

    if (!(await verifyWithKey(new TextEncoder().encode(sigBase), rawSig, sigKey, keyAlg))) {
      throw new VerificationError('HTTP message signature invalid', { code: VerificationCode.SignatureInvalid });
    }

    return vd;
  }
}

/**
 * Creates a DNSid RFC 9421 HTTP Message Signatures profile for the given agent.
 *
 * @example
 * ```ts
 * const httpSignatures = createHttpSignaturesProfile({
 *   domain: 'agent.example',
 *   keyProvider,
 *   identityResolver,
 * });
 *
 * // Sign an outbound request with the agent's operational key
 * const signed = await httpSignatures.createSignedHttpRequest(
 *   new Request('https://api.example/things', { method: 'POST', body: '{}' }),
 * );
 *
 * // Verify an inbound request; returns the signer's VerifiedDomain
 * const signer = await httpSignatures.verifySignedHttpRequest(incomingRequest);
 * ```
 */
export function createHttpSignaturesProfile(opts: HttpSignaturesProfileOptions): HttpSignaturesProfile {
  return new HttpSignaturesProfile(opts);
}


function asMessage(input: HttpMessage): { message: Request | Response; request?: Request } {
  if (input instanceof Request || input instanceof Response) return { message: input };
  return input;
}

function componentName(component: ComponentIdentifier): string {
  return typeof component === 'string' ? component : component.name;
}

function componentParams(component: ComponentIdentifier): Record<string, string | number | boolean> {
  return typeof component === 'string' ? {} : (component.params ?? {});
}

/** Checks whether two component identifiers are equivalent: same name and identical parameters. */
export function sameComponent(a: ComponentIdentifier, b: ComponentIdentifier): boolean {
  if (componentName(a) !== componentName(b)) return false;
  const aParams = componentParams(a);
  const bParams = componentParams(b);
  const aKeys = Object.keys(aParams);
  const bKeys = Object.keys(bParams);
  return aKeys.length === bKeys.length && aKeys.every(key => aParams[key] === bParams[key]);
}

/** Checks whether a component with the given name is present, ignoring parameters. */
export function hasComponentNamed(components: ComponentIdentifier[], name: string): boolean {
  return components.some(component => componentName(component) === name);
}

/**
 * Validates a component identifier: the name must be a known derived component
 * ({@link KNOWN_DERIVED_COMPONENTS}) or a lowercase HTTP field name, and `@query-param`
 * must carry a `name` parameter.
 *
 * @throws ArgumentError if the component is not valid.
 */
export function validateComponentIdentifier(component: ComponentIdentifier): void {
  const name = componentName(component);
  if (!KNOWN_DERIVED_COMPONENTS.has(name) && !isLowercaseHttpFieldName(name)) {
    throw new ArgumentError(`unknown signature component: ${name}`);
  }
  const params = componentParams(component);
  const entries = Object.entries(params);
  const allowed = new Set<string>();
  if (name === '@query-param') {
    allowed.add('name');
    allowed.add('req');
    if (typeof params.name !== 'string' || params.name.length === 0) throw new ArgumentError('@query-param requires non-empty string name parameter');
  } else if (name === '@status') {
    // No parameters are supported on @status.
  } else if (KNOWN_DERIVED_COMPONENTS.has(name)) {
    allowed.add('req');
  } else {
    allowed.add('key');
    allowed.add('req');
    if (params.key !== undefined && (typeof params.key !== 'string' || params.key.length === 0)) {
      throw new ArgumentError('field component key parameter must be a non-empty string');
    }
  }
  for (const [parameter, value] of entries) {
    if (!allowed.has(parameter)) throw new ArgumentError(`unsupported component parameter: ${parameter}`);
    if (parameter === 'req' && value !== true) throw new ArgumentError('component req parameter must be Boolean true');
  }
}

function extractComponentValue(input: HttpMessage, component: ComponentIdentifier): string {
  validateComponentIdentifier(component);
  const { message, request } = asMessage(input);
  const params = componentParams(component);
  if (params.req === true && (!(message instanceof Response) || !request)) {
    throw new ArgumentError(`covered component "${componentName(component)}" requires response request context`);
  }
  const source = params.req === true ? request : message;
  if (!source) throw new ArgumentError(`covered component "${componentName(component)}" requires request context`);
  const req = source instanceof Request ? source : undefined;
  const res = source instanceof Response ? source : undefined;
  const url = req ? new URL(req.url) : undefined;
  const name = componentName(component);
  switch (name) {
    case '@method':
      if (!req) throw new ArgumentError('@method is only available on requests');
      return req.method;
    case '@authority':
      if (!req || !url) throw new ArgumentError('@authority is only available on requests');
      return normalizedAuthority(url);
    case '@target-uri':
      if (!req || !url) throw new ArgumentError('@target-uri is only available on requests');
      return `${url.protocol}//${normalizedAuthority(url)}${url.pathname}${url.search}`;
    case '@path':
      if (!url) throw new ArgumentError('@path is only available on requests');
      return url.pathname;
    case '@query':
      if (!url) throw new ArgumentError('@query is only available on requests');
      return url.search || '?';
    case '@query-param': {
      if (!url) throw new ArgumentError('@query-param is only available on requests');
      const paramName = String(params.name);
      const values = canonicalQueryParamValues(url.search, paramName);
      if (values.length === 0) throw new ArgumentError(`covered query parameter "${paramName}" not present in request`);
      if (values.length > 1) throw new ArgumentError(`covered query parameter "${paramName}" appears more than once`);
      return values[0]!;
    }
    case '@scheme':
      if (!url) throw new ArgumentError('@scheme is only available on requests');
      return url.protocol.replace(':', '');
    case '@request-target':
      if (!url) throw new ArgumentError('@request-target is only available on requests');
      return url.pathname + url.search;
    case '@status':
      if (!res) throw new ArgumentError('@status is only available on responses');
      return String(res.status);
    default: {
      const val = source.headers.get(name);
      if (val === null) throw new ArgumentError(`covered component "${name}" not present in message`);
      if (params.key !== undefined) {
        const key = String(params.key);
        let dict: Dictionary;
        try {
          dict = parseStructuredDictionary(val);
        } catch {
          throw new ArgumentError(`covered component "${name}" is not a valid structured field dictionary`);
        }
        const member = dict.get(key);
        if (!member) throw new ArgumentError(`covered component "${name}" missing dictionary key "${key}"`);
        return serializeStructuredMember(member);
      }
      return val;
    }
  }
}

/** Serializes a bare value as an RFC 8941 structured field Item (bytes become `:base64:` byte sequences). */
export function serializeStructuredFieldValue(value: string | number | boolean | Uint8Array | ArrayBuffer): string {
  return serializeStructuredItem(toStructuredBareItem(value));
}

/** Serializes a component identifier as it appears in the signature base and `Signature-Input` header (quoted name plus parameters). */
export function serializeComponentIdentifier(component: ComponentIdentifier): string {
  const name = componentName(component);
  const params = componentParams(component);
  return serializeStructuredItem(name, toStructuredParams(params));
}

function serializeSigParams(params: SignatureParams): string {
  const items: Item[] = params.components.map(component => [componentName(component), toStructuredParams(componentParams(component))]);
  const innerList = serializeStructuredInnerList([items, new Map()]);
  return innerList + signatureParameterList(params)
    .map(([name, value]) => serializeStructuredParameters(new Map([[name, value]])))
    .join('');
}

/**
 * Builds the RFC 9421 signature base for a message: one `"component": value` line per
 * covered component, terminated by the canonical `"@signature-params"` line.
 *
 * @returns The UTF-8 encoded signature base — the payload that is signed/verified.
 * @throws ArgumentError if a covered component is invalid or cannot be resolved from the
 *         message (absent header, missing request context, unavailable derived component,
 *         or a `@query-param` that is absent or repeated).
 */
export function buildSignatureInput(msg: HttpMessage, params: SignatureParams): Uint8Array {
  validateComponents(params.components);
  const lines: string[] = [];
  for (const component of params.components) {
    lines.push(`${serializeComponentIdentifier(component)}: ${extractComponentValue(msg, component)}`);
  }
  lines.push(`"@signature-params": ${serializeSigParams(params)}`);
  return new TextEncoder().encode(lines.join('\n'));
}

/**
 * Signs an HTTP message per RFC 9421 with the key provider's current operational key.
 *
 * Builds the signature base for `params.components`, signs it via `keyProvider.sign()`, and
 * returns a copy of the message with the `params.label` member set (or replaced) in its
 * `Signature-Input` and `Signature` dictionary headers. Existing members under other labels
 * are preserved. The input message is not mutated. Callers are responsible for setting
 * `Content-Digest` before covering `content-digest`.
 *
 * @param msg - Request or Response to sign; pass `{ message, request }` to sign a response
 *   whose covered components reference the originating request (`req` parameter).
 * @param params - Covered components and signature parameters to serialize into `Signature-Input`.
 * @returns A new message of the same type carrying the signature headers.
 * @throws ArgumentError if a covered component cannot be resolved (see {@link buildSignatureInput}).
 */
export async function signHttpMessage<T extends Request | Response>(msg: T | { message: T; request?: Request }, params: SignatureParams, keyProvider: KeyProvider): Promise<T> {
  const { message } = asMessage(msg);
  const sigRaw = await keyProvider.sign(buildSignatureInput(msg, params));
  const headers = new Headers(message.headers);
  setDictionaryMember(headers, 'Signature-Input', params.label, serializeSigParams(params));
  setDictionaryMember(headers, 'Signature', params.label, `:${toStdBase64(sigRaw)}:`);
  if (message instanceof Request) {
    const body = message.body ? await message.clone().arrayBuffer() : undefined;
    return rebuildRequest(message, headers, body) as T;
  }
  const body = await message.clone().arrayBuffer();
  return new Response(body, { status: message.status, statusText: message.statusText, headers }) as T;
}

function rebuildRequest(request: Request, headers: Headers, body?: ArrayBuffer): Request {
  return new Request(request, {
    headers,
    body,
    referrer: request.referrer,
    referrerPolicy: request.referrerPolicy,
  });
}

function normalizedAuthority(url: URL): string {
  return url.port ? `${url.hostname.toLowerCase()}:${url.port}` : url.hostname.toLowerCase();
}

function canonicalQueryParamValues(search: string, paramName: string): string[] {
  const query = search.startsWith('?') ? search.slice(1) : search;
  if (!query) return [];
  const values: string[] = [];
  for (const part of query.split('&')) {
    const pair = new URLSearchParams(part);
    const entry = Array.from(pair.entries())[0];
    if (!entry) continue;
    const [name, value] = entry;
    if (formPercentEncode(name) === paramName) {
      values.push(formPercentEncode(value));
    }
  }
  return values;
}

function formPercentEncode(value: string): string {
  return encodeURIComponent(value).replace(/[!'()~]/g, ch => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`);
}

function splitDictionary(headerValue: string): string[] {
  const parts: string[] = [];
  let start = 0, depth = 0;
  let inString = false, inBytes = false, escape = false;
  for (let i = 0; i < headerValue.length; i++) {
    const ch = headerValue[i]!;
    if (escape) { escape = false; continue; }
    if (inString && ch === '\\') { escape = true; continue; }
    if (!inBytes && ch === '"') inString = !inString;
    if (!inString && ch === ':') inBytes = !inBytes;
    if (!inString && !inBytes) {
      if (ch === '(') depth++;
      else if (ch === ')') depth--;
      else if (ch === ',' && depth === 0) {
        parts.push(headerValue.slice(start, i).trim());
        start = i + 1;
      }
    }
    if (depth < 0) throw new VerificationError('malformed structured field header', { code: VerificationCode.RecordInvalid });
  }
  if (inString || inBytes || depth !== 0 || escape) throw new VerificationError('malformed structured field header', { code: VerificationCode.RecordInvalid });
  const tail = headerValue.slice(start).trim();
  if (tail) parts.push(tail);
  return parts;
}

/**
 * Parses a `Signature-Input` header (RFC 8941 Dictionary of Inner Lists) into per-label
 * signature params, preserving component and parameter order for canonical
 * signature-base reconstruction.
 *
 * @throws VerificationError with VerificationCode.RecordInvalid if the header is malformed,
 *         a label is duplicated, or a parameter has the wrong structured-field type.
 */
export function parseSignatureInput(headerValue: string): Map<string, SignatureParams> {
  assertHeaderBound(headerValue);
  const out = new Map<string, SignatureParams>();
  let dictionary: Dictionary;
  let entries: string[];
  try {
    entries = splitDictionary(headerValue);
    dictionary = parseStructuredDictionary(headerValue);
  } catch {
    throw new VerificationError('malformed Signature-Input header', { code: VerificationCode.RecordInvalid });
  }
  if (dictionary.size > 16 || dictionary.size !== entries.length) {
    throw new VerificationError('malformed Signature-Input header', { code: VerificationCode.RecordInvalid });
  }
  let index = 0;
  for (const [label, member] of dictionary) {
    const entry = entries[index++]!;
    if (!isInnerList(member)) {
      throw new VerificationError('malformed Signature-Input header', { code: VerificationCode.RecordInvalid });
    }

    const [items, params] = member;
    if (items.length > 64) throw new VerificationError('too many covered components', { code: VerificationCode.RecordInvalid });
    const components = items.map(parseComponentItem);
    try {
      validateComponents(components);
    } catch (error) {
      throw new VerificationError((error as Error).message, { code: VerificationCode.RecordInvalid });
    }
    const memberText = entry.slice(entry.indexOf('=') + 1).trim();
    const parameters = parseSignatureParameterOccurrences(memberText);
    const parsed: SignatureParams = { label, components, parameters };
    applySignatureInputParams(parsed, parameters);
    out.set(label, parsed);
  }
  return out;
}

/**
 * Parses a `Signature` header (RFC 8941 Dictionary of byte sequences) into raw signature
 * bytes keyed by label.
 *
 * @throws VerificationError with VerificationCode.RecordInvalid if the header is malformed,
 *         a label is duplicated, or a member is not a byte sequence.
 */
export function parseSignature(headerValue: string): Map<string, Uint8Array> {
  assertHeaderBound(headerValue);
  const out = new Map<string, Uint8Array>();
  let dictionary: Dictionary;
  let entryCount: number;
  try {
    entryCount = splitDictionary(headerValue).length;
    dictionary = parseStructuredDictionary(headerValue);
  } catch {
    throw new VerificationError('malformed Signature header', { code: VerificationCode.RecordInvalid });
  }
  if (dictionary.size > 16 || dictionary.size !== entryCount) {
    throw new VerificationError('malformed Signature header', { code: VerificationCode.RecordInvalid });
  }
  for (const [label, member] of dictionary) {
    if (!isItem(member) || !(member[0] instanceof ArrayBuffer) || member[1].size !== 0) {
      throw new VerificationError('malformed Signature header', { code: VerificationCode.RecordInvalid });
    }
    out.set(label, new Uint8Array(member[0]));
  }
  return out;
}

function assertHeaderBound(value: string): void {
  if (value.length > 16 * 1024) throw new VerificationError('signature header exceeds 16 KiB', { code: VerificationCode.RecordInvalid });
}

async function readBoundedBody(request: Request, signal: AbortSignal): Promise<ArrayBuffer> {
  const reader = request.clone().body!.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await waitForVerification(() => reader.read(), signal);
      if (done) break;
      size += value.length;
      if (size > 1024 * 1024) throw new VerificationError('HTTP signature body exceeds 1 MiB', { code: VerificationCode.RecordInvalid });
      chunks.push(value);
    }
  } finally { void reader.cancel().catch(() => {}); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes.buffer;
}

function selectSignatureCandidates(inputs: Map<string, SignatureParams>, sigs: Map<string, Uint8Array>, requiredTag?: string): SignatureParams[] {
  const matching = Array.from(inputs.values()).filter(params => sigs.has(params.label) && (requiredTag === undefined || params.tag === requiredTag));
  if (matching.length === 0) {
    const message = requiredTag === undefined
      ? 'expected at least one matching Signature and Signature-Input label'
      : `expected at least one matching Signature and Signature-Input label with tag: ${requiredTag}`;
    throw new VerificationError(message, { code: VerificationCode.RecordInvalid });
  }
  return matching;
}

/**
 * Sets one member of a structured-field Dictionary header (e.g. `Signature`, `Signature-Input`)
 * to `label=value`, replacing any existing member with that label and preserving the rest.
 */
export function setDictionaryMember(headers: Headers, name: string, label: string, value: string): void {
  const current = headers.get(name);
  try {
    const replacementText = `${label}=${value}`;
    const replacement = parseStructuredDictionary(replacementText);
    if (replacement.size !== 1 || !replacement.has(label)) throw new Error('invalid replacement dictionary member');
    if (current) {
      const entries = splitDictionary(current);
      const dictionary = parseStructuredDictionary(current);
      if (dictionary.size !== entries.length) throw new Error('duplicate dictionary member');
      const index = Array.from(dictionary.keys()).indexOf(label);
      if (index >= 0) entries[index] = replacementText;
      else entries.push(replacementText);
      headers.set(name, entries.join(', '));
      return;
    }
    headers.set(name, replacementText);
  } catch {
    throw new ArgumentError(`malformed ${name} structured field dictionary`);
  }
}

function isInnerList(member: Item | InnerList): member is InnerList {
  return Array.isArray(member[0]);
}

function isItem(member: Item | InnerList): member is Item {
  return !isInnerList(member);
}

function parseComponentItem(item: Item): ComponentIdentifier {
  const [rawName, rawParams] = item;
  if (typeof rawName !== 'string') {
    throw new VerificationError('malformed Signature-Input component', { code: VerificationCode.RecordInvalid });
  }
  const params = fromStructuredParams(rawParams);
  return Object.keys(params).length ? { name: rawName, params } : rawName;
}

function applySignatureInputParams(parsed: SignatureParams, params: SignatureParameter[]): void {
  const seenKnown = new Set<string>();
  for (const [key, value] of params) {
    if (value instanceof Date || value instanceof DisplayString) {
      throw new VerificationError('unsupported structured field bare value', { code: VerificationCode.RecordInvalid });
    }
    if (['keyid', 'alg', 'created', 'expires', 'nonce', 'tag'].includes(key)) {
      if (seenKnown.has(key)) {
        throw new VerificationError(`duplicate Signature-Input ${key} parameter`, { code: VerificationCode.RecordInvalid });
      }
      seenKnown.add(key);
    }
    if (key === 'keyid') parsed.keyId = signatureStringParam(key, value);
    else if (key === 'alg') parsed.alg = signatureStringParam(key, value);
    else if (key === 'created') parsed.created = signatureIntegerParam(key, value);
    else if (key === 'nonce') parsed.nonce = signatureStringParam(key, value);
    else if (key === 'expires') parsed.expires = signatureIntegerParam(key, value);
    else if (key === 'tag') parsed.tag = signatureStringParam(key, value);
  }
}

function signatureParameterList(params: SignatureParams): SignatureParameter[] {
  if (params.parameters) {
    const out: SignatureParameter[] = [];
    const seenKnown = new Set<string>();
    for (const [name, value] of params.parameters) {
      if (value instanceof Date || value instanceof DisplayString) throw new ArgumentError('RFC 9651-only signature parameters are unsupported');
      if (['keyid', 'alg', 'created', 'expires', 'nonce', 'tag'].includes(name)) {
        if (seenKnown.has(name)) throw new ArgumentError(`duplicate Signature-Input ${name} parameter`);
        seenKnown.add(name);
      }
      if (['keyid', 'alg', 'nonce', 'tag'].includes(name) && typeof value !== 'string') {
        throw new ArgumentError(`Signature-Input ${name} parameter must be a string`);
      }
      if (['created', 'expires'].includes(name) && (typeof value !== 'number' || !Number.isInteger(value))) {
        throw new ArgumentError(`Signature-Input ${name} parameter must be an integer`);
      }
      out.push([name, value]);
    }
    return out;
  }
  const out: SignatureParameter[] = [];
  if (params.keyId !== undefined) out.push(['keyid', params.keyId]);
  if (params.alg !== undefined) out.push(['alg', params.alg]);
  if (params.created !== undefined) out.push(['created', params.created]);
  if (params.nonce !== undefined) out.push(['nonce', params.nonce]);
  if (params.expires !== undefined) out.push(['expires', params.expires]);
  if (params.tag !== undefined) out.push(['tag', params.tag]);
  return out;
}

function validateComponents(components: ComponentIdentifier[]): void {
  for (let i = 0; i < components.length; i++) {
    validateComponentIdentifier(components[i]!);
    if (components.slice(0, i).some(component => sameComponent(component, components[i]!))) {
      throw new ArgumentError(`duplicate covered component: ${serializeComponentIdentifier(components[i]!)}`);
    }
  }
}

function parseSignatureParameterOccurrences(member: string): SignatureParameter[] {
  const close = findInnerListClose(member);
  const out: SignatureParameter[] = [];
  for (const segment of scanParameterSegments(member.slice(close + 1))) {
    let dictionary: Dictionary;
    try {
      dictionary = parseStructuredDictionary(`x=()${segment}`);
    } catch {
      throw new VerificationError('malformed Signature-Input parameter', { code: VerificationCode.RecordInvalid });
    }
    const parsedMember = dictionary.get('x');
    if (!parsedMember || !isInnerList(parsedMember) || parsedMember[1].size !== 1) {
      throw new VerificationError('malformed Signature-Input parameter', { code: VerificationCode.RecordInvalid });
    }
    out.push(Array.from(parsedMember[1].entries())[0]!);
  }
  return out;
}

function findInnerListClose(member: string): number {
  let inString = false, escape = false;
  for (let i = 1; i < member.length; i++) {
    const ch = member[i]!;
    if (escape) { escape = false; continue; }
    if (inString && ch === '\\') { escape = true; continue; }
    if (ch === '"') { inString = !inString; continue; }
    if (!inString && ch === ')') return i;
  }
  return -1;
}

function scanParameterSegments(value: string): string[] {
  const segments: string[] = [];
  for (let i = 0; i < value.length;) {
    while (value[i] === ' ') i++;
    if (value[i] !== ';') break;
    const start = i++;
    while (i < value.length && /[a-z0-9_.*-]/.test(value[i]!)) i++;
    if (value[i] === '=') i++;
    if (value[i] === '"' || (value[i] === '%' && value[i + 1] === '"')) {
      if (value[i] === '%') i++;
      for (i++; i < value.length; i++) {
        if (value[i] === '\\') i++;
        else if (value[i] === '"') { i++; break; }
      }
    } else if (value[i] === ':') {
      i = value.indexOf(':', i + 1);
      i = i < 0 ? value.length : i + 1;
    } else {
      while (i < value.length && value[i] !== ';') i++;
    }
    segments.push(value.slice(start, i).trim());
  }
  return segments;
}

function validateHttpSignaturesConfig(config: HttpSignaturesProfileConfig): void {
  if (config.maxAge !== undefined && (!Number.isSafeInteger(config.maxAge) || config.maxAge <= 0)) {
    throw new ArgumentError('httpMessageSignatures.maxAge must be positive');
  }
  if (config.clockSkew !== undefined && (!Number.isFinite(config.clockSkew) || config.clockSkew < 0)) {
    throw new ArgumentError('httpMessageSignatures.clockSkew must be non-negative');
  }
}

function parseSha256ContentDigest(headerValue: string): Uint8Array {
  let dictionary: Dictionary;
  try {
    dictionary = parseStructuredDictionary(headerValue);
  } catch {
    throw new VerificationError('malformed Content-Digest header', { code: VerificationCode.SignatureInvalid });
  }
  const member = dictionary.get('sha-256');
  if (!member || !isItem(member) || !(member[0] instanceof ArrayBuffer) || member[1].size !== 0) {
    throw new VerificationError('DNSid HTTP signatures require sha-256 Content-Digest', {
      code: VerificationCode.SignatureInvalid,
    });
  }
  return new Uint8Array(member[0]);
}

function signatureStringParam(key: string, value: BareItem): string {
  if (typeof value !== 'string') {
    throw new VerificationError(`malformed Signature-Input ${key} parameter`, { code: VerificationCode.RecordInvalid });
  }
  return value;
}

function signatureIntegerParam(key: string, value: BareItem): number {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new VerificationError(`malformed Signature-Input ${key} parameter`, { code: VerificationCode.RecordInvalid });
  }
  return value;
}

function fromStructuredParams(params: Parameters): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  for (const [key, value] of params) {
    if (typeof value === 'string' || typeof value === 'boolean' || (typeof value === 'number' && Number.isInteger(value))) {
      out[key] = value;
    } else {
      throw new VerificationError('unsupported structured field bare value', { code: VerificationCode.RecordInvalid });
    }
  }
  return out;
}

function toStructuredParams(params: Record<string, string | number | boolean>): Parameters {
  const out: Parameters = new Map();
  for (const [key, value] of Object.entries(params)) out.set(key, value);
  return out;
}

function toStructuredBareItem(value: string | number | boolean | Uint8Array | ArrayBuffer): BareItem {
  if (value instanceof Uint8Array) return new Uint8Array(value).buffer;
  return value;
}

function serializeStructuredMember(member: Item | InnerList): string {
  return isInnerList(member) ? serializeStructuredInnerList(member) : serializeStructuredItem(member);
}

function toStdBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

function isReadableStreamBody(body: unknown): body is ReadableStream<Uint8Array> {
  if (!body || typeof body !== 'object') return false;
  if (typeof ReadableStream !== 'undefined' && body instanceof ReadableStream) return true;
  return typeof (body as { getReader?: unknown }).getReader === 'function';
}

function rejectNonReplayableFetchBody(body: unknown): void {
  if (isReadableStreamBody(body)) {
    throw new ArgumentError('createSignedFetch does not support non-replayable ReadableStream request bodies');
  }
}
