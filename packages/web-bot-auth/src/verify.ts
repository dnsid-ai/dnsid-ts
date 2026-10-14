import type { IdentityResolver, TLSCertificate, VerificationOptions, VerifiedDomain, DnsIdJWK } from '@dnsid-ai/protocol';
import { ArgumentError, VerificationError, VerificationCode, normalizeFQDN, jwkThumbprint, fromBase64Url, toBase64Url, parseJsonNoDuplicateMembers, verifyWithKey, withVerificationBudget, waitForVerification } from '@dnsid-ai/protocol';
import type { SignatureParams, HttpMessage } from '@dnsid-ai/http-signatures';
import { parseSignatureInput, parseSignature, sameComponent, buildSignatureInput, readBoundedBody, parseSha256ContentDigest, constantTimeEqual, parseDictionaryField } from '@dnsid-ai/http-signatures';
import { Token } from 'structured-headers';

/** Trusted transport must validate Web PKI and pin connections to public DNS addresses.
 * It must honor manual redirects and cancellation. Do not inject ordinary fetch on a server.
 */
export type WebBotAuthDiscoveryFetch = (request: Request) => Promise<Response>;

export interface WebBotAuthVerificationOptions extends VerificationOptions {
  /** Trusted expected signer. Discovery cannot delegate to another host. */
  signerDomain?: string;
  /** Explicit permission to use the signed Signature-Agent host as signer identity. Default: false. */
  allowSignatureAgentDomain?: boolean;
  /** Trusted endpoint when Signature-Agent is absent. Must belong to signerDomain. */
  discovery?: { uri: string; type?: 'directory' | 'jwks_uri' };
  /** Current application peer, never the directory endpoint certificate. */
  peerCert?: TLSCertificate;
  /** Atomically consume (domain, keyid, nonce), retaining through retainUntil. False rejects reuse;
   * errors fail closed. Without this policy, valid requests can be replayed.
   */
  consumeNonce?: (entry: { signerDomain: string; keyid: string; nonce: string; retainUntil: Date }, signal: AbortSignal) => Promise<boolean>;
}

function invalid(message: string): never {
  throw new VerificationError(message, { code: VerificationCode.SignatureInvalid });
}

function select(message: Request | Response, tag: string, keyid?: string): { params: SignatureParams; signature: Uint8Array } {
  let headerSize = 0;
  for (const [name, value] of message.headers) headerSize += name.length + value.length;
  if (headerSize > 64 * 1024) invalid('WBA message headers exceed size limit');
  if (message instanceof Request && message.url.length > 16 * 1024) invalid('WBA request URL exceeds size limit');
  const inputs = parseSignatureInput(message.headers.get('Signature-Input') ?? '');
  const signatures = parseSignature(message.headers.get('Signature') ?? '');
  const candidates = [...inputs.values()].filter(p => p.tag === tag && signatures.has(p.label) && (keyid === undefined || p.keyId === keyid));
  if (candidates.length !== 1) invalid('expected exactly one complete WBA profile signature');
  const params = candidates[0]!;
  return { params, signature: signatures.get(params.label)! };
}

function validity(params: SignatureParams, skew: number): void {
  const { created, expires, keyId, alg } = params;
  if (!Number.isSafeInteger(created) || !Number.isSafeInteger(expires) || created! > expires! || expires! - created! > 300) invalid('invalid WBA signature lifetime');
  if (alg !== 'ed25519' || !keyId || !/^[A-Za-z0-9_-]{43}$/.test(keyId) || toBase64Url(fromBase64Url(keyId)) !== keyId) invalid('invalid WBA algorithm or thumbprint');
  const now = Date.now() / 1000;
  if (created! > now + skew || expires! < now - skew) invalid('WBA signature is not currently valid');
}

function covers(params: SignatureParams, component: Parameters<typeof sameComponent>[0]): void {
  if (!params.components.some(c => sameComponent(c, component))) invalid('missing required WBA component coverage');
}

async function digest(message: Request | Response, params: SignatureParams, signal: AbortSignal, maxBytes: number): Promise<Uint8Array> {
  if (message.body === null) {
    if (params.components.some(c => sameComponent(c, 'content-digest'))) invalid('covered digest without supplied content');
    return new Uint8Array();
  }
  covers(params, 'content-digest');
  const expected = parseSha256ContentDigest(message.headers.get('Content-Digest') ?? '');
  const bytes = new Uint8Array(await readBoundedBody(message, signal, maxBytes));
  const actual = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  if (!constantTimeEqual(expected, actual)) invalid('WBA Content-Digest mismatch');
  return bytes;
}

function endpoint(uri: string, type: string, domain?: string): URL {
  if (uri.length > 16 * 1024) invalid('WBA discovery URI exceeds size limit');
  let url: URL;
  try { url = new URL(uri); } catch { return invalid('invalid WBA discovery URI'); }
  if (url.protocol !== 'https:' || url.username || url.password) invalid('WBA discovery requires HTTPS');
  // Domain identities exclude IP literals; the transport also checks resolved addresses at connection time.
  let host: string;
  try { host = normalizeFQDN(url.hostname, true); } catch { return invalid('invalid WBA discovery host'); }
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || (domain && host !== domain)) invalid('unapproved WBA discovery host');
  if (type === 'directory') return new URL('/.well-known/http-message-signatures-directory', url.origin);
  if (type !== 'jwks_uri' || url.hash) invalid('unsupported WBA discovery type or fragment');
  return url;
}

function cacheExpiry(response: Response): number {
  const ageHeader = response.headers.get('Age');
  const maxAge = /(?:^|,)\s*max-age\s*=\s*"?(\d+)"?\s*(?:,|$)/i.exec(response.headers.get('Cache-Control') ?? '');
  if (ageHeader !== null && !/^\d+$/.test(ageHeader)) invalid('invalid directory cache age');
  if (!maxAge) {
    if (ageHeader !== null) invalid('cached directory lacks bounded HTTP freshness');
    return Infinity;
  }
  const now = Date.now();
  const date = Date.parse(response.headers.get('Date') ?? '');
  const age = Math.max(Number(ageHeader ?? 0), Number.isFinite(date) ? (now - date) / 1000 : 0);
  return now + (Number(maxAge[1]) - age) * 1000;
}

function boundedDepth(value: unknown, depth = 0): void {
  if (depth > 16) invalid('WBA directory JSON is too deep');
  if (value && typeof value === 'object') for (const child of Object.values(value)) boundedDepth(child, depth + 1);
}

async function signature(message: HttpMessage, params: SignatureParams, raw: Uint8Array, key: DnsIdJWK): Promise<void> {
  try {
    if (!await verifyWithKey(buildSignatureInput(message, params), raw, { ...key, alg: 'EdDSA' }, 'EdDSA')) invalid('invalid WBA signature');
  } catch (cause) {
    if (cause instanceof VerificationError) throw cause;
    throw new VerificationError('invalid WBA signature or key', { code: VerificationCode.SignatureInvalid, cause });
  }
}

export async function verifyWebBotAuthRequest(req: Request, resolver: IdentityResolver, fetchDirectory: WebBotAuthDiscoveryFetch, skew: number, opts: WebBotAuthVerificationOptions): Promise<VerifiedDomain> {
  return withVerificationBudget(async signal => {
    let response: Response | undefined;
    try {
      const request = select(req, 'web-bot-auth');
      validity(request.params, skew);
      covers(request.params, '@authority');
      await digest(req, request.params, signal, 1024 * 1024);
      let domain = opts.signerDomain === undefined ? undefined : normalizeFQDN(opts.signerDomain, true);
      let discovery = opts.discovery;
      const agent = req.headers.get('Signature-Agent');
      if (agent !== null) {
        if (agent.length > 16 * 1024) invalid('Signature-Agent exceeds size limit');
        const components = request.params.components.filter(c => typeof c !== 'string' && c.name === 'signature-agent' && typeof c.params?.key === 'string' && Object.keys(c.params).length === 1);
        if (components.length !== 1) invalid('expected one covered Signature-Agent member');
        const component = components[0] as { name: string; params: { key: string } };
        const member = parseDictionaryField(agent).get(component.params.key);
        if (!member || typeof member[0] !== 'string') invalid('invalid Signature-Agent member');
        const type = member[1].get('type');
        if (type !== undefined && !(type instanceof Token)) invalid('Signature-Agent type must be a token');
        discovery = { uri: member[0], type: (type === undefined ? 'directory' : type.toString()) as 'directory' | 'jwks_uri' };
        if (!domain && opts.allowSignatureAgentDomain === true) domain = normalizeFQDN(endpoint(discovery.uri, discovery.type!).hostname, true);
      }
      if (!domain || !discovery) throw new ArgumentError('trusted signer domain and discovery policy are required');
      let url = endpoint(discovery.uri, discovery.type ?? 'directory', domain);
      let directoryRequest: Request;
      for (let redirects = 0; ; redirects++) {
        directoryRequest = new Request(url, { redirect: 'manual', signal });
        response = await waitForVerification(() => fetchDirectory(directoryRequest), signal);
        if (response.redirected) invalid('discovery transport followed an unchecked redirect');
        if (response.status < 300 || response.status >= 400) break;
        void response.body?.cancel().catch(() => {});
        const location = response.headers.get('Location');
        if (!location || location.length > 16 * 1024 || redirects >= 5) invalid('invalid or excessive WBA directory redirect');
        url = endpoint(new URL(location, url).href, 'jwks_uri', domain);
      }
      if (response.status !== 200 || response.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/http-message-signatures-directory+json') invalid('invalid WBA directory response');
      // Transport implementations can return responses from a different Fetch implementation.
      response = new Response(response.body, { status: response.status, headers: response.headers });
      const directory = select(response, 'http-message-signatures-directory', request.params.keyId);
      const httpFreshUntil = cacheExpiry(response);
      validity(directory.params, skew);
      for (const component of [{ name: '@authority', params: { req: true } }, 'content-type', 'cache-control', 'content-digest'] as const) covers(directory.params, component);
      const bytes = await digest(response, directory.params, signal, 256 * 1024);
      let document: unknown;
      try { document = parseJsonNoDuplicateMembers(bytes); } catch { invalid('invalid WBA directory JSON'); }
      boundedDepth(document);
      const keys = (document as { keys?: unknown[] } | null)?.keys;
      if (!Array.isArray(keys) || keys.length === 0 || keys.length > 64) invalid('invalid WBA directory key count');
      const matching: DnsIdJWK[] = [];
      for (const value of keys) {
        if (!value || typeof value !== 'object' || Array.isArray(value)) invalid('invalid directory JWK');
        const key = value as DnsIdJWK;
        if (key.kty !== 'OKP' || key.crv !== 'Ed25519' || typeof key.x !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(key.x) || toBase64Url(fromBase64Url(key.x)) !== key.x || 'd' in key || (key.alg !== undefined && key.alg !== 'ed25519') || (key.use !== undefined && key.use !== 'sig')) invalid('invalid public Ed25519 directory key');
        if (await jwkThumbprint(key) !== key.kid) invalid('directory JWK thumbprint mismatch');
        if (key.kid === request.params.keyId) matching.push(key);
      }
      if (matching.length !== 1) invalid('expected one matching WBA directory key');
      const key = matching[0]!;
      await signature({ message: response, request: directoryRequest }, directory.params, directory.signature, key);
      await signature(req, request.params, request.signature, key);
      const verified = await waitForVerification(() => resolver.verifyDomain(domain!, opts.peerCert, { signal }), signal);
      if (verified.domain !== domain) invalid('DNSid signer domain mismatch');
      const bound = await Promise.all(verified.jwks.keys.map(k => jwkThumbprint(k)));
      if (!bound.includes(key.kid)) invalid('WBA key is not bound to current DNSid ku material');
      const fresh = () => {
        validity(request.params, skew);
        validity(directory.params, skew);
        if (httpFreshUntil < Date.now()) invalid('directory HTTP cache freshness expired');
        if (!(verified.expiry().getTime() > Date.now())) invalid('DNSid evidence expired during WBA verification');
      };
      fresh();
      if (opts.consumeNonce) {
        if (!request.params.nonce) invalid('replay policy requires a non-empty nonce');
        const accepted = await waitForVerification(() => opts.consumeNonce!({ signerDomain: domain!, keyid: key.kid, nonce: request.params.nonce!, retainUntil: new Date((request.params.expires! + skew) * 1000) }, signal), signal);
        if (!accepted) invalid('replayed WBA nonce');
      }
      fresh();
      return verified;
    } finally { void response?.body?.cancel().catch(() => {}); }
  }, opts);
}
