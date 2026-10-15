# @dnsid-ai/web-bot-auth

DNSid Web Bot Auth profile helpers.

This package signs and verifies DNSid Web Bot Auth requests (RFC 9421 HTTP Message Signatures with the `web-bot-auth` tag), serves signed key directories, and verifies discovered directories against current DNSid operational (`ku`) keys. It targets published `draft-ietf-webbotauth-httpsig-protocol-00`, including its directory format, not the editor's copy or a finalized WBA standard. This is a narrower DNSid profile, not a general WBA implementation. External partner interoperability has not been tested.

It builds on `@dnsid-ai/http-signatures` and `@dnsid-ai/protocol` contracts and performs no DNS or HTTPS transport itself. Signing requires an Ed25519 operational key; the profile throws `ArgumentError` for other key types.

## Install

```sh
npm install @dnsid-ai/web-bot-auth @dnsid-ai/protocol
```

## Example

Sign an outbound request:

```ts
import { createWebBotAuthProfile } from '@dnsid-ai/web-bot-auth';

const profile = createWebBotAuthProfile({
  domain: 'agent.example',
  keyProvider, // Ed25519 operational key
});

const signed = await profile.createWebBotAuthSignedRequest(
  new Request('https://origin.example/api'),
);
await fetch(signed);
```

Serve the key directory (mount at `/.well-known/http-message-signatures-directory`):

```ts
const response = await profile.serveHttpMessageSignaturesDirectory(request);
```

The directory response is signed with the `http-message-signatures-directory` tag and served as `application/http-message-signatures-directory+json`. Signatures are backdated by `min(5, ttl - 1)` seconds without extending their lifetime. The default response has at most 295 seconds of freshness and signed `Cache-Control: max-age=295, must-revalidate`. Disable CDN stale-serving overrides, `stale-while-revalidate`, and `stale-if-error` for this endpoint.

## Verify a request

Verification-only construction does not need a local identity or signing key:

```ts
import { createSsrfSafeFetch } from '@dnsid-ai/transport'; // Node transport

const safeFetch = createSsrfSafeFetch({}, { decompress: false });
const verifier = createWebBotAuthProfile({
  identityResolver, // RefreshingIdentityResolver, including configured entity acceptance
  discoveryFetch: request => safeFetch(request),
});
const identity = await verifier.verifyWebBotAuthSignedRequest(request, {
  signerDomain: 'agent.example', // trusted application policy
  requiredComponents: ['@method', '@target-uri'], // enforce operation binding
  peerCert, // current application peer certificate, required for fl=mtls
  timeoutMs: 30_000,
  signal,
});
```

Install `@dnsid-ai/transport` to use this Node transport. The package stays runtime-neutral: `discoveryFetch` is required and must enforce valid Web PKI, public-address DNS checks and connection pinning on every connection, rejection of all redirects (including same-host HTTPS), cancellation, and unmodified response bytes and headers without decompression. Coded directories are rejected. Ordinary server-side `fetch` is not safe for untrusted discovery. Do not enable private-address exceptions for WBA discovery.

Alternatively, explicitly set `allowSignatureAgentDomain: true` to let the signed HTTPS discovery host identify the signer. Cross-host delegation is rejected. `Signature-Agent` and its exact keyed coverage are mandatory, even with trusted `discovery: { uri, type }`, which now constrains the signed endpoint rather than replacing it. Missing, uncovered, invalid, or unsupported discovery rejects before network work. The default type is `directory` and requires an exact ASCII HTTPS origin without a trailing slash, path, query, or fragment; `jwks_uri` addresses a direct signed directory endpoint, not an unsigned JWKS. Signature relabeling preserves the original covered discovery member.

Every invocation verifies request and directory signatures, content digests, and current DNSid key binding and acceptance. There is no directory-only fallback or internal directory cache. Every discovery request uses `cache: 'no-store'` and `Cache-Control: no-cache`. Injected transports must bypass local caches and revalidate upstream on each call. A fresh directory missing the key fails without a retry. HTTP cache lifetime does not limit use of a freshly acquired signed directory in the current invocation, including `no-store, max-age=0`. Injected caching transports must enforce RFC 9111 freshness using original acquisition timing and HTTP age metadata, reject reuse without sufficient metadata, and never restart freshness when returning the same response. Key attribution must use the normalized discovery URL and thumbprint within the policy context. Newer resolutions replace older key sets, including removed keys; order signed proofs by `created`. Failed refreshes must neither evict evidence nor extend freshness. The verifier does not infer cache reuse or derive an HTTP deadline from signed creation time. Results authenticate identity but do not grant application permissions. Default required coverage is `@authority`, not method or path. Use signing `additionalComponents` to add bindings and verifier `requiredComponents` to require them, with exact parameter equality. Nested WBA signing is unsupported. Coverage policy is checked before discovery; malformed policy raises `ArgumentError`. Covered keyed `Content-Digest` components must select `sha-256`; unsupported members are rejected. Profile configuration, including nested discovery settings, is snapshotted and validated on construction.

For one-time requests, supply `consumeNonce(entry, signal)`. It must atomically consume `(signerDomain, keyid, nonce)` and retain the entry until `retainUntil` (`expires + clockSkew`). Return `false` for reuse; store errors reject verification. Without this hook, time-valid requests can be replayed.

The overall timeout defaults to 30 seconds and covers discovery, reads, DNSid verification, and replay storage. Redirects are rejected. Limits are 256 KiB directory content, 64 keys, JSON depth 16, 16 KiB signature/discovery/digest headers and URLs, 64 KiB aggregate header characters, and 1 MiB request content. The hosting layer must bound incoming request streams before cloning them; verification preserves the original request body. Signature lifetimes cannot exceed 300 seconds. Directory signature creation cannot be in the future, even within configured clock skew. Evidence freshness is checked again before return, including both certificates and key age. Fresh zero-TTL DNS evidence is valid only within the acquiring invocation. Directory timeouts and temporary HTTP failures are transient; invalid TLS, unsafe destinations, and invalid signatures remain permanent.

## Options

- `signatureAgent` — the discovery URI and type advertised in `Signature-Agent`. It defaults to the domain's HTTPS origin with `type=directory`; use `type=jwks_uri` for a direct JWKS endpoint.
- `directoryURL` — deprecated compatibility option interpreted as a direct `jwks_uri` endpoint. Use `signatureAgent.uri` instead.
- `signatureTTL` / `directorySignatureTTL` — signature lifetimes in seconds (defaults: 60 for requests, 300 for the directory).
- `clockSkew` — non-negative verification tolerance in seconds (default: 5); never permits future directory creation.

You can also build the profile from a signing identity manager with `WebBotAuthProfile.fromIdentityManager(idm)`.

The `includeSignatureAgent` configuration and per-request `signatureAgent` omission options have been removed. Only the current DNSid operational key is accepted, without overlapping-key grace. Verification requires `RefreshingIdentityResolver`; missing `refreshDomain` raises `ArgumentError` on construction. After valid request and directory signatures, a current-key mismatch permits one `refreshDomain` attempt per normalized signer domain per five seconds, shared across concurrent calls and discovery URLs. Failed attempts consume the allowance; concurrent retries are suppressed. Admission state is capped at 1024 domains and fails closed when full. Refreshed evidence must pass normal acceptance, current-peer, current-key, and freshness checks. There is no eviction workaround or stale fallback. Propagation and availability can still interrupt rotation, and learning the new key rejects outstanding old-key requests.

The agent domain is the identity FQDN, not its accountable entity or request destination. WBA discovery must be separate from the live `ku` JWKS, including query/fragment variants. `fromIdentityManager` rejects locally configured `ku` discovery; verification checks the authenticated `ku` endpoint. Validated HTTPS at the agent's public `ku` endpoint supplies DNSid's agent-FQDN TLS check without inbound access to the crawler process. With `fl=mtls`, current application-peer evidence remains required.

Use the shared managed rotation/recovery workflow, pause request and directory signing during rotation, and probe new-key requests through a verifier caching the old key. For a lost or suspected compromised key, stop signing and use revocation/reissuance, not routine rotation. Short TTLs and mismatch refresh do not revoke stolen keys. The same `ku` also authorizes `KEY_ROTATION`: unrestricted key access on a signing node can authorize identity rotation, not just forge requests. Keeping `ek` off the fleet does not remove this exposure; dedicated fleet-key delegation requires a separate security design.
