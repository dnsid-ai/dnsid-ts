# @dnsid-ai/web-bot-auth

DNSid Web Bot Auth profile helpers.

This package signs and verifies DNSid Web Bot Auth requests (RFC 9421 HTTP Message Signatures with the `web-bot-auth` tag), serves signed key directories, and verifies discovered directories against current DNSid operational (`ku`) keys. It targets `draft-meunier-webbotauth-httpsig-protocol-00` and `draft-meunier-webbotauth-httpsig-directory-00`, which are Internet-Drafts, not finalized WBA standards. External partner interoperability has not been tested.

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

The directory response is itself signed with the `http-message-signatures-directory` tag and served as `application/http-message-signatures-directory+json`.

## Verify a request

Verification-only construction does not need a local identity or signing key:

```ts
import { createSsrfSafeFetch } from '@dnsid-ai/transport'; // Node transport

const safeFetch = createSsrfSafeFetch();
const verifier = createWebBotAuthProfile({
  identityResolver, // configured DNSid resolver, including entity acceptance
  discoveryFetch: request => safeFetch(request),
});
const identity = await verifier.verifyWebBotAuthSignedRequest(request, {
  signerDomain: 'agent.example', // trusted application policy
  peerCert, // current application peer certificate, required for fl=mtls
  timeoutMs: 30_000,
  signal,
});
```

Install `@dnsid-ai/transport` to use this Node transport. The package stays runtime-neutral: `discoveryFetch` is required and must enforce valid Web PKI, public-address DNS checks and connection pinning on every connection, manual redirects, and cancellation. Ordinary server-side `fetch` is not safe for untrusted discovery. Do not enable private-address exceptions for WBA discovery.

Alternatively, explicitly set `allowSignatureAgentDomain: true` to let the signed HTTPS discovery host identify the signer. Cross-host delegation is rejected. Without `Signature-Agent`, supply both `signerDomain` and trusted `discovery: { uri, type }`. The default discovery type is `directory`; `jwks_uri` addresses a direct signed directory endpoint, not an unsigned JWKS.

Every invocation verifies request and directory signatures, content digests, and current DNSid key binding and acceptance. There is no directory-only fallback or internal directory cache. Results authenticate identity but do not grant application permissions. The required coverage is `@authority`, not method or path; use `additionalComponents` when your operation requires those bindings.

For one-time requests, supply `consumeNonce(entry, signal)`. It must atomically consume `(signerDomain, keyid, nonce)` and retain the entry until `retainUntil` (`expires + clockSkew`). Return `false` for reuse; store errors reject verification. Without this hook, time-valid requests can be replayed.

The overall timeout defaults to 30 seconds and covers discovery, reads, DNSid verification, and replay storage. Limits are five redirects, 256 KiB directory content, 64 keys, JSON depth 16, 16 KiB signature/discovery/digest headers and URLs, 64 KiB aggregate header characters, and 1 MiB request content. The hosting layer must bound incoming request streams before cloning them; verification preserves the original request body. Signature lifetimes cannot exceed 300 seconds. Evidence freshness is checked again before return.

## Options

- `signatureAgent` — the discovery URI and type advertised in `Signature-Agent`. It defaults to the domain's HTTPS origin with `type=directory`; use `type=jwks_uri` for a direct JWKS endpoint.
- `directoryURL` — deprecated compatibility option interpreted as a direct `jwks_uri` endpoint. Use `signatureAgent.uri` instead.
- `signatureTTL` / `directorySignatureTTL` — signature lifetimes in seconds (defaults: 60 for requests, 300 for the directory).
- `includeSignatureAgent` — set `false` to omit the generated `Signature-Agent` member; verification then needs trusted out-of-band discovery.
- `clockSkew` — non-negative verification tolerance in seconds (default: 5).

You can also build the profile from a signing identity manager with `WebBotAuthProfile.fromIdentityManager(idm)`.
