# @identity-digital/dnsid-web-bot-auth

DNSid Web Bot Auth profile helpers.

This package signs outbound HTTP requests per the Web Bot Auth draft (RFC 9421 HTTP Message Signatures with the `web-bot-auth` tag) and serves the `/.well-known/http-message-signatures-directory` document so origins can discover and verify an agent's keys.

It builds on `@identity-digital/dnsid-http-signatures` and `@identity-digital/dnsid-protocol` contracts and performs no DNS or HTTPS transport itself. Signing requires an Ed25519 operational key; the profile throws `ArgumentError` for other key types.

## Install

```sh
npm install @identity-digital/dnsid-web-bot-auth @identity-digital/dnsid-protocol
```

## Example

Sign an outbound request:

```ts
import { createWebBotAuthProfile } from '@identity-digital/dnsid-web-bot-auth';

const profile = createWebBotAuthProfile({
  domain: 'agent.example.com',
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

## Options

- `signatureAgent` — the discovery URI and type advertised in `Signature-Agent`. It defaults to the domain's HTTPS origin with `type=directory`; use `type=jwks_uri` for a direct JWKS endpoint.
- `directoryURL` — deprecated compatibility option interpreted as a direct `jwks_uri` endpoint. Use `signatureAgent.uri` instead.
- `signatureTTL` / `directorySignatureTTL` — signature lifetimes in seconds (defaults: 60 for requests, 300 for the directory).
- `includeSignatureAgent` — set `false` to omit the `Signature-Agent` header.

You can also build the profile from a signing identity manager with `WebBotAuthProfile.fromIdentityManager(idm)`.
