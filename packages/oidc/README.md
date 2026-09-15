# @identity-digital/dnsid-oidc

DNSid OIDC federation helpers for server-side token minting and verification.

## Install

```sh
npm install @identity-digital/dnsid-oidc
```

For Node.js local key loading, also install the aggregate SDK:

```sh
npm install @identity-digital/dnsid @identity-digital/dnsid-oidc
```

## Mint an OIDC access token from server code

Use `mintOIDCToken()` when an agent service needs to call another service, gateway, or tool with a DNSid OIDC bearer token.

```ts
import { LocalKeyProvider } from '@identity-digital/dnsid/node';
import { mintOIDCToken } from '@identity-digital/dnsid-oidc';

const agentDomain = process.env.DNSID_DOMAIN!;
const audience = process.env.AGENTCORE_GATEWAY_AUDIENCE!;
const issuer = process.env.DNSID_OIDC_ISSUER;

const keyProvider = await LocalKeyProvider.load(
  process.env.DNSID_KEY_STORE ?? '.dnsid/keys.json',
);

const token = await mintOIDCToken({
  domain: agentDomain,
  keyProvider,
  audience,
  scopes: ['openid', 'dnsid'],
  issuer,
  serverUrl: issuer ? undefined : process.env.DNSID_SERVER_URL,
  timeoutMs: 5000,
});

await fetch(process.env.AGENTCORE_GATEWAY_URL!, {
  method: 'POST',
  headers: {
    authorization: `Bearer ${token.accessToken}`,
    'content-type': 'application/json',
  },
  body: JSON.stringify({ input: 'status' }),
});
```

Configure either:

- `issuer` for explicit OIDC issuer discovery, which uses the discovered same-origin `token_endpoint`.
- `serverUrl` for DNSid CLI-compatible server mode, which discovers the issuer from the server but posts to `<serverUrl>/token`.
- `issuer` plus `tokenEndpoint` to bypass discovery when both values are already trusted configuration.

`scope` accepts the CLI-style space-separated string. `scopes` accepts an array and joins it with spaces. Empty scope values are omitted so the DNSid server default applies.

## Private JWK input

Applications with private JWK material can use `privateJwk` directly:

```ts
import { mintOIDCToken } from '@identity-digital/dnsid-oidc';

const token = await mintOIDCToken({
  domain: 'agent.example.com',
  privateJwk,
  issuer: 'https://oidc.dnsid.example',
  audience: 'https://gateway.example.com',
});
```

If the JWK has no `kid`, the SDK computes the RFC 7638 JWK thumbprint and uses that as the JWT header `kid`.

## Verification boundaries

`verifyOIDCToken(token, { issuer, audience, peerCert, timeoutMs, signal })`
uses a 30-second overall default across discovery, JWKS and DNSid subject
verification. Supply trusted current-peer evidence when the subject requires
`fl=mtls`; it is forwarded on every invocation, including cache hits.
Strict compact JSON parsing rejects duplicate members and malformed headers or
NumericDates before discovery. Tokens are capped at 1 MiB, encoded headers at
16 KiB, and fetched JSON at 1 MiB. Expiration is rechecked after subject discovery
without skew grace. Zero skew is respected; invalid explicit lifetimes fail.
Injected transports/resolvers must honor cancellation and bounded-response contracts.

## Server-side only

Do not mint DNSid OIDC tokens in browser or client code. The private key or signing provider must stay on trusted server infrastructure such as an AgentCore-hosted service, backend worker, KMS-backed signer, HSM, or equivalent server-side runtime.

Minting a token is not the trust decision. Receivers still verify the DNSid OIDC token, issuer, audience, signature, and DNSid subject status according to their verifier policy.
