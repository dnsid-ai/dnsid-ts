# DNSid OIDC example

Minimal Node example for the DNSid OIDC federation profile
(`@dnsid-ai/oidc`): minting OIDC credentials from a DNSid
identity.

It always runs an **offline** flow:

1. Generates an operational key with `LocalKeyProvider` (from
   `@dnsid-ai/sdk/node`).
2. Creates an `OIDCTokenMinter` and mints a signed RFC 7523 JWT bearer
   client assertion (`iss`/`sub`/`fqdn` = `agent.example`, `aud` = issuer).
3. Decodes the assertion's header and claims with `decodeOIDCClaims` and
   prints them.

## Run

From the repo root:

```sh
npm install
npm run start -w @dnsid-ai/example-oidc
```

## Optional: live token exchange

Set both env vars to also exchange the assertion for an access token at a
real OIDC issuer's token endpoint (network access required):

```sh
DNSID_OIDC_ISSUER=https://issuer.example \
DNSID_OIDC_AUDIENCE=https://api.example \
npm run start -w @dnsid-ai/example-oidc
```

Replace the `.example` URLs with your real issuer and service audience. The issuer
must be an exact HTTPS issuer root (no path, query, or trailing slash). Live exchange
also requires the agent domain and generated operational key to be published as a
DNSid identity accepted by that issuer; setting the URLs alone is insufficient.
The offline example does not provision that identity.

## Note

Token minting is server-side only — it requires the agent's private
operational key. Never mint OIDC tokens or client assertions in
browser/client code.
