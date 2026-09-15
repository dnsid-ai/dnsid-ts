# DNSid OIDC example

Minimal Node example for the DNSid OIDC federation profile
(`@identity-digital/dnsid-oidc`): minting OIDC credentials from a DNSid
identity.

It always runs an **offline** flow:

1. Generates an operational key with `LocalKeyProvider` (from
   `@identity-digital/dnsid/node`).
2. Creates an `OIDCTokenMinter` and mints a signed RFC 7523 JWT bearer
   client assertion (`iss`/`sub`/`fqdn` = agent domain, `aud` = issuer).
3. Decodes the assertion's header and claims with `decodeOIDCClaims` and
   prints them.

## Run

From the repo root:

```sh
npm install
npm run start -w @identity-digital/dnsid-example-oidc
```

## Optional: live token exchange

Set both env vars to also exchange the assertion for an access token at a
real OIDC issuer's token endpoint (network access required):

```sh
DNSID_OIDC_ISSUER=https://issuer.example.com \
DNSID_OIDC_AUDIENCE=https://api.example.com \
npm run start -w @identity-digital/dnsid-example-oidc
```

The issuer must be an exact HTTPS issuer root (no path, query, or trailing
slash), and its DNSid operational key must match the assertion's signing key
for the exchange to succeed.

## Note

Token minting is server-side only — it requires the agent's private
operational key. Never mint OIDC tokens or client assertions in
browser/client code.
