# @identity-digital/dnsid-jose

DNSid JOSE profile helpers for JWT and JWS workflows.

This package builds on `@identity-digital/dnsid-protocol` contracts and does not perform DNS or HTTPS transport itself. Provide an identity resolver and key provider directly, or construct the profile from a signing `IdentityManager`.

## Install

```sh
npm install @identity-digital/dnsid-jose @identity-digital/dnsid-protocol
```

## Example

```ts
import { createJoseProfile } from '@identity-digital/dnsid-jose';

const joseProfile = createJoseProfile({
  domain: 'agent.example',
  keyProvider,
  identityResolver,
});
```

## Verification

A verification-only profile may omit `domain` and `keyProvider`:

```ts
const verifier = createJoseProfile({ identityResolver });
await verifier.verifyJWT(token, {
  expectedAudience: 'service.example', // trusted configuration, never token-derived
  peerCert, // trusted current application peer; required for fl=mtls
  timeoutMs: 5000,
  signal,
});
await verifier.verifyJWS(jws, { peerCert, signal });
```

Both helpers default to a 30-second overall deadline and pass cancellation to
identity discovery. Compact tokens are limited to 1 MiB and encoded headers to
16 KiB before decoding. Duplicate JSON members, unsupported critical/unencoded
headers, and incorrectly typed claims are rejected before discovery. Expiration
has no skew grace and is checked again after verification; fractional NumericDates
and explicit zero clock skew are supported. Explicit invalid lifetimes are errors.
`fl=logchk` remains caller-owned operation policy.

`@identity-digital/dnsid` also re-exports this package as `jose` and exports `JoseProfile` / `createJoseProfile` directly.
