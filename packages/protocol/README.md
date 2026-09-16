# @dnsid-ai/protocol

Protocol core for DNSid TypeScript packages.

Use this package when you want the DNSid protocol engine and contracts without runtime-specific defaults.

## Responsibilities

- `IdentityManager`
- DNSid TXT record parsing, validation, serialization, and canonicalization
- JWKS validation and JWK thumbprints
- Protocol data types and strict protocol status validation
- DNS, fetch, cache, key-provider, and log contracts
- Common DNSid errors and verification primitives

This package intentionally does not include Node DNS/HTTPS transport, local filesystem key storage, environment-variable loading, registry-specific lifecycle behavior, or profile-specific conveniences.

## Install

```sh
npm install @dnsid-ai/protocol
```

## Example

```ts
import { IdentityManager } from '@dnsid-ai/protocol';

// config is data only; runtime objects are injected as dependencies.
const idm = new IdentityManager(
  {
    identity,                                  // omit for a verification-only manager
    verification: { dnssecMode: 'required', trustedEntities: [{ governanceId: 'acme.example' }] },
  },
  { keyProvider, entityKeyProvider, logRegistry, dnsResolver, cache, fetchJson },
);
```

`verification.trustedEntities` is an optional counterparty allowlist checked on every
`verifyDomain` return (including cache hits) after protocol verification. Entries match
the verified record's governance ID exactly; optional `entityKeyThumbprints` pin the
current record-signing key. Omit it to make no acceptance decision; `[]` denies all. A
denial raises `VerificationError` with code `CounterpartyNotAccepted` carrying only the
observed `verifiedGovernanceId`/`verifiedEntityKeyThumbprint`.

The core has no default DNS or HTTPS implementation, so `config.transport` settings are
rejected here; use `@dnsid-ai/sdk/node`, which consumes them for its defaults.

For ergonomic Node.js defaults, use `@dnsid-ai/sdk/node` with `@dnsid-ai/transport`.

## Verification context and limits

`verifyDomain(domain, peerCert?, { timeoutMs?, signal? })` has a 30-second
whole-operation default. Each coalesced caller retains its deadline; shared
identity work also has a 30-second cap and is canceled when its last caller leaves.
DNS, HTTPS redirects, and lifecycle evidence share the remaining budget.
Injected resolvers, fetchers, and log factories must honor the supplied signal,
keep trust configuration immutable, and bound their responses before allocation.
Native system DNS work may finish in the background under the platform's finite
resolver retry limits; canceled verification does not proceed or populate caches.
TXT input is limited to 65,535 characters/1,024 chunks; JWKS and status fetches
request 256 KiB and 16 KiB limits respectively.

Injected caches are namespaced per manager, never shared by domain alone.
Configuration and log-method selection are snapshotted at construction; use a
new manager for changed trust policy. DNS expiry starts at lookup acquisition,
not verification completion. Status refresh never extends it, zero-TTL answers
are never reused, and DNS/TLS/key-age bounds are checked before returning.

## High-value operation log checks

`verifyDomain()` validates the bilateral ISSUANCE binding for every identity. If
the verified record advertises `fl=logchk`, the application must additionally
perform a current non-revocation check before relying on the identity for an
operation it classifies as high value or irreversible:

```ts
const verified = await idm.verifyDomain('agent.example.com');
if (verified.requiresLogCheck()) {
  const evidence = await verified.verifyNonRevocation();
  console.log(evidence.logReference, evidence.freshnessTime);
}
```

Operation classification remains application policy. Call
`verifyNonRevocation()` regardless of the advertised flag when local policy
requires it. The returned evidence retains the verified history, completeness,
checkpoint, and freshness boundary. Log unavailability or stale evidence fails the check closed.
