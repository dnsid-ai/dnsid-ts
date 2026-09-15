# Security Operations

Operational security details for this repository. For vulnerability reporting, see [SECURITY.md](../SECURITY.md).

## SAST / Code Scanning

This repository uses GitHub CodeQL (Actions workflow) for static analysis. Critical and high findings are triaged within 1 business day; medium findings within 5 business days.

## Secret Scanning

GitHub Secret Scanning is enabled on this repository. Any detected secrets are revoked and rotated immediately upon alert. Contributors must never commit credentials; use environment variables or GitHub Actions secrets instead.

## SBOM

Software Bill of Materials is available via the GitHub Dependency Graph. For a machine-readable SBOM, use:
```
gh api /repos/dnsid-ai/dnsid-ts/dependency-graph/sbom
```
Alternatively, generate locally with Syft:
```
syft dnsid-ai/dnsid-ts -o spdx-json
```

## Monitoring

Repository activity is monitored via GitHub audit logs and Dependabot alerts. Unusual activity (force pushes, new admin grants, secret alerts) is escalated to the security team within 1 business day.

## Key rotation and token overlap

DNSid has two key roles in draft-01 records:

- **`ek` accountable-entity / record-signing key** — signs the identity record.
- **`ku` operational key** — signs runtime artifacts such as DNSid JOSE JWTs, HTTP Message Signatures, and lifecycle events.

The SDK's managed rotation path rotates the operational `ku` key as an immediate cutover. `rotateOperationalKey()` generates a pending key, publishes a JWKS containing only the new operational key, writes a `KEY_ROTATION` lifecycle event linking the previous and new key material, activates the new key, and then supersedes the previous key in the configured `KeyProvider`. Draft-01 operational JWKS validation expects exactly one current signing key, so this SDK release does not support publishing old and new operational signing keys together for JWT overlap.

### JWTs after signing-key rotation

DNSid JOSE JWTs carry the signing key's bare `kid` in the JWT header. Verification resolves the issuer's current DNSid identity, reads the issuer's current published JWKS, finds that `kid`, checks the JWT time claims, checks algorithm/key consistency, and verifies the signature.

That means a JWT signed before rotation remains verifiable only while all of the following stay true:

1. the JWT is still within its `exp`, `iat`, `nbf`, `maxLifetime`, and clock-skew limits;
2. the verifier can still resolve a non-expired DNSid identity result whose JWKS contains the old key; and
3. the status endpoint still reports the agent as `ACTIVE`.

New calls to `createJWT()` use the active key returned by the `KeyProvider`. The default DNSid JOSE lifetime and maximum accepted lifetime are both 15 minutes, with 60 seconds of clock skew. Because this release publishes exactly one current operational signing key, operators should pause or drain old-key JWT issuance and wait for existing JWTs to expire before cutover. If you configure a longer JOSE lifetime, extend that drain period to match it.

### Recommended overlap and cleanup

Use this minimum drain/overlap calculation before cutting over to a new operational key or deleting retained key material:

```
max JWT lifetime
+ allowed clock skew
+ DNS TTL for _dnsid records and any CDN/JWKS cache TTL
+ IdentityManager cache lifetime
+ status refresh interval
+ operational deployment skew
```

For the defaults in this repository, start with at least 20 minutes for short-lived JWTs, then add your published DNS/JWKS/cache TTLs and deployment skew. Production operators usually choose a longer conservative window, such as one to several hours, when downstream caches or partner verifiers are not tightly controlled. With the built-in managed helper, treat that interval as a pre-cutover drain period because old and new operational signing keys are not published together.

For SDK-managed rotation, the old operational key is superseded as part of the successful rotation transaction. Do not call the provider's `supersede(kid)` again for that old key after the drain period; by then `LocalKeyProvider` has already removed it from the local key store, and `AwsKmsKeyProvider` has already removed it from provider state and, when `scheduleKeyDeletionOnPurge` is enabled, scheduled AWS KMS deletion. The final KMS deletion timing is governed by AWS KMS policy.

Choose rotation intervals from your operational risk model. The SDK enforces `ka` when the identity record includes a maximum operational key age, so set rotation cadence comfortably below that limit. If no `ka` is published, use your internal key-management standard, incident-response requirements, and cloud KMS/HSM policy as the rotation driver.

### Revocation, JWKS, status, and cache implications

A non-`ACTIVE` status response is a revocation signal for SDK verification. On a fresh verification, `verifyDomain()` fetches the status document and rejects states other than `ACTIVE`. On a cached verification, `statusCheckInterval` controls whether the cached identity can be reused before re-fetching status:

- default `statusCheckInterval` is `0`, so cached results re-fetch status on each `verifyDomain()` call;
- when `statusCheckInterval > 0`, a cached result may be reused without a status fetch until that interval elapses;
- if status refresh returns a non-`ACTIVE` state, the cache entry is evicted and verification fails.

Identity cache entries also expire at the earliest of the DNS TXT TTL, the TLS certificate expiry, or the `ka` maximum key age when present. The default Node resolvers cannot observe real DNS TTLs and report TTL 0, so identity evidence they produce is never reused beyond the acquiring operation; inject a TTL-aware `DNSResolver` to enable identity caching. Explicitly call `evictDomain(domain)` after emergency rotation or revocation if you need a local process to drop a cached identity immediately.

### Provider-specific notes

- **Local keys** (`LocalKeyProvider`) are file-backed and intended for local development, examples, and tightly controlled deployments. Keep stores private and back them up if identity continuity matters. SDK-managed operational rotation removes the old retained key during the successful rotation transaction.
- **AWS KMS** (`@identity-digital/dnsid-key-aws`) keeps private key material in AWS KMS and exposes the DNSid `KeyProvider` contract. KMS deletion, recovery windows, aliases, grants, and audit retention are AWS operational policy, not DNSid SDK policy.
- **Other KMS/HSMs** can implement `KeyProvider`, but this repo does not currently publish production GCP, Azure, or generic HSM providers. Match their retained-key and deletion behavior to the overlap formula above.
- **Runtime examples** show local and AWS-backed key providers where supported. Browser/client runtimes should not hold DNSid private signing keys.

## Production operational behavior

### API versioning and compatibility

The TypeScript SDK is pre-1.0. Package versions are synchronized across this monorepo, and package interdependencies use matching `^0.15.0` ranges in this release line. DNSid protocol compatibility is driven by the current identity-record parser, JWKS validation, lifecycle log verification, and status document validation in `@identity-digital/dnsid-protocol`. Upgrade SDK and server/registry components together when protocol behavior changes.

### HTTP fetch, redirects, timeouts, retries, and response caps

The protocol verifier is runtime-neutral. It only performs network I/O when a caller injects a `JsonFetcher`; the Node helpers wire that to `@identity-digital/dnsid-transport`.

Node `fetchJson()` behavior:

- HTTPS only; plain HTTP URLs are rejected.
- Optional `allowedHost` pinning is used by JWKS verification: `ek`/record-signing JWKS may be on the governance domain or a subdomain, and `ku` runtime JWKS must be on the agent FQDN. Status fetches use the record's `su` URL with HTTPS, SSRF-safe lookup, and response-size enforcement, but without JWKS-style host pinning.
- SSRF-safe lookup rejects private, loopback, link-local, multicast, documentation, CGN, reserved, 6to4/Teredo, and IPv4-mapped/compatible unsafe addresses.
- Redirects are followed up to 5 hops, but every redirect must stay HTTPS and satisfy the same host policy.
- Default timeout is 10 seconds per request; pass `timeoutMs` in transport options where you call `fetchJson` directly.
- Default body cap is 1 MiB. Protocol verification uses tighter caps: 256 KiB for JWKS and 16 KiB for status.
- Only HTTP 200 is accepted. HTTP 5xx responses and network-shaped transport failures are marked transient; TLS certificate failures and policy failures are not.
- JSON parse failures are reported as record-invalid verification failures.

The core retry helper `retryTransientVerification()` defaults to 3 total attempts, 100 ms initial delay, multiplier 2, 2 second max delay, and full jitter. It retries only `VerificationError` instances marked `transient` unless you provide a custom `shouldRetry` callback. Integrity, policy, malformed-record, signature, and revocation failures are not retried by default.

### DNS lookup, DNSSEC, and caching

`IdentityManager.verifyDomain()` looks up `_dnsid.<agent-fqdn>` TXT records through the injected `DNSResolver`. Missing TXT records produce a DNS-resolution verification failure. The Node system/custom resolver returns empty records for `ENODATA`/`ENOTFOUND`, maps `SERVFAIL` to DNSSEC `FAILED`, and otherwise reports DNSSEC state `UNKNOWN` because Node's resolver APIs do not expose DNSSEC validation results.

DNSSEC modes are:

- `auto` (default): accepts `VALID`, `UNSIGNED`, or `UNKNOWN`; rejects `FAILED`.
- `validated`: accepts `VALID` or `UNSIGNED`; rejects `UNKNOWN` and `FAILED`.
- `required`: accepts only `VALID`.

The default `InMemoryIdentityCache` is per manager/process. It caches successful `VerifiedDomain` results until `VerifiedDomain.expiry()`, which is the earliest DNS TTL, TLS certificate expiry, or `ka` key-age deadline. It does not negative-cache failed lookups. Custom caches must evict expired entries and be safe for concurrent use.

`createDnsResolverFromServer()` accepts a DNS server host, `host:port`, or `[ipv6]:port`. If the DNS server is provided as a hostname, that hostname is resolved once and cached for the resolver lifetime. TXT answers from the default Node resolvers carry TTL 0 (no SDK identity caching).

### Concurrency, async model, and lifecycle

Public verification, signing, key-provider, registry, transport, and log APIs are asynchronous and return promises. There is no synchronous domain verification path, because DNS, HTTPS, key storage, KMS, and log reads are asynchronous boundaries.

`IdentityManager`, `JoseProfile`, HTTP signature profiles, transport fetchers, and key providers are intended to be reused. Reuse preserves caches and avoids rebuilding DNS/HTTPS/KMS state. `InMemoryIdentityCache` uses timers that are `unref()`'d when supported, so cache timers do not keep Node running. The SDK does not expose a general `close()` or `dispose()` method; release resources owned by injected dependencies according to those dependencies' own lifecycle rules.

### Logging and errors

The SDK does not install a logger, emit structured logs, or write to console during normal library operation. To log, wrap injected dependencies such as `dnsResolver`, `fetchJson`, `KeyProvider`, registry `fetch`, or lifecycle log readers/writers. To disable SDK-originated logs, no action is needed beyond avoiding logging wrappers.

Common error mapping:

| Failure | Typical error surface |
| --- | --- |
| DNS resolution failure or no `_dnsid` record | `VerificationError` with `DNSResolution` |
| DNSSEC failed/unknown under strict policy | `VerificationError` with `DNSSECFailed` |
| Malformed TXT record, JWKS, status, or invalid JSON | `ParseError`, `ValidationError`, or `VerificationError` with `RecordInvalid` depending on layer |
| TLS failure, expired certificate, hostname mismatch, timeout, unsafe address, disallowed redirect, oversized response, non-200 response | `VerificationError` with `TLSError` |
| Invalid record/JWT/JWS/HTTP signature | `VerificationError` with `SignatureInvalid` or `RecordInvalid` |
| Expired JWT or JWT lifetime/claim violation | `VerificationError` with `RecordInvalid` |
| Status unavailable or unusable | `VerificationError` with `StatusUnavailable` |
| Revoked, retired, suspended, or otherwise non-active identity status | `VerificationError` with `StatusNotActive` and `agentState` |
| Operational key older than `ka` | `VerificationError` with `KeyAgeExceeded` |
| Lifecycle log read, continuity, or revocation-check failure | `VerificationError` with `LogError` |

### Proxy and TLS behavior

The built-in Node protocol transport does not read `HTTP_PROXY`, `HTTPS_PROXY`, or `SOCKS_PROXY` environment variables, and it does not include authenticated proxy support. If your environment requires a proxy, inject a fetcher/dispatcher that enforces the same DNSid HTTPS, host, response-size, timeout, redirect, and SSRF protections.

TLS verification uses Node's TLS stack with `rejectUnauthorized: true`. `DNSID_CA_BUNDLE` / `caBundlePath` appends an extra PEM CA bundle to Node's root certificates for SDK-managed HTTPS. The SDK does not currently expose first-class options for client certificates, certificate pinning, FIPS mode selection, or enterprise trust-store integration beyond what your Node runtime and injected transport provide. For mTLS DNSid policy (`fl=mtls`), pass the peer certificate to `verifyDomain(domain, peerCert)`; verification requires a SAN matching the agent FQDN.

### Resource and performance guidance

Create and reuse managers, profiles, resolvers, fetchers, and key providers instead of constructing them per request. Keep response caps at or below the protocol defaults unless you have a clear reason to accept larger remote documents. Use `statusCheckInterval` carefully: raising it reduces status endpoint load but increases how long a process may reuse a cached identity before observing revocation. Use `evictDomain()` after emergency revocation, key compromise, or forced cache invalidation.
