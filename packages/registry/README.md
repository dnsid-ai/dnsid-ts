# @dnsid-ai/registry

Registry control-plane client and TXT publishing helpers for DNSid TypeScript packages.

This package owns the current DNSid registry API surface and registry-shaped lifecycle/status behavior. It intentionally keeps registry-specific states separate from protocol-strict `@dnsid-ai/protocol` agent status types.

## Install

```sh
npm install @dnsid-ai/registry @dnsid-ai/protocol
```

## Example

```ts
import { RegistryClient, publishClientControlledRecord } from '@dnsid-ai/registry';
import { createRegistryClientFromEnvironment } from '@dnsid-ai/sdk/node';

// Local by default: http://127.0.0.1:7755 from `dnsid local up`, no credential.
// Hosted: set DNSID_REGISTRY_URL and DNSID_API_KEY from the console.
const registryClient = await createRegistryClientFromEnvironment();
// Or explicitly: new RegistryClient({ baseUrl, token }). HTTPS required except on loopback.

await publishClientControlledRecord({
  config,
  entityKeyProvider,
  registryClient,
});
```

## Notes

Registry workflow status is kept separate from protocol `AgentStatus`. Client-controlled identities publish with `publishClientControlledRecord()`; registry-managed identities use `awaitRegistryManagedPublication()`, which requires an observed and verified DNS record before succeeding. `publishToRegistry()` remains as a deprecated compatibility alias.

The client supports self-managed, zone-explicit, and Live registration workflows, authenticated/custom requests, verification/challenge helpers, typed preparation of C2SP issuance and key rotation, record signing, revoke, cancel, unregister, and retire helpers. `registerLiveAgent()` sets `tier: "live"` and `managed: true` internally, requires a separate idempotency key, and returns a distinct proof challenge rather than a normal registration. While `challenge_pending`, the response includes the assigned domain and validated challenge transcript. Sign the exact bytes decoded from the latest `challengeMessage`; a reissued challenge supersedes every earlier challenge and message. Preparation returns untrusted exact bytes and their bound log reference; it does not submit or append them. Registry-managed lifecycle operations are single-owner workflows: callers submit through the registry and must not append a duplicate local lifecycle event.

### Unified registration and recovery

`registerAgent({ publicKeyJwk }, idempotencyKey?)` requests an assigned name under
the registry's sandbox root without injecting legacy defaults. Optional
`domain`, `rootDomain`, and `governanceDomain` select an exact FQDN, caller-owned
active root, and expected accountable GI. `domain` and `rootDomain` are mutually
exclusive. Assigned names require a public key; the registry decides hosting,
ownership, admission, and whether an exact-domain request requires a key.

The client validates the creation response's immutable `id`, domain, and required
`publication_config`, then reads authenticated management status to obtain
`publicationAuthority`. The returned `publicationConfig` and `oidcIssuerUrl` are
creation snapshots, not values inferred from selectors or replaced by later
status defaults. Persist them; they do not grant counterparty trust.

Ordinary registration permits an omitted key. For retry safety, generate and persist the
key **and registration input before the first attempt**, then reuse both for
reconciliation. Existing `input.idempotencyKey` remains supported. Do not generate a fresh key on each retry: the POST may have
created an agent even when its response or the subsequent status GET fails.
Matching ordinary registration replays still require HTTP 201.

Request/response failures throw `RegistrationError` with `idempotencyKey`, the
original `input` and `cause`, `httpStatus` and registry `code` when available,
and `creation` containing any decoded creation facts (including ID, domain,
publication configuration, and OIDC issuer). These facts remain untrusted if
validation failed. `domain` is also exposed when parsed. If the domain is known,
call `getRegistration(error.domain)` to recover status without another POST;
otherwise replay only with the original key and complete input. Do not retry an
unknown creation outcome without a key. Governance-unavailable or input-mismatch
errors do not trigger fallback roots, replacement creation, or anonymous reads. An error does not prove creation succeeded or failed. No automatic
retries are performed; resolve permanent request errors rather than blindly
retrying them.

Automatic managed recovery requires permanent **organization-scoped** replay claims. Identical
low-level key strings in different organizations are independent. Named SDK setup derives keys
from organization ID, normalized name, and the initial key thumbprint; the server must validate
those bindings before allocation, claim one nonterminal identity per organization/name atomically,
and reject conflicting keys/input without mutation or disclosure. Matching hosts open the same
immutable identity. Claims survive retirement/deletion: old replay returns the old identity or
a terminal error, never a replacement. Explicit replacement uses a fresh key, ID, domain, and
log stream, preserving history and rejecting all previously used keys.

`getOrganizationOnboarding()` reads the existing authenticated `/api/v1/org/onboarding` endpoint
and exposes organization ID, GI proof/gate readiness, and entity-key delegation status. Managed
setup validates readiness and all configured/saved bindings. Discovery does not return an entity
JWKS URL and does not establish counterparty trust. Failed reads are never retried anonymously.

These are required server contracts, not claims of deployed support. Verify them with real
server persistence/integration tests before enabling named recovery; the existing expiring store
is insufficient, and an acknowledgement flag cannot establish safety.

Key-rotation preparation requires owner credentials: a session cookie or organization API key. An agent bearer token is not accepted.

Registry status semantics are still expected to align with ongoing registry server status work before this API is considered stable.

Legacy selectors `environment`, `managed`, and `zoneId` remain supported;
explicit GI/root selectors are sent unchanged for server resolution.
`registerSelfManagedAgent({ domain })` and
`registerInZone({ zoneId, publicKeyJwk })` retain their production environment
default. An exact domain does not guarantee client-controlled publication.
Private JWK members and JWKS-shaped keys are rejected before any request is sent. Client-controlled
publication validates every known TXT tag against
the effective publication configuration. `config.maxKeyAge` controls the `ka`
tag; when omitted, the helper expects `ka` to be omitted. Legacy callers may
pass `effectiveMaxKeyAge` as an explicit override. Callers must configure the
effective `gi`, `ek`, `ku`, `lr`, `su`, `fl`, and `cu` values exactly.

`submitPreparedEvent()` throws `PreparedEventSubmissionError` for structured
product errors. Only `TLOG_SUBMISSION_BUSY` and
`TLOG_SUBMISSION_INDETERMINATE` are marked retryable; callers must retain and
retry the same idempotency key and exact entry bytes when
`retryWithSameBytes` is true.
