# @identity-digital/dnsid-registry

Registry control-plane client and TXT publishing helpers for DNSid TypeScript packages.

This package owns the current DNSid registry API surface and registry-shaped lifecycle/status behavior. It intentionally keeps registry-specific states separate from protocol-strict `@identity-digital/dnsid-protocol` agent status types.

## Install

```sh
npm install @identity-digital/dnsid-registry @identity-digital/dnsid-protocol
```

## Example

```ts
import { RegistryClient, publishClientControlledRecord } from '@identity-digital/dnsid-registry';

// Uses https://api.dnsid.ai by default; override with baseUrl if needed.
const registryClient = new RegistryClient({
  token: process.env.DNSID_REGISTRY_TOKEN,
});

await publishClientControlledRecord({
  config,
  entityKeyProvider,
  registryClient,
});
```

## Notes

Registry workflow status is kept separate from protocol `AgentStatus`. Client-controlled identities publish with `publishClientControlledRecord()`; registry-managed identities use `awaitRegistryManagedPublication()`, which requires an observed and verified DNS record before succeeding. `publishToRegistry()` remains as a deprecated compatibility alias.

The client supports self-managed, managed, zone-explicit, and Live registration workflows, authenticated/custom requests, verification/challenge helpers, typed preparation of C2SP issuance and key rotation, record signing, revoke, cancel, unregister, and retire helpers. `registerLiveAgent()` sets `tier: "live"` and `managed: true` internally, requires a separate idempotency key, and returns a distinct proof challenge rather than a normal registration. While `challenge_pending`, the response includes the assigned domain and validated challenge transcript. Sign the exact bytes decoded from the latest `challengeMessage`; a reissued challenge supersedes every earlier challenge and message. Preparation returns untrusted exact bytes and their bound log reference; it does not submit or append them. Registry-managed lifecycle operations are single-owner workflows: callers submit through the registry and must not append a duplicate local lifecycle event.

### Registration retries (breaking API change)

`registerAgent()`, `registerManagedAgent()`, `registerSelfManagedAgent()`, and
`registerInZone()` now require `input.idempotencyKey`. Generate and persist the
key **and registration input before the first attempt**, then reuse both for
reconciliation. Do not generate a fresh key on each retry: the POST may have
created an agent even when its response or the subsequent status GET fails.
Matching ordinary registration replays still require HTTP 201.

Request/response failures throw `RegistrationError` with `idempotencyKey`, the
original `cause`, and `domain` when the creation response supplied it. If the
domain is known, call `getRegistration(error.domain)` to recover status without
another POST; otherwise replay the original registration with the same key and
input. An error does not prove creation succeeded or failed. No automatic
retries are performed; resolve permanent request errors rather than blindly
retrying them. Replay safety depends on the registry's idempotency retention
policy; reconcile with the registry before retrying beyond that window.

Key-rotation preparation requires owner credentials: a session cookie or organization API key. An agent bearer token is not accepted.

Registry status semantics are still expected to align with ongoing registry server status work before this API is considered stable.

For the current product API, an omitted registration environment defaults to
`sandbox`, and `sandbox` is registry-managed. Self-managed registration therefore
requires an explicit non-sandbox environment through every registration entry
point and a domain. Sandbox, explicit `managed`, and zone registrations are
managed; managed registrations omit `domain`, and `domain` and `zoneId` are
mutually exclusive. Registration accepts `sandbox` or `production`
and rejects private JWK members before sending a request. Client-controlled
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
