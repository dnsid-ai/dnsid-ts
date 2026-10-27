# @dnsid-ai/http-signatures

DNSid RFC 9421 HTTP Message Signatures profile helpers.

This package provides signing, verification, canonicalization, digest, nonce, and algorithm-mapping helpers built on `@dnsid-ai/protocol` contracts. It does not include DNS or HTTPS transport defaults.

## Install

```sh
npm install @dnsid-ai/http-signatures @dnsid-ai/protocol
```

## Example

```ts
import { createHttpSignaturesProfile } from '@dnsid-ai/http-signatures';

const httpSignatures = createHttpSignaturesProfile({
  domain: 'agent.example',
  keyProvider,
  identityResolver,
});
```

Verification accepts `{ peerCert, timeoutMs, signal }`. `peerCert` is the trusted
current application peer, required for `fl=mtls`, including cached identities.
The overall default is 30 seconds across all signature candidates, discovery,
and body digest work. Standalone verification rejects signature headers over
16 KiB, more than 16 labels, more than 64 covered components per label, and
bodies over 1 MiB; bodies are bounded while reading without changing their bytes.
Injected identity resolvers must honor cancellation and enforce bounded I/O.
`fl=logchk` remains caller-owned operation policy.

## Negotiated response authentication

Request signatures alone do not authenticate the responder. Enable the RFC 9421
§5 response profile explicitly:

```ts
import { createResponseSignatureTransport } from '@dnsid-ai/transport';

const responseTransport = createResponseSignatureTransport(transportConfig);
const signedFetch = httpSignatures.createSignedFetch({
  fetch: globalThis.fetch, // Used only when responseSignature is absent.
  responseTransport,
  timeoutMs: 30_000,
  signing: {
    responseSignature: {
      expectedDomain: 'service.example', // Local agent policy, not necessarily the URL host.
      additionalComponents: ['content-type'],
    },
  },
});
const response = await signedFetch('https://gateway.example/operation');
```

The client emits one `sig1` negotiation with a fresh 32-byte base64url challenge,
requests timestamps, and covers `accept-signature` in its request signature. The
response must cover status, originating request method/authority/target,
negotiation and both request signature fields, content digest, cache policy, and
selected additions. The client snapshots each invocation's policy and request,
verifies the requested label against the expected agent before returning **any**
response, including HTTP errors and redirects, and preserves exact response bytes.
A gateway cannot substitute a differently signed request with the same challenge.

`responseTransport` is required in this mode. Ordinary fetch cannot disable hidden
transport retries or expose the current peer certificate and is rejected before
sending. The trusted transport contract requires one send without redirects,
retries/replay, caches, or transparent content decoding; it must honor the request
abort signal. The Node implementation meets that contract and returns the actual
connection's certificate. Custom transports must provide equivalent guarantees;
a discovery certificate or a previous connection's certificate is not a substitute.
`fl=mtls` requires the current server peer, including DNSid cache hits. Configured
entity acceptance and all normal DNSid status/lifecycle checks still apply on every
verification. `expectedDomain` does not replace `trustedEntities` policy.

The send, bounded read, and verification share a finite budget (default 30 seconds).
Requests use `redirect: 'manual'` and `cache: 'no-store'`; the SDK never automatically
resends an operation. Start explicit attempts from the **unsigned original**, with
fresh preparation. HTTPS is mandatory; response authentication occurs **after**
request data is sent, not before disclosure of sensitive data.

### Standalone helpers and server use

```ts
// Client: retain BOTH snapshots, without later mutation.
const policy = { expectedDomain: 'service.example', additionalComponents: ['content-type'] };
const prepared = await httpSignatures.createSignedHttpRequest(unsignedRequest, {
  responseSignature: policy,
});
const savedRequest = prepared.clone();
const { response, peerCert } = await responseTransport(prepared);
const identity = await httpSignatures.verifySignedHttpResponse(
  savedRequest, response, policy, peerCert, { timeoutMs: 30_000 },
);

// Server, before sending headers/content:
const caller = await serverProfile.verifySignedHttpRequest(incomingRequest, { peerCert: callerPeer });
// Apply application authorization before processing the request.
const signedResponse = await serverProfile.signRequestedHttpResponse(incomingRequest, finalResponse);
```

Standalone callers are responsible for retaining the unmodified prepared request
and the original local policy snapshot until verification completes. Standalone
request preparation neither sends nor verifies a response. `verifySignedHttpResponse`
returns `VerifiedDomain`; only after success may the response be used as
authenticated. Its optional fifth argument accepts `{ timeoutMs, signal }`.

Without `Accept-Signature`, the server helper returns the identical response and
makes no key-provider call, even in a verification-only profile. Otherwise it
strictly validates the complete negotiation, signs with the current operational
key, preserves unrelated signature labels, and rejects label collisions. It sets
SHA-256 `Content-Digest` and adds `Cache-Control: no-store` without deleting other
directives. It returns a new response only after signing succeeds; errors never
fall back to unsigned success. Server applications should sign application error
responses too. Finalize content coding/covered metadata before signing and do not
modify covered bytes afterward.

Only **covered** metadata is authenticated. `Content-Type`, `Content-Encoding`,
and `Location` are not covered by default. Request their coverage when the
application relies on them, or use a trusted interpretation. A digest authenticates
content bytes, not the meaning supplied by an uncovered content type or encoding.

### Limits and content ownership

Negotiation and each signature header are limited to 16 KiB, signature dictionaries
to 16 labels, component lists to 64 entries, and response challenges to 1024 encoded
characters (at least 32 decoded bytes, canonical unpadded base64url). Enabled request
preparation and response helpers read at most 1 MiB of content under a finite budget.
Standalone response helpers default to 30 seconds. Limits reject the complete
operation, not a subset of candidates. Owned response resources are canceled on
verification failure, cancellation, or oversized content. Successful verification
preserves the original response, including exact content bytes. Host transports
must enforce their own finite HTTP header/input limits before constructing messages.

A supplied empty body is distinct from unavailable ordinary content. HEAD and
204/205/304 responses use the semantically empty digest; supplied nonempty content
on these no-content responses is rejected. Ordinary content must be available.
Informational responses, protocol upgrades, and tunnels are not authenticated by
these helpers. Native WHATWG `Response` cannot represent informational responses;
the Node transport rejects upgrades and tunnel establishment. Raw coded content
can be authenticated; transparently decoded bytes fail digest verification rather
than being substituted for the signed representation.

Native conformance cases `NR01`–`NR26` in `test/http-response-signing.test.ts`
follow the shared negotiated-response table in order. Live HTTPS checks in
`test/http-response-transport.test.ts` also cover raw bytes, current peers,
redirect/replay prevention, upgrades/tunnels, and resource cleanup.

`@dnsid-ai/sdk` also re-exports this package as `httpSignatures` and exports `HttpSignaturesProfile` / `createHttpSignaturesProfile` directly.
