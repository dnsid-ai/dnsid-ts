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

The client verifies the response against the expected agent before it returns
**any** response, including HTTP errors and redirects. `responseTransport` is
required: ordinary fetch cannot disable hidden retries, keep raw content bytes,
or expose the current peer certificate. Custom transports must send once, without
redirects, retries, caches, or content decoding, and must honor the abort signal.
`expectedDomain` does not replace resolver `trustedEntities` policy. Start each
explicit retry from the unsigned original request. HTTPS is mandatory; the
responder is authenticated **after** request data is sent.

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

Standalone callers must retain the unmodified prepared request and the original
policy snapshot until verification completes. Without `Accept-Signature`, the
server helper returns the response unchanged and does not use the key provider.
Finalize content coding and covered headers before signing. Errors never fall
back to an unsigned response.

Only **covered** metadata is authenticated. `Content-Type`, `Content-Encoding`,
and `Location` are not covered by default; request them through
`additionalComponents` when the application relies on them.

### Limits

Negotiation and each signature header: 16 KiB. Signature dictionaries: 16 labels.
Component lists: 64 entries. Challenges: 1024 encoded characters, at least 32
decoded bytes. Content: 1 MiB. Default budget: 30 seconds. HEAD and 204/205/304
responses use the empty-content digest; other responses must supply content.
Rejected or cancelled responses are cancelled and never returned as authenticated.

Native conformance cases `NR01`–`NR26` in `test/http-response-signing.test.ts`
follow the shared negotiated-response table in order. Live HTTPS checks in
`test/http-response-transport.test.ts` also cover raw bytes, current peers,
redirect/replay prevention, upgrades/tunnels, and resource cleanup.

`@dnsid-ai/sdk` also re-exports this package as `httpSignatures` and exports `HttpSignaturesProfile` / `createHttpSignaturesProfile` directly.
