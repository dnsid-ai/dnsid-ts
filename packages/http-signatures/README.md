# @identity-digital/dnsid-http-signatures

DNSid RFC 9421 HTTP Message Signatures profile helpers.

This package provides signing, verification, canonicalization, digest, nonce, and algorithm-mapping helpers built on `@identity-digital/dnsid-protocol` contracts. It does not include DNS or HTTPS transport defaults.

## Install

```sh
npm install @identity-digital/dnsid-http-signatures @identity-digital/dnsid-protocol
```

## Example

```ts
import { createHttpSignaturesProfile } from '@identity-digital/dnsid-http-signatures';

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

`@identity-digital/dnsid` also re-exports this package as `httpSignatures` and exports `HttpSignaturesProfile` / `createHttpSignaturesProfile` directly.
