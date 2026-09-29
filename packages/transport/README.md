# @dnsid-ai/transport

Node.js transport implementation for DNSid TypeScript packages.

Use this package when you want default Node DNS and HTTPS/TLS plumbing for `@dnsid-ai/protocol` or `@dnsid-ai/sdk/node`.

## Responsibilities

- DNS TXT resolution through system DNS or a configured DNS server
- DNS server parsing and lookup helpers
- HTTPS JSON fetching
- SSRF-safe `fetch` for profile packages that need connection-time DNS checks
- TLS certificate capture
- custom CA bundle support
- custom DNS server support

This package is Node-only and intentionally separate from `@dnsid-ai/protocol`.

## Install

```sh
npm install @dnsid-ai/transport
```

## Example

```ts
import { createDefaultDnsResolver, createSsrfSafeFetch, fetchJson } from '@dnsid-ai/transport';

const dnsResolver = createDefaultDnsResolver({ dnsServer: process.env.DNSID_DNS_SERVER });
const result = await fetchJson('https://agent.example/.well-known/dnsid-status.json', {
  allowedHost: 'agent.example',
  dnsServer: process.env.DNSID_DNS_SERVER,
  caBundlePath: process.env.DNSID_CA_BUNDLE,
});

const safeFetch = createSsrfSafeFetch({ dnsServer: process.env.DNSID_DNS_SERVER });
```

Most Node applications should use this through `@dnsid-ai/sdk/node` or profile defaults.

Node's system TXT lookup API exposes no remaining TTLs, so the system resolver returns TTL `0` and disables SDK identity caching. With `dnsServer` configured, TXT queries use UDP (with TCP fallback on truncation) and return the recursive server's remaining TTL, capped at one day. Both paths report `DNSSECState.UNKNOWN` (`FAILED` on SERVFAIL); `validated`/`required` DNSSEC modes still require an injected validating resolver. Cached verification still re-fetches status unless `verification.statusCheckInterval` is set.

`createSsrfSafeFetch()` enforces unsafe-address rejection in the lookup used by the outgoing socket and returns redirects without following them automatically. Trusted test/private deployments may pass `privateAddressHosts`: exact hostnames or leading-dot suffixes such as `.test` (label-bounded, case-insensitive); only RFC 1918/ULA private and loopback results are then accepted for matching hosts, while link-local, mixed public/private, and IP-literal URLs remain blocked. Nothing is allowed by default, not even `.test`; a local `dnsid` stack needs `privateAddressHosts: ['.test']` (or `DNSID_PRIVATE_HOSTS=.test` through `loadEnvironment`). Profile packages that accept a custom `fetch` cannot force equivalent behavior on arbitrary implementations, so custom fetch injection remains trusted infrastructure.
