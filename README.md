# DNSid TypeScript SDK

Cryptographically verifiable identity for agents, anchored in DNS. DNSid binds an agent's identity to a domain the operator controls — a DNS TXT record plus JWKS documents — so any peer can verify who an agent is with nothing but DNS and HTTPS.

Node-specific packages, subpaths, tooling, and the CLI require Node.js >= 22.0.0.
Packages ship dual ESM/CJS builds; the default `@dnsid-ai/sdk`
entrypoint is also safe to bundle for browsers.

## Compatibility

| Area | Supported/tested baseline | Notes |
| --- | --- | --- |
| Node.js | Node.js 22.x in CI; Node-bound package metadata requires `>=22.0.0`. | `@dnsid-ai/transport`, `@dnsid-ai/oidc`, `@dnsid-ai/key-aws`, `@dnsid-ai/key-gcp`, the `@dnsid-ai/sdk/node` subpath, examples, and development tooling are Node-oriented. |
| Browser and non-Node runtimes | Root `@dnsid-ai/sdk` entrypoint and runtime-neutral packages can be bundled when callers inject DNS, JSON fetch, cache, log, and key-provider implementations. | The SDK does not ship browser DNS/DNSSEC, browser key custody, or browser transport defaults. Do not put private signing keys in browser/client code. |
| TypeScript | `typescript` 6.0.3 from `package-lock.json`; `tsconfig.json` targets ES2022 with `module: ESNext`, `moduleResolution: bundler`, `strict: true`, and `lib: ["ES2022", "dom"]`. | Published packages include declaration files from `tsup --dts`. |
| Module formats | ESM and CommonJS package exports. | Packages use `type: "module"` and expose both `import` (`dist/*.js`) and `require` (`dist/*.cjs`) entries. |
| Runtime dependencies | Locked by npm lockfile v3 and installed in CI with `npm ci`. Current key versions: `@noble/hashes` 2.2.0, `jose` 6.2.4, `structured-headers` 2.0.3, `undici` 8.9.0, `uuid` 14.0.1. | Published packages declare semver ranges; applications should use their own lockfile and upgrade through normal dependency review. |
| Package manager | npm with the committed `package-lock.json`. | CI uses `npm ci`; other package managers are not part of the tested baseline. |
| OS/architecture | Ubuntu Linux x64 in GitHub Actions. | macOS, Windows, Linux arm64, and other platforms are not intentionally blocked, but they are not release-gating test targets in this repository. |
| Examples | Example apps are development/demo workspaces, typechecked with Node-oriented tooling. | They are not published SDK packages and may carry extra demo dependencies or local-service assumptions. |

## Install

```sh
npm install @dnsid-ai/sdk @dnsid-ai/transport @dnsid-ai/log-c2sp-tlog
```

## Verify your first domain

```ts
import { createC2spTlogVerificationRegistry } from '@dnsid-ai/log-c2sp-tlog';
import { createNodeIdentityVerifier } from '@dnsid-ai/sdk/node';

const logRegistry = await createC2spTlogVerificationRegistry({
  // Explicitly trusted configuration for DNSid's public test log.
  policyUrl: 'https://log.dnsid.dev/dnsid-policy',
  // Local policy for any non-revocation checks made through this registry.
  checkpointMaxAge: 24 * 60 * 60 * 1000,
});
// Optional: accept only these accountable entities (exact governance-ID match).
const idm = await createNodeIdentityVerifier(
  { verification: { trustedEntities: [{ governanceId: 'acme.example' }] } },
  { logRegistry },
);

const verified = await idm.verifyDomain('your-agent.example.com');
console.log(verified.domain, verified.cachedState());

// Before an operation your application has classified as high value or irreversible:
if (verified.requiresLogCheck()) {
  const evidence = await verified.verifyNonRevocation();
  console.log(evidence.logReference, evidence.freshnessTime);
}
```

`fl=logchk` does not classify an operation as high value. The application makes
that policy decision and calls `verifyNonRevocation()` before relying on the
identity. Local policy may require the same check even when the record does not
advertise `logchk`. The returned evidence retains the verified history, completeness,
checkpoint, and freshness boundary. Log unavailability or stale evidence fails the check closed.

Never derive the policy URL from an unverified identity record or log reference. The factory's default checkpoint store protects against rollback only for the process lifetime; production deployments that need protection across restarts should inject durable storage.

A runnable version lives in [`examples/validate-domain`](examples/validate-domain/README.md). The Node helpers use the system or configured resolver by default. It reports DNSSEC state `UNKNOWN`, which the default `auto` policy accepts and preserves; inject a DNSSEC-aware resolver for stricter policy.

## Packages

| Package | Purpose |
| --- | --- |
| `@dnsid-ai/sdk` | Runtime-neutral SDK entrypoint. Verification requires injected DNS and JSON fetch implementations; local identity operations also require key providers. |
| `@dnsid-ai/sdk/node` | Node.js SDK convenience subpath: local file-backed keys, env config, and optional Node transport defaults. |
| `@dnsid-ai/protocol` | Protocol core: TXT/JWKS parsing, validation, identity verification, injected runtime interfaces. |
| `@dnsid-ai/transport` | Node.js DNS/HTTPS transport implementation. Node-only; uses Node built-ins and `undici`. |
| `@dnsid-ai/oidc` | DNSid OIDC federation profile helpers. |
| `@dnsid-ai/jose` | DNSid JOSE JWT/JWS profile helpers. |
| `@dnsid-ai/http-signatures` | DNSid RFC 9421 HTTP Message Signatures profile helpers. |
| `@dnsid-ai/web-bot-auth` | DNSid Web Bot Auth profile: signed bot requests + key directory. |
| `@dnsid-ai/registry` | Registry client and TXT publishing helpers. |
| `@dnsid-ai/log-c2sp-tlog` | Node.js C2SP lifecycle reader/verifier, plus portable `/writer` and `/version` subpaths used by the browser-safe root SDK. |
| `@dnsid-ai/key-aws` | AWS KMS-backed key provider. |

`@dnsid-ai/key-gcp` remains in the workspace as a private placeholder and is not published.

## Package layout

- **Root export (`@dnsid-ai/sdk`)** — runtime-neutral: no Node built-ins, `Buffer`, filesystem, or `undici`. You inject `dnsResolver`, `fetchJson`, and key providers. Safe to bundle for browsers and other non-Node runtimes.
- **`@dnsid-ai/sdk/node` subpath** — Node conveniences (`LocalKeyProvider`, `configFromEnvironment`, `createNodeIdentityManager`, `createNodeIdentityManagerFromDnsid`). Loads the optional `@dnsid-ai/transport` peer only when HTTPS defaults are needed.
- **OIDC lives in its own package** — `@dnsid-ai/oidc` is deliberately not re-exported from the root because its default transport is Node-bound, and private-key token minting belongs in server-side code. Import it directly.

## Runtime-neutral usage

Use the root SDK when your application provides runtime dependencies explicitly:

```ts
import { createIdentityManager } from '@dnsid-ai/sdk';

const idm = createIdentityManager({ identity, verification }, {
  keyProvider,       // operational ku key
  entityKeyProvider, // accountable-entity ek key
  dnsResolver,
  fetchJson,
});
```

For verification without a local identity or signing keys:

```ts
import { createIdentityVerifier } from '@dnsid-ai/sdk';

const verifier = createIdentityVerifier({}, { dnsResolver, fetchJson, logRegistry });
const verified = await verifier.verifyDomain('agent.example.com');
```

For OIDC minting (server-side only — private keys never belong in browser/client code):

```ts
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
import { mintOIDCToken } from '@dnsid-ai/oidc';

const keyProvider = await LocalKeyProvider.load(process.env.DNSID_KEY_STORE ?? '.dnsid/keys.json', true);
const token = await mintOIDCToken({
  domain: process.env.DNSID_DOMAIN!,
  keyProvider,
  audience: process.env.AGENTCORE_GATEWAY_AUDIENCE!,
  issuer: process.env.DNSID_OIDC_ISSUER,
  serverUrl: process.env.DNSID_OIDC_ISSUER ? undefined : process.env.DNSID_SERVER_URL,
  scopes: ['openid', 'dnsid'],
});
```

If you pass `OIDCProfile` or `OIDCTokenMinter` a custom `fetch`, that fetch replaces the safe default; only inject trusted/test transports that enforce equivalent DNS/SSRF checks.

## Node.js convenience usage

```ts
import { configFromEnvironment, createNodeIdentityManager, LocalKeyProvider } from '@dnsid-ai/sdk/node';

const { config, keyStorePath } = configFromEnvironment();
const keyProvider = await LocalKeyProvider.load(keyStorePath ?? '.dnsid/keys.json', true);
const entityKeyProvider = await LocalKeyProvider.load('.dnsid/entity.keys.json', true);
const idm = await createNodeIdentityManager(config, { keyProvider, entityKeyProvider });
```

`LocalKeyProvider.load(path)` loads an existing store; pass `true` to create one when missing.
By default, the Node helper uses the system or configured DNS resolver. Because Node cannot expose DNSSEC validation results, that resolver reports `UNKNOWN`, which the default `auto` policy permits and preserves. Inject a DNSSEC-aware resolver for `validated` or `required` policy.

If the registry CLI has already written `~/.dnsid/config.json` and `~/.dnsid/<fqdn>/private.jwk`:

```ts
import { createNodeIdentityManagerFromDnsid } from '@dnsid-ai/sdk/node';

const idm = await createNodeIdentityManagerFromDnsid();
```

`@dnsid-ai/transport` is an optional peer of `@dnsid-ai/sdk`; it provides the Node DNS and HTTPS defaults. DNSSEC modes are: `auto` (default), which rejects `FAILED` and permits `VALID`, `UNSIGNED`, or `UNKNOWN`; `validated`, which permits `VALID` or `UNSIGNED`; and `required`, which permits only `VALID`.

### Registering an agent

**Local (default).** The registry client talks to the local registry from `dnsid local up` unless told otherwise, and needs no credential to start:

```sh
dnsid local up                             # local registry, DNS, and CA in Docker
dnsid local run my-agent -- node app.js    # registers my-agent if needed, runs with DNSID_* set
```

```ts
import { RegistryClient } from '@dnsid-ai/registry';
import { registryClientOptionsFromEnvironment } from '@dnsid-ai/sdk/node';

// DNSID_REGISTRY_URL and DNSID_API_KEY when set; otherwise http://127.0.0.1:7755 with no credential.
const registry = new RegistryClient(registryClientOptionsFromEnvironment());
```

To export the same variables into your shell instead of wrapping one command: `eval "$(dnsid local env my-agent)"`.
If nothing is listening, calls fail with `no registry at 127.0.0.1:7755; run \`dnsid local up\` or set DNSID_REGISTRY_URL`.

**Hosted.** Set `DNSID_REGISTRY_URL` and `DNSID_API_KEY` from the console; the same code then talks to the hosted registry:

```sh
export DNSID_REGISTRY_URL=https://api.dnsid.ai
export DNSID_API_KEY=...   # console-issued owner key
```

Registration is production-only: `registerSelfManagedAgent({ domain })` for a domain you control, `registerInZone({ zoneId })` for a delegated zone, `registerLiveAgent()` for Live. Sandbox registration lives in the console and CLI; use the SDK for everything after registration.

### Environment variables

`configFromEnvironment()` reads the following `DNSID_*` variables:

| Variable | Required? | Purpose |
| --- | --- | --- |
| `DNSID_DOMAIN` | Yes | Agent FQDN, e.g. `alice.example.com`. |
| `DNSID_GOVERNANCE_ID` | Yes | Governance identifier. Usually a parent/domain FQDN, e.g. `example.com`. |
| `DNSID_STATUS_URL` | No | HTTPS URL for the agent status document. Derived from `registryUrl` + domain when not set. |
| `DNSID_REGISTRY_URL` | No | Registry base URL. Defaults to the local registry, `http://127.0.0.1:7755`; set it to the hosted registry for hosted use. HTTPS, or HTTP on loopback only. Used to derive the status URL and for registry workflows. |
| `DNSID_API_KEY` | No | Owner API key for registry workflows. `dnsid local env` exports one for the local registry; hosted keys come from the console. |
| `DNSID_LOG_REF` | No | Lifecycle log reference. Defaults to `noop:0`. |
| `DNSID_EK_URL` | Yes for DNSid1 publishing | Accountable-entity JWKS URL. Host must equal `DNSID_GOVERNANCE_ID` or be a subdomain of it. |
| `DNSID_KU_URL` | Yes for DNSid1 publishing | Operational JWKS URL. Host must match `DNSID_DOMAIN`. |
| `DNSID_DNS_SERVER` | No | DNS server for SDK-managed DNS and HTTPS lookups. |
| `DNSID_CA_BUNDLE` | No | Additional PEM CA bundle for SDK-managed HTTPS verification. |
| `DNSID_DNSSEC_MODE` | No | DNSSEC mode: `auto` (default), `validated`, or `required`. |
| `DNSID_KEY_STORE` | No | Local key-store path for `LocalKeyProvider`. Defaults to `.dnsid/keys.json` when loading from environment. |
| `DNSID_PUBLIC_URL` | No | Public base URL for examples/servers. Not part of core DNSid config. |
| `DNSID_AGENT_PORT` | No | Local example/server port. |
| `DNSID_AGENT_NAME` | No | Local example/server display name. |

Minimal hosted-registry configuration (the local registry needs none of this — `dnsid local run` exports it):

```sh
DNSID_DOMAIN=alice.example.com
DNSID_GOVERNANCE_ID=example.com
DNSID_EK_URL=https://example.com/.well-known/entity-jwks.json
DNSID_KU_URL=https://alice.example.com/.well-known/jwks.json
DNSID_REGISTRY_URL=https://api.dnsid.ai
DNSID_API_KEY=...
```

Minimal direct-status configuration:

```sh
DNSID_DOMAIN=alice.example.com
DNSID_GOVERNANCE_ID=example.com
DNSID_EK_URL=https://example.com/.well-known/entity-jwks.json
DNSID_KU_URL=https://alice.example.com/.well-known/jwks.json
DNSID_STATUS_URL=https://alice.example.com/.well-known/dnsid-status.json
```

## Low-level core usage

Use `@dnsid-ai/protocol` directly when you want only the protocol engine and interfaces, with no SDK/profile conveniences:

```ts
import { IdentityManager } from '@dnsid-ai/protocol';

const idm = new IdentityManager(
  { identity, verification, transport: {} },              // data only
  { keyProvider, entityKeyProvider, logRegistry, dnsResolver, cache, fetchJson }, // runtime objects
);
```

This is intended for advanced consumers that already have their own runtime wiring, storage, transport, or dependency-injection system.

## Browser/runtime note

Browser support should use injected browser-safe transport and key-provider implementations. Direct browser DNS/DNSSEC and key custody require explicit design; future packages may include browser transport and web-wallet key-provider integrations.

## Documentation

- Guides and protocol documentation: [docs.dnsid.ai](https://docs.dnsid.ai/)
- Generated API reference (this repo, one page per package): [`docs/reference/index.md`](docs/reference/index.md)
- Security and production operations: [`docs/security.md`](docs/security.md)
- Examples: [`examples/`](https://github.com/dnsid-ai/dnsid-ts/tree/main/examples)

## Current limitations

- When a DNSid record advertises `fl=mtls`, verification requires the peer's TLS certificate: pass it as the second argument to `verifyDomain(domain, peerCert)`, and its SAN must match the agent FQDN. Without a certificate (or with a mismatched SAN), verification fails with `VerificationError`.
- The Node transport's system DNS resolver reports DNSSEC state `UNKNOWN`; supply a DNSSEC-validating resolver for production use. DNS-over-HTTPS is not implemented.

## Stability

DNSid is pre-1.0. APIs may change between minor releases. Review the current limitations before production use.

## License

Licensed under the [Apache License 2.0](LICENSE).
