# DNSid validate-domain example

Minimal Node example that verifies one DNSid domain end to end: it configures the C2SP transparency-log verifier, resolves the domain's DNSid TXT record and JWKS documents, and prints the resulting `VerifiedDomain`.

This is the runnable version of the snippet in the [root README](../../README.md).

## What it shows

- Creating a verification-only identity manager with `createNodeIdentityVerifier`.
- Creating a ready-to-use C2SP `LogRegistry` with `createC2spTlogVerificationRegistry`.
- Explicitly trusting DNSid's public test log policy at `https://log.dev.dnsid.ai/dnsid-policy`.
- Verifying a third-party domain with `idm.verifyDomain(domain)`.

The policy URL is independently trusted application configuration. Production applications should select their own trusted policy URL or pass trusted `policyDocument` bytes. Never derive the policy location from an unverified identity record, its `lr`, or its log prefix. `constructIdentityManager` builds the log registry with the SDK's fixed 10-minute checkpoint maximum age; a deployment that needs a different freshness policy calls `createC2spTlogVerificationRegistry` itself and injects `logRegistry`. The factory's default trusted-checkpoint store is process-lifetime only; inject durable storage when rollback protection must survive restarts.

## DNS resolution and DNSSEC state

When no `dnsResolver` is injected, `createNodeIdentityVerifier` installs the system-backed resolver from [`@dnsid-ai/transport`](../../packages/transport/README.md). Node's system resolver cannot distinguish DNSSEC states, so it reports `UNKNOWN`.

For production verification, inject a DNSSEC-aware `DNSResolver` that reports `VALID`, `UNSIGNED`, or `FAILED`.

## Run

From the repo root:

```sh
npm install
npm run start -w @dnsid-ai/example-validate-domain -- your-agent.example
```

Replace `your-agent.example` with a published domain whose lifecycle log uses DNSid's public test C2SP log.

The example is `constructIdentityManager(mergeLoadedConfig(fallbackTrust, await loadEnvironment()))`. Against the local registry, provision `bob.test` and its ISSUANCE, then evaluate `dnsid local env bob`. The agent-specific form includes the identity and key paths as well as `DNSID_LOG_POLICY_URL`, `DNSID_DNS_SERVER`, `DNSID_CA_BUNDLE`, and `DNSID_PRIVATE_HOSTS=.test`, which `loadEnvironment()` picks up and the constructor wires into both the policy fetch and DNS/HTTPS defaults:

```sh
dnsid local up --zone test
dnsid local agent ensure bob --upstream http://localhost:3002 -- \
  dnsid log issue --domain bob.test
eval "$(dnsid local env bob)"
npm run start -w @dnsid-ai/example-validate-domain -- bob.test
```

On success it prints the `VerifiedDomain` object: domain, agent status, verified key set, and the DNSSEC state the resolver reported.
