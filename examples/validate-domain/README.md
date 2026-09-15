# DNSid validate-domain example

Minimal Node example that verifies one DNSid domain end to end: it configures the C2SP transparency-log verifier, resolves the domain's DNSid TXT record and JWKS documents, and prints the resulting `VerifiedDomain`.

This is the runnable version of the snippet in the [root README](../../README.md).

## What it shows

- Creating a verification-only identity manager with `createNodeIdentityVerifier`.
- Creating a ready-to-use C2SP `LogRegistry` with `createC2spTlogVerificationRegistry`.
- Explicitly trusting the DNSid sandbox policy at `https://log.dnsid.dev/dnsid-policy`.
- Verifying a third-party domain with `idm.verifyDomain(domain)`.

The policy URL is independently trusted application configuration. Production applications should select their own trusted policy URL or pass trusted `policyDocument` bytes. Never derive the policy location from an unverified identity record, its `lr`, or its log prefix. The example also sets a local 24-hour checkpoint maximum-age policy for non-revocation checks. The factory's default trusted-checkpoint store is process-lifetime only; inject durable storage when rollback protection must survive restarts.

## DNS resolution and DNSSEC state

When no `dnsResolver` is injected, `createNodeIdentityVerifier` installs the system-backed resolver from [`@identity-digital/dnsid-transport`](../../packages/transport/README.md). Node's system resolver cannot distinguish DNSSEC states, so it reports `UNKNOWN`.

For production verification, inject a DNSSEC-aware `DNSResolver` that reports `VALID`, `UNSIGNED`, or `FAILED`.

## Run

From the repo root:

```sh
npm install
npm run start -w @identity-digital/dnsid-example-validate-domain -- your-agent.example.com
```

Replace `your-agent.example.com` with a domain whose lifecycle log uses the DNSid sandbox's public C2SP log.

On success it prints the `VerifiedDomain` object: domain, agent status, verified key set, and the DNSSEC state the resolver reported.
