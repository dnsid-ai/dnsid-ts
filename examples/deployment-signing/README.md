# Deployment signing

Loads one deployment JSON file, selects an existing key provider, verifies the
signing identity, and creates an RFC 9421 signed HTTP request **without sending it**.
The same application runs with either configuration file.

This example does not register identities, generate keys, rotate or delete keys,
or attempt recovery after a failure.

## Prerequisites and placeholders

- Node.js 22 or later and npm.
- An already published, ACTIVE DNSid identity with valid bilateral ISSUANCE and
  operational-key continuity evidence. DNS, HTTPS key/status endpoints, and log
  evidence must be reachable from this application.
- The existing operational signing key, accessible through the selected provider.

This standalone example supplies no application peer TLS certificate, so it does
not support identities that require `fl=mtls` verification.

Both files are **templates, not runnable deployments as supplied**:

- Replace `agent.example`, `example.com`, and all example URLs with the persisted
  publication settings of your identity.
- Replace `<persisted lifecycle-log reference>` with its exact persisted `logRef`.
  Do not invent a new reference.
- For AWS, replace `<immutable signing-key ARN>` with the ARN of the existing
  asymmetric KMS signing key, not an alias. Set its region correctly.
- For file custody, `./keys.json` must already contain the SDK `LocalKeyProvider`
  key-store format (`active`, `retained`, `pending`), not a bare private JWK or PEM.
  Use a store from your existing development identity; this example never creates it.

The SDK's current identity fields are `ekUrl` (entity key URL) and `kuUrl`
(operational key URL), not `entityKeyUrl` and `keyUrl`. The strict deployment loader
rejects those alternative names.

The files illustrate **alternative custody configurations**, not interchangeable
keys for one identity. Each real deployment must select the key already bound to
its own published identity. An AWS KMS key normally cannot be exported to a local
file. Do not switch between two different keys while retaining one identity's
publication settings. Changing `keyRef` does not authorize rotation; an unrelated
key is rejected and requires a separate authorized rotation workflow.

Local private-key files are for development, not production custody. Keep private
keys outside deployment JSON, restrict file permissions (for example, `chmod 600
keys.json`), and never commit them. The repository ignores `keys.json`. Keep all
credentials outside deployment JSON as well.

## Log trust

Keep `"logTrust": { "managed": true }` **only** if this identity uses a supported
DNSid-managed log. The current catalog accepts exact canonical `public` references
to `https://log.dev.dnsid.ai` or `https://log.dnsid.ai`; it does not cover arbitrary
logs or the CLI's local testnet.

For another log, replace the whole `logTrust` section with appropriate,
independently trusted configuration, for example:

```json
"logTrust": {
  "policyUrl": "https://YOUR-TRUSTED-POLICY-HOST/dnsid-policy"
}
```

`YOUR-TRUSTED-POLICY-HOST` is a placeholder. Alternatively, use `logTrust.profile`
with a complete `dnsid-c2sp-tlog-trust-profile@v1` object supplied by your trusted
operator. Select exactly one trust variant. Never discover the trust policy from
an unverified identity record, its log reference, or its log prefix. See the
[log package documentation](../../packages/log-c2sp-tlog/README.md).

## Install and run

From the repository root:

```sh
npm install
npm run build
```

npm links the repository workspaces, including `@dnsid-ai/sdk` and
`@dnsid-ai/key-aws`. The latter is an optional dependency of this example and is
loaded only for AWS custody. Outside the monorepo, install the SDK and selected
provider in your application (`npm install @dnsid-ai/sdk @dnsid-ai/transport
@dnsid-ai/key-aws` for AWS, as one command). The Node transport is required for the
default DNS/HTTPS verification used here. The provider includes `@aws-sdk/client-kms`; the file provider is part of the Node SDK.
An unavailable selected provider causes an error, never a file fallback.

After editing the selected template to match an existing published identity:

```sh
# AWS custody
AWS_PROFILE=your-existing-profile npm -w examples/deployment-signing run start -- deployment.aws-kms.json

# Development file custody
npm -w examples/deployment-signing run start -- deployment.file.json
```

npm runs these commands in `examples/deployment-signing`. Deployment file paths and
relative `keyRef` paths resolve from that working directory, not from the JSON
file's directory. Put the existing `keys.json` there or change `keyRef` to its path.

### AWS credentials and permissions

Authentication uses the AWS SDK's ambient credential chain: an existing shared
profile, environment credentials, or a workload role (for example, EC2, ECS, or
EKS). For an SSO profile, complete `aws sso login --profile your-existing-profile`
first. Do not put access keys, session tokens, or credentials in provider settings.
The JSON contains only the key ARN, region, and algorithm.

The IAM principal and KMS key policy must allow `kms:GetPublicKey` and `kms:Sign`
on that key ARN. No key-creation, rotation, or deletion permissions are required.
For this template, the key must be enabled, have usage `SIGN_VERIFY`, spec
`ECC_NIST_P256`, and support `ECDSA_SHA_256` (DNSid/JWS `ES256`). See the
[AWS provider documentation](../../packages/key-aws/README.md).

## What the code checks

`loadFile` parses the selected deployment without generating keys or reading
credentials. `constructIdentityManager` opens the configured provider and
**automatically verifies local publication before returning**. It compares the
selected operational key's ID, algorithm, and RFC 7638 public-key thumbprint with
the current published operational key. No provider is injected, so the example
reuses these checks rather than bypassing or duplicating them. Missing publication,
unavailable verification, or a key mismatch stops construction.

The application then calls `verifyDomain` for its own identity before signing.
This also applies configured acceptance policy, if any. Finally,
`HttpSignaturesProfile.createSignedHttpRequest` creates a signed POST request with
`Signature`, `Signature-Input`, and `Content-Digest` headers and prints it.
It never calls `fetch` to send that request. Publication verification does perform
DNS/HTTPS reads, and AWS custody performs a KMS signing call; this is not an
offline startup example.

## Check

From the repository root:

```sh
npm -w examples/deployment-signing run typecheck
npx vitest run test/deployment-signing.test.ts
```

The focused test parses both templates, uses a test-only in-memory signer, checks
the resulting HTTP signature without sending it, and checks that construction or
self-verification failures prevent signing. It does not exercise live AWS KMS.
