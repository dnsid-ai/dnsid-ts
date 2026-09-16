# Web Bot Auth Example

Demonstrates the [`@dnsid-ai/web-bot-auth`](../../packages/web-bot-auth/README.md) package: signing outbound bot requests per Web Bot Auth (RFC 9421 HTTP Message Signatures with the `web-bot-auth` tag) and serving the signed key directory that verifiers use to fetch the agent's public keys.

The example runs fully offline (no network calls). It:

1. Loads (or creates on first run) a local Ed25519 key store with `LocalKeyProvider`.
2. Creates a `WebBotAuthProfile` for an agent domain via `createWebBotAuthProfile`.
3. Signs a `POST` request with `createWebBotAuthSignedRequest` and prints the resulting `Signature`, `Signature-Input`, `Signature-Agent`, and `Content-Digest` headers.
4. Builds the signed `/.well-known/http-message-signatures-directory` response with `serveHttpMessageSignaturesDirectory` and prints its JSON body and signature headers.

Note: Web Bot Auth requires an Ed25519 (EdDSA) operational key. `LocalKeyProvider` generates Ed25519 keys, so it satisfies this out of the box; signing with any other key type throws.

## Run Example:

From the root directory:

```sh
npm install
npm run start -w @dnsid-ai/example-webbotauth
```

Note: The key store is written to `examples/webbotauth/keys.json` on first run and reused afterwards. Delete that file to reset the example with a fresh key.
