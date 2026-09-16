import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
import {
  HTTP_MESSAGE_SIGNATURES_DIRECTORY_PATH,
  createWebBotAuthProfile,
} from '@dnsid-ai/web-bot-auth';

// The agent domain the profile signs for. Purely illustrative: everything in
// this example runs offline, so the domain never has to resolve.
const agentDomain = 'bot.example.com';

// Load the Ed25519 key store next to this example (created on first run).
// Web Bot Auth requires an Ed25519 / EdDSA operational key, which is exactly
// what LocalKeyProvider generates.
const keyStorePath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'keys.json');
const keyProvider = await LocalKeyProvider.load(keyStorePath, true);
const signingKey = await keyProvider.signingKey();
console.log(`active key: kid=${signingKey.kid} kty=${signingKey.kty} crv=${signingKey.crv} alg=${signingKey.alg}`);

const profile = createWebBotAuthProfile({ domain: agentDomain, keyProvider });

// 1. Sign an outbound request (RFC 9421, tag `web-bot-auth`).
// A Content-Digest header is added automatically because the request has a body.
const signed = await profile.createWebBotAuthSignedRequest(
  new Request('https://origin.example/api', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hello: 'origin' }),
  }),
);

console.log('\nsigned request:', signed.method, signed.url);
for (const name of ['Signature', 'Signature-Input', 'Signature-Agent', 'Content-Digest']) {
  console.log(`  ${name}: ${signed.headers.get(name)}`);
}

// 2. Serve the signed key directory the agent would host at
// https://<domain>/.well-known/http-message-signatures-directory so that
// origins can fetch the public key and verify the signature above.
const directoryResponse = await profile.serveHttpMessageSignaturesDirectory(
  new Request(`https://${agentDomain}${HTTP_MESSAGE_SIGNATURES_DIRECTORY_PATH}`),
);

console.log('\nkey directory response:', directoryResponse.status);
for (const name of ['Content-Type', 'Cache-Control', 'Content-Digest', 'Signature', 'Signature-Input']) {
  console.log(`  ${name}: ${directoryResponse.headers.get(name)}`);
}
console.log('  body:', JSON.stringify(await directoryResponse.json(), null, 2));
