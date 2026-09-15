/**
 * DNSid OIDC federation profile example.
 *
 * Offline (always runs): generate an operational key, mint a signed RFC 7523
 * JWT bearer client assertion for an OIDC issuer, and decode its header and
 * claims for inspection.
 *
 * Online (opt-in): set DNSID_OIDC_ISSUER and DNSID_OIDC_AUDIENCE to exchange
 * a fresh assertion for an access token at the issuer's token endpoint.
 *
 * Token minting is server-side only — it uses the agent's private operational
 * key. Never run this in browser/client code.
 */
import { LocalKeyProvider } from '@identity-digital/dnsid/node';
import { createOIDCTokenMinter, decodeOIDCClaims } from '@identity-digital/dnsid-oidc';

const domain = 'agent.example.com';
const issuer = process.env.DNSID_OIDC_ISSUER ?? 'https://issuer.example.com';

// In a real deployment, load a persisted key instead:
//   const keyProvider = await LocalKeyProvider.load('.dnsid/keys.json', true);
const keyProvider = await LocalKeyProvider.generate();

const minter = await createOIDCTokenMinter({ domain, keyProvider, issuer });

// --- Offline: mint and inspect a client assertion (no network involved) ---
const assertion = await minter.createAssertion({ issuer });

const header = JSON.parse(Buffer.from(assertion.split('.')[0]!, 'base64url').toString());
const claims = decodeOIDCClaims(assertion); // decode-only; never use for authorization

console.log('Client assertion (JWT bearer, RFC 7523):');
console.log(`  ${assertion.slice(0, 60)}...`);
console.log('Header:', JSON.stringify(header));
console.log('Claims:', JSON.stringify(claims, null, 2));

// --- Online (optional): exchange the assertion for an OIDC access token ---
const audience = process.env.DNSID_OIDC_AUDIENCE;
if (process.env.DNSID_OIDC_ISSUER && audience) {
  const token = await minter.mintToken({ audience });
  console.log('Access token:', token.accessToken);
  console.log('Token type:', token.tokenType, 'expires in:', token.expiresIn);
} else {
  console.log('\nSet DNSID_OIDC_ISSUER and DNSID_OIDC_AUDIENCE to perform a live token exchange.');
}
