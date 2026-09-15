import type { IdentityResolver, KeyProvider } from '@identity-digital/dnsid';
import { createJoseProfile, fromBase64Url } from '@identity-digital/dnsid';
import { LocalKeyProvider } from '@identity-digital/dnsid/node';

// Load from existing local key store if it exists, otherwise create
const keyStorePath = 'keys.json';
const keyProvider: KeyProvider = await LocalKeyProvider.load(keyStorePath, true);
console.log('loaded active key:', await keyProvider.signingKey());
console.log('visible key ids:', await keyProvider.listKeyIds());

// Get only the active signing key
const signingKey = await keyProvider.signingKey();
console.log('\nget jwk by kid:', await keyProvider.jwk(signingKey.kid));
const initialSigningKid = signingKey.kid;

// Generate a new key, stored in `pending` until activated
const pendingKid = await keyProvider.generateKey();
console.log('\ngenerated pending kid:', pendingKid);
console.log('visible key ids before activation:', await keyProvider.listKeyIds());

// Activate the new key, old key goes to `retained`
await keyProvider.activate(pendingKid);
console.log('\nvisible key ids after activation:', await keyProvider.listKeyIds());
console.log('new active key:', await keyProvider.signingKey());

// Construct JWKS manually (IdentityManager handles this for us but out of scope for this example)
// This is what should be hosted at `https://<fqdn>/.well-known/jwks.json`
const jwks = {
  keys: await Promise.all(
    (await keyProvider.listKeyIds()).map(kid => keyProvider.jwk(kid))
  ),
};
console.log('\npublic JWKS:', jwks);

// Purge the old key to prevent the example keys file from growing with each run
await keyProvider.purge(initialSigningKid)


// Create a jose profile (provides: createJWT, verifyJWT, createJWS, verifyJWS)
const joseProfile = createJoseProfile({
  keyProvider,
  domain: 'alice.example.com',
  identityResolver: getDummyIdResolver(),
})

// Create a signed JWT, uses keyProvider passed in joseProfile creation
// Allows overriding parameters
const jwt = await joseProfile.createJWT({
  audience: 'bob.example.com',
  additionalClaims: { example: 'local-key-provider' },
});
console.log('\nsigned JWT:', jwt);

// Decode jwt
console.log('\ndecoded JWT header:', decodeJwtPart(jwt, 0));
console.log('decoded JWT payload:', decodeJwtPart(jwt, 1));


function decodeJwtPart(jwt: string, part: 0 | 1): unknown {
  return JSON.parse(new TextDecoder().decode(fromBase64Url(jwt.split('.')[part]!)));
}
function getDummyIdResolver(): IdentityResolver {
  return {
    async verifyDomain() { throw new Error('This example only signs; verification would use a real DNSid resolver.'); },
  };
}
