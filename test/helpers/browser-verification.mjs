import * as sdk from '@dnsid-ai/sdk';

// Retain every root export so tree shaking cannot hide a Node-only dependency.
globalThis.__dnsidBrowserExports = sdk;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function rejectsCode(operation, code) {
  try {
    await operation();
  } catch (error) {
    assert(error instanceof sdk.VerificationError && error.code === code, `expected ${code}, got ${error}`);
    return;
  }
  throw new Error(`expected rejection with ${code}`);
}

globalThis.__dnsidBrowserVerification = async () => {
  const domain = 'agent.example.com';
  const audience = 'verifier.example.com';
  const encoder = new TextEncoder();

  for (const alg of ['ES256', 'EdDSA']) {
    const keyAlgorithm = alg === 'ES256' ? { name: 'ECDSA', namedCurve: 'P-256' } : 'Ed25519';
    const signAlgorithm = alg === 'ES256' ? { name: 'ECDSA', hash: 'SHA-256' } : 'Ed25519';
    const entity = await crypto.subtle.generateKey(keyAlgorithm, true, ['sign', 'verify']);
    const operational = await crypto.subtle.generateKey(keyAlgorithm, true, ['sign', 'verify']);
    const entityKey = { ...await crypto.subtle.exportKey('jwk', entity.publicKey), kid: 'entity', alg, use: 'sig' };
    const operationalKey = { ...await crypto.subtle.exportKey('jwk', operational.publicKey), kid: 'operational', alg, use: 'sig' };
    const sign = async (bytes, key) => sdk.toBase64Url(new Uint8Array(await crypto.subtle.sign(signAlgorithm, key, bytes)));
    const corrupt = value => {
      const bytes = sdk.fromBase64Url(value);
      bytes[0] ^= 1;
      return sdk.toBase64Url(bytes);
    };

    const record = new sdk.DnsIdTxtRecord();
    Object.assign(record, {
      v: sdk.DNSID_VERSION,
      gi: 'example.com',
      ek: 'https://example.com/entity-jwks.json',
      ku: `https://${domain}/jwks.json`,
      su: `https://${domain}/status`,
      lr: 'fixture:issuance',
      agentFQDN: domain,
    });
    record.sg = await sign(encoder.encode(record.canonical()), entity.privateKey);

    // DNS, HTTPS/TLS metadata, and lifecycle evidence are fixtures, not live verification.
    let dnssecState = sdk.DNSSECState.UNSIGNED;
    let status = 'ACTIVE';
    const initialEntityThumbprint = await sdk.jwkThumbprint(entityKey);
    const initialOperationalThumbprint = await sdk.jwkThumbprint(operationalKey);
    const logRegistry = new sdk.LogRegistry();
    logRegistry.register('fixture', () => ({
      verifyBilateralBinding: async () => ({ initialEntityThumbprint, initialOperationalThumbprint, timestamp: new Date() }),
      verifyOperationalContinuity: async (actualDomain, initial, current) => {
        assert(actualDomain === domain && initial === initialOperationalThumbprint && current === initial, 'wrong continuity inputs');
      },
    }));
    const verifier = sdk.createIdentityVerifier({}, {
      logRegistry,
      dnsResolver: {
        fetchTXT: async name => {
          assert(name === `_dnsid.${domain}`, `unexpected DNS query: ${name}`);
          return [[{ strings: [record.serialize()], ttl: 300 }], dnssecState];
        },
      },
      fetchJson: async url => {
        assert([record.ek, record.ku, record.su].includes(url), `unexpected JSON URL: ${url}`);
        return {
          data: url === record.su
            ? { state: status, lastTransitionAt: new Date().toISOString(), ...(status === 'REVOKED' ? { revocationReason: 'keyCompromise' } : {}) }
            : { keys: [url === record.ek ? entityKey : operationalKey] },
          tlsCert: { san: [domain, 'example.com'], notAfter: new Date(Date.now() + 60_000) },
        };
      },
    });

    const verified = await verifier.verifyDomain(domain);
    assert(verified.domain === domain && verified.cachedState() === 'ACTIVE', `${alg}: domain verification failed`);
    assert(verified.signingKey.kid === entityKey.kid && verified.jwks.keys[0].kid === operationalKey.kid, 'wrong verified keys');

    const now = Math.floor(Date.now() / 1000);
    const encode = value => sdk.toBase64Url(encoder.encode(JSON.stringify(value)));
    const input = `${encode({ alg, kid: operationalKey.kid, typ: 'JWT' })}.${encode({ iss: domain, sub: domain, aud: audience, iat: now, exp: now + 60 })}`;
    const signature = await sign(encoder.encode(input), operational.privateKey);
    const jose = sdk.createJoseProfile({ identityResolver: verifier });
    assert((await jose.verifyJWT(`${input}.${signature}`, { expectedAudience: audience })).domain === domain, `${alg}: JWT verification failed`);
    await rejectsCode(() => jose.verifyJWT(`${input}.${corrupt(signature)}`, { expectedAudience: audience }), sdk.VerificationCode.SignatureInvalid);

    verifier.evictDomain(domain);
    const validSignature = record.sg;
    record.sg = corrupt(validSignature);
    await rejectsCode(() => verifier.verifyDomain(domain), sdk.VerificationCode.SignatureInvalid);
    record.sg = validSignature;

    status = 'REVOKED';
    await rejectsCode(() => verifier.verifyDomain(domain), sdk.VerificationCode.StatusNotActive);
    status = 'ACTIVE';
    dnssecState = sdk.DNSSECState.FAILED;
    await rejectsCode(() => verifier.verifyDomain(domain), sdk.VerificationCode.DNSSECFailed);
  }

  return 'browser verification passed (ES256 and Ed25519; domain, JWT, invalid signatures, revoked status, failed DNSSEC)';
};
