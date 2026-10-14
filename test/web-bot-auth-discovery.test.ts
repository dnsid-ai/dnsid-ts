import { describe, expect, it, vi } from 'vitest';
const lookup = vi.hoisted(() => vi.fn());
vi.mock('node:dns/promises', () => ({ lookup }));
import { exportJWK, generateKeyPair } from 'jose';
import { WebBotAuthProfile } from '@dnsid-ai/web-bot-auth';
import { createSsrfSafeFetch } from '@dnsid-ai/transport';
import { toArrayBuffer } from '@dnsid-ai/protocol';
import type { DnsIdJWK, KeyProvider } from '@dnsid-ai/protocol';

describe('WBA public-address transport', () => {
  it.each(['127.0.0.1', '10.0.0.1', '169.254.169.254', 'fc00::1', '224.0.0.1'])('rejects discovery resolving to %s', async address => {
    lookup.mockResolvedValue([{ address, family: address.includes(':') ? 6 : 4 }]);
    const pair = await generateKeyPair('EdDSA');
    const key = { ...await exportJWK(pair.publicKey), kid: 'operational', alg: 'EdDSA' } as DnsIdJWK;
    const keyProvider = {
      signingKey: async () => key,
      sign: async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey, toArrayBuffer(bytes))),
    } as KeyProvider;
    const signer = new WebBotAuthProfile({ domain: 'bot.example.com', keyProvider });
    const req = await signer.createWebBotAuthSignedRequest(new Request('https://target.example/'));
    const safeFetch = createSsrfSafeFetch({}, { decompress: false });
    const resolver = { verifyDomain: vi.fn() };
    const verifier = new WebBotAuthProfile({ identityResolver: resolver, discoveryFetch: request => safeFetch(request) });
    await expect(verifier.verifyWebBotAuthSignedRequest(req, { signerDomain: 'bot.example.com' })).rejects.toThrow();
    expect(lookup).toHaveBeenCalledWith('bot.example.com', expect.any(Object));
    expect(resolver.verifyDomain).not.toHaveBeenCalled();
  });
});
