import { describe, expect, it } from 'vitest';
import { jwkThumbprint } from '@dnsid-ai/sdk';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';

describe('LocalKeyProvider generated kids', () => {
  it('names generated keys by their RFC 7638 thumbprint, as the registry requires', async () => {
    for (const alg of ['EdDSA', 'ES256'] as const) {
      const kp = await LocalKeyProvider.generate(alg);
      const key = await kp.signingKey();
      expect(key.kid).toBe(await jwkThumbprint(key));
      const pending = await kp.generateKey();
      expect(pending).toBe(await jwkThumbprint(await kp.jwk(pending)));
    }
  });
});
