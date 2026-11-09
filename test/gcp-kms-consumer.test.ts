import { afterAll, expect, it, vi } from 'vitest';
import { KeyManagementServiceClient } from '@google-cloud/kms';

// Install before the consumer fixture and native SDK are imported. No cloud
// credentials or transport are part of this fake-only consumer proof.
const offline = vi.hoisted(async () => {
  const http = await import('node:http');
  const https = await import('node:https');
  const net = await import('node:net');
  const tls = await import('node:tls');
  const { syncBuiltinESMExports } = await import('node:module');
  const originals: Array<() => void> = [];
  const forbidden = () => { throw new Error('fake-only GCP consumer forbids network'); };
  for (const [api, names] of [
    [http.default, ['request', 'get']], [https.default, ['request', 'get']],
    [net.default, ['connect', 'createConnection']], [tls.default, ['connect']],
  ] as const) {
    for (const name of names) {
      const object = api as unknown as Record<string, unknown>;
      const original = object[name];
      originals.push(() => { object[name] = original; });
      object[name] = forbidden;
    }
  }
  const fetch = globalThis.fetch;
  globalThis.fetch = forbidden;
  syncBuiltinESMExports();
  return () => {
    originals.reverse().forEach(restore => restore());
    globalThis.fetch = fetch;
    syncBuiltinESMExports();
  };
});
afterAll(async () => (await offline)());
import { gcpConsumer } from './helpers/gcp-consumer.ts';

it('Given deployment A and independent publication A, When composing actual GCP and SDK, Then public HTTP verifies, tampering and B binding reject, and local lifecycle preserves consumer A', () => gcpConsumer());

it('Given existing default deployment settings, When exercising unchanged composition and local lifecycle, Then real publication and consumer verification succeed', () => gcpConsumer('existing'));

it('Given fake-only GCP consumer RPCs, When rotation reads version readiness, Then the fixture owns exact-version metadata and leaves no unhandled rejection', async () => {
  // Mode: fake-only. Guard the test fixture, not product readiness semantics.
  const prototype = KeyManagementServiceClient.prototype;
  const original = Object.getOwnPropertyDescriptor(prototype, 'getCryptoKeyVersion')!;
  const escaped: unknown[] = [];
  const reads: Array<{ request: { name: string }; response: any }> = [];
  const unhandled: unknown[] = [];
  const onUnhandled = (reason: unknown) => { unhandled.push(reason); };
  const denied = async (request: unknown) => {
    escaped.push(request);
    throw new Error('consumer fixture omitted version metadata RPC; native credentials forbidden');
  };
  let implementation: (...args: any[]) => any = denied;
  // Observe only the fixture's public native-client seam. Never call the
  // original RPC: even the broken baseline must not attempt authentication.
  Object.defineProperty(prototype, 'getCryptoKeyVersion', {
    configurable: true,
    get: () => implementation,
    set: (fake: (...args: any[]) => any) => {
      implementation = async (...args: any[]) => {
        const response = await fake(...args);
        reads.push({ request: args[0], response });
        return response;
      };
    },
  });
  process.on('unhandledRejection', onUnhandled);
  try {
    await gcpConsumer();
    await new Promise(resolve => setImmediate(resolve));
    expect(escaped, 'consumer fixture must fake every version metadata RPC before native authentication').toEqual([]);
    expect(reads.length, 'pending metadata case must exercise the fixture readiness response').toBeGreaterThan(0);
    for (const { request, response } of reads) {
      expect(request.name).toBe('projects/consumer/locations/global/keyRings/agents/cryptoKeys/signer/cryptoKeyVersions/8');
      expect(response[0]).toMatchObject({
        name: request.name, algorithm: 'EC_SIGN_ED25519', protectionLevel: 'SOFTWARE',
      });
      // This fixture's metadata-failure branch must remain unavailable, rather
      // than rewriting its existing assert.rejects expectation into success.
      expect(response[0].state).not.toBe('ENABLED');
    }
    expect(unhandled).toEqual([]);
  } finally {
    process.off('unhandledRejection', onUnhandled);
    Object.defineProperty(prototype, 'getCryptoKeyVersion', original);
  }
}, 15_000);
