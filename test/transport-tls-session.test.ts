import { EventEmitter } from 'node:events';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type * as https from 'node:https';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { fetchJson } from '@identity-digital/dnsid-transport';
import { generateSelfSignedCert } from './helpers/self-signed-cert';

// The transport's own https.get is intercepted only to capture the agent it
// passes; the captured agent is then driven against a real TLS server.
const httpsGetMock = vi.hoisted(() => vi.fn());
vi.mock('node:https', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:https')>();
  return { ...actual, get: httpsGetMock };
});

async function captureTransportAgent(): Promise<https.Agent> {
  httpsGetMock.mockImplementation((_url: string, _options: https.RequestOptions, callback: (res: IncomingMessage) => void): ClientRequest => {
    const req = new EventEmitter() as ClientRequest;
    req.setTimeout = vi.fn(() => req) as unknown as ClientRequest['setTimeout'];
    req.destroy = vi.fn(() => req) as unknown as ClientRequest['destroy'];
    queueMicrotask(() => {
      const res = new EventEmitter() as IncomingMessage;
      res.statusCode = 500;
      res.headers = {};
      res.resume = vi.fn(() => res) as unknown as IncomingMessage['resume'];
      callback(res);
    });
    return req;
  });
  await fetchJson('https://agent.example/.well-known/jwks.json').catch(() => undefined);
  const [, options] = httpsGetMock.mock.calls[0] as [string, https.RequestOptions];
  expect(options.agent).toBeDefined();
  return options.agent as https.Agent;
}

describe('transport TLS sessions', () => {
  let server: import('node:https').Server;
  let port: number;
  let cert: string;
  let agent: https.Agent;

  beforeAll(async () => {
    const generated = generateSelfSignedCert('localhost');
    cert = generated.cert;
    const realHttps = await vi.importActual<typeof import('node:https')>('node:https');
    server = realHttps.createServer({ key: generated.key, cert, minVersion: 'TLSv1.3' }, (req, res) => {
      // Close after every response so the next request opens a new
      // connection, which is when a cached session would be resumed.
      res.setHeader('Connection', 'close');
      res.end('{}');
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as { port: number }).port;
    agent = await captureTransportAgent();
  });

  afterAll(async () => {
    await new Promise<void>(resolve => server.close(() => resolve()));
  });

  it('never resumes a TLS session, so every connection carries the peer certificate', async () => {
    const realHttps = await vi.importActual<typeof import('node:https')>('node:https');
    const get = () => new Promise<{ reused: boolean; certKeys: number }>((resolve, reject) => {
      realHttps.get(`https://localhost:${port}/`, { agent, ca: cert, servername: 'localhost' }, (res) => {
        const socket = res.socket as import('node:tls').TLSSocket;
        const peer = socket.getPeerCertificate();
        res.resume();
        res.on('end', () => resolve({ reused: socket.isSessionReused(), certKeys: Object.keys(peer).length }));
      }).on('error', reject);
    });
    for (let i = 0; i < 3; i++) {
      const { reused, certKeys } = await get();
      expect(reused, `request ${i} resumed a cached TLS session`).toBe(false);
      expect(certKeys, `request ${i} saw no peer certificate`).toBeGreaterThan(0);
    }
  });
});
