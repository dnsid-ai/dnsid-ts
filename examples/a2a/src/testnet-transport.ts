import * as fs from 'node:fs';
import * as https from 'node:https';
import * as tls from 'node:tls';
import {
  VerificationCode,
  VerificationError,
  type FetchResult,
  type JsonFetcher,
  type TLSCertificate,
} from '@identity-digital/dnsid';
import { createLookup } from '@identity-digital/dnsid-transport';

interface TestnetJsonFetcherOptions {
  dnsServer: string;
  caBundlePath?: string;
}

const REQUEST_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1 * 1024 * 1024;

/**
 * Testnet-only HTTPS JSON fetcher.
 *
 * The DNSid CLI's local testnet view intentionally resolves agent domains to the
 * host's loopback proxy. Production SDK transport keeps SSRF protections strict;
 * this example injects an explicit local-testnet transport instead.
 */
export function createTestnetJsonFetcher(testnet: TestnetJsonFetcherOptions): JsonFetcher {
  const requestOptions: https.RequestOptions = {
    rejectUnauthorized: true,
    lookup: createLookup(testnet.dnsServer),
  };
  if (testnet.caBundlePath) requestOptions.ca = [...tls.rootCertificates, fs.readFileSync(testnet.caBundlePath, 'utf8')];

  return (url, opts = {}) => {
    const target = httpsUrl(url);
    return getJson(target, requestOptions, opts.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES);
  };
}

function getJson(url: URL, requestOptions: https.RequestOptions, maxBytes: number): Promise<FetchResult> {
  return new Promise((resolve, reject) => {
    const fail = (err: Error) => reject(err);
    const req = https.get(url, requestOptions, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        fail(tlsError(`unexpected HTTP status ${res.statusCode}`, (res.statusCode ?? 0) >= 500));
        return;
      }

      const tlsCert = peerTlsCert(res.socket as tls.TLSSocket);
      let body = '';
      let bytes = 0;

      res.setEncoding('utf8');
      res.on('data', (chunk: string) => {
        bytes += Buffer.byteLength(chunk, 'utf8');
        if (bytes > maxBytes) {
          req.destroy();
          fail(tlsError(`response body exceeds ${maxBytes} byte limit`));
        } else {
          body += chunk;
        }
      });
      res.on('end', () => {
        try {
          const data = JSON.parse(body) as unknown;
          const status = data && typeof data === 'object'
            ? (data as { protocolStatus?: unknown }).protocolStatus
            : undefined;
          resolve({ data: url.pathname.startsWith('/v1/status/') && status ? status : data, tlsCert });
        } catch {
          fail(new VerificationError('response body is not valid JSON', { code: VerificationCode.RecordInvalid }));
        }
      });
      res.on('error', err => fail(tlsError(`response stream error: ${err.message}`, true)));
    });

    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.destroy();
      fail(tlsError(`request timed out after ${REQUEST_TIMEOUT_MS}ms`, true));
    });
    req.on('error', err => fail(tlsError(`HTTPS fetch failed: ${err.message}`, true)));
  });
}

function httpsUrl(url: string): URL {
  try {
    const target = new URL(url);
    if (target.protocol === 'https:') return target;
  } catch {
    // handled below
  }
  throw tlsError(`invalid or non-HTTPS URL: ${url}`);
}

function peerTlsCert(socket: tls.TLSSocket): TLSCertificate {
  const cert = socket.getPeerCertificate();
  return {
    notAfter: new Date(cert.valid_to),
    san: cert.subjectaltname
      ?.split(', ')
      .flatMap(part => part.startsWith('DNS:') ? [part.slice(4)] : []) ?? [],
  };
}

function tlsError(message: string, transient = false): VerificationError {
  return new VerificationError(message, { code: VerificationCode.TLSError, transient });
}
