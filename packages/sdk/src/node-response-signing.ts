import type { IncomingMessage, ServerResponse } from 'node:http';
import type { TLSSocket } from 'node:tls';
import type { HttpSignaturesProfile } from '@dnsid-ai/http-signatures';

const MAX_BUFFERED_BYTES = 8 * 1024 * 1024;
const SIGNED_FIELDS = ['content-digest', 'cache-control', 'signature-input', 'signature'];

/** Options for {@link createResponseSigningMiddleware}. */
export interface ResponseSigningMiddlewareOptions {
  /**
   * Public origin the client used, such as `https://bob.test`. Set it behind a
   * TLS-terminating proxy. Default: the socket's scheme and the Host header.
   */
  origin?: string;
}

/** Connect-style middleware, usable with Express, Connect, or a plain `node:http` handler. */
export type NodeMiddleware = (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void) => void;

/**
 * Signs responses to requests that carry Accept-Signature, for `node:http` servers.
 * Requests without negotiation pass through unbuffered. Negotiated responses are
 * buffered up to 8 MiB and signed with `signRequestedHttpResponse` before any header
 * is sent. On a signing failure, an exceeded bound, or a `flushHeaders()` call
 * (streaming, such as SSE) it sends an empty 500; it never sends the unsigned
 * response. Register it before request verification, compression, and handlers
 * so that it sees their final status, headers, and content coding.
 * Informational responses written with `writeContinue` or `writeEarlyHints` are
 * sent directly and are not signed.
 */
export function createResponseSigningMiddleware(
  profile: HttpSignaturesProfile,
  options: ResponseSigningMiddlewareOptions = {},
): NodeMiddleware {
  return (req, res, next) => {
    if (req.headers['accept-signature'] === undefined) return next();
    if (res.headersSent) return next(new Error('response headers already sent; register response signing first'));

    const writeHead = res.writeHead.bind(res) as (status: number) => ServerResponse;
    const end = res.end.bind(res) as (chunk?: Buffer) => ServerResponse;
    const chunks: Buffer[] = [];
    let size = 0;
    let overflow = false;
    let ended = false;
    let done = false;
    let releasing = false;

    const collect = (chunk: unknown, encoding: unknown): boolean => {
      if (chunk === undefined || chunk === null || typeof chunk === 'function') return true;
      const bytes = typeof chunk === 'string'
        ? Buffer.from(chunk, typeof encoding === 'string' ? encoding as BufferEncoding : 'utf8')
        : Buffer.from(chunk as Uint8Array);
      size += bytes.length;
      if (size > MAX_BUFFERED_BYTES) {
        overflow = true;
        chunks.length = 0;
        return false;
      }
      chunks.push(bytes);
      return true;
    };
    const send = (body?: Buffer) => {
      done = true;
      releasing = true;
      end(body);
    };
    const fail = () => {
      if (done) return;
      for (const name of res.getHeaderNames()) res.removeHeader(name);
      res.statusCode = 500;
      send();
    };

    res.writeHead = ((status: number, ...args: unknown[]) => {
      // ServerResponse.end calls this.writeHead, so the release must pass through.
      if (releasing) return writeHead(status);
      res.statusCode = status;
      if (typeof args[0] === 'string') res.statusMessage = args.shift() as string;
      setHeaders(res, args[0]);
      return res;
    }) as typeof res.writeHead;
    res.flushHeaders = () => fail();
    res.write = ((chunk: unknown, encoding?: unknown, callback?: unknown) => {
      const cb = typeof encoding === 'function' ? encoding : callback;
      if (ended || done || !collect(chunk, encoding)) {
        if (typeof cb === 'function') process.nextTick(cb, new Error('response not writable'));
        return false;
      }
      if (typeof cb === 'function') process.nextTick(cb);
      return true;
    }) as typeof res.write;
    res.end = ((chunk?: unknown, encoding?: unknown, callback?: unknown) => {
      if (ended || done) return res;
      ended = true;
      const cb = [chunk, encoding, callback].find(arg => typeof arg === 'function');
      if (typeof cb === 'function') res.once('finish', cb as () => void);
      collect(chunk, encoding);
      void release();
      return res;
    }) as typeof res.end;

    async function release(): Promise<void> {
      if (done) return;
      if (overflow) return fail();
      try {
        const noContent = req.method === 'HEAD' || [204, 205, 304].includes(res.statusCode);
        const body = Buffer.concat(chunks);
        const signed = await profile.signRequestedHttpResponse(
          toRequest(req, options.origin),
          new Response(noContent ? null : body, { status: res.statusCode, headers: toHeaders(res.getHeaders()) }),
        );
        if (done) return;
        // Copy back only the fields signing sets, so multi-valued fields keep their lines.
        for (const name of SIGNED_FIELDS) {
          const value = signed.headers.get(name);
          if (value !== null) res.setHeader(name, value);
        }
        send(noContent ? undefined : body);
      } catch {
        fail();
      }
    }

    next();
  };
}

function toRequest(req: IncomingMessage, origin: string | undefined): Request {
  // Express rewrites req.url under a mounted router; originalUrl keeps the request target.
  const path = (req as IncomingMessage & { originalUrl?: string }).originalUrl ?? req.url ?? '';
  if (!path.startsWith('/')) throw new Error('only origin-form request targets can be signed');
  const scheme = (req.socket as TLSSocket).encrypted ? 'https' : 'http';
  const base = origin ?? `${scheme}://${req.headers.host ?? ''}`;
  return new Request(`${new URL(base).origin}${path}`, { method: req.method, headers: toHeaders(req.headers) });
}

function toHeaders(fields: Record<string, number | string | string[] | undefined>): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(fields)) {
    for (const item of Array.isArray(value) ? value : [value]) {
      if (item !== undefined) headers.append(name, String(item));
    }
  }
  return headers;
}

function setHeaders(res: ServerResponse, headers: unknown): void {
  if (Array.isArray(headers)) {
    // writeHead accepts a flat [name, value, name, value] list.
    const grouped = new Map<string, string[]>();
    for (let i = 0; i + 1 < headers.length; i += 2) {
      const name = String(headers[i]).toLowerCase();
      grouped.set(name, [...grouped.get(name) ?? [], String(headers[i + 1])]);
    }
    for (const [name, values] of grouped) res.setHeader(name, values);
  } else if (typeof headers === 'object' && headers !== null) {
    for (const [name, value] of Object.entries(headers)) {
      if (value !== undefined) res.setHeader(name, value as string | number | string[]);
    }
  }
}
