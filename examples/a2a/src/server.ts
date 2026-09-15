import express from 'express';
import rateLimit from 'express-rate-limit';
import type { Request as ExpressRequest, RequestHandler } from 'express';
import * as http from 'node:http';
import {
  ClientFactory,
  ClientFactoryOptions,
  DefaultAgentCardResolver,
  JsonRpcTransportFactory,
} from '@a2a-js/sdk/client';
import type { Client } from '@a2a-js/sdk/client';
import { AGENT_CARD_PATH, canonicalizeAgentCard } from '@a2a-js/sdk';
import type { AgentCard, SendMessageResult } from '@a2a-js/sdk';
import {
  DefaultRequestHandler,
  InMemoryTaskStore,
  type AgentExecutor,
} from '@a2a-js/sdk/server';
import type { A2ARequestHandler, User } from '@a2a-js/sdk/server';
import { agentCardHandler, jsonRpcHandler } from '@a2a-js/sdk/server/express';
import {
  activeStatusDocument,
  HttpSignaturesProfile,
  IdentityManager,
  JoseProfile,
  type TransportConfig,
  type VerifiedDomain,
} from '@identity-digital/dnsid';
import { createDnsidFetch } from '@identity-digital/dnsid-transport';
import {
  A2A_VERSION,
  DNSID_A2A_EXTENSION_URI,
  DNSID_A2A_SIGNATURE_TAG,
  buildAgentCard,
  messageText,
  textUserMessage,
} from './agent.ts';
import { dashboardHtml } from './dashboard.ts';

interface RawBodyRequest extends ExpressRequest {
  rawBody?: string;
  senderId?: string;
}

interface EchoAgentOptions {
  publicUrl?: string;
  /** Testnet DNS/CA settings for outbound A2A requests. */
  transport?: TransportConfig;
}

interface DemoTrace {
  agentCard?: unknown;
  request?: {
    method: string;
    url: string;
    headers: Record<string, string>;
    signedBody: string;
    transmittedBody: string;
  };
  response?: {
    status: number;
    body: string;
  };
}

class VerifiedSenderUser implements User {
  constructor(private readonly id: string) {}
  get isAuthenticated() { return this.id !== ''; }
  get userName() { return this.id; }
}

export class EchoAgent {
  private readonly identityManager: IdentityManager;
  private readonly joseProfile: JoseProfile;
  private readonly httpProfile: HttpSignaturesProfile;
  private readonly port: number;
  private readonly card: AgentCard;
  private readonly executor: AgentExecutor;
  private readonly transport: TransportConfig;
  private server!: http.Server;

  private constructor(
    manager: IdentityManager,
    joseProfile: JoseProfile,
    httpProfile: HttpSignaturesProfile,
    port: number,
    executor: AgentExecutor,
    card: AgentCard,
    transport: TransportConfig,
  ) {
    this.identityManager = manager;
    this.transport = transport;
    this.joseProfile = joseProfile;
    this.httpProfile = httpProfile;
    this.port = port;
    this.card = card;
    this.executor = executor;
  }

  static async create(
    executor: AgentExecutor,
    idm: IdentityManager,
    port: number,
    options: EchoAgentOptions = {},
  ): Promise<EchoAgent> {
    const publicUrl = options.publicUrl ?? `https://${idm.config.identity!.domain}`;
    const providerUrl = idm.config.identity!.governanceId.includes(':')
      ? publicUrl
      : `https://${idm.config.identity!.governanceId}`;
    const card = buildAgentCard(idm.config.identity!.domain, publicUrl, providerUrl);
    const joseProfile = JoseProfile.fromIdentityManager(idm);
    const httpProfile = HttpSignaturesProfile.fromIdentityManager(idm);

    await signAgentCard(card, joseProfile);
    return new EchoAgent(idm, joseProfile, httpProfile, port, executor, card, options.transport ?? {});
  }

  get url() { return this.card.supportedInterfaces[0]?.url ?? ''; }

  async start(): Promise<void> {
    const requestHandler = this.createRequestHandler();
    const app = express();
    app.set('trust proxy', 'loopback');

    app.use(rateLimit({ windowMs: 60_000, limit: 120 }));
    app.use(captureRawJsonBody());
    this.mountDemoRoutes(app);
    app.use(this.verifySignedA2aPost());
    this.mountDnsidWellKnownRoutes(app);
    this.mountA2aRoutes(app, requestHandler);

    await this.listen(app);
  }

  /** Create an A2A client that signs every outgoing request with this agent's key. */
  async createClient(
    targetBaseUrl: string,
    demo?: { trace: DemoTrace; tamper: boolean },
  ): Promise<Client> {
    const baseFetch = createDnsidFetch(this.transport);
    const tracedFetch = demo
      ? createDemoFetch(baseFetch, demo.trace, demo.tamper)
      : baseFetch;
    const signingFetch = this.httpProfile.createSignedFetch({
      fetch: tracedFetch,
      signing: (req: Request) => req.method.toUpperCase() === 'POST'
        ? {
          label: 'a2a',
          additionalComponents: ['content-type', 'a2a-version', 'a2a-extensions'],
          expiresInSeconds: 300,
          tag: DNSID_A2A_SIGNATURE_TAG,
        }
        : { label: 'a2a', expiresInSeconds: 300, tag: DNSID_A2A_SIGNATURE_TAG },
      prepareRequest: prepareSignedA2aRequest,
    });

    const factory = new ClientFactory(
      ClientFactoryOptions.createFrom(ClientFactoryOptions.default, {
        transports: [new JsonRpcTransportFactory({ fetchImpl: signingFetch })],
        cardResolver: new DefaultAgentCardResolver({ fetchImpl: signingFetch }),
      }),
    );
    return factory.createFromUrl(targetBaseUrl);
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve, reject) =>
      this.server.close(err => (err ? reject(err) : resolve())),
    );
  }

  private createRequestHandler(): A2ARequestHandler {
    return new DefaultRequestHandler(this.card, new InMemoryTaskStore(), this.executor);
  }

  private mountDemoRoutes(app: express.Express): void {
    app.get('/demo', (req, res) => {
      if (!isLoopbackRequest(req)) return res.sendStatus(404);
      res.type('html').send(dashboardHtml);
    });

    app.post('/demo/send', async (req, res) => {
      if (!isLoopbackRequest(req)) return res.sendStatus(404);
      try {
        const target = typeof req.body?.target === 'string' ? req.body.target : '';
        const message = typeof req.body?.message === 'string' ? req.body.message : '';
        if (!target || !message || message.length > 2_000) {
          throw new BadRequestError('target and a message of at most 2,000 characters are required');
        }
        res.json(await this.runDemo(target, message, req.body?.tamper === true));
      } catch (err) {
        res.status(err instanceof BadRequestError ? 400 : 502).json({ error: String(err) });
      }
    });
  }

  private async runDemo(target: string, message: string, tamper: boolean): Promise<unknown> {
    const verified = await this.identityManager.verifyDomain(target);
    const verification = await describeDomainVerification(this.identityManager, verified);
    const trace: DemoTrace = {};
    let result: SendMessageResult | undefined;
    let error = '';

    try {
      const client = await this.createClient(peerUrl(this.identityManager.config.identity!.kuUrl, verified.domain), {
        trace,
        tamper,
      });
      result = await client.sendMessage({
        tenant: '',
        message: textUserMessage(message),
        configuration: undefined,
        metadata: undefined,
      });
    } catch (err) {
      error = String(err);
    }

    const alice = await this.identityManager.verifyDomain(this.identityManager.config.identity!.domain);
    const bobVerification = await describeDomainVerification(this.identityManager, alice);

    return {
      source: this.identityManager.config.identity!.domain,
      target: verified.domain,
      tampered: tamper,
      accepted: result !== undefined,
      verification,
      bobVerification: {
        ...bobVerification,
        evidenceNote: 'The inspector re-resolved the public evidence that Bob independently checked.',
        request: {
          checks: result
            ? ['keyid resolves to Alice', 'required components are signed', 'HTTP signature is valid', 'Content-Digest matches the received body']
            : ['keyid resolves to Alice', 'required components are signed', 'Content-Digest does not match the received body'],
          result: result ? 'VERIFIED' : 'REJECTED',
          response: trace.response,
        },
      },
      trace,
      reply: result ? messageText(result) : '',
      error,
    };
  }

  private verifySignedA2aPost(): RequestHandler {
    return async (req: ExpressRequest, res, next) => {
      if (req.method !== 'POST') return next();

      try {
        const rawReq = req as RawBodyRequest;
        const publicOrigin = new URL(this.url).origin;
        const headers = headersForPublicRequest(rawReq, publicOrigin);
        requireDnsidA2aHeaders(headers);

        const verified = await this.httpProfile.verifySignedHttpRequest(toWebRequest(rawReq, headers, publicOrigin), {
          requiredTag: DNSID_A2A_SIGNATURE_TAG,
          requiredComponents: [
            '@method',
            '@target-uri',
            'content-type',
            'content-digest',
            'a2a-version',
            'a2a-extensions',
          ],
        });

        rawReq.senderId = verified.domain;
        console.log(
          `[${this.identityManager.config.identity!.domain}] verified signed ${rawReq.method} ${rawReq.url ?? '/'} from ${verified.domain}`,
        );
        next();
      } catch (err) {
        const status = err instanceof BadRequestError ? 400 : 401;
        res.status(status).json({ error: String(err) });
      }
    };
  }

  private mountA2aRoutes(app: express.Express, requestHandler: A2ARequestHandler): void {
    app.use(`/${AGENT_CARD_PATH}`, agentCardHandler({ agentCardProvider: requestHandler }));
    app.use(
      '/',
      jsonRpcHandler({
        requestHandler,
        userBuilder: async (req: ExpressRequest) =>
          new VerifiedSenderUser((req as RawBodyRequest).senderId ?? ''),
      }),
    );
  }

  private mountDnsidWellKnownRoutes(app: express.Express): void {
    app.get('/.well-known/jwks.json', async (_req, res) => {
      res.json((await this.identityManager.getKeySet()).toJSON());
    });
    if (this.identityManager.config.identity!.ekUrl) {
      app.get(new URL(this.identityManager.config.identity!.ekUrl).pathname, async (_req, res) => {
        res.json((await this.identityManager.getEntityKeySet()).toJSON());
      });
    }

    app.get('/.well-known/status.json', async (_req, res) => {
      res.json(activeStatusDocument());
    });
  }

  private async listen(app: express.Express): Promise<void> {
    await new Promise<void>(resolve => {
      this.server = app.listen(this.port, () => resolve()) as http.Server;
    });
  }
}

async function describeDomainVerification(identityManager: IdentityManager, verified: VerifiedDomain) {
  const lifecycle = await identityManager.loadDomainLog(verified);
  return {
    dns: {
      query: `_dnsid.${verified.domain}`,
      txtRecord: verified.record.serialize(),
      dnssec: verified.dnssecState,
      ttlSeconds: verified.dnsTTL,
    },
    entityKeys: {
      url: verified.record.ek,
      jwks: verified.recordSigningJwks.toJSON(),
      recordSigningKeyId: verified.signingKey.kid,
      checks: ['entity JWKS is valid', '_dnsid record signature is valid'],
    },
    operationalKeys: {
      url: verified.record.ku,
      jwks: verified.jwks.toJSON(),
      activeKeyId: verified.jwks.currentOperationalSigningKey().kid,
      checks: ['operational JWKS is valid', 'entity and operational keys are distinct'],
    },
    lifecycle: {
      logReference: verified.record.lr,
      checks: [
        'C2SP inclusion and timestamp proofs are valid',
        'ISSUANCE entity signature and operational countersignature are valid',
        'operational key continuity reaches the currently published key',
        'complete lifecycle history is internally consistent',
      ],
      events: lifecycle.events,
    },
    status: {
      url: verified.record.su,
      state: verified.cachedState(),
      verifiedAt: verified.verifiedAt.toISOString(),
    },
  };
}

async function signAgentCard(card: AgentCard, joseProfile: JoseProfile): Promise<void> {
  const { signatures: _signatures, ...unsignedCard } = card;
  const jws = await joseProfile.createJWS(new TextEncoder().encode(canonicalizeAgentCard(unsignedCard)));
  const [protectedHeader, , signature] = jws.split('.') as [string, string, string];
  card.signatures = [{ protected: protectedHeader, signature, header: undefined }];
}

function createDemoFetch(baseFetch: typeof fetch, trace: DemoTrace, tamper: boolean): typeof fetch {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = init === undefined && input instanceof Request ? input.clone() : new Request(input, init);
    let outbound = request;

    if (request.method === 'POST') {
      const body = await request.clone().text();
      const transmittedBody = tamper ? `${body} ` : body;
      trace.request = {
        method: request.method,
        url: request.url,
        headers: selectedHeaders(request.headers),
        signedBody: body,
        transmittedBody,
      };
      if (tamper) outbound = new Request(request, { body: transmittedBody });
    }

    const response = await baseFetch(outbound);
    if (request.method === 'GET' && request.url.includes('/.well-known/agent-card.json')) {
      try { trace.agentCard = await response.clone().json(); } catch { /* displayed as unavailable */ }
    }
    if (request.method === 'POST') {
      trace.response = { status: response.status, body: await response.clone().text() };
    }
    return response;
  };
}

function isLoopbackRequest(req: ExpressRequest): boolean {
  return ['localhost', '127.0.0.1', '::1'].includes(req.hostname);
}

function selectedHeaders(headers: Headers): Record<string, string> {
  const selected: Record<string, string> = {};
  for (const name of [
    'content-type',
    'content-digest',
    'a2a-version',
    'a2a-extensions',
    'signature-input',
    'signature',
  ]) {
    const value = headers.get(name);
    if (value) selected[name] = value;
  }
  return selected;
}

function peerUrl(localKuUrl: string | undefined, peerFqdn: string): string {
  const url = new URL(localKuUrl ?? `https://${peerFqdn}`);
  url.hostname = peerFqdn;
  url.pathname = '';
  url.search = '';
  url.hash = '';
  return url.toString().replace(/\/$/, '');
}

function captureRawJsonBody(): RequestHandler {
  return express.json({
    type: ['application/json', 'application/a2a+json'],
    verify: (req: ExpressRequest, _res, buf: Buffer) => {
      (req as RawBodyRequest).rawBody = buf.toString('utf-8');
    },
  });
}

async function prepareSignedA2aRequest(req: Request): Promise<Request> {
  if (req.method.toUpperCase() !== 'POST') return req;

  const headers = new Headers(req.headers);
  if (!headers.has('content-type')) headers.set('content-type', 'application/json');
  headers.set('a2a-version', A2A_VERSION);
  headers.set('a2a-extensions', DNSID_A2A_EXTENSION_URI);

  return new Request(req.url, {
    method: req.method,
    headers,
    body: await req.arrayBuffer(),
  });
}

function requireDnsidA2aHeaders(headers: Headers): void {
  if (headers.get('a2a-version') !== A2A_VERSION) {
    throw new BadRequestError(`A2A-Version must be ${A2A_VERSION}`);
  }

  const requestedExtensions = (headers.get('a2a-extensions') ?? '')
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);
  if (!requestedExtensions.includes(DNSID_A2A_EXTENSION_URI)) {
    throw new BadRequestError(`A2A-Extensions must include ${DNSID_A2A_EXTENSION_URI}`);
  }
}

function headersForPublicRequest(req: RawBodyRequest, publicOrigin: string): Headers {
  const headers = new Headers(req.headers as unknown as HeadersInit);
  headers.set('host', new URL(publicOrigin).host);
  return headers;
}

function toWebRequest(req: RawBodyRequest, headers: Headers, publicOrigin: string): Request {
  return new Request(`${publicOrigin}${req.url ?? '/'}`, {
    method: req.method,
    headers,
    body: req.rawBody || undefined,
  });
}

class BadRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BadRequestError';
  }
}

