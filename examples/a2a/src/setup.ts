import { echoExecutor } from './agent.ts';
import { EchoAgent } from './server.ts';
import {
  configFromEnvironment,
  createNodeIdentityManager,
  LocalKeyProvider,
} from '@dnsid-ai/sdk/node';
import {
  awaitRegistryManagedPublication,
  RegistryClient,
  toBase64Url,
  VerificationCode,
  VerificationError,
} from '@dnsid-ai/sdk';
import type { IdentityManager, LogRegistry, TransportConfig } from '@dnsid-ai/sdk';
import {
  createC2spTlogVerificationRegistry,
  createFetchBackedC2spResourceFetcher,
  parseC2spTlogLr,
  requiredC2spResourceFetchGuarantees,
} from '@dnsid-ai/log-c2sp-tlog';
import { createDefaultDnsResolver, createDnsidFetch, createSsrfSafeFetch } from '@dnsid-ai/transport';
import { requiredTestnetLogPolicyUrl } from './testnet-config.ts';

type Environment = ReturnType<typeof configFromEnvironment<'agentPort' | 'kuUrl'>>;

export interface RunningEchoAgent {
  idm: IdentityManager;
  agent: EchoAgent;
  stop(): Promise<void>;
}

export async function startEchoAgent(): Promise<RunningEchoAgent> {
  const environment = loadEnvironment();
  // Core has no default transport; the testnet DNS/CA settings are consumed
  // here and handed to every HTTP client the example builds.
  const transport = environment.config.transport ?? {};
  const idm = await createIdentity(environment, transport);
  const agent = await createAndStartAgent(idm, environment, transport);

  await ensurePublished(idm, transport);
  // CoreDNS reloads the generated zone every two seconds. Avoid caching the
  // initial NXDOMAIN by waiting for that reload before the first self-check.
  await new Promise(resolve => setTimeout(resolve, 2_500));
  await poll(`self-verify ${idm.config.identity!.domain}`, () => idm.verifyDomain(idm.config.identity!.domain).then(() => undefined));

  return { idm, agent, stop: () => agent.stop() };
}

export async function poll(label: string, fn: () => Promise<void>): Promise<void> {
  let lastError: unknown;
  for (let i = 0; i < 60; i++) {
    try {
      await fn();
      return;
    } catch (err) {
      lastError = err;
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }
  throw new Error(`${label} failed: ${String(lastError)}`);
}

function loadEnvironment(): Environment {
  return configFromEnvironment({
    require: ['agentPort', 'kuUrl'],
  });
}

async function createIdentity(environment: Environment, transport: TransportConfig): Promise<IdentityManager> {
  const { identity } = environment.config;
  const zone = process.env.DNSID_TESTNET_ZONE;
  if (!zone) throw new Error('DNSID_TESTNET_ZONE is required; run with `dnsid testnet run`');
  const publicUrl = environment.publicUrl ?? new URL(identity.kuUrl).origin;
  const config = {
    ...environment.config,
    identity: {
      ...identity,
      capabilitiesUrl: identity.capabilitiesUrl ?? `${publicUrl}/.well-known/agent-card.json`,
    },
    // Testnet only: every host listed resolves to this machine. Both agents are
    // listed because each verifies the other, as caller and as receiver.
    transport: {
      ...transport,
      allowedUnsafeHosts: [
        `alice.${zone}`,
        `bob.${zone}`,
        `dnsid.${identity.governanceId}`,
        new URL(requiredTestnetLogPolicyUrl()).hostname,
      ],
    },
  };

  const configDir = process.env.DNSID_CONFIG_DIR;
  if (!configDir) throw new Error('DNSID_CONFIG_DIR is required; run with `dnsid testnet run`');

  const keyProvider = await LocalKeyProvider.fromDirectory(configDir);
  const logRegistry = await createLogRegistry(
    identity.logRef,
    requiredTestnetLogPolicyUrl(),
    transport.dnsServer,
    transport.caBundlePath,
  );
  // Route testnet lookups to its local CoreDNS instance. It reports UNKNOWN,
  // which the default auto policy permits and preserves.
  const dnsResolver = createDefaultDnsResolver({ dnsServer: transport.dnsServer });
  return createNodeIdentityManager(config, { keyProvider, dnsResolver, logRegistry });
}

async function createLogRegistry(
  logRef: string,
  policyUrl: string,
  dnsServer?: string,
  caBundlePath?: string,
): Promise<LogRegistry> {
  // Trusted testnet configuration includes the complete URL so a CLI-selected
  // non-default HTTPS port is preserved. Never derive this trust anchor from lr.
  const policyHost = new URL(policyUrl).host;
  const logHost = new URL(parseC2spTlogLr(logRef).logPrefix).host;
  const allowedHosts = new Set([policyHost, logHost]);
  const testnetFetch = createSsrfSafeFetch(
    { dnsServer, caBundlePath },
    { allowedUnsafeHosts: [...allowedHosts].map(host => new URL(`https://${host}`).hostname) },
  );
  const hostnameScopedFetch: typeof fetch = async (input, init) => {
    const target = new URL(input instanceof Request ? input.url : input);
    if (!allowedHosts.has(target.host)) {
      throw new VerificationError(`testnet C2SP resource host is not allowlisted: ${target.host}`, {
        code: VerificationCode.TLSError,
      });
    }
    return testnetFetch(input, init);
  };
  const resourceFetcher = createFetchBackedC2spResourceFetcher(
    hostnameScopedFetch,
    requiredC2spResourceFetchGuarantees(),
  );
  return createC2spTlogVerificationRegistry({ policyUrl, resourceFetcher });
}

async function createAndStartAgent(idm: IdentityManager, environment: Environment, transport: TransportConfig): Promise<EchoAgent> {
  const publicUrl = environment.publicUrl ?? new URL(idm.config.identity!.kuUrl ?? `https://${idm.config.identity!.domain}`).origin;
  const agent = await EchoAgent.create(echoExecutor(idm.config.identity!.domain), idm, environment.agentPort, { publicUrl, transport });

  await agent.start();
  console.log(`${environment.agentName ?? idm.config.identity!.domain} -> ${agent.url}`);

  // Give the local proxy a moment to see the server before registry verification starts.
  await new Promise(resolve => setTimeout(resolve, 500));
  return agent;
}

async function ensurePublished(idm: IdentityManager, transport: TransportConfig): Promise<void> {
  const registry = new RegistryClient({
    baseUrl: parseC2spTlogLr(idm.config.identity!.logRef).logPrefix,
    fetch: createDnsidFetch(transport),
  });
  let registration = await registry.getRegistration(idm.config.identity!.domain);

  if (!registration || !['VERIFIED', 'READY'].includes(registration.registryStatus)) {
    await verifyAgent(registry, idm, registration);
  }

  registration = await registry.getRegistration(idm.config.identity!.domain);
  if (!registration) throw new Error('registry registration disappeared after verification');
  if (registration.registryStatus !== 'READY') {
    if (registration.publicationAuthority !== 'registry') {
      throw new Error('client-controlled draft-01 publication requires an accountable-entity key workflow');
    }
    await awaitRegistryManagedPublication({
      domain: idm.config.identity!.domain,
      registryClient: registry,
      identityManager: idm,
      publishProfile: idm.config.identity!.publishProfile,
    });
  }
}

async function verifyAgent(
  registry: RegistryClient,
  idm: IdentityManager,
  registration: Awaited<ReturnType<RegistryClient['getRegistration']>>,
): Promise<void> {
  if (registration?.registryStatus !== 'VERIFICATION') {
    await registry.verifyAgent(idm.config.identity!.domain);
  }

  const challengeStatus = await registry.waitForStatus(idm.config.identity!.domain, current => {
    const raw = current.raw as { challenge?: unknown };
    return typeof raw.challenge === 'string' || isRegistryFailure(current.registryStatus);
  }, { intervalMs: 100, timeoutMs: 30_000 });
  if (isRegistryFailure(challengeStatus.registryStatus)) {
    throw new Error(`registry verification failed in ${challengeStatus.registryStatus}`);
  }

  const raw = challengeStatus.raw as { challenge?: unknown };
  const challenge = typeof raw.challenge === 'string' ? raw.challenge : '';
  if (!challenge) throw new Error('registry did not return a verification challenge');

  const sig = await idm.getKeyProvider().sign(base64UrlBytes(challenge));
  await registry.submitChallengeSignature(idm.config.identity!.domain, {
    nonce: challenge,
    signature: toBase64Url(sig),
  });

  const completed = await registry.waitForStatus(idm.config.identity!.domain,
    current => ['VERIFIED', 'READY'].includes(current.registryStatus) || isRegistryFailure(current.registryStatus),
    { intervalMs: 100, timeoutMs: 30_000 },
  );
  if (isRegistryFailure(completed.registryStatus)) {
    throw new Error(`registry verification failed in ${completed.registryStatus}`);
  }
}

function isRegistryFailure(status: string): boolean {
  return ['ERROR', 'REJECTED', 'CANCELLED', 'REVOKED'].includes(status);
}

function base64UrlBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, 'base64url'));
}
