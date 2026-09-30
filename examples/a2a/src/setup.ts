import { echoExecutor } from './agent.ts';
import { EchoAgent } from './server.ts';
import { constructIdentityManager, loadEnvironment, mergeLoadedConfig, type LoadedConfig } from '@dnsid-ai/sdk/node';
import {
  awaitRegistryManagedPublication,
  RegistryClient,
  toBase64Url,
} from '@dnsid-ai/sdk';
import type { IdentityManager, TransportConfig } from '@dnsid-ai/sdk';
import { parseC2spTlogLr } from '@dnsid-ai/log-c2sp-tlog';
import { createDnsidFetch } from '@dnsid-ai/transport';

export interface RunningEchoAgent {
  idm: IdentityManager;
  agent: EchoAgent;
  stop(): Promise<void>;
}

export async function startEchoAgent(): Promise<RunningEchoAgent> {
  const loaded = await loadEnvironment();
  const idm = await createIdentity(loaded);
  // The Node factory consumes and clears idm.config.transport. Reuse the
  // loaded DNS/CA settings for the registry and outbound A2A clients.
  const transport = loaded.dnsid?.transport ?? {};
  const agent = await createAndStartAgent(idm, transport);

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

/** `dnsid local run` exports the DNSID_* environment: identity, DNSID_CONFIG_DIR (keys), DNSID_LOG_POLICY_URL (trust), and transport. */
async function createIdentity(loaded: LoadedConfig): Promise<IdentityManager> {
  const kuUrl = loaded.dnsid?.identity?.kuUrl;
  if (!kuUrl) throw new Error('DNSID_KU_URL is required; run with `dnsid local run`');
  if (!loaded.keySource?.cliDirectory) throw new Error('DNSID_CONFIG_DIR is required; run with `dnsid local run`');
  if (!loaded.logTrust) throw new Error('DNSID_LOG_POLICY_URL is required; run with `dnsid local run`');
  // Not SDK configuration: the example derives its agent card URL from the public URL the testnet exports.
  const publicUrl = process.env.DNSID_PUBLIC_URL ?? new URL(kuUrl).origin;
  const overlay = { dnsid: { identity: { capabilitiesUrl: `${publicUrl}/.well-known/agent-card.json` } } };
  return constructIdentityManager(mergeLoadedConfig(overlay, loaded));
}

/** DNSID_AGENT_PORT / DNSID_AGENT_NAME / DNSID_PUBLIC_URL are deployment settings, read by the example, not the SDK. */
async function createAndStartAgent(idm: IdentityManager, transport: TransportConfig): Promise<EchoAgent> {
  const port = Number(process.env.DNSID_AGENT_PORT);
  if (!Number.isInteger(port) || port <= 0) throw new Error('DNSID_AGENT_PORT must be a positive integer');
  const publicUrl = process.env.DNSID_PUBLIC_URL ?? new URL(idm.config.identity!.kuUrl ?? `https://${idm.config.identity!.domain}`).origin;
  const agent = await EchoAgent.create(echoExecutor(idm.config.identity!.domain), idm, port, { publicUrl, transport });

  await agent.start();
  console.log(`${process.env.DNSID_AGENT_NAME ?? idm.config.identity!.domain} -> ${agent.url}`);

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
