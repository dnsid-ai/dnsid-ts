import { messageText, textUserMessage } from './agent.ts';
import { poll, startEchoAgent } from './setup.ts';
import type { RunningEchoAgent } from './setup.ts';

const running = await startEchoAgent();
const peerFqdn = process.argv[2];

if (peerFqdn) {
  await sendHello(running, peerFqdn);
  await running.stop();
  process.exit(0);
}

await waitForShutdown(running.stop);

async function sendHello({ idm, agent }: RunningEchoAgent, peerFqdn: string): Promise<void> {
  await poll(`verify ${peerFqdn}`, () => idm.verifyDomain(peerFqdn).then(() => undefined));
  console.log(`verified: ${idm.config.identity!.domain} -> ${peerFqdn}\n`);

  const client = await agent.createClient(peerUrl(idm.config.identity!.kuUrl, peerFqdn));
  const result = await client.sendMessage({
    tenant: '',
    message: textUserMessage(`hello from ${idm.config.identity!.domain}`),
    configuration: undefined,
    metadata: undefined,
  });

  console.log(`reply: "${messageText(result)}"`);
}

function peerUrl(localKuUrl: string | undefined, peerFqdn: string): string {
  const url = new URL(localKuUrl ?? `https://${peerFqdn}`);
  url.hostname = peerFqdn;
  url.pathname = '';
  url.search = '';
  url.hash = '';
  return url.toString().replace(/\/$/, '');
}

async function waitForShutdown(stopAgent: () => Promise<void>): Promise<void> {
  const keepAlive = setInterval(() => undefined, 1 << 30);
  await new Promise<void>(resolve => {
    const shutdown = () => {
      clearInterval(keepAlive);
      void stopAgent().finally(resolve);
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
  });
}
