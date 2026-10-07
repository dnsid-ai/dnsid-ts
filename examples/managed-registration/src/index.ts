import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { runRegistration } from './registration.ts';

let token = '';
let directory = '';
try {
  const { values } = parseArgs({ options: {
    'state-dir': { type: 'string' },
    'api-key-file': { type: 'string' },
    'server-contract-verified': { type: 'boolean' },
  } });
  if (!values['state-dir']) throw new Error('usage: npm run start -- --server-contract-verified --state-dir <directory> [--api-key-file <file>]');
  if (!values['server-contract-verified']) throw new Error('verify permanent registry-wide creation idempotency with server integration tests, then pass --server-contract-verified');
  directory = resolve(values['state-dir']);
  token = (values['api-key-file']
    ? await readFile(values['api-key-file'], 'utf8') : process.env.DNSID_API_KEY ?? '').trim();
  if (!token || /\s/.test(token)) throw new Error('provide one API token through DNSID_API_KEY or --api-key-file');
  await runRegistration(directory, token);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(token ? message.replaceAll(token, '[REDACTED]') : message);
  if (directory) console.error(`Keep the recovery files in ${directory}. Rerun with the same directory.`);
  process.exitCode = 1;
}
