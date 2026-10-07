import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runRegistration } from './registration.ts';

const directory = process.argv[2];
const keyFile = process.env.DNSID_API_KEY_FILE;
if (!directory || !keyFile) {
  console.error('usage: DNSID_API_KEY_FILE=<file> npm run start -- <state-directory>');
  process.exit(2);
}

let token = '';
try {
  token = (await readFile(keyFile, 'utf8')).trim();
  if (!token || /\s/.test(token)) throw new Error('API key file must contain one nonempty token');
  await runRegistration(resolve(directory), token);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(token ? message.replaceAll(token, '[REDACTED]') : message);
  console.error(`Keep the recovery files in ${resolve(directory)}. Rerun with the same directory; do not start a new operation after an unknown outcome.`);
  process.exitCode = 1;
}
