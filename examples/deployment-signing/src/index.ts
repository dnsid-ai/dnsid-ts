import { signDeploymentRequest } from './sign-request.ts';

const file = process.argv[2];
if (!file) throw new Error('usage: npm run start -- <deployment.json>');

const signed = await signDeploymentRequest(file);
console.log(`${signed.method} ${signed.url} (not sent)`);
console.log(Object.fromEntries(signed.headers));
console.log(await signed.text());
