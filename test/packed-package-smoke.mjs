import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packages = ['protocol', 'http-signatures', 'jose', 'oidc', 'registry', 'transport', 'web-bot-auth', 'log-c2sp-tlog', 'sdk', 'key-aws'];
const browserCapablePackages = ['protocol', 'http-signatures', 'jose', 'registry', 'web-bot-auth', 'log-c2sp-tlog', 'sdk'];

for (const name of browserCapablePackages) {
  const manifest = JSON.parse(await readFile(path.join(root, 'packages', name, 'package.json'), 'utf8'));
  if (manifest.engines?.node) {
    throw new Error(`browser-capable package ${manifest.name} must not declare a package-wide Node.js engine requirement`);
  }
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    stdio: 'inherit',
    shell: process.platform === 'win32',
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with exit code ${result.status}`);
  }
}

const work = await mkdtemp(path.join(tmpdir(), 'dnsid-pack-smoke-'));
const tarballDir = path.join(work, 'tarballs');
const consumerDir = path.join(work, 'consumer');
await mkdir(tarballDir);
await mkdir(consumerDir);

run('npm', ['run', 'build']);

const tarballs = [];
for (const name of packages) {
  const manifest = JSON.parse(await readFile(path.join(root, 'packages', name, 'package.json'), 'utf8'));
  if (manifest.license !== 'Apache-2.0') throw new Error(`${manifest.name} must declare the Apache-2.0 license`);

  const result = spawnSync('npm', ['pack', path.join(root, 'packages', name), '--json', '--pack-destination', tarballDir], {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
    shell: process.platform === 'win32',
  });
  if (result.status !== 0) {
    throw new Error(`npm pack packages/${name} failed with exit code ${result.status}`);
  }
  const parsed = JSON.parse(result.stdout);
  const [packed] = Array.isArray(parsed) ? parsed : Object.values(parsed); // npm <=11: array; npm 12: {name: {...}}
  if (!packed.files.some((file) => file.path === 'LICENSE')) throw new Error(`${packed.name} tarball is missing LICENSE`);
  tarballs.push(path.join(tarballDir, packed.filename));
}

await writeFile(path.join(consumerDir, 'package.json'), JSON.stringify({ type: 'module', private: true }, null, 2));
run('npm', ['install', '--ignore-scripts', '--no-audit', '--package-lock=false', ...tarballs], { cwd: consumerDir });

await writeFile(path.join(consumerDir, 'esm.mjs'), `
import { IdentityManager, LogRegistry } from '@dnsid-ai/protocol';
import { HttpSignaturesProfile } from '@dnsid-ai/http-signatures';
import { JoseProfile } from '@dnsid-ai/jose';
import { OIDCProfile, OIDCTokenMinter, createOIDCKeyProviderFromJWK, createOIDCTokenMinter, mintOIDCToken } from '@dnsid-ai/oidc';
import { RegistryClient, publishToRegistry } from '@dnsid-ai/registry';
import { createDnsidFetch } from '@dnsid-ai/transport';
import { WebBotAuthProfile } from '@dnsid-ai/web-bot-auth';
import { C2spTlogReader, createC2spTlogVerificationRegistry, registerC2spTlog } from '@dnsid-ai/log-c2sp-tlog';
import { parsePreparedC2spTlogEvent } from '@dnsid-ai/log-c2sp-tlog/writer';
import { C2SP_TLOG_PROFILE_VERSION } from '@dnsid-ai/log-c2sp-tlog/version';
import {
  DNSSECState,
  DnsIdTxtRecord as RootDnsIdTxtRecord,
  IdentityManager as RootIdentityManager,
  JWKS_MAX_RESPONSE_BYTES,
  LogRegistry as RootLogRegistry,
  STATUS_MAX_RESPONSE_BYTES,
  createIdentityManager,
} from '@dnsid-ai/sdk';
import { LocalKeyProvider, createNodeIdentityManager } from '@dnsid-ai/sdk/node';
import { AwsKmsKeyProvider, AwsSdkKmsFacade } from '@dnsid-ai/key-aws';

for (const value of [IdentityManager, RootIdentityManager, LocalKeyProvider, LogRegistry, RootLogRegistry, RootDnsIdTxtRecord, HttpSignaturesProfile, JoseProfile, OIDCProfile, OIDCTokenMinter, createOIDCKeyProviderFromJWK, createOIDCTokenMinter, mintOIDCToken, RegistryClient, publishToRegistry, createDnsidFetch, WebBotAuthProfile, C2spTlogReader, createC2spTlogVerificationRegistry, registerC2spTlog, parsePreparedC2spTlogEvent, createIdentityManager, createNodeIdentityManager, AwsKmsKeyProvider, AwsSdkKmsFacade]) {
  if (typeof value !== 'function') throw new Error('expected ESM function export');
}
if (DNSSECState.VALID !== 'VALID') throw new Error('expected root DNSSECState export');
if (JWKS_MAX_RESPONSE_BYTES !== 256 * 1024) throw new Error('expected root JWKS_MAX_RESPONSE_BYTES export');
if (STATUS_MAX_RESPONSE_BYTES !== 16 * 1024) throw new Error('expected root STATUS_MAX_RESPONSE_BYTES export');
if (C2SP_TLOG_PROFILE_VERSION !== 1) throw new Error('expected portable C2SP version export');
`);

await writeFile(path.join(consumerDir, 'cjs.cjs'), `
const core = require('@dnsid-ai/protocol');
const http = require('@dnsid-ai/http-signatures');
const jose = require('@dnsid-ai/jose');
const oidc = require('@dnsid-ai/oidc');
const registry = require('@dnsid-ai/registry');
const transport = require('@dnsid-ai/transport');
const webBotAuth = require('@dnsid-ai/web-bot-auth');
const c2spTlog = require('@dnsid-ai/log-c2sp-tlog');
const c2spTlogWriter = require('@dnsid-ai/log-c2sp-tlog/writer');
const c2spTlogVersion = require('@dnsid-ai/log-c2sp-tlog/version');
const sdk = require('@dnsid-ai/sdk');
const sdkNode = require('@dnsid-ai/sdk/node');
const keyAws = require('@dnsid-ai/key-aws');

for (const value of [core.IdentityManager, sdk.IdentityManager, sdkNode.LocalKeyProvider, core.LogRegistry, sdk.LogRegistry, sdk.DnsIdTxtRecord, http.HttpSignaturesProfile, jose.JoseProfile, oidc.OIDCProfile, oidc.OIDCTokenMinter, oidc.createOIDCKeyProviderFromJWK, oidc.createOIDCTokenMinter, oidc.mintOIDCToken, registry.RegistryClient, registry.publishToRegistry, transport.createDnsidFetch, webBotAuth.WebBotAuthProfile, c2spTlog.C2spTlogReader, c2spTlog.createC2spTlogVerificationRegistry, c2spTlog.registerC2spTlog, c2spTlogWriter.parsePreparedC2spTlogEvent, sdk.createIdentityManager, sdkNode.createNodeIdentityManager, keyAws.AwsKmsKeyProvider, keyAws.AwsSdkKmsFacade]) {
  if (typeof value !== 'function') throw new Error('expected CJS function export');
}
if (sdk.DNSSECState.VALID !== 'VALID') throw new Error('expected root DNSSECState export');
if (sdk.JWKS_MAX_RESPONSE_BYTES !== 256 * 1024) throw new Error('expected root JWKS_MAX_RESPONSE_BYTES export');
if (sdk.STATUS_MAX_RESPONSE_BYTES !== 16 * 1024) throw new Error('expected root STATUS_MAX_RESPONSE_BYTES export');
if (c2spTlogVersion.C2SP_TLOG_PROFILE_VERSION !== 1) throw new Error('expected portable C2SP version export');
`);

await writeFile(path.join(consumerDir, 'browser.mjs'), `
import {
  DomainLog,
  SDK_CONFORMANCE,
  createIdentityManager,
  issueManagedIdentity,
  rotateManagedOperationalKey,
} from '@dnsid-ai/sdk';

globalThis.__dnsidBrowserExports = [
  DomainLog,
  SDK_CONFORMANCE,
  createIdentityManager,
  issueManagedIdentity,
  rotateManagedOperationalKey,
];
`);

run('node', ['esm.mjs'], { cwd: consumerDir });
run('node', ['cjs.cjs'], { cwd: consumerDir });
run(path.join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'esbuild.cmd' : 'esbuild'), ['browser.mjs', '--bundle', '--platform=browser', '--format=esm', '--outfile=browser-bundle.mjs'], { cwd: consumerDir });

const browserBundle = await readFile(path.join(consumerDir, 'browser-bundle.mjs'), 'utf8');
for (const forbidden of [/\bnode:/, /\bBuffer\b/, /\bprocess\./]) {
  if (forbidden.test(browserBundle)) throw new Error(`browser bundle contains Node-only global: ${forbidden}`);
}

console.log(`packed-package smoke test passed (${work})`);
