import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packages = ['core', 'http-signatures', 'jose', 'oidc', 'registry', 'transport', 'web-bot-auth', 'log-c2sp-tlog', 'sdk', 'key-aws'];
const browserCapablePackages = ['core', 'http-signatures', 'jose', 'registry', 'web-bot-auth', 'log-c2sp-tlog', 'sdk'];

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
  const [packed] = JSON.parse(result.stdout);
  if (!packed.files.some((file) => file.path === 'LICENSE')) throw new Error(`${packed.name} tarball is missing LICENSE`);
  tarballs.push(path.join(tarballDir, packed.filename));
}

await writeFile(path.join(consumerDir, 'package.json'), JSON.stringify({ type: 'module', private: true }, null, 2));
run('npm', ['install', '--ignore-scripts', '--no-audit', '--package-lock=false', ...tarballs], { cwd: consumerDir });

await writeFile(path.join(consumerDir, 'esm.mjs'), `
import { IdentityManager, LogRegistry } from '@identity-digital/dnsid-protocol';
import { HttpSignaturesProfile } from '@identity-digital/dnsid-http-signatures';
import { JoseProfile } from '@identity-digital/dnsid-jose';
import { OIDCProfile, OIDCTokenMinter, createOIDCKeyProviderFromJWK, createOIDCTokenMinter, mintOIDCToken } from '@identity-digital/dnsid-oidc';
import { RegistryClient, publishToRegistry } from '@identity-digital/dnsid-registry';
import { createDnsidFetch } from '@identity-digital/dnsid-transport';
import { WebBotAuthProfile } from '@identity-digital/dnsid-web-bot-auth';
import { C2spTlogReader, createC2spTlogVerificationRegistry, registerC2spTlog } from '@identity-digital/dnsid-log-c2sp-tlog';
import { parsePreparedC2spTlogEvent } from '@identity-digital/dnsid-log-c2sp-tlog/writer';
import { C2SP_TLOG_PROFILE_VERSION } from '@identity-digital/dnsid-log-c2sp-tlog/version';
import {
  DNSSECState,
  DnsIdTxtRecord as RootDnsIdTxtRecord,
  IdentityManager as RootIdentityManager,
  JWKS_MAX_RESPONSE_BYTES,
  LogRegistry as RootLogRegistry,
  STATUS_MAX_RESPONSE_BYTES,
  createIdentityManager,
} from '@identity-digital/dnsid';
import { LocalKeyProvider, createNodeIdentityManager } from '@identity-digital/dnsid/node';
import { AwsKmsKeyProvider, AwsSdkKmsFacade } from '@identity-digital/dnsid-key-aws';

for (const value of [IdentityManager, RootIdentityManager, LocalKeyProvider, LogRegistry, RootLogRegistry, RootDnsIdTxtRecord, HttpSignaturesProfile, JoseProfile, OIDCProfile, OIDCTokenMinter, createOIDCKeyProviderFromJWK, createOIDCTokenMinter, mintOIDCToken, RegistryClient, publishToRegistry, createDnsidFetch, WebBotAuthProfile, C2spTlogReader, createC2spTlogVerificationRegistry, registerC2spTlog, parsePreparedC2spTlogEvent, createIdentityManager, createNodeIdentityManager, AwsKmsKeyProvider, AwsSdkKmsFacade]) {
  if (typeof value !== 'function') throw new Error('expected ESM function export');
}
if (DNSSECState.VALID !== 'VALID') throw new Error('expected root DNSSECState export');
if (JWKS_MAX_RESPONSE_BYTES !== 256 * 1024) throw new Error('expected root JWKS_MAX_RESPONSE_BYTES export');
if (STATUS_MAX_RESPONSE_BYTES !== 16 * 1024) throw new Error('expected root STATUS_MAX_RESPONSE_BYTES export');
if (C2SP_TLOG_PROFILE_VERSION !== 1) throw new Error('expected portable C2SP version export');
`);

await writeFile(path.join(consumerDir, 'cjs.cjs'), `
const core = require('@identity-digital/dnsid-protocol');
const http = require('@identity-digital/dnsid-http-signatures');
const jose = require('@identity-digital/dnsid-jose');
const oidc = require('@identity-digital/dnsid-oidc');
const registry = require('@identity-digital/dnsid-registry');
const transport = require('@identity-digital/dnsid-transport');
const webBotAuth = require('@identity-digital/dnsid-web-bot-auth');
const c2spTlog = require('@identity-digital/dnsid-log-c2sp-tlog');
const c2spTlogWriter = require('@identity-digital/dnsid-log-c2sp-tlog/writer');
const c2spTlogVersion = require('@identity-digital/dnsid-log-c2sp-tlog/version');
const sdk = require('@identity-digital/dnsid');
const sdkNode = require('@identity-digital/dnsid/node');
const keyAws = require('@identity-digital/dnsid-key-aws');

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
} from '@identity-digital/dnsid';

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
