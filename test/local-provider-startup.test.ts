import { execFile } from 'node:child_process';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
import { withTemp } from './helpers/cli-directory.ts';

const run = promisify(execFile);

describe('local operational key warning across application restarts (known-foundry#57)', () => {
  // Mode: fake-only for publication evidence; real-capable local filesystem/crypto.
  // No warning spy: each fresh Node process writes its native diagnostic to stderr.
  it.each([undefined, 'file'] as const)('warns on both startups with provider %s', provider => withTemp(async root => {
    // Given existing keys and deployment configuration, never fresh-key generation in construction.
    const store = join(root, 'keys.json');
    const created = await LocalKeyProvider.load(store, true);
    const key = await created.signingKey();
    const before = await readFile(store, 'utf8');
    const config = join(root, 'dnsid.json');
    await writeFile(config, JSON.stringify({
      dnsid: { identity: { domain: 'alice.example.com', governanceId: 'example.com', logRef: 'noop:0', statusUrl: 'https://alice.example.com/status' } },
      keySource: { provider, keyStorePath: store },
    }));
    // Existing esbuild tooling resolves the same public SDK aliases as the test harness.
    const app = join(root, 'startup.mjs');
    await build({ entryPoints: ['test/helpers/local-provider-startup.mjs'], outfile: app, bundle: true, platform: 'node', format: 'esm', banner: { js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);" } });
    const filesBefore = (await readdir(root)).sort();
    for (const startup of [1, 2]) {
      // When a completely fresh application reopens the same files.
      const result = await run(process.execPath, [app, config], { timeout: 20_000 });
      // Then it retains the key and warns about production safety with cloud guidance.
      expect(JSON.parse(result.stdout), `startup ${startup}`).toEqual({ kid: key.kid });
      expect(result.stderr, `startup ${startup}`).toMatch(/unsuitable for production/i);
      expect(result.stderr, `startup ${startup}`).toMatch(/cloud/i);
      expect(await readFile(store, 'utf8')).toBe(before);
      expect((await readdir(root)).sort()).toEqual(filesBefore);
    }
  }), 30_000);
});
