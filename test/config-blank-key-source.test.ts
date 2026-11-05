import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadFile, mergeLoadedConfig } from '@dnsid-ai/sdk/node';

// Mode: fake-only. Temporary deployment files only; no providers or network.
// Contract: compliance 939d241, 12-configuration-loading.md, Principle and Merge.
async function withSource(source: Record<string, unknown>, check: (loaded: Awaited<ReturnType<typeof loadFile>>) => void) {
  const root = await mkdtemp(join(tmpdir(), 'dnsid-blank-source-'));
  try {
    const file = join(root, 'deployment.json');
    await writeFile(file, JSON.stringify({ keySource: source }));
    check(await loadFile(file));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

const blanks = [['empty', ''], ['whitespace', ' \t\r\n ']] as const;
const strings = ['provider', 'keyRef', 'cliDirectory', 'keyStorePath', 'entityKeyPath'] as const;

describe('deployment keySource blank optional strings', () => {
  for (const field of strings) {
    it.each(blanks)(`${field}: %s is absent`, (_name, blank) => {
      // Given an optional deployment-file string with no non-whitespace.
      // When the deployment file is loaded.
      return withSource({ [field]: blank }, loaded => {
        // Then the field is absent, not an explicit empty/blank value or default.
        expect(loaded.keySource?.[field]).toBeUndefined();
      });
    });
  }

  for (const field of ['provider', 'keyRef', 'cliDirectory', 'keyStorePath', 'all']) {
    it.each(blanks)(`${field}: %s operational overlay retains the base`, (_name, blank) => {
      // Given a base cloud source and only blank operational file strings.
      const base = { keySource: { provider: 'aws-kms' as const, keyRef: 'stable-key', settings: { region: 'us-east-1' }, entityKeyPath: '/base/entity.jwk' } };
      const source = field === 'all'
        ? { provider: blank, keyRef: blank, cliDirectory: blank, keyStorePath: blank }
        : { [field]: blank };
      return withSource(source, loaded => {
        // When merging the loaded file, then no operational group is displaced.
        expect(mergeLoadedConfig(base, loaded).keySource).toEqual(base.keySource);
      });
    });
  }

  it.each(blanks)('%s entity path retains the independent base path', (_name, blank) => {
    // Given a CLI base and a new cloud file selection with a blank entity path.
    const base = { keySource: { cliDirectory: '/base/cli', entityKeyPath: '/base/entity.jwk' } };
    return withSource({ provider: 'aws-kms', keyRef: 'next-key', settings: { region: 'us-east-1' }, entityKeyPath: blank }, loaded => {
      // When merging, then operational fields replace together and entity stays.
      expect(mergeLoadedConfig(base, loaded).keySource).toEqual({
        provider: 'aws-kms', keyRef: 'next-key', settings: { region: 'us-east-1' }, entityKeyPath: '/base/entity.jwk',
      });
    });
  });

  it('preserves padded nonempty file strings and provider settings unchanged', () => {
    // Given padded file strings and opaque non-secret provider settings.
    const source = {
      provider: ' aws-kms ', keyRef: ' stable-key ', cliDirectory: ' /cli ', keyStorePath: ' /store ', entityKeyPath: ' /entity ',
      settings: { region: ' us-east-1 ', blank: ' \t ', empty: '', nested: { keep: ' padded ' }, enabled: false, retries: 0 },
    };
    return withSource(source, loaded => {
      // When parsed without provider construction, then nothing is trimmed/defaulted.
      expect(loaded.keySource).toEqual(source);
    });
  });
});
