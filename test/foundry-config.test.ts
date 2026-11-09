import { join } from 'node:path';
import { writeFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { loadEnvironment, loadFile, mergeLoadedConfig, constructIdentityManager } from '@dnsid-ai/sdk/node';
import { withTemp } from './helpers/cli-directory.ts';

describe('Foundry configuration loading', () => {
  it('preserves only supplied expectations and does not construct an identity or acceptance policy', async () => {
    await withTemp(async root => {
      const file = join(root, 'deployment.json');
      await writeFile(file, JSON.stringify({ foundry: { organizationId: 'Org-A', governanceId: 'EXAMPLE.COM.' } }));
      const loaded = await loadFile(file);
      expect(loaded).toEqual({ foundry: { organizationId: 'Org-A', governanceId: 'EXAMPLE.COM.' } });
      const manager = await constructIdentityManager(loaded);
      expect(manager.config.identity).toBeUndefined();
      expect(manager.config.verification.trustedEntities).toBeUndefined();
    });
  });
  it('merges Foundry fields by presence, without adding SDK-specific environment variables', async () => {
    expect(mergeLoadedConfig({ foundry: { organizationId: 'Org-A', governanceId: 'example.com' } },
      { foundry: { organizationId: '' } })).toEqual({ foundry: { organizationId: '', governanceId: 'example.com' } });
    expect(await loadEnvironment({ DNSID_FOUNDRY_ORGANIZATION_ID: 'ignored', DNSID_FOUNDRY_GOVERNANCE_ID: 'ignored' })).toEqual({});
    expect(await loadEnvironment({ DNSID_GOVERNANCE_ID: 'ordinary.example' })).toEqual({ dnsid: { identity: { governanceId: 'ordinary.example' } } });
    expect(mergeLoadedConfig({}, {})).not.toHaveProperty('foundry');
  });
  it.each([{ unknown: 'x' }, { organizationId: 42 }, { governanceId: null }, []])('rejects unknown or mistyped values: %j', async foundry => {
    await withTemp(async root => {
      const file = join(root, 'deployment.json');
      await writeFile(file, JSON.stringify({ foundry }));
      await expect(loadFile(file)).rejects.toThrow();
    });
  });
  it('omits blank values and rejects duplicate members', async () => {
    await withTemp(async root => {
      const file = join(root, 'deployment.json');
      await writeFile(file, JSON.stringify({ foundry: { organizationId: ' ', governanceId: '' } }));
      expect((await loadFile(file)).foundry).toBeUndefined();
      await writeFile(file, '{"foundry":{"organizationId":"a","organizationId":"b"}}');
      await expect(loadFile(file)).rejects.toThrow();
    });
  });
});
