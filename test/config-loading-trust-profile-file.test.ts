import { readFileSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';

import { DNSSECState } from '@dnsid-ai/sdk';
import type { DNSResolver, JsonFetcher } from '@dnsid-ai/sdk';
import { constructIdentityManager, loadEnvironment, mergeLoadedConfig } from '@dnsid-ai/sdk/node';
import { withTemp } from './helpers/cli-directory.ts';

// Observe the trust profile the loader hands to the verification registry.
const registryCalls = vi.hoisted(() => [] as Array<{ trustProfile?: unknown }>);
vi.mock('@dnsid-ai/log-c2sp-tlog', async importOriginal => {
  const actual = await importOriginal<typeof import('@dnsid-ai/log-c2sp-tlog')>();
  return {
    ...actual,
    createC2spTlogVerificationRegistry: async (options: Parameters<typeof actual.createC2spTlogVerificationRegistry>[0]) => {
      registryCalls.push(options);
      return actual.createC2spTlogVerificationRegistry(options);
    },
  };
});

const dnsResolver: DNSResolver = { fetchTXT: vi.fn().mockResolvedValue([[], DNSSECState.UNSIGNED]) };
const fetchJson: JsonFetcher = vi.fn();
const deps = { dnsResolver, fetchJson };
const vectors = JSON.parse(readFileSync(new URL('./fixtures/c2sp-trust-profile-epochs-v1.json', import.meta.url), 'utf8')) as { profiles: Record<string, string> };

function trustedEpochIds(): string[] {
  const profile = registryCalls.at(-1)?.trustProfile as { version: number; epochs?: Array<{ id: string }> } | undefined;
  expect(profile?.version).toBe(2);
  return profile!.epochs!.map(epoch => epoch.id);
}

describe('DNSID_LOG_TRUST_PROFILE_FILE edits after loading', () => {
  // createNodeIdentityManagerFromEnvironment is exactly loadEnvironment -> mergeLoadedConfig ->
  // constructIdentityManager; the steps are called separately so the loaded profile can be edited.
  it('uses the file bytes for an unedited profile', () => withTemp(async root => {
    const file = join(root, 'profile.json');
    await writeFile(file, vectors.profiles['v2-bounded']!);
    await constructIdentityManager(mergeLoadedConfig(await loadEnvironment({ DNSID_LOG_TRUST_PROFILE_FILE: file }), {}), deps);
    expect(trustedEpochIds()).toEqual(['legacy', 'successor']);
  }));

  it('honors an edit that removes an epoch instead of trusting the file bytes again', () => withTemp(async root => {
    const file = join(root, 'profile.json');
    await writeFile(file, vectors.profiles['v2-bounded']!);
    const loaded = await loadEnvironment({ DNSID_LOG_TRUST_PROFILE_FILE: file });
    const epochs = loaded.logTrust!.profile!.epochs as Array<{ id: string }>;
    epochs.splice(epochs.findIndex(epoch => epoch.id === 'legacy'), 1);
    await constructIdentityManager(mergeLoadedConfig(loaded, {}), deps);
    expect(trustedEpochIds()).toEqual(['successor']);
  }));
});
