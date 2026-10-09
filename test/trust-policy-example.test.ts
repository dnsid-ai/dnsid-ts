import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, it } from 'vitest';

it('rejects missing arguments and invalid trust without network access', () => {
  const script = 'examples/trust-policy/src/index.ts';
  const run = (...args: string[]) => spawnSync(process.execPath, ['--import', 'tsx', script, ...args], { encoding: 'utf8' });
  const missing = run();
  expect(missing.status).toBe(1);
  expect(missing.stderr).toContain('usage:');
  const dir = mkdtempSync(join(tmpdir(), 'dnsid-trust-'));
  try {
    const profile = join(dir, 'profile.json');
    writeFileSync(profile, '{}');
    const invalid = run('agent.example', profile, 'acme.example', 'invalid');
    expect(invalid.status).toBe(1);
    expect(invalid.stderr).toMatch(/trust profile/i);
    // A valid profile reaches pin validation without querying DNS.
    writeFileSync(profile, JSON.stringify({
      version: 1,
      scope: 'public',
      log_prefix: 'https://log.example',
      tlog_policy: 'log log.example+3db4ee08+AcqTrBcFGHBx1nuDx/8O/oEI6OxFMFdddyaHkzPb2r58\n'
        + 'witness primary witness.example+da76602f+BG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx\n'
        + 'quorum primary\n',
      bundle_verifier_keys: ['dnsid-stream-bundle+dfa43feb+AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
    }));
    const invalidPin = run('agent.example', profile, 'acme.example', 'invalid');
    expect(invalidPin.status).toBe(1);
    expect(invalidPin.stderr).toMatch(/thumbprint/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
