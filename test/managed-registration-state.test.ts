import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, it, vi } from 'vitest';
import { runRegistration } from '../examples/managed-registration/src/registration.ts';
import { prepareStateDirectory, readState, writeState } from '../examples/managed-registration/src/state.ts';

it('preserves replay keys and exact issuance bytes through file-backed recovery', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'dnsid-registration-state-'));
  const directory = join(parent, 'nested', 'state');
  try {
    await prepareStateDirectory(directory);
    expect((await stat(directory)).mode & 0o777).toBe(0o700);
    expect(await readState(directory, 'request.json')).toBeUndefined();

    const request = { idempotencyKey: 'registration-1', input: { environment: 'sandbox' } };
    await writeState(directory, 'request.json', request);
    expect(await readState(directory, 'request.json')).toEqual(request);

    const issuance = {
      idempotencyKey: 'issuance-1', entryBytes: new Uint8Array([0, 1, 127, 128, 255]),
      activated: false,
    };
    await writeState(directory, 'issuance.json', issuance);
    expect((await stat(join(directory, 'issuance.json'))).mode & 0o777).toBe(0o600);
    expect(await readState(directory, 'issuance.json')).toEqual(issuance);
    expect(JSON.parse(await readFile(join(directory, 'issuance.json'), 'utf8')).entryBytes).toBe('AAF_gP8');

    // An interrupted temporary write must not replace the last durable state.
    await writeFile(join(directory, 'issuance.json.tmp'), '{', { mode: 0o600 });
    expect(await readState(directory, 'issuance.json')).toEqual(issuance);
    const accepted = { ...issuance, submission: { state: 'accepted' }, activated: true };
    await writeState(directory, 'issuance.json', accepted);
    expect(await readState(directory, 'issuance.json')).toEqual(accepted);

    // Corruption is an error, not permission to start a second registration.
    await writeFile(join(directory, 'request.json'), '{');
    await expect(readState(directory, 'request.json')).rejects.toThrow(SyntaxError);

    await rm(join(directory, 'request.json'));
    const fetch = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('unexpected network request'));
    try {
      await expect(runRegistration(directory, 'offline-test-token')).rejects.toThrow('original registration request is missing');
      expect(fetch).not.toHaveBeenCalled();
      expect(await readState(directory, 'keys.json')).toBeUndefined();
    } finally {
      fetch.mockRestore();
    }
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});
