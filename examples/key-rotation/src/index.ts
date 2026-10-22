import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { resumeManagedOperationalKeyRotation, rotateManagedOperationalKey } from '@dnsid-ai/sdk';
import { openDemo } from './support.ts';

async function main() {
  const demo = await openDemo();
  const { manager, keyProvider, keyPath, registryClient } = demo;
  const { domain, logRef: logReference } = manager.config.identity!;
  const restoring = demo.rotation?.activated === true;
  const coordination = {
    identityManager: manager,
    persistRotation: demo.persistRotation,
    setApplicationSigningPaused: demo.setApplicationSigningPaused,
    setApplicationSigner: demo.setApplicationSigner,
  };

  let rotation;
  if (demo.rotation) {
    // Resume the saved operation, never prepare a replacement.
    rotation = await resumeManagedOperationalKeyRotation({
      rotation: demo.rotation, registryClient, ...coordination,
      resolveKeyProvider: demo.resolveKeyProvider,
    });
  } else {
    // Show that the current key works before rotating it.
    const before = await manager.verifyLocalPublication();
    const oldMessage = await demo.signAndVerify(before);
    await demo.saveOldMessage(oldMessage);
    console.log('old key signs and verifies');

    rotation = await rotateManagedOperationalKey({
      domain, logReference, keyProvider, registryClient,
      idempotencyKey: randomUUID(),
      previousProviderReference: keyPath, newProviderReference: keyPath,
      ...coordination,
    });
  }

  assert(rotation.activated && !rotation.applicationSigningPaused,
    'rotation pending; rerun the same command to resume');
  if (restoring) {
    console.log('saved rotation restored; no network checks');
    return;
  }

  // Fetch current evidence: the new key must work and the old key must fail.
  const after = await manager.verifyLocalPublication();
  assert.equal(after.jwks.keys.length, 1);
  assert.equal(after.jwks.currentOperationalSigningKey().kid, rotation.newKid);
  assert(!(await keyProvider.listKeyIds()).includes(rotation.previousKid));
  await demo.signAndVerify(after);
  await demo.rejectOldMessage();

  console.log(`rotation verified: ${rotation.previousKid} -> ${rotation.newKid}`);
  console.log('new key signs and verifies; old key is absent from live JWKS and provider');
}

main().catch(error => {
  console.error('rotation:', error.message, error.cause?.message ?? '');
  console.error('Rerun the same command to recover; do not delete the saved state.');
  process.exitCode = 1;
});
