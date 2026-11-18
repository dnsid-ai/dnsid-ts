// Fresh application process: real loader/merge, persisted key parsing and crypto.
// Publication evidence is a controlled seam, NOT functional publication proof.
import assert from 'node:assert/strict';
import { IdentityManager, JWKS, verifyWithKey } from '@dnsid-ai/sdk';
import { constructIdentityManager, loadFile, mergeLoadedConfig } from '@dnsid-ai/sdk/node';

IdentityManager.prototype.verifyPublicationEvidence = async function () {
  return { jwks: new JWKS([await this.getKeyProvider().signingKey()]) };
};
const loaded = mergeLoadedConfig(await loadFile(process.argv[2]), {});
const idm = await constructIdentityManager(loaded);
const provider = idm.getKeyProvider();
const key = await provider.signingKey();
const payload = new TextEncoder().encode('fresh application startup');
assert.equal(await verifyWithKey(payload, await provider.sign(payload), key, key.alg), true);
console.log(JSON.stringify({ kid: key.kid }));
