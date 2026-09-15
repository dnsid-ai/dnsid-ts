import { describe, expect, it } from 'vitest';

import { IdentityManager, LogRegistry } from '@identity-digital/dnsid-protocol';
import { LocalKeyProvider, createNodeIdentityVerifier } from '@identity-digital/dnsid/node';
import { HttpSignaturesProfile } from '@identity-digital/dnsid-http-signatures';
import { JoseProfile } from '@identity-digital/dnsid-jose';
import {
  OIDCProfile,
  OIDCTokenMinter,
  createOIDCKeyProviderFromJWK,
  createOIDCTokenMinter,
  mintOIDCToken,
} from '@identity-digital/dnsid-oidc';
import { createDnsidFetch } from '@identity-digital/dnsid-transport';
import {
  ManagedIssuanceActivationError,
  ManagedIssuanceSubmissionError,
  ManagedKeyRotationActivationError,
  ManagedKeyRotationSubmissionError,
  SDK_CONFORMANCE,
  createIdentityManager,
  createIdentityVerifier,
  issueManagedIdentity,
  resumeManagedIssuance,
  resumeManagedOperationalKeyRotation,
  rotateManagedOperationalKey,
} from '@identity-digital/dnsid';
import {
  RegistryClient,
  awaitRegistryManagedPublication,
  publishClientControlledRecord,
  PreparedEventSubmissionError,
  publishToRegistry,
} from '@identity-digital/dnsid-registry';
import { WebBotAuthProfile } from '@identity-digital/dnsid-web-bot-auth';
import { AwsKmsKeyProvider, AwsSdkKmsFacade } from '@identity-digital/dnsid-key-aws';
import { GcpCloudKmsKeyProvider } from '@identity-digital/dnsid-key-gcp';
import { C2spTlogReader, createC2spTlogVerificationRegistry, registerC2spTlog } from '@identity-digital/dnsid-log-c2sp-tlog';

describe('modular package entrypoints', () => {
  it('export the expected public package surfaces', () => {
    expect(IdentityManager).toBeTypeOf('function');
    expect(LogRegistry).toBeTypeOf('function');
    expect(HttpSignaturesProfile).toBeTypeOf('function');
    expect(JoseProfile).toBeTypeOf('function');
    expect(OIDCProfile).toBeTypeOf('function');
    expect(OIDCTokenMinter).toBeTypeOf('function');
    expect(createOIDCTokenMinter).toBeTypeOf('function');
    expect(mintOIDCToken).toBeTypeOf('function');
    expect(createOIDCKeyProviderFromJWK).toBeTypeOf('function');
    expect(createDnsidFetch).toBeTypeOf('function');
    expect(RegistryClient).toBeTypeOf('function');
    expect(awaitRegistryManagedPublication).toBeTypeOf('function');
    expect(publishClientControlledRecord).toBeTypeOf('function');
    expect(PreparedEventSubmissionError).toBeTypeOf('function');
    expect(publishToRegistry).toBeTypeOf('function');
    expect(WebBotAuthProfile).toBeTypeOf('function');
    expect(LocalKeyProvider).toBeTypeOf('function');
    expect(createIdentityManager).toBeTypeOf('function');
    expect(createIdentityVerifier).toBeTypeOf('function');
    expect(createNodeIdentityVerifier).toBeTypeOf('function');
    expect(issueManagedIdentity).toBeTypeOf('function');
    expect(resumeManagedIssuance).toBeTypeOf('function');
    expect(ManagedIssuanceActivationError).toBeTypeOf('function');
    expect(ManagedIssuanceSubmissionError).toBeTypeOf('function');
    expect(rotateManagedOperationalKey).toBeTypeOf('function');
    expect(resumeManagedOperationalKeyRotation).toBeTypeOf('function');
    expect(ManagedKeyRotationActivationError).toBeTypeOf('function');
    expect(ManagedKeyRotationSubmissionError).toBeTypeOf('function');
    expect(SDK_CONFORMANCE).toEqual({
      publishProfile: 'dnsid-draft-01',
      verificationProfiles: {
        'dnsid-draft-01': 'dnsid-draft-01',
        DNSid1: 'dnsid-draft-01',
      },
      specificationStatus: 'internet-draft',
      logBindings: {
        'c2sp-tlog': 'profile=1;tlog-checkpoint=https://c2sp.org/tlog-checkpoint@v1.0.0;tlog-tiles=https://c2sp.org/tlog-tiles@v0.1.0;tlog-proof=ab17a74116563005f908b9167e6421cc929a5c2b;tlog-policy=1896a5aea5559b3203d275d0206d872f59348cf5;tlog-witness=https://c2sp.org/tlog-witness@v1.0.0;tlog-cosignature=https://c2sp.org/tlog-cosignature@v1.0.1;tlog-mirror=d0fe789122c75b903bfc1680b0b8b8dc570f0db3;signed-note=https://c2sp.org/signed-note@v1.0.0;dnsid-method=d5a65d06f76eff4db81e50f8767a600d2ca7fc2a',
      },
      knownDeviations: [],
    });
    expect(Object.isFrozen(SDK_CONFORMANCE)).toBe(true);
    expect(Object.isFrozen(SDK_CONFORMANCE.verificationProfiles)).toBe(true);
    expect(Object.isFrozen(SDK_CONFORMANCE.logBindings)).toBe(true);
    expect(Object.isFrozen(SDK_CONFORMANCE.knownDeviations)).toBe(true);
    expect(AwsKmsKeyProvider).toBeTypeOf('function');
    expect(AwsSdkKmsFacade).toBeTypeOf('function');
    expect(GcpCloudKmsKeyProvider).toBeTypeOf('function');
    expect(C2spTlogReader).toBeTypeOf('function');
    expect(createC2spTlogVerificationRegistry).toBeTypeOf('function');
    expect(registerC2spTlog).toBeTypeOf('function');
  });
});
