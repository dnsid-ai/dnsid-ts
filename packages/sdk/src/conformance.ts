import {
  DEFAULT_PUBLISH_PROFILE,
  DNSID_DRAFT01_VERSION,
  DNSID_VERSION,
} from '@identity-digital/dnsid-protocol';
import { C2SP_TLOG_PROFILE_VERSION, C2SP_TLOG_SPECIFICATIONS, DNSID_C2SP_METHOD_REVISION } from '@identity-digital/dnsid-log-c2sp-tlog/version';

/** Immutable protocol-facing conformance metadata for this SDK release. */
export interface SDKConformance {
  readonly publishProfile: string;
  readonly verificationProfiles: Readonly<Record<string, string>>;
  readonly specificationStatus: 'internet-draft' | 'rfc';
  readonly logBindings: Readonly<Record<string, string>>;
  readonly knownDeviations: readonly string[];
}

const c2spTlogConformance = [
  `profile=${C2SP_TLOG_PROFILE_VERSION}`,
  ...Object.entries(C2SP_TLOG_SPECIFICATIONS).map(([name, revision]) => `${name}=${revision}`),
  `dnsid-method=${DNSID_C2SP_METHOD_REVISION}`,
].join(';');

/** Exact DNSid profile and log-binding behavior implemented by this SDK release. */
export const SDK_CONFORMANCE: SDKConformance = Object.freeze({
  publishProfile: DEFAULT_PUBLISH_PROFILE,
  verificationProfiles: Object.freeze({
    [DNSID_DRAFT01_VERSION]: DNSID_DRAFT01_VERSION,
    [DNSID_VERSION]: DNSID_DRAFT01_VERSION,
  }),
  specificationStatus: 'internet-draft',
  logBindings: Object.freeze({
    'c2sp-tlog': c2spTlogConformance,
  }),
  knownDeviations: Object.freeze([]),
});
