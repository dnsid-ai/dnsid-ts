/** Exact external specifications implemented by this c2sp-tlog package. */
export const C2SP_TLOG_PROFILE_VERSION = 1 as const;

/** DNSid method contract with signature-independent logical event identity. */
export const DNSID_C2SP_METHOD_REVISION = 'd5a65d06f76eff4db81e50f8767a600d2ca7fc2a' as const;

/** Pinned versions (URL or commit) of each C2SP specification this package implements. */
export const C2SP_TLOG_SPECIFICATIONS = Object.freeze({
  'tlog-checkpoint': 'https://c2sp.org/tlog-checkpoint@v1.0.0',
  'tlog-tiles': 'https://c2sp.org/tlog-tiles@v0.1.0',
  'tlog-proof': 'ab17a74116563005f908b9167e6421cc929a5c2b',
  'tlog-policy': '1896a5aea5559b3203d275d0206d872f59348cf5',
  'tlog-witness': 'https://c2sp.org/tlog-witness@v1.0.0',
  'tlog-cosignature': 'https://c2sp.org/tlog-cosignature@v1.0.1',
  'tlog-mirror': 'd0fe789122c75b903bfc1680b0b8b8dc570f0db3',
  'signed-note': 'https://c2sp.org/signed-note@v1.0.0',
} as const);
