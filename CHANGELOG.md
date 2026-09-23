
## [0.22.0] - 2026-09-23

### Features

- feat(transport)!: rename allowedUnsafeHosts to privateAddressHosts ([#28](https://github.com/dnsid-ai/dnsid-ts/pull/28))

## [unreleased]

### Features

- [**breaking**] sdk: configuration loading follows SDK design 12 (loaders parse; constructors default). `@dnsid-ai/sdk/node` adds `loadEnvironment`, `loadFile`, `loadCliDirectory`, `mergeLoadedConfig`, `constructIdentityManager`, `createNodeIdentityManagerFromEnvironment`, `createNodeIdentityManagerFromFile`, and `createRegistryClientFromEnvironment`. Removed `configFromEnvironment`, `dnsidEnvironmentVariables`, `registryClientOptionsFromEnvironment`, `LocalKeyProvider.fromEnvironment`, and `keyStorePathFromEnvironment` (with its `DNSID_KEY_STORE_PATH`/`DNSID_KEYSTORE_PATH` aliases).
- [**breaking**] sdk: loaders no longer substitute a `noop:0` log reference or derive `statusUrl` from a registry URL; a local identity needs `DNSID_LOG_REF` and `DNSID_STATUS_URL` (or the persisted CLI values) or construction fails with `ArgumentError`.
- [**breaking**] sdk: `createNodeIdentityManagerFromDnsid()` with no directory reads `~/.dnsid` and no longer consults `DNSID_CONFIG_DIR`. Under `dnsid local run` use `createNodeIdentityManagerFromEnvironment()`, which takes keys from `DNSID_CONFIG_DIR`.
- sdk: new variables `DNSID_PUBLISH_PROFILE`, `DNSID_CAPABILITIES_URL`, `DNSID_LOG_POLICY_URL`, `DNSID_LOG_POLICY_FILE`, `DNSID_LOG_TRUST_PROFILE_FILE`, `DNSID_CONFIG_DIR`; `DNSID_PUBLIC_URL`, `DNSID_AGENT_PORT`, `DNSID_AGENT_NAME` are no longer read by the SDK.
- [**breaking**] transport: rename `allowedUnsafeHosts` to `privateAddressHosts` (no alias) on `TransportConfig`, `HTTPSFetchOptions`, and `SsrfSafeFetchOptions`
- [**breaking**] transport: `.test` names are no longer implicitly allowed to resolve to loopback/private addresses; configure `privateAddressHosts: ['.test']`
- transport: `privateAddressHosts` accepts leading-dot suffix entries (`.test` matches `test` and every name beneath it, label-bounded, case-insensitive); IP-literal URLs are never exempted; entries are validated with `ArgumentError` at construction
- sdk: `loadEnvironment` reads `DNSID_PRIVATE_HOSTS` (comma-separated) into `transport.privateAddressHosts`
- [**breaking**] protocol/registry: `IdentityManager.verifyPublicationEvidence` is no longer part of the published typings (`stripInternal`); `awaitRegistryManagedPublication` takes an `IdentityManager` and `RegistryPublicationVerifier` is no longer exported

## [0.21.0] - 2026-09-22

### Chores

- ci: stage npm releases for 2FA approval instead of direct publish ([#24](https://github.com/dnsid-ai/dnsid-ts/pull/24))
- ci: drop accept-unsigned from readiness caller — npm provenance is live (0.20.2) ([#26](https://github.com/dnsid-ai/dnsid-ts/pull/26))

### Features

- feat: verify against a private registry such as dnsid local ([#27](https://github.com/dnsid-ai/dnsid-ts/pull/27))


## [0.20.2] - 2026-09-22

### Chores

- chore: normalize repository.url to git+https (npm pkg fix) ([#22](https://github.com/dnsid-ai/dnsid-ts/pull/22))


## [0.20.1] - 2026-09-21

### Other

- registry: accept sandbox environment in agent registration ([#18](https://github.com/dnsid-ai/dnsid-ts/pull/18))


## [0.20.0] - 2026-09-21

### Bug Fixes

- fix: rename packages ([#8](https://github.com/dnsid-ai/dnsid-ts/pull/8))

### Chores

- Bump @a2a-js/sdk from 1.0.1 to 1.1.0 ([#1](https://github.com/dnsid-ai/dnsid-ts/pull/1))
- Bump vitest from 4.1.11 to 5.0.0 ([#2](https://github.com/dnsid-ai/dnsid-ts/pull/2))
- Bump undici from 8.9.0 to 8.10.2 ([#3](https://github.com/dnsid-ai/dnsid-ts/pull/3))
- Bump tsx from 4.23.5 to 4.23.13 ([#5](https://github.com/dnsid-ai/dnsid-ts/pull/5))
- ci: sign release PR commits via GitHub API ([#10](https://github.com/dnsid-ai/dnsid-ts/pull/10))
- ci: sign regenerated-docs commits via GitHub API ([#12](https://github.com/dnsid-ai/dnsid-ts/pull/12))
- Chore/public release cleanup ([#15](https://github.com/dnsid-ai/dnsid-ts/pull/15))

### Documentation

- docs: describe registration positively ([#14](https://github.com/dnsid-ai/dnsid-ts/pull/14))

### Features

- feat(transport): allowedUnsafeHosts on fetchJson ([#6](https://github.com/dnsid-ai/dnsid-ts/pull/6))
- Add release-readiness check from dnsid-sdk-compliance ([#9](https://github.com/dnsid-ai/dnsid-ts/pull/9))

### Other

- perf(protocol): run post-sg identity and status work concurrently ([#11](https://github.com/dnsid-ai/dnsid-ts/pull/11))
- registry: default registration environment to production ([#13](https://github.com/dnsid-ai/dnsid-ts/pull/13))
- examples(validate-domain): support the local registry via dnsid local env ([#17](https://github.com/dnsid-ai/dnsid-ts/pull/17))


## [0.19.1] - 2026-09-15

### Chores

- chore: add copyright line to NOTICE header ([#239](https://github.com/dnsid-ai/dnsid-ts/pull/239))

### Other

- build(deps): bump @noble/hashes from 2.2.0 to 2.4.0 ([#240](https://github.com/dnsid-ai/dnsid-ts/pull/240))

### Testing

- test: cover delegated-agent acceptance and observable dnsServer plumbing ([#287](https://github.com/dnsid-ai/dnsid-ts/pull/287))


## [0.19.0] - 2026-09-15

### Bug Fixes

- fix(transport): disable caching for unknown DNS TXT TTLs ([#279](https://github.com/dnsid-ai/dnsid-ts/pull/279))
- fix(core): classify missing DNS identity records as resolution failures ([#281](https://github.com/dnsid-ai/dnsid-ts/pull/281))
- fix(registry)!: require replay keys and expose registration recovery details ([#280](https://github.com/dnsid-ai/dnsid-ts/pull/280))
- fix(sdk): persist local key stores atomically with durable backups ([#278](https://github.com/dnsid-ai/dnsid-ts/pull/278))
- fix: name generated keys by their RFC 7638 thumbprint ([#282](https://github.com/dnsid-ai/dnsid-ts/pull/282))
- fix(transport): never resume TLS sessions on protocol fetches ([#284](https://github.com/dnsid-ai/dnsid-ts/pull/284))

### Features

- feat!: consolidate DnsidConfig and add counterparty acceptance ([#286](https://github.com/dnsid-ai/dnsid-ts/pull/286))

### Other

- build(deps): bump taiki-e/install-action from 2.86.2 to 2.87.8 ([#285](https://github.com/dnsid-ai/dnsid-ts/pull/285))
- build(deps-dev): bump vitest from 4.1.10 to 4.1.11 ([#269](https://github.com/dnsid-ai/dnsid-ts/pull/269))
- build(deps): bump qs from 6.15.3 to 6.16.0 ([#261](https://github.com/dnsid-ai/dnsid-ts/pull/261))
- build(deps): bump jose from 6.2.7 to 6.2.10 ([#244](https://github.com/dnsid-ai/dnsid-ts/pull/244))
- build(deps): bump @aws-sdk/client-kms from 3.1101.0 to 3.1124.0 ([#243](https://github.com/dnsid-ai/dnsid-ts/pull/243))
- build(deps-dev): bump @types/node from 26.1.2 to 26.5.0 ([#242](https://github.com/dnsid-ai/dnsid-ts/pull/242))
- build(deps): bump express-rate-limit from 8.6.0 to 8.7.0 ([#241](https://github.com/dnsid-ai/dnsid-ts/pull/241))


## [0.18.0] - 2026-09-09

### Bug Fixes

- fix(registry): harden public key boundaries ([#264](https://github.com/dnsid-ai/dnsid-ts/pull/264))
- fix: align verification and C2SP design contracts ([#267](https://github.com/dnsid-ai/dnsid-ts/pull/267))


## [0.17.0] - 2026-09-03

### Bug Fixes

- fix: exact 500 errors ([#256](https://github.com/dnsid-ai/dnsid-ts/pull/256))
- fix: return logged state evidence ([#257](https://github.com/dnsid-ai/dnsid-ts/pull/257))
- fix(c2sp): return evidence for migrated histories ([#260](https://github.com/dnsid-ai/dnsid-ts/pull/260))
- fix(registry): align client with live API ([#262](https://github.com/dnsid-ai/dnsid-ts/pull/262))

### Features

- Add security baseline config ([#252](https://github.com/dnsid-ai/dnsid-ts/pull/252))
- feat: add C2SP tlog trust profiles ([#253](https://github.com/dnsid-ai/dnsid-ts/pull/253))
- feat: support direct C2SP bundle verifier keys ([#259](https://github.com/dnsid-ai/dnsid-ts/pull/259))
- feat: add production stream bundle trust profile ([#263](https://github.com/dnsid-ai/dnsid-ts/pull/263))

### Other

- perf: coalesce same-domain verification ([#250](https://github.com/dnsid-ai/dnsid-ts/pull/250))
- perf: prefer C2SP stream bundles for verification ([#255](https://github.com/dnsid-ai/dnsid-ts/pull/255))


## [0.16.0] - 2026-08-24

### Bug Fixes

- fix(deps): resolve Dependabot alerts for nanoid and esbuild ([#235](https://github.com/dnsid-ai/dnsid-ts/pull/235))
- fix(examples): point validate-domain at a live sandbox domain ([#236](https://github.com/dnsid-ai/dnsid-ts/pull/236))
- fix: trust testnet log policy URL from environment ([#248](https://github.com/dnsid-ai/dnsid-ts/pull/248))
- fix governance validation and logchk support ([#249](https://github.com/dnsid-ai/dnsid-ts/pull/249))

### Chores

- ci: call the compliance suite from its standalone repo ([#237](https://github.com/dnsid-ai/dnsid-ts/pull/237))
- chore: point CODEOWNERS at the sdk-maintainers team ([#238](https://github.com/dnsid-ai/dnsid-ts/pull/238))

### Documentation

- Document SDK security operations ([#228](https://github.com/dnsid-ai/dnsid-ts/pull/228))

### Features

- feat: add c2sp-tlog verification registry ([#246](https://github.com/dnsid-ai/dnsid-ts/pull/246))

### Other

- build(deps): bump taiki-e/install-action from 2.85.2 to 2.85.7 ([#233](https://github.com/dnsid-ai/dnsid-ts/pull/233))
- build(deps): bump @aws-sdk/client-kms from 3.1096.0 to 3.1101.0 ([#232](https://github.com/dnsid-ai/dnsid-ts/pull/232))
- build(deps-dev): bump tsx from 4.23.1 to 4.23.5 ([#231](https://github.com/dnsid-ai/dnsid-ts/pull/231))
- build(deps): bump jose from 6.2.4 to 6.2.7 ([#230](https://github.com/dnsid-ai/dnsid-ts/pull/230))
- build(deps-dev): bump @types/node from 26.1.1 to 26.1.2 ([#229](https://github.com/dnsid-ai/dnsid-ts/pull/229))
- build(deps): bump taiki-e/install-action from 2.85.7 to 2.86.2 ([#247](https://github.com/dnsid-ai/dnsid-ts/pull/247))


## [0.15.0] - 2026-08-07

### Chores

- ci: auto-regenerate reference docs on PR branches ([#223](https://github.com/dnsid-ai/dnsid-ts/pull/223))
- chore: add NOTICE ([#225](https://github.com/dnsid-ai/dnsid-ts/pull/225))

### Features

- feat!: add revoke ops ([#227](https://github.com/dnsid-ai/dnsid-ts/pull/227))


## [0.14.0] - 2026-08-07

### Bug Fixes

- fix: align HTTP signatures with corrected profile ([#218](https://github.com/dnsid-ai/dnsid-ts/pull/218))
- fix: a2a example ([#221](https://github.com/dnsid-ai/dnsid-ts/pull/221))

### Chores

- chore: mark root jose dependency as development-only ([#220](https://github.com/dnsid-ai/dnsid-ts/pull/220))

### Features

- feat: add dashboard to show a2a process ([#222](https://github.com/dnsid-ai/dnsid-ts/pull/222))

### Other

- build(deps): bump brace-expansion from 5.0.8 to 5.0.9 ([#211](https://github.com/dnsid-ai/dnsid-ts/pull/211))
- build(deps): bump postcss from 8.5.20 to 8.5.25 ([#210](https://github.com/dnsid-ai/dnsid-ts/pull/210))
- build(deps): bump taiki-e/install-action from 2.84.0 to 2.85.2 ([#204](https://github.com/dnsid-ai/dnsid-ts/pull/204))
- build(deps): bump jose from 6.2.3 to 6.2.4 ([#202](https://github.com/dnsid-ai/dnsid-ts/pull/202))
- build(deps): bump @a2a-js/sdk from 1.0.0-beta.0 to 1.0.1 ([#201](https://github.com/dnsid-ai/dnsid-ts/pull/201))
- build(deps): bump @aws-sdk/client-kms from 3.1092.0 to 3.1096.0 ([#200](https://github.com/dnsid-ai/dnsid-ts/pull/200))


## [0.13.0] - 2026-08-04

### Bug Fixes

- fix: load authoritative publication configuration ([#217](https://github.com/dnsid-ai/dnsid-ts/pull/217))

### Features

- feat(sdk)!: remove dnsid-testts binary ([#216](https://github.com/dnsid-ai/dnsid-ts/pull/216))
- feat: prepare for public release ([#207](https://github.com/dnsid-ai/dnsid-ts/pull/207))

### Other

- build(deps): bump undici from 8.7.0 to 8.9.0 ([#203](https://github.com/dnsid-ai/dnsid-ts/pull/203))
- build(deps): bump ip-address from 10.2.0 to 10.4.0 ([#214](https://github.com/dnsid-ai/dnsid-ts/pull/214))


## [0.12.0] - 2026-08-03

### Features

- feat: parity registration verifier ([#208](https://github.com/dnsid-ai/dnsid-ts/pull/208))


## [0.11.1] - 2026-08-03

### Bug Fixes

- fix: make package browser safe ([#206](https://github.com/dnsid-ai/dnsid-ts/pull/206))

### Chores

- chore: harden public release surface ([#199](https://github.com/dnsid-ai/dnsid-ts/pull/199))


## [0.11.0] - 2026-07-31

### Bug Fixes

- fix: align c2sp lifecycle semantics ([#196](https://github.com/dnsid-ai/dnsid-ts/pull/196))
- fix: add local key provider support for es256 ([#197](https://github.com/dnsid-ai/dnsid-ts/pull/197))
- Fix/secure managed issuance ([#198](https://github.com/dnsid-ai/dnsid-ts/pull/198))

### Documentation

- docs: harmonize reference nav with the Go/Python naming and nest kind pages ([#193](https://github.com/dnsid-ai/dnsid-ts/pull/193))

### Features

- feat: expose SDK conformance metadata ([#195](https://github.com/dnsid-ai/dnsid-ts/pull/195))

### Other

- build(deps): bump taiki-e/install-action from 2.83.2 to 2.84.0 ([#181](https://github.com/dnsid-ai/dnsid-ts/pull/181))
- build(deps): bump actions/checkout from 7.0.0 to 7.0.1 ([#180](https://github.com/dnsid-ai/dnsid-ts/pull/180))
- build(deps): bump @aws-sdk/client-kms from 3.1086.0 to 3.1092.0 ([#179](https://github.com/dnsid-ai/dnsid-ts/pull/179))
- build(deps): bump structured-headers from 2.0.2 to 2.0.3 ([#178](https://github.com/dnsid-ai/dnsid-ts/pull/178))
- build(deps): bump express-rate-limit from 8.5.2 to 8.6.0 ([#177](https://github.com/dnsid-ai/dnsid-ts/pull/177))
- build(deps-dev): bump @types/node from 25.9.4 to 26.1.1 ([#161](https://github.com/dnsid-ai/dnsid-ts/pull/161))


## [0.10.0] - 2026-07-29

### Bug Fixes

- fix!: align DNSSEC verification policy ([#189](https://github.com/dnsid-ai/dnsid-ts/pull/189))
- fix: bugs identified during compliance testing ([#191](https://github.com/dnsid-ai/dnsid-ts/pull/191))

### Chores

- ci: grant compliance workflow permissions ([#190](https://github.com/dnsid-ai/dnsid-ts/pull/190))

### Documentation

- docs: TSDoc coverage, TypeDoc reference pipeline, READMEs, and examples ([#187](https://github.com/dnsid-ai/dnsid-ts/pull/187))
- docs: split oversized reference pages by member kind ([#192](https://github.com/dnsid-ai/dnsid-ts/pull/192))


## [0.9.0] - 2026-07-28

### Features

- feat: enforce strict lifecycle state machine ([#185](https://github.com/dnsid-ai/dnsid-ts/pull/185))


## [0.8.1] - 2026-07-27

### Bug Fixes

- fix: address outstanding design issues ([#183](https://github.com/dnsid-ai/dnsid-ts/pull/183))


## [0.8.0] - 2026-07-27

### Bug Fixes

- fix: improve verification and lifecycle semantics ([#166](https://github.com/dnsid-ai/dnsid-ts/pull/166))
- fix: align registry lifecycle behavior ([#168](https://github.com/dnsid-ai/dnsid-ts/pull/168))
- fix: various to support tweaked design doc ([#169](https://github.com/dnsid-ai/dnsid-ts/pull/169))
- fix: preserve pre-v1 breaking version bumps ([#182](https://github.com/dnsid-ai/dnsid-ts/pull/182))

### Features

- feat: align to ddoc versioning scheme ([#170](https://github.com/dnsid-ai/dnsid-ts/pull/170))
- feat!: complete SDK design compliance ([#175](https://github.com/dnsid-ai/dnsid-ts/pull/175))

### Other

- build(deps): bump undici from 8.6.0 to 8.7.0 ([#145](https://github.com/dnsid-ai/dnsid-ts/pull/145))
- build(deps-dev): bump tsx from 4.23.0 to 4.23.1 ([#158](https://github.com/dnsid-ai/dnsid-ts/pull/158))
- build(deps-dev): bump vitest from 4.1.9 to 4.1.10 ([#159](https://github.com/dnsid-ai/dnsid-ts/pull/159))
- build(deps): bump @aws-sdk/client-kms from 3.1079.0 to 3.1086.0 ([#160](https://github.com/dnsid-ai/dnsid-ts/pull/160))
- build(deps): bump taiki-e/install-action from 2.82.9 to 2.83.2 ([#162](https://github.com/dnsid-ai/dnsid-ts/pull/162))
- build(deps): bump actions/setup-node from 6.4.0 to 7.0.0 ([#163](https://github.com/dnsid-ai/dnsid-ts/pull/163))


## [0.7.0] - 2026-07-21

### Bug Fixes

- fix: fixes issues with version, sg, and ek/gi validation ([#148](https://github.com/dnsid-ai/dnsid-ts/pull/148))
- fix: several fixes to improve key handling and spec compliance ([#149](https://github.com/dnsid-ai/dnsid-ts/pull/149))
- fix(core): reject malformed lr in DnsIdTxtRecord.validate() ([#151](https://github.com/dnsid-ai/dnsid-ts/pull/151))
- fix: align more with registry and spec ([#150](https://github.com/dnsid-ai/dnsid-ts/pull/150))
- fix: validate() rejects malformed lr values locally ([#140](https://github.com/dnsid-ai/dnsid-ts/pull/140))
- fix: expect line delimited instead of json policy ([#153](https://github.com/dnsid-ai/dnsid-ts/pull/153))
- fix: correct example readme ([#154](https://github.com/dnsid-ai/dnsid-ts/pull/154))
- fix: remove use owner ([#155](https://github.com/dnsid-ai/dnsid-ts/pull/155))
- fix: security fixes for c2sp signing pre checks ([#156](https://github.com/dnsid-ai/dnsid-ts/pull/156))
- fix: mTLS and cache fixes to match design doc ([#157](https://github.com/dnsid-ai/dnsid-ts/pull/157))
- fix: address p0 sdk protocol and sec gaps ([#164](https://github.com/dnsid-ai/dnsid-ts/pull/164))
- fix: improve http signature handling ([#165](https://github.com/dnsid-ai/dnsid-ts/pull/165))

### Chores

- chore: add security policy and ops docs ([#152](https://github.com/dnsid-ai/dnsid-ts/pull/152))

### Documentation

- docs: document signed commit setup ([#135](https://github.com/dnsid-ai/dnsid-ts/pull/135))
- docs(security): publish SECURITY.md and add CodeQL workflow ([#128](https://github.com/dnsid-ai/dnsid-ts/pull/128))

### Features

- feat(core): enforce pairwise ek/ku RFC 7638 thumbprint distinctness ([#105](https://github.com/dnsid-ai/dnsid-ts/pull/105))
- feat: implement ek≠ku JWK thumbprint distinctness check (#105) ([#117](https://github.com/dnsid-ai/dnsid-ts/pull/117))
- feat: add c2sp-tlog support ([#109](https://github.com/dnsid-ai/dnsid-ts/pull/109))
- feat: add a2a example back ([#103](https://github.com/dnsid-ai/dnsid-ts/pull/103))

### Other

- build(deps): bump @aws-sdk/client-kms from 3.1068.0 to 3.1079.0 ([#142](https://github.com/dnsid-ai/dnsid-ts/pull/142))
- build(deps): bump uuid from 14.0.0 to 14.0.1 ([#144](https://github.com/dnsid-ai/dnsid-ts/pull/144))
- build(deps-dev): bump tsx from 4.22.4 to 4.23.0 ([#146](https://github.com/dnsid-ai/dnsid-ts/pull/146))
- build(deps): bump taiki-e/install-action from 2.82.6 to 2.82.9 ([#147](https://github.com/dnsid-ai/dnsid-ts/pull/147))

### Testing

- test: cover dnsid-draft01 version dispatch and EdDSA sg verification (closes #64) ([#141](https://github.com/dnsid-ai/dnsid-ts/pull/141))


## [0.6.0] - 2026-07-09

### Bug Fixes

- fix: verify sg as detached compact JWS against ek key (draft-01) ([#111](https://github.com/dnsid-ai/dnsid-ts/pull/111))
- fix(core): reject cross-profile protocol tags ek/oi as invalid (#116) ([#120](https://github.com/dnsid-ai/dnsid-ts/pull/120))
- fix(core): reject FQDN labels with leading/trailing hyphen (#114) ([#121](https://github.com/dnsid-ai/dnsid-ts/pull/121))

### Features

- feat: implement fl=mtls peer-certificate validation ([#129](https://github.com/dnsid-ai/dnsid-ts/pull/129))
- feat(core): dual-signed ISSUANCE model + concrete bilateral binding check (#106) ([#124](https://github.com/dnsid-ai/dnsid-ts/pull/124))


## [0.5.0] - 2026-07-09

### Bug Fixes

- fix(core): emit v= first in canonical() for cross-SDK sg= verification ([#115](https://github.com/dnsid-ai/dnsid-ts/pull/115))
- fix(core): map UTS46 label separators to '.' in normalizeFQDN (#113) ([#123](https://github.com/dnsid-ai/dnsid-ts/pull/123))

### Features

- feat: dnsid1 support ([#97](https://github.com/dnsid-ai/dnsid-ts/pull/97))

### Other

- build(deps): bump undici from 8.3.0 to 8.6.0 ([#84](https://github.com/dnsid-ai/dnsid-ts/pull/84))
- build(deps): bump taiki-e/install-action from 2.81.8 to 2.82.6 ([#101](https://github.com/dnsid-ai/dnsid-ts/pull/101))
- build(deps-dev): bump @types/node from 25.9.1 to 26.0.1 ([#99](https://github.com/dnsid-ai/dnsid-ts/pull/99))
- build(deps-dev): bump vitest from 4.1.8 to 4.1.9 ([#87](https://github.com/dnsid-ai/dnsid-ts/pull/87))
- build(deps-dev): bump vite from 8.0.12 to 8.1.3 ([#77](https://github.com/dnsid-ai/dnsid-ts/pull/77))
- build(deps): bump actions/checkout from 6.0.3 to 7.0.0 ([#95](https://github.com/dnsid-ai/dnsid-ts/pull/95))
- Type log-derived lifecycle state as AgentStatusState (#108) ([#110](https://github.com/dnsid-ai/dnsid-ts/pull/110))


## [0.4.0] - 2026-06-26

### Bug Fixes

- fix: dont trust pub key will match, rederive it ([#92](https://github.com/dnsid-ai/dnsid-ts/pull/92))

### Features

- feat: allow init from config created by cli tool ([#89](https://github.com/dnsid-ai/dnsid-ts/pull/89))
- feat: Web bot auth support ([#93](https://github.com/dnsid-ai/dnsid-ts/pull/93))


## [0.3.0] - 2026-06-18

### Bug Fixes

- fix: emit v=dnsid-draft-01-20260504 in TXT records ([#82](https://github.com/dnsid-ai/dnsid-ts/pull/82))

### Features

- Add private DNSid evaluation license ([#72](https://github.com/dnsid-ai/dnsid-ts/pull/72))
- feat: add oidc feature ([#76](https://github.com/dnsid-ai/dnsid-ts/pull/76))
- feat: local key example ([#79](https://github.com/dnsid-ai/dnsid-ts/pull/79))
- feat: add dnsid-testts CLI binary to SDK ([#69](https://github.com/dnsid-ai/dnsid-ts/pull/69))
- Add DNSid OIDC token minting API ([#78](https://github.com/dnsid-ai/dnsid-ts/pull/78))
- feat: default server/base URL to https://api.dnsid.ai ([#83](https://github.com/dnsid-ai/dnsid-ts/pull/83))

### Other

- AWS KMS Implementation ([#80](https://github.com/dnsid-ai/dnsid-ts/pull/80))


## [0.2.2] - 2026-06-12

### Bug Fixes

- fix: align TypeScript SDK with deployed DNSid TXT version ([#66](https://github.com/dnsid-ai/dnsid-ts/pull/66))
- fix: Add simple verify domain example ([#71](https://github.com/dnsid-ai/dnsid-ts/pull/71))


## [0.2.1] - 2026-06-11

### Bug Fixes

- fix: make wire behavior conformant ([#54](https://github.com/dnsid-ai/dnsid-ts/pull/54))
- fix: improve tag handling and tests ([#55](https://github.com/dnsid-ai/dnsid-ts/pull/55))
- fix casing ([#56](https://github.com/dnsid-ai/dnsid-ts/pull/56))
- fix: improve transport security checks, add tests ([#57](https://github.com/dnsid-ai/dnsid-ts/pull/57))
- fix: adding retry and cache helpers ([#58](https://github.com/dnsid-ai/dnsid-ts/pull/58))
- fix: update alg handling ([#59](https://github.com/dnsid-ai/dnsid-ts/pull/59))
- fix: add capabilities url, add special transport for testnet ([#60](https://github.com/dnsid-ai/dnsid-ts/pull/60))
- fix: send user agent from node transport ([#65](https://github.com/dnsid-ai/dnsid-ts/pull/65))

### Chores

- ci: pin workflow actions to commit SHAs ([#49](https://github.com/dnsid-ai/dnsid-ts/pull/49))

### Features

- feat: add TypeScript SDK walkthrough ([#62](https://github.com/dnsid-ai/dnsid-ts/pull/62))

### Other

- build(deps-dev): bump tsx from 4.22.3 to 4.22.4 ([#44](https://github.com/dnsid-ai/dnsid-ts/pull/44))
- build(deps-dev): bump vitest from 4.1.7 to 4.1.8 ([#45](https://github.com/dnsid-ai/dnsid-ts/pull/45))
- build(deps): bump actions/checkout from 4.3.1 to 6.0.3 ([#51](https://github.com/dnsid-ai/dnsid-ts/pull/51))
- build(deps): bump actions/setup-node from 4.4.0 to 6.4.0 ([#52](https://github.com/dnsid-ai/dnsid-ts/pull/52))


## [0.2.0] - 2026-06-04

### Bug Fixes

- fix: make example work ([#42](https://github.com/dnsid-ai/dnsid-ts/pull/42))

### Chores

- chore: add todo, fix scope in release ([#43](https://github.com/dnsid-ai/dnsid-ts/pull/43))

### Features

- feat(refactor): refactor and migrate packages ([#40](https://github.com/dnsid-ai/dnsid-ts/pull/40))


## [0.1.1] - 2026-06-02

### Bug Fixes

- fix: patch deviations from design  ([#36](https://github.com/dnsid-ai/dnsid-ts/pull/36))

### Chores

- chore: upgrade uuid to v14 and patch qs DoS vulnerability ([#35](https://github.com/dnsid-ai/dnsid-ts/pull/35))

### Other

- examples: make the a2a example work and add doc for testnet ([#24](https://github.com/dnsid-ai/dnsid-ts/pull/24))
- build(deps-dev): bump @types/node from 25.6.0 to 25.9.0 ([#32](https://github.com/dnsid-ai/dnsid-ts/pull/32))
- build(deps): bump undici from 7.25.0 to 8.3.0 ([#34](https://github.com/dnsid-ai/dnsid-ts/pull/34))
- build(deps-dev): bump tsx from 4.21.0 to 4.22.3 ([#33](https://github.com/dnsid-ai/dnsid-ts/pull/33))
- build(deps-dev): bump vitest from 4.1.5 to 4.1.7 ([#38](https://github.com/dnsid-ai/dnsid-ts/pull/38))
- build(deps-dev): bump @types/node from 25.9.0 to 25.9.1 ([#39](https://github.com/dnsid-ai/dnsid-ts/pull/39))


## [0.1.0] - 2026-05-20

### Bug Fixes

- fix(errors): Add fqdn from claims to errors during verification ([#2](https://github.com/dnsid-ai/dnsid-ts/pull/2))
- fix(config): ensure default token lifetime is not greater than max token lifetime ([#3](https://github.com/dnsid-ai/dnsid-ts/pull/3))
- fix(verify): match verification status casing ([#4](https://github.com/dnsid-ai/dnsid-ts/pull/4))
- fix(verify): match go sdk behavior for key selection ([#5](https://github.com/dnsid-ai/dnsid-ts/pull/5))
- fix(errors): surface signature error instead of network error for rotation case ([#6](https://github.com/dnsid-ai/dnsid-ts/pull/6))
- fix(lifecycle): handle request cancelling better ([#7](https://github.com/dnsid-ai/dnsid-ts/pull/7))
- fix: dont leak errors ([#18](https://github.com/dnsid-ai/dnsid-ts/pull/18))
- fix: update content sig stuff to match spec ([#20](https://github.com/dnsid-ai/dnsid-ts/pull/20))

### Chores

- update readme with changes ([#8](https://github.com/dnsid-ai/dnsid-ts/pull/8))
- sec: dont suggest brand new versions of packages ([#19](https://github.com/dnsid-ai/dnsid-ts/pull/19))

### Features

- feat(sign): refactor key provider to signer pattern ([#1](https://github.com/dnsid-ai/dnsid-ts/pull/1))
- add arch file, cleanup ([#9](https://github.com/dnsid-ai/dnsid-ts/pull/9))
- Add versioning/release workflows to dnsid-ts (mirror dnsid-go) ([#25](https://github.com/dnsid-ai/dnsid-ts/pull/25))

### Other

- create a better a2a example ([#10](https://github.com/dnsid-ai/dnsid-ts/pull/10))
- rewrite ([#11](https://github.com/dnsid-ai/dnsid-ts/pull/11))
- Enable Dependabot updates and add a baseline TypeScript compile CI workflow ([#13](https://github.com/dnsid-ai/dnsid-ts/pull/13))
- Initial implementation based on design doc ([#12](https://github.com/dnsid-ai/dnsid-ts/pull/12))
- build(deps-dev): bump @types/node from 22.19.17 to 25.6.0 ([#23](https://github.com/dnsid-ai/dnsid-ts/pull/23))
- build(deps-dev): bump vitest from 2.1.9 to 4.1.5 ([#22](https://github.com/dnsid-ai/dnsid-ts/pull/22))

# Changelog
