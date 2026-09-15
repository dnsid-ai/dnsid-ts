# Public Release Preparation

## Release blockers

### Corrected C2SP cutover and cross-SDK validation

- SDK updates target design commit `5e5c783b0bea773423094a9e7639a487582f489e`
  and method revision `d5a65d06f76eff4db81e50f8767a600d2ca7fc2a`.
- Local tests include exact corrected method vectors, real ES256 replay/fork
  cases, and regenerated lifecycle signatures, checkpoints and bundle proofs.
  Historical fixture bytes remain available and are not rewritten as submissions.
- Regenerate the compliance repository's historical signed matrix fixtures and
  validate all SDK adapters before release; previous matrix counts do not certify
  the corrected contract. The focused hash checker is not a substitute.
- Coordinate log readers, writers, monitors and bundle producers. Inventory
  histories and outstanding exact-byte submissions; preserve conforming and
  terminal histories, retain incompatible historical evidence, and use fresh
  streams when required. Do not run incompatible writers concurrently.

### 1. Configure npmjs publishing

- npmjs is the selected public registry, but the account and trusted publisher are not configured yet.
- None of the packages currently exist on npmjs.
- `.github/workflows/release.yml` still publishes to GitHub Packages.
- Switch the release workflow to npmjs trusted publishing with `--provenance` and `--access public` once the account is available.

### 2. Prepare the repository for public visibility

- The repository is currently private.
- Before changing visibility, scan the entire Git history, issues, PRs, release assets, and workflow logs for credentials and internal information.
- Existing private releases `v0.1.0` through `v0.12.0` and their artifacts will become visible too.

### 3. Finish public-facing documentation

- Add a GitHub repository description; it is currently empty.

### 4. Finish package metadata

- Add explicit npmjs `publishConfig` to every public package manifest when the publishing workflow is switched.
- Confirm the exact package set.
- `key-gcp` is correctly private, but old GitHub artifacts and packages include obsolete names such as `dnsid-provenance` and `dnsid-ts`; do not accidentally expose them.

## Recommended release sequence

1. Configure the npmjs account and trusted publisher.
2. Update npmjs package metadata and the publishing workflow.
3. Run a full-history and public-content audit.
4. Publish the next release to npmjs with provenance.
5. Make the repository public and verify anonymous installation from a clean environment.
