# Rules for docs/ (humans and agents)

Durable rules for anyone touching files under `docs/` in this repo.

## docs/reference/ is generated — never hand-edit

- Every file in `docs/reference/` (including `index.md` and `nav.json`) is generated from TSDoc comments by `npm run docs:md` (TypeDoc → `typedoc-plugin-markdown` → `scripts/build-docs-reference.mjs`).
- To change reference content, edit the TSDoc comments in `packages/*/src/` and regenerate with `npm run docs:md`. Commit the regenerated output — it is a committed directory precisely so reference changes show up as reviewable diffs in normal PRs.
- CI fails if `docs/reference/` is stale (see the docs job in `.github/workflows/compile.yml`): it reruns `docs:md` and diffs. Hand-edits and forgotten regeneration are both caught this way.

## Export contract with the docs site

- `docs/reference/` is exported verbatim to the `dnsid-ai/dnsid-docs` repo (Astro/Starlight) under `src/content/docs/reference/ts/`, where it renders at `https://docs.dnsid.ai/reference/ts/...`.
- `docs/reference/nav.json` is an ordered array of `{ "label", "slug" }` entries imported by the docs site's `nav.mjs`. Page order in `scripts/build-docs-reference.mjs` is the nav order.
- Every page must have YAML frontmatter with a `title` (pattern: `TypeScript: @dnsid-ai/<package>`) and a one-line `description`. The generator emits these; keep the pattern if you change the generator.

## Link rules

- Links to other docs pages must be **absolute** `https://docs.dnsid.ai/...` URLs. The files render both on GitHub and on the docs site, so site-relative slugs would break on GitHub. The generator enforces this for cross-page reference links; follow the same rule in any hand-written docs page.
- Links out to source code or the repo use full GitHub URLs.

## Terminology and content conventions

- "DNSid" (capital DNS, lowercase id) — never "DNSID", "DnsId", or "dnsid" in prose.
- "identity record", "operational key" / "entity key", "agent" — match `packages/protocol` usage.
- Known protocol gaps and sharp edges (DNSSEC state `UNKNOWN` from the system resolver, no DoH, `fl=mtls` requiring a caller-supplied peer certificate) must be stated plainly wherever the feature is mentioned, not hidden.
- Doc comments and docs describe behavior and contracts, not implementation history.
