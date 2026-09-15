// Post-processes typedoc-plugin-markdown output (.typedoc-md/) into the
// committed, docs-site-ready reference under docs/reference/.
//
// - One page per published package (the `@identity-digital/dnsid/node` subpath
//   gets its own page so anchors never collide with the root export's).
// - Oversized packages list the member kinds to extract in `splitKinds`: those
//   kinds (e.g. Classes, Interfaces) move to their own pages and the package
//   page keeps the prose, the remaining kinds, and a table of contents for the
//   extracted ones. typedoc's explicit HTML anchors (useHTMLAnchors) move with
//   their blocks, and all links — including same-page #fragment links — are
//   re-routed to whichever page the target anchor landed on.
// - Nav labels follow the reader-topic naming shared with the Go and Python
//   references ("Profile: JOSE", "Registry", ...), and extracted kind pages
//   nest under their package entry in nav.json ({label, items: [...]}).
// - Starlight YAML frontmatter (title + description) on every page.
// - Cross-page links become absolute https://docs.dnsid.ai/... URLs so the
//   files render correctly both on GitHub and on the docs site.
//
// Run via `npm run docs:md`. Never hand-edit docs/reference/ — regenerate.

import { mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { posix as path } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const srcRoot = path.join(repoRoot, '.typedoc-md');
const outRoot = path.join(repoRoot, 'docs', 'reference');
const SITE_BASE = 'https://docs.dnsid.ai/reference/ts';

// Member-kind sections emitted by typedoc-plugin-markdown.
const KIND_SECTIONS = ['Enumerations', 'Classes', 'Interfaces', 'Type Aliases', 'Variables', 'Functions'];

// Ordered: order here is the docs-site nav order (mirrors the Python and Go
// reference nav). `label` is the nav label; `splitKinds` lists member kinds
// that get their own nested pages.
const PAGES = [
  {
    slug: 'dnsid',
    label: 'Core SDK',
    pkg: '@identity-digital/dnsid',
    src: 'index/@identity-digital/dnsid/index.md',
    prepend: '@identity-digital/dnsid/README.md',
    splitKinds: ['Classes', 'Interfaces'],
    description: 'Runtime-neutral SDK entry point; inject DNS, fetch, and key-provider implementations.',
  },
  {
    slug: 'dnsid-node',
    label: 'Node runtime',
    pkg: '@identity-digital/dnsid/node',
    src: '@identity-digital/dnsid/node.md',
    description: 'Node.js conveniences: local file-backed keys, env config, Node identity-manager factories.',
  },
  {
    slug: 'dnsid-protocol',
    label: 'Protocol core',
    pkg: '@identity-digital/dnsid-protocol',
    src: '@identity-digital/dnsid-protocol.md',
    splitKinds: ['Classes', 'Interfaces'],
    description: 'Protocol core: TXT/JWKS parsing, validation, identity verification, runtime interfaces.',
  },
  {
    slug: 'dnsid-transport',
    label: 'Transport',
    pkg: '@identity-digital/dnsid-transport',
    src: '@identity-digital/dnsid-transport.md',
    description: 'Node-only DNS/HTTPS transport built on Node built-ins and undici.',
  },
  {
    slug: 'dnsid-jose',
    label: 'Profile: JOSE',
    pkg: '@identity-digital/dnsid-jose',
    src: '@identity-digital/dnsid-jose.md',
    description: 'JOSE profile helpers for JWT and JWS workflows.',
  },
  {
    slug: 'dnsid-http-signatures',
    label: 'Profile: HTTP signatures',
    pkg: '@identity-digital/dnsid-http-signatures',
    src: '@identity-digital/dnsid-http-signatures.md',
    description: 'RFC 9421 HTTP Message Signatures profile: sign and verify HTTP messages.',
  },
  {
    slug: 'dnsid-web-bot-auth',
    label: 'Profile: Web Bot Auth',
    pkg: '@identity-digital/dnsid-web-bot-auth',
    src: '@identity-digital/dnsid-web-bot-auth.md',
    description: 'Web Bot Auth profile: signed bot requests and the key-directory endpoint.',
  },
  {
    slug: 'dnsid-oidc',
    label: 'Profile: OIDC',
    pkg: '@identity-digital/dnsid-oidc',
    src: '@identity-digital/dnsid-oidc.md',
    description: 'OIDC federation profile: token minting and verification (server-side).',
  },
  {
    slug: 'dnsid-key-aws',
    label: 'Key providers: AWS KMS',
    pkg: '@identity-digital/dnsid-key-aws',
    src: '@identity-digital/dnsid-key-aws.md',
    description: 'AWS KMS-backed key provider.',
  },
  {
    slug: 'dnsid-registry',
    label: 'Registry',
    pkg: '@identity-digital/dnsid-registry',
    src: '@identity-digital/dnsid-registry.md',
    description: 'Registry client and TXT publishing helpers.',
  },
  {
    slug: 'dnsid-log-c2sp-tlog',
    label: 'Transparency log',
    pkg: '@identity-digital/dnsid-log-c2sp-tlog',
    src: '@identity-digital/dnsid-log-c2sp-tlog.md',
    splitKinds: ['Classes', 'Interfaces', 'Functions'],
    description: 'C2SP tlog-backed lifecycle log reader, writer, and verifier.',
  },
];

// Generated files that have no page of their own; links into them are
// redirected to the canonical package page.
const ALIASES = {
  'index/@identity-digital/dnsid/namespaces/jose.md': 'dnsid-jose',
  'index/@identity-digital/dnsid/namespaces/httpSignatures.md': 'dnsid-http-signatures',
  'index/@identity-digital/dnsid/namespaces/webBotAuth.md': 'dnsid-web-bot-auth',
  'index/@identity-digital/dnsid/namespaces/registry.md': 'dnsid-registry',
  '@identity-digital/dnsid/README.md': 'dnsid',
  'README.md': '',
};

const fileToSlug = new Map(Object.entries(ALIASES));
for (const page of PAGES) fileToSlug.set(page.src, page.slug);

function pageUrl(slug) {
  return slug === '' ? `${SITE_BASE}/` : `${SITE_BASE}/${slug}/`;
}

const kindSlug = (kind) => kind.toLowerCase().replace(/ /g, '-');

// anchorRoute: package slug -> (anchor id -> final page slug). Filled while
// partitioning split pages; consulted when rewriting every link.
const anchorRoute = new Map();

function recordAnchors(text, pkgSlug, finalSlug) {
  let route = anchorRoute.get(pkgSlug);
  if (!route) anchorRoute.set(pkgSlug, (route = new Map()));
  for (const m of text.matchAll(/<a id="([^"]+)"/g)) route.set(m[1], finalSlug);
}

/**
 * Partitions a package body: member-kind sections named in `extract` move to
 * kind pages; everything else (prose, non-kind sections, remaining kinds)
 * stays on the package page. Returns { main, kinds } where `kinds` maps kind
 * name -> { body, members: [{name, anchor}] }.
 */
function partition(body, extract) {
  const lines = body.split('\n');
  const main = [];
  const kinds = new Map();
  let sink = main;
  let currentKind = null;
  let pendingAnchor = null;
  for (const line of lines) {
    const h2 = line.match(/^## (.+?)\s*$/);
    if (h2) {
      pendingAnchor = null;
      if (extract.includes(h2[1])) {
        currentKind = { body: [], members: [] };
        kinds.set(h2[1], currentKind);
        sink = currentKind.body;
        continue; // kind heading re-emitted on the kind page
      }
      sink = main;
      currentKind = null;
    }
    if (currentKind) {
      const anchor = line.match(/<a id="([^"]+)"/);
      if (anchor) pendingAnchor = anchor[1];
      const h3 = line.match(/^### (.+?)\s*$/);
      if (h3) {
        currentKind.members.push({ name: h3[1], anchor: pendingAnchor });
        pendingAnchor = null;
      }
    }
    sink.push(line);
  }
  return { main: main.join('\n'), kinds };
}

/** Rewrites markdown link targets; `fromDir` is the source file's directory. */
function rewriteLinks(markdown, fromDir, ownSlug, ownPkgSlug) {
  return markdown.replace(/\]\(([^()\s]+)\)/g, (match, target) => {
    if (/^(https?:|mailto:)/.test(target)) return match;
    if (target.startsWith('#')) {
      // Same-package fragment link; the anchor may have moved to a kind page.
      const frag = target.slice(1);
      const dest = anchorRoute.get(ownPkgSlug)?.get(frag);
      if (dest === undefined || dest === ownSlug) return match;
      return `](${pageUrl(dest)}#${frag})`;
    }
    const [file, fragment] = target.split('#');
    const resolved = path.normalize(path.join(fromDir, file));
    const slug = fileToSlug.get(resolved);
    if (slug === undefined) return match; // unknown target; leave untouched
    const frag = fragment ? fragment.toLowerCase() : '';
    const dest = frag ? (anchorRoute.get(slug)?.get(frag) ?? slug) : slug;
    if (dest === ownSlug) return `](${frag ? `#${frag}` : '#'})`;
    return `](${pageUrl(dest)}${frag ? `#${frag}` : ''})`;
  });
}

function stripLeadingH1(markdown) {
  return markdown.replace(/^\s*# [^\n]*\n/, '');
}

function frontmatter(title, description) {
  return `---\ntitle: "${title}"\ndescription: "${description}"\n---\n\n`;
}

const GENERATED_NOTE =
  '<!-- Generated by `npm run docs:md` from TSDoc comments. Do not edit by hand; see docs/AGENTS.md. -->\n\n';

if (!existsSync(srcRoot)) {
  console.error(`missing ${srcRoot} — run \`typedoc --options typedoc.markdown.json\` first`);
  process.exit(1);
}

rmSync(outRoot, { recursive: true, force: true });
mkdirSync(outRoot, { recursive: true });

// Pass 1: load bodies; partition split packages and build the anchor routes.
const prepared = [];
for (const page of PAGES) {
  const srcPath = path.join(srcRoot, page.src);
  if (!existsSync(srcPath)) {
    console.error(`expected typedoc output missing: ${page.src}`);
    process.exit(1);
  }
  const body = stripLeadingH1(readFileSync(srcPath, 'utf8'));
  // Kept separate from the body until links are rewritten: its relative
  // links resolve against the prepend file's own directory, not the src's.
  const prependBody = page.prepend
    ? stripLeadingH1(readFileSync(path.join(srcRoot, page.prepend), 'utf8')).trim()
    : '';
  recordAnchors(prependBody, page.slug, page.slug);
  if (!page.splitKinds) {
    recordAnchors(body, page.slug, page.slug);
    prepared.push({ page, body, prependBody });
    continue;
  }
  const { main, kinds } = partition(body, page.splitKinds);
  recordAnchors(main, page.slug, page.slug);
  for (const [kind, part] of kinds) {
    recordAnchors(part.body.join('\n'), page.slug, `${page.slug}-${kindSlug(kind)}`);
  }
  prepared.push({ page, body: main, prependBody, kinds });
}

// Pass 2: rewrite links and emit pages + nav entries.
const nav = [{ label: 'Overview', slug: 'reference/ts' }];
for (const { page, body, prependBody, kinds } of prepared) {
  const title = `TypeScript: ${page.pkg}`;
  const intro = prependBody
    ? rewriteLinks(prependBody, path.dirname(page.prepend), page.slug, page.slug) + '\n\n'
    : '';
  if (!kinds || kinds.size === 0) {
    const out =
      frontmatter(title, page.description) +
      GENERATED_NOTE +
      (intro + rewriteLinks(body, path.dirname(page.src), page.slug, page.slug)).trim() +
      '\n';
    writeFileSync(path.join(outRoot, `${page.slug}.md`), out);
    nav.push({ label: page.label, slug: `reference/ts/${page.slug}` });
    continue;
  }

  // Split package: package page = prose + remaining kinds + per-kind TOCs.
  const tocSections = [];
  for (const [kind, part] of kinds) {
    const sub = `${page.slug}-${kindSlug(kind)}`;
    tocSections.push(
      `## ${kind}`,
      '',
      `Documented on [${page.label}: ${kind.toLowerCase()}](${pageUrl(sub)}):`,
      '',
      ...part.members.map((m) => `- [${m.name}](${pageUrl(sub)}${m.anchor ? `#${m.anchor}` : ''})`),
      '',
    );
  }
  const mainOut =
    frontmatter(title, page.description) +
    GENERATED_NOTE +
    (intro + rewriteLinks(body, path.dirname(page.src), page.slug, page.slug)).trim() +
    '\n\n' +
    tocSections.join('\n');
  writeFileSync(path.join(outRoot, `${page.slug}.md`), mainOut.trim() + '\n');

  const navChildren = [{ label: 'Overview', slug: `reference/ts/${page.slug}` }];
  for (const [kind, part] of kinds) {
    const sub = `${page.slug}-${kindSlug(kind)}`;
    const subTitle = `TypeScript: ${page.pkg} — ${kind.toLowerCase()}`;
    const subDesc = `${kind} exported by ${page.pkg}.`;
    const subIntro = `Part of [${page.label}](${pageUrl(page.slug)}) (\`${page.pkg}\`).\n\n## ${kind}\n\n`;
    const out =
      frontmatter(subTitle, subDesc) +
      GENERATED_NOTE +
      subIntro +
      rewriteLinks(part.body.join('\n'), path.dirname(page.src), sub, page.slug).trim() +
      '\n';
    writeFileSync(path.join(outRoot, `${sub}.md`), out);
    navChildren.push({ label: kind, slug: `reference/ts/${sub}` });
  }
  nav.push({ label: page.label, items: navChildren });
}

// Landing page.
const indexLines = [
  frontmatter(
    'TypeScript SDK reference',
    'Generated API reference for the DNSid TypeScript packages.',
  ),
  GENERATED_NOTE,
  'API reference for the [DNSid TypeScript SDK](https://github.com/dnsid-ai/dnsid-ts), generated from TSDoc comments. One page per published package (large packages are further divided by member kind):',
  '',
  ...PAGES.map((p) => `- [${p.label}](${pageUrl(p.slug)}) (\`${p.pkg}\`) — ${p.description}`),
  '',
];
writeFileSync(path.join(outRoot, 'index.md'), indexLines.join('\n'));

writeFileSync(path.join(outRoot, 'nav.json'), JSON.stringify(nav, null, 2) + '\n');

const total = prepared.reduce((n, p) => n + 1 + (p.kinds ? p.kinds.size : 0), 1);
console.log(`wrote ${total} pages + nav.json to docs/reference/`);
