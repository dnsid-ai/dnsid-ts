#!/usr/bin/env bash
# =============================================================================
# scripts/walkthrough.sh — DNSid TypeScript SDK walkthrough
#
# Walks through the end-to-end happy path of the @identity-digital/dnsid
# TypeScript SDK: key generation, DNS record resolution, JWT signing, and
# JWT verification — all against an in-memory mock to demonstrate the API
# without requiring a live DNS infrastructure.
#
# Usage:
#   ./scripts/walkthrough.sh [--domain <fqdn>]
#
# Environment variables (override defaults):
#   DNSID_DOMAIN   — domain to use in the walkthrough (default: demo.agent.example.com)
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers — degrade gracefully when stdout is not a terminal.
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  BOLD='\033[1m'
  GREEN='\033[0;32m'
  RED='\033[0;31m'
  CYAN='\033[0;36m'
  RESET='\033[0m'
else
  BOLD='' GREEN='' RED='' CYAN='' RESET=''
fi

pass() { echo -e "  ${GREEN}✓ PASS${RESET}"; }
fail() { echo -e "  ${RED}✗ FAIL${RESET}"; }
header() { echo -e "\n${BOLD}${CYAN}[$1] $2${RESET}\n"; }

# ---------------------------------------------------------------------------
# Results tracking for final summary table.
# ---------------------------------------------------------------------------
declare -a STEP_NAMES=()
declare -a STEP_RESULTS=()
WALKTHROUGH_EXIT_CODE=0

record_result() {
  STEP_NAMES+=("$1")
  STEP_RESULTS+=("$2")
}

# ---------------------------------------------------------------------------
# Parse arguments.
# ---------------------------------------------------------------------------
DNSID_DOMAIN="${DNSID_DOMAIN:-demo.agent.example.com}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)
      shift
      DNSID_DOMAIN="${1:?--domain requires a FQDN}"
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [--domain <fqdn>]"
      echo ""
      echo "Demonstrates the DNSid TypeScript SDK end-to-end flow:"
      echo "  1. Install dependencies"
      echo "  2. Generate Ed25519 signing keys"
      echo "  3. Resolve/verify a DNSid identity record"
      echo "  4. Sign a JWT with the agent's Ed25519 key"
      echo "  5. Verify the JWT against the resolved identity"
      echo ""
      echo "Options:"
      echo "  --domain <fqdn>  Agent domain (default: \$DNSID_DOMAIN or demo.agent.example.com)"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

echo -e "${BOLD}DNSid TypeScript SDK Walkthrough${RESET}"
echo -e "Domain: ${CYAN}${DNSID_DOMAIN}${RESET}"
echo ""

# ---------------------------------------------------------------------------
# Resolve repo root (script may be invoked from anywhere).
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Step 0: Preflight — check Node.js and npm are available.
# ---------------------------------------------------------------------------
header "0" "Preflight check"

if ! command -v node &>/dev/null; then
  echo -e "${RED}✗ 'node' not found on PATH. Install Node.js >= 22.${RESET}"
  exit 1
fi

NODE_VERSION=$(node --version)
echo -e "  ${GREEN}✓${RESET} node found: $NODE_VERSION"

if ! command -v npx &>/dev/null; then
  echo -e "${RED}✗ 'npx' not found on PATH.${RESET}"
  exit 1
fi
echo -e "  ${GREEN}✓${RESET} npx found: $(command -v npx)"
record_result "Preflight" "PASS"

# ---------------------------------------------------------------------------
# Step 1: Install dependencies.
# ---------------------------------------------------------------------------
header "1" "Install npm dependencies"

echo -e "  ${CYAN}\$ npm install${RESET}"
echo ""

rc=0
npm install --prefer-offline --no-audit --no-fund 2>&1 | tail -5 || rc=$?

echo ""
if [ $rc -eq 0 ]; then
  pass
  record_result "npm install" "PASS"
else
  fail
  record_result "npm install" "FAIL (exit $rc)"
  echo -e "${RED}Cannot continue without dependencies. Exiting.${RESET}"
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 2: Build packages.
# ---------------------------------------------------------------------------
header "2" "Build packages"

echo -e "  ${CYAN}\$ npm run build${RESET}"
echo ""

rc=0
npm run build 2>&1 | tail -10 || rc=$?

echo ""
if [ $rc -eq 0 ]; then
  pass
  record_result "build" "PASS"
else
  fail
  record_result "build" "FAIL (exit $rc)"
  echo -e "${RED}Cannot continue without built packages. Exiting.${RESET}"
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 3: Generate Ed25519 key pair and sign/verify a JWT (full demo).
# ---------------------------------------------------------------------------
header "3" "Generate Ed25519 key, create DNSid record, sign JWT, verify JWT"

echo -e "  Running end-to-end TypeScript demo via ${CYAN}npx tsx${RESET}..."
echo ""

rc=0
TS_DEMO_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dnsid-ts-walkthrough.XXXXXX")"
TS_DEMO_FILE="$TS_DEMO_DIR/demo.ts"
cleanup_ts_demo() {
  rm -f "$TS_DEMO_FILE"
  rmdir "$TS_DEMO_DIR" 2>/dev/null || true
}
trap cleanup_ts_demo EXIT

cat > "$TS_DEMO_FILE" <<'TS'
import { DnsIdTxtRecord, DNSID_VERSION, IdentityManager, DNSSECState, InMemoryIdentityCache, toBase64Url, fromBase64Url } from '@identity-digital/dnsid-protocol';
import { JoseProfile } from '@identity-digital/dnsid-jose';
import { v4 as uuidv4 } from 'uuid';

const DOMAIN = process.env.DNSID_DOMAIN;
if (!DOMAIN) {
  throw new Error('DNSID_DOMAIN is required');
}
const VERIFIER_DOMAIN = 'verifier.example.com';

async function main() {
  // ── Step 3a: Generate Ed25519 key pair ──────────────────────────────────
  console.log('  📋 Step 3a: Generate Ed25519 key pair');
  const keyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  );
  const pubJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const kid = uuidv4();

  const dnsidJwk = {
    kty: pubJwk.kty!,
    crv: pubJwk.crv!,
    x: pubJwk.x!,
    alg: 'EdDSA',
    kid,
    use: 'sig',
  };
  console.log('     kid:', kid);
  console.log('     alg: EdDSA (Ed25519)');
  console.log('  ✅ Key pair generated');
  console.log('');

  // ── Step 3b: Create and self-sign a _dnsid TXT record ──────────────────
  console.log('  📋 Step 3b: Create and self-sign _dnsid TXT record');
  const record = new DnsIdTxtRecord();
  record.v = DNSID_VERSION;
  record.gi = 'example.com';
  record.ku = 'https://' + DOMAIN + '/.well-known/jwks.json';
  record.lr = 'microledger:demo-ref';
  record.su = 'https://' + DOMAIN + '/status';
  record.agentFQDN = DOMAIN;

  // Sign the canonical form
  const canonical = record.canonical();
  const sigBytes = new Uint8Array(
    await crypto.subtle.sign({ name: 'Ed25519' }, keyPair.privateKey, new TextEncoder().encode(canonical)),
  );
  record.sg = 'EdDSA:' + toBase64Url(sigBytes);

  console.log('     domain:', DOMAIN);
  console.log('     record:', record.serialize().slice(0, 80) + '...');
  console.log('  ✅ TXT record created and signed');
  console.log('');

  // ── Step 3c: Resolve identity (mock DNS + JWKS + status) ───────────────
  console.log('  📋 Step 3c: Verify identity record (mock resolver)');
  const txtRdata = record.serialize();

  // Mock DNS resolver returns our self-signed record
  const dnsResolver = {
    fetchTXT: async () => [[{ strings: [txtRdata], ttl: 300 }], DNSSECState.UNSIGNED],
  };

  // Mock JSON fetcher returns JWKS and status
  const tlsCert = { notAfter: new Date('2099-01-01'), san: [DOMAIN] };
  const fetchJson = async (url) => {
    if (url.includes('/status')) {
      return { data: { status: 'READY', updated_at: new Date().toISOString() }, tlsCert };
    }
    return { data: { keys: [dnsidJwk] }, tlsCert };
  };

  const config = {
    domain: DOMAIN,
    governanceId: 'example.com',
    kuUrl: 'https://' + DOMAIN + '/.well-known/jwks.json',
    logRef: 'microledger:demo-ref',
    statusUrl: 'https://' + DOMAIN + '/status',
  };

  const keyProvider = {
    signingKey: async () => dnsidJwk,
    jwk: async (k) => dnsidJwk,
    listKeyIds: async () => [kid],
    sign: async (payload) =>
      new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, keyPair.privateKey, payload)),
    generateKey: async () => kid,
    activate: async () => {},
    purge: async () => {},
  };

  const im = new IdentityManager(
    config,
    keyProvider,
    undefined,
    dnsResolver,
    new InMemoryIdentityCache(),
    fetchJson,
  );

  const verifiedDomain = await im.verifyDomain(DOMAIN);
  console.log('     verified domain:', verifiedDomain.domain);
  console.log('     signing key kid:', verifiedDomain.signingKey.kid);
  console.log('     status:', verifiedDomain.registryStatus.state);
  console.log('  ✅ Identity verified successfully');
  console.log('');

  // ── Step 3d: Sign a JWT ────────────────────────────────────────────────
  console.log('  📋 Step 3d: Sign a JWT (issuer → verifier)');
  const jose = new JoseProfile({
    domain: DOMAIN,
    keyProvider,
    identityResolver: im,
  });

  const jwt = await jose.createJWT({ audience: VERIFIER_DOMAIN });
  const [hdr, payload] = jwt.split('.').slice(0, 2).map(p =>
    JSON.parse(new TextDecoder().decode(fromBase64Url(p))),
  );
  console.log('     iss:', payload.iss);
  console.log('     aud:', payload.aud);
  console.log('     kid:', hdr.kid);
  console.log('     alg:', hdr.alg);
  console.log('     exp:', new Date(payload.exp * 1000).toISOString());
  console.log('     JWT:', jwt.slice(0, 60) + '...');
  console.log('  ✅ JWT signed');
  console.log('');

  // ── Step 3e: Verify the JWT ────────────────────────────────────────────
  console.log('  📋 Step 3e: Verify JWT (verifier side)');

  // The verifier only needs an identity resolver; verifyJWT does not require
  // the issuer's private key or any local verifier signing key.
  const verifierKeyProvider = {
    signingKey: async () => { throw new Error('verifier signing key is not needed for JWT verification'); },
    jwk: async () => { throw new Error('verifier JWKS publication is not needed for JWT verification'); },
    listKeyIds: async () => [],
    sign: async () => { throw new Error('verifier signing is not needed for JWT verification'); },
    generateKey: async () => { throw new Error('verifier key generation is not needed for JWT verification'); },
    activate: async () => { throw new Error('verifier key activation is not needed for JWT verification'); },
    purge: async () => { throw new Error('verifier key purge is not needed for JWT verification'); },
  };

  const verifierIm = new IdentityManager(
    { ...config, domain: VERIFIER_DOMAIN },
    verifierKeyProvider,
    undefined,
    dnsResolver,
    new InMemoryIdentityCache(),
    fetchJson,
  );

  const verifierJose = new JoseProfile({
    domain: VERIFIER_DOMAIN,
    keyProvider: verifierKeyProvider,
    identityResolver: verifierIm,
  });

  const result = await verifierJose.verifyJWT(jwt);
  console.log('     issuer verified:', result.domain);
  console.log('     signing key:', result.signingKey.kid);
  console.log('  ✅ JWT verified — issuer identity confirmed via DNSid');
  console.log('');
}

main().catch(e => {
  console.error('❌ Error:', e.message || e);
  process.exit(1);
});
TS
DNSID_DOMAIN="$DNSID_DOMAIN" npx tsx --eval "$(cat "$TS_DEMO_FILE")" || rc=$?

echo ""
if [ $rc -eq 0 ]; then
  pass
  record_result "E2E demo" "PASS"
else
  fail
  record_result "E2E demo" "FAIL (exit $rc)"
  WALKTHROUGH_EXIT_CODE=$rc
fi

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}═══════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Summary${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════${RESET}"
echo ""
printf "  %-20s  %s\n" "STEP" "RESULT"
printf "  %-20s  %s\n" "────────────────────" "──────────────"

for i in "${!STEP_NAMES[@]}"; do
  result="${STEP_RESULTS[$i]}"
  if [[ "$result" == "PASS" ]]; then
    printf "  %-20s  ${GREEN}%s${RESET}\n" "${STEP_NAMES[$i]}" "$result"
  elif [[ "$result" == SKIP* ]]; then
    printf "  %-20s  %s\n" "${STEP_NAMES[$i]}" "$result"
  else
    printf "  %-20s  ${RED}%s${RESET}\n" "${STEP_NAMES[$i]}" "$result"
  fi
done

echo ""
if [ "$WALKTHROUGH_EXIT_CODE" -eq 0 ]; then
  echo -e "${BOLD}Walkthrough complete.${RESET}"
else
  echo -e "${BOLD}Walkthrough failed.${RESET}"
fi
exit "$WALKTHROUGH_EXIT_CODE"
