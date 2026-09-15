import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@identity-digital/dnsid-protocol': new URL('./packages/core/src/index.ts', import.meta.url).pathname,
      '@identity-digital/dnsid-http-signatures': new URL('./packages/http-signatures/src/index.ts', import.meta.url).pathname,
      '@identity-digital/dnsid-jose': new URL('./packages/jose/src/index.ts', import.meta.url).pathname,
      '@identity-digital/dnsid-oidc': new URL('./packages/oidc/src/index.ts', import.meta.url).pathname,
      '@identity-digital/dnsid-transport': new URL('./packages/transport/src/index.ts', import.meta.url).pathname,
      '@identity-digital/dnsid-registry': new URL('./packages/registry/src/index.ts', import.meta.url).pathname,
      '@identity-digital/dnsid-web-bot-auth': new URL('./packages/web-bot-auth/src/index.ts', import.meta.url).pathname,
      '@identity-digital/dnsid-log-c2sp-tlog/writer': new URL('./packages/log-c2sp-tlog/src/writer.ts', import.meta.url).pathname,
      '@identity-digital/dnsid-log-c2sp-tlog/version': new URL('./packages/log-c2sp-tlog/src/version.ts', import.meta.url).pathname,
      '@identity-digital/dnsid-log-c2sp-tlog': new URL('./packages/log-c2sp-tlog/src/index.ts', import.meta.url).pathname,
      '@identity-digital/dnsid/node': new URL('./packages/sdk/src/node.ts', import.meta.url).pathname,
      '@identity-digital/dnsid': new URL('./packages/sdk/src/index.ts', import.meta.url).pathname,
      '@identity-digital/dnsid-key-aws': new URL('./packages/key-aws/src/index.ts', import.meta.url).pathname,
      '@identity-digital/dnsid-key-gcp': new URL('./packages/key-gcp/src/index.ts', import.meta.url).pathname,
    },
  },
});
