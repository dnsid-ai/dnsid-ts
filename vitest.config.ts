import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@dnsid-ai/protocol': new URL('./packages/protocol/src/index.ts', import.meta.url).pathname,
      '@dnsid-ai/http-signatures': new URL('./packages/http-signatures/src/index.ts', import.meta.url).pathname,
      '@dnsid-ai/jose': new URL('./packages/jose/src/index.ts', import.meta.url).pathname,
      '@dnsid-ai/oidc': new URL('./packages/oidc/src/index.ts', import.meta.url).pathname,
      '@dnsid-ai/transport': new URL('./packages/transport/src/index.ts', import.meta.url).pathname,
      '@dnsid-ai/registry': new URL('./packages/registry/src/index.ts', import.meta.url).pathname,
      '@dnsid-ai/web-bot-auth': new URL('./packages/web-bot-auth/src/index.ts', import.meta.url).pathname,
      '@dnsid-ai/log-c2sp-tlog/writer': new URL('./packages/log-c2sp-tlog/src/writer.ts', import.meta.url).pathname,
      '@dnsid-ai/log-c2sp-tlog/version': new URL('./packages/log-c2sp-tlog/src/version.ts', import.meta.url).pathname,
      '@dnsid-ai/log-c2sp-tlog': new URL('./packages/log-c2sp-tlog/src/index.ts', import.meta.url).pathname,
      '@dnsid-ai/sdk/node': new URL('./packages/sdk/src/node.ts', import.meta.url).pathname,
      '@dnsid-ai/sdk': new URL('./packages/sdk/src/index.ts', import.meta.url).pathname,
      '@dnsid-ai/key-aws': new URL('./packages/key-aws/src/index.ts', import.meta.url).pathname,
      '@dnsid-ai/key-gcp': new URL('./packages/key-gcp/src/index.ts', import.meta.url).pathname,
    },
  },
});
