import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const site = process.env.SITE_URL || 'https://shettyh.github.io';
const base = process.env.BASE_PATH ?? '/shunt';

export default defineConfig({
  site,
  base,
  integrations: [
    starlight({
      title: 'Shunt',
      description:
        'Ultra-lean, pluggable Rust gateway for HTTP APIs, multi-provider AI, and MCP agentic traffic.',
      logo: {
        src: './src/assets/logo.svg',
        replacesTitle: false,
      },
      favicon: '/favicon.svg',
      head: [
        {
          tag: 'script',
          content: `if (!localStorage.getItem('starlight-theme')) { localStorage.setItem('starlight-theme', 'light'); document.documentElement.dataset.theme = 'light'; }`,
        },
        {
          tag: 'link',
          attrs: { rel: 'preconnect', href: 'https://fonts.googleapis.com' },
        },
        {
          tag: 'link',
          attrs: { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: true },
        },
        {
          tag: 'link',
          attrs: {
            rel: 'stylesheet',
            href: 'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Source+Serif+4:ital,opsz,wght@0,8..60,400;0,8..60,500;0,8..60,600;1,8..60,400;1,8..60,500&display=swap',
          },
        },
      ],
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/shettyh/shunt' },
      ],
      editLink: {
        baseUrl: 'https://github.com/shettyh/shunt/edit/main/website/',
      },
      customCss: ['./src/styles/custom.css'],
      expressiveCode: {
        themes: ['github-light', 'github-dark-dimmed'],
        styleOverrides: {
          borderRadius: '8px',
          borderWidth: '1px',
          borderColor: 'var(--shunt-code-border)',
          codeBackground: 'var(--shunt-code-bg)',
          codeFontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
          codeFontSize: '0.84rem',
          codeLineHeight: '1.65',
          codePaddingBlock: '1rem',
          codePaddingInline: '1.2rem',
          frames: {
            frameBoxShadowCssValue: 'none',
            editorTabBarBackground: 'var(--shunt-code-header)',
            editorActiveTabBackground: 'var(--shunt-code-bg)',
            editorActiveTabIndicatorTopColor: 'transparent',
            terminalTitlebarBackground: 'var(--shunt-code-header)',
            terminalBackground: 'var(--shunt-code-bg)',
          },
        },
      },
      sidebar: [
        {
          label: 'Getting Started',
          items: [
            { label: 'Installation', slug: 'getting-started/installation' },
            { label: 'Quickstart: HTTP API Gateway', slug: 'getting-started/quickstart-api' },
            { label: 'Quickstart: AI Gateway', slug: 'getting-started/quickstart-ai' },
            { label: 'Quickstart: MCP Gateway', slug: 'getting-started/quickstart-mcp' },
          ],
        },
        {
          label: 'Core Concepts',
          items: [
            { label: 'Architecture & HookMask', slug: 'concepts/architecture' },
            { label: 'Configuration (shunt.toml)', slug: 'concepts/configuration' },
            { label: 'Observability & Inspector UI', slug: 'concepts/observability' },
            { label: 'Verification & Testing', slug: 'concepts/verification' },
          ],
        },
        {
          label: 'API Gateway',
          items: [
            { label: 'Overview & Routing', slug: 'api-gateway/overview' },
            { label: 'Security, TLS & Auth', slug: 'api-gateway/security-and-tls' },
            { label: 'Traffic, Compression & Mirroring', slug: 'api-gateway/traffic-and-compression' },
            { label: 'Kubernetes Gateway API', slug: 'api-gateway/kubernetes' },
          ],
        },
        {
          label: 'AI Gateway',
          items: [
            { label: 'Overview & Protocols', slug: 'ai-gateway/overview' },
            { label: 'Providers, Presets & Cloud IAM', slug: 'ai-gateway/providers' },
            { label: 'Smart Routing & Failover', slug: 'ai-gateway/routing-and-failover' },
            { label: 'Governance, Guardrails & Alerts', slug: 'ai-gateway/governance-and-safety' },
            { label: 'AI Caching (Exact, SSE & Semantic)', slug: 'ai-gateway/caching' },
          ],
        },
        {
          label: 'MCP Gateway',
          items: [
            { label: 'Virtual MCP & Agent Governance', slug: 'mcp-gateway/overview' },
          ],
        },
        {
          label: 'Plugins Reference',
          items: [
            { label: 'HTTP Plugins (shunt-plugins)', slug: 'plugins/http-plugins' },
            { label: 'AI Plugins (shunt-ai)', slug: 'plugins/ai-plugins' },
            { label: 'MCP Plugins (shunt-mcp)', slug: 'plugins/mcp-plugins' },
            { label: 'Writing Custom Plugins', slug: 'plugins/custom-plugins' },
          ],
        },
        {
          label: 'Guides & Recipes',
          items: [
            { label: 'Which Plugins Do I Need?', slug: 'guides/recipes' },
            { label: 'Production & Troubleshooting', slug: 'guides/production-and-troubleshooting' },
            { label: 'Coding Agents & Local LLMs', slug: 'guides/coding-agents' },
            { label: 'Migrating from LiteLLM', slug: 'guides/litellm-migration' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'CLI Commands', slug: 'reference/cli' },
            { label: 'Admin API (:9090)', slug: 'reference/admin-api' },
            { label: 'Benchmarks', slug: 'reference/benchmarks' },
          ],
        },
      ],
    }),
  ],
});
