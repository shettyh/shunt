/**
 * Structured, lossless domain projections for Shunt's AI Gateway, MCP Gateway, and HTTP Routes
 * on top of canonical `TopologyResource[]`.
 *
 * Every mutation synthesizes `shunt verify`-clean Shunt topology IR (`[[upstreams]]`, `[[routes]]`,
 * canonically ordered plugin chains) while preserving lossless round-trips for imported `shunt.toml`.
 */

import { api, slugify, TopologyResource } from './api';

// =============================================================================
// Built-in Shunt AI Provider Presets (mirrors `crates/shunt-ai/src/presets.rs`)
// =============================================================================

export type ProviderPresetId =
  | 'openai'
  | 'anthropic'
  | 'gemini'
  | 'bedrock'
  | 'azure_openai'
  | 'groq'
  | 'deepseek'
  | 'openrouter'
  | 'mistral'
  | 'xai'
  | 'together'
  | 'fireworks'
  | 'cohere'
  | 'ollama'
  | 'vllm'
  | 'jina'
  | 'voyage'
  | 'custom';

export type ProviderAuthKind = 'vault' | 'env' | 'aws_sigv4' | 'client_passthrough' | 'none';

export interface ProviderPresetMeta {
  id: ProviderPresetId;
  name: string;
  short: string;
  tagline: string;
  defaultBaseUrl: string;
  defaultSlug: string;
  defaultAuthKind: ProviderAuthKind;
  defaultEnvVar: string;
  defaultModelPattern: string;
  popularModels: string[];
  accentDot: string;
  category: 'frontier' | 'cloud' | 'fast' | 'local';
  supportsVertex?: boolean;
  requiresRegion?: boolean;
  requiresApiVersion?: boolean;
}

export const AI_PROVIDER_PRESETS: ProviderPresetMeta[] = [
  {
    id: 'openai',
    name: 'OpenAI',
    short: 'OA',
    tagline: 'GPT-4o, o3, Responses API & embeddings',
    defaultBaseUrl: 'https://api.openai.com',
    defaultSlug: 'openai',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'OPENAI_API_KEY',
    defaultModelPattern: 'gpt-*',
    popularModels: ['gpt-4o', 'gpt-4o-mini', 'o3-mini', 'text-embedding-3-small'],
    accentDot: '#10a37f',
    category: 'frontier',
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    short: 'AN',
    tagline: 'Claude 4 Sonnet, Opus & Haiku (Messages + OpenAI parity)',
    defaultBaseUrl: 'https://api.anthropic.com',
    defaultSlug: 'anthropic',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'ANTHROPIC_API_KEY',
    defaultModelPattern: 'claude-*',
    popularModels: ['claude-sonnet-4-20250514', 'claude-opus-4-20250514', 'claude-3-5-haiku-20241022'],
    accentDot: '#d95b26',
    category: 'frontier',
    supportsVertex: true,
  },
  {
    id: 'gemini',
    name: 'Google Gemini',
    short: 'GM',
    tagline: 'Gemini 2.5 Pro & Flash via AI Studio or Vertex AI',
    defaultBaseUrl: 'https://generativelanguage.googleapis.com',
    defaultSlug: 'gemini',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'GEMINI_API_KEY',
    defaultModelPattern: 'gemini-*',
    popularModels: ['gemini-2.5-pro', 'gemini-2.5-flash', 'text-embedding-004'],
    accentDot: '#4285f4',
    category: 'frontier',
    supportsVertex: true,
  },
  {
    id: 'bedrock',
    name: 'AWS Bedrock',
    short: 'BR',
    tagline: 'Converse & ConverseStream with pure-Rust AWS SigV4',
    defaultBaseUrl: 'https://bedrock-runtime.us-east-1.amazonaws.com',
    defaultSlug: 'bedrock',
    defaultAuthKind: 'aws_sigv4',
    defaultEnvVar: 'AWS_ACCESS_KEY_ID',
    defaultModelPattern: 'anthropic.*',
    popularModels: [
      'anthropic.claude-sonnet-4-20250514-v1:0',
      'amazon.titan-embed-text-v2:0',
    ],
    accentDot: '#f59e0b',
    category: 'cloud',
    requiresRegion: true,
  },
  {
    id: 'azure_openai',
    name: 'Azure OpenAI',
    short: 'AZ',
    tagline: 'Enterprise Azure OpenAI deployments with API versioning',
    defaultBaseUrl: 'https://my-resource.openai.azure.com',
    defaultSlug: 'azure',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'AZURE_OPENAI_API_KEY',
    defaultModelPattern: '',
    popularModels: ['gpt-4o', 'gpt-4o-mini'],
    accentDot: '#0ea5e9',
    category: 'cloud',
    requiresApiVersion: true,
  },
  {
    id: 'groq',
    name: 'Groq',
    short: 'GQ',
    tagline: 'Ultra-low-latency Llama & Mixtral inference',
    defaultBaseUrl: 'https://api.groq.com',
    defaultSlug: 'groq',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'GROQ_API_KEY',
    defaultModelPattern: 'llama-*',
    popularModels: ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant'],
    accentDot: '#ea580c',
    category: 'fast',
  },
  {
    id: 'deepseek',
    name: 'DeepSeek',
    short: 'DS',
    tagline: 'DeepSeek-V3 & DeepSeek-R1 reasoning models',
    defaultBaseUrl: 'https://api.deepseek.com',
    defaultSlug: 'deepseek',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'DEEPSEEK_API_KEY',
    defaultModelPattern: 'deepseek-*',
    popularModels: ['deepseek-chat', 'deepseek-reasoner'],
    accentDot: '#6366f1',
    category: 'frontier',
  },
  {
    id: 'openrouter',
    name: 'OpenRouter',
    short: 'OR',
    tagline: 'Multi-model meta-router upstream',
    defaultBaseUrl: 'https://openrouter.ai',
    defaultSlug: 'openrouter',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'OPENROUTER_API_KEY',
    defaultModelPattern: '',
    popularModels: ['openai/gpt-4o', 'anthropic/claude-sonnet-4'],
    accentDot: '#8b5cf6',
    category: 'fast',
  },
  {
    id: 'mistral',
    name: 'Mistral AI',
    short: 'MS',
    tagline: 'Mistral Large, Codestral & open-weight models',
    defaultBaseUrl: 'https://api.mistral.ai',
    defaultSlug: 'mistral',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'MISTRAL_API_KEY',
    defaultModelPattern: 'mistral-*',
    popularModels: ['mistral-large-latest', 'codestral-latest'],
    accentDot: '#f97316',
    category: 'frontier',
  },
  {
    id: 'xai',
    name: 'xAI',
    short: 'XA',
    tagline: 'Grok frontier reasoning & vision models',
    defaultBaseUrl: 'https://api.x.ai',
    defaultSlug: 'xai',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'XAI_API_KEY',
    defaultModelPattern: 'grok-*',
    popularModels: ['grok-3', 'grok-3-mini'],
    accentDot: '#18181b',
    category: 'frontier',
  },
  {
    id: 'together',
    name: 'Together AI',
    short: 'TG',
    tagline: 'Fast serverless open-source models',
    defaultBaseUrl: 'https://api.together.xyz',
    defaultSlug: 'together',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'TOGETHER_API_KEY',
    defaultModelPattern: '',
    popularModels: ['meta-llama/Llama-3.3-70B-Instruct-Turbo'],
    accentDot: '#2563eb',
    category: 'fast',
  },
  {
    id: 'fireworks',
    name: 'Fireworks AI',
    short: 'FW',
    tagline: 'Low-latency FireAttention serverless models',
    defaultBaseUrl: 'https://api.fireworks.ai',
    defaultSlug: 'fireworks',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'FIREWORKS_API_KEY',
    defaultModelPattern: '',
    popularModels: ['accounts/fireworks/models/llama-v3p3-70b-instruct'],
    accentDot: '#db2777',
    category: 'fast',
  },
  {
    id: 'cohere',
    name: 'Cohere',
    short: 'CO',
    tagline: 'Command R+ & Rerank v3.5',
    defaultBaseUrl: 'https://api.cohere.com',
    defaultSlug: 'cohere',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'COHERE_API_KEY',
    defaultModelPattern: 'command-*',
    popularModels: ['command-r-plus', 'rerank-v3.5'],
    accentDot: '#059669',
    category: 'fast',
  },
  {
    id: 'ollama',
    name: 'Ollama (Local)',
    short: 'OL',
    tagline: 'Local models on your machine or private GPU host',
    defaultBaseUrl: 'http://127.0.0.1:11434',
    defaultSlug: 'ollama',
    defaultAuthKind: 'none',
    defaultEnvVar: '',
    defaultModelPattern: '',
    popularModels: ['llama3.2', 'qwen2.5-coder', 'deepseek-r1'],
    accentDot: '#52525b',
    category: 'local',
  },
  {
    id: 'vllm',
    name: 'vLLM (Self-Hosted)',
    short: 'VL',
    tagline: 'Self-hosted vLLM cluster with OpenAI-compatible API',
    defaultBaseUrl: 'http://127.0.0.1:8000',
    defaultSlug: 'vllm',
    defaultAuthKind: 'none',
    defaultEnvVar: '',
    defaultModelPattern: '',
    popularModels: ['meta-llama/Llama-3.1-8B-Instruct'],
    accentDot: '#7c3aed',
    category: 'local',
  },
  {
    id: 'jina',
    name: 'Jina AI',
    short: 'JN',
    tagline: 'Multilingual embeddings & reranking',
    defaultBaseUrl: 'https://api.jina.ai',
    defaultSlug: 'jina',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'JINA_API_KEY',
    defaultModelPattern: 'jina-*',
    popularModels: ['jina-embeddings-v3', 'jina-reranker-v2-base-multilingual'],
    accentDot: '#0d9488',
    category: 'fast',
  },
  {
    id: 'voyage',
    name: 'Voyage AI',
    short: 'VY',
    tagline: 'High-accuracy code & domain embeddings',
    defaultBaseUrl: 'https://api.voyageai.com',
    defaultSlug: 'voyage',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'VOYAGE_API_KEY',
    defaultModelPattern: 'voyage-*',
    popularModels: ['voyage-3-large', 'voyage-code-3'],
    accentDot: '#0284c7',
    category: 'fast',
  },
  {
    id: 'custom',
    name: 'Custom OpenAI-Compatible',
    short: 'CU',
    tagline: 'Any private endpoint speaking OpenAI chat/embeddings',
    defaultBaseUrl: 'https://api.example.com',
    defaultSlug: 'custom-llm',
    defaultAuthKind: 'vault',
    defaultEnvVar: 'CUSTOM_LLM_API_KEY',
    defaultModelPattern: '',
    popularModels: [],
    accentDot: '#71717a',
    category: 'local',
  },
];

export function getPresetMeta(id?: string): ProviderPresetMeta {
  return (
    AI_PROVIDER_PRESETS.find((p) => p.id === id) ||
    AI_PROVIDER_PRESETS[AI_PROVIDER_PRESETS.length - 1]
  );
}

// =============================================================================
// Extracted Structured Models from `TopologyResource[]`
// =============================================================================

export interface PluginSpec {
  name: string;
  id?: string;
  config?: Record<string, unknown>;
}

export interface RouteSpec {
  id: string;
  path_prefix?: string;
  path_exact?: string;
  path_template?: string;
  path_regex?: string;
  host?: string;
  methods?: string[];
  upstream?: string;
  group?: string;
  max_attempts?: number;
  max_body_bytes?: number;
  response_headers_timeout_ms?: number;
  idle_chunk_timeout_ms?: number;
  idle_body_timeout_ms?: number;
  allow_websockets?: boolean;
  plugins?: PluginSpec[];
  [key: string]: unknown;
}

export interface UpstreamSpec {
  name: string;
  endpoints: string[];
  connect_timeout_ms?: number;
  [key: string]: unknown;
}

export interface AiProviderView {
  slug: string;
  preset: ProviderPresetId;
  baseUrl: string;
  upstreamName: string;
  authSummary: string;
  authKind: ProviderAuthKind;
  keyRefs: string[];
  dropParams: boolean;
  region?: string;
  apiVersion?: string;
  vertexProject?: string;
  vertexLocation?: string;
  rawConfig: Record<string, unknown>;
}

export interface AiModelTarget {
  provider: string;
  upstream: string;
  model?: string;
  weight?: number;
  capabilities?: string[];
}

export interface AiModelAliasView {
  name: string;
  kind: 'alias' | 'rule';
  strategy: 'priority' | 'weighted' | 'latency' | 'cost';
  targets: AiModelTarget[];
}

export interface AiProtectionView {
  virtualKeysEnabled: boolean;
  virtualKeysSyncNamespace: string;
  failoverEnabled: boolean;
  failoverCooldownMs: number;
  failoverRetries: number[];
  rateLimitEnabled: boolean;
  rateLimitRpm: number;
  rateLimitTpm: number;
  budgetEnabled: boolean;
  budgetWindow: 'daily' | 'weekly' | 'monthly';
  budgetMode: 'hard' | 'soft';
  budgetDefaultUsd: number;
  cacheEnabled: boolean;
  cacheTtlSecs: number;
  cacheStreaming: boolean;
  guardrailsEnabled: boolean;
  guardrailsPresets: string[];
  guardrailsAction: 'redact' | 'block' | 'warn';
  usageTrackerEnabled: boolean;
}

export interface AiGatewayState {
  routeResource: TopologyResource | null;
  routeSlug: string;
  routePath: string;
  providers: AiProviderView[];
  models: AiModelAliasView[];
  exposedModels: string[];
  defaultStrategy: 'priority' | 'weighted' | 'latency' | 'cost';
  protection: AiProtectionView;
}

export interface McpServerView {
  slug: string;
  upstreamName: string;
  baseUrl: string;
  path: string;
  authType: 'none' | 'bearer' | 'header';
  authHeader?: string;
  authKeyRef?: string;
  stateful: boolean;
  resourcePrefixes: string[];
  description?: string;
  enabled: boolean;
}

export interface McpProtectionView {
  authEnabled: boolean;
  guardrailsEnabled: boolean;
  argumentDetectors: string[];
  responseDetectors: string[];
  deniedTools: string[];
  requireApprovalTools: string[];
  rateLimitEnabled: boolean;
  rpm: number;
  toolRpm: number;
  maxCallsPerSession: number;
  loopBreakerEnabled: boolean;
  loopBreakerMaxRepeats: number;
  telemetryEnabled: boolean;
}

export interface McpGatewayState {
  routeResource: TopologyResource | null;
  routeSlug: string;
  routePath: string;
  serverName: string;
  servers: McpServerView[];
  protection: McpProtectionView;
}

// =============================================================================
// Extractors (Lossless Read from `TopologyResource[]`)
// =============================================================================

function asObj(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function asPlugins(routeSpec: Record<string, unknown>): PluginSpec[] {
  return Array.isArray(routeSpec.plugins)
    ? (routeSpec.plugins as PluginSpec[]).filter((p) => p && typeof p.name === 'string')
    : [];
}

export function getGatewayListenPort(resources: TopologyResource[]): string {
  const srv = resources.find((r) => r.kind === 'server');
  const listen = typeof asObj(srv?.spec).listen === 'string' ? String(asObj(srv?.spec).listen) : '0.0.0.0:8080';
  const port = listen.split(':').pop() || '8080';
  return port;
}

export function findAiRoute(resources: TopologyResource[]): TopologyResource | null {
  const routes = resources.filter((r) => r.kind === 'route');
  const byPlugin = routes.find((r) =>
    asPlugins(asObj(r.spec)).some((p) => p.name === 'ai-provider-adapter' || p.name === 'ai-model-router')
  );
  if (byPlugin) return byPlugin;
  return routes.find((r) => r.slug === 'ai-gateway') || null;
}

export function findMcpRoute(resources: TopologyResource[]): TopologyResource | null {
  const routes = resources.filter((r) => r.kind === 'route');
  const byPlugin = routes.find((r) =>
    asPlugins(asObj(r.spec)).some((p) => p.name === 'mcp-router' || p.name === 'mcp-auth')
  );
  if (byPlugin) return byPlugin;
  return routes.find((r) => r.slug === 'mcp-gateway') || null;
}

function detectAuthSummary(cfg: Record<string, unknown>): {
  kind: ProviderAuthKind;
  summary: string;
  refs: string[];
} {
  const auth = asObj(cfg.auth);
  const authType = typeof auth.type === 'string' ? auth.type : '';
  if (authType === 'aws_sigv4') {
    return {
      kind: 'aws_sigv4',
      summary: 'AWS SigV4',
      refs: [String(auth.access_key_id || ''), String(auth.secret_access_key || '')].filter(Boolean),
    };
  }
  if (authType === 'client_passthrough') {
    return { kind: 'client_passthrough', summary: 'Client BYOK', refs: [] };
  }
  if (authType === 'aws_iam' || authType === 'gcp_iam' || authType === 'azure_ad') {
    return { kind: 'aws_sigv4', summary: authType.toUpperCase(), refs: [] };
  }

  const refs: string[] = [];
  if (typeof cfg.api_key === 'string' && cfg.api_key) refs.push(cfg.api_key);
  if (Array.isArray(cfg.api_keys)) {
    for (const k of cfg.api_keys) {
      if (typeof k === 'string' && k) refs.push(k);
    }
  }
  if (typeof auth.api_key === 'string' && auth.api_key) refs.push(auth.api_key);
  if (Array.isArray(auth.api_keys)) {
    for (const k of auth.api_keys) {
      if (typeof k === 'string' && k) refs.push(k);
    }
  }

  if (refs.length === 0) {
    return { kind: 'none', summary: 'No auth', refs: [] };
  }
  const isVault = refs.some((r) => r.startsWith('secret:'));
  const isEnv = refs.some((r) => r.startsWith('env:'));
  const kind: ProviderAuthKind = isVault ? 'vault' : isEnv ? 'env' : 'vault';
  const label =
    refs.length > 1
      ? `${refs.length} keys (${isVault ? 'vault' : isEnv ? 'env' : 'pool'})`
      : isVault
        ? 'Vault secret'
        : isEnv
          ? refs[0]
          : 'API key';
  return { kind, summary: label, refs };
}

export function extractAiGatewayState(resources: TopologyResource[]): AiGatewayState {
  const routeRes = findAiRoute(resources);
  const routeSpec = asObj(routeRes?.spec);
  const plugins = asPlugins(routeSpec);

  const upstreamsByName = new Map<string, UpstreamSpec>();
  for (const r of resources) {
    if (r.kind === 'upstream') {
      const s = asObj(r.spec);
      const name = typeof s.name === 'string' && s.name ? s.name : r.slug;
      upstreamsByName.set(name, {
        name,
        endpoints: Array.isArray(s.endpoints) ? s.endpoints.map(String) : [],
        ...s,
      });
    }
  }

  const adapterPlugin = plugins.find((p) => p.name === 'ai-provider-adapter');
  const routerPlugin = plugins.find((p) => p.name === 'ai-model-router');
  const vkeysPlugin = plugins.find((p) => p.name === 'ai-virtual-keys');
  const failoverPlugin = plugins.find((p) => p.name === 'ai-failover');
  const rlPlugin = plugins.find((p) => p.name === 'ai-token-rate-limit');
  const budgetPlugin = plugins.find((p) => p.name === 'ai-budget');
  const cachePlugin = plugins.find((p) => p.name === 'ai-cache');
  const guardrailsPlugin = plugins.find((p) => p.name === 'ai-guardrails');
  const usagePlugin = plugins.find((p) => p.name === 'ai-usage-tracker');

  // Extract providers
  const providersMap = asObj(asObj(adapterPlugin?.config).providers);
  const providers: AiProviderView[] = Object.entries(providersMap).map(([slug, raw]) => {
    const cfg = asObj(raw);
    const presetRaw =
      typeof cfg.preset === 'string'
        ? cfg.preset
        : typeof cfg.dialect === 'string'
          ? cfg.dialect === 'openai_compatible'
            ? 'custom'
            : cfg.dialect
          : 'custom';
    const preset = (AI_PROVIDER_PRESETS.some((p) => p.id === presetRaw)
      ? presetRaw
      : 'custom') as ProviderPresetId;
    const presetMeta = getPresetMeta(preset);
    const up = upstreamsByName.get(slug);
    const baseUrl = up?.endpoints?.[0] || presetMeta.defaultBaseUrl;
    const authInfo = detectAuthSummary(cfg);

    return {
      slug,
      preset,
      baseUrl,
      upstreamName: up?.name || slug,
      authKind: authInfo.kind,
      authSummary: authInfo.summary,
      keyRefs: authInfo.refs,
      dropParams: Boolean(cfg.drop_params),
      region: typeof cfg.region === 'string' ? cfg.region : undefined,
      apiVersion: typeof cfg.api_version === 'string' ? cfg.api_version : undefined,
      vertexProject: typeof cfg.vertex_project === 'string' ? cfg.vertex_project : undefined,
      vertexLocation: typeof cfg.vertex_location === 'string' ? cfg.vertex_location : undefined,
      rawConfig: cfg,
    };
  });

  // Extract models + rules
  const routerCfg = asObj(routerPlugin?.config);
  const defaultStrategy = (
    typeof routerCfg.strategy === 'string' ? routerCfg.strategy : 'priority'
  ) as 'priority' | 'weighted' | 'latency' | 'cost';
  const exposedModels = Array.isArray(routerCfg.exposed_models)
    ? routerCfg.exposed_models.map(String)
    : [];

  const models: AiModelAliasView[] = [];
  const rawModels = asObj(routerCfg.models);
  for (const [alias, entry] of Object.entries(rawModels)) {
    if (Array.isArray(entry)) {
      models.push({
        name: alias,
        kind: 'alias',
        strategy: defaultStrategy,
        targets: entry.map((t) => {
          const to = asObj(t);
          return {
            provider: String(to.provider || ''),
            upstream: String(to.upstream || to.provider || ''),
            model: typeof to.model === 'string' ? to.model : undefined,
            weight: typeof to.weight === 'number' ? to.weight : undefined,
            capabilities: Array.isArray(to.capabilities) ? to.capabilities.map(String) : undefined,
          };
        }),
      });
    } else if (entry && typeof entry === 'object') {
      const eo = asObj(entry);
      const tArr = Array.isArray(eo.targets) ? eo.targets : [];
      models.push({
        name: alias,
        kind: 'alias',
        strategy: (typeof eo.strategy === 'string' ? eo.strategy : defaultStrategy) as AiModelAliasView['strategy'],
        targets: tArr.map((t) => {
          const to = asObj(t);
          return {
            provider: String(to.provider || ''),
            upstream: String(to.upstream || to.provider || ''),
            model: typeof to.model === 'string' ? to.model : undefined,
            weight: typeof to.weight === 'number' ? to.weight : undefined,
            capabilities: Array.isArray(to.capabilities) ? to.capabilities.map(String) : undefined,
          };
        }),
      });
    }
  }

  if (Array.isArray(routerCfg.rules)) {
    for (const r of routerCfg.rules) {
      const ro = asObj(r);
      const pattern = String(ro.pattern || '');
      if (!pattern) continue;
      const tArr = Array.isArray(ro.targets) ? ro.targets : [];
      models.push({
        name: pattern,
        kind: 'rule',
        strategy: (typeof ro.strategy === 'string' ? ro.strategy : defaultStrategy) as AiModelAliasView['strategy'],
        targets: tArr.map((t) => {
          const to = asObj(t);
          return {
            provider: String(to.provider || ''),
            upstream: String(to.upstream || to.provider || ''),
            model: typeof to.model === 'string' ? to.model : undefined,
            weight: typeof to.weight === 'number' ? to.weight : undefined,
          };
        }),
      });
    }
  }

  // Protection toggles
  const vkeysCfg = asObj(vkeysPlugin?.config);
  const failoverCfg = asObj(failoverPlugin?.config);
  const rlCfg = asObj(rlPlugin?.config);
  const budgetCfg = asObj(budgetPlugin?.config);
  const cacheCfg = asObj(cachePlugin?.config);
  const guardCfg = asObj(guardrailsPlugin?.config);

  const protection: AiProtectionView = {
    virtualKeysEnabled: Boolean(vkeysPlugin),
    virtualKeysSyncNamespace:
      typeof vkeysCfg.sync_namespace === 'string' ? vkeysCfg.sync_namespace : 'ai.virtual_keys',
    failoverEnabled: Boolean(failoverPlugin),
    failoverCooldownMs: typeof failoverCfg.cooldown_ms === 'number' ? failoverCfg.cooldown_ms : 30000,
    failoverRetries: Array.isArray(failoverCfg.retry_statuses)
      ? failoverCfg.retry_statuses.map(Number)
      : [429, 500, 502, 503, 504, 529],
    rateLimitEnabled: Boolean(rlPlugin),
    rateLimitRpm: typeof rlCfg.rpm === 'number' ? rlCfg.rpm : 60,
    rateLimitTpm: typeof rlCfg.tpm === 'number' ? rlCfg.tpm : 100000,
    budgetEnabled: Boolean(budgetPlugin),
    budgetWindow: (typeof budgetCfg.window === 'string' ? budgetCfg.window : 'monthly') as
      | 'daily'
      | 'weekly'
      | 'monthly',
    budgetMode: (typeof budgetCfg.mode === 'string' ? budgetCfg.mode : 'hard') as 'hard' | 'soft',
    budgetDefaultUsd: typeof budgetCfg.default_limit_usd === 'number' ? budgetCfg.default_limit_usd : 100,
    cacheEnabled: Boolean(cachePlugin),
    cacheTtlSecs: typeof cacheCfg.ttl_secs === 'number' ? cacheCfg.ttl_secs : 300,
    cacheStreaming: Boolean(cacheCfg.cache_streaming),
    guardrailsEnabled: Boolean(guardrailsPlugin),
    guardrailsPresets: Array.isArray(guardCfg.presets)
      ? guardCfg.presets.map(String)
      : ['pii', 'secrets', 'prompt_injection'],
    guardrailsAction: (typeof guardCfg.action === 'string' ? guardCfg.action : 'redact') as
      | 'redact'
      | 'block'
      | 'warn',
    usageTrackerEnabled: Boolean(usagePlugin),
  };

  return {
    routeResource: routeRes,
    routeSlug: routeRes?.slug || 'ai-gateway',
    routePath: typeof routeSpec.path_prefix === 'string' ? routeSpec.path_prefix : '/v1',
    providers,
    models,
    exposedModels,
    defaultStrategy,
    protection,
  };
}

export function extractMcpGatewayState(resources: TopologyResource[]): McpGatewayState {
  const routeRes = findMcpRoute(resources);
  const routeSpec = asObj(routeRes?.spec);
  const plugins = asPlugins(routeSpec);

  const upstreamsByName = new Map<string, UpstreamSpec>();
  for (const r of resources) {
    if (r.kind === 'upstream') {
      const s = asObj(r.spec);
      const name = typeof s.name === 'string' && s.name ? s.name : r.slug;
      upstreamsByName.set(name, {
        name,
        endpoints: Array.isArray(s.endpoints) ? s.endpoints.map(String) : [],
        ...s,
      });
    }
  }

  const authPlugin = plugins.find((p) => p.name === 'mcp-auth');
  const routerPlugin = plugins.find((p) => p.name === 'mcp-router');
  const guardPlugin = plugins.find((p) => p.name === 'mcp-guardrails');
  const rlPlugin = plugins.find((p) => p.name === 'mcp-rate-limit');
  const telPlugin = plugins.find((p) => p.name === 'mcp-telemetry');

  const routerCfg = asObj(routerPlugin?.config);
  const rawServers = asObj(routerCfg.servers);

  const servers: McpServerView[] = Object.entries(rawServers).map(([slug, raw]) => {
    const s = asObj(raw);
    const upstreamName = String(s.upstream || `mcp-${slug}`);
    const up = upstreamsByName.get(upstreamName);
    const auth = asObj(s.auth);
    const authType = (
      auth.type === 'bearer' || auth.type === 'header' ? auth.type : 'none'
    ) as McpServerView['authType'];
    return {
      slug,
      upstreamName,
      baseUrl: up?.endpoints?.[0] || 'http://127.0.0.1:8090',
      path: typeof s.path === 'string' ? s.path : '/mcp',
      authType,
      authHeader: typeof auth.header === 'string' ? auth.header : undefined,
      authKeyRef: typeof auth.api_key === 'string' ? auth.api_key : undefined,
      stateful: Boolean(s.stateful),
      resourcePrefixes: Array.isArray(s.resource_prefixes) ? s.resource_prefixes.map(String) : [],
      description: typeof s.description === 'string' ? s.description : undefined,
      enabled: s.enabled !== false,
    };
  });

  const guardCfg = asObj(guardPlugin?.config);
  const rlCfg = asObj(rlPlugin?.config);
  const lbCfg = asObj(rlCfg.loop_breaker);

  const protection: McpProtectionView = {
    authEnabled: Boolean(authPlugin),
    guardrailsEnabled: Boolean(guardPlugin),
    argumentDetectors: Array.isArray(guardCfg.argument_detectors)
      ? guardCfg.argument_detectors.map(String)
      : ['aws_key', 'api_key', 'private_key'],
    responseDetectors: Array.isArray(guardCfg.response_detectors)
      ? guardCfg.response_detectors.map(String)
      : ['prompt_injection', 'private_key'],
    deniedTools: Array.isArray(guardCfg.denied_tools) ? guardCfg.denied_tools.map(String) : [],
    requireApprovalTools: Array.isArray(guardCfg.require_approval_tools)
      ? guardCfg.require_approval_tools.map(String)
      : [],
    rateLimitEnabled: Boolean(rlPlugin),
    rpm: typeof rlCfg.rpm === 'number' ? rlCfg.rpm : 120,
    toolRpm: typeof rlCfg.tool_rpm === 'number' ? rlCfg.tool_rpm : 60,
    maxCallsPerSession: typeof rlCfg.max_calls_per_session === 'number' ? rlCfg.max_calls_per_session : 50,
    loopBreakerEnabled: Boolean(rlCfg.loop_breaker),
    loopBreakerMaxRepeats: typeof lbCfg.max_repeats === 'number' ? lbCfg.max_repeats : 3,
    telemetryEnabled: Boolean(telPlugin),
  };

  return {
    routeResource: routeRes,
    routeSlug: routeRes?.slug || 'mcp-gateway',
    routePath: typeof routeSpec.path_prefix === 'string' ? routeSpec.path_prefix : '/mcp',
    serverName: typeof routerCfg.server_name === 'string' ? routerCfg.server_name : 'shunt-mcp-gateway',
    servers,
    protection,
  };
}

// =============================================================================
// Canonical `shunt verify`-clean AI & MCP Pipeline Builders
// =============================================================================

const AI_PLUGIN_ORDER = [
  'ai-virtual-keys',
  'ai-model-router',
  'ai-guardrails',
  'ai-cache',
  'ai-token-rate-limit',
  'ai-budget',
  'ai-provider-adapter',
  'ai-failover',
  'ai-usage-tracker',
  'ai-audit',
  'ai-alerts',
];

function sortPluginsCanonically(plugins: PluginSpec[], order: string[]): PluginSpec[] {
  return [...plugins].sort((a, b) => {
    const ia = order.indexOf(a.name);
    const ib = order.indexOf(b.name);
    const ra = ia === -1 ? 500 : ia;
    const rb = ib === -1 ? 500 : ib;
    return ra - rb;
  });
}

function upsertPlugin(plugins: PluginSpec[], name: string, config: Record<string, unknown>, order: string[]): PluginSpec[] {
  const next = plugins.filter((p) => p.name !== name);
  next.push({ name, config });
  return sortPluginsCanonically(next, order);
}

function removePlugin(plugins: PluginSpec[], name: string): PluginSpec[] {
  return plugins.filter((p) => p.name !== name);
}

export interface UpsertAiProviderInput {
  slug: string;
  preset: ProviderPresetId;
  baseUrl: string;
  authKind: ProviderAuthKind;
  keyRefs: string[]; // `secret:...` or `env:...`
  awsAccessKeyRef?: string;
  awsSecretKeyRef?: string;
  region?: string;
  apiVersion?: string;
  vertexProject?: string;
  vertexLocation?: string;
  dropParams?: boolean;
  seedDefaultRule?: boolean;
}

export async function saveAiProvider(
  clusterSlug: string,
  resources: TopologyResource[],
  input: UpsertAiProviderInput
): Promise<void> {
  const cleanSlug = slugify(input.slug);
  const existingUpstream = resources.find((r) => r.kind === 'upstream' && r.slug === cleanSlug);
  const existingUpSpec = asObj(existingUpstream?.spec);

  // 1. Upsert backing upstream pool
  await api.upsertResource(
    clusterSlug,
    'upstream',
    cleanSlug,
    {
      ...existingUpSpec,
      name: cleanSlug,
      endpoints: [input.baseUrl.trim()],
      connect_timeout_ms:
        typeof existingUpSpec.connect_timeout_ms === 'number'
          ? existingUpSpec.connect_timeout_ms
          : 5000,
    },
    { etag: existingUpstream?.etag }
  );

  // 2. Build ai-provider-adapter entry
  const providerEntry: Record<string, unknown> = {};
  if (input.preset === 'custom') {
    providerEntry.dialect = 'openai_compatible';
  } else {
    providerEntry.preset = input.preset;
  }

  if (input.authKind === 'aws_sigv4') {
    providerEntry.auth = {
      type: 'aws_sigv4',
      access_key_id: input.awsAccessKeyRef || 'env:AWS_ACCESS_KEY_ID',
      secret_access_key: input.awsSecretKeyRef || 'env:AWS_SECRET_ACCESS_KEY',
    };
  } else if (input.authKind === 'client_passthrough') {
    providerEntry.auth = { type: 'client_passthrough' };
  } else if (input.authKind === 'none') {
    providerEntry.auth = { type: 'none' };
  } else if (input.keyRefs.length > 1) {
    providerEntry.api_keys = input.keyRefs;
    providerEntry.key_cooldown_ms = 30000;
  } else if (input.keyRefs.length === 1) {
    providerEntry.api_key = input.keyRefs[0];
  }

  if (input.region?.trim()) providerEntry.region = input.region.trim();
  if (input.apiVersion?.trim()) providerEntry.api_version = input.apiVersion.trim();
  if (input.vertexProject?.trim()) providerEntry.vertex_project = input.vertexProject.trim();
  if (input.vertexLocation?.trim()) providerEntry.vertex_location = input.vertexLocation.trim();
  if (input.dropParams) providerEntry.drop_params = true;

  // 3. Ensure or update `/v1` AI route
  const aiRoute = findAiRoute(resources);
  const routeSpec: RouteSpec = aiRoute
    ? { ...(asObj(aiRoute.spec) as RouteSpec) }
    : {
        id: 'ai-gateway',
        path_prefix: '/v1',
        methods: ['GET', 'POST'],
        upstream: cleanSlug,
        max_body_bytes: 2097152,
        response_headers_timeout_ms: 60000,
        idle_chunk_timeout_ms: 30000,
        plugins: [],
      };

  let plugins = asPlugins(routeSpec);

  // Ensure ai-provider-adapter
  const existingAdapter = asObj(plugins.find((p) => p.name === 'ai-provider-adapter')?.config);
  const existingProviders = asObj(existingAdapter.providers);
  plugins = upsertPlugin(
    plugins,
    'ai-provider-adapter',
    {
      ...existingAdapter,
      response_headers: existingAdapter.response_headers ?? true,
      providers: {
        ...existingProviders,
        [cleanSlug]: providerEntry,
      },
    },
    AI_PLUGIN_ORDER
  );

  // Ensure ai-model-router + seed friendly default pattern rule on first add
  const existingRouter = asObj(plugins.find((p) => p.name === 'ai-model-router')?.config);
  const existingModels = asObj(existingRouter.models);
  const existingRules = Array.isArray(existingRouter.rules)
    ? [...(existingRouter.rules as Record<string, unknown>[])]
    : [];
  const existingExposed = Array.isArray(existingRouter.exposed_models)
    ? [...existingRouter.exposed_models.map(String)]
    : [];

  const presetMeta = getPresetMeta(input.preset);
  if (input.seedDefaultRule !== false) {
    if (
      presetMeta.defaultModelPattern &&
      !existingRules.some((r) => String(asObj(r).pattern) === presetMeta.defaultModelPattern)
    ) {
      existingRules.push({
        pattern: presetMeta.defaultModelPattern,
        targets: [{ provider: cleanSlug, upstream: cleanSlug }],
      });
    }
    if (presetMeta.popularModels[0] && !existingExposed.includes(presetMeta.popularModels[0])) {
      existingExposed.push(presetMeta.popularModels[0]);
    }
    // If router has zero models & zero rules (e.g. Ollama/Custom), create a clean default alias
    if (Object.keys(existingModels).length === 0 && existingRules.length === 0) {
      const modelId = presetMeta.popularModels[0] || 'default';
      existingModels[cleanSlug] = [{ provider: cleanSlug, upstream: cleanSlug, model: modelId }];
    }
  }

  plugins = upsertPlugin(
    plugins,
    'ai-model-router',
    {
      auto_max_attempts: true,
      serve_models_endpoint: true,
      serve_count_tokens_endpoint: true,
      ...existingRouter,
      exposed_models: existingExposed,
      models: existingModels,
      rules: existingRules,
    },
    AI_PLUGIN_ORDER
  );

  // Enable failover + usage tracker by default when provisioning fresh AI route
  if (!aiRoute) {
    plugins = upsertPlugin(
      plugins,
      'ai-failover',
      {
        retry_statuses: [429, 500, 502, 503, 504, 529],
        cooldown_ms: 30000,
        respect_retry_after: true,
      },
      AI_PLUGIN_ORDER
    );
    plugins = upsertPlugin(plugins, 'ai-usage-tracker', { log_usage: true }, AI_PLUGIN_ORDER);
  }

  routeSpec.plugins = plugins;
  if (!routeSpec.upstream) routeSpec.upstream = cleanSlug;

  await api.upsertResource(clusterSlug, 'route', aiRoute?.slug || 'ai-gateway', routeSpec, {
    etag: aiRoute?.etag,
  });
}

export async function deleteAiProvider(
  clusterSlug: string,
  resources: TopologyResource[],
  providerSlug: string
): Promise<void> {
  const aiRoute = findAiRoute(resources);
  if (aiRoute) {
    const routeSpec: RouteSpec = { ...(asObj(aiRoute.spec) as RouteSpec) };
    let plugins = asPlugins(routeSpec);

    const adapterCfg = asObj(plugins.find((p) => p.name === 'ai-provider-adapter')?.config);
    const nextProviders = { ...asObj(adapterCfg.providers) };
    delete nextProviders[providerSlug];
    const remainingSlugs = Object.keys(nextProviders);

    if (remainingSlugs.length === 0) {
      await api.deleteResource(clusterSlug, 'route', aiRoute.slug, aiRoute.etag);
    } else {
      // Clean targets referencing removed provider
      const routerCfg = asObj(plugins.find((p) => p.name === 'ai-model-router')?.config);
      const nextModels: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(asObj(routerCfg.models))) {
        if (Array.isArray(v)) {
          const kept = v.filter((t) => String(asObj(t).provider) !== providerSlug);
          if (kept.length > 0) nextModels[k] = kept;
        } else if (v && typeof v === 'object') {
          const vo = asObj(v);
          const kept = (Array.isArray(vo.targets) ? vo.targets : []).filter(
            (t) => String(asObj(t).provider) !== providerSlug
          );
          if (kept.length > 0) nextModels[k] = { ...vo, targets: kept };
        }
      }
      const nextRules = (Array.isArray(routerCfg.rules) ? routerCfg.rules : [])
        .map((r) => {
          const ro = asObj(r);
          const kept = (Array.isArray(ro.targets) ? ro.targets : []).filter(
            (t) => String(asObj(t).provider) !== providerSlug
          );
          return kept.length > 0 ? { ...ro, targets: kept } : null;
        })
        .filter(Boolean);

      plugins = upsertPlugin(
        plugins,
        'ai-provider-adapter',
        { ...adapterCfg, providers: nextProviders },
        AI_PLUGIN_ORDER
      );
      plugins = upsertPlugin(
        plugins,
        'ai-model-router',
        { ...routerCfg, models: nextModels, rules: nextRules },
        AI_PLUGIN_ORDER
      );
      routeSpec.plugins = plugins;
      if (routeSpec.upstream === providerSlug) {
        routeSpec.upstream = remainingSlugs[0];
      }
      await api.upsertResource(clusterSlug, 'route', aiRoute.slug, routeSpec, {
        etag: aiRoute.etag,
      });
    }
  }

  const upstream = resources.find((r) => r.kind === 'upstream' && r.slug === providerSlug);
  if (upstream) {
    await api.deleteResource(clusterSlug, 'upstream', upstream.slug, upstream.etag);
  }
}

export async function saveAiModelEntry(
  clusterSlug: string,
  resources: TopologyResource[],
  entry: AiModelAliasView,
  previous?: { name: string; kind: 'alias' | 'rule' }
): Promise<void> {
  const aiRoute = findAiRoute(resources);
  if (!aiRoute) throw new Error('Add at least one AI provider before defining models.');

  const routeSpec: RouteSpec = { ...(asObj(aiRoute.spec) as RouteSpec) };
  let plugins = asPlugins(routeSpec);
  const routerCfg = asObj(plugins.find((p) => p.name === 'ai-model-router')?.config);
  const nextModels = { ...asObj(routerCfg.models) };
  let nextRules = Array.isArray(routerCfg.rules) ? [...(routerCfg.rules as Record<string, unknown>[])] : [];

  if (previous) {
    if (previous.kind === 'alias') {
      delete nextModels[previous.name];
    } else {
      nextRules = nextRules.filter((r) => String(asObj(r).pattern) !== previous.name);
    }
  }

  const cleanTargets = entry.targets.map((t) => {
    const out: Record<string, unknown> = {
      provider: t.provider,
      upstream: t.upstream || t.provider,
    };
    if (t.model?.trim()) out.model = t.model.trim();
    if (t.weight && t.weight > 1) out.weight = t.weight;
    if (t.capabilities && t.capabilities.length > 0) out.capabilities = t.capabilities;
    return out;
  });

  if (entry.kind === 'alias') {
    nextModels[entry.name.trim()] =
      entry.strategy === 'priority'
        ? cleanTargets
        : { strategy: entry.strategy, targets: cleanTargets };
  } else {
    nextRules = nextRules.filter((r) => String(asObj(r).pattern) !== entry.name.trim());
    nextRules.push({
      pattern: entry.name.trim(),
      ...(entry.strategy !== 'priority' ? { strategy: entry.strategy } : {}),
      targets: cleanTargets,
    });
  }

  plugins = upsertPlugin(
    plugins,
    'ai-model-router',
    {
      ...routerCfg,
      models: nextModels,
      rules: nextRules,
    },
    AI_PLUGIN_ORDER
  );
  routeSpec.plugins = plugins;

  await api.upsertResource(clusterSlug, 'route', aiRoute.slug, routeSpec, { etag: aiRoute.etag });
}

export async function deleteAiModelEntry(
  clusterSlug: string,
  resources: TopologyResource[],
  entry: { name: string; kind: 'alias' | 'rule' }
): Promise<void> {
  const aiRoute = findAiRoute(resources);
  if (!aiRoute) return;
  const routeSpec: RouteSpec = { ...(asObj(aiRoute.spec) as RouteSpec) };
  let plugins = asPlugins(routeSpec);
  const routerCfg = asObj(plugins.find((p) => p.name === 'ai-model-router')?.config);
  const nextModels = { ...asObj(routerCfg.models) };
  let nextRules = Array.isArray(routerCfg.rules) ? [...(routerCfg.rules as Record<string, unknown>[])] : [];

  if (entry.kind === 'alias') {
    delete nextModels[entry.name];
  } else {
    nextRules = nextRules.filter((r) => String(asObj(r).pattern) !== entry.name);
  }

  plugins = upsertPlugin(
    plugins,
    'ai-model-router',
    { ...routerCfg, models: nextModels, rules: nextRules },
    AI_PLUGIN_ORDER
  );
  routeSpec.plugins = plugins;
  await api.upsertResource(clusterSlug, 'route', aiRoute.slug, routeSpec, { etag: aiRoute.etag });
}

export async function saveAiProtection(
  clusterSlug: string,
  resources: TopologyResource[],
  next: AiProtectionView
): Promise<void> {
  const aiRoute = findAiRoute(resources);
  if (!aiRoute) throw new Error('Add at least one AI provider first to enable AI protection.');

  const routeSpec: RouteSpec = { ...(asObj(aiRoute.spec) as RouteSpec) };
  let plugins = asPlugins(routeSpec);

  // 1. ai-virtual-keys (wired to Channel 2 `ai.virtual_keys`)
  if (next.virtualKeysEnabled) {
    const existing = asObj(plugins.find((p) => p.name === 'ai-virtual-keys')?.config);
    plugins = upsertPlugin(
      plugins,
      'ai-virtual-keys',
      {
        strip_key_header: true,
        accept_bearer: true,
        accept_x_api_key: true,
        ...existing,
        sync_namespace: next.virtualKeysSyncNamespace || 'ai.virtual_keys',
      },
      AI_PLUGIN_ORDER
    );
  } else {
    plugins = removePlugin(plugins, 'ai-virtual-keys');
  }

  // 2. ai-guardrails
  if (next.guardrailsEnabled) {
    const existing = asObj(plugins.find((p) => p.name === 'ai-guardrails')?.config);
    plugins = upsertPlugin(
      plugins,
      'ai-guardrails',
      {
        direction: 'both',
        redaction_mode: 'mask',
        on_stream_violation: 'redact_and_stop',
        ...existing,
        presets: next.guardrailsPresets.length > 0 ? next.guardrailsPresets : ['pii', 'secrets'],
        action: next.guardrailsAction,
      },
      AI_PLUGIN_ORDER
    );
  } else {
    plugins = removePlugin(plugins, 'ai-guardrails');
  }

  // 3. ai-cache
  if (next.cacheEnabled) {
    const existing = asObj(plugins.find((p) => p.name === 'ai-cache')?.config);
    plugins = upsertPlugin(
      plugins,
      'ai-cache',
      {
        scope: 'virtual_key',
        require_deterministic: true,
        ...existing,
        ttl_secs: Math.max(1, next.cacheTtlSecs),
        cache_streaming: next.cacheStreaming,
      },
      AI_PLUGIN_ORDER
    );
  } else {
    plugins = removePlugin(plugins, 'ai-cache');
  }

  // 4. ai-token-rate-limit
  if (next.rateLimitEnabled) {
    const existing = asObj(plugins.find((p) => p.name === 'ai-token-rate-limit')?.config);
    plugins = upsertPlugin(
      plugins,
      'ai-token-rate-limit',
      {
        window_secs: 60,
        key_by: 'virtual_key',
        reconcile_usage: true,
        ...existing,
        rpm: Math.max(1, next.rateLimitRpm),
        tpm: Math.max(100, next.rateLimitTpm),
      },
      AI_PLUGIN_ORDER
    );
  } else {
    plugins = removePlugin(plugins, 'ai-token-rate-limit');
  }

  // 5. ai-budget
  if (next.budgetEnabled) {
    const existing = asObj(plugins.find((p) => p.name === 'ai-budget')?.config);
    plugins = upsertPlugin(
      plugins,
      'ai-budget',
      {
        scope: 'virtual_key',
        soft_warning_ratio: 0.8,
        use_builtin_pricing: true,
        ...existing,
        window: next.budgetWindow,
        mode: next.budgetMode,
        default_limit_usd: Math.max(0.01, next.budgetDefaultUsd),
      },
      AI_PLUGIN_ORDER
    );
  } else {
    plugins = removePlugin(plugins, 'ai-budget');
  }

  // 6. ai-failover
  if (next.failoverEnabled) {
    const existing = asObj(plugins.find((p) => p.name === 'ai-failover')?.config);
    plugins = upsertPlugin(
      plugins,
      'ai-failover',
      {
        respect_retry_after: true,
        ...existing,
        retry_statuses: next.failoverRetries,
        cooldown_ms: Math.max(1000, next.failoverCooldownMs),
      },
      AI_PLUGIN_ORDER
    );
  } else {
    plugins = removePlugin(plugins, 'ai-failover');
  }

  // 7. ai-usage-tracker
  if (next.usageTrackerEnabled) {
    const existing = asObj(plugins.find((p) => p.name === 'ai-usage-tracker')?.config);
    plugins = upsertPlugin(
      plugins,
      'ai-usage-tracker',
      { log_usage: true, ...existing },
      AI_PLUGIN_ORDER
    );
  } else {
    plugins = removePlugin(plugins, 'ai-usage-tracker');
  }

  routeSpec.plugins = sortPluginsCanonically(plugins, AI_PLUGIN_ORDER);
  await api.upsertResource(clusterSlug, 'route', aiRoute.slug, routeSpec, { etag: aiRoute.etag });
}

// =============================================================================
// MCP Gateway Synthesizers
// =============================================================================

const MCP_PLUGIN_ORDER = [
  'mcp-auth',
  'mcp-router',
  'mcp-guardrails',
  'mcp-rate-limit',
  'mcp-telemetry',
];

export async function saveMcpServer(
  clusterSlug: string,
  resources: TopologyResource[],
  input: {
    slug: string;
    baseUrl: string;
    path: string;
    authType: 'none' | 'bearer' | 'header';
    authHeader?: string;
    authKeyRef?: string;
    stateful: boolean;
    resourcePrefixes: string[];
    description?: string;
    enabled: boolean;
  }
): Promise<void> {
  const cleanSlug = slugify(input.slug);
  const upstreamName = `mcp-${cleanSlug}`;
  const existingUpstream = resources.find((r) => r.kind === 'upstream' && r.slug === upstreamName);

  await api.upsertResource(
    clusterSlug,
    'upstream',
    upstreamName,
    {
      ...asObj(existingUpstream?.spec),
      name: upstreamName,
      endpoints: [input.baseUrl.trim()],
      connect_timeout_ms: 5000,
    },
    { etag: existingUpstream?.etag }
  );

  const mcpRoute = findMcpRoute(resources);
  const routeSpec: RouteSpec = mcpRoute
    ? { ...(asObj(mcpRoute.spec) as RouteSpec) }
    : {
        id: 'mcp-gateway',
        path_prefix: '/mcp',
        methods: ['GET', 'POST', 'DELETE'],
        upstream: upstreamName,
        max_body_bytes: 2097152,
        response_headers_timeout_ms: 30000,
        idle_chunk_timeout_ms: 60000,
        plugins: [],
      };

  let plugins = asPlugins(routeSpec);
  const existingRouter = asObj(plugins.find((p) => p.name === 'mcp-router')?.config);
  const existingServers = { ...asObj(existingRouter.servers) };

  const serverEntry: Record<string, unknown> = {
    upstream: upstreamName,
    path: input.path.trim() || '/mcp',
    stateful: input.stateful,
    enabled: input.enabled,
  };
  if (input.resourcePrefixes.length > 0) serverEntry.resource_prefixes = input.resourcePrefixes;
  if (input.description?.trim()) serverEntry.description = input.description.trim();

  if (input.authType === 'bearer' && input.authKeyRef) {
    serverEntry.auth = { type: 'bearer', api_key: input.authKeyRef };
  } else if (input.authType === 'header' && input.authKeyRef) {
    serverEntry.auth = {
      type: 'header',
      header: input.authHeader?.trim() || 'x-api-key',
      api_key: input.authKeyRef,
    };
  }

  existingServers[cleanSlug] = serverEntry;

  plugins = upsertPlugin(
    plugins,
    'mcp-router',
    {
      max_body_bytes: 2097152,
      namespace_separator: '__',
      server_name: 'shunt-mcp-gateway',
      response_headers: true,
      ...existingRouter,
      servers: existingServers,
    },
    MCP_PLUGIN_ORDER
  );

  if (!mcpRoute) {
    plugins = upsertPlugin(
      plugins,
      'mcp-auth',
      {
        strip_key_header: true,
        bind_session_to_principal: true,
        sync_namespace: 'mcp.agent_acls',
        kill_switch_namespace: 'mcp.kill_switch',
      },
      MCP_PLUGIN_ORDER
    );
    plugins = upsertPlugin(plugins, 'mcp-telemetry', { log_calls: true }, MCP_PLUGIN_ORDER);
  }

  routeSpec.plugins = sortPluginsCanonically(plugins, MCP_PLUGIN_ORDER);
  if (!routeSpec.upstream) routeSpec.upstream = upstreamName;

  await api.upsertResource(clusterSlug, 'route', mcpRoute?.slug || 'mcp-gateway', routeSpec, {
    etag: mcpRoute?.etag,
  });
}

export async function deleteMcpServer(
  clusterSlug: string,
  resources: TopologyResource[],
  serverSlug: string
): Promise<void> {
  const mcpRoute = findMcpRoute(resources);
  const upstreamName = `mcp-${serverSlug}`;
  if (mcpRoute) {
    const routeSpec: RouteSpec = { ...(asObj(mcpRoute.spec) as RouteSpec) };
    let plugins = asPlugins(routeSpec);
    const routerCfg = asObj(plugins.find((p) => p.name === 'mcp-router')?.config);
    const nextServers = { ...asObj(routerCfg.servers) };
    delete nextServers[serverSlug];
    const remaining = Object.keys(nextServers);

    if (remaining.length === 0) {
      await api.deleteResource(clusterSlug, 'route', mcpRoute.slug, mcpRoute.etag);
    } else {
      plugins = upsertPlugin(
        plugins,
        'mcp-router',
        { ...routerCfg, servers: nextServers },
        MCP_PLUGIN_ORDER
      );
      routeSpec.plugins = plugins;
      if (routeSpec.upstream === upstreamName) {
        const firstServer = asObj(nextServers[remaining[0]]);
        routeSpec.upstream = String(firstServer.upstream || `mcp-${remaining[0]}`);
      }
      await api.upsertResource(clusterSlug, 'route', mcpRoute.slug, routeSpec, {
        etag: mcpRoute.etag,
      });
    }
  }

  const up = resources.find((r) => r.kind === 'upstream' && r.slug === upstreamName);
  if (up) {
    await api.deleteResource(clusterSlug, 'upstream', up.slug, up.etag);
  }
}

export async function saveMcpProtection(
  clusterSlug: string,
  resources: TopologyResource[],
  next: McpProtectionView
): Promise<void> {
  const mcpRoute = findMcpRoute(resources);
  if (!mcpRoute) throw new Error('Add at least one MCP server first.');

  const routeSpec: RouteSpec = { ...(asObj(mcpRoute.spec) as RouteSpec) };
  let plugins = asPlugins(routeSpec);

  if (next.authEnabled) {
    const existing = asObj(plugins.find((p) => p.name === 'mcp-auth')?.config);
    plugins = upsertPlugin(
      plugins,
      'mcp-auth',
      {
        strip_key_header: true,
        bind_session_to_principal: true,
        ...existing,
        sync_namespace: 'mcp.agent_acls',
        kill_switch_namespace: 'mcp.kill_switch',
      },
      MCP_PLUGIN_ORDER
    );
  } else {
    plugins = removePlugin(plugins, 'mcp-auth');
  }

  if (next.guardrailsEnabled) {
    const existing = asObj(plugins.find((p) => p.name === 'mcp-guardrails')?.config);
    plugins = upsertPlugin(
      plugins,
      'mcp-guardrails',
      {
        argument_action: 'redact',
        response_action: 'block',
        ...existing,
        argument_detectors: next.argumentDetectors,
        response_detectors: next.responseDetectors,
        denied_tools: next.deniedTools,
        require_approval_tools: next.requireApprovalTools,
      },
      MCP_PLUGIN_ORDER
    );
  } else {
    plugins = removePlugin(plugins, 'mcp-guardrails');
  }

  if (next.rateLimitEnabled) {
    const existing = asObj(plugins.find((p) => p.name === 'mcp-rate-limit')?.config);
    const rlCfg: Record<string, unknown> = {
      window_secs: 60,
      ...existing,
      rpm: Math.max(1, next.rpm),
      tool_rpm: Math.max(1, next.toolRpm),
      max_calls_per_session: Math.max(1, next.maxCallsPerSession),
    };
    if (next.loopBreakerEnabled) {
      rlCfg.loop_breaker = {
        max_repeats: Math.max(1, next.loopBreakerMaxRepeats),
        window_secs: 60,
      };
    } else {
      delete rlCfg.loop_breaker;
    }
    plugins = upsertPlugin(plugins, 'mcp-rate-limit', rlCfg, MCP_PLUGIN_ORDER);
  } else {
    plugins = removePlugin(plugins, 'mcp-rate-limit');
  }

  if (next.telemetryEnabled) {
    const existing = asObj(plugins.find((p) => p.name === 'mcp-telemetry')?.config);
    plugins = upsertPlugin(
      plugins,
      'mcp-telemetry',
      { log_calls: true, inspect_tool_errors: true, ...existing },
      MCP_PLUGIN_ORDER
    );
  } else {
    plugins = removePlugin(plugins, 'mcp-telemetry');
  }

  routeSpec.plugins = sortPluginsCanonically(plugins, MCP_PLUGIN_ORDER);
  await api.upsertResource(clusterSlug, 'route', mcpRoute.slug, routeSpec, { etag: mcpRoute.etag });
}
