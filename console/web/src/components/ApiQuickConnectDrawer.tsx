import { useEffect, useMemo, useState } from 'react';
import { Code2, Sparkles, Terminal } from 'lucide-react';
import { TopologyResource } from '../lib/api';
import {
  extractAiGatewayState,
  extractMcpGatewayState,
  getGatewayListenPort,
} from '../lib/gateway';
import { CopyButton, Drawer, SegmentedTabs, TagPill } from './ui';

type ClientKind = 'openai_py' | 'openai_js' | 'anthropic' | 'curl' | 'mcp';

export function ApiQuickConnectDrawer({
  open,
  onClose,
  resources,
  clusterSlug,
  initialTab = 'openai_py',
  prefillKey,
}: {
  open: boolean;
  onClose: () => void;
  resources: TopologyResource[];
  clusterSlug: string;
  initialTab?: ClientKind;
  prefillKey?: string;
}) {
  const ai = useMemo(() => extractAiGatewayState(resources), [resources]);
  const mcp = useMemo(() => extractMcpGatewayState(resources), [resources]);
  const listenPort = useMemo(() => getGatewayListenPort(resources), [resources]);

  const modelChoices = useMemo(() => {
    const set = new Set<string>();
    for (const m of ai.models) {
      if (m.kind === 'alias') set.add(m.name);
    }
    for (const m of ai.exposedModels) set.add(m);
    if (set.size === 0) set.add('gpt-4o');
    return Array.from(set);
  }, [ai]);

  const [tab, setTab] = useState<ClientKind>(initialTab);
  const [gatewayHost, setGatewayHost] = useState(`http://127.0.0.1:${listenPort}`);
  const [model, setModel] = useState(modelChoices[0] || 'gpt-4o');
  const [apiKey, setApiKey] = useState(prefillKey || 'sk-shunt-your-virtual-key');

  useEffect(() => {
    if (prefillKey) setApiKey(prefillKey);
  }, [prefillKey]);

  useEffect(() => {
    setGatewayHost(`http://127.0.0.1:${listenPort}`);
  }, [listenPort]);

  const cleanHost = gatewayHost.trim().replace(/\/+$/, '') || `http://127.0.0.1:${listenPort}`;
  const activeModel = modelChoices.includes(model) ? model : modelChoices[0] || 'gpt-4o';
  const keyVal = apiKey.trim() || 'sk-shunt-your-virtual-key';

  const snippet = useMemo(() => {
    switch (tab) {
      case 'openai_py':
        return `from openai import OpenAI

client = OpenAI(
    base_url="${cleanHost}/v1",
    api_key="${keyVal}",
)

response = client.chat.completions.create(
    model="${activeModel}",
    messages=[{"role": "user", "content": "Hello via Shunt AI Gateway!"}],
)
print(response.choices[0].message.content)`;

      case 'openai_js':
        return `import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "${cleanHost}/v1",
  apiKey: "${keyVal}",
});

const response = await client.chat.completions.create({
  model: "${activeModel}",
  messages: [{ role: "user", content: "Hello via Shunt AI Gateway!" }],
});
console.log(response.choices[0].message.content);`;

      case 'anthropic':
        return `# Works with Claude Code & Anthropic SDKs directly against Shunt /v1/messages
export ANTHROPIC_BASE_URL="${cleanHost}"
export ANTHROPIC_API_KEY="${keyVal}"

# Or with the Anthropic Python SDK:
# client = anthropic.Anthropic(base_url="${cleanHost}", api_key="${keyVal}")
claude`;

      case 'curl':
        return `curl ${cleanHost}/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer ${keyVal}" \\
  -d '{
    "model": "${activeModel}",
    "messages": [{"role": "user", "content": "Say hello in one sentence."}]
  }'`;

      case 'mcp':
        return `{
  "mcpServers": {
    "shunt-${clusterSlug}": {
      "type": "http",
      "url": "${cleanHost}${mcp.routePath}",
      "headers": {
        "Authorization": "Bearer ${keyVal.startsWith('sk-mcp-') ? keyVal : 'sk-mcp-your-agent-key'}"
      }
    }
  }
}`;
    }
  }, [tab, cleanHost, keyVal, activeModel, clusterSlug, mcp.routePath]);

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title="Use Your Gateway"
      subtitle={`Point any OpenAI, Anthropic, or MCP client directly at cluster "${clusterSlug}".`}
      widthClass="max-w-2xl"
    >
      <div className="space-y-5">
        {/* Live Endpoint Summary */}
        <div className="card-subtle p-4 space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                Gateway Data-Plane URL
              </label>
              <input
                className="input-base mono text-[13px]"
                value={gatewayHost}
                onChange={(e) => setGatewayHost(e.target.value)}
                placeholder={`http://127.0.0.1:${listenPort}`}
              />
            </div>
            {tab !== 'mcp' && (
              <div>
                <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                  Model / Alias
                </label>
                <select
                  className="input-base mono text-[13px]"
                  value={activeModel}
                  onChange={(e) => setModel(e.target.value)}
                >
                  {modelChoices.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-[12px] font-medium" style={{ color: 'var(--ink-secondary)' }}>
                {tab === 'mcp' ? 'Agent Key' : 'Virtual API Key'}
              </label>
              <span className="text-[11.5px]" style={{ color: 'var(--ink-muted)' }}>
                {ai.protection.virtualKeysEnabled
                  ? 'Virtual Key Auth is enabled'
                  : 'Optional while Virtual Key Auth is off'}
              </span>
            </div>
            <input
              className="input-base mono text-[13px]"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="sk-shunt-..."
            />
          </div>
        </div>

        {/* Protocol Switcher */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <SegmentedTabs
            value={tab}
            onChange={setTab}
            items={[
              { id: 'openai_py', label: 'Python' },
              { id: 'openai_js', label: 'TypeScript' },
              { id: 'anthropic', label: 'Claude Code' },
              { id: 'curl', label: 'cURL' },
              { id: 'mcp', label: 'MCP JSON' },
            ]}
          />
          <CopyButton text={snippet} label="Copy snippet" />
        </div>

        <pre className="code-block m-0">{snippet}</pre>

        {/* Supported Unified Endpoints Reference */}
        <div className="pt-2 space-y-2.5" style={{ borderTop: '1px solid var(--border-row)' }}>
          <div className="flex items-center gap-2 text-[12px] font-medium" style={{ color: 'var(--ink-muted)' }}>
            <Sparkles size={13} style={{ color: 'var(--brand)' }} />
            <span>Unified endpoints exposed by Shunt on {cleanHost}</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            <TagPill mono dot="brand">POST /v1/chat/completions</TagPill>
            <TagPill mono dot="brand">POST /v1/messages</TagPill>
            <TagPill mono dot="brand">POST /v1/responses</TagPill>
            <TagPill mono dot="info">POST /v1/embeddings</TagPill>
            <TagPill mono dot="ok">GET /v1/models</TagPill>
            <TagPill mono dot="neutral">POST {mcp.routePath}</TagPill>
          </div>
          <div className="flex items-center gap-2 text-[12px] pt-1" style={{ color: 'var(--ink-muted)' }}>
            <Terminal size={12} />
            <span>
              {ai.providers.length > 0
                ? `${ai.providers.length} AI provider${ai.providers.length === 1 ? '' : 's'} configured (${ai.providers.map((p) => p.slug).join(', ')}).`
                : 'Add an AI provider in AI Gateway and publish a release to start routing.'}
            </span>
          </div>
        </div>

        <div className="flex justify-end pt-1">
          <button type="button" className="btn btn-primary" onClick={onClose}>
            <Code2 size={14} />
            <span>Done</span>
          </button>
        </div>
      </div>
    </Drawer>
  );
}
