import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertOctagon,
  Blocks,
  Bot,
  Check,
  Gauge,
  Lock,
  Plus,
  Shield,
  ShieldAlert,
  Trash2,
  Zap,
} from 'lucide-react';
import {
  api,
  ApiProblemError,
  Cluster,
  ControlStateItem,
  formatRelativeTime,
  Organization,
  SecretMeta,
  slugify,
  TopologyResource,
} from '../lib/api';
import { generatePlaintextKey, keyDisplayPrefix, sha256Prefixed } from '../lib/crypto';
import {
  deleteMcpServer,
  extractMcpGatewayState,
  McpProtectionView,
  McpServerView,
  saveMcpProtection,
  saveMcpServer,
} from '../lib/gateway';
import { ClusterHeaderContext, PageHeader } from '../components/PageHeader';
import {
  CopyButton,
  Drawer,
  EmptyState,
  FeatureToggleRow,
  Modal,
  SearchField,
  SegmentedTabs,
  StatusIndicator,
  TagPill,
  ToggleSwitch,
  useToast,
} from '../components/ui';

type McpTab = 'servers' | 'agents' | 'protection' | 'killswitch';

interface McpAgentRecord {
  id: string;
  enabled: boolean;
  team?: string;
  key_prefix?: string;
  key_hashes: string[];
  allowed_servers: string[];
  allowed_tools: string[];
  denied_tools: string[];
  rpm?: number;
  tool_rpm?: number;
}

interface KillSwitchEntry {
  id: string;
  scope: 'principal' | 'session';
  target: string;
  reason: string;
  updated_at: string;
}

function parseAgent(item: ControlStateItem): McpAgentRecord {
  const p = (item.payload && typeof item.payload === 'object' ? item.payload : {}) as Record<string, unknown>;
  return {
    id: item.item_key,
    enabled: p.enabled !== false,
    team: typeof p.team === 'string' ? p.team : undefined,
    key_prefix: typeof p.key_prefix === 'string' ? p.key_prefix : undefined,
    key_hashes: Array.isArray(p.key_hashes) ? p.key_hashes.map(String) : [],
    allowed_servers: Array.isArray(p.allowed_servers) ? p.allowed_servers.map(String) : [],
    allowed_tools: Array.isArray(p.allowed_tools) ? p.allowed_tools.map(String) : [],
    denied_tools: Array.isArray(p.denied_tools) ? p.denied_tools.map(String) : [],
    rpm: typeof p.rpm === 'number' ? p.rpm : undefined,
    tool_rpm: typeof p.tool_rpm === 'number' ? p.tool_rpm : undefined,
  };
}

function parseKillSwitch(item: ControlStateItem): KillSwitchEntry {
  const p = (item.payload && typeof item.payload === 'object' ? item.payload : {}) as Record<string, unknown>;
  return {
    id: item.item_key,
    scope: p.scope === 'session' ? 'session' : 'principal',
    target: String(p.target || '*'),
    reason: String(p.reason || 'Emergency halt'),
    updated_at: item.updated_at,
  };
}

export function McpGatewayPage({
  org,
  cluster,
  headerCtx,
  resources,
  onChanged,
}: {
  org: Organization;
  cluster: Cluster;
  headerCtx: ClusterHeaderContext;
  resources: TopologyResource[];
  onChanged: () => Promise<void>;
}) {
  const toast = useToast();
  const mcp = useMemo(() => extractMcpGatewayState(resources), [resources]);

  const [tab, setTab] = useState<McpTab>('servers');
  const [search, setSearch] = useState('');
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [agentItems, setAgentItems] = useState<ControlStateItem[]>([]);
  const [killItems, setKillItems] = useState<ControlStateItem[]>([]);
  const [busy, setBusy] = useState(false);

  // Server Drawer
  const [srvOpen, setSrvOpen] = useState(false);
  const [editingSrv, setEditingSrv] = useState<string | null>(null);
  const [sSlug, setSSlug] = useState('');
  const [sBaseUrl, setSBaseUrl] = useState('http://127.0.0.1:8090');
  const [sPath, setSPath] = useState('/mcp');
  const [sAuthType, setSAuthType] = useState<'none' | 'bearer' | 'header'>('none');
  const [sAuthHeader, setSAuthHeader] = useState('x-api-key');
  const [sSecretInput, setSSecretInput] = useState('');
  const [sStateful, setSStateful] = useState(false);
  const [sDesc, setSDesc] = useState('');

  // Agent Drawer
  const [agentOpen, setAgentOpen] = useState(false);
  const [editingAgent, setEditingAgent] = useState<McpAgentRecord | null>(null);
  const [aId, setAId] = useState('');
  const [aTeam, setATeam] = useState('platform');
  const [aServers, setAServers] = useState<string[]>([]);
  const [aAllowTools, setAAllowTools] = useState('');
  const [aDenyTools, setADenyTools] = useState('*delete*, *drop*');
  const [aToolRpm, setAToolRpm] = useState('30');
  const [mintedAgentKey, setMintedAgentKey] = useState<{ id: string; plaintext: string } | null>(null);

  // Kill-Switch Modal
  const [ksOpen, setKsOpen] = useState(false);
  const [ksScope, setKsScope] = useState<'principal' | 'session'>('principal');
  const [ksTarget, setKsTarget] = useState('');
  const [ksReason, setKsReason] = useState('Suspected prompt injection or runaway tool loop');

  // Protection state
  const [prot, setProt] = useState<McpProtectionView>(mcp.protection);
  useEffect(() => {
    setProt(mcp.protection);
  }, [mcp.protection]);

  const loadAux = async () => {
    const [sec, ag, ks] = await Promise.all([
      api.listSecrets(org.slug).catch(() => []),
      api.getNamespaceState(cluster.slug, 'mcp.agent_acls').catch(() => null),
      api.getNamespaceState(cluster.slug, 'mcp.kill_switch').catch(() => null),
    ]);
    setSecrets(sec);
    setAgentItems(ag?.items || []);
    setKillItems(ks?.items || []);
  };

  useEffect(() => {
    loadAux();
  }, [org.slug, cluster.slug]);

  const agents = useMemo(() => agentItems.map(parseAgent), [agentItems]);
  const killRules = useMemo(() => killItems.map(parseKillSwitch), [killItems]);

  // Server actions
  const openNewServer = () => {
    setEditingSrv(null);
    setSSlug('');
    setSBaseUrl('http://127.0.0.1:8090');
    setSPath('/mcp');
    setSAuthType('none');
    setSAuthHeader('x-api-key');
    setSSecretInput('');
    setSStateful(false);
    setSDesc('');
    setSrvOpen(true);
  };

  const openEditServer = (s: McpServerView) => {
    setEditingSrv(s.slug);
    setSSlug(s.slug);
    setSBaseUrl(s.baseUrl);
    setSPath(s.path);
    setSAuthType(s.authType);
    setSAuthHeader(s.authHeader || 'x-api-key');
    setSSecretInput('');
    setSStateful(s.stateful);
    setSDesc(s.description || '');
    setSrvOpen(true);
  };

  const handleSaveServer = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanSlug = slugify(sSlug);
    if (!cleanSlug) return;
    setBusy(true);
    try {
      let authKeyRef: string | undefined;
      if (sAuthType !== 'none') {
        if (sSecretInput.trim()) {
          if (sSecretInput.trim().startsWith('env:') || sSecretInput.trim().startsWith('secret:')) {
            authKeyRef = sSecretInput.trim();
          } else {
            const secretSlug = slugify(`mcp-${cleanSlug}-token`);
            const existing = secrets.find((s) => s.slug === secretSlug);
            await api.upsertSecret(
              org.slug,
              secretSlug,
              {
                description: `Upstream MCP token for ${cleanSlug}`,
                scope_type: 'cluster',
                scope_id: cluster.id,
                delivery_mode: 'vault',
                value: sSecretInput.trim(),
              },
              existing?.etag
            );
            authKeyRef = `secret:${secretSlug}`;
          }
        } else if (editingSrv) {
          authKeyRef = mcp.servers.find((x) => x.slug === editingSrv)?.authKeyRef;
        }
      }

      await saveMcpServer(cluster.slug, resources, {
        slug: cleanSlug,
        baseUrl: sBaseUrl.trim(),
        path: sPath.trim() || '/mcp',
        authType: sAuthType,
        authHeader: sAuthType === 'header' ? sAuthHeader.trim() : undefined,
        authKeyRef,
        stateful: sStateful,
        resourcePrefixes: [],
        description: sDesc.trim() || undefined,
        enabled: true,
      });

      toast.push(editingSrv ? `Updated MCP server "${cleanSlug}"` : `Added MCP server "${cleanSlug}"`);
      setSrvOpen(false);
      await Promise.all([onChanged(), loadAux()]);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  const handleDeleteServer = async (s: McpServerView) => {
    if (!window.confirm(`Remove MCP server "${s.slug}" from draft?`)) return;
    setBusy(true);
    try {
      await deleteMcpServer(cluster.slug, resources, s.slug);
      toast.push(`Removed MCP server "${s.slug}"`);
      await onChanged();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  // Agent actions
  const openNewAgent = () => {
    setEditingAgent(null);
    setAId('');
    setATeam('platform');
    setAServers(mcp.servers.map((s) => s.slug));
    setAAllowTools('');
    setADenyTools('*delete*, *drop*');
    setAToolRpm('30');
    setAgentOpen(true);
  };

  const openEditAgent = (a: McpAgentRecord) => {
    setEditingAgent(a);
    setAId(a.id);
    setATeam(a.team || '');
    setAServers(a.allowed_servers);
    setAAllowTools(a.allowed_tools.join(', '));
    setADenyTools(a.denied_tools.join(', '));
    setAToolRpm(a.tool_rpm ? String(a.tool_rpm) : '');
    setAgentOpen(true);
  };

  const handleSaveAgent = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanId = editingAgent ? editingAgent.id : slugify(aId || `agent-${Date.now().toString(36).slice(-4)}`);
    setBusy(true);
    try {
      let plaintext: string | null = null;
      let keyHashes = editingAgent?.key_hashes || [];
      let prefix = editingAgent?.key_prefix;
      if (!editingAgent) {
        plaintext = generatePlaintextKey('sk-mcp-');
        keyHashes = [await sha256Prefixed(plaintext)];
        prefix = keyDisplayPrefix(plaintext);
      }

      const splitCsv = (raw: string) =>
        raw
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);

      await api.upsertStateItem(cluster.slug, 'mcp.agent_acls', cleanId, {
        id: cleanId,
        enabled: editingAgent ? editingAgent.enabled : true,
        team: aTeam.trim() || undefined,
        key_prefix: prefix,
        key_hashes: keyHashes,
        allowed_servers: aServers,
        allowed_tools: splitCsv(aAllowTools),
        denied_tools: splitCsv(aDenyTools),
        tool_rpm: Number(aToolRpm) > 0 ? Number(aToolRpm) : undefined,
      });

      setAgentOpen(false);
      await loadAux();
      if (plaintext) {
        setMintedAgentKey({ id: cleanId, plaintext });
        toast.push(`Minted MCP agent "${cleanId}" and synced fleet-wide`);
      } else {
        toast.push(`Updated agent "${cleanId}" across fleet`);
      }
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  const handleToggleAgent = async (a: McpAgentRecord, enabled: boolean) => {
    const raw = agentItems.find((i) => i.item_key === a.id);
    const prev = (raw?.payload && typeof raw.payload === 'object' ? raw.payload : {}) as Record<string, unknown>;
    await api.upsertStateItem(cluster.slug, 'mcp.agent_acls', a.id, { ...prev, enabled });
    toast.push(`${enabled ? 'Enabled' : 'Disabled'} agent "${a.id}" across fleet`);
    await loadAux();
  };

  const handleDeleteAgent = async (a: McpAgentRecord) => {
    if (!window.confirm(`Revoke MCP agent "${a.id}" immediately?`)) return;
    await api.deleteStateItem(cluster.slug, 'mcp.agent_acls', a.id);
    toast.push(`Revoked agent "${a.id}"`);
    await loadAux();
  };

  // Kill-Switch actions
  const handleTriggerKillSwitch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ksTarget.trim()) return;
    setBusy(true);
    try {
      const id = `ks_${slugify(ksTarget)}_${Date.now().toString(36).slice(-4)}`;
      await api.upsertStateItem(cluster.slug, 'mcp.kill_switch', id, {
        scope: ksScope,
        target: ksTarget.trim(),
        reason: ksReason.trim() || 'Emergency halt',
      });
      toast.push(`Kill-switch activated for ${ksScope} "${ksTarget.trim()}" across fleet`);
      setKsOpen(false);
      setKsTarget('');
      await loadAux();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  const handleLiftKillSwitch = async (rule: KillSwitchEntry) => {
    await api.deleteStateItem(cluster.slug, 'mcp.kill_switch', rule.id);
    toast.push(`Lifted kill-switch on "${rule.target}"`);
    await loadAux();
  };

  const persistProtection = async (next: McpProtectionView, label: string) => {
    setProt(next);
    setBusy(true);
    try {
      await saveMcpProtection(cluster.slug, resources, next);
      toast.push(label);
      await onChanged();
    } catch (err) {
      setProt(mcp.protection);
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  const q = search.trim().toLowerCase();
  const filteredServers = mcp.servers.filter(
    (s) => !q || s.slug.includes(q) || s.baseUrl.toLowerCase().includes(q)
  );
  const filteredAgents = agents.filter(
    (a) => !q || a.id.toLowerCase().includes(q) || (a.team || '').toLowerCase().includes(q)
  );

  const primaryAction =
    tab === 'servers' ? (
      <button type="button" className="btn btn-primary h-8" onClick={openNewServer}>
        <Plus size={14} />
        <span>Add server</span>
      </button>
    ) : tab === 'agents' ? (
      <button type="button" className="btn btn-primary h-8" onClick={openNewAgent}>
        <Plus size={14} />
        <span>New agent</span>
      </button>
    ) : tab === 'killswitch' ? (
      <button
        type="button"
        className="btn h-8"
        style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }}
        onClick={() => setKsOpen(true)}
      >
        <AlertOctagon size={14} />
        <span>Trigger Kill-Switch</span>
      </button>
    ) : null;

  return (
    <div>
      <PageHeader
        title="MCP Gateway"
        badge={
          <div className="flex items-center gap-1.5">
            {mcp.servers.length > 0 && (
              <TagPill mono dot="brand">
                {mcp.routePath}
              </TagPill>
            )}
            {killRules.length > 0 && (
              <TagPill dot="danger">
                {killRules.length} kill-switch active
              </TagPill>
            )}
          </div>
        }
        ctx={headerCtx}
        primaryAction={primaryAction}
        controlsLeft={
          <SegmentedTabs
            value={tab}
            onChange={setTab}
            items={[
              { id: 'servers', label: 'Servers', count: mcp.servers.length },
              { id: 'agents', label: 'Agents', count: agents.length },
              { id: 'protection', label: 'Protection' },
              { id: 'killswitch', label: 'Kill-Switch', count: killRules.length },
            ]}
          />
        }
        controlsRight={
          tab === 'servers' || tab === 'agents' ? (
            <SearchField
              value={search}
              onChange={setSearch}
              placeholder={tab === 'servers' ? 'Search MCP servers' : 'Search agents'}
            />
          ) : undefined
        }
      />

      {/* TAB 1: SERVERS */}
      {tab === 'servers' && (
        <div>
          {filteredServers.length === 0 ? (
            <EmptyState
              icon={<Blocks size={17} />}
              title="No MCP servers multiplexed yet"
              description="Register Streamable HTTP MCP servers (GitHub, Postgres, Jira, internal tools) behind a single governed /mcp endpoint with per-agent tool ACLs."
              action={
                <button type="button" className="btn btn-primary" onClick={openNewServer}>
                  <Plus size={14} />
                  <span>Add First MCP Server</span>
                </button>
              }
            />
          ) : (
            <div>
              {filteredServers.map((s) => (
                <div
                  key={s.slug}
                  className="row-item row-item-clickable"
                  onClick={() => openEditServer(s)}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="icon-tile">
                      <Blocks size={14} />
                    </div>
                    <span className="mono text-[13.5px] font-semibold shrink-0">{s.slug}</span>
                    <TagPill mono dot="info">
                      {s.slug}__*
                    </TagPill>
                    <TagPill dot={s.authType === 'none' ? 'neutral' : 'ok'}>
                      {s.authType === 'none' ? 'No auth' : s.authType}
                    </TagPill>
                    {s.stateful && <TagPill>stateful</TagPill>}
                  </div>
                  <div
                    className="flex items-center gap-4 shrink-0"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <span className="hidden lg:inline mono text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                      {s.baseUrl.replace(/^https?:\/\//, '')}
                      {s.path}
                    </span>
                    <StatusIndicator tone={s.enabled ? 'ok' : 'neutral'} label={s.enabled ? 'Active' : 'Disabled'} />
                    <button
                      type="button"
                      className="btn-ghost p-1.5"
                      style={{ color: 'var(--ink-muted)' }}
                      onClick={() => handleDeleteServer(s)}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: AGENTS */}
      {tab === 'agents' && (
        <div>
          {filteredAgents.length === 0 ? (
            <EmptyState
              icon={<Bot size={17} />}
              title="No MCP agents configured"
              description="Mint least-privilege agent credentials (sk-mcp-…) synced fleet-wide over Channel 2. Unauthorized tools are automatically hidden from tools/list."
              action={
                <button type="button" className="btn btn-primary" onClick={openNewAgent}>
                  <Plus size={14} />
                  <span>Create First Agent</span>
                </button>
              }
            />
          ) : (
            <div>
              {filteredAgents.map((a) => (
                <div
                  key={a.id}
                  className="row-item row-item-clickable"
                  onClick={() => openEditAgent(a)}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="icon-tile">
                      <Bot size={14} style={{ color: a.enabled ? 'var(--brand)' : 'var(--ink-muted)' }} />
                    </div>
                    <span className="mono text-[13.5px] font-semibold shrink-0">{a.id}</span>
                    {a.team && <TagPill dot="info">{a.team}</TagPill>}
                    <TagPill dot={a.allowed_servers.length > 0 ? 'ok' : 'neutral'}>
                      {a.allowed_servers.length > 0 ? a.allowed_servers.join(', ') : 'all servers'}
                    </TagPill>
                    {a.denied_tools.length > 0 && (
                      <TagPill dot="danger">{a.denied_tools.length} denied</TagPill>
                    )}
                  </div>
                  <div
                    className="flex items-center gap-4 shrink-0"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <StatusIndicator tone={a.enabled ? 'ok' : 'danger'} label={a.enabled ? 'Active' : 'Disabled'} />
                    <ToggleSwitch checked={a.enabled} onChange={(v) => handleToggleAgent(a, v)} />
                    <button
                      type="button"
                      className="btn-ghost p-1.5"
                      style={{ color: 'var(--ink-muted)' }}
                      onClick={() => handleDeleteAgent(a)}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: PROTECTION */}
      {tab === 'protection' && (
        <div>
          {mcp.servers.length === 0 ? (
            <EmptyState
              icon={<Shield size={17} />}
              title="Add an MCP server first"
              description="Once you register an upstream MCP server, configure agent auth, prompt-injection defense, and stuck-agent loop breakers here."
              action={
                <button type="button" className="btn btn-primary" onClick={openNewServer}>
                  <Plus size={14} />
                  <span>Add MCP Server</span>
                </button>
              }
            />
          ) : (
            <div>
              <FeatureToggleRow
                icon={<Lock size={15} />}
                title="Agent Auth, Session Binding & Live Kill-Switch"
                description="Authenticate agents over Channel 2 (mcp.agent_acls), bind Mcp-Session-Id to principal, and enforce instant mcp.kill_switch blocks."
                tag="Instant Sync"
                checked={prot.authEnabled}
                disabled={busy}
                onToggle={(v) =>
                  persistProtection(
                    { ...prot, authEnabled: v },
                    v ? 'Enabled MCP Agent Auth' : 'Disabled MCP Agent Auth'
                  )
                }
              />

              <FeatureToggleRow
                icon={<ShieldAlert size={15} />}
                title="Tool Guardrails & Indirect Prompt-Injection Defense"
                description="Redact secrets in tool arguments and block indirect prompt-injection payloads returned by untrusted MCP servers."
                tag="redact + block"
                checked={prot.guardrailsEnabled}
                disabled={busy}
                onToggle={(v) =>
                  persistProtection(
                    { ...prot, guardrailsEnabled: v },
                    v ? 'Enabled MCP Guardrails' : 'Disabled MCP Guardrails'
                  )
                }
              />

              <FeatureToggleRow
                icon={<Gauge size={15} />}
                title="Agent Rate Limits & Identical-Call Loop Breaker"
                description="Cap tool calls per session and automatically halt stuck agents repeating identical tool calls."
                tag={`${prot.toolRpm} tool/min`}
                checked={prot.rateLimitEnabled}
                disabled={busy}
                onToggle={(v) =>
                  persistProtection(
                    { ...prot, rateLimitEnabled: v },
                    v ? 'Enabled MCP Rate Limits' : 'Disabled MCP Rate Limits'
                  )
                }
              >
                <div className="flex flex-wrap items-end gap-3">
                  <div className="w-32">
                    <label className="block text-[12px] mb-1" style={{ color: 'var(--ink-secondary)' }}>
                      Tool RPM
                    </label>
                    <input
                      type="number"
                      className="input-base mono text-[13px]"
                      value={prot.toolRpm}
                      onChange={(e) => setProt({ ...prot, toolRpm: Number(e.target.value) })}
                    />
                  </div>
                  <div className="w-36">
                    <label className="block text-[12px] mb-1" style={{ color: 'var(--ink-secondary)' }}>
                      Max Calls / Session
                    </label>
                    <input
                      type="number"
                      className="input-base mono text-[13px]"
                      value={prot.maxCallsPerSession}
                      onChange={(e) => setProt({ ...prot, maxCallsPerSession: Number(e.target.value) })}
                    />
                  </div>
                  <div className="w-36">
                    <label className="block text-[12px] mb-1" style={{ color: 'var(--ink-secondary)' }}>
                      Loop Max Repeats
                    </label>
                    <input
                      type="number"
                      className="input-base mono text-[13px]"
                      value={prot.loopBreakerMaxRepeats}
                      onChange={(e) =>
                        setProt({ ...prot, loopBreakerEnabled: true, loopBreakerMaxRepeats: Number(e.target.value) })
                      }
                    />
                  </div>
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    disabled={busy}
                    onClick={() => persistProtection(prot, 'Saved MCP rate limits & loop breaker')}
                  >
                    Save
                  </button>
                </div>
              </FeatureToggleRow>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: KILL-SWITCH */}
      {tab === 'killswitch' && (
        <div>
          {killRules.length === 0 ? (
            <EmptyState
              icon={<AlertOctagon size={17} style={{ color: 'var(--danger)' }} />}
              title="No active kill-switches"
              description="When an agent behaves unexpectedly or suffers indirect prompt injection, trigger a Kill-Switch to halt its access across 100% of nodes in milliseconds — without reloading config."
              action={
                <button
                  type="button"
                  className="btn btn-danger"
                  onClick={() => setKsOpen(true)}
                >
                  <AlertOctagon size={14} />
                  <span>Trigger Kill-Switch</span>
                </button>
              }
            />
          ) : (
            <div>
              {killRules.map((rule) => (
                <div key={rule.id} className="row-item">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="icon-tile" style={{ borderColor: 'var(--danger-border)', color: 'var(--danger)' }}>
                      <AlertOctagon size={14} />
                    </div>
                    <TagPill dot="danger" mono>
                      {rule.scope}={rule.target}
                    </TagPill>
                    <span className="text-[13.5px] truncate">{rule.reason}</span>
                  </div>
                  <div className="flex items-center gap-4 shrink-0">
                    <span className="text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                      {formatRelativeTime(rule.updated_at)}
                    </span>
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => handleLiftKillSwitch(rule)}
                    >
                      Lift Block
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ADD / EDIT MCP SERVER DRAWER */}
      <Drawer
        open={srvOpen}
        onClose={() => setSrvOpen(false)}
        title={editingSrv ? `Edit MCP Server · ${editingSrv}` : 'Add MCP Server'}
        subtitle="Tools exposed by this server are automatically namespaced as <server>__<tool>."
        widthClass="max-w-lg"
      >
        <form onSubmit={handleSaveServer} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Server Name / Prefix</label>
              <input
                className="input-base mono"
                value={sSlug}
                disabled={Boolean(editingSrv)}
                onChange={(e) => setSSlug(slugify(e.target.value))}
                placeholder="github"
                required
              />
            </div>
            <div>
              <label className="block text-[12.5px] font-medium mb-1">MCP Path</label>
              <input
                className="input-base mono"
                value={sPath}
                onChange={(e) => setSPath(e.target.value)}
                placeholder="/mcp"
              />
            </div>
          </div>
          <div>
            <label className="block text-[12.5px] font-medium mb-1">Upstream Origin URL</label>
            <input
              className="input-base mono"
              value={sBaseUrl}
              onChange={(e) => setSBaseUrl(e.target.value)}
              placeholder="http://127.0.0.1:8090"
              required
            />
          </div>
          <div className="card-subtle p-4 space-y-3">
            <div className="flex items-center justify-between">
              <label className="text-[12.5px] font-semibold">Upstream Auth</label>
              <SegmentedTabs
                value={sAuthType}
                onChange={setSAuthType}
                items={[
                  { id: 'none', label: 'None' },
                  { id: 'bearer', label: 'Bearer' },
                  { id: 'header', label: 'Header' },
                ]}
              />
            </div>
            {sAuthType === 'header' && (
              <div>
                <label className="block text-[12px] mb-1" style={{ color: 'var(--ink-secondary)' }}>
                  Header Name
                </label>
                <input
                  className="input-base mono"
                  value={sAuthHeader}
                  onChange={(e) => setSAuthHeader(e.target.value)}
                />
              </div>
            )}
            {sAuthType !== 'none' && (
              <div>
                <label className="block text-[12px] mb-1" style={{ color: 'var(--ink-secondary)' }}>
                  Token (auto-encrypted to Vault, or pass <code>env:VAR</code>)
                </label>
                <input
                  type="password"
                  className="input-base mono"
                  value={sSecretInput}
                  onChange={(e) => setSSecretInput(e.target.value)}
                  placeholder="ghp_… or env:GITHUB_MCP_TOKEN"
                />
              </div>
            )}
          </div>
          <label className="flex items-center gap-2 text-[13px] cursor-pointer">
            <input
              type="checkbox"
              checked={sStateful}
              onChange={(e) => setSStateful(e.target.checked)}
            />
            <span>Stateful MCP server (requires upstream initialize + Mcp-Session-Id)</span>
          </label>
          <div className="flex justify-end gap-2.5 pt-3" style={{ borderTop: '1px solid var(--border-row)' }}>
            <button type="button" className="btn" onClick={() => setSrvOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Saving…' : 'Save Server'}
            </button>
          </div>
        </form>
      </Drawer>

      {/* ADD / EDIT AGENT DRAWER */}
      <Drawer
        open={agentOpen}
        onClose={() => setAgentOpen(false)}
        title={editingAgent ? `Edit Agent · ${editingAgent.id}` : 'New MCP Agent'}
        subtitle="Least-privilege tool permissions synced immediately over Channel 2."
        widthClass="max-w-lg"
      >
        <form onSubmit={handleSaveAgent} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Agent ID</label>
              <input
                className="input-base mono"
                value={aId}
                disabled={Boolean(editingAgent)}
                onChange={(e) => setAId(slugify(e.target.value))}
                placeholder="ci-triage-bot"
                required
              />
            </div>
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Team</label>
              <input
                className="input-base"
                value={aTeam}
                onChange={(e) => setATeam(e.target.value)}
              />
            </div>
          </div>

          {mcp.servers.length > 0 && (
            <div className="space-y-1.5">
              <label className="block text-[12.5px] font-medium">Allowed MCP Servers</label>
              <div className="flex flex-wrap gap-1.5">
                {mcp.servers.map((s) => {
                  const active = aServers.includes(s.slug);
                  return (
                    <button
                      key={s.slug}
                      type="button"
                      onClick={() =>
                        setAServers(active ? aServers.filter((x) => x !== s.slug) : [...aServers, s.slug])
                      }
                      className="btn btn-sm mono"
                      style={{
                        background: active ? 'var(--brand-soft)' : 'var(--sheet)',
                        borderColor: active ? 'var(--brand-border)' : 'var(--border)',
                        color: active ? 'var(--brand)' : 'var(--ink-secondary)',
                      }}
                    >
                      {active && <Check size={11} />}
                      <span>{s.slug}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          <div>
            <label className="block text-[12.5px] font-medium mb-1">
              Allowed Tool Globs (comma-separated, blank = all on allowed servers)
            </label>
            <input
              className="input-base mono text-[13px]"
              value={aAllowTools}
              onChange={(e) => setAAllowTools(e.target.value)}
              placeholder="github__get_*, github__list_*"
            />
          </div>

          <div>
            <label className="block text-[12.5px] font-medium mb-1">
              Denied Tool Globs (comma-separated)
            </label>
            <input
              className="input-base mono text-[13px]"
              value={aDenyTools}
              onChange={(e) => setADenyTools(e.target.value)}
              placeholder="*delete*, *drop*"
            />
          </div>

          <div className="w-40">
            <label className="block text-[12.5px] font-medium mb-1">Tool Calls / Min</label>
            <input
              type="number"
              className="input-base mono"
              value={aToolRpm}
              onChange={(e) => setAToolRpm(e.target.value)}
            />
          </div>

          <div className="flex justify-end gap-2.5 pt-3" style={{ borderTop: '1px solid var(--border-row)' }}>
            <button type="button" className="btn" onClick={() => setAgentOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              <Zap size={13} />
              <span>{busy ? 'Syncing…' : editingAgent ? 'Save & Sync' : 'Mint & Sync Agent'}</span>
            </button>
          </div>
        </form>
      </Drawer>

      {/* MINTED AGENT KEY MODAL */}
      <Modal
        open={Boolean(mintedAgentKey)}
        onClose={() => setMintedAgentKey(null)}
        title={`Agent "${mintedAgentKey?.id}" is live`}
        subtitle="Copy this agent token now — only its SHA-256 hash is persisted."
      >
        {mintedAgentKey && (
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <code className="code-block flex-1 py-2.5 break-all">{mintedAgentKey.plaintext}</code>
              <CopyButton text={mintedAgentKey.plaintext} label="Copy" />
            </div>
            <div className="flex justify-end">
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setMintedAgentKey(null)}
              >
                Done
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* TRIGGER KILL-SWITCH MODAL */}
      <Modal
        open={ksOpen}
        onClose={() => setKsOpen(false)}
        title="Trigger Emergency Kill-Switch"
        subtitle="Propagates in milliseconds to 100% of connected nodes over Channel 2. Unaffected by topology rollbacks."
      >
        <form onSubmit={handleTriggerKillSwitch} className="space-y-4">
          <div className="flex items-center justify-between">
            <label className="text-[12.5px] font-medium">Scope</label>
            <SegmentedTabs
              value={ksScope}
              onChange={setKsScope}
              items={[
                { id: 'principal', label: 'Agent Principal' },
                { id: 'session', label: 'MCP Session ID' },
              ]}
            />
          </div>
          <div>
            <label className="block text-[12.5px] font-medium mb-1">
              Target ({ksScope === 'principal' ? 'agent ID or * for all' : 'Mcp-Session-Id'})
            </label>
            <input
              className="input-base mono"
              value={ksTarget}
              onChange={(e) => setKsTarget(e.target.value)}
              placeholder={agents[0]?.id || 'agent_ci'}
              required
            />
            {ksScope === 'principal' && agents.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {agents.map((a) => (
                  <button
                    key={a.id}
                    type="button"
                    className="btn btn-sm mono"
                    onClick={() => setKsTarget(a.id)}
                  >
                    {a.id}
                  </button>
                ))}
              </div>
            )}
          </div>
          <div>
            <label className="block text-[12.5px] font-medium mb-1">Reason</label>
            <input
              className="input-base"
              value={ksReason}
              onChange={(e) => setKsReason(e.target.value)}
            />
          </div>
          <div className="flex justify-end gap-2.5 pt-2">
            <button type="button" className="btn" onClick={() => setKsOpen(false)}>
              Cancel
            </button>
            <button
              type="submit"
              className="btn"
              style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }}
              disabled={busy}
            >
              <AlertOctagon size={14} />
              <span>Halt Immediately</span>
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
