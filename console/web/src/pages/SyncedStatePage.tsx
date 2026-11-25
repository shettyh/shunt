import React, { useEffect, useState } from 'react';
import {
  CheckCircle2,
  Edit3,
  Layers,
  Plus,
  RefreshCw,
  Trash2,
  Zap,
} from 'lucide-react';
import {
  api,
  ApiProblemError,
  Cluster,
  ControlStateItem,
  formatRelativeTime,
  NamespaceStateResponse,
  NamespaceStateSummary,
} from '../lib/api';
import { Drawer, useToast } from '../components/ui';

interface PolicyGroupMeta {
  title: string;
  pillar: 'AI' | 'MCP' | 'Custom';
  key: string;
  hint: string;
  value: object;
}

const POLICY_CATALOG: Record<string, PolicyGroupMeta> = {
  'ai.virtual_keys': {
    title: 'AI Virtual Keys',
    pillar: 'AI',
    key: 'vk_team_search',
    hint: 'Hashed virtual API keys, allowed models, RPM/TPM & spend caps for ai-virtual-keys',
    value: {
      enabled: true,
      org: 'acme',
      team: 'search',
      key_hashes: ['sha256:0000000000000000000000000000000000000000000000000000000000000000'],
      allowed_models: ['gpt-4o*', 'claude-sonnet-*'],
      rpm: 120,
      budget_usd: 250.0,
    },
  },
  'ai.budgets': {
    title: 'AI Budgets',
    pillar: 'AI',
    key: 'team:acme/search',
    hint: 'Organization and team spend ceilings (soft & hard caps) enforced by ai-budget',
    value: { limit_usd: 1000.0, soft_limit_usd: 800.0, window: 'monthly', mode: 'hard' },
  },
  'ai.pricing': {
    title: 'Model Pricing',
    pillar: 'AI',
    key: 'gpt-4o',
    hint: 'Per-1M token cost overrides applied fleet-wide without reloading gateway config',
    value: { input_usd_per_1m: 2.5, output_usd_per_1m: 10.0, cached_input_usd_per_1m: 1.25 },
  },
  'mcp.agent_acls': {
    title: 'MCP Agent Permissions',
    pillar: 'MCP',
    key: 'agent_ci_triage',
    hint: 'Least-privilege server, tool, resource & prompt allow/deny rules per agent',
    value: {
      enabled: true,
      allowed_servers: ['github', 'jira'],
      allowed_tools: ['github__get_*', 'github__list_*'],
      denied_tools: ['github__delete_*'],
    },
  },
  'mcp.kill_switch': {
    title: 'Emergency Kill-Switch',
    pillar: 'MCP',
    key: 'ks_emergency_1',
    hint: 'Sub-second fleet-wide blocks for rogue agents, sessions, servers, or tools',
    value: {
      scope: 'principal',
      target: 'agent_rogue_1',
      reason: 'Suspected indirect prompt injection',
      expires_at: null,
    },
  },
  'mcp.approvals': {
    title: 'MCP Tool Approvals',
    pillar: 'MCP',
    key: 'appr_01',
    hint: 'Args-bound human-in-the-loop approval grants for gated tool invocations',
    value: { principal: 'agent_ci_triage', tool: 'github__create_issue', max_uses: 1 },
  },
};

function getPolicyMeta(namespace: string): PolicyGroupMeta {
  return (
    POLICY_CATALOG[namespace] || {
      title: namespace,
      pillar: 'Custom',
      key: 'policy_1',
      hint: 'Instant-sync runtime policy entries',
      value: { enabled: true },
    }
  );
}

function summarizePolicy(ns: string, payload: unknown): string {
  const p = (payload && typeof payload === 'object' ? payload : {}) as Record<string, unknown>;
  switch (ns) {
    case 'ai.virtual_keys': {
      const parts: string[] = [];
      if (p.enabled === false) parts.push('disabled');
      if (p.team) parts.push(`team:${String(p.team)}`);
      if (Array.isArray(p.allowed_models) && p.allowed_models.length > 0) {
        parts.push(`models:${p.allowed_models.slice(0, 2).join(',')}`);
      }
      if (typeof p.budget_usd === 'number') parts.push(`$${p.budget_usd}`);
      if (typeof p.rpm === 'number') parts.push(`${p.rpm} rpm`);
      return parts.length > 0 ? parts.join(' · ') : JSON.stringify(payload);
    }
    case 'ai.budgets': {
      const limit = typeof p.limit_usd === 'number' ? `$${p.limit_usd}` : '';
      const window = typeof p.window === 'string' ? `/${p.window}` : '';
      const mode = typeof p.mode === 'string' ? ` (${p.mode})` : '';
      return limit ? `${limit}${window}${mode}` : JSON.stringify(payload);
    }
    case 'ai.pricing': {
      const inp = typeof p.input_usd_per_1m === 'number' ? `in $${p.input_usd_per_1m}` : '';
      const out = typeof p.output_usd_per_1m === 'number' ? `out $${p.output_usd_per_1m}` : '';
      return inp || out ? `${inp} · ${out} / 1M tok` : JSON.stringify(payload);
    }
    case 'mcp.agent_acls': {
      const servers = Array.isArray(p.allowed_servers) ? p.allowed_servers.join(', ') : '';
      const allow = Array.isArray(p.allowed_tools) ? `${p.allowed_tools.length} allow` : '';
      const deny = Array.isArray(p.denied_tools) ? `${p.denied_tools.length} deny` : '';
      return [servers && `servers: ${servers}`, allow, deny].filter(Boolean).join(' · ') || JSON.stringify(payload);
    }
    case 'mcp.kill_switch': {
      const scope = p.scope ? `${String(p.scope)}=${String(p.target ?? '*')}` : '';
      const reason = p.reason ? ` · ${String(p.reason)}` : '';
      return scope ? `${scope}${reason}` : JSON.stringify(payload);
    }
    default:
      return JSON.stringify(payload);
  }
}

export function SyncedStatePage({ cluster }: { cluster: Cluster }) {
  const toast = useToast();
  const [summaries, setSummaries] = useState<NamespaceStateSummary[]>([]);
  const [selectedNs, setSelectedNs] = useState<string>('ai.virtual_keys');
  const [detail, setDetail] = useState<NamespaceStateResponse | null>(null);
  const [loading, setLoading] = useState(true);

  // Upsert Policy Drawer
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [itemKey, setItemKey] = useState('');
  const [itemJson, setItemJson] = useState('');
  const [editingExisting, setEditingExisting] = useState(false);
  const [saving, setSaving] = useState(false);

  const selectedMeta = getPolicyMeta(selectedNs);

  const loadSummaries = async () => {
    try {
      const s = await api.listStateNamespaces(cluster.slug);
      setSummaries(s);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : 'Failed to load policy groups', 'error');
    }
  };

  const loadDetail = async (ns: string) => {
    setLoading(true);
    try {
      const d = await api.getNamespaceState(cluster.slug, ns);
      setDetail(d);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : 'Failed to load policies', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSummaries();
    loadDetail(selectedNs);
  }, [cluster.slug, selectedNs]);

  const openCreateDrawer = () => {
    const tpl = getPolicyMeta(selectedNs);
    setItemKey(tpl.key);
    setItemJson(JSON.stringify(tpl.value, null, 2));
    setEditingExisting(false);
    setDrawerOpen(true);
  };

  const openEditDrawer = (item: ControlStateItem) => {
    setItemKey(item.item_key);
    setItemJson(JSON.stringify(item.payload, null, 2));
    setEditingExisting(true);
    setDrawerOpen(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    let parsed: unknown;
    try {
      parsed = JSON.parse(itemJson);
    } catch (err) {
      toast.push(`Invalid JSON payload: ${String(err)}`, 'error');
      return;
    }
    setSaving(true);
    try {
      await api.upsertStateItem(cluster.slug, selectedNs, itemKey.trim(), parsed);
      toast.push(`Synced ${selectedMeta.title} policy "${itemKey.trim()}" across fleet`);
      setDrawerOpen(false);
      await Promise.all([loadSummaries(), loadDetail(selectedNs)]);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (key: string) => {
    if (
      !window.confirm(
        `Remove "${key}" from ${selectedMeta.title}? This takes effect immediately across 100% of cluster nodes.`
      )
    ) {
      return;
    }
    try {
      await api.deleteStateItem(cluster.slug, selectedNs, key);
      toast.push(`Removed "${key}" from ${selectedMeta.title} across fleet`);
      await Promise.all([loadSummaries(), loadDetail(selectedNs)]);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  return (
    <div className="space-y-3.5">
      {/* Compact Top Toolbar */}
      <div className="surface px-3.5 py-2.5 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2.5 min-w-0">
          <span className="font-semibold text-sm">Live Policies</span>
          <span className="badge badge-ok">
            <Zap size={10} />
            <span>Instant Sync</span>
          </span>
          <span className="text-xs hidden lg:inline" style={{ color: 'var(--text-muted)' }}>
            Applied to 100% of nodes in milliseconds—independent of config releases and never undone by rollbacks
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => {
              loadSummaries();
              loadDetail(selectedNs);
            }}
          >
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
          <button type="button" className="btn btn-sm btn-primary" onClick={openCreateDrawer}>
            <Plus size={13} />
            <span>Add Policy</span>
          </button>
        </div>
      </div>

      {/* 3-Column Master-Detail Operations Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-3.5 items-start">
        {/* Left Rail: Policy Groups */}
        <div className="surface overflow-hidden xl:col-span-3">
          <div
            className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wide"
            style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-sidebar)', color: 'var(--text-muted)' }}
          >
            Policy Groups
          </div>
          <div className="divide-y tabular" style={{ borderColor: 'var(--border-light)' }}>
            {summaries.map((s) => {
              const meta = getPolicyMeta(s.namespace);
              const active = s.namespace === selectedNs;
              const allConverged =
                s.total_online_nodes > 0 && s.converged_nodes === s.total_online_nodes;
              return (
                <button
                  key={s.namespace}
                  type="button"
                  onClick={() => setSelectedNs(s.namespace)}
                  className="w-full px-3 py-2.5 text-left cursor-pointer border-0 transition-colors block"
                  style={{
                    background: active ? 'var(--accent-soft)' : 'transparent',
                    borderLeft: `2px solid ${active ? 'var(--accent)' : 'transparent'}`,
                  }}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
                      {meta.title}
                    </span>
                    <span className={meta.pillar === 'MCP' ? 'badge badge-accent text-[10px]' : 'badge text-[10px]'}>
                      {meta.pillar}
                    </span>
                  </div>
                  <div className="mt-1 flex items-center justify-between text-[11px]" style={{ color: 'var(--text-muted)' }}>
                    <span>
                      <strong style={{ color: 'var(--text-primary)' }}>{s.item_count}</strong> active
                    </span>
                    <span style={{ color: allConverged ? 'var(--ok)' : 'var(--text-muted)' }}>
                      {s.total_online_nodes === 0
                        ? '0 online'
                        : `${s.converged_nodes}/${s.total_online_nodes} synced`}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Center: Active Policy Entries */}
        <div className="surface overflow-hidden xl:col-span-6">
          <div
            className="px-3.5 py-2.5 flex items-center justify-between gap-3"
            style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-sidebar)' }}
          >
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <Layers size={13} style={{ color: 'var(--text-muted)' }} />
                <span className="text-xs font-semibold truncate">{selectedMeta.title}</span>
                <span className="badge mono text-[10px]">{selectedNs}</span>
              </div>
              <div className="text-[11px] truncate mt-0.5" style={{ color: 'var(--text-muted)' }}>
                {selectedMeta.hint}
              </div>
            </div>
            <button type="button" className="btn btn-sm shrink-0" onClick={openCreateDrawer}>
              <Zap size={12} />
              <span>Add</span>
            </button>
          </div>

          {loading ? (
            <div className="p-8 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
              Loading policies…
            </div>
          ) : !detail || detail.items.length === 0 ? (
            <div className="p-10 text-center text-xs space-y-2.5" style={{ color: 'var(--text-muted)' }}>
              <div>No active policies in <strong>{selectedMeta.title}</strong> yet.</div>
              <button type="button" className="btn btn-sm" onClick={openCreateDrawer}>
                <Plus size={12} />
                <span>Add first policy</span>
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="swiss-table text-xs">
                <thead>
                  <tr>
                    <th>Policy ID</th>
                    <th>Summary</th>
                    <th>Updated</th>
                    <th className="text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.items.map((item) => (
                    <tr key={item.item_key}>
                      <td className="mono font-semibold whitespace-nowrap">{item.item_key}</td>
                      <td
                        className="mono text-[11px] max-w-sm truncate"
                        style={{ color: 'var(--text-secondary)' }}
                        title={JSON.stringify(item.payload)}
                      >
                        {summarizePolicy(selectedNs, item.payload)}
                      </td>
                      <td className="whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                        {formatRelativeTime(item.updated_at)}
                      </td>
                      <td className="text-right whitespace-nowrap">
                        <div className="inline-flex items-center gap-1">
                          <button
                            type="button"
                            className="btn btn-sm"
                            onClick={() => openEditDrawer(item)}
                          >
                            <Edit3 size={11} />
                            <span>Edit</span>
                          </button>
                          <button
                            type="button"
                            className="btn-ghost p-1 rounded cursor-pointer border-0"
                            style={{ color: 'var(--danger)' }}
                            onClick={() => handleDelete(item.item_key)}
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right: Recent Policy Changes */}
        <div className="surface overflow-hidden xl:col-span-3">
          <div
            className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wide"
            style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-sidebar)', color: 'var(--text-muted)' }}
          >
            Recent Policy Changes
          </div>
          {!detail || detail.recent_events.length === 0 ? (
            <div className="p-6 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
              No policy changes recorded yet.
            </div>
          ) : (
            <div className="p-2.5 space-y-1.5 max-h-[520px] overflow-y-auto tabular">
              {detail.recent_events.map((ev) => (
                <div
                  key={ev.seq}
                  className="px-2.5 py-2 rounded-md text-xs"
                  style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-light)' }}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="mono font-semibold truncate">{ev.item_key}</span>
                    <span className={ev.op === 'delete' ? 'badge badge-danger' : 'badge badge-ok'}>
                      {ev.op === 'delete' ? 'removed' : 'updated'}
                    </span>
                  </div>
                  <div className="text-[10.5px] mt-1 flex items-center justify-between" style={{ color: 'var(--text-muted)' }}>
                    <span>{formatRelativeTime(ev.created_at)}</span>
                    <span className="mono opacity-75">v{ev.seq}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Right-Hand Upsert Policy Drawer */}
      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={
          editingExisting
            ? `Update ${selectedMeta.title} · ${itemKey}`
            : `Add ${selectedMeta.title} Policy`
        }
        subtitle="Applies immediately to 100% of connected nodes without reloading gateway config."
        widthClass="max-w-xl"
      >
        <form onSubmit={handleSave} className="space-y-4">
          <div>
            <label className="block text-xs font-medium mb-1">Policy ID</label>
            <input
              className="input-base mono text-xs"
              value={itemKey}
              disabled={editingExisting}
              onChange={(e) => setItemKey(e.target.value)}
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1">Policy JSON</label>
            <textarea
              className="input-base mono text-xs min-h-[320px]"
              value={itemJson}
              onChange={(e) => setItemJson(e.target.value)}
              spellCheck={false}
              required
            />
          </div>
          <div className="flex items-center justify-between pt-2">
            <span className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--ok)' }}>
              <CheckCircle2 size={13} />
              <span>Instant fleet sync · Unaffected by rollbacks</span>
            </span>
            <div className="flex gap-2">
              <button type="button" className="btn" onClick={() => setDrawerOpen(false)}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={saving}>
                <Zap size={13} />
                <span>{saving ? 'Syncing…' : 'Save & Sync'}</span>
              </button>
            </div>
          </div>
        </form>
      </Drawer>
    </div>
  );
}
