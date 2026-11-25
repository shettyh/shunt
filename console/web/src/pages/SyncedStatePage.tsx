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
import { Modal, useToast } from '../components/ui';

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

export function SyncedStatePage({ cluster }: { cluster: Cluster }) {
  const toast = useToast();
  const [summaries, setSummaries] = useState<NamespaceStateSummary[]>([]);
  const [selectedNs, setSelectedNs] = useState<string>('ai.virtual_keys');
  const [detail, setDetail] = useState<NamespaceStateResponse | null>(null);
  const [loading, setLoading] = useState(true);

  // Upsert Modal
  const [modalOpen, setModalOpen] = useState(false);
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

  const openCreateModal = () => {
    const tpl = getPolicyMeta(selectedNs);
    setItemKey(tpl.key);
    setItemJson(JSON.stringify(tpl.value, null, 2));
    setEditingExisting(false);
    setModalOpen(true);
  };

  const openEditModal = (item: ControlStateItem) => {
    setItemKey(item.item_key);
    setItemJson(JSON.stringify(item.payload, null, 2));
    setEditingExisting(true);
    setModalOpen(true);
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
      setModalOpen(false);
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
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="m-0 text-xl font-semibold tracking-tight">Live Policies</h1>
            <span className="badge badge-ok">
              <Zap size={11} />
              <span>Instant Sync</span>
            </span>
          </div>
          <p className="m-0 mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
            High-velocity access &amp; safety controls applied to 100% of nodes in milliseconds—independent of config releases and never undone by rollbacks.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="btn"
            onClick={() => {
              loadSummaries();
              loadDetail(selectedNs);
            }}
          >
            <RefreshCw size={14} />
            <span>Refresh</span>
          </button>
          <button type="button" className="btn btn-primary" onClick={openCreateModal}>
            <Plus size={14} />
            <span>Add Policy</span>
          </button>
        </div>
      </div>

      {/* Policy Group Selector Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 tabular">
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
              className="surface p-3.5 text-left cursor-pointer transition-colors"
              style={{
                background: active ? 'var(--accent-soft)' : 'var(--bg-elevated)',
                borderColor: active ? 'var(--accent)' : 'var(--border)',
              }}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold">{meta.title}</span>
                <span className={meta.pillar === 'MCP' ? 'badge badge-accent text-[10px]' : 'badge text-[10px]'}>
                  {meta.pillar}
                </span>
              </div>
              <div className="mono text-[11px] mt-0.5" style={{ color: 'var(--text-muted)' }}>
                {s.namespace}
              </div>
              <div className="mt-2.5 flex items-center justify-between text-xs" style={{ color: 'var(--text-muted)' }}>
                <span>
                  <strong style={{ color: 'var(--text-primary)' }}>{s.item_count}</strong> active{' '}
                  {s.item_count === 1 ? 'policy' : 'policies'}
                </span>
                <span style={{ color: allConverged ? 'var(--ok)' : 'var(--text-muted)' }}>
                  {s.total_online_nodes === 0
                    ? '0 nodes online'
                    : `${s.converged_nodes}/${s.total_online_nodes} nodes updated`}
                </span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Active Policy Group Items */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="surface p-5 lg:col-span-2 space-y-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="m-0 text-sm font-semibold flex items-center gap-2">
                <Layers size={15} />
                <span>{selectedMeta.title}</span>
                <span className="badge mono text-[11px]">{selectedNs}</span>
              </h2>
              <p className="m-0 mt-0.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                {selectedMeta.hint}
              </p>
            </div>
            <button type="button" className="btn text-xs py-1 px-2.5 shrink-0" onClick={openCreateModal}>
              <Zap size={12} />
              <span>Add Policy</span>
            </button>
          </div>

          {loading ? (
            <div className="py-8 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
              Loading policies…
            </div>
          ) : !detail || detail.items.length === 0 ? (
            <div className="py-10 text-center text-xs space-y-2" style={{ color: 'var(--text-muted)' }}>
              <div>No active policies in <strong>{selectedMeta.title}</strong> yet.</div>
              <button type="button" className="btn text-xs" onClick={openCreateModal}>
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
                    <th>Configuration</th>
                    <th>Updated</th>
                    <th className="text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.items.map((item) => (
                    <tr key={item.item_key}>
                      <td className="mono font-semibold">{item.item_key}</td>
                      <td className="mono text-[11px] max-w-xs truncate" style={{ color: 'var(--text-secondary)' }}>
                        {JSON.stringify(item.payload)}
                      </td>
                      <td style={{ color: 'var(--text-muted)' }}>{formatRelativeTime(item.updated_at)}</td>
                      <td className="text-right">
                        <div className="inline-flex items-center gap-1">
                          <button
                            type="button"
                            className="btn text-xs py-1 px-2"
                            onClick={() => openEditModal(item)}
                          >
                            <Edit3 size={12} />
                          </button>
                          <button
                            type="button"
                            className="btn-ghost p-1.5 rounded cursor-pointer border-0"
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

        {/* Recent Policy Changes Feed */}
        <div className="surface p-5 space-y-3">
          <h2 className="m-0 text-sm font-semibold">Recent Policy Changes</h2>
          <p className="m-0 text-xs" style={{ color: 'var(--text-muted)' }}>
            Real-time change feed propagated automatically to every connected node.
          </p>
          {!detail || detail.recent_events.length === 0 ? (
            <div className="py-8 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
              No policy changes recorded yet.
            </div>
          ) : (
            <div className="space-y-2 max-h-[420px] overflow-y-auto tabular">
              {detail.recent_events.map((ev) => (
                <div
                  key={ev.seq}
                  className="p-2.5 rounded-lg text-xs"
                  style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-light)' }}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="mono font-semibold truncate">{ev.item_key}</span>
                    <span className={ev.op === 'delete' ? 'badge badge-danger' : 'badge badge-ok'}>
                      {ev.op === 'delete' ? 'removed' : 'updated'}
                    </span>
                  </div>
                  <div className="text-[11px] mt-1 flex items-center justify-between" style={{ color: 'var(--text-muted)' }}>
                    <span>{formatRelativeTime(ev.created_at)}</span>
                    <span className="mono opacity-75">v{ev.seq}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Upsert Policy Modal */}
      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title={
          editingExisting
            ? `Update ${selectedMeta.title} · ${itemKey}`
            : `Add ${selectedMeta.title} Policy`
        }
        subtitle="Applies immediately to 100% of connected nodes without reloading gateway config."
        maxWidth="max-w-xl"
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
              className="input-base mono text-xs min-h-[210px]"
              value={itemJson}
              onChange={(e) => setItemJson(e.target.value)}
              spellCheck={false}
              required
            />
          </div>
          <div className="flex items-center justify-between pt-1">
            <span className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--ok)' }}>
              <CheckCircle2 size={13} />
              <span>Instant fleet sync · Unaffected by config rollbacks</span>
            </span>
            <div className="flex gap-2">
              <button type="button" className="btn" onClick={() => setModalOpen(false)}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={saving}>
                <Zap size={14} />
                <span>{saving ? 'Syncing…' : 'Save & Sync'}</span>
              </button>
            </div>
          </div>
        </form>
      </Modal>
    </div>
  );
}
