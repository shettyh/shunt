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

const NAMESPACE_TEMPLATES: Record<string, { key: string; value: object; hint: string }> = {
  'ai.virtual_keys': {
    key: 'vk_team_search',
    hint: 'SHA-256 hashed virtual key policies synced to ai-virtual-keys',
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
    key: 'team:acme/search',
    hint: 'Org & team spend ceilings synced to ai-budget',
    value: { limit_usd: 1000.0, soft_limit_usd: 800.0, window: 'monthly', mode: 'hard' },
  },
  'ai.pricing': {
    key: 'gpt-4o',
    hint: 'Per-1M token model pricing overrides',
    value: { input_usd_per_1m: 2.5, output_usd_per_1m: 10.0, cached_input_usd_per_1m: 1.25 },
  },
  'mcp.agent_acls': {
    key: 'agent_ci_triage',
    hint: 'Least-privilege MCP tool & server ACLs',
    value: {
      enabled: true,
      allowed_servers: ['github', 'jira'],
      allowed_tools: ['github__get_*', 'github__list_*'],
      denied_tools: ['github__delete_*'],
    },
  },
  'mcp.kill_switch': {
    key: 'ks_emergency_1',
    hint: 'Emergency sub-50ms containment rules for agents, sessions, servers, or tools',
    value: {
      scope: 'principal',
      target: 'agent_rogue_1',
      reason: 'Suspected indirect prompt injection',
      expires_at: null,
    },
  },
  'mcp.approvals': {
    key: 'appr_01',
    hint: 'Cryptographically args-pinned human-in-the-loop MCP approval grants',
    value: { principal: 'agent_ci_triage', tool: 'github__create_issue', max_uses: 1 },
  },
};

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

  const loadSummaries = async () => {
    try {
      const s = await api.listStateNamespaces(cluster.slug);
      setSummaries(s);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : 'Failed to load namespaces', 'error');
    }
  };

  const loadDetail = async (ns: string) => {
    setLoading(true);
    try {
      const d = await api.getNamespaceState(cluster.slug, ns);
      setDetail(d);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : 'Failed to load namespace state', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSummaries();
    loadDetail(selectedNs);
  }, [cluster.slug, selectedNs]);

  const openCreateModal = () => {
    const tpl = NAMESPACE_TEMPLATES[selectedNs] || {
      key: 'item_1',
      value: { enabled: true },
    };
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
      const ev = await api.upsertStateItem(cluster.slug, selectedNs, itemKey.trim(), parsed);
      toast.push(`Pushed ${selectedNs}/${itemKey.trim()} at seq #${ev.seq} over Channel 2`);
      setModalOpen(false);
      await Promise.all([loadSummaries(), loadDetail(selectedNs)]);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (key: string) => {
    if (!window.confirm(`Delete "${key}" from ${selectedNs}? This fans out immediately to 100% of cluster nodes.`)) {
      return;
    }
    try {
      const ev = await api.deleteStateItem(cluster.slug, selectedNs, key);
      toast.push(`Deleted ${selectedNs}/${key} at seq #${ev.seq} (propagating fleet-wide)`);
      await Promise.all([loadSummaries(), loadDetail(selectedNs)]);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="m-0 text-xl font-semibold tracking-tight">Synced State Tables (Channel 2)</h1>
          <p className="m-0 mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
            Lock-free <code>ArcSwap</code> identity &amp; policy tables synced fleet-wide in ~20–50ms via monotonic SSE deltas—completely isolated from Channel 1 topology rollbacks.
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
            <span>Upsert Entry</span>
          </button>
        </div>
      </div>

      {/* Namespace Selector Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 tabular">
        {summaries.map((s) => {
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
                <span className="mono text-xs font-semibold">{s.namespace}</span>
                <span className="badge mono text-[11px]">seq #{s.head_seq}</span>
              </div>
              <div className="mt-2 flex items-center justify-between text-xs" style={{ color: 'var(--text-muted)' }}>
                <span>
                  <strong style={{ color: 'var(--text-primary)' }}>{s.item_count}</strong> active key
                  {s.item_count === 1 ? '' : 's'}
                </span>
                <span style={{ color: allConverged ? 'var(--ok)' : 'var(--text-muted)' }}>
                  {s.total_online_nodes === 0
                    ? '0 nodes online'
                    : `${s.converged_nodes}/${s.total_online_nodes} converged`}
                </span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Active Namespace Items */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="surface p-5 lg:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="m-0 text-sm font-semibold flex items-center gap-2 mono">
                <Layers size={15} />
                <span>{selectedNs}</span>
                {detail && <span className="badge badge-ok">head seq #{detail.head_seq}</span>}
              </h2>
              {NAMESPACE_TEMPLATES[selectedNs]?.hint && (
                <p className="m-0 mt-0.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                  {NAMESPACE_TEMPLATES[selectedNs].hint}
                </p>
              )}
            </div>
            <button type="button" className="btn text-xs py-1 px-2.5" onClick={openCreateModal}>
              <Zap size={12} />
              <span>Push Delta</span>
            </button>
          </div>

          {loading ? (
            <div className="py-8 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
              Loading entries…
            </div>
          ) : !detail || detail.items.length === 0 ? (
            <div className="py-10 text-center text-xs space-y-2" style={{ color: 'var(--text-muted)' }}>
              <div>No active entries in <code>{selectedNs}</code>.</div>
              <button type="button" className="btn text-xs" onClick={openCreateModal}>
                <Plus size={12} />
                <span>Add first entry</span>
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="swiss-table text-xs">
                <thead>
                  <tr>
                    <th>Item Key</th>
                    <th>Seq</th>
                    <th>Value Preview</th>
                    <th>Updated</th>
                    <th className="text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.items.map((item) => (
                    <tr key={item.item_key}>
                      <td className="mono font-semibold">{item.item_key}</td>
                      <td className="mono" style={{ color: 'var(--text-muted)' }}>
                        #{item.seq}
                      </td>
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

        {/* Append-only Delta Log */}
        <div className="surface p-5 space-y-3">
          <h2 className="m-0 text-sm font-semibold">Recent Delta Events</h2>
          <p className="m-0 text-xs" style={{ color: 'var(--text-muted)' }}>
            Append-only <code>control_events</code> streamed over SSE with automatic <code>full_sync</code> fallback on compacted cursors.
          </p>
          {!detail || detail.recent_events.length === 0 ? (
            <div className="py-8 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
              No delta events yet.
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
                    <span className="mono font-semibold">#{ev.seq}</span>
                    <span className={ev.op === 'delete' ? 'badge badge-danger mono' : 'badge badge-ok mono'}>
                      {ev.op}
                    </span>
                  </div>
                  <div className="mono mt-1 truncate">{ev.item_key}</div>
                  <div className="text-[11px] mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    {formatRelativeTime(ev.created_at)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Upsert Entry Modal */}
      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editingExisting ? `Update ${selectedNs}/${itemKey}` : `Push entry to ${selectedNs}`}
        subtitle="Propagates immediately to 100% of connected nodes over Channel 2 SSE."
        maxWidth="max-w-xl"
      >
        <form onSubmit={handleSave} className="space-y-4">
          <div>
            <label className="block text-xs font-medium mb-1">Item Key</label>
            <input
              className="input-base mono text-xs"
              value={itemKey}
              disabled={editingExisting}
              onChange={(e) => setItemKey(e.target.value)}
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1">JSON Payload</label>
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
              <span>Zero topology reload · Lock-free ArcSwap</span>
            </span>
            <div className="flex gap-2">
              <button type="button" className="btn" onClick={() => setModalOpen(false)}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={saving}>
                <Zap size={14} />
                <span>{saving ? 'Pushing…' : 'Push to Fleet'}</span>
              </button>
            </div>
          </div>
        </form>
      </Modal>
    </div>
  );
}
