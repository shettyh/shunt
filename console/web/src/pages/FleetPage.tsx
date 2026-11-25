import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  KeyRound,
  Plus,
  RefreshCw,
  Server,
  Tag,
  Terminal,
  Trash2,
  XCircle,
} from 'lucide-react';
import {
  api,
  ApiProblemError,
  BootstrapTokenMeta,
  Cluster,
  CreatedBootstrapToken,
  formatRelativeTime,
  NamespaceStateSummary,
  NodeRecord,
  NodeStatus,
  shortDigest,
} from '../lib/api';
import { ConnectCommandBox, Modal, useToast } from '../components/ui';

function NodeStatusBadge({ status }: { status: NodeStatus }) {
  const map: Record<NodeStatus, { cls: string; label: string }> = {
    synced: { cls: 'badge badge-ok', label: 'Synced' },
    converging: { cls: 'badge badge-accent', label: 'Converging' },
    drifted: { cls: 'badge badge-danger', label: 'Drifted' },
    lagging: { cls: 'badge badge-warn', label: 'Policy Lag' },
    offline: { cls: 'badge', label: 'Offline' },
  };
  const cfg = map[status] || map.offline;
  return (
    <span className={cfg.cls}>
      <span
        className="inline-block w-1.5 h-1.5 rounded-full"
        style={{ background: 'currentColor' }}
      />
      <span>{cfg.label}</span>
    </span>
  );
}

function PolicySyncCell({
  node,
  namespaces,
}: {
  node: NodeRecord;
  namespaces: NamespaceStateSummary[];
}) {
  if (node.status === 'offline') {
    return (
      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Offline
      </span>
    );
  }
  const activeNamespaces = namespaces.filter((ns) => ns.head_seq > 0);
  const behind = activeNamespaces.filter((ns) => (node.synced_seqs[ns.namespace] ?? 0) < ns.head_seq);
  const detailsTooltip =
    activeNamespaces.length === 0
      ? 'No live policies configured yet'
      : activeNamespaces
          .map((ns) => `${ns.namespace}: v${node.synced_seqs[ns.namespace] ?? 0} / v${ns.head_seq}`)
          .join('\n');

  if (behind.length === 0) {
    return (
      <span className="badge badge-ok" title={detailsTooltip}>
        <CheckCircle2 size={11} />
        <span>Up to date</span>
      </span>
    );
  }

  return (
    <span className="badge badge-warn" title={detailsTooltip}>
      <span>
        {behind.length} {behind.length === 1 ? 'group' : 'groups'} syncing
      </span>
    </span>
  );
}

export function FleetPage({
  cluster,
  openConnectModal,
  onConnectModalClose,
}: {
  cluster: Cluster;
  openConnectModal: boolean;
  onConnectModalClose: () => void;
}) {
  const toast = useToast();
  const [nodes, setNodes] = useState<NodeRecord[]>([]);
  const [tokens, setTokens] = useState<BootstrapTokenMeta[]>([]);
  const [namespaces, setNamespaces] = useState<NamespaceStateSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Connect Node / Bootstrap Token creation modal state
  const [tokenName, setTokenName] = useState('fleet-enrollment');
  const [tokenLabels, setTokenLabels] = useState('ring=stable');
  const [tokenHours, setTokenHours] = useState('720');
  const [createdToken, setCreatedToken] = useState<CreatedBootstrapToken | null>(null);
  const [creatingToken, setCreatingToken] = useState(false);

  // Edit Node Labels modal
  const [editingNode, setEditingNode] = useState<NodeRecord | null>(null);
  const [editLabelsStr, setEditLabelsStr] = useState('');

  const load = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [n, t, ns] = await Promise.all([
        api.listNodes(cluster.slug),
        api.listBootstrapTokens(cluster.slug).catch(() => []),
        api.listStateNamespaces(cluster.slug).catch(() => []),
      ]);
      setNodes(n);
      setTokens(t);
      setNamespaces(ns);
    } catch (err) {
      if (!silent) {
        toast.push(err instanceof ApiProblemError ? err.message : 'Failed to load fleet', 'error');
      }
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [cluster.slug]);

  useEffect(() => {
    if (!autoRefresh) return;
    const id = window.setInterval(() => load(true), 4000);
    return () => window.clearInterval(id);
  }, [autoRefresh, cluster.slug]);

  const parseLabelsString = (raw: string): Record<string, string> => {
    const out: Record<string, string> = {};
    for (const part of raw.split(',').map((s) => s.trim()).filter(Boolean)) {
      const idx = part.indexOf('=');
      if (idx > 0) {
        out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
      }
    }
    return out;
  };

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreatingToken(true);
    try {
      const res = await api.createBootstrapToken(cluster.slug, {
        name: tokenName.trim() || 'node-enrollment',
        default_labels: parseLabelsString(tokenLabels),
        expires_in_hours: Number(tokenHours) > 0 ? Number(tokenHours) : null,
      });
      setCreatedToken(res);
      toast.push('Bootstrap token generated — copy the command below');
      load(true);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setCreatingToken(false);
    }
  };

  const handleRevokeToken = async (id: string) => {
    try {
      await api.revokeBootstrapToken(cluster.slug, id);
      toast.push('Bootstrap token revoked');
      load(true);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handleSaveLabels = async () => {
    if (!editingNode) return;
    try {
      await api.updateNodeLabels(cluster.slug, editingNode.id, parseLabelsString(editLabelsStr));
      toast.push(`Updated labels for ${editingNode.name}`);
      setEditingNode(null);
      load(true);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handleDeleteNode = async (node: NodeRecord) => {
    if (!window.confirm(`Deregister node "${node.name}" from ${cluster.slug}?`)) return;
    try {
      await api.deleteNode(cluster.slug, node.id);
      toast.push(`Removed ${node.name}`);
      load(true);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="m-0 text-xl font-semibold tracking-tight">Fleet &amp; Nodes</h1>
          <p className="m-0 mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
            Live inventory of outbound-connected <code>shunt</code> instances, release rollout convergence, canary labels, and live policy sync health.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-xs cursor-pointer select-none px-2.5 py-1.5 rounded-lg surface">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            <span>Live poll (4s)</span>
          </label>
          <button type="button" className="btn" onClick={() => load()}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => {
              setCreatedToken(null);
              // Trigger via parent
              window.dispatchEvent(new CustomEvent('shunt-open-connect-node'));
            }}
          >
            <Plus size={14} />
            <span>Connect Node</span>
          </button>
        </div>
      </div>

      {/* Node Inventory Table */}
      <div className="surface overflow-hidden">
        {nodes.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <Server size={28} style={{ color: 'var(--text-muted)' }} className="mx-auto" />
            <div className="font-medium text-sm">No nodes enrolled in {cluster.slug}</div>
            <p className="m-0 text-xs max-w-md mx-auto" style={{ color: 'var(--text-muted)' }}>
              Mint a cluster bootstrap token and start any <code>shunt</code> binary with <code>--control-plane</code>. No local config file needed.
            </p>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => window.dispatchEvent(new CustomEvent('shunt-open-connect-node'))}
            >
              <Terminal size={14} />
              <span>Connect First Node</span>
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="swiss-table text-xs">
              <thead>
                <tr>
                  <th>Node</th>
                  <th>Status</th>
                  <th>Config Release</th>
                  <th>Live Policies</th>
                  <th>Labels</th>
                  <th>Last Heartbeat</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {nodes.map((node) => (
                  <React.Fragment key={node.id}>
                    <tr>
                      <td>
                        <div className="font-semibold text-sm">{node.name}</div>
                        <div className="mono text-[11px]" style={{ color: 'var(--text-muted)' }}>
                          {node.id} · v{node.shunt_version}
                        </div>
                      </td>
                      <td>
                        <NodeStatusBadge status={node.status} />
                      </td>
                      <td className="mono">
                        <div>
                          <strong>v{node.active_revision}</strong>
                          {node.target_revision != null && node.target_revision !== node.active_revision && (
                            <span style={{ color: 'var(--warn)' }}> → v{node.target_revision}</span>
                          )}
                        </div>
                        <div className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
                          {shortDigest(node.active_digest)}
                        </div>
                      </td>
                      <td>
                        <PolicySyncCell node={node} namespaces={namespaces} />
                      </td>
                      <td>
                        <div className="flex flex-wrap gap-1">
                          {Object.entries(node.labels).length === 0 ? (
                            <span style={{ color: 'var(--text-muted)' }}>none</span>
                          ) : (
                            Object.entries(node.labels).map(([k, v]) => (
                              <span key={k} className="badge mono text-[11px]">
                                {k}={v}
                              </span>
                            ))
                          )}
                        </div>
                      </td>
                      <td style={{ color: 'var(--text-muted)' }}>
                        {formatRelativeTime(node.last_heartbeat_at)}
                      </td>
                      <td className="text-right">
                        <div className="inline-flex items-center gap-1">
                          <button
                            type="button"
                            className="btn text-xs py-1 px-2"
                            title="Edit labels (canary rings)"
                            onClick={() => {
                              setEditingNode(node);
                              setEditLabelsStr(
                                Object.entries(node.labels)
                                  .map(([k, v]) => `${k}=${v}`)
                                  .join(',')
                              );
                            }}
                          >
                            <Tag size={12} />
                            <span>Labels</span>
                          </button>
                          <button
                            type="button"
                            className="btn-ghost p-1.5 rounded cursor-pointer border-0"
                            style={{ color: 'var(--danger)' }}
                            title="Deregister node"
                            onClick={() => handleDeleteNode(node)}
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                    {node.last_reload_error && (
                      <tr>
                        <td colSpan={7} style={{ background: 'var(--danger-soft)' }}>
                          <div className="flex items-start gap-2 text-xs" style={{ color: 'var(--danger)' }}>
                            <AlertTriangle size={14} className="shrink-0 mt-0.5" />
                            <div>
                              <strong>Last reload failed (previous snapshot preserved):</strong>{' '}
                              <code className="mono">{node.last_reload_error}</code>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Bootstrap Tokens List */}
      <div className="surface p-5 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="m-0 text-sm font-semibold flex items-center gap-2">
              <KeyRound size={15} />
              <span>Cluster Bootstrap Enrollment Tokens</span>
            </h2>
            <p className="m-0 mt-0.5 text-xs" style={{ color: 'var(--text-muted)' }}>
              Tokens used by new <code>shunt</code> nodes to enroll and obtain a long-lived node credential.
            </p>
          </div>
        </div>

        {tokens.length === 0 ? (
          <div className="text-xs py-4" style={{ color: 'var(--text-muted)' }}>
            No enrollment tokens created yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="swiss-table text-xs">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Prefix</th>
                  <th>Default Labels</th>
                  <th>Uses</th>
                  <th>Status</th>
                  <th className="text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {tokens.map((t) => (
                  <tr key={t.id}>
                    <td className="font-medium">{t.name}</td>
                    <td className="mono">{t.prefix}</td>
                    <td>
                      {Object.entries(t.default_labels).map(([k, v]) => (
                        <span key={k} className="badge mono mr-1">
                          {k}={v}
                        </span>
                      ))}
                    </td>
                    <td className="mono">
                      {t.uses_count}
                      {t.max_uses ? ` / ${t.max_uses}` : ''}
                    </td>
                    <td>
                      {t.revoked_at ? (
                        <span className="badge badge-danger">
                          <XCircle size={11} />
                          Revoked
                        </span>
                      ) : (
                        <span className="badge badge-ok">
                          <CheckCircle2 size={11} />
                          Active
                        </span>
                      )}
                    </td>
                    <td className="text-right">
                      {!t.revoked_at && (
                        <button
                          type="button"
                          className="btn btn-danger text-xs py-1 px-2"
                          onClick={() => handleRevokeToken(t.id)}
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Connect Node Modal */}
      <Modal
        open={openConnectModal}
        onClose={() => {
          setCreatedToken(null);
          onConnectModalClose();
        }}
        title={`Connect a Shunt node to ${cluster.slug}`}
        subtitle="Generate a cluster bootstrap token and copy the ready-to-run command."
        maxWidth="max-w-2xl"
      >
        {!createdToken ? (
          <form onSubmit={handleCreateToken} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <div>
                <label className="block text-xs font-medium mb-1">Token Name</label>
                <input
                  className="input-base"
                  value={tokenName}
                  onChange={(e) => setTokenName(e.target.value)}
                  placeholder="prod-us-asg"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium mb-1">Expiry (hours, 0 = none)</label>
                <input
                  className="input-base mono"
                  type="number"
                  value={tokenHours}
                  onChange={(e) => setTokenHours(e.target.value)}
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium mb-1">
                Default Node Labels (comma-separated)
              </label>
              <input
                className="input-base mono text-xs"
                value={tokenLabels}
                onChange={(e) => setTokenLabels(e.target.value)}
                placeholder="ring=stable,region=us-east-1"
              />
              <div className="mt-1.5 flex gap-1.5">
                <button
                  type="button"
                  className="btn text-xs py-0.5 px-2"
                  onClick={() => setTokenLabels('ring=stable')}
                >
                  ring=stable
                </button>
                <button
                  type="button"
                  className="btn text-xs py-0.5 px-2"
                  onClick={() => setTokenLabels('ring=canary')}
                >
                  ring=canary
                </button>
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button type="button" className="btn" onClick={onConnectModalClose}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={creatingToken}>
                <Terminal size={14} />
                <span>{creatingToken ? 'Generating…' : 'Generate Token & Command'}</span>
              </button>
            </div>
          </form>
        ) : (
          <div className="space-y-4">
            <div
              className="p-3 rounded-lg text-xs"
              style={{
                background: 'var(--ok-soft)',
                border: '1px solid var(--ok-border)',
                color: 'var(--ok)',
              }}
            >
              Bootstrap token created! Copy it now — the plaintext secret is never stored or displayed again.
            </div>
            <ConnectCommandBox
              controlPlaneUrl={window.location.origin}
              clusterSlug={cluster.slug}
              token={createdToken.plaintext_token}
              labels={tokenLabels}
            />
            <div className="flex justify-end">
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => {
                  setCreatedToken(null);
                  onConnectModalClose();
                }}
              >
                Done
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* Edit Node Labels Modal */}
      <Modal
        open={Boolean(editingNode)}
        onClose={() => setEditingNode(null)}
        title={`Edit labels for ${editingNode?.name || ''}`}
        subtitle="Changing labels immediately re-evaluates canary ring assignments for this node."
      >
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium mb-1">Labels (`key=value,key2=value2`)</label>
            <input
              className="input-base mono text-xs"
              value={editLabelsStr}
              onChange={(e) => setEditLabelsStr(e.target.value)}
              placeholder="ring=canary,region=us-east-1"
              autoFocus
            />
          </div>
          <div className="flex justify-end gap-2">
            <button type="button" className="btn" onClick={() => setEditingNode(null)}>
              Cancel
            </button>
            <button type="button" className="btn btn-primary" onClick={handleSaveLabels}>
              Save &amp; Re-evaluate Ring
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
