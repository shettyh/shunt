import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  KeyRound,
  Plus,
  RefreshCw,
  Server,
  Tag,
  Terminal,
  Trash2,
} from 'lucide-react';
import {
  api,
  ApiProblemError,
  BootstrapTokenMeta,
  Cluster,
  CreatedBootstrapToken,
  formatRelativeTime,
  NodeRecord,
  NodeStatus,
  shortDigest,
} from '../lib/api';
import { ClusterHeaderContext, PageHeader } from '../components/PageHeader';
import {
  ConnectCommandBox,
  EmptyState,
  Modal,
  SearchField,
  SegmentedTabs,
  StatusIndicator,
  TagPill,
  useToast,
} from '../components/ui';

type FleetTab = 'nodes' | 'tokens';

function statusTone(status: NodeStatus): { tone: 'ok' | 'warn' | 'danger' | 'neutral'; label: string } {
  switch (status) {
    case 'synced':
      return { tone: 'ok', label: 'Synced' };
    case 'converging':
      return { tone: 'warn', label: 'Converging' };
    case 'lagging':
      return { tone: 'warn', label: 'Policy Lag' };
    case 'drifted':
      return { tone: 'danger', label: 'Drifted' };
    default:
      return { tone: 'neutral', label: 'Offline' };
  }
}

export function FleetPage({
  cluster,
  headerCtx,
  openConnectModal,
  onConnectModalClose,
  onOpenConnectModal,
}: {
  cluster: Cluster;
  headerCtx: ClusterHeaderContext;
  openConnectModal: boolean;
  onConnectModalClose: () => void;
  onOpenConnectModal: () => void;
}) {
  const toast = useToast();
  const [tab, setTab] = useState<FleetTab>('nodes');
  const [search, setSearch] = useState('');
  const [nodes, setNodes] = useState<NodeRecord[]>([]);
  const [tokens, setTokens] = useState<BootstrapTokenMeta[]>([]);
  const [loading, setLoading] = useState(true);

  // Connect Node modal
  const [tokenName, setTokenName] = useState('fleet-enrollment');
  const [tokenLabels, setTokenLabels] = useState('ring=stable');
  const [tokenHours, setTokenHours] = useState('720');
  const [createdToken, setCreatedToken] = useState<CreatedBootstrapToken | null>(null);
  const [creatingToken, setCreatingToken] = useState(false);

  // Labels modal
  const [editingNode, setEditingNode] = useState<NodeRecord | null>(null);
  const [editLabelsStr, setEditLabelsStr] = useState('');

  const load = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [n, t] = await Promise.all([
        api.listNodes(cluster.slug),
        api.listBootstrapTokens(cluster.slug).catch(() => []),
      ]);
      setNodes(n);
      setTokens(t);
    } catch (err) {
      if (!silent) toast.push(err instanceof ApiProblemError ? err.message : 'Failed to load fleet', 'error');
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const id = window.setInterval(() => load(true), 5000);
    return () => window.clearInterval(id);
  }, [cluster.slug]);

  const parseLabels = (raw: string): Record<string, string> => {
    const out: Record<string, string> = {};
    for (const part of raw.split(',').map((s) => s.trim()).filter(Boolean)) {
      const idx = part.indexOf('=');
      if (idx > 0) out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
    }
    return out;
  };

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreatingToken(true);
    try {
      const res = await api.createBootstrapToken(cluster.slug, {
        name: tokenName.trim() || 'node-enrollment',
        default_labels: parseLabels(tokenLabels),
        expires_in_hours: Number(tokenHours) > 0 ? Number(tokenHours) : null,
      });
      setCreatedToken(res);
      toast.push('Bootstrap token generated');
      load(true);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setCreatingToken(false);
    }
  };

  const handleSaveLabels = async () => {
    if (!editingNode) return;
    try {
      await api.updateNodeLabels(cluster.slug, editingNode.id, parseLabels(editLabelsStr));
      toast.push(`Updated labels for ${editingNode.name}`);
      setEditingNode(null);
      load(true);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handleDeleteNode = async (node: NodeRecord) => {
    if (!window.confirm(`Deregister node "${node.name}" from ${cluster.slug}?`)) return;
    await api.deleteNode(cluster.slug, node.id);
    toast.push(`Removed ${node.name}`);
    load(true);
  };

  const handleRevokeToken = async (id: string) => {
    await api.revokeBootstrapToken(cluster.slug, id);
    toast.push('Enrollment token revoked');
    load(true);
  };

  const q = search.trim().toLowerCase();
  const filteredNodes = nodes.filter(
    (n) => !q || n.name.toLowerCase().includes(q) || n.id.toLowerCase().includes(q)
  );
  const filteredTokens = tokens.filter(
    (t) => !q || t.name.toLowerCase().includes(q) || t.prefix.toLowerCase().includes(q)
  );

  return (
    <div>
      <PageHeader
        title="Fleet"
        ctx={headerCtx}
        secondaryAction={
          <button type="button" className="btn h-8 px-2.5" onClick={() => load()} title="Refresh">
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          </button>
        }
        primaryAction={
          <button
            type="button"
            className="btn btn-primary h-8"
            onClick={() => {
              setCreatedToken(null);
              onOpenConnectModal();
            }}
          >
            <Plus size={14} />
            <span>Connect node</span>
          </button>
        }
        controlsLeft={
          <SegmentedTabs
            value={tab}
            onChange={setTab}
            items={[
              { id: 'nodes', label: 'Nodes', count: nodes.length },
              { id: 'tokens', label: 'Enrollment Tokens', count: tokens.length },
            ]}
          />
        }
        controlsRight={<SearchField value={search} onChange={setSearch} placeholder="Search fleet" />}
      />

      {tab === 'nodes' && (
        <div>
          {filteredNodes.length === 0 ? (
            <EmptyState
              icon={<Server size={17} />}
              title={`No nodes enrolled in ${cluster.slug}`}
              description="Start any stateless shunt binary with --control-plane. Nodes connect outbound-only and pull signed releases automatically."
              action={
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => {
                    setCreatedToken(null);
                    onOpenConnectModal();
                  }}
                >
                  <Terminal size={14} />
                  <span>Connect First Node</span>
                </button>
              }
            />
          ) : (
            <div>
              {filteredNodes.map((node) => {
                const st = statusTone(node.status);
                return (
                  <div key={node.id} style={{ borderBottom: '1px solid var(--border-row)' }} className="last:border-b-0">
                    <div className="row-item" style={{ borderBottom: 'none' }}>
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="icon-tile">
                          <Server size={14} />
                        </div>
                        <span className="text-[14px] font-medium truncate">{node.name}</span>
                        <TagPill mono dot={node.target_revision && node.target_revision !== node.active_revision ? 'warn' : 'ok'}>
                          v{node.active_revision}
                          {node.target_revision != null && node.target_revision !== node.active_revision
                            ? ` → v${node.target_revision}`
                            : ''}
                        </TagPill>
                        <span className="hidden xl:inline mono text-[11.5px]" style={{ color: 'var(--ink-muted)' }}>
                          {shortDigest(node.active_digest)}
                        </span>
                        {Object.entries(node.labels).map(([k, v]) => (
                          <TagPill key={k} mono dot={k === 'ring' && v === 'canary' ? 'brand' : undefined}>
                            {k}={v}
                          </TagPill>
                        ))}
                      </div>

                      <div className="flex items-center gap-3 shrink-0">
                        <StatusIndicator tone={st.tone} label={st.label} />
                        <span className="hidden md:inline text-[12px] tabular w-16 text-right" style={{ color: 'var(--ink-muted)' }}>
                          {formatRelativeTime(node.last_heartbeat_at)}
                        </span>
                        <button
                          type="button"
                          className="btn btn-sm"
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
                          className="btn-ghost p-1.5"
                          style={{ color: 'var(--ink-muted)' }}
                          onClick={() => handleDeleteNode(node)}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </div>

                    {node.last_reload_error && (
                      <div
                        className="mx-6 mb-3 px-3.5 py-2 rounded-lg text-[12.5px] flex items-start gap-2"
                        style={{
                          background: 'var(--danger-soft)',
                          border: '1px solid var(--danger-border)',
                          color: 'var(--danger)',
                        }}
                      >
                        <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                        <span className="mono break-all">{node.last_reload_error}</span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {tab === 'tokens' && (
        <div>
          {filteredTokens.length === 0 ? (
            <EmptyState
              icon={<KeyRound size={17} />}
              title="No enrollment tokens"
              description="Generate a scoped bootstrap token to enroll Shunt data-plane instances into this cluster."
              action={
                <button type="button" className="btn btn-primary" onClick={onOpenConnectModal}>
                  <Plus size={14} />
                  <span>Generate Token</span>
                </button>
              }
            />
          ) : (
            <div>
              {filteredTokens.map((t) => (
                <div key={t.id} className="row-item">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="icon-tile">
                      <KeyRound size={14} />
                    </div>
                    <span className="text-[14px] font-medium truncate">{t.name}</span>
                    <TagPill mono>{t.prefix}</TagPill>
                    <span className="mono text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                      {t.uses_count}
                      {t.max_uses ? `/${t.max_uses}` : ''} uses
                    </span>
                  </div>
                  <div className="flex items-center gap-4 shrink-0">
                    <StatusIndicator
                      tone={t.revoked_at ? 'danger' : 'ok'}
                      label={t.revoked_at ? 'Revoked' : 'Active'}
                    />
                    {!t.revoked_at && (
                      <button
                        type="button"
                        className="btn btn-sm btn-danger"
                        onClick={() => handleRevokeToken(t.id)}
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Connect Node Modal */}
      <Modal
        open={openConnectModal}
        onClose={() => {
          setCreatedToken(null);
          onConnectModalClose();
        }}
        title={`Connect a Shunt node to ${cluster.slug}`}
        subtitle="Generate an enrollment token and copy the ready-to-run command."
        maxWidth="max-w-2xl"
      >
        {!createdToken ? (
          <form onSubmit={handleCreateToken} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <div>
                <label className="block text-[12.5px] font-medium mb-1">Token Name</label>
                <input
                  className="input-base"
                  value={tokenName}
                  onChange={(e) => setTokenName(e.target.value)}
                  required
                />
              </div>
              <div>
                <label className="block text-[12.5px] font-medium mb-1">Expiry (hours, 0 = none)</label>
                <input
                  type="number"
                  className="input-base mono"
                  value={tokenHours}
                  onChange={(e) => setTokenHours(e.target.value)}
                />
              </div>
            </div>
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Default Node Labels</label>
              <input
                className="input-base mono"
                value={tokenLabels}
                onChange={(e) => setTokenLabels(e.target.value)}
                placeholder="ring=stable,region=us-east-1"
              />
              <div className="flex gap-2 mt-2">
                <button type="button" className="btn btn-sm" onClick={() => setTokenLabels('ring=stable')}>
                  ring=stable
                </button>
                <button type="button" className="btn btn-sm" onClick={() => setTokenLabels('ring=canary')}>
                  ring=canary
                </button>
              </div>
            </div>
            <div className="flex justify-end gap-2.5 pt-2">
              <button type="button" className="btn" onClick={onConnectModalClose}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={creatingToken}>
                <Terminal size={14} />
                <span>{creatingToken ? 'Generating…' : 'Generate Command'}</span>
              </button>
            </div>
          </form>
        ) : (
          <div className="space-y-4">
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
        title={`Edit labels · ${editingNode?.name || ''}`}
        subtitle="Changing labels immediately re-evaluates canary ring assignments."
      >
        <div className="space-y-4">
          <input
            className="input-base mono"
            value={editLabelsStr}
            onChange={(e) => setEditLabelsStr(e.target.value)}
            placeholder="ring=canary,region=us-east-1"
            autoFocus
          />
          <div className="flex justify-end gap-2">
            <button type="button" className="btn" onClick={() => setEditingNode(null)}>
              Cancel
            </button>
            <button type="button" className="btn btn-primary" onClick={handleSaveLabels}>
              Save Labels
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
