import { useEffect, useState } from 'react';
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  FileCode2,
  KeyRound,
  Layers,
  RefreshCw,
  Server,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import {
  AdminAuditEntry,
  api,
  AuditChainVerification,
  Cluster,
  formatRelativeTime,
  NamespaceStateSummary,
  NodeRecord,
  shortDigest,
  TopologyRevision,
} from '../lib/api';
import { NavSection } from '../components/CommandPalette';

export function OverviewPage({
  cluster,
  onNavigate,
  onConnectNode,
}: {
  cluster: Cluster;
  onNavigate: (s: NavSection) => void;
  onConnectNode: () => void;
}) {
  const [nodes, setNodes] = useState<NodeRecord[]>([]);
  const [revisions, setRevisions] = useState<TopologyRevision[]>([]);
  const [namespaces, setNamespaces] = useState<NamespaceStateSummary[]>([]);
  const [audit, setAudit] = useState<AdminAuditEntry[]>([]);
  const [auditCheck, setAuditCheck] = useState<AuditChainVerification | null>(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [n, r, ns, a, v] = await Promise.all([
        api.listNodes(cluster.slug),
        api.listRevisions(cluster.slug),
        api.listStateNamespaces(cluster.slug),
        api.listAdminAudit(8).catch(() => []),
        api.verifyAdminAudit().catch(() => null),
      ]);
      setNodes(n);
      setRevisions(r);
      setNamespaces(ns);
      setAudit(a);
      setAuditCheck(v);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [cluster.slug]);

  const syncedNodes = nodes.filter((n) => n.status === 'synced').length;
  const driftedNodes = nodes.filter((n) => n.status === 'drifted' || n.status === 'lagging').length;
  const activeDefaultRev = cluster.ring_assignments['*'] ?? revisions[0]?.revision ?? 0;
  const totalCh2Items = namespaces.reduce((acc, s) => acc + s.item_count, 0);
  const latestRev = revisions.find((r) => r.revision === activeDefaultRev) || revisions[0];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="m-0 text-xl font-semibold tracking-tight">{cluster.name}</h1>
            <span className="badge mono">{cluster.slug}</span>
            <span className="badge badge-accent">{cluster.environment}</span>
          </div>
          <p className="m-0 mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
            Unified 3-Channel control plane overview for Channel 1 topology revisions and Channel 2 dynamic state tables.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button type="button" className="btn" onClick={load} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          <button type="button" className="btn btn-primary" onClick={onConnectNode}>
            <Terminal size={14} />
            <span>Connect Node</span>
          </button>
        </div>
      </div>

      {/* Onboarding callout if 0 nodes connected */}
      {!loading && nodes.length === 0 && (
        <div
          className="surface p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
          style={{
            background: 'var(--accent-soft)',
            borderColor: 'var(--accent-border)',
          }}
        >
          <div>
            <div className="font-semibold text-sm flex items-center gap-2">
              <Server size={16} style={{ color: 'var(--accent)' }} />
              <span>No data-plane nodes connected to {cluster.slug} yet</span>
            </div>
            <p className="m-0 mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
              Connect your first stateless <code>shunt</code> node with one outbound command. It will pull Revision #{activeDefaultRev || 1} and stay synchronized automatically.
            </p>
          </div>
          <button type="button" className="btn btn-accent shrink-0" onClick={onConnectNode}>
            <Terminal size={14} />
            <span>Get Connect Command</span>
          </button>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 tabular">
        <button
          type="button"
          onClick={() => onNavigate('fleet')}
          className="surface p-4 text-left cursor-pointer hover:border-[var(--accent)] transition-colors"
        >
          <div className="flex items-center justify-between text-xs" style={{ color: 'var(--text-muted)' }}>
            <span>FLEET NODES</span>
            <Server size={14} />
          </div>
          <div className="mt-2 text-2xl font-semibold mono">{nodes.length}</div>
          <div className="mt-1 text-xs" style={{ color: driftedNodes > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>
            {nodes.length === 0
              ? 'Ready to enroll'
              : driftedNodes > 0
                ? `${syncedNodes} synced · ${driftedNodes} drifted/lagging`
                : `${syncedNodes}/${nodes.length} synced`}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('topology')}
          className="surface p-4 text-left cursor-pointer hover:border-[var(--accent)] transition-colors"
        >
          <div className="flex items-center justify-between text-xs" style={{ color: 'var(--text-muted)' }}>
            <span>CHANNEL 1 REVISION</span>
            <FileCode2 size={14} />
          </div>
          <div className="mt-2 text-2xl font-semibold mono">
            {activeDefaultRev > 0 ? `v${activeDefaultRev}` : 'Draft'}
          </div>
          <div className="mt-1 text-xs mono" style={{ color: 'var(--text-muted)' }}>
            {latestRev ? `sha256:${shortDigest(latestRev.digest)}` : 'No published revision yet'}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('state')}
          className="surface p-4 text-left cursor-pointer hover:border-[var(--accent)] transition-colors"
        >
          <div className="flex items-center justify-between text-xs" style={{ color: 'var(--text-muted)' }}>
            <span>CHANNEL 2 STATE ITEMS</span>
            <Layers size={14} />
          </div>
          <div className="mt-2 text-2xl font-semibold mono">{totalCh2Items}</div>
          <div className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
            Across {namespaces.length} lock-free ArcSwap namespaces
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('access')}
          className="surface p-4 text-left cursor-pointer hover:border-[var(--accent)] transition-colors"
        >
          <div className="flex items-center justify-between text-xs" style={{ color: 'var(--text-muted)' }}>
            <span>ADMIN AUDIT CHAIN</span>
            <ShieldCheck size={14} />
          </div>
          <div className="mt-2 text-2xl font-semibold mono">
            {auditCheck ? (auditCheck.valid ? 'Verified' : 'Alert') : '—'}
          </div>
          <div className="mt-1 text-xs" style={{ color: auditCheck?.valid ? 'var(--ok)' : 'var(--text-muted)' }}>
            {auditCheck ? `${auditCheck.checked_entries} hash-chained rows` : 'Read-only access'}
          </div>
        </button>
      </div>

      {/* Main two-column operational breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Ring assignments & quick actions */}
        <div className="surface p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="m-0 text-sm font-semibold">Active Rollout Rings</h2>
            <button
              type="button"
              className="btn-ghost text-xs py-1 px-2 flex items-center gap-1 cursor-pointer border-0 rounded"
              onClick={() => onNavigate('topology')}
            >
              <span>Manage</span>
              <ArrowRight size={12} />
            </button>
          </div>

          {Object.keys(cluster.ring_assignments).length === 0 ? (
            <p className="m-0 text-xs" style={{ color: 'var(--text-muted)' }}>
              No topology revisions published yet. Open <strong>Topology &amp; Revisions</strong> to validate and publish Revision #1.
            </p>
          ) : (
            <div className="space-y-2 tabular">
              {Object.entries(cluster.ring_assignments).map(([ring, rev]) => (
                <div
                  key={ring}
                  className="flex items-center justify-between px-3 py-2 rounded-lg"
                  style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-light)' }}
                >
                  <span className="mono text-xs font-medium">
                    {ring === '*' ? '* (all default nodes)' : ring}
                  </span>
                  <span className="badge badge-ok mono">rev #{rev}</span>
                </div>
              ))}
            </div>
          )}

          <div className="pt-3 space-y-2" style={{ borderTop: '1px solid var(--border-light)' }}>
            <div className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
              Common Workflows
            </div>
            <button
              type="button"
              className="btn w-full justify-between"
              onClick={() => onNavigate('topology')}
            >
              <span className="flex items-center gap-2">
                <FileCode2 size={14} />
                <span>Edit or Import shunt.toml</span>
              </span>
              <ArrowRight size={13} />
            </button>
            <button
              type="button"
              className="btn w-full justify-between"
              onClick={() => onNavigate('state')}
            >
              <span className="flex items-center gap-2">
                <Layers size={14} />
                <span>Push Instant Channel 2 Update</span>
              </span>
              <ArrowRight size={13} />
            </button>
            <button
              type="button"
              className="btn w-full justify-between"
              onClick={() => onNavigate('secrets')}
            >
              <span className="flex items-center gap-2">
                <KeyRound size={14} />
                <span>Store Encrypted Secret</span>
              </span>
              <ArrowRight size={13} />
            </button>
          </div>
        </div>

        {/* Recent Admin Audit Feed */}
        <div className="surface p-5 lg:col-span-2">
          <div className="flex items-center justify-between mb-3">
            <h2 className="m-0 text-sm font-semibold flex items-center gap-2">
              <Activity size={15} />
              <span>Recent Control Plane Activity</span>
            </h2>
            <button
              type="button"
              className="btn-ghost text-xs py-1 px-2 flex items-center gap-1 cursor-pointer border-0 rounded"
              onClick={() => onNavigate('access')}
            >
              <span>Full Audit Log</span>
              <ArrowRight size={12} />
            </button>
          </div>

          {audit.length === 0 ? (
            <div className="py-10 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
              No audit events recorded yet.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="swiss-table text-xs">
                <thead>
                  <tr>
                    <th>Seq</th>
                    <th>Action</th>
                    <th>Resource</th>
                    <th>Actor</th>
                    <th>When</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.map((entry) => (
                    <tr key={entry.seq}>
                      <td className="mono" style={{ color: 'var(--text-muted)' }}>
                        #{entry.seq}
                      </td>
                      <td>
                        <span className="badge mono">{entry.action}</span>
                      </td>
                      <td className="mono">
                        {entry.resource_type}/{entry.resource_id}
                      </td>
                      <td style={{ color: 'var(--text-secondary)' }}>{entry.actor_id}</td>
                      <td style={{ color: 'var(--text-muted)' }}>{formatRelativeTime(entry.ts)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {auditCheck?.valid && (
            <div
              className="mt-3 pt-3 flex items-center gap-2 text-xs"
              style={{ borderTop: '1px solid var(--border-light)', color: 'var(--ok)' }}
            >
              <CheckCircle2 size={13} />
              <span>{auditCheck.message}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
