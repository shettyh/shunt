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
        api.listAdminAudit(10).catch(() => []),
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
  const totalPolicyItems = namespaces.reduce((acc, s) => acc + s.item_count, 0);
  const latestRev = revisions.find((r) => r.revision === activeDefaultRev) || revisions[0];

  return (
    <div className="space-y-5">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="m-0 text-[22px] font-semibold tracking-tight">{cluster.name}</h1>
            <span className="badge mono">{cluster.slug}</span>
            <span className="badge badge-accent">{cluster.environment}</span>
          </div>
          <p className="m-0 mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
            Unified gateway control plane for HTTP APIs, AI routing, and MCP governance.
          </p>
        </div>
        <div className="flex items-center gap-2.5 shrink-0">
          <button type="button" className="btn" onClick={load} disabled={loading}>
            <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          <button type="button" className="btn btn-primary" onClick={onConnectNode}>
            <Terminal size={15} />
            <span>Connect Node</span>
          </button>
        </div>
      </div>

      {/* Onboarding callout if 0 nodes connected */}
      {!loading && nodes.length === 0 && (
        <div
          className="surface p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
          style={{
            background: 'var(--accent-soft)',
            borderColor: 'var(--accent-border)',
          }}
        >
          <div className="flex items-start gap-3">
            <Server size={18} style={{ color: 'var(--accent)' }} className="mt-0.5 shrink-0" />
            <div>
              <div className="font-semibold text-sm">No data-plane nodes connected to {cluster.slug} yet</div>
              <p className="m-0 mt-0.5 text-sm" style={{ color: 'var(--text-secondary)' }}>
                Connect your first stateless <code>shunt</code> node with one outbound command. It will pull Release v{activeDefaultRev || 1} and stay synchronized automatically.
              </p>
            </div>
          </div>
          <button type="button" className="btn btn-accent shrink-0" onClick={onConnectNode}>
            <Terminal size={15} />
            <span>Get Connect Command</span>
          </button>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 tabular">
        <button
          type="button"
          onClick={() => onNavigate('fleet')}
          className="surface p-4 text-left cursor-pointer hover:border-[var(--accent)] transition-colors"
        >
          <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
            <span>Fleet Nodes</span>
            <Server size={15} />
          </div>
          <div className="mt-2 text-2xl font-semibold mono">{nodes.length}</div>
          <div className="mt-1 text-xs" style={{ color: driftedNodes > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>
            {nodes.length === 0
              ? 'Ready to enroll'
              : driftedNodes > 0
                ? `${syncedNodes} synced · ${driftedNodes} issue`
                : `${syncedNodes}/${nodes.length} synced`}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('topology')}
          className="surface p-4 text-left cursor-pointer hover:border-[var(--accent)] transition-colors"
        >
          <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
            <span>Active Release</span>
            <FileCode2 size={15} />
          </div>
          <div className="mt-2 text-2xl font-semibold mono">
            {activeDefaultRev > 0 ? `v${activeDefaultRev}` : 'Draft'}
          </div>
          <div className="mt-1 text-xs mono" style={{ color: 'var(--text-muted)' }}>
            {latestRev ? shortDigest(latestRev.digest) : 'No published release yet'}
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('state')}
          className="surface p-4 text-left cursor-pointer hover:border-[var(--accent)] transition-colors"
        >
          <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
            <span>Live Policies</span>
            <Layers size={15} />
          </div>
          <div className="mt-2 text-2xl font-semibold mono">{totalPolicyItems}</div>
          <div className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
            Across {namespaces.length} instant-sync groups
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('access')}
          className="surface p-4 text-left cursor-pointer hover:border-[var(--accent)] transition-colors"
        >
          <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
            <span>Audit Chain</span>
            <ShieldCheck size={15} />
          </div>
          <div className="mt-2 text-2xl font-semibold mono">
            {auditCheck ? (auditCheck.valid ? 'Verified' : 'Alert') : '—'}
          </div>
          <div className="mt-1 text-xs" style={{ color: auditCheck?.valid ? 'var(--ok)' : 'var(--text-muted)' }}>
            {auditCheck ? `${auditCheck.checked_entries} hash-chained rows` : 'Read-only access'}
          </div>
        </button>
      </div>

      {/* Main Operational Split */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        <div className="surface p-5 xl:col-span-4 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="m-0 text-sm font-semibold">Active Rollout Rings</h2>
            <button
              type="button"
              className="btn-ghost text-xs px-2 py-1 flex items-center gap-1 cursor-pointer border-0 rounded"
              onClick={() => onNavigate('topology')}
            >
              <span>Manage</span>
              <ArrowRight size={13} />
            </button>
          </div>

          {Object.keys(cluster.ring_assignments).length === 0 ? (
            <p className="m-0 text-sm" style={{ color: 'var(--text-muted)' }}>
              No releases published yet. Open <strong>Config &amp; Releases</strong> to validate and publish Release v1.
            </p>
          ) : (
            <div className="space-y-2 tabular">
              {Object.entries(cluster.ring_assignments).map(([ring, rev]) => (
                <div
                  key={ring}
                  className="flex items-center justify-between px-3 py-2 rounded-lg"
                  style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-light)' }}
                >
                  <span className="mono text-sm font-medium">
                    {ring === '*' ? '* (all default nodes)' : ring}
                  </span>
                  <span className="badge badge-ok mono">v{rev}</span>
                </div>
              ))}
            </div>
          )}

          <div className="pt-3.5 space-y-2" style={{ borderTop: '1px solid var(--border-light)' }}>
            <div className="text-xs font-semibold uppercase tracking-wide mb-1.5" style={{ color: 'var(--text-muted)' }}>
              Quick Actions
            </div>
            <button
              type="button"
              className="btn w-full justify-between"
              onClick={() => onNavigate('topology')}
            >
              <span className="flex items-center gap-2">
                <FileCode2 size={15} />
                <span>Edit Config or Import shunt.toml</span>
              </span>
              <ArrowRight size={14} />
            </button>
            <button
              type="button"
              className="btn w-full justify-between"
              onClick={() => onNavigate('state')}
            >
              <span className="flex items-center gap-2">
                <Layers size={15} />
                <span>Manage Live Policies</span>
              </span>
              <ArrowRight size={14} />
            </button>
            <button
              type="button"
              className="btn w-full justify-between"
              onClick={() => onNavigate('secrets')}
            >
              <span className="flex items-center gap-2">
                <KeyRound size={15} />
                <span>Store Encrypted Secret</span>
              </span>
              <ArrowRight size={14} />
            </button>
          </div>
        </div>

        <div className="surface overflow-hidden xl:col-span-8">
          <div
            className="px-5 py-3.5 flex items-center justify-between gap-3"
            style={{ borderBottom: '1px solid var(--border)' }}
          >
            <div className="flex items-center gap-2.5">
              <Activity size={16} style={{ color: 'var(--text-muted)' }} />
              <h2 className="m-0 text-sm font-semibold">Recent Control Plane Activity</h2>
              {auditCheck?.valid && (
                <span className="badge badge-ok hidden sm:inline-flex">
                  <CheckCircle2 size={12} />
                  <span>Hash chain intact</span>
                </span>
              )}
            </div>
            <button
              type="button"
              className="btn-ghost text-xs px-2 py-1 flex items-center gap-1 cursor-pointer border-0 rounded"
              onClick={() => onNavigate('access')}
            >
              <span>Full Audit Log</span>
              <ArrowRight size={13} />
            </button>
          </div>

          {audit.length === 0 ? (
            <div className="p-10 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
              No audit events recorded yet.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="swiss-table">
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
                      <td className="mono text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                        #{entry.seq}
                      </td>
                      <td className="whitespace-nowrap">
                        <span className="badge mono">{entry.action}</span>
                      </td>
                      <td className="mono text-[13px] whitespace-nowrap">
                        {entry.resource_type}/{entry.resource_id}
                      </td>
                      <td className="whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>
                        {entry.actor_id}
                      </td>
                      <td className="text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                        {formatRelativeTime(entry.ts)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
