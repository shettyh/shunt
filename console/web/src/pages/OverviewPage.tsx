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
        api.listAdminAudit(12).catch(() => []),
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
    <div className="space-y-3.5">
      {/* Compact Header Strip */}
      <div className="surface px-3.5 py-2.5 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2 min-w-0">
          <span className="font-semibold text-sm">{cluster.name}</span>
          <span className="badge mono">{cluster.slug}</span>
          <span className="text-xs hidden md:inline" style={{ color: 'var(--text-muted)' }}>
            Unified gateway control plane for HTTP APIs, AI routing, and MCP governance
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button type="button" className="btn btn-sm" onClick={load} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          <button type="button" className="btn btn-sm btn-primary" onClick={onConnectNode}>
            <Terminal size={13} />
            <span>Connect Node</span>
          </button>
        </div>
      </div>

      {/* Onboarding callout if 0 nodes connected */}
      {!loading && nodes.length === 0 && (
        <div
          className="surface px-4 py-3 flex flex-wrap items-center justify-between gap-3"
          style={{
            background: 'var(--accent-soft)',
            borderColor: 'var(--accent-border)',
          }}
        >
          <div className="flex items-center gap-2.5 text-xs min-w-0">
            <Server size={15} style={{ color: 'var(--accent)' }} className="shrink-0" />
            <span>
              <strong>No data-plane nodes connected to {cluster.slug} yet.</strong> Connect a stateless{' '}
              <code>shunt</code> node with one outbound command—it will pull Release #{activeDefaultRev || 1} automatically.
            </span>
          </div>
          <button type="button" className="btn btn-sm btn-accent shrink-0" onClick={onConnectNode}>
            <Terminal size={12} />
            <span>Get Connect Command</span>
          </button>
        </div>
      )}

      {/* Dense KPI Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 tabular">
        <button
          type="button"
          onClick={() => onNavigate('fleet')}
          className="surface px-3.5 py-3 text-left cursor-pointer hover:border-[var(--accent)] transition-colors"
        >
          <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
            <span>Fleet Nodes</span>
            <Server size={13} />
          </div>
          <div className="mt-1.5 flex items-baseline justify-between gap-2">
            <span className="text-xl font-semibold mono">{nodes.length}</span>
            <span className="text-[11px] truncate" style={{ color: driftedNodes > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>
              {nodes.length === 0
                ? 'Ready to enroll'
                : driftedNodes > 0
                  ? `${syncedNodes} synced · ${driftedNodes} issue`
                  : `${syncedNodes}/${nodes.length} synced`}
            </span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('topology')}
          className="surface px-3.5 py-3 text-left cursor-pointer hover:border-[var(--accent)] transition-colors"
        >
          <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
            <span>Active Release</span>
            <FileCode2 size={13} />
          </div>
          <div className="mt-1.5 flex items-baseline justify-between gap-2">
            <span className="text-xl font-semibold mono">
              {activeDefaultRev > 0 ? `v${activeDefaultRev}` : 'Draft'}
            </span>
            <span className="text-[11px] mono truncate" style={{ color: 'var(--text-muted)' }}>
              {latestRev ? shortDigest(latestRev.digest) : 'unpublished'}
            </span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('state')}
          className="surface px-3.5 py-3 text-left cursor-pointer hover:border-[var(--accent)] transition-colors"
        >
          <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
            <span>Live Policies</span>
            <Layers size={13} />
          </div>
          <div className="mt-1.5 flex items-baseline justify-between gap-2">
            <span className="text-xl font-semibold mono">{totalPolicyItems}</span>
            <span className="text-[11px] truncate" style={{ color: 'var(--text-muted)' }}>
              {namespaces.length} instant-sync groups
            </span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('access')}
          className="surface px-3.5 py-3 text-left cursor-pointer hover:border-[var(--accent)] transition-colors"
        >
          <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
            <span>Audit Chain</span>
            <ShieldCheck size={13} />
          </div>
          <div className="mt-1.5 flex items-baseline justify-between gap-2">
            <span className="text-xl font-semibold mono">
              {auditCheck ? (auditCheck.valid ? 'Verified' : 'Alert') : '—'}
            </span>
            <span className="text-[11px] truncate" style={{ color: auditCheck?.valid ? 'var(--ok)' : 'var(--text-muted)' }}>
              {auditCheck ? `${auditCheck.checked_entries} rows` : 'Read-only'}
            </span>
          </div>
        </button>
      </div>

      {/* Main Operational Split */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-3.5 items-start">
        {/* Left: Active Rollout Rings + Quick Actions */}
        <div className="surface p-4 xl:col-span-4 space-y-3.5">
          <div className="flex items-center justify-between">
            <h2 className="m-0 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
              Active Rollout Rings
            </h2>
            <button
              type="button"
              className="btn-ghost text-xs px-1.5 py-0.5 flex items-center gap-1 cursor-pointer border-0 rounded"
              onClick={() => onNavigate('topology')}
            >
              <span>Manage</span>
              <ArrowRight size={11} />
            </button>
          </div>

          {Object.keys(cluster.ring_assignments).length === 0 ? (
            <p className="m-0 text-xs" style={{ color: 'var(--text-muted)' }}>
              No releases published yet. Open <strong>Config &amp; Releases</strong> to validate and publish Release #1.
            </p>
          ) : (
            <div className="space-y-1.5 tabular">
              {Object.entries(cluster.ring_assignments).map(([ring, rev]) => (
                <div
                  key={ring}
                  className="flex items-center justify-between px-2.5 py-1.5 rounded-md"
                  style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-light)' }}
                >
                  <span className="mono text-xs font-medium">
                    {ring === '*' ? '* (all default nodes)' : ring}
                  </span>
                  <span className="badge badge-ok mono">v{rev}</span>
                </div>
              ))}
            </div>
          )}

          <div className="pt-3 space-y-1.5" style={{ borderTop: '1px solid var(--border-light)' }}>
            <div className="text-[11px] font-semibold uppercase tracking-wide mb-1" style={{ color: 'var(--text-muted)' }}>
              Quick Actions
            </div>
            <button
              type="button"
              className="btn btn-sm w-full justify-between"
              onClick={() => onNavigate('topology')}
            >
              <span className="flex items-center gap-2">
                <FileCode2 size={13} />
                <span>Edit Config or Import shunt.toml</span>
              </span>
              <ArrowRight size={12} />
            </button>
            <button
              type="button"
              className="btn btn-sm w-full justify-between"
              onClick={() => onNavigate('state')}
            >
              <span className="flex items-center gap-2">
                <Layers size={13} />
                <span>Manage Live Policies</span>
              </span>
              <ArrowRight size={12} />
            </button>
            <button
              type="button"
              className="btn btn-sm w-full justify-between"
              onClick={() => onNavigate('secrets')}
            >
              <span className="flex items-center gap-2">
                <KeyRound size={13} />
                <span>Store Encrypted Secret</span>
              </span>
              <ArrowRight size={12} />
            </button>
          </div>
        </div>

        {/* Right: Recent Control Plane Activity */}
        <div className="surface overflow-hidden xl:col-span-8">
          <div
            className="px-4 py-2.5 flex items-center justify-between gap-2"
            style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-sidebar)' }}
          >
            <div className="flex items-center gap-2">
              <Activity size={14} style={{ color: 'var(--text-muted)' }} />
              <span className="text-xs font-semibold">Recent Control Plane Activity</span>
              {auditCheck?.valid && (
                <span className="badge badge-ok hidden sm:inline-flex">
                  <CheckCircle2 size={10} />
                  <span>Hash chain intact</span>
                </span>
              )}
            </div>
            <button
              type="button"
              className="btn-ghost text-xs px-1.5 py-0.5 flex items-center gap-1 cursor-pointer border-0 rounded"
              onClick={() => onNavigate('access')}
            >
              <span>Full Audit Log</span>
              <ArrowRight size={11} />
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
                      <td className="mono whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                        #{entry.seq}
                      </td>
                      <td className="whitespace-nowrap">
                        <span className="badge mono">{entry.action}</span>
                      </td>
                      <td className="mono whitespace-nowrap">
                        {entry.resource_type}/{entry.resource_id}
                      </td>
                      <td className="whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>
                        {entry.actor_id}
                      </td>
                      <td className="whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
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
