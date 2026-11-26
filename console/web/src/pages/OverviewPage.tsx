import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  ArrowRight,
  Blocks,
  Check,
  Code2,
  GitBranch,
  KeyRound,
  Rocket,
  Server,
  ShieldCheck,
  Sparkles,
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
  TopologyResource,
  TopologyRevision,
  ValidateDraftResult,
} from '../lib/api';
import { extractAiGatewayState, extractMcpGatewayState } from '../lib/gateway';
import { NavSection } from '../components/CommandPalette';
import { ClusterHeaderContext, PageHeader } from '../components/PageHeader';
import { StatusIndicator, TagPill } from '../components/ui';

export function OverviewPage({
  cluster,
  headerCtx,
  resources,
  validation,
  revisions,
  hasPendingChanges,
  onNavigate,
  onConnectNode,
  onPublish,
}: {
  cluster: Cluster;
  headerCtx: ClusterHeaderContext;
  resources: TopologyResource[];
  validation: ValidateDraftResult | null;
  revisions: TopologyRevision[];
  hasPendingChanges: boolean;
  onNavigate: (s: NavSection) => void;
  onConnectNode: () => void;
  onPublish: () => void;
}) {
  const [nodes, setNodes] = useState<NodeRecord[]>([]);
  const [namespaces, setNamespaces] = useState<NamespaceStateSummary[]>([]);
  const [audit, setAudit] = useState<AdminAuditEntry[]>([]);
  const [auditCheck, setAuditCheck] = useState<AuditChainVerification | null>(null);

  useEffect(() => {
    let active = true;
    Promise.all([
      api.listNodes(cluster.slug).catch(() => []),
      api.listStateNamespaces(cluster.slug).catch(() => []),
      api.listAdminAudit(12).catch(() => []),
      api.verifyAdminAudit().catch(() => null),
    ]).then(([n, ns, a, v]) => {
      if (!active) return;
      setNodes(n);
      setNamespaces(ns);
      setAudit(a);
      setAuditCheck(v);
    });
    return () => {
      active = false;
    };
  }, [cluster.slug]);

  const ai = useMemo(() => extractAiGatewayState(resources), [resources]);
  const mcp = useMemo(() => extractMcpGatewayState(resources), [resources]);
  const httpRouteCount = useMemo(
    () =>
      resources.filter(
        (r) =>
          r.kind === 'route' &&
          r.id !== ai.routeResource?.id &&
          r.id !== mcp.routeResource?.id
      ).length,
    [resources, ai.routeResource, mcp.routeResource]
  );

  const syncedNodes = nodes.filter((n) => n.status === 'synced').length;
  const activeRev = cluster.ring_assignments['*'] ?? revisions[0]?.revision ?? 0;
  const virtualKeysCount =
    namespaces.find((ns) => ns.namespace === 'ai.virtual_keys')?.item_count ?? 0;
  const mcpAgentsCount =
    namespaces.find((ns) => ns.namespace === 'mcp.agent_acls')?.item_count ?? 0;

  const hasGatewayTraffic = ai.providers.length > 0 || mcp.servers.length > 0 || httpRouteCount > 0;
  const isPublished = activeRev > 0 && !hasPendingChanges;
  const hasNodes = nodes.length > 0;
  const showQuickstart = !hasGatewayTraffic || !hasNodes || hasPendingChanges;

  const checklist = [
    {
      id: 'provider',
      done: hasGatewayTraffic,
      title: 'Add an AI provider, MCP server, or HTTP route',
      detail:
        ai.providers.length > 0
          ? `${ai.providers.length} AI provider${ai.providers.length === 1 ? '' : 's'} ready (${ai.providers.map((p) => p.slug).join(', ')})`
          : 'Connect OpenAI, Anthropic, Gemini, Bedrock, Ollama, or any HTTP/MCP service in 30 seconds.',
      cta: 'Configure AI Gateway',
      onClick: () => onNavigate('ai'),
    },
    {
      id: 'publish',
      done: isPublished,
      title: hasPendingChanges ? 'Publish pending configuration changes' : 'Publish your signed gateway release',
      detail:
        activeRev > 0 && !hasPendingChanges
          ? `Release v${activeRev} is live across ring * (${shortDigest(revisions[0]?.digest || '')}).`
          : 'Every release is verified with shunt verify and Ed25519-signed before nodes reload.',
      cta: hasPendingChanges ? 'Publish Release' : 'View Releases',
      onClick: hasPendingChanges ? onPublish : () => onNavigate('releases'),
    },
    {
      id: 'node',
      done: hasNodes,
      title: 'Connect a Shunt data-plane node',
      detail: hasNodes
        ? `${syncedNodes}/${nodes.length} connected node${nodes.length === 1 ? '' : 's'} synced.`
        : 'Start a stateless shunt binary anywhere with one outbound command — zero local config files.',
      cta: 'Connect Node',
      onClick: onConnectNode,
    },
    {
      id: 'call',
      done: hasGatewayTraffic && hasNodes && isPublished,
      title: 'Send your first request via OpenAI SDK, Claude Code, or cURL',
      detail: 'Open ready-to-paste client snippets pre-filled with your models and virtual keys.',
      cta: 'Open API Snippets',
      onClick: headerCtx.onOpenApiDrawer,
    },
  ];

  return (
    <div>
      <PageHeader
        title="Overview"
        badge={
          <TagPill dot={cluster.environment === 'production' ? 'brand' : 'ok'}>
            {cluster.environment}
          </TagPill>
        }
        ctx={headerCtx}
        primaryAction={
          <button type="button" className="btn btn-primary h-8" onClick={() => onNavigate('ai')}>
            <Sparkles size={13} />
            <span>Add AI Provider</span>
          </button>
        }
      />

      {/* Quiet Single-Line Operational Pulse (No heavy 4-box dashboard slop) */}
      <div
        className="px-6 py-3.5 flex flex-wrap items-center gap-x-7 gap-y-2 tabular text-[13px]"
        style={{ borderBottom: '1px solid var(--border-row)' }}
      >
        <button
          type="button"
          onClick={() => onNavigate('ai')}
          className="btn-ghost px-1.5 py-0.5 -ml-1.5 text-[13px]"
        >
          <span style={{ color: 'var(--ink-muted)' }}>AI Providers</span>
          <span className="font-semibold" style={{ color: 'var(--ink)' }}>
            {ai.providers.length}
          </span>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('ai')}
          className="btn-ghost px-1.5 py-0.5 text-[13px]"
        >
          <span style={{ color: 'var(--ink-muted)' }}>Virtual Keys</span>
          <span className="font-semibold" style={{ color: 'var(--ink)' }}>
            {virtualKeysCount}
          </span>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('mcp')}
          className="btn-ghost px-1.5 py-0.5 text-[13px]"
        >
          <span style={{ color: 'var(--ink-muted)' }}>MCP Servers</span>
          <span className="font-semibold" style={{ color: 'var(--ink)' }}>
            {mcp.servers.length}
          </span>
          {mcpAgentsCount > 0 && (
            <span style={{ color: 'var(--ink-muted)' }}>· {mcpAgentsCount} agents</span>
          )}
        </button>

        <button
          type="button"
          onClick={() => onNavigate('fleet')}
          className="btn-ghost px-1.5 py-0.5 text-[13px]"
        >
          <span style={{ color: 'var(--ink-muted)' }}>Fleet</span>
          <span className="font-semibold" style={{ color: 'var(--ink)' }}>
            {syncedNodes}/{nodes.length} synced
          </span>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('releases')}
          className="btn-ghost px-1.5 py-0.5 text-[13px]"
        >
          <span style={{ color: 'var(--ink-muted)' }}>Live Release</span>
          <span className="mono font-semibold" style={{ color: 'var(--ink)' }}>
            {activeRev > 0 ? `v${activeRev}` : 'none'}
          </span>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('security')}
          className="btn-ghost px-1.5 py-0.5 text-[13px] ml-auto"
        >
          <ShieldCheck
            size={14}
            style={{ color: auditCheck?.valid ? 'var(--ok)' : 'var(--ink-muted)' }}
          />
          <span style={{ color: 'var(--ink-muted)' }}>
            {auditCheck?.valid ? `Audit verified (${auditCheck.checked_entries})` : 'Audit'}
          </span>
        </button>
      </div>

      {/* Guided Quickstart Checklist (Cloudflare-style progressive onboarding) */}
      {showQuickstart && (
        <section style={{ borderBottom: '1px solid var(--border-row)' }}>
          <div className="px-6 pt-5 pb-2 flex items-center justify-between">
            <div className="text-[12px] font-semibold uppercase tracking-wider" style={{ color: 'var(--ink-muted)' }}>
              Get started with {cluster.name}
            </div>
            <span className="text-[12px] tabular" style={{ color: 'var(--ink-muted)' }}>
              {checklist.filter((c) => c.done).length} of {checklist.length} complete
            </span>
          </div>
          <div>
            {checklist.map((item, idx) => (
              <div key={item.id} className="row-item">
                <div className="flex items-center gap-3.5 min-w-0">
                  <div
                    className="icon-tile"
                    style={{
                      background: item.done ? 'var(--ok-soft)' : 'var(--sheet)',
                      borderColor: item.done ? 'var(--ok-border)' : 'var(--border)',
                      color: item.done ? 'var(--ok)' : 'var(--ink-muted)',
                    }}
                  >
                    {item.done ? (
                      <Check size={14} />
                    ) : (
                      <span className="mono text-[12px] font-medium">{idx + 1}</span>
                    )}
                  </div>
                  <div className="min-w-0">
                    <div
                      className="text-[13.5px] font-medium"
                      style={{
                        color: item.done ? 'var(--ink-muted)' : 'var(--ink)',
                        textDecoration: item.done ? 'line-through' : 'none',
                      }}
                    >
                      {item.title}
                    </div>
                    <div className="text-[12.5px] truncate" style={{ color: 'var(--ink-muted)' }}>
                      {item.detail}
                    </div>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={item.onClick}
                  className={item.done ? 'btn btn-sm' : 'btn btn-sm btn-primary'}
                >
                  <span>{item.cta}</span>
                  <ArrowRight size={12} />
                </button>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Gateway Surfaces Summary (Direct Discoverability into Shunt's 3 Pillars) */}
      <section style={{ borderBottom: '1px solid var(--border-row)' }}>
        <div className="px-6 pt-5 pb-2 text-[12px] font-semibold uppercase tracking-wider" style={{ color: 'var(--ink-muted)' }}>
          Gateway Surfaces
        </div>

        <div className="row-item row-item-clickable" onClick={() => onNavigate('ai')}>
          <div className="flex items-center gap-3.5 min-w-0">
            <div className="icon-tile">
              <Sparkles size={15} style={{ color: 'var(--brand)' }} />
            </div>
            <div className="min-w-0 flex flex-wrap items-center gap-2">
              <span className="text-[14px] font-medium">AI Gateway</span>
              <span className="mono text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                {ai.routePath}
              </span>
              <TagPill dot={ai.providers.length > 0 ? 'brand' : 'neutral'}>
                {ai.providers.length} provider{ai.providers.length === 1 ? '' : 's'}
              </TagPill>
              <TagPill dot={ai.models.length > 0 ? 'info' : 'neutral'}>
                {ai.models.length} model{ai.models.length === 1 ? '' : 's'}
              </TagPill>
              {virtualKeysCount > 0 && (
                <TagPill dot="ok">{virtualKeysCount} virtual keys</TagPill>
              )}
            </div>
          </div>
          <div className="flex items-center gap-4 shrink-0">
            <StatusIndicator
              tone={ai.providers.length > 0 ? 'ok' : 'neutral'}
              label={ai.providers.length > 0 ? 'Configured' : 'Not set up'}
            />
            <ArrowRight size={14} style={{ color: 'var(--ink-muted)' }} />
          </div>
        </div>

        <div className="row-item row-item-clickable" onClick={() => onNavigate('mcp')}>
          <div className="flex items-center gap-3.5 min-w-0">
            <div className="icon-tile">
              <Blocks size={15} />
            </div>
            <div className="min-w-0 flex flex-wrap items-center gap-2">
              <span className="text-[14px] font-medium">MCP Gateway</span>
              <span className="mono text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                {mcp.routePath}
              </span>
              <TagPill dot={mcp.servers.length > 0 ? 'ok' : 'neutral'}>
                {mcp.servers.length} server{mcp.servers.length === 1 ? '' : 's'}
              </TagPill>
              {mcpAgentsCount > 0 && <TagPill dot="info">{mcpAgentsCount} agents</TagPill>}
            </div>
          </div>
          <div className="flex items-center gap-4 shrink-0">
            <StatusIndicator
              tone={mcp.servers.length > 0 ? 'ok' : 'neutral'}
              label={mcp.servers.length > 0 ? 'Configured' : 'Optional'}
            />
            <ArrowRight size={14} style={{ color: 'var(--ink-muted)' }} />
          </div>
        </div>

        <div className="row-item row-item-clickable" onClick={() => onNavigate('routes')}>
          <div className="flex items-center gap-3.5 min-w-0">
            <div className="icon-tile">
              <GitBranch size={15} />
            </div>
            <div className="min-w-0 flex flex-wrap items-center gap-2">
              <span className="text-[14px] font-medium">HTTP API Routes</span>
              <TagPill dot={httpRouteCount > 0 ? 'ok' : 'neutral'}>
                {httpRouteCount} custom route{httpRouteCount === 1 ? '' : 's'}
              </TagPill>
              <TagPill>
                {validation?.upstream_count ?? 0} total upstream{(validation?.upstream_count ?? 0) === 1 ? '' : 's'}
              </TagPill>
            </div>
          </div>
          <div className="flex items-center gap-4 shrink-0">
            <StatusIndicator
              tone={validation?.valid === false ? 'danger' : 'ok'}
              label={validation?.valid === false ? `${validation.errors} verify error` : 'Verified'}
            />
            <ArrowRight size={14} style={{ color: 'var(--ink-muted)' }} />
          </div>
        </div>
      </section>

      {/* Recent Control Plane Activity — Pure Editorial Rows */}
      <section>
        <div className="px-6 pt-5 pb-2 flex items-center justify-between">
          <div className="text-[12px] font-semibold uppercase tracking-wider" style={{ color: 'var(--ink-muted)' }}>
            Recent Activity
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              className="btn-ghost px-2 py-1 text-[12px]"
              onClick={headerCtx.onOpenApiDrawer}
            >
              <Code2 size={13} />
              <span>API Snippets</span>
            </button>
            <button
              type="button"
              className="btn-ghost px-2 py-1 text-[12px]"
              onClick={() => onNavigate('security')}
            >
              <span>Full Audit Log</span>
              <ArrowRight size={12} />
            </button>
          </div>
        </div>

        {audit.length === 0 ? (
          <div className="px-6 py-10 text-[13px]" style={{ color: 'var(--ink-muted)' }}>
            No control-plane events recorded yet.
          </div>
        ) : (
          <div>
            {audit.slice(0, 8).map((entry) => {
              const Icon = entry.action.includes('secret')
                ? KeyRound
                : entry.action.includes('release') || entry.action.includes('revision')
                  ? Rocket
                  : entry.action.includes('node')
                    ? Server
                    : entry.action.includes('token')
                      ? Terminal
                      : Activity;
              return (
                <div key={entry.seq} className="row-item">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="icon-tile">
                      <Icon size={14} />
                    </div>
                    <span className="mono text-[12px] w-10 shrink-0 tabular" style={{ color: 'var(--ink-muted)' }}>
                      #{entry.seq}
                    </span>
                    <span className="text-[13.5px] font-medium truncate">
                      {entry.resource_type}/{entry.resource_id}
                    </span>
                    <TagPill dot="brand" mono>
                      {entry.action}
                    </TagPill>
                  </div>
                  <div className="flex items-center gap-5 shrink-0 text-[12.5px]" style={{ color: 'var(--ink-muted)' }}>
                    <span className="hidden sm:inline truncate max-w-[160px]">{entry.actor_id}</span>
                    <span className="tabular w-16 text-right">{formatRelativeTime(entry.ts)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
