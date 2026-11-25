import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Columns2,
  Download,
  Edit3,
  FileCode2,
  GitBranch,
  History,
  Plus,
  Rocket,
  RotateCcw,
  Search,
  ShieldCheck,
  Trash2,
  Upload,
} from 'lucide-react';
import {
  api,
  ApiProblemError,
  Cluster,
  formatRelativeTime,
  shortDigest,
  slugify,
  TopologyResource,
  TopologyResourceKind,
  TopologyRevision,
  ValidateDraftResult,
} from '../lib/api';
import { CopyButton, Drawer, Modal, useToast } from '../components/ui';

const RESOURCE_TEMPLATES: Record<TopologyResourceKind, object> = {
  upstream: {
    name: 'my-service',
    endpoints: ['http://127.0.0.1:4000'],
  },
  route: {
    id: 'my-route',
    path_prefix: '/api/items',
    upstream: 'my-service',
    plugins: [],
  },
  route_group: {
    id: 'api-v1',
    path_prefix: '/v1',
    plugins: [],
  },
  global_plugin: {
    name: 'request-id',
    config: {},
  },
  server: {
    listen: '0.0.0.0:8080',
    drain_timeout_ms: 30000,
  },
  admin: {
    enabled: true,
    listen: '127.0.0.1:9090',
    ui: false,
  },
  state: {
    backend: 'memory',
  },
  telemetry: {
    enabled: false,
    backend: 'otlp_http',
  },
};

const QUICK_STARTER_SNIPPETS: Partial<
  Record<TopologyResourceKind, { label: string; slug: string; spec: object }[]>
> = {
  upstream: [
    {
      label: 'HTTP Service',
      slug: 'api-backend',
      spec: { name: 'api-backend', endpoints: ['http://127.0.0.1:3000'] },
    },
    {
      label: 'AI Provider (OpenAI)',
      slug: 'openai-upstream',
      spec: { name: 'openai-upstream', endpoints: ['https://api.openai.com'] },
    },
    {
      label: 'MCP Server',
      slug: 'mcp-github',
      spec: { name: 'mcp-github', endpoints: ['http://127.0.0.1:8090'] },
    },
  ],
  route: [
    {
      label: 'HTTP API Route',
      slug: 'api-route',
      spec: { id: 'api-route', path_prefix: '/api', upstream: 'api-backend', plugins: [] },
    },
    {
      label: 'AI Gateway (/v1)',
      slug: 'ai-v1',
      spec: { id: 'ai-v1', path_prefix: '/v1', upstream: 'openai-upstream', plugins: [] },
    },
    {
      label: 'MCP Gateway (/mcp)',
      slug: 'mcp-endpoint',
      spec: { id: 'mcp-endpoint', path_prefix: '/mcp', upstream: 'mcp-github', plugins: [] },
    },
  ],
};

const KIND_ORDER: Record<TopologyResourceKind, number> = {
  route: 0,
  route_group: 1,
  upstream: 2,
  global_plugin: 3,
  server: 4,
  admin: 5,
  state: 6,
  telemetry: 7,
};

const KIND_META: Record<TopologyResourceKind, { label: string; badgeCls: string }> = {
  route: { label: 'route', badgeCls: 'badge badge-accent mono' },
  route_group: { label: 'group', badgeCls: 'badge badge-accent mono' },
  upstream: { label: 'upstream', badgeCls: 'badge badge-ok mono' },
  global_plugin: { label: 'plugin', badgeCls: 'badge mono' },
  server: { label: 'server', badgeCls: 'badge mono' },
  admin: { label: 'admin', badgeCls: 'badge mono' },
  state: { label: 'state', badgeCls: 'badge mono' },
  telemetry: { label: 'telemetry', badgeCls: 'badge mono' },
};

type KindFilter = 'all' | 'route' | 'upstream' | 'route_group' | 'global_plugin' | 'system';

const SYSTEM_KINDS = new Set<TopologyResourceKind>(['server', 'admin', 'state', 'telemetry']);

function summarizeResource(r: TopologyResource): string {
  const s = (r.spec && typeof r.spec === 'object' ? r.spec : {}) as Record<string, unknown>;
  switch (r.kind) {
    case 'route': {
      const matcher = s.path_exact
        ? `EXACT ${String(s.path_exact)}`
        : s.path_template
          ? `TEMPLATE ${String(s.path_template)}`
          : s.path_regex
            ? `REGEX ${String(s.path_regex)}`
            : s.path_prefix
              ? `PREFIX ${String(s.path_prefix)}`
              : 'ANY';
      const target = s.upstream ? ` → ${String(s.upstream)}` : '';
      const group = s.group ? ` · group:${String(s.group)}` : '';
      const plugins = Array.isArray(s.plugins) && s.plugins.length > 0 ? ` · ${s.plugins.length} plugin${s.plugins.length === 1 ? '' : 's'}` : '';
      return `${matcher}${target}${group}${plugins}`;
    }
    case 'route_group': {
      const prefix = s.path_prefix ? `PREFIX ${String(s.path_prefix)}` : 'shared group';
      const upstream = s.upstream ? ` → ${String(s.upstream)}` : '';
      const plugins = Array.isArray(s.plugins) ? ` · ${s.plugins.length} plugin${s.plugins.length === 1 ? '' : 's'}` : '';
      return `${prefix}${upstream}${plugins}`;
    }
    case 'upstream': {
      const eps = Array.isArray(s.endpoints) ? s.endpoints.map(String) : [];
      const first = eps[0] || 'no endpoints';
      const more = eps.length > 1 ? ` (+${eps.length - 1} more)` : '';
      const timeout = typeof s.connect_timeout_ms === 'number' ? ` · connect ${s.connect_timeout_ms}ms` : '';
      return `${first}${more}${timeout}`;
    }
    case 'global_plugin': {
      const name = typeof s.name === 'string' ? s.name : r.slug;
      const cfg = s.config && typeof s.config === 'object' ? Object.keys(s.config as object) : [];
      return cfg.length > 0 ? `${name} (${cfg.join(', ')})` : `${name} (default config)`;
    }
    case 'server': {
      const listen = typeof s.listen === 'string' ? s.listen : '0.0.0.0:8080';
      const drain = typeof s.drain_timeout_ms === 'number' ? ` · drain ${Math.round(s.drain_timeout_ms / 1000)}s` : '';
      const tls = s.tls ? ' · TLS' : '';
      return `listen ${listen}${drain}${tls}`;
    }
    case 'admin': {
      if (s.enabled === false) return 'disabled';
      const listen = typeof s.listen === 'string' ? s.listen : '127.0.0.1:9090';
      const ui = s.ui ? ' · Inspector UI on' : ' · API only';
      return `${listen}${ui}`;
    }
    case 'state': {
      const backend = typeof s.backend === 'string' ? s.backend : 'memory';
      return `backend: ${backend}`;
    }
    case 'telemetry': {
      const enabled = Boolean(s.enabled);
      const backend = typeof s.backend === 'string' ? s.backend : 'otlp_http';
      return enabled ? `enabled · ${backend}` : `disabled (${backend})`;
    }
    default:
      return JSON.stringify(r.spec);
  }
}

export function TopologyPage({
  cluster,
  onClusterChanged,
}: {
  cluster: Cluster;
  onClusterChanged: () => void;
}) {
  const toast = useToast();
  const [tab, setTab] = useState<'draft' | 'toml' | 'revisions'>('draft');
  const [kindFilter, setKindFilter] = useState<KindFilter>('all');
  const [search, setSearch] = useState('');
  const [splitToml, setSplitToml] = useState(true);
  const [showDiagnostics, setShowDiagnostics] = useState(false);

  const [resources, setResources] = useState<TopologyResource[]>([]);
  const [validation, setValidation] = useState<ValidateDraftResult | null>(null);
  const [revisions, setRevisions] = useState<TopologyRevision[]>([]);
  const [loading, setLoading] = useState(true);

  // Resource Editor Drawer
  const [editorOpen, setEditorOpen] = useState(false);
  const [editKind, setEditKind] = useState<TopologyResourceKind>('route');
  const [editSlug, setEditSlug] = useState('');
  const [editEtag, setEditEtag] = useState<string | undefined>(undefined);
  const [editJson, setEditJson] = useState('');
  const [editError, setEditError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Import TOML Modal
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState('');
  const [importing, setImporting] = useState(false);

  // Publish Modal
  const [publishOpen, setPublishOpen] = useState(false);
  const [pubRing, setPubRing] = useState('*');
  const [pubNotes, setPubNotes] = useState('');
  const [publishing, setPublishing] = useState(false);

  // Inspect Release TOML Drawer
  const [inspectRev, setInspectRev] = useState<TopologyRevision | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const [res, val, revs] = await Promise.all([
        api.listResources(cluster.slug),
        api.validateDraft(cluster.slug),
        api.listRevisions(cluster.slug),
      ]);
      setResources(res);
      setValidation(val);
      setRevisions(revs);
      if (val && (!val.valid || val.diagnostics.length > 0)) {
        setShowDiagnostics(true);
      }
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : 'Failed to load config', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [cluster.slug]);

  const sortedResources = useMemo(() => {
    return [...resources].sort(
      (a, b) =>
        (KIND_ORDER[a.kind] ?? 99) - (KIND_ORDER[b.kind] ?? 99) ||
        a.sort_order - b.sort_order ||
        a.slug.localeCompare(b.slug)
    );
  }, [resources]);

  const filteredResources = useMemo(() => {
    const q = search.trim().toLowerCase();
    return sortedResources.filter((r) => {
      if (kindFilter === 'system') {
        if (!SYSTEM_KINDS.has(r.kind)) return false;
      } else if (kindFilter !== 'all' && r.kind !== kindFilter) {
        return false;
      }
      if (!q) return true;
      return (
        r.slug.toLowerCase().includes(q) ||
        r.kind.toLowerCase().includes(q) ||
        summarizeResource(r).toLowerCase().includes(q)
      );
    });
  }, [sortedResources, kindFilter, search]);

  const counts = useMemo(() => {
    const c = { all: resources.length, route: 0, upstream: 0, route_group: 0, global_plugin: 0, system: 0 };
    for (const r of resources) {
      if (SYSTEM_KINDS.has(r.kind)) c.system += 1;
      else if (r.kind in c) c[r.kind as keyof typeof c] += 1;
    }
    return c;
  }, [resources]);

  const openNewResource = (kind: TopologyResourceKind) => {
    setEditKind(kind);
    setEditSlug(kind === 'upstream' ? 'new-upstream' : kind === 'route' ? 'new-route' : 'default');
    setEditEtag(undefined);
    setEditJson(JSON.stringify(RESOURCE_TEMPLATES[kind], null, 2));
    setEditError(null);
    setEditorOpen(true);
  };

  const openEditResource = (r: TopologyResource) => {
    setEditKind(r.kind);
    setEditSlug(r.slug);
    setEditEtag(r.etag);
    setEditJson(JSON.stringify(r.spec, null, 2));
    setEditError(null);
    setEditorOpen(true);
  };

  const handleSaveResource = async (e: React.FormEvent) => {
    e.preventDefault();
    setEditError(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(editJson);
    } catch (err) {
      setEditError(`Invalid JSON: ${String(err)}`);
      return;
    }
    setSaving(true);
    try {
      await api.upsertResource(cluster.slug, editKind, slugify(editSlug), parsed, {
        etag: editEtag,
      });
      toast.push(`Saved ${editKind}/${slugify(editSlug)} to draft`);
      setEditorOpen(false);
      await load();
    } catch (err) {
      if (err instanceof ApiProblemError && err.status === 412) {
        setEditError('ETag conflict (412): This resource was updated by someone else. Close, refresh, and retry.');
      } else {
        setEditError(err instanceof ApiProblemError ? err.message : String(err));
      }
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteResource = async (r: TopologyResource) => {
    if (!window.confirm(`Delete ${r.kind}/${r.slug} from draft?`)) return;
    try {
      await api.deleteResource(cluster.slug, r.kind, r.slug, r.etag);
      toast.push(`Deleted ${r.kind}/${r.slug}`);
      load();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handleImportToml = async (e: React.FormEvent) => {
    e.preventDefault();
    setImporting(true);
    try {
      await api.importToml(cluster.slug, importText);
      toast.push('Imported shunt.toml into cluster draft');
      setImportOpen(false);
      setImportText('');
      await load();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setImporting(false);
    }
  };

  const handlePublish = async (e: React.FormEvent) => {
    e.preventDefault();
    setPublishing(true);
    try {
      const rev = await api.publishRevision(cluster.slug, {
        ring_selector: pubRing.trim() || '*',
        notes: pubNotes.trim(),
      });
      toast.push(`Published Release #${rev.revision} to ring "${pubRing || '*'}"`);
      setPublishOpen(false);
      setPubNotes('');
      onClusterChanged();
      await load();
      setTab('revisions');
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setPublishing(false);
    }
  };

  const handleRollback = async (rev: number) => {
    if (
      !window.confirm(
        `Roll back cluster "${cluster.slug}" default fleet to Release #${rev}?\n\nActive Live Policies (virtual keys, budgets, MCP agent permissions, and kill-switches) will NOT be reverted.`
      )
    ) {
      return;
    }
    try {
      await api.rollbackRevision(cluster.slug, rev, '*');
      toast.push(`Rolled back ${cluster.slug} to Release #${rev} (Live Policies untouched)`);
      onClusterChanged();
      await load();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handlePromote = async (rev: number) => {
    try {
      await api.promoteRevision(cluster.slug, rev, '*');
      toast.push(`Promoted Release #${rev} to all nodes (*)`);
      onClusterChanged();
      await load();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  return (
    <div className="space-y-3.5">
      {/* Compact Unified Toolbar */}
      <div className="surface px-3.5 py-2.5 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3 min-w-0">
          {/* Segmented View Switcher */}
          <div
            className="inline-flex rounded-md p-0.5 text-xs"
            style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border)' }}
          >
            {[
              { id: 'draft' as const, label: `Draft Config (${resources.length})`, icon: <GitBranch size={13} /> },
              { id: 'revisions' as const, label: `Releases (${revisions.length})`, icon: <History size={13} /> },
              { id: 'toml' as const, label: 'Full TOML', icon: <FileCode2 size={13} /> },
            ].map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id)}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded border-0 cursor-pointer font-medium transition-colors"
                style={{
                  background: tab === t.id ? 'var(--bg-elevated)' : 'transparent',
                  color: tab === t.id ? 'var(--text-primary)' : 'var(--text-muted)',
                  boxShadow: tab === t.id ? '0 1px 2px rgba(0,0,0,0.05)' : 'none',
                }}
              >
                {t.icon}
                <span>{t.label}</span>
              </button>
            ))}
          </div>

          {/* Inline Live Validation Pill */}
          {validation && (
            <button
              type="button"
              onClick={() => setShowDiagnostics((v) => !v)}
              className={validation.valid ? 'badge badge-ok cursor-pointer' : 'badge badge-danger cursor-pointer'}
              title={`Draft digest: ${validation.digest}`}
            >
              {validation.valid ? <CheckCircle2 size={12} /> : <AlertTriangle size={12} />}
              <span>
                {validation.valid
                  ? `Valid · ${validation.upstream_count} upstream · ${validation.route_count} route${validation.warnings ? ` · ${validation.warnings} warn` : ''}`
                  : `${validation.errors} validation error${validation.errors === 1 ? '' : 's'}`}
              </span>
            </button>
          )}
          {validation && (
            <span className="mono text-[11px] hidden 2xl:inline" style={{ color: 'var(--text-muted)' }}>
              {shortDigest(validation.digest)}
            </span>
          )}
        </div>

        {/* Right-Aligned Actions */}
        <div className="flex items-center gap-2 shrink-0">
          {tab === 'draft' && (
            <button
              type="button"
              className="btn btn-sm hidden xl:inline-flex"
              style={{
                background: splitToml ? 'var(--accent-soft)' : undefined,
                borderColor: splitToml ? 'var(--accent-border)' : undefined,
                color: splitToml ? 'var(--accent)' : undefined,
              }}
              onClick={() => setSplitToml((v) => !v)}
              title="Toggle live compiled shunt.toml split pane"
            >
              <Columns2 size={13} />
              <span>{splitToml ? 'Split TOML' : 'Show TOML'}</span>
            </button>
          )}
          <button type="button" className="btn btn-sm" onClick={() => setImportOpen(true)}>
            <Upload size={13} />
            <span>Import TOML</span>
          </button>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            disabled={!validation?.valid}
            onClick={() => setPublishOpen(true)}
          >
            <Rocket size={13} />
            <span>Publish Release</span>
          </button>
        </div>
      </div>

      {/* Collapsible shunt verify Diagnostics */}
      {showDiagnostics && validation && validation.diagnostics.length > 0 && (
        <div className="surface p-3 space-y-1.5">
          <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
            <span>shunt verify Diagnostics ({validation.diagnostics.length})</span>
            <button
              type="button"
              className="btn-ghost text-[11px] px-1.5 py-0.5 border-0 cursor-pointer rounded"
              onClick={() => setShowDiagnostics(false)}
            >
              Hide
            </button>
          </div>
          {validation.diagnostics.map((d, i) => (
            <div
              key={i}
              className="text-xs px-2.5 py-1.5 rounded flex items-start gap-2"
              style={{
                background: d.severity === 'error' ? 'var(--danger-soft)' : 'var(--warn-soft)',
                border: `1px solid ${d.severity === 'error' ? 'var(--danger-border)' : 'var(--warn-border)'}`,
              }}
            >
              <span className="badge mono uppercase">{d.severity}</span>
              <div className="min-w-0">
                <span className="mono font-semibold">{d.rule}</span>
                {d.subject && <span className="mono ml-1.5 opacity-80">({d.subject})</span>}
                <span className="ml-2">{d.message}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 1: Draft Config (+ Live Split Compiled TOML on Desktop) */}
      {tab === 'draft' && (
        <div className={splitToml ? 'grid grid-cols-1 xl:grid-cols-12 gap-3.5 items-start' : 'space-y-3.5'}>
          {/* Resource Table Card */}
          <div className={splitToml ? 'surface overflow-hidden xl:col-span-7' : 'surface overflow-hidden'}>
            {/* Integrated Filter + Search + Add Bar */}
            <div
              className="px-3 py-2 flex flex-wrap items-center justify-between gap-2"
              style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-sidebar)' }}
            >
              <div className="flex flex-wrap items-center gap-1">
                {(
                  [
                    { id: 'all', label: `All (${counts.all})` },
                    { id: 'route', label: `Routes (${counts.route})` },
                    { id: 'upstream', label: `Upstreams (${counts.upstream})` },
                    { id: 'route_group', label: `Groups (${counts.route_group})` },
                    { id: 'global_plugin', label: `Plugins (${counts.global_plugin})` },
                    { id: 'system', label: `System (${counts.system})` },
                  ] as { id: KindFilter; label: string }[]
                ).map((f) => (
                  <button
                    key={f.id}
                    type="button"
                    onClick={() => setKindFilter(f.id)}
                    className="px-2 py-1 rounded text-[11px] font-medium border-0 cursor-pointer transition-colors"
                    style={{
                      background: kindFilter === f.id ? 'var(--bg-hover)' : 'transparent',
                      color: kindFilter === f.id ? 'var(--text-primary)' : 'var(--text-muted)',
                    }}
                  >
                    {f.label}
                  </button>
                ))}
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                <div className="relative">
                  <Search
                    size={12}
                    className="absolute left-2 top-1/2 -translate-y-1/2 pointer-events-none"
                    style={{ color: 'var(--text-muted)' }}
                  />
                  <input
                    className="input-base text-xs py-1 pl-6 pr-2 w-36"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Filter…"
                  />
                </div>
                {(['route', 'upstream', 'route_group', 'global_plugin'] as TopologyResourceKind[]).map(
                  (k) => (
                    <button
                      key={k}
                      type="button"
                      className="btn btn-sm"
                      onClick={() => openNewResource(k)}
                    >
                      <Plus size={11} />
                      <span>{KIND_META[k].label}</span>
                    </button>
                  )
                )}
              </div>
            </div>

            {loading ? (
              <div className="p-8 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
                Loading draft configuration…
              </div>
            ) : filteredResources.length === 0 ? (
              <div className="p-8 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
                No matching resources.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="swiss-table text-xs">
                  <thead>
                    <tr>
                      <th>Kind</th>
                      <th>Slug</th>
                      <th>Configuration</th>
                      <th>Ver</th>
                      <th>Updated</th>
                      <th className="text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredResources.map((r) => {
                      const meta = KIND_META[r.kind];
                      return (
                        <tr key={r.id}>
                          <td className="whitespace-nowrap">
                            <span className={meta.badgeCls}>{meta.label}</span>
                          </td>
                          <td className="mono font-semibold whitespace-nowrap">{r.slug}</td>
                          <td
                            className="mono text-[11.5px] max-w-md truncate"
                            style={{ color: 'var(--text-secondary)' }}
                            title={JSON.stringify(r.spec)}
                          >
                            {summarizeResource(r)}
                          </td>
                          <td
                            className="mono whitespace-nowrap"
                            style={{ color: 'var(--text-muted)' }}
                            title={`ETag: ${r.etag}`}
                          >
                            v{r.version}
                          </td>
                          <td className="whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                            {formatRelativeTime(r.updated_at)}
                          </td>
                          <td className="text-right whitespace-nowrap">
                            <div className="inline-flex items-center gap-1">
                              <button
                                type="button"
                                className="btn btn-sm"
                                onClick={() => openEditResource(r)}
                              >
                                <Edit3 size={11} />
                                <span>Edit</span>
                              </button>
                              <button
                                type="button"
                                className="btn-ghost p-1 rounded cursor-pointer border-0"
                                style={{ color: 'var(--danger)' }}
                                title={`Delete ${r.kind}/${r.slug}`}
                                onClick={() => handleDeleteResource(r)}
                              >
                                <Trash2 size={13} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Live Compiled shunt.toml Split Pane */}
          {splitToml && (
            <div className="surface overflow-hidden xl:col-span-5 xl:sticky xl:top-16">
              <div
                className="px-3.5 py-2 flex items-center justify-between gap-2"
                style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-sidebar)' }}
              >
                <div className="flex items-center gap-2 min-w-0">
                  <FileCode2 size={13} style={{ color: 'var(--text-muted)' }} />
                  <span className="text-xs font-semibold truncate">Compiled shunt.toml</span>
                  <span className="badge mono text-[10px]">secrets redacted</span>
                </div>
                <CopyButton text={validation?.compiled_toml || ''} label="Copy" />
              </div>
              <pre
                className="mono m-0 p-3.5 text-[11.5px] leading-relaxed overflow-auto max-h-[calc(100vh-11rem)]"
                style={{ background: 'var(--bg-code)', color: 'var(--text-primary)' }}
              >
                {validation?.compiled_toml || '# No compiled config yet'}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Full-Width Compiled TOML View */}
      {tab === 'toml' && (
        <div className="surface overflow-hidden">
          <div
            className="px-4 py-2.5 flex items-center justify-between gap-3"
            style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-sidebar)' }}
          >
            <div>
              <div className="text-xs font-semibold">Canonical Compiled shunt.toml (Secrets Redacted)</div>
              <div className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
                References like <code>secret:&lt;slug&gt;</code> are resolved into node memory only when authenticated nodes pull a signed release bundle.
              </div>
            </div>
            <CopyButton text={validation?.compiled_toml || ''} label="Copy TOML" />
          </div>
          <pre
            className="mono m-0 p-4 text-xs leading-relaxed overflow-auto max-h-[72vh]"
            style={{ background: 'var(--bg-code)', color: 'var(--text-primary)' }}
          >
            {validation?.compiled_toml || ''}
          </pre>
        </div>
      )}

      {/* Tab 3: Releases & Rollback */}
      {tab === 'revisions' && (
        <div className="space-y-3">
          <div
            className="surface px-3.5 py-2.5 flex items-center gap-2 text-xs"
            style={{ background: 'var(--bg-elevated)' }}
          >
            <ShieldCheck size={15} style={{ color: 'var(--ok)' }} className="shrink-0" />
            <span>
              <strong>Safe Rollback Guarantee:</strong> Rolling back a config release never un-revokes virtual keys, budgets, MCP agent permissions, or emergency kill-switches managed under <strong>Live Policies</strong>.
            </span>
          </div>

          <div className="surface overflow-hidden">
            {revisions.length === 0 ? (
              <div className="p-10 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
                No releases published yet. Click <strong>Publish Release</strong> above to cut Release #1.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="swiss-table text-xs">
                  <thead>
                    <tr>
                      <th>Release</th>
                      <th>Active Rings</th>
                      <th>Digest</th>
                      <th>Notes</th>
                      <th>Published</th>
                      <th className="text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {revisions.map((rev) => {
                      const activeRings = Object.entries(cluster.ring_assignments)
                        .filter(([, r]) => r === rev.revision)
                        .map(([k]) => k);
                      const isDefaultActive = cluster.ring_assignments['*'] === rev.revision;
                      return (
                        <tr key={rev.id}>
                          <td className="mono font-semibold whitespace-nowrap">v{rev.revision}</td>
                          <td className="whitespace-nowrap">
                            {activeRings.length === 0 ? (
                              <span style={{ color: 'var(--text-muted)' }}>historical</span>
                            ) : (
                              <div className="flex flex-wrap gap-1">
                                {activeRings.map((ring) => (
                                  <span
                                    key={ring}
                                    className={ring === '*' ? 'badge badge-ok mono' : 'badge badge-accent mono'}
                                  >
                                    {ring}
                                  </span>
                                ))}
                              </div>
                            )}
                          </td>
                          <td className="mono whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                            {shortDigest(rev.digest)}
                          </td>
                          <td>{rev.notes || <span style={{ color: 'var(--text-muted)' }}>—</span>}</td>
                          <td className="whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                            {rev.published_by} · {formatRelativeTime(rev.created_at)}
                          </td>
                          <td className="text-right whitespace-nowrap">
                            <div className="inline-flex items-center gap-1.5">
                              <button
                                type="button"
                                className="btn btn-sm"
                                onClick={() => setInspectRev(rev)}
                              >
                                <FileCode2 size={11} />
                                <span>TOML</span>
                              </button>
                              <a
                                href={`/api/v1/clusters/${cluster.slug}/revisions/${rev.revision}/export.toml`}
                                className="btn btn-sm no-underline"
                                title="Download shunt.toml"
                              >
                                <Download size={11} />
                              </a>
                              {!isDefaultActive && activeRings.length > 0 && (
                                <button
                                  type="button"
                                  className="btn btn-sm btn-accent"
                                  onClick={() => handlePromote(rev.revision)}
                                >
                                  Promote to *
                                </button>
                              )}
                              {!isDefaultActive && (
                                <button
                                  type="button"
                                  className="btn btn-sm"
                                  onClick={() => handleRollback(rev.revision)}
                                >
                                  <RotateCcw size={11} />
                                  <span>Rollback</span>
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Right-Hand Resource Editor Drawer */}
      <Drawer
        open={editorOpen}
        onClose={() => setEditorOpen(false)}
        title={editEtag ? `Edit ${editKind}/${editSlug}` : `Add ${editKind}`}
        subtitle="Uses ETag + If-Match optimistic concurrency to prevent silent overwrites."
        widthClass="max-w-xl"
      >
        <form onSubmit={handleSaveResource} className="space-y-4">
          {editError && (
            <div
              className="p-3 rounded-md text-xs"
              style={{
                background: 'var(--danger-soft)',
                border: '1px solid var(--danger-border)',
                color: 'var(--danger)',
              }}
            >
              {editError}
            </div>
          )}
          {!editEtag && QUICK_STARTER_SNIPPETS[editKind] && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Quick template:
              </span>
              {QUICK_STARTER_SNIPPETS[editKind]!.map((tpl) => (
                <button
                  key={tpl.label}
                  type="button"
                  className="btn btn-sm"
                  onClick={() => {
                    setEditSlug(tpl.slug);
                    setEditJson(JSON.stringify(tpl.spec, null, 2));
                  }}
                >
                  {tpl.label}
                </button>
              ))}
            </div>
          )}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium mb-1">Resource Kind</label>
              <input className="input-base mono text-xs" value={editKind} disabled />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1">Slug</label>
              <input
                className="input-base mono text-xs"
                value={editSlug}
                disabled={Boolean(editEtag)}
                onChange={(e) => setEditSlug(e.target.value)}
                required
              />
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium mb-1">Spec JSON</label>
            <textarea
              className="input-base mono text-xs min-h-[340px]"
              value={editJson}
              onChange={(e) => setEditJson(e.target.value)}
              spellCheck={false}
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" className="btn" onClick={() => setEditorOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? 'Saving…' : 'Save to Draft'}
            </button>
          </div>
        </form>
      </Drawer>

      {/* Import TOML Modal */}
      <Modal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        title="Import shunt.toml into Draft"
        subtitle="Decomposes your shunt.toml into structured cluster resources without affecting running nodes until you publish."
        maxWidth="max-w-2xl"
      >
        <form onSubmit={handleImportToml} className="space-y-4">
          <textarea
            className="input-base mono text-xs min-h-[260px]"
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            placeholder="Paste shunt.toml contents here…"
            required
          />
          <div className="flex justify-end gap-2">
            <button type="button" className="btn" onClick={() => setImportOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={importing}>
              <Upload size={13} />
              <span>{importing ? 'Importing…' : 'Import into Draft'}</span>
            </button>
          </div>
        </form>
      </Modal>

      {/* Publish Release Modal */}
      <Modal
        open={publishOpen}
        onClose={() => setPublishOpen(false)}
        title={`Publish Config Release to ${cluster.slug}`}
        subtitle="Creates an immutable, Ed25519-signed release and rolls it out to matching nodes."
      >
        <form onSubmit={handlePublish} className="space-y-4">
          <div>
            <label className="block text-xs font-medium mb-1">Target Rollout Ring</label>
            <input
              className="input-base mono text-xs"
              value={pubRing}
              onChange={(e) => setPubRing(e.target.value)}
              placeholder="*"
            />
            <div className="mt-1.5 flex gap-1.5">
              <button type="button" className="btn btn-sm" onClick={() => setPubRing('*')}>
                * (All Nodes)
              </button>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => setPubRing('ring=canary')}
              >
                ring=canary (Canary Only)
              </button>
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium mb-1">Release Notes</label>
            <input
              className="input-base"
              value={pubNotes}
              onChange={(e) => setPubNotes(e.target.value)}
              placeholder="e.g. Add /v2/orders upstream pool and increase drain timeout"
            />
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <button type="button" className="btn" onClick={() => setPublishOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={publishing}>
              <Rocket size={13} />
              <span>{publishing ? 'Publishing…' : 'Publish & Roll Out'}</span>
            </button>
          </div>
        </form>
      </Modal>

      {/* Release TOML Inspector Drawer */}
      <Drawer
        open={Boolean(inspectRev)}
        onClose={() => setInspectRev(null)}
        title={`Release v${inspectRev?.revision} — Canonical shunt.toml`}
        subtitle={`Digest: ${inspectRev?.digest || ''} · Ed25519 signed`}
        widthClass="max-w-2xl"
      >
        {inspectRev && (
          <div className="space-y-3">
            <div className="flex justify-end">
              <CopyButton text={inspectRev.compiled_toml} label="Copy TOML" />
            </div>
            <pre className="code-block m-0">{inspectRev.compiled_toml}</pre>
          </div>
        )}
      </Drawer>
    </div>
  );
}
