import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Download,
  FileCode2,
  GitBranch,
  History,
  Plus,
  Rocket,
  RotateCcw,
  Save,
  Search,
  ShieldCheck,
  SlidersHorizontal,
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

const ADD_MENU_ITEMS: { kind: TopologyResourceKind; title: string; desc: string }[] = [
  {
    kind: 'route',
    title: 'Route',
    desc: 'Match HTTP API, /v1 AI, or /mcp paths to an upstream',
  },
  {
    kind: 'upstream',
    title: 'Upstream',
    desc: 'Backend service pool, AI provider, or MCP server',
  },
  {
    kind: 'route_group',
    title: 'Route Group',
    desc: 'Shared path prefix and plugin chain for multiple routes',
  },
  {
    kind: 'global_plugin',
    title: 'Global Plugin',
    desc: 'Middleware running across every route (metrics, auth, limits)',
  },
];

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
  route: { label: 'Route', badgeCls: 'badge badge-accent' },
  route_group: { label: 'Route Group', badgeCls: 'badge badge-accent' },
  upstream: { label: 'Upstream', badgeCls: 'badge badge-ok' },
  global_plugin: { label: 'Plugin', badgeCls: 'badge' },
  server: { label: 'Server', badgeCls: 'badge' },
  admin: { label: 'Admin', badgeCls: 'badge' },
  state: { label: 'State', badgeCls: 'badge' },
  telemetry: { label: 'Telemetry', badgeCls: 'badge' },
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
      const plugins =
        Array.isArray(s.plugins) && s.plugins.length > 0
          ? ` · ${s.plugins.length} plugin${s.plugins.length === 1 ? '' : 's'}`
          : '';
      return `${matcher}${target}${group}${plugins}`;
    }
    case 'route_group': {
      const prefix = s.path_prefix ? `PREFIX ${String(s.path_prefix)}` : 'shared group';
      const upstream = s.upstream ? ` → ${String(s.upstream)}` : '';
      const plugins = Array.isArray(s.plugins)
        ? ` · ${s.plugins.length} plugin${s.plugins.length === 1 ? '' : 's'}`
        : '';
      return `${prefix}${upstream}${plugins}`;
    }
    case 'upstream': {
      const eps = Array.isArray(s.endpoints) ? s.endpoints.map(String) : [];
      const first = eps[0] || 'no endpoints';
      const more = eps.length > 1 ? ` (+${eps.length - 1} more)` : '';
      const timeout =
        typeof s.connect_timeout_ms === 'number' ? ` · connect ${s.connect_timeout_ms}ms` : '';
      return `${first}${more}${timeout}`;
    }
    case 'global_plugin': {
      const name = typeof s.name === 'string' ? s.name : r.slug;
      const cfg = s.config && typeof s.config === 'object' ? Object.keys(s.config as object) : [];
      return cfg.length > 0 ? `${name} (${cfg.join(', ')})` : `${name} · default settings`;
    }
    case 'server': {
      const listen = typeof s.listen === 'string' ? s.listen : '0.0.0.0:8080';
      const drain =
        typeof s.drain_timeout_ms === 'number'
          ? ` · drain ${Math.round(s.drain_timeout_ms / 1000)}s`
          : '';
      const tls = s.tls ? ' · TLS' : '';
      return `Listen ${listen}${drain}${tls}`;
    }
    case 'admin': {
      if (s.enabled === false) return 'Disabled';
      const listen = typeof s.listen === 'string' ? s.listen : '127.0.0.1:9090';
      const ui = s.ui ? ' · Inspector UI on' : ' · API only';
      return `${listen}${ui}`;
    }
    case 'state': {
      const backend = typeof s.backend === 'string' ? s.backend : 'memory';
      return `Backend: ${backend}`;
    }
    case 'telemetry': {
      const enabled = Boolean(s.enabled);
      const backend = typeof s.backend === 'string' ? s.backend : 'otlp_http';
      return enabled ? `Enabled (${backend})` : `Disabled (${backend})`;
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
  const [tab, setTab] = useState<'draft' | 'revisions' | 'toml'>('draft');
  const [inspectorTab, setInspectorTab] = useState<'editor' | 'toml'>('editor');
  const [kindFilter, setKindFilter] = useState<KindFilter>('all');
  const [search, setSearch] = useState('');
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const [addMenuOpen, setAddMenuOpen] = useState(false);
  const addMenuRef = useRef<HTMLDivElement>(null);
  const inspectorRef = useRef<HTMLDivElement>(null);

  const [resources, setResources] = useState<TopologyResource[]>([]);
  const [validation, setValidation] = useState<ValidateDraftResult | null>(null);
  const [revisions, setRevisions] = useState<TopologyRevision[]>([]);
  const [loading, setLoading] = useState(true);

  // Docked Inspector / Editor state
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [creatingNew, setCreatingNew] = useState(false);
  const [editKind, setEditKind] = useState<TopologyResourceKind>('route');
  const [editSlug, setEditSlug] = useState('');
  const [editEtag, setEditEtag] = useState<string | undefined>(undefined);
  const [editJson, setEditJson] = useState('');
  const [initialJson, setInitialJson] = useState('');
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

  // Inspect Historical Release TOML Drawer
  const [inspectRev, setInspectRev] = useState<TopologyRevision | null>(null);

  useEffect(() => {
    if (!addMenuOpen) return;
    const onDocClick = (e: MouseEvent) => {
      if (addMenuRef.current && !addMenuRef.current.contains(e.target as Node)) {
        setAddMenuOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setAddMenuOpen(false);
    };
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [addMenuOpen]);

  const sortedResources = useMemo(() => {
    return [...resources].sort(
      (a, b) =>
        (KIND_ORDER[a.kind] ?? 99) - (KIND_ORDER[b.kind] ?? 99) ||
        a.sort_order - b.sort_order ||
        a.slug.localeCompare(b.slug)
    );
  }, [resources]);

  const selectResource = (r: TopologyResource) => {
    const formatted = JSON.stringify(r.spec, null, 2);
    setCreatingNew(false);
    setSelectedId(r.id);
    setEditKind(r.kind);
    setEditSlug(r.slug);
    setEditEtag(r.etag);
    setEditJson(formatted);
    setInitialJson(formatted);
    setEditError(null);
    setInspectorTab('editor');
  };

  const load = async (preferKindSlug?: { kind: TopologyResourceKind; slug: string }) => {
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
      const sorted = [...res].sort(
        (a, b) =>
          (KIND_ORDER[a.kind] ?? 99) - (KIND_ORDER[b.kind] ?? 99) ||
          a.sort_order - b.sort_order ||
          a.slug.localeCompare(b.slug)
      );
      const preferred = preferKindSlug
        ? sorted.find((r) => r.kind === preferKindSlug.kind && r.slug === preferKindSlug.slug)
        : sorted.find((r) => r.id === selectedId);
      const next = preferred || sorted[0];
      if (next) {
        selectResource(next);
      } else {
        setSelectedId(null);
      }
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : 'Failed to load config', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setSelectedId(null);
    setCreatingNew(false);
    load();
  }, [cluster.slug]);

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

  const selectedResource = useMemo(
    () => resources.find((r) => r.id === selectedId) || null,
    [resources, selectedId]
  );

  const isDirty = creatingNew || editJson !== initialJson;

  const openNewResource = (kind: TopologyResourceKind) => {
    setAddMenuOpen(false);
    const defaultSlug =
      kind === 'upstream' ? 'new-upstream' : kind === 'route' ? 'new-route' : 'default';
    const formatted = JSON.stringify(RESOURCE_TEMPLATES[kind], null, 2);
    setCreatingNew(true);
    setSelectedId(null);
    setEditKind(kind);
    setEditSlug(defaultSlug);
    setEditEtag(undefined);
    setEditJson(formatted);
    setInitialJson(formatted);
    setEditError(null);
    setTab('draft');
    setInspectorTab('editor');
    inspectorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
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
    const cleanSlug = slugify(editSlug);
    if (!cleanSlug) {
      setEditError('Please enter a valid slug (letters, numbers, hyphens).');
      return;
    }
    setSaving(true);
    try {
      await api.upsertResource(cluster.slug, editKind, cleanSlug, parsed, {
        etag: editEtag,
      });
      toast.push(`Saved ${KIND_META[editKind].label} "${cleanSlug}" to draft`);
      await load({ kind: editKind, slug: cleanSlug });
    } catch (err) {
      if (err instanceof ApiProblemError && err.status === 412) {
        setEditError('Conflict (412): This resource was updated by someone else. Refresh and retry.');
      } else {
        setEditError(err instanceof ApiProblemError ? err.message : String(err));
      }
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteResource = async (r: TopologyResource) => {
    if (!window.confirm(`Delete ${KIND_META[r.kind].label} "${r.slug}" from draft?`)) return;
    try {
      await api.deleteResource(cluster.slug, r.kind, r.slug, r.etag);
      toast.push(`Deleted ${KIND_META[r.kind].label} "${r.slug}"`);
      await load();
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
      toast.push(`Published Release v${rev.revision} to ring "${pubRing || '*'}"`);
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
        `Roll back cluster "${cluster.slug}" default fleet to Release v${rev}?\n\nActive Live Policies (virtual keys, budgets, MCP agent permissions, and kill-switches) will NOT be reverted.`
      )
    ) {
      return;
    }
    try {
      await api.rollbackRevision(cluster.slug, rev, '*');
      toast.push(`Rolled back ${cluster.slug} to Release v${rev} (Live Policies untouched)`);
      onClusterChanged();
      await load();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handlePromote = async (rev: number) => {
    try {
      await api.promoteRevision(cluster.slug, rev, '*');
      toast.push(`Promoted Release v${rev} to all nodes (*)`);
      onClusterChanged();
      await load();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  return (
    <div className="space-y-5">
      {/* Full-Width Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="m-0 text-[22px] font-semibold tracking-tight">Config &amp; Releases</h1>
            {validation && (
              <button
                type="button"
                onClick={() => setShowDiagnostics((v) => !v)}
                className={validation.valid ? 'badge badge-ok cursor-pointer' : 'badge badge-danger cursor-pointer'}
                title={`Draft digest: ${validation.digest}`}
              >
                {validation.valid ? <CheckCircle2 size={13} /> : <AlertTriangle size={13} />}
                <span>
                  {validation.valid
                    ? `Valid · ${validation.upstream_count} upstream, ${validation.route_count} route${validation.warnings ? ` · ${validation.warnings} warning` : ''}`
                    : `${validation.errors} error${validation.errors === 1 ? '' : 's'} in draft`}
                </span>
              </button>
            )}
          </div>
          <p className="m-0 mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
            Manage routes, upstreams, and plugins for HTTP APIs, AI models, and MCP servers—then publish signed releases to your fleet.
          </p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <button type="button" className="btn" onClick={() => setImportOpen(true)}>
            <Upload size={15} />
            <span>Import shunt.toml</span>
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!validation?.valid}
            onClick={() => setPublishOpen(true)}
          >
            <Rocket size={15} />
            <span>Publish Release</span>
          </button>
        </div>
      </div>

      {/* Collapsible shunt verify Diagnostics */}
      {showDiagnostics && validation && validation.diagnostics.length > 0 && (
        <div className="surface p-4 space-y-2">
          <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
            <span>shunt verify Diagnostics ({validation.diagnostics.length})</span>
            <button
              type="button"
              className="btn-ghost text-xs px-2 py-1 border-0 cursor-pointer rounded"
              onClick={() => setShowDiagnostics(false)}
            >
              Hide
            </button>
          </div>
          {validation.diagnostics.map((d, i) => (
            <div
              key={i}
              className="text-sm px-3 py-2 rounded-lg flex items-start gap-2.5"
              style={{
                background: d.severity === 'error' ? 'var(--danger-soft)' : 'var(--warn-soft)',
                border: `1px solid ${d.severity === 'error' ? 'var(--danger-border)' : 'var(--warn-border)'}`,
              }}
            >
              <span className="badge mono uppercase mt-0.5">{d.severity}</span>
              <div className="min-w-0">
                <span className="mono font-semibold">{d.rule}</span>
                {d.subject && <span className="mono ml-1.5 opacity-80">({d.subject})</span>}
                <div className="mt-0.5">{d.message}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Clean Single Tab Row */}
      <div className="flex items-center gap-1" style={{ borderBottom: '1px solid var(--border)' }}>
        {[
          { id: 'draft' as const, label: `Draft Config (${resources.length})`, icon: <GitBranch size={15} /> },
          { id: 'revisions' as const, label: `Releases & Rollback (${revisions.length})`, icon: <History size={15} /> },
          { id: 'toml' as const, label: 'Compiled shunt.toml', icon: <FileCode2 size={15} /> },
        ].map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className="flex items-center gap-2 px-3.5 py-2.5 text-sm font-medium bg-transparent border-0 cursor-pointer transition-colors"
            style={{
              color: tab === t.id ? 'var(--text-primary)' : 'var(--text-muted)',
              borderBottom: `2px solid ${tab === t.id ? 'var(--accent)' : 'transparent'}`,
              marginBottom: -1,
            }}
          >
            {t.icon}
            <span>{t.label}</span>
          </button>
        ))}
      </div>

      {/* Tab 1: Full-Width Master-Detail Draft Workspace */}
      {tab === 'draft' && (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
          {/* Left: Draft Resources List */}
          <div className="surface xl:col-span-7">
            <div
              className="px-4 py-3 flex flex-wrap items-center justify-between gap-3"
              style={{ borderBottom: '1px solid var(--border)' }}
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
                ).map((f) => {
                  const active = kindFilter === f.id;
                  return (
                    <button
                      key={f.id}
                      type="button"
                      onClick={() => setKindFilter(f.id)}
                      className="px-2.5 py-1.5 rounded-md text-sm font-medium border-0 cursor-pointer transition-colors"
                      style={{
                        background: active ? 'var(--bg-subtle)' : 'transparent',
                        color: active ? 'var(--text-primary)' : 'var(--text-muted)',
                      }}
                    >
                      {f.label}
                    </button>
                  );
                })}
              </div>

              <div className="flex items-center gap-2.5">
                <div
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg w-48"
                  style={{ background: 'var(--bg)', border: '1px solid var(--border)' }}
                >
                  <Search size={14} style={{ color: 'var(--text-muted)' }} className="shrink-0" />
                  <input
                    className="w-full bg-transparent border-0 outline-none text-sm"
                    style={{ color: 'var(--text-primary)' }}
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Filter resources…"
                  />
                </div>

                {/* Single Friendly Add Resource Menu */}
                <div className="relative" ref={addMenuRef}>
                  <button
                    type="button"
                    className="btn btn-accent"
                    onClick={() => setAddMenuOpen((o) => !o)}
                  >
                    <Plus size={15} />
                    <span>Add Resource</span>
                    <ChevronDown size={14} />
                  </button>
                  {addMenuOpen && (
                    <div
                      className="surface absolute right-0 mt-1.5 w-80 p-1.5 z-30 shadow-xl"
                      style={{ background: 'var(--bg-elevated)' }}
                    >
                      {ADD_MENU_ITEMS.map((item) => (
                        <button
                          key={item.kind}
                          type="button"
                          onClick={() => openNewResource(item.kind)}
                          className="w-full text-left px-3 py-2.5 rounded-lg border-0 bg-transparent cursor-pointer transition-colors hover:bg-[var(--bg-hover)] block"
                        >
                          <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                            {item.title}
                          </div>
                          <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                            {item.desc}
                          </div>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {loading ? (
              <div className="p-10 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                Loading draft configuration…
              </div>
            ) : filteredResources.length === 0 ? (
              <div className="p-10 text-center space-y-2">
                <div className="text-sm font-medium">No matching resources</div>
                <div className="text-sm" style={{ color: 'var(--text-muted)' }}>
                  Try clearing your filter or click <strong>Add Resource</strong> to add a route, upstream, or plugin.
                </div>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="swiss-table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Name</th>
                      <th>Summary</th>
                      <th>Ver</th>
                      <th>Updated</th>
                      <th className="text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredResources.map((r) => {
                      const meta = KIND_META[r.kind];
                      const isSelected = !creatingNew && r.id === selectedId;
                      return (
                        <tr
                          key={r.id}
                          className="cursor-pointer"
                          onClick={() => selectResource(r)}
                          style={{
                            background: isSelected ? 'var(--accent-soft)' : undefined,
                          }}
                        >
                          <td className="whitespace-nowrap">
                            <span className={meta.badgeCls}>{meta.label}</span>
                          </td>
                          <td className="mono font-semibold whitespace-nowrap">{r.slug}</td>
                          <td
                            className="mono text-[13px] max-w-md truncate"
                            style={{ color: 'var(--text-secondary)' }}
                            title={JSON.stringify(r.spec)}
                          >
                            {summarizeResource(r)}
                          </td>
                          <td
                            className="mono text-xs whitespace-nowrap"
                            style={{ color: 'var(--text-muted)' }}
                            title={`ETag: ${r.etag}`}
                          >
                            v{r.version}
                          </td>
                          <td className="text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                            {formatRelativeTime(r.updated_at)}
                          </td>
                          <td
                            className="text-right whitespace-nowrap"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <button
                              type="button"
                              className="btn-ghost p-1.5 rounded-md cursor-pointer border-0"
                              style={{ color: 'var(--danger)' }}
                              title={`Delete ${meta.label} "${r.slug}"`}
                              onClick={() => handleDeleteResource(r)}
                            >
                              <Trash2 size={15} />
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Right: Docked Resource Inspector / Live Editor Panel */}
          <div ref={inspectorRef} className="surface overflow-hidden xl:col-span-5 xl:sticky xl:top-20">
            {/* Inspector Header + Switcher */}
            <div
              className="px-4 py-3 flex items-center justify-between gap-3"
              style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-canvas)' }}
            >
              <div className="flex items-center gap-2 min-w-0">
                {inspectorTab === 'editor' ? (
                  <>
                    <SlidersHorizontal size={15} style={{ color: 'var(--accent)' }} className="shrink-0" />
                    <span className="text-sm font-semibold truncate">
                      {creatingNew
                        ? `New ${KIND_META[editKind].label}`
                        : selectedResource
                          ? `${KIND_META[selectedResource.kind].label} · ${selectedResource.slug}`
                          : 'Resource Editor'}
                    </span>
                    {isDirty && <span className="badge badge-warn">Unsaved</span>}
                  </>
                ) : (
                  <>
                    <FileCode2 size={15} style={{ color: 'var(--accent)' }} className="shrink-0" />
                    <span className="text-sm font-semibold truncate">Compiled shunt.toml</span>
                  </>
                )}
              </div>

              <div
                className="inline-flex rounded-lg p-0.5 text-xs shrink-0"
                style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border)' }}
              >
                <button
                  type="button"
                  onClick={() => setInspectorTab('editor')}
                  className="px-2.5 py-1 rounded-md border-0 cursor-pointer font-medium transition-colors"
                  style={{
                    background: inspectorTab === 'editor' ? 'var(--bg-elevated)' : 'transparent',
                    color: inspectorTab === 'editor' ? 'var(--text-primary)' : 'var(--text-muted)',
                  }}
                >
                  Editor
                </button>
                <button
                  type="button"
                  onClick={() => setInspectorTab('toml')}
                  className="px-2.5 py-1 rounded-md border-0 cursor-pointer font-medium transition-colors"
                  style={{
                    background: inspectorTab === 'toml' ? 'var(--bg-elevated)' : 'transparent',
                    color: inspectorTab === 'toml' ? 'var(--text-primary)' : 'var(--text-muted)',
                  }}
                >
                  TOML
                </button>
              </div>
            </div>

            {inspectorTab === 'editor' ? (
              !creatingNew && !selectedResource ? (
                <div className="p-10 text-center space-y-2 text-sm" style={{ color: 'var(--text-muted)' }}>
                  <div>Select any resource on the left to inspect or edit it, or click <strong>Add Resource</strong>.</div>
                </div>
              ) : (
                <form onSubmit={handleSaveResource} className="p-5 space-y-4">
                  {editError && (
                    <div
                      className="p-3.5 rounded-lg text-sm"
                      style={{
                        background: 'var(--danger-soft)',
                        border: '1px solid var(--danger-border)',
                        color: 'var(--danger)',
                      }}
                    >
                      {editError}
                    </div>
                  )}

                  {!creatingNew && selectedResource && (
                    <div
                      className="px-3.5 py-2.5 rounded-lg text-sm flex items-center justify-between gap-2"
                      style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-light)' }}
                    >
                      <span className="mono text-[13px] truncate" style={{ color: 'var(--text-secondary)' }}>
                        {summarizeResource(selectedResource)}
                      </span>
                      <span className="badge mono shrink-0">v{selectedResource.version}</span>
                    </div>
                  )}

                  {creatingNew && QUICK_STARTER_SNIPPETS[editKind] && (
                    <div className="space-y-1.5">
                      <div className="text-xs font-medium" style={{ color: 'var(--text-muted)' }}>
                        Start from an example:
                      </div>
                      <div className="flex flex-wrap gap-2">
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
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-3.5">
                    <div>
                      <label className="block text-sm font-medium mb-1.5">Resource Type</label>
                      <input className="input-base" value={KIND_META[editKind].label} disabled />
                    </div>
                    <div>
                      <label className="block text-sm font-medium mb-1.5">Name / Slug</label>
                      <input
                        className="input-base mono"
                        value={editSlug}
                        disabled={!creatingNew}
                        onChange={(e) => setEditSlug(e.target.value)}
                        required
                      />
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <label className="text-sm font-medium">Configuration (JSON)</label>
                      {!creatingNew && isDirty && (
                        <button
                          type="button"
                          className="btn-ghost text-xs px-2 py-0.5 rounded border-0 cursor-pointer"
                          onClick={() => {
                            setEditJson(initialJson);
                            setEditError(null);
                          }}
                        >
                          Reset changes
                        </button>
                      )}
                    </div>
                    <textarea
                      className="input-base mono text-[13px] min-h-[290px]"
                      value={editJson}
                      onChange={(e) => setEditJson(e.target.value)}
                      spellCheck={false}
                    />
                  </div>

                  <div className="flex items-center justify-between gap-3 pt-1">
                    {creatingNew ? (
                      <button
                        type="button"
                        className="btn"
                        onClick={() => {
                          setCreatingNew(false);
                          if (sortedResources[0]) selectResource(sortedResources[0]);
                        }}
                      >
                        Cancel
                      </button>
                    ) : (
                      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                        Saved to draft until you publish
                      </span>
                    )}
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={saving || (!creatingNew && !isDirty)}
                    >
                      <Save size={15} />
                      <span>{saving ? 'Saving…' : creatingNew ? 'Add to Draft' : 'Save to Draft'}</span>
                    </button>
                  </div>
                </form>
              )
            ) : (
              <div>
                <div
                  className="px-4 py-2.5 flex items-center justify-between gap-2 text-xs"
                  style={{ borderBottom: '1px solid var(--border-light)', color: 'var(--text-muted)' }}
                >
                  <span>Secrets redacted · digest {shortDigest(validation?.digest || '')}</span>
                  <CopyButton text={validation?.compiled_toml || ''} label="Copy TOML" />
                </div>
                <pre
                  className="mono m-0 p-4 text-[13px] leading-relaxed overflow-auto max-h-[calc(100vh-16rem)]"
                  style={{ background: 'var(--bg-code)', color: 'var(--text-primary)' }}
                >
                  {validation?.compiled_toml || '# No compiled config yet'}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Releases & Rollback */}
      {tab === 'revisions' && (
        <div className="space-y-4">
          <div
            className="surface px-4 py-3 flex items-center gap-3 text-sm"
            style={{ background: 'var(--bg-elevated)' }}
          >
            <ShieldCheck size={18} style={{ color: 'var(--ok)' }} className="shrink-0" />
            <span>
              <strong>Safe Rollback Guarantee:</strong> Rolling back a config release never un-revokes virtual keys, budgets, MCP agent permissions, or emergency kill-switches managed under <strong>Live Policies</strong>.
            </span>
          </div>

          <div className="surface overflow-hidden">
            {revisions.length === 0 ? (
              <div className="p-12 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                No releases published yet. Click <strong>Publish Release</strong> above to create Release v1.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="swiss-table">
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
                              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>historical</span>
                            ) : (
                              <div className="flex flex-wrap gap-1.5">
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
                          <td className="mono text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                            {shortDigest(rev.digest)}
                          </td>
                          <td>{rev.notes || <span style={{ color: 'var(--text-muted)' }}>—</span>}</td>
                          <td className="text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                            {rev.published_by} · {formatRelativeTime(rev.created_at)}
                          </td>
                          <td className="text-right whitespace-nowrap">
                            <div className="inline-flex items-center gap-1.5">
                              <button
                                type="button"
                                className="btn btn-sm"
                                onClick={() => setInspectRev(rev)}
                              >
                                <FileCode2 size={13} />
                                <span>View TOML</span>
                              </button>
                              <a
                                href={`/api/v1/clusters/${cluster.slug}/revisions/${rev.revision}/export.toml`}
                                className="btn btn-sm no-underline"
                                title="Download shunt.toml"
                              >
                                <Download size={13} />
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
                                  <RotateCcw size={13} />
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

      {/* Tab 3: Full Compiled TOML View */}
      {tab === 'toml' && (
        <div className="surface overflow-hidden">
          <div
            className="px-5 py-3.5 flex flex-wrap items-center justify-between gap-3"
            style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-canvas)' }}
          >
            <div>
              <div className="text-sm font-semibold">Canonical Compiled shunt.toml (Secrets Redacted)</div>
              <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                References like <code>secret:&lt;slug&gt;</code> are resolved into node memory only when authenticated nodes pull a signed release bundle.
              </div>
            </div>
            <CopyButton text={validation?.compiled_toml || ''} label="Copy TOML" />
          </div>
          <pre
            className="mono m-0 p-5 text-[13px] leading-relaxed overflow-auto max-h-[70vh]"
            style={{ background: 'var(--bg-code)', color: 'var(--text-primary)' }}
          >
            {validation?.compiled_toml || ''}
          </pre>
        </div>
      )}

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
            className="input-base mono text-[13px] min-h-[280px]"
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            placeholder="Paste shunt.toml contents here…"
            required
          />
          <div className="flex justify-end gap-2.5">
            <button type="button" className="btn" onClick={() => setImportOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={importing}>
              <Upload size={15} />
              <span>{importing ? 'Importing…' : 'Import into Draft'}</span>
            </button>
          </div>
        </form>
      </Modal>

      {/* Publish Release Modal */}
      <Modal
        open={publishOpen}
        onClose={() => setPublishOpen(false)}
        title={`Publish Release to ${cluster.slug}`}
        subtitle="Creates an immutable, Ed25519-signed release and rolls it out to matching nodes."
      >
        <form onSubmit={handlePublish} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1.5">Target Rollout Ring</label>
            <input
              className="input-base mono"
              value={pubRing}
              onChange={(e) => setPubRing(e.target.value)}
              placeholder="*"
            />
            <div className="mt-2 flex gap-2">
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
            <label className="block text-sm font-medium mb-1.5">Release Notes</label>
            <input
              className="input-base"
              value={pubNotes}
              onChange={(e) => setPubNotes(e.target.value)}
              placeholder="e.g. Add /v2/orders upstream pool and increase drain timeout"
            />
          </div>
          <div className="flex justify-end gap-2.5 pt-2">
            <button type="button" className="btn" onClick={() => setPublishOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={publishing}>
              <Rocket size={15} />
              <span>{publishing ? 'Publishing…' : 'Publish & Roll Out'}</span>
            </button>
          </div>
        </form>
      </Modal>

      {/* Historical Release TOML Drawer */}
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
