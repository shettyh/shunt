import React, { useMemo, useState } from 'react';
import {
  FileCode2,
  GitBranch,
  Globe,
  Plus,
  Server,
  Sliders,
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
  ValidateDraftResult,
} from '../lib/api';
import { findAiRoute, findMcpRoute } from '../lib/gateway';
import { ClusterHeaderContext, PageHeader } from '../components/PageHeader';
import {
  CopyButton,
  Drawer,
  EmptyState,
  Modal,
  SearchField,
  SegmentedTabs,
  StatusIndicator,
  TagPill,
  useToast,
} from '../components/ui';

type RoutesTab = 'routes' | 'upstreams' | 'toml';
type MatchKind = 'path_prefix' | 'path_exact' | 'path_template' | 'path_regex';

function asObj(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function describeRouteMatch(spec: Record<string, unknown>): { kind: string; pattern: string } {
  if (spec.path_exact) return { kind: 'exact', pattern: String(spec.path_exact) };
  if (spec.path_template) return { kind: 'template', pattern: String(spec.path_template) };
  if (spec.path_regex) return { kind: 'regex', pattern: String(spec.path_regex) };
  if (spec.path_prefix) return { kind: 'prefix', pattern: String(spec.path_prefix) };
  return { kind: 'any', pattern: '/' };
}

export function RoutesPage({
  cluster,
  headerCtx,
  resources,
  validation,
  onChanged,
}: {
  cluster: Cluster;
  headerCtx: ClusterHeaderContext;
  resources: TopologyResource[];
  validation: ValidateDraftResult | null;
  onChanged: () => Promise<void>;
}) {
  const toast = useToast();
  const [tab, setTab] = useState<RoutesTab>('routes');
  const [search, setSearch] = useState('');
  const [busy, setBusy] = useState(false);

  const aiRoute = useMemo(() => findAiRoute(resources), [resources]);
  const mcpRoute = useMemo(() => findMcpRoute(resources), [resources]);

  const routes = useMemo(() => resources.filter((r) => r.kind === 'route'), [resources]);
  const upstreams = useMemo(() => resources.filter((r) => r.kind === 'upstream'), [resources]);
  const systemResources = useMemo(
    () =>
      resources.filter((r) =>
        ['server', 'admin', 'state', 'telemetry', 'global_plugin', 'route_group'].includes(r.kind)
      ),
    [resources]
  );

  // Route Drawer
  const [routeOpen, setRouteOpen] = useState(false);
  const [editingRoute, setEditingRoute] = useState<TopologyResource | null>(null);
  const [routeMode, setRouteMode] = useState<'form' | 'json'>('form');
  const [rSlug, setRSlug] = useState('');
  const [rMatchKind, setRMatchKind] = useState<MatchKind>('path_prefix');
  const [rPath, setRPath] = useState('/api');
  const [rUpstream, setRUpstream] = useState('');
  const [rMethods, setRMethods] = useState('GET, POST');
  const [rTimeoutMs, setRTimeoutMs] = useState('30000');
  const [rRawJson, setRRawJson] = useState('');

  // Upstream Drawer
  const [upOpen, setUpOpen] = useState(false);
  const [editingUp, setEditingUp] = useState<TopologyResource | null>(null);
  const [upMode, setUpMode] = useState<'form' | 'json'>('form');
  const [uSlug, setUSlug] = useState('');
  const [uEndpoints, setUEndpoints] = useState('http://127.0.0.1:3000');
  const [uTimeoutMs, setUTimeoutMs] = useState('5000');
  const [uRawJson, setURawJson] = useState('');

  // System Resource JSON Drawer
  const [sysOpen, setSysOpen] = useState(false);
  const [editingSys, setEditingSys] = useState<TopologyResource | null>(null);
  const [sysKind, setSysKind] = useState<TopologyResourceKind>('global_plugin');
  const [sysSlug, setSysSlug] = useState('');
  const [sysJson, setSysJson] = useState('');

  // Import TOML Modal
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState('');

  const openNewRoute = () => {
    setEditingRoute(null);
    setRouteMode('form');
    setRSlug('');
    setRMatchKind('path_prefix');
    setRPath('/api');
    setRUpstream(upstreams[0]?.slug || '');
    setRMethods('GET, POST');
    setRTimeoutMs('30000');
    setRRawJson(
      JSON.stringify(
        { id: 'api-route', path_prefix: '/api', upstream: upstreams[0]?.slug || 'backend', plugins: [] },
        null,
        2
      )
    );
    setRouteOpen(true);
  };

  const openEditRoute = (r: TopologyResource) => {
    const s = asObj(r.spec);
    setEditingRoute(r);
    setRouteMode('form');
    setRSlug(r.slug);
    if (s.path_exact) {
      setRMatchKind('path_exact');
      setRPath(String(s.path_exact));
    } else if (s.path_template) {
      setRMatchKind('path_template');
      setRPath(String(s.path_template));
    } else if (s.path_regex) {
      setRMatchKind('path_regex');
      setRPath(String(s.path_regex));
    } else {
      setRMatchKind('path_prefix');
      setRPath(String(s.path_prefix || '/'));
    }
    setRUpstream(String(s.upstream || ''));
    setRMethods(Array.isArray(s.methods) ? s.methods.join(', ') : '');
    setRTimeoutMs(typeof s.response_headers_timeout_ms === 'number' ? String(s.response_headers_timeout_ms) : '30000');
    setRRawJson(JSON.stringify(r.spec, null, 2));
    setRouteOpen(true);
  };

  const handleSaveRoute = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanSlug = editingRoute ? editingRoute.slug : slugify(rSlug);
    if (!cleanSlug) return;
    setBusy(true);
    try {
      let spec: Record<string, unknown>;
      if (routeMode === 'json') {
        spec = JSON.parse(rRawJson) as Record<string, unknown>;
      } else {
        const prev: Record<string, unknown> = editingRoute
          ? { ...asObj(editingRoute.spec) }
          : { plugins: [] };
        delete prev.path_prefix;
        delete prev.path_exact;
        delete prev.path_template;
        delete prev.path_regex;
        spec = {
          ...prev,
          id: cleanSlug,
          [rMatchKind]: rPath.trim(),
          upstream: rUpstream.trim(),
        };
        const methodsList = rMethods
          .split(',')
          .map((m) => m.trim().toUpperCase())
          .filter(Boolean);
        if (methodsList.length > 0) spec.methods = methodsList;
        else delete spec.methods;
        if (Number(rTimeoutMs) > 0) spec.response_headers_timeout_ms = Number(rTimeoutMs);
      }

      await api.upsertResource(cluster.slug, 'route', cleanSlug, spec, {
        etag: editingRoute?.etag,
      });
      toast.push(`Saved route "${cleanSlug}" to draft`);
      setRouteOpen(false);
      await onChanged();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  const openNewUpstream = () => {
    setEditingUp(null);
    setUpMode('form');
    setUSlug('');
    setUEndpoints('http://127.0.0.1:3000');
    setUTimeoutMs('5000');
    setURawJson(JSON.stringify({ name: 'api-backend', endpoints: ['http://127.0.0.1:3000'], connect_timeout_ms: 5000 }, null, 2));
    setUpOpen(true);
  };

  const openEditUpstream = (u: TopologyResource) => {
    const s = asObj(u.spec);
    setEditingUp(u);
    setUpMode('form');
    setUSlug(u.slug);
    setUEndpoints(Array.isArray(s.endpoints) ? s.endpoints.map(String).join('\n') : '');
    setUTimeoutMs(typeof s.connect_timeout_ms === 'number' ? String(s.connect_timeout_ms) : '5000');
    setURawJson(JSON.stringify(u.spec, null, 2));
    setUpOpen(true);
  };

  const handleSaveUpstream = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanSlug = editingUp ? editingUp.slug : slugify(uSlug);
    if (!cleanSlug) return;
    setBusy(true);
    try {
      let spec: Record<string, unknown>;
      if (upMode === 'json') {
        spec = JSON.parse(uRawJson) as Record<string, unknown>;
      } else {
        const eps = uEndpoints
          .split('\n')
          .map((l) => l.trim())
          .filter(Boolean);
        spec = {
          ...(editingUp ? asObj(editingUp.spec) : {}),
          name: cleanSlug,
          endpoints: eps,
          connect_timeout_ms: Math.max(100, Number(uTimeoutMs) || 5000),
        };
      }
      await api.upsertResource(cluster.slug, 'upstream', cleanSlug, spec, {
        etag: editingUp?.etag,
      });
      toast.push(`Saved upstream "${cleanSlug}" to draft`);
      setUpOpen(false);
      await onChanged();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  const handleSaveSys = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanSlug = editingSys ? editingSys.slug : slugify(sysSlug);
    if (!cleanSlug) return;
    setBusy(true);
    try {
      const parsed = JSON.parse(sysJson);
      await api.upsertResource(cluster.slug, sysKind, cleanSlug, parsed, {
        etag: editingSys?.etag,
      });
      toast.push(`Saved ${sysKind} "${cleanSlug}"`);
      setSysOpen(false);
      await onChanged();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async (r: TopologyResource) => {
    if (!window.confirm(`Delete ${r.kind} "${r.slug}" from draft?`)) return;
    try {
      await api.deleteResource(cluster.slug, r.kind, r.slug, r.etag);
      toast.push(`Deleted "${r.slug}"`);
      await onChanged();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handleImportToml = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.importToml(cluster.slug, importText);
      toast.push('Imported shunt.toml into cluster draft');
      setImportOpen(false);
      setImportText('');
      await onChanged();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  const q = search.trim().toLowerCase();
  const filteredRoutes = routes.filter(
    (r) => !q || r.slug.includes(q) || JSON.stringify(r.spec).toLowerCase().includes(q)
  );
  const filteredUpstreams = upstreams.filter(
    (u) => !q || u.slug.includes(q) || JSON.stringify(u.spec).toLowerCase().includes(q)
  );

  const primaryAction =
    tab === 'routes' ? (
      <button type="button" className="btn btn-primary h-8" onClick={openNewRoute}>
        <Plus size={14} />
        <span>New route</span>
      </button>
    ) : tab === 'upstreams' ? (
      <button type="button" className="btn btn-primary h-8" onClick={openNewUpstream}>
        <Plus size={14} />
        <span>New upstream</span>
      </button>
    ) : (
      <button type="button" className="btn btn-primary h-8" onClick={() => setImportOpen(true)}>
        <Upload size={14} />
        <span>Import shunt.toml</span>
      </button>
    );

  return (
    <div>
      <PageHeader
        title="HTTP Routes"
        badge={
          validation && (
            <StatusIndicator
              tone={validation.valid ? 'ok' : 'danger'}
              label={validation.valid ? 'Verified' : `${validation.errors} errors`}
            />
          )
        }
        ctx={headerCtx}
        primaryAction={primaryAction}
        controlsLeft={
          <SegmentedTabs
            value={tab}
            onChange={setTab}
            items={[
              { id: 'routes', label: 'Routes', count: routes.length },
              { id: 'upstreams', label: 'Upstreams', count: upstreams.length },
              { id: 'toml', label: 'Settings & TOML' },
            ]}
          />
        }
        controlsRight={
          tab !== 'toml' ? (
            <SearchField
              value={search}
              onChange={setSearch}
              placeholder={tab === 'routes' ? 'Search routes' : 'Search upstreams'}
            />
          ) : undefined
        }
      />

      {/* TAB 1: ROUTES */}
      {tab === 'routes' && (
        <div>
          {filteredRoutes.length === 0 ? (
            <EmptyState
              icon={<GitBranch size={17} />}
              title="No HTTP routes configured"
              description="Define Prefix, Exact, Path Template (/orders/{id}), or Regex routes forwarding traffic to any upstream pool, or import an existing shunt.toml."
              action={
                <>
                  <button type="button" className="btn" onClick={() => setImportOpen(true)}>
                    <Upload size={14} />
                    <span>Import shunt.toml</span>
                  </button>
                  <button type="button" className="btn btn-primary" onClick={openNewRoute}>
                    <Plus size={14} />
                    <span>New Route</span>
                  </button>
                </>
              }
            />
          ) : (
            <div>
              {filteredRoutes.map((r) => {
                const s = asObj(r.spec);
                const m = describeRouteMatch(s);
                const plugins = Array.isArray(s.plugins) ? s.plugins : [];
                const isAi = r.id === aiRoute?.id;
                const isMcp = r.id === mcpRoute?.id;
                return (
                  <div
                    key={r.id}
                    className="row-item row-item-clickable"
                    onClick={() => openEditRoute(r)}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="icon-tile">
                        <GitBranch size={14} style={{ color: isAi ? 'var(--brand)' : 'var(--ink-secondary)' }} />
                      </div>
                      <span className="mono text-[13px] font-semibold shrink-0">{r.slug}</span>
                      <TagPill mono dot={isAi ? 'brand' : isMcp ? 'info' : 'ok'}>
                        {m.kind} {m.pattern}
                      </TagPill>
                      {typeof s.upstream === 'string' && (
                        <span className="mono text-[12.5px] truncate" style={{ color: 'var(--ink-muted)' }}>
                          → {s.upstream}
                        </span>
                      )}
                      {isAi && <TagPill brand>AI Gateway</TagPill>}
                      {isMcp && <TagPill dot="info">MCP Gateway</TagPill>}
                    </div>
                    <div
                      className="flex items-center gap-4 shrink-0"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <span className="hidden md:inline text-[12px] tabular" style={{ color: 'var(--ink-muted)' }}>
                        {plugins.length} plugin{plugins.length === 1 ? '' : 's'}
                      </span>
                      <span className="hidden sm:inline text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                        {formatRelativeTime(r.updated_at)}
                      </span>
                      <button
                        type="button"
                        className="btn-ghost p-1.5"
                        style={{ color: 'var(--ink-muted)' }}
                        onClick={() => handleDelete(r)}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: UPSTREAMS */}
      {tab === 'upstreams' && (
        <div>
          {filteredUpstreams.length === 0 ? (
            <EmptyState
              icon={<Globe size={17} />}
              title="No upstream pools yet"
              description="Upstreams represent backend HTTP services, AI providers, or MCP server origins with connection pooling and timeouts."
              action={
                <button type="button" className="btn btn-primary" onClick={openNewUpstream}>
                  <Plus size={14} />
                  <span>New Upstream</span>
                </button>
              }
            />
          ) : (
            <div>
              {filteredUpstreams.map((u) => {
                const s = asObj(u.spec);
                const eps = Array.isArray(s.endpoints) ? s.endpoints.map(String) : [];
                return (
                  <div
                    key={u.id}
                    className="row-item row-item-clickable"
                    onClick={() => openEditUpstream(u)}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="icon-tile">
                        <Server size={14} />
                      </div>
                      <span className="mono text-[13.5px] font-semibold shrink-0">{u.slug}</span>
                      <span className="mono text-[12.5px] truncate" style={{ color: 'var(--ink-secondary)' }}>
                        {eps[0] || 'no endpoints'}
                      </span>
                      {eps.length > 1 && <TagPill>+{eps.length - 1} more</TagPill>}
                    </div>
                    <div
                      className="flex items-center gap-4 shrink-0"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {typeof s.connect_timeout_ms === 'number' && (
                        <span className="hidden sm:inline mono text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                          {s.connect_timeout_ms}ms
                        </span>
                      )}
                      <button
                        type="button"
                        className="btn-ghost p-1.5"
                        style={{ color: 'var(--ink-muted)' }}
                        onClick={() => handleDelete(u)}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: SETTINGS & COMPILED TOML */}
      {tab === 'toml' && (
        <div>
          <section style={{ borderBottom: '1px solid var(--border-row)' }}>
            <div className="px-6 pt-5 pb-2 flex items-center justify-between">
              <span className="text-[12px] font-semibold uppercase tracking-wider" style={{ color: 'var(--ink-muted)' }}>
                Server, Global Plugins &amp; Runtime
              </span>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => {
                  setEditingSys(null);
                  setSysKind('global_plugin');
                  setSysSlug('cors');
                  setSysJson(JSON.stringify({ name: 'cors', config: {} }, null, 2));
                  setSysOpen(true);
                }}
              >
                <Plus size={12} />
                <span>Add global plugin</span>
              </button>
            </div>
            {systemResources.map((r) => (
              <div
                key={r.id}
                className="row-item row-item-clickable"
                onClick={() => {
                  setEditingSys(r);
                  setSysKind(r.kind);
                  setSysSlug(r.slug);
                  setSysJson(JSON.stringify(r.spec, null, 2));
                  setSysOpen(true);
                }}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="icon-tile">
                    <Sliders size={14} />
                  </div>
                  <TagPill mono>{r.kind}</TagPill>
                  <span className="mono text-[13px] font-medium">{r.slug}</span>
                  <span className="mono text-[12px] truncate" style={{ color: 'var(--ink-muted)' }}>
                    {JSON.stringify(r.spec)}
                  </span>
                </div>
                <span className="mono text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                  v{r.version}
                </span>
              </div>
            ))}
          </section>

          <section className="p-6 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <FileCode2 size={15} style={{ color: 'var(--brand)' }} />
                <span className="text-[14px] font-semibold">Canonical Compiled shunt.toml</span>
                <TagPill mono>digest {shortDigest(validation?.digest || '')}</TagPill>
              </div>
              <CopyButton text={validation?.compiled_toml || ''} label="Copy TOML" />
            </div>
            <pre className="code-block m-0 max-h-[60vh]">
              {validation?.compiled_toml || '# Empty cluster draft'}
            </pre>
          </section>
        </div>
      )}

      {/* ROUTE EDITOR DRAWER */}
      <Drawer
        open={routeOpen}
        onClose={() => setRouteOpen(false)}
        title={editingRoute ? `Edit Route · ${editingRoute.slug}` : 'New HTTP Route'}
        subtitle="Structured form or raw JSON for full plugin chains."
        widthClass="max-w-xl"
      >
        <form onSubmit={handleSaveRoute} className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-[12.5px] font-medium" style={{ color: 'var(--ink-muted)' }}>
              Editor mode
            </span>
            <SegmentedTabs
              value={routeMode}
              onChange={setRouteMode}
              items={[
                { id: 'form', label: 'Visual Form' },
                { id: 'json', label: 'Raw JSON' },
              ]}
            />
          </div>

          {routeMode === 'form' ? (
            <>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[12.5px] font-medium mb-1">Route ID</label>
                  <input
                    className="input-base mono"
                    value={rSlug}
                    disabled={Boolean(editingRoute)}
                    onChange={(e) => setRSlug(slugify(e.target.value))}
                    placeholder="orders-api"
                    required
                  />
                </div>
                <div>
                  <label className="block text-[12.5px] font-medium mb-1">Target Upstream</label>
                  <select
                    className="input-base mono text-[13px]"
                    value={rUpstream}
                    onChange={(e) => setRUpstream(e.target.value)}
                    required
                  >
                    <option value="">Select upstream…</option>
                    {upstreams.map((u) => (
                      <option key={u.id} value={u.slug}>
                        {u.slug}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-[12.5px] font-medium mb-1">Match Type</label>
                  <select
                    className="input-base text-[13px]"
                    value={rMatchKind}
                    onChange={(e) => setRMatchKind(e.target.value as MatchKind)}
                  >
                    <option value="path_prefix">Prefix</option>
                    <option value="path_exact">Exact</option>
                    <option value="path_template">Template</option>
                    <option value="path_regex">Regex</option>
                  </select>
                </div>
                <div className="col-span-2">
                  <label className="block text-[12.5px] font-medium mb-1">Path Pattern</label>
                  <input
                    className="input-base mono"
                    value={rPath}
                    onChange={(e) => setRPath(e.target.value)}
                    placeholder={rMatchKind === 'path_template' ? '/orders/{id}' : '/api'}
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[12.5px] font-medium mb-1">
                    HTTP Methods (blank = all)
                  </label>
                  <input
                    className="input-base mono text-[13px]"
                    value={rMethods}
                    onChange={(e) => setRMethods(e.target.value)}
                    placeholder="GET, POST"
                  />
                </div>
                <div>
                  <label className="block text-[12.5px] font-medium mb-1">
                    Response Timeout (ms)
                  </label>
                  <input
                    type="number"
                    className="input-base mono"
                    value={rTimeoutMs}
                    onChange={(e) => setRTimeoutMs(e.target.value)}
                  />
                </div>
              </div>
            </>
          ) : (
            <textarea
              className="input-base mono text-[12.5px] min-h-[320px]"
              value={rRawJson}
              onChange={(e) => setRRawJson(e.target.value)}
              spellCheck={false}
            />
          )}

          <div className="flex justify-end gap-2.5 pt-3" style={{ borderTop: '1px solid var(--border-row)' }}>
            <button type="button" className="btn" onClick={() => setRouteOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Saving…' : 'Save Route'}
            </button>
          </div>
        </form>
      </Drawer>

      {/* UPSTREAM EDITOR DRAWER */}
      <Drawer
        open={upOpen}
        onClose={() => setUpOpen(false)}
        title={editingUp ? `Edit Upstream · ${editingUp.slug}` : 'New Upstream Pool'}
        widthClass="max-w-lg"
      >
        <form onSubmit={handleSaveUpstream} className="space-y-4">
          <div className="flex justify-end">
            <SegmentedTabs
              value={upMode}
              onChange={setUpMode}
              items={[
                { id: 'form', label: 'Visual Form' },
                { id: 'json', label: 'Raw JSON' },
              ]}
            />
          </div>
          {upMode === 'form' ? (
            <>
              <div>
                <label className="block text-[12.5px] font-medium mb-1">Upstream Name</label>
                <input
                  className="input-base mono"
                  value={uSlug}
                  disabled={Boolean(editingUp)}
                  onChange={(e) => setUSlug(slugify(e.target.value))}
                  placeholder="orders-service"
                  required
                />
              </div>
              <div>
                <label className="block text-[12.5px] font-medium mb-1">
                  Endpoints (one URL per line)
                </label>
                <textarea
                  className="input-base mono text-[13px] min-h-[100px]"
                  value={uEndpoints}
                  onChange={(e) => setUEndpoints(e.target.value)}
                  required
                />
              </div>
              <div className="w-44">
                <label className="block text-[12.5px] font-medium mb-1">Connect Timeout (ms)</label>
                <input
                  type="number"
                  className="input-base mono"
                  value={uTimeoutMs}
                  onChange={(e) => setUTimeoutMs(e.target.value)}
                />
              </div>
            </>
          ) : (
            <textarea
              className="input-base mono text-[12.5px] min-h-[280px]"
              value={uRawJson}
              onChange={(e) => setURawJson(e.target.value)}
              spellCheck={false}
            />
          )}
          <div className="flex justify-end gap-2.5 pt-3" style={{ borderTop: '1px solid var(--border-row)' }}>
            <button type="button" className="btn" onClick={() => setUpOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Saving…' : 'Save Upstream'}
            </button>
          </div>
        </form>
      </Drawer>

      {/* SYSTEM / GLOBAL PLUGIN JSON DRAWER */}
      <Drawer
        open={sysOpen}
        onClose={() => setSysOpen(false)}
        title={editingSys ? `Edit ${editingSys.kind} · ${editingSys.slug}` : 'Add Global Plugin'}
        widthClass="max-w-lg"
      >
        <form onSubmit={handleSaveSys} className="space-y-4">
          {!editingSys && (
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Plugin Slug</label>
              <input
                className="input-base mono"
                value={sysSlug}
                onChange={(e) => setSysSlug(slugify(e.target.value))}
                required
              />
            </div>
          )}
          <div>
            <label className="block text-[12.5px] font-medium mb-1">Specification (JSON)</label>
            <textarea
              className="input-base mono text-[12.5px] min-h-[260px]"
              value={sysJson}
              onChange={(e) => setSysJson(e.target.value)}
              spellCheck={false}
            />
          </div>
          <div className="flex justify-end gap-2.5 pt-3" style={{ borderTop: '1px solid var(--border-row)' }}>
            <button type="button" className="btn" onClick={() => setSysOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              Save
            </button>
          </div>
        </form>
      </Drawer>

      {/* IMPORT TOML MODAL */}
      <Modal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        title="Import shunt.toml into Draft"
        subtitle="Parses your shunt.toml into structured AI providers, MCP servers, routes, and upstreams without affecting live nodes until you publish."
        maxWidth="max-w-2xl"
      >
        <form onSubmit={handleImportToml} className="space-y-4">
          <textarea
            className="input-base mono text-[12.5px] min-h-[260px]"
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            placeholder="Paste shunt.toml contents here…"
            required
          />
          <div className="flex justify-end gap-2.5">
            <button type="button" className="btn" onClick={() => setImportOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              <Upload size={14} />
              <span>{busy ? 'Importing…' : 'Import into Draft'}</span>
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
