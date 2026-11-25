import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  Edit3,
  FileCode2,
  GitBranch,
  History,
  Plus,
  Rocket,
  RotateCcw,
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
import { CopyButton, Modal, useToast } from '../components/ui';

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

export function TopologyPage({
  cluster,
  onClusterChanged,
}: {
  cluster: Cluster;
  onClusterChanged: () => void;
}) {
  const toast = useToast();
  const [tab, setTab] = useState<'draft' | 'toml' | 'revisions'>('draft');
  const [resources, setResources] = useState<TopologyResource[]>([]);
  const [validation, setValidation] = useState<ValidateDraftResult | null>(null);
  const [revisions, setRevisions] = useState<TopologyRevision[]>([]);
  const [loading, setLoading] = useState(true);

  // Resource Editor Modal
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

  // Inspect Revision TOML Modal
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
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : 'Failed to load topology', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [cluster.slug]);

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
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="m-0 text-xl font-semibold tracking-tight">Config &amp; Releases</h1>
            <span className="badge">Versioned · Rollback-safe</span>
          </div>
          <p className="m-0 mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
            Listeners, upstreams, routes, and plugins for HTTP APIs, AI models, and MCP servers—validated by <code>shunt-config</code> + <code>shunt verify</code> and Ed25519-signed before rollout.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button type="button" className="btn" onClick={() => setImportOpen(true)}>
            <Upload size={14} />
            <span>Import shunt.toml</span>
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!validation?.valid}
            onClick={() => setPublishOpen(true)}
          >
            <Rocket size={14} />
            <span>Publish Release</span>
          </button>
        </div>
      </div>

      {/* Live Validation Strip */}
      {validation && (
        <div
          className="surface p-3.5 flex flex-wrap items-center justify-between gap-3"
          style={{
            background: validation.valid ? 'var(--ok-soft)' : 'var(--danger-soft)',
            borderColor: validation.valid ? 'var(--ok-border)' : 'var(--danger-border)',
          }}
        >
          <div className="flex items-center gap-2.5 text-xs">
            {validation.valid ? (
              <CheckCircle2 size={16} style={{ color: 'var(--ok)' }} />
            ) : (
              <AlertTriangle size={16} style={{ color: 'var(--danger)' }} />
            )}
            <span style={{ color: validation.valid ? 'var(--ok)' : 'var(--danger)' }} className="font-semibold">
              {validation.valid
                ? `Draft valid — ${validation.upstream_count} upstream(s), ${validation.route_count} route(s), ${validation.warnings} warning(s)`
                : `Validation failed — ${validation.errors} error(s), ${validation.warnings} warning(s)`}
            </span>
          </div>
          <span className="mono text-[11px]" style={{ color: 'var(--text-muted)' }}>
            draft digest: {shortDigest(validation.digest)}
          </span>
        </div>
      )}

      {validation && validation.diagnostics.length > 0 && (
        <div className="surface p-4 space-y-2">
          <div className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
            shunt verify Diagnostics
          </div>
          {validation.diagnostics.map((d, i) => (
            <div
              key={i}
              className="text-xs p-2.5 rounded-lg flex items-start gap-2.5"
              style={{
                background: d.severity === 'error' ? 'var(--danger-soft)' : 'var(--warn-soft)',
                border: `1px solid ${d.severity === 'error' ? 'var(--danger-border)' : 'var(--warn-border)'}`,
              }}
            >
              <span className="badge mono uppercase">{d.severity}</span>
              <div>
                <span className="mono font-semibold">{d.rule}</span>
                {d.subject && <span className="mono ml-1.5 opacity-80">({d.subject})</span>}
                <div className="mt-0.5">{d.message}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Sub-tabs */}
      <div className="flex items-center gap-1" style={{ borderBottom: '1px solid var(--border)' }}>
        {[
          { id: 'draft' as const, label: `Draft Config (${resources.length})`, icon: <GitBranch size={14} /> },
          { id: 'toml' as const, label: 'Compiled shunt.toml', icon: <FileCode2 size={14} /> },
          { id: 'revisions' as const, label: `Releases & Rollback (${revisions.length})`, icon: <History size={14} /> },
        ].map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className="flex items-center gap-1.5 px-3.5 py-2.5 text-xs font-medium bg-transparent border-0 cursor-pointer transition-colors"
            style={{
              color: tab === t.id ? 'var(--text-primary)' : 'var(--text-muted)',
              borderBottom: `2px solid ${tab === t.id ? 'var(--text-primary)' : 'transparent'}`,
              marginBottom: -1,
            }}
          >
            {t.icon}
            <span>{t.label}</span>
          </button>
        ))}
      </div>

      {/* Tab 1: Draft Resources */}
      {tab === 'draft' && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium" style={{ color: 'var(--text-muted)' }}>
              Add resource:
            </span>
            {(['upstream', 'route', 'route_group', 'global_plugin'] as TopologyResourceKind[]).map(
              (k) => (
                <button
                  key={k}
                  type="button"
                  className="btn text-xs py-1 px-2.5"
                  onClick={() => openNewResource(k)}
                >
                  <Plus size={12} />
                  <span className="mono">{k}</span>
                </button>
              )
            )}
          </div>

          <div className="surface overflow-hidden">
            {loading ? (
              <div className="p-8 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
                Loading draft resources…
              </div>
            ) : (
              <table className="swiss-table text-xs">
                <thead>
                  <tr>
                    <th>Kind</th>
                    <th>Slug</th>
                    <th>Summary</th>
                    <th>Version / ETag</th>
                    <th>Updated</th>
                    <th className="text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {resources.map((r) => (
                    <tr key={r.id}>
                      <td>
                        <span className="badge mono">{r.kind}</span>
                      </td>
                      <td className="mono font-semibold">{r.slug}</td>
                      <td className="mono text-[11px] max-w-md truncate" style={{ color: 'var(--text-muted)' }}>
                        {JSON.stringify(r.spec)}
                      </td>
                      <td className="mono" style={{ color: 'var(--text-muted)' }}>
                        v{r.version} · {r.etag}
                      </td>
                      <td style={{ color: 'var(--text-muted)' }}>{formatRelativeTime(r.updated_at)}</td>
                      <td className="text-right">
                        <div className="inline-flex items-center gap-1">
                          <button
                            type="button"
                            className="btn text-xs py-1 px-2"
                            onClick={() => openEditResource(r)}
                          >
                            <Edit3 size={12} />
                            <span>Edit</span>
                          </button>
                          <button
                            type="button"
                            className="btn-ghost p-1.5 rounded cursor-pointer border-0"
                            style={{ color: 'var(--danger)' }}
                            onClick={() => handleDeleteResource(r)}
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Compiled TOML Preview */}
      {tab === 'toml' && (
        <div className="surface p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="m-0 text-sm font-semibold">Canonical Compiled shunt.toml (Secrets Redacted)</h2>
              <p className="m-0 mt-0.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                References like <code>secret:&lt;slug&gt;</code> are resolved into node memory only when authenticated nodes pull a signed release bundle.
              </p>
            </div>
            <CopyButton text={validation?.compiled_toml || ''} label="Copy TOML" />
          </div>
          <pre className="code-block m-0 max-h-[60vh]">{validation?.compiled_toml || ''}</pre>
        </div>
      )}

      {/* Tab 3: Releases & Rollback */}
      {tab === 'revisions' && (
        <div className="space-y-4">
          <div
            className="surface p-3.5 flex items-center gap-2.5 text-xs"
            style={{ background: 'var(--bg-subtle)' }}
          >
            <ShieldCheck size={16} style={{ color: 'var(--ok)' }} className="shrink-0" />
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
                        <td className="mono font-semibold text-sm">#{rev.revision}</td>
                        <td>
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
                        <td className="mono" style={{ color: 'var(--text-muted)' }}>
                          {shortDigest(rev.digest)}
                        </td>
                        <td>{rev.notes || <span style={{ color: 'var(--text-muted)' }}>—</span>}</td>
                        <td style={{ color: 'var(--text-muted)' }}>
                          {rev.published_by} · {formatRelativeTime(rev.created_at)}
                        </td>
                        <td className="text-right">
                          <div className="inline-flex items-center gap-1.5">
                            <button
                              type="button"
                              className="btn text-xs py-1 px-2"
                              onClick={() => setInspectRev(rev)}
                            >
                              <FileCode2 size={12} />
                              <span>TOML</span>
                            </button>
                            <a
                              href={`/api/v1/clusters/${cluster.slug}/revisions/${rev.revision}/export.toml`}
                              className="btn text-xs py-1 px-2 no-underline"
                            >
                              <Download size={12} />
                            </a>
                            {!isDefaultActive && activeRings.length > 0 && (
                              <button
                                type="button"
                                className="btn btn-accent text-xs py-1 px-2"
                                onClick={() => handlePromote(rev.revision)}
                              >
                                Promote to *
                              </button>
                            )}
                            {!isDefaultActive && (
                              <button
                                type="button"
                                className="btn text-xs py-1 px-2"
                                onClick={() => handleRollback(rev.revision)}
                              >
                                <RotateCcw size={12} />
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
            )}
          </div>
        </div>
      )}

      {/* Resource Editor Modal */}
      <Modal
        open={editorOpen}
        onClose={() => setEditorOpen(false)}
        title={editEtag ? `Edit ${editKind}/${editSlug}` : `Add ${editKind}`}
        subtitle="Uses ETag + If-Match optimistic concurrency to prevent silent overwrites."
        maxWidth="max-w-2xl"
      >
        <form onSubmit={handleSaveResource} className="space-y-4">
          {editError && (
            <div
              className="p-3 rounded-lg text-xs"
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
                  className="btn text-xs py-0.5 px-2"
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
              className="input-base mono text-xs min-h-[240px]"
              value={editJson}
              onChange={(e) => setEditJson(e.target.value)}
              spellCheck={false}
            />
          </div>
          <div className="flex justify-end gap-2">
            <button type="button" className="btn" onClick={() => setEditorOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? 'Saving…' : 'Save to Draft'}
            </button>
          </div>
        </form>
      </Modal>

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
              <Upload size={14} />
              <span>{importing ? 'Importing…' : 'Import into Draft'}</span>
            </button>
          </div>
        </form>
      </Modal>

      {/* Publish Modal */}
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
              <button type="button" className="btn text-xs py-0.5 px-2" onClick={() => setPubRing('*')}>
                * (All Nodes)
              </button>
              <button
                type="button"
                className="btn text-xs py-0.5 px-2"
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
              <Rocket size={14} />
              <span>{publishing ? 'Publishing…' : 'Publish & Roll Out'}</span>
            </button>
          </div>
        </form>
      </Modal>

      {/* Release TOML Viewer Modal */}
      <Modal
        open={Boolean(inspectRev)}
        onClose={() => setInspectRev(null)}
        title={`Release #${inspectRev?.revision} — Canonical shunt.toml`}
        subtitle={`Digest: ${inspectRev?.digest || ''} · Ed25519 signed`}
        maxWidth="max-w-3xl"
      >
        {inspectRev && (
          <div className="space-y-3">
            <div className="flex justify-end">
              <CopyButton text={inspectRev.compiled_toml} label="Copy TOML" />
            </div>
            <pre className="code-block m-0 max-h-[60vh]">{inspectRev.compiled_toml}</pre>
          </div>
        )}
      </Modal>
    </div>
  );
}
