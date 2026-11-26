import { useState } from 'react';
import {
  AlertTriangle,
  Download,
  FileCode2,
  History,
  Rocket,
  RotateCcw,
  ShieldCheck,
} from 'lucide-react';
import {
  api,
  ApiProblemError,
  Cluster,
  formatRelativeTime,
  shortDigest,
  TopologyRevision,
  ValidateDraftResult,
} from '../lib/api';
import { ClusterHeaderContext, PageHeader } from '../components/PageHeader';
import {
  CopyButton,
  Drawer,
  EmptyState,
  StatusIndicator,
  TagPill,
  useToast,
} from '../components/ui';

export function ReleasesPage({
  cluster,
  headerCtx,
  revisions,
  validation,
  hasPendingChanges,
  onOpenPublish,
  onChanged,
}: {
  cluster: Cluster;
  headerCtx: ClusterHeaderContext;
  revisions: TopologyRevision[];
  validation: ValidateDraftResult | null;
  hasPendingChanges: boolean;
  onOpenPublish: () => void;
  onChanged: () => Promise<void>;
}) {
  const toast = useToast();
  const [inspectRev, setInspectRev] = useState<TopologyRevision | null>(null);

  const handleRollback = async (rev: number) => {
    if (
      !window.confirm(
        `Roll back cluster "${cluster.slug}" default fleet (*) to Release v${rev}?\n\nVirtual keys, MCP agent ACLs, and active kill-switches will NOT be reverted.`
      )
    ) {
      return;
    }
    try {
      await api.rollbackRevision(cluster.slug, rev, '*');
      toast.push(`Rolled back to Release v${rev} (Live policies untouched)`);
      await onChanged();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handlePromote = async (rev: number) => {
    try {
      await api.promoteRevision(cluster.slug, rev, '*');
      toast.push(`Promoted Release v${rev} to all nodes (*)`);
      await onChanged();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  return (
    <div>
      <PageHeader
        title="Releases"
        badge={
          hasPendingChanges ? (
            <TagPill dot="brand">Unpublished draft changes</TagPill>
          ) : (
            <StatusIndicator tone="ok" label="Draft matches live" />
          )
        }
        ctx={headerCtx}
        primaryAction={
          <button
            type="button"
            className="btn btn-brand h-8"
            disabled={!validation?.valid}
            onClick={onOpenPublish}
          >
            <Rocket size={13} />
            <span>Publish release</span>
          </button>
        }
      />

      {/* Safe Rollback Note + Diagnostics */}
      {validation && validation.diagnostics.length > 0 && (
        <div
          className="px-6 py-3.5 space-y-2"
          style={{ borderBottom: '1px solid var(--border-row)', background: 'var(--surface-subtle)' }}
        >
          <div className="flex items-center gap-2 text-[12px] font-semibold uppercase tracking-wider" style={{ color: 'var(--ink-muted)' }}>
            <AlertTriangle size={13} style={{ color: validation.valid ? 'var(--warn)' : 'var(--danger)' }} />
            <span>shunt verify diagnostics ({validation.diagnostics.length})</span>
          </div>
          {validation.diagnostics.map((d, idx) => (
            <div key={idx} className="text-[13px] flex items-start gap-2.5">
              <TagPill dot={d.severity === 'error' ? 'danger' : 'warn'} mono>
                {d.rule}
              </TagPill>
              <span style={{ color: 'var(--ink-secondary)' }}>{d.message}</span>
            </div>
          ))}
        </div>
      )}

      <div
        className="px-6 py-3 flex items-center gap-2.5 text-[12.5px]"
        style={{ borderBottom: '1px solid var(--border-row)', color: 'var(--ink-muted)' }}
      >
        <ShieldCheck size={14} style={{ color: 'var(--ok)' }} className="shrink-0" />
        <span>
          Immutable Ed25519-signed releases. Rolling back a release never un-revokes virtual keys, budgets, MCP agent ACLs, or emergency kill-switches.
        </span>
      </div>

      {revisions.length === 0 ? (
        <EmptyState
          icon={<History size={17} />}
          title="No releases published yet"
          description="Validate your draft with shunt verify and publish Release v1 so connected nodes pull your configuration."
          action={
            <button
              type="button"
              className="btn btn-brand"
              disabled={!validation?.valid}
              onClick={onOpenPublish}
            >
              <Rocket size={14} />
              <span>Publish Release v1</span>
            </button>
          }
        />
      ) : (
        <div>
          {revisions.map((rev) => {
            const activeRings = Object.entries(cluster.ring_assignments)
              .filter(([, r]) => r === rev.revision)
              .map(([k]) => k);
            const isDefaultActive = cluster.ring_assignments['*'] === rev.revision;
            return (
              <div key={rev.id} className="row-item">
                <div className="flex items-center gap-3 min-w-0">
                  <div
                    className="icon-tile mono text-[12px] font-semibold"
                    style={{
                      borderColor: isDefaultActive ? 'var(--brand-border)' : 'var(--border)',
                      background: isDefaultActive ? 'var(--brand-soft)' : 'var(--sheet)',
                      color: isDefaultActive ? 'var(--brand)' : 'var(--ink-secondary)',
                    }}
                  >
                    v{rev.revision}
                  </div>
                  <div className="min-w-0 flex flex-wrap items-center gap-2">
                    <span className="text-[13.5px] font-medium truncate">
                      {rev.notes || `Release v${rev.revision}`}
                    </span>
                    <span className="mono text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                      {shortDigest(rev.digest)}
                    </span>
                    {activeRings.map((ring) => (
                      <TagPill key={ring} dot={ring === '*' ? 'ok' : 'brand'} mono>
                        {ring === '*' ? 'live (*)' : ring}
                      </TagPill>
                    ))}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="hidden lg:inline text-[12px] mr-2" style={{ color: 'var(--ink-muted)' }}>
                    {rev.published_by} · {formatRelativeTime(rev.created_at)}
                  </span>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => setInspectRev(rev)}
                  >
                    <FileCode2 size={13} />
                    <span>TOML</span>
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
                      className="btn btn-sm btn-brand"
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
              </div>
            );
          })}
        </div>
      )}

      <Drawer
        open={Boolean(inspectRev)}
        onClose={() => setInspectRev(null)}
        title={`Release v${inspectRev?.revision} — Canonical shunt.toml`}
        subtitle={`Digest ${shortDigest(inspectRev?.digest || '')} · Ed25519 signed`}
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
