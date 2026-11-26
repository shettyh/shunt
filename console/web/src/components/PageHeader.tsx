import React, { useEffect, useRef, useState } from 'react';
import { Check, ChevronDown, Code2, Plus } from 'lucide-react';
import { Cluster } from '../lib/api';

export interface ClusterHeaderContext {
  clusters: Cluster[];
  currentCluster: Cluster;
  onSelectCluster: (slug: string) => void;
  onCreateCluster: () => void;
  onOpenApiDrawer: () => void;
}

export function PageHeader({
  title,
  badge,
  ctx,
  primaryAction,
  secondaryAction,
  controlsLeft,
  controlsRight,
}: {
  title: string;
  badge?: React.ReactNode;
  ctx: ClusterHeaderContext;
  primaryAction?: React.ReactNode;
  secondaryAction?: React.ReactNode;
  controlsLeft?: React.ReactNode;
  controlsRight?: React.ReactNode;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen) return;
    const onDoc = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [menuOpen]);

  return (
    <div style={{ borderBottom: '1px solid var(--border-row)' }}>
      {/* Primary Header Row — mirrors Entire's ultra-clean Title + Context Pill + CTA */}
      <div className="px-6 pt-5 pb-3.5 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <h1
            className="m-0 text-[20px] font-semibold tracking-[-0.02em] truncate"
            style={{ color: 'var(--ink)' }}
          >
            {title}
          </h1>
          {badge}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {/* Cluster Context Pill (like `lumen/app v`) */}
          <div className="relative" ref={menuRef}>
            <button
              type="button"
              onClick={() => setMenuOpen((o) => !o)}
              className="btn h-8 px-2.5 text-[13px] font-medium"
              title="Switch cluster"
            >
              <span
                className="inline-block w-2 h-2 rounded-full shrink-0"
                style={{
                  background:
                    ctx.currentCluster.environment === 'production'
                      ? 'var(--brand)'
                      : 'var(--ok-dot)',
                }}
              />
              <span className="max-w-[140px] truncate">{ctx.currentCluster.slug}</span>
              <ChevronDown size={13} style={{ color: 'var(--ink-muted)' }} />
            </button>

            {menuOpen && (
              <div
                className="absolute right-0 mt-1.5 w-60 p-1.5 z-40 shadow-xl"
                style={{
                  background: 'var(--sheet)',
                  border: '1px solid var(--border)',
                  borderRadius: 12,
                }}
              >
                <div
                  className="px-2.5 py-1.5 text-[11px] font-semibold uppercase tracking-wider"
                  style={{ color: 'var(--ink-muted)' }}
                >
                  Clusters
                </div>
                {ctx.clusters.map((c) => {
                  const selected = c.slug === ctx.currentCluster.slug;
                  return (
                    <button
                      key={c.id}
                      type="button"
                      onClick={() => {
                        ctx.onSelectCluster(c.slug);
                        setMenuOpen(false);
                      }}
                      className="w-full flex items-center justify-between gap-2 px-2.5 py-2 rounded-lg text-left text-[13px] border-0 cursor-pointer transition-colors"
                      style={{
                        background: selected ? 'var(--surface-subtle)' : 'transparent',
                        color: 'var(--ink)',
                      }}
                    >
                      <div className="min-w-0">
                        <div className="font-medium truncate">{c.name}</div>
                        <div className="mono text-[11px] truncate" style={{ color: 'var(--ink-muted)' }}>
                          {c.slug} · {c.environment}
                        </div>
                      </div>
                      {selected && <Check size={14} style={{ color: 'var(--brand)' }} className="shrink-0" />}
                    </button>
                  );
                })}
                <div className="my-1" style={{ borderTop: '1px solid var(--border-row)' }} />
                <button
                  type="button"
                  onClick={() => {
                    setMenuOpen(false);
                    ctx.onCreateCluster();
                  }}
                  className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-[13px] border-0 bg-transparent cursor-pointer hover:bg-[var(--surface-subtle)]"
                  style={{ color: 'var(--ink-secondary)' }}
                >
                  <Plus size={14} />
                  <span>New cluster</span>
                </button>
              </div>
            )}
          </div>

          {/* Cloudflare AI Gateway-inspired persistent API Quick-Connect button */}
          <button
            type="button"
            onClick={ctx.onOpenApiDrawer}
            className="btn h-8 px-2.5 text-[13px]"
            title="Copy SDK & cURL snippets for this gateway"
          >
            <Code2 size={14} style={{ color: 'var(--brand)' }} />
            <span className="hidden sm:inline">API</span>
          </button>

          {secondaryAction}
          {primaryAction}
        </div>
      </div>

      {/* Control Strip (Segmented Tabs + Search) */}
      {(controlsLeft || controlsRight) && (
        <div className="px-6 pb-3.5 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2.5">{controlsLeft}</div>
          <div className="flex flex-wrap items-center gap-2.5">{controlsRight}</div>
        </div>
      )}
    </div>
  );
}
