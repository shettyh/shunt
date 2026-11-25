import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  FileCode2,
  KeyRound,
  Layers,
  Moon,
  Search,
  Server,
  Shield,
  Sun,
  Terminal,
  ExternalLink,
} from 'lucide-react';
import { Cluster } from '../lib/api';
import { useTheme } from './ui';

export type NavSection = 'overview' | 'fleet' | 'topology' | 'state' | 'secrets' | 'access';

export interface CommandAction {
  id: string;
  group: string;
  label: string;
  hint?: string;
  icon: React.ReactNode;
  run: () => void;
}

export function CommandPalette({
  open,
  onClose,
  onNavigate,
  clusters,
  onSelectCluster,
  onQuickConnectNode,
}: {
  open: boolean;
  onClose: () => void;
  onNavigate: (section: NavSection) => void;
  clusters: Cluster[];
  onSelectCluster: (slug: string) => void;
  onQuickConnectNode: () => void;
}) {
  const [query, setQuery] = useState('');
  const [idx, setIdx] = useState(0);
  const theme = useTheme();

  const actions = useMemo<CommandAction[]>(() => {
    const base: CommandAction[] = [
      {
        id: 'nav-overview',
        group: 'Navigate',
        label: 'Cluster Overview',
        hint: 'Health, active revision, convergence',
        icon: <Activity size={15} />,
        run: () => onNavigate('overview'),
      },
      {
        id: 'nav-fleet',
        group: 'Navigate',
        label: 'Fleet & Nodes',
        hint: 'Enrolled nodes, drift status, labels',
        icon: <Server size={15} />,
        run: () => onNavigate('fleet'),
      },
      {
        id: 'nav-topology',
        group: 'Navigate',
        label: 'Topology & Revisions (Channel 1)',
        hint: 'Resources, shunt verify, publish & rollback',
        icon: <FileCode2 size={15} />,
        run: () => onNavigate('topology'),
      },
      {
        id: 'nav-state',
        group: 'Navigate',
        label: 'Synced State Tables (Channel 2)',
        hint: 'Sub-50ms ArcSwap namespaces & deltas',
        icon: <Layers size={15} />,
        run: () => onNavigate('state'),
      },
      {
        id: 'nav-secrets',
        group: 'Navigate',
        label: 'Secrets Vault',
        hint: 'AES-256-GCM envelope vault & env refs',
        icon: <KeyRound size={15} />,
        run: () => onNavigate('secrets'),
      },
      {
        id: 'nav-access',
        group: 'Navigate',
        label: 'Access, API Tokens & Audit Log',
        hint: 'RBAC, OIDC, hash-chain verification',
        icon: <Shield size={15} />,
        run: () => onNavigate('access'),
      },
      {
        id: 'act-connect',
        group: 'Quick Actions',
        label: 'Connect a Shunt Node',
        hint: 'Generate bootstrap token & CLI snippet',
        icon: <Terminal size={15} />,
        run: onQuickConnectNode,
      },
      {
        id: 'act-theme',
        group: 'Preferences',
        label: `Cycle Theme (current: ${theme.pref})`,
        hint: 'System / Light / Dark',
        icon: theme.resolved === 'dark' ? <Sun size={15} /> : <Moon size={15} />,
        run: () => theme.cycle(),
      },
      {
        id: 'act-openapi',
        group: 'Developer',
        label: 'Open OpenAPI 3.1 Specification JSON',
        hint: '/api/v1/openapi.json',
        icon: <ExternalLink size={15} />,
        run: () => window.open('/api/v1/openapi.json', '_blank'),
      },
    ];

    for (const c of clusters) {
      base.push({
        id: `cluster-${c.slug}`,
        group: 'Switch Cluster',
        label: `${c.name} (${c.slug})`,
        hint: c.environment,
        icon: <Server size={15} />,
        run: () => onSelectCluster(c.slug),
      });
    }
    return base;
  }, [clusters, onNavigate, onSelectCluster, onQuickConnectNode, theme]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return actions;
    return actions.filter(
      (a) =>
        a.label.toLowerCase().includes(q) ||
        (a.hint && a.hint.toLowerCase().includes(q)) ||
        a.group.toLowerCase().includes(q)
    );
  }, [actions, query]);

  useEffect(() => {
    if (open) {
      setQuery('');
      setIdx(0);
    }
  }, [open]);

  useEffect(() => {
    setIdx(0);
  }, [query]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setIdx((i) => Math.min(filtered.length - 1, i + 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setIdx((i) => Math.max(0, i - 1));
      } else if (e.key === 'Enter' && filtered[idx]) {
        e.preventDefault();
        filtered[idx].run();
        onClose();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, filtered, idx, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[14vh] p-4"
      style={{ background: 'rgba(0, 0, 0, 0.42)', backdropFilter: 'blur(3px)' }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="surface w-full max-w-lg shadow-2xl overflow-hidden">
        <div
          className="flex items-center gap-2.5 px-4 py-3"
          style={{ borderBottom: '1px solid var(--border)' }}
        >
          <Search size={16} style={{ color: 'var(--text-muted)' }} />
          <input
            className="flex-1 bg-transparent border-0 outline-none text-sm"
            style={{ color: 'var(--text-primary)' }}
            placeholder="Jump to view, switch cluster, or run action…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
          />
          <kbd
            className="text-[11px] mono px-1.5 py-0.5 rounded"
            style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border)', color: 'var(--text-muted)' }}
          >
            ESC
          </kbd>
        </div>

        <div className="max-h-80 overflow-y-auto py-1.5">
          {filtered.length === 0 ? (
            <div className="px-4 py-8 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
              No matching commands
            </div>
          ) : (
            filtered.map((item, i) => (
              <button
                key={item.id}
                type="button"
                onMouseEnter={() => setIdx(i)}
                onClick={() => {
                  item.run();
                  onClose();
                }}
                className="w-full text-left px-4 py-2.5 flex items-center justify-between gap-3 cursor-pointer border-0 transition-colors"
                style={{
                  background: i === idx ? 'var(--bg-hover)' : 'transparent',
                  color: 'var(--text-primary)',
                }}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <span style={{ color: 'var(--text-muted)' }}>{item.icon}</span>
                  <span className="text-sm font-medium truncate">{item.label}</span>
                </div>
                <span className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                  {item.hint || item.group}
                </span>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
