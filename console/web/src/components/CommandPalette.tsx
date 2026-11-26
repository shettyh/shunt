import React, { useEffect, useMemo, useState } from 'react';
import {
  Blocks,
  Code2,
  ExternalLink,
  GitBranch,
  History,
  Home,
  Moon,
  Rocket,
  Search,
  Server,
  Shield,
  Sparkles,
  Sun,
  Terminal,
} from 'lucide-react';
import { Cluster } from '../lib/api';
import { useTheme } from './ui';

export type NavSection = 'overview' | 'ai' | 'mcp' | 'routes' | 'fleet' | 'releases' | 'security';

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
  onOpenApi,
  onOpenPublish,
}: {
  open: boolean;
  onClose: () => void;
  onNavigate: (section: NavSection) => void;
  clusters: Cluster[];
  onSelectCluster: (slug: string) => void;
  onQuickConnectNode: () => void;
  onOpenApi: () => void;
  onOpenPublish: () => void;
}) {
  const [query, setQuery] = useState('');
  const [idx, setIdx] = useState(0);
  const theme = useTheme();

  const actions = useMemo<CommandAction[]>(() => {
    const base: CommandAction[] = [
      { id: 'nav-overview', group: 'Navigate', label: 'Overview', hint: 'Quickstart & live pulse', icon: <Home size={14} />, run: () => onNavigate('overview') },
      { id: 'nav-ai', group: 'Navigate', label: 'AI Gateway', hint: 'Providers, models, virtual keys, guardrails', icon: <Sparkles size={14} />, run: () => onNavigate('ai') },
      { id: 'nav-mcp', group: 'Navigate', label: 'MCP Gateway', hint: 'MCP servers, agents & kill-switch', icon: <Blocks size={14} />, run: () => onNavigate('mcp') },
      { id: 'nav-routes', group: 'Navigate', label: 'HTTP Routes & Upstreams', hint: 'API routes, pools & shunt.toml', icon: <GitBranch size={14} />, run: () => onNavigate('routes') },
      { id: 'nav-fleet', group: 'Navigate', label: 'Fleet & Nodes', hint: 'Connected shunt nodes & tokens', icon: <Server size={14} />, run: () => onNavigate('fleet') },
      { id: 'nav-releases', group: 'Navigate', label: 'Releases & Rollback', hint: 'Signed revisions & canary rings', icon: <History size={14} />, run: () => onNavigate('releases') },
      { id: 'nav-security', group: 'Navigate', label: 'Security & Audit', hint: 'Secrets vault, RBAC, SSO & audit chain', icon: <Shield size={14} />, run: () => onNavigate('security') },
      { id: 'act-api', group: 'Quick Actions', label: 'Use Gateway (API & SDK Snippets)', hint: 'Python, TypeScript, Claude Code, cURL, MCP', icon: <Code2 size={14} />, run: onOpenApi },
      { id: 'act-publish', group: 'Quick Actions', label: 'Publish Signed Release', hint: 'Validate and roll out draft', icon: <Rocket size={14} />, run: onOpenPublish },
      { id: 'act-connect', group: 'Quick Actions', label: 'Connect a Shunt Node', hint: 'Mint bootstrap token & CLI snippet', icon: <Terminal size={14} />, run: onQuickConnectNode },
      { id: 'act-theme', group: 'Preferences', label: `Switch Theme (${theme.pref})`, hint: 'Light / Dark / System', icon: theme.resolved === 'dark' ? <Sun size={14} /> : <Moon size={14} />, run: () => theme.cycle() },
      { id: 'act-openapi', group: 'Developer', label: 'OpenAPI 3.1 Spec', hint: '/api/v1/openapi.json', icon: <ExternalLink size={14} />, run: () => window.open('/api/v1/openapi.json', '_blank') },
    ];
    for (const c of clusters) {
      base.push({
        id: `cluster-${c.slug}`,
        group: 'Clusters',
        label: c.name,
        hint: `${c.slug} · ${c.environment}`,
        icon: <Server size={14} />,
        run: () => onSelectCluster(c.slug),
      });
    }
    return base;
  }, [clusters, onNavigate, onSelectCluster, onQuickConnectNode, onOpenApi, onOpenPublish, theme]);

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

  useEffect(() => setIdx(0), [query]);

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
      style={{ background: 'rgba(17, 17, 19, 0.35)', backdropFilter: 'blur(3px)' }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="w-full max-w-lg shadow-2xl overflow-hidden"
        style={{ background: 'var(--sheet)', border: '1px solid var(--border)', borderRadius: 14 }}
      >
        <div
          className="flex items-center gap-2.5 px-4 py-3"
          style={{ borderBottom: '1px solid var(--border-row)' }}
        >
          <Search size={15} style={{ color: 'var(--ink-muted)' }} />
          <input
            className="flex-1 bg-transparent border-0 outline-none text-[13.5px]"
            style={{ color: 'var(--ink)' }}
            placeholder="Jump to AI Gateway, models, fleet, or actions…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
          />
          <kbd className="tag-pill mono text-[11px]">ESC</kbd>
        </div>

        <div className="max-h-80 overflow-y-auto py-1.5">
          {filtered.length === 0 ? (
            <div className="px-4 py-8 text-center text-[12.5px]" style={{ color: 'var(--ink-muted)' }}>
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
                  background: i === idx ? 'var(--surface-subtle)' : 'transparent',
                  color: 'var(--ink)',
                }}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <span style={{ color: i === idx ? 'var(--brand)' : 'var(--ink-muted)' }}>{item.icon}</span>
                  <span className="text-[13.5px] font-medium truncate">{item.label}</span>
                </div>
                <span className="text-[12px] truncate" style={{ color: 'var(--ink-muted)' }}>
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
