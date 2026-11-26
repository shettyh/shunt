import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Clock,
  Copy,
  Search,
  Terminal,
  X,
  XCircle,
} from 'lucide-react';
import { buildShuntConnectCommand, ConnectCommandMode } from '../lib/api';

// =============================================================================
// Theme Context (Light Hero Default + Warm Obsidian Dark Mode)
// =============================================================================

export type ThemePref = 'light' | 'dark' | 'system';

interface ThemeContextValue {
  pref: ThemePref;
  resolved: 'light' | 'dark';
  setPref: (pref: ThemePref) => void;
  cycle: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [pref, setPrefState] = useState<ThemePref>(() => {
    const saved = localStorage.getItem('shunt_console_theme');
    return saved === 'light' || saved === 'dark' || saved === 'system' ? saved : 'light';
  });

  const [systemDark, setSystemDark] = useState(() =>
    window.matchMedia('(prefers-color-scheme: dark)').matches
  );

  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = (e: MediaQueryListEvent) => setSystemDark(e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  const resolved: 'light' | 'dark' =
    pref === 'system' ? (systemDark ? 'dark' : 'light') : pref;

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', resolved);
    localStorage.setItem('shunt_console_theme', pref);
  }, [pref, resolved]);

  const setPref = useCallback((p: ThemePref) => setPrefState(p), []);
  const cycle = useCallback(() => {
    setPrefState((cur) => (cur === 'light' ? 'dark' : cur === 'dark' ? 'system' : 'light'));
  }, []);

  return (
    <ThemeContext.Provider value={{ pref, resolved, setPref, cycle }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be inside ThemeProvider');
  return ctx;
}

// =============================================================================
// Toast Notifications
// =============================================================================

interface Toast {
  id: number;
  kind: 'success' | 'error' | 'info';
  message: string;
}

interface ToastContextValue {
  push: (message: string, kind?: 'success' | 'error' | 'info') => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const push = useCallback((message: string, kind: 'success' | 'error' | 'info' = 'success') => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev.slice(-3), { id, kind, message }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  }, []);

  return (
    <ToastContext.Provider value={{ push }}>
      {children}
      <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 max-w-md pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            className="pointer-events-auto card-quiet shadow-lg px-3.5 py-2.5 flex items-start gap-2.5 text-[13px]"
            style={{
              borderColor:
                t.kind === 'error'
                  ? 'var(--danger-border)'
                  : t.kind === 'success'
                    ? 'var(--border-strong)'
                    : 'var(--border)',
            }}
          >
            {t.kind === 'error' ? (
              <AlertTriangle size={15} style={{ color: 'var(--danger)' }} className="mt-0.5 shrink-0" />
            ) : (
              <CheckCircle2 size={15} style={{ color: 'var(--ok)' }} className="mt-0.5 shrink-0" />
            )}
            <span className="flex-1" style={{ color: 'var(--ink)' }}>
              {t.message}
            </span>
            <button
              type="button"
              onClick={() => setToasts((prev) => prev.filter((x) => x.id !== t.id))}
              className="btn-ghost p-0.5"
              style={{ color: 'var(--ink-muted)' }}
              aria-label="Dismiss notification"
            >
              <X size={13} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be inside ToastProvider');
  return ctx;
}

// =============================================================================
// Brand Mark (Clean Ink Tile + Warm Shunt Terracotta Accent Dot)
// =============================================================================

export function ShuntMark({ size = 28 }: { size?: number }) {
  return (
    <div
      style={{
        width: size,
        height: size,
        borderRadius: Math.max(7, Math.round(size * 0.28)),
        background: 'var(--ink)',
        color: 'var(--sheet)',
        display: 'grid',
        placeItems: 'center',
        position: 'relative',
        flexShrink: 0,
      }}
      className="select-none"
      aria-hidden="true"
    >
      <svg
        width={Math.round(size * 0.56)}
        height={Math.round(size * 0.56)}
        viewBox="0 0 18 18"
        fill="none"
      >
        <path
          d="M3 5.5H9.5C11.1569 5.5 12.5 6.84315 12.5 8.5V8.5C12.5 10.1569 11.1569 11.5 9.5 11.5H5.5"
          stroke="currentColor"
          strokeWidth="2.1"
          strokeLinecap="round"
        />
        <path
          d="M15 12.5H8.5C6.84315 12.5 5.5 11.1569 5.5 9.5"
          stroke="var(--brand)"
          strokeWidth="2.1"
          strokeLinecap="round"
        />
        <circle cx="14.2" cy="5.5" r="2" fill="var(--brand)" />
      </svg>
    </div>
  );
}

// =============================================================================
// Editorial Primitives (Segmented Tabs, Search, Tag Pill, Quiet Status, Toggle)
// =============================================================================

export function SegmentedTabs<T extends string>({
  value,
  onChange,
  items,
}: {
  value: T;
  onChange: (next: T) => void;
  items: { id: T; label: string; count?: number }[];
}) {
  return (
    <div className="segmented" role="tablist">
      {items.map((item) => {
        const active = item.id === value;
        return (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={active}
            data-active={active}
            onClick={() => onChange(item.id)}
            className="segmented-btn"
          >
            <span>{item.label}</span>
            {typeof item.count === 'number' && (
              <span
                className="tabular text-[11px]"
                style={{ color: active ? 'var(--ink-secondary)' : 'var(--ink-muted)' }}
              >
                {item.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

export function SearchField({
  value,
  onChange,
  placeholder = 'Search',
  className = 'w-56',
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  className?: string;
}) {
  return (
    <div
      className={`flex items-center gap-2 px-2.5 h-8 rounded-lg ${className}`}
      style={{ background: 'var(--surface-subtle)', border: '1px solid var(--border)' }}
    >
      <Search size={13} style={{ color: 'var(--ink-muted)' }} className="shrink-0" />
      <input
        className="w-full bg-transparent border-0 outline-none text-[13px]"
        style={{ color: 'var(--ink)' }}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange('')}
          className="btn-ghost p-0.5"
          style={{ color: 'var(--ink-muted)' }}
          aria-label="Clear search"
        >
          <X size={12} />
        </button>
      )}
    </div>
  );
}

export type DotColor = 'brand' | 'ok' | 'warn' | 'danger' | 'info' | 'neutral';

const DOT_VAR: Record<DotColor, string> = {
  brand: 'var(--brand)',
  ok: 'var(--ok-dot)',
  warn: 'var(--warn-dot)',
  danger: 'var(--danger-dot)',
  info: 'var(--info-dot)',
  neutral: 'var(--ink-muted)',
};

export function TagPill({
  children,
  dot,
  mono = false,
  brand = false,
}: {
  children: React.ReactNode;
  dot?: DotColor;
  mono?: boolean;
  brand?: boolean;
}) {
  return (
    <span className={`tag-pill ${brand ? 'tag-pill-brand' : ''} ${mono ? 'mono text-[11.5px]' : ''}`}>
      {dot && (
        <span
          className="inline-block w-1.5 h-1.5 rounded-full shrink-0"
          style={{ background: DOT_VAR[dot] }}
        />
      )}
      <span>{children}</span>
    </span>
  );
}

export function StatusIndicator({
  tone,
  label,
}: {
  tone: 'ok' | 'warn' | 'danger' | 'neutral';
  label: string;
}) {
  if (tone === 'ok') {
    return (
      <span className="inline-flex items-center gap-1.5 text-[12.5px] font-medium whitespace-nowrap" style={{ color: 'var(--ink-muted)' }}>
        <Check size={13} style={{ color: 'var(--ok)' }} />
        <span>{label}</span>
      </span>
    );
  }
  if (tone === 'warn') {
    return (
      <span className="inline-flex items-center gap-1.5 text-[12.5px] font-medium whitespace-nowrap" style={{ color: 'var(--warn)' }}>
        <Clock size={13} />
        <span>{label}</span>
      </span>
    );
  }
  if (tone === 'danger') {
    return (
      <span className="inline-flex items-center gap-1.5 text-[12.5px] font-medium whitespace-nowrap" style={{ color: 'var(--danger)' }}>
        <XCircle size={13} />
        <span>{label}</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-[12.5px] whitespace-nowrap" style={{ color: 'var(--ink-muted)' }}>
      <span className="inline-block w-1.5 h-1.5 rounded-full" style={{ background: 'var(--border-strong)' }} />
      <span>{label}</span>
    </span>
  );
}

export function ToggleSwitch({
  checked,
  onChange,
  disabled = false,
  label,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
  label?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      data-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="toggle-switch"
    >
      <span className="toggle-knob" />
    </button>
  );
}

export function FeatureToggleRow({
  icon,
  title,
  description,
  tag,
  checked,
  onToggle,
  disabled = false,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  tag?: string;
  checked: boolean;
  onToggle: (next: boolean) => void;
  disabled?: boolean;
  children?: React.ReactNode;
}) {
  return (
    <div style={{ borderBottom: '1px solid var(--border-row)' }} className="last:border-b-0">
      <div className="flex items-center justify-between gap-4 px-6 py-4">
        <div className="flex items-start gap-3.5 min-w-0">
          <div className="icon-tile mt-0.5">{icon}</div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[14px] font-medium" style={{ color: 'var(--ink)' }}>
                {title}
              </span>
              {tag && <TagPill dot={checked ? 'brand' : 'neutral'}>{tag}</TagPill>}
            </div>
            <p className="m-0 mt-0.5 text-[13px]" style={{ color: 'var(--ink-muted)' }}>
              {description}
            </p>
          </div>
        </div>
        <ToggleSwitch checked={checked} onChange={onToggle} disabled={disabled} label={title} />
      </div>
      {checked && children && (
        <div
          className="px-6 pb-5 pt-3 ml-[44px]"
          style={{ borderTop: '1px dashed var(--border-row)' }}
        >
          {children}
        </div>
      )}
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="px-6 py-16 text-center max-w-md mx-auto">
      <div className="icon-tile mx-auto mb-3.5" style={{ width: 38, height: 38, borderRadius: 10 }}>
        {icon}
      </div>
      <div className="text-[15px] font-semibold tracking-tight" style={{ color: 'var(--ink)' }}>
        {title}
      </div>
      <p className="m-0 mt-1.5 text-[13px]" style={{ color: 'var(--ink-muted)' }}>
        {description}
      </p>
      {action && <div className="mt-5 flex items-center justify-center gap-2.5">{action}</div>}
    </div>
  );
}

// =============================================================================
// Copy Button, Modal, SlideOver Drawer, Connect Command Box
// =============================================================================

export function CopyButton({
  text,
  label = 'Copy',
  className = '',
}: {
  text: string;
  label?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard blocked
    }
  };

  return (
    <button type="button" onClick={handleCopy} className={`btn btn-sm ${className}`}>
      {copied ? (
        <>
          <Check size={13} style={{ color: 'var(--ok)' }} />
          {label !== '' && <span>Copied</span>}
        </>
      ) : (
        <>
          <Copy size={13} />
          {label !== '' && <span>{label}</span>}
        </>
      )}
    </button>
  );
}

export function Modal({
  open,
  onClose,
  title,
  subtitle,
  children,
  maxWidth = 'max-w-xl',
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  maxWidth?: string;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(17, 17, 19, 0.36)', backdropFilter: 'blur(3px)' }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className={`w-full ${maxWidth} max-h-[88vh] flex flex-col overflow-hidden shadow-2xl`}
        style={{
          background: 'var(--sheet)',
          border: '1px solid var(--border)',
          borderRadius: 16,
        }}
      >
        <div
          className="px-6 py-4 flex items-start justify-between gap-4 shrink-0"
          style={{ borderBottom: '1px solid var(--border-row)' }}
        >
          <div className="min-w-0">
            <h2 className="m-0 text-[15px] font-semibold tracking-tight">{title}</h2>
            {subtitle && (
              <p className="m-0 mt-0.5 text-[13px]" style={{ color: 'var(--ink-muted)' }}>
                {subtitle}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="btn-ghost p-1.5"
            aria-label="Close modal"
          >
            <X size={16} />
          </button>
        </div>
        <div className="p-6 overflow-y-auto">{children}</div>
      </div>
    </div>
  );
}

export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  widthClass = 'max-w-xl',
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  widthClass?: string;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end p-2.5 sm:p-3"
      style={{ background: 'rgba(17, 17, 19, 0.28)', backdropFilter: 'blur(2px)' }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className={`w-full ${widthClass} h-full flex flex-col shadow-2xl overflow-hidden`}
        style={{
          background: 'var(--sheet)',
          border: '1px solid var(--border)',
          borderRadius: 16,
        }}
      >
        <div
          className="px-6 py-4 flex items-start justify-between gap-4 shrink-0"
          style={{ borderBottom: '1px solid var(--border-row)' }}
        >
          <div className="min-w-0">
            <h2 className="m-0 text-[15px] font-semibold tracking-tight truncate">{title}</h2>
            {subtitle && (
              <p className="m-0 mt-0.5 text-[13px]" style={{ color: 'var(--ink-muted)' }}>
                {subtitle}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="btn-ghost p-1.5 shrink-0"
            aria-label="Close panel"
          >
            <X size={16} />
          </button>
        </div>
        <div className="p-6 overflow-y-auto flex-1">{children}</div>
      </div>
    </div>
  );
}

export function ConnectCommandBox({
  controlPlaneUrl,
  clusterSlug,
  token,
  labels,
}: {
  controlPlaneUrl: string;
  clusterSlug: string;
  token: string;
  labels?: string;
}) {
  const [mode, setMode] = useState<ConnectCommandMode>('binary');
  const cmd = buildShuntConnectCommand({
    controlPlaneUrl,
    clusterSlug,
    token,
    labels,
    mode,
  });

  return (
    <div className="space-y-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <SegmentedTabs
          value={mode}
          onChange={setMode}
          items={[
            { id: 'binary', label: 'shunt CLI' },
            { id: 'cargo', label: 'cargo run' },
            { id: 'docker', label: 'Docker' },
          ]}
        />
        <CopyButton label="Copy" text={cmd} />
      </div>
      <div>
        <div
          className="flex items-center gap-1.5 px-3.5 py-1.5 text-[11.5px] rounded-t-[10px]"
          style={{
            background: 'var(--surface-subtle)',
            border: '1px solid var(--border)',
            borderBottom: 'none',
            color: 'var(--ink-muted)',
          }}
        >
          <Terminal size={12} />
          <span>
            {mode === 'cargo'
              ? 'Run from the Shunt repository root'
              : mode === 'docker'
                ? 'Run with Docker (maps localhost to host.docker.internal)'
                : 'Run anywhere `shunt` is installed in PATH'}
          </span>
        </div>
        <pre className="code-block m-0 rounded-t-none">{cmd}</pre>
      </div>
    </div>
  );
}
