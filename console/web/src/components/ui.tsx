import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { Check, CheckCircle2, AlertTriangle, X, Copy, Terminal } from 'lucide-react';
import { buildShuntConnectCommand, ConnectCommandMode } from '../lib/api';

export type ThemePref = 'system' | 'light' | 'dark';

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
    return saved === 'light' || saved === 'dark' || saved === 'system' ? saved : 'system';
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
    setPrefState((cur) => (cur === 'system' ? 'light' : cur === 'light' ? 'dark' : 'system'));
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
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-md pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            className="pointer-events-auto surface shadow-lg px-3.5 py-2.5 flex items-start gap-2.5 text-sm"
            style={{
              borderColor:
                t.kind === 'error'
                  ? 'var(--danger-border)'
                  : t.kind === 'success'
                    ? 'var(--ok-border)'
                    : 'var(--border)',
            }}
          >
            {t.kind === 'error' ? (
              <AlertTriangle size={16} style={{ color: 'var(--danger)' }} className="mt-0.5 shrink-0" />
            ) : (
              <CheckCircle2 size={16} style={{ color: 'var(--ok)' }} className="mt-0.5 shrink-0" />
            )}
            <span className="flex-1" style={{ color: 'var(--text-primary)' }}>
              {t.message}
            </span>
            <button
              onClick={() => setToasts((prev) => prev.filter((x) => x.id !== t.id))}
              className="opacity-60 hover:opacity-100 cursor-pointer bg-transparent border-0 p-0"
              style={{ color: 'var(--text-muted)' }}
              aria-label="Dismiss notification"
            >
              <X size={14} />
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
// Shared Micro-Components
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
      // Fallback
    }
  };

  return (
    <button type="button" onClick={handleCopy} className={`btn text-xs py-1 px-2.5 ${className}`}>
      {copied ? (
        <>
          <Check size={13} style={{ color: 'var(--ok)' }} />
          <span>Copied</span>
        </>
      ) : (
        <>
          <Copy size={13} />
          <span>{label}</span>
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
      className="fixed inset-0 z-40 flex items-center justify-center p-4"
      style={{ background: 'rgba(0, 0, 0, 0.45)', backdropFilter: 'blur(3px)' }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className={`surface w-full ${maxWidth} max-h-[90vh] flex flex-col shadow-2xl overflow-hidden`}>
        <div
          className="px-5 py-4 flex items-start justify-between gap-4"
          style={{ borderBottom: '1px solid var(--border)' }}
        >
          <div>
            <h2 className="m-0 text-base font-semibold tracking-tight">{title}</h2>
            {subtitle && (
              <p className="m-0 mt-0.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                {subtitle}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="btn-ghost p-1 rounded-md cursor-pointer border-0"
            aria-label="Close modal"
          >
            <X size={16} />
          </button>
        </div>
        <div className="p-5 overflow-y-auto">{children}</div>
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
      className="fixed inset-0 z-40 flex justify-end"
      style={{ background: 'rgba(0, 0, 0, 0.35)', backdropFilter: 'blur(2px)' }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className={`w-full ${widthClass} h-full flex flex-col shadow-2xl overflow-hidden`}
        style={{
          background: 'var(--bg-elevated)',
          borderLeft: '1px solid var(--border)',
        }}
      >
        <div
          className="px-5 py-3.5 flex items-start justify-between gap-4 shrink-0"
          style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-sidebar)' }}
        >
          <div className="min-w-0">
            <h2 className="m-0 text-sm font-semibold tracking-tight truncate">{title}</h2>
            {subtitle && (
              <p className="m-0 mt-0.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                {subtitle}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="btn-ghost p-1 rounded-md cursor-pointer border-0 shrink-0"
            aria-label="Close drawer"
          >
            <X size={16} />
          </button>
        </div>
        <div className="p-5 overflow-y-auto flex-1">{children}</div>
      </div>
    </div>
  );
}

export function ShuntMark({ size = 26 }: { size?: number }) {
  return (
    <div
      style={{
        width: size,
        height: size,
        borderRadius: 7,
        background: 'var(--text-primary)',
        color: 'var(--bg)',
        display: 'grid',
        placeItems: 'center',
        fontWeight: 700,
        fontSize: Math.round(size * 0.52),
        letterSpacing: '-0.04em',
        flexShrink: 0,
      }}
      className="mono select-none"
    >
      S
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
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div
          className="inline-flex rounded-lg p-0.5 text-xs"
          style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border)' }}
        >
          {(
            [
              { id: 'binary', label: 'shunt binary' },
              { id: 'cargo', label: 'cargo run (repo)' },
              { id: 'docker', label: 'Docker' },
            ] as const
          ).map((m) => (
            <button
              key={m.id}
              type="button"
              onClick={() => setMode(m.id)}
              className="px-2.5 py-1 rounded-md border-0 cursor-pointer font-medium transition-colors"
              style={{
                background: mode === m.id ? 'var(--bg-elevated)' : 'transparent',
                color: mode === m.id ? 'var(--text-primary)' : 'var(--text-muted)',
              }}
            >
              {m.label}
            </button>
          ))}
        </div>
        <CopyButton label="Copy command" text={cmd} />
      </div>
      <div className="relative">
        <div
          className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] rounded-t-lg"
          style={{
            background: 'var(--bg-subtle)',
            border: '1px solid var(--border)',
            borderBottom: 'none',
            color: 'var(--text-muted)',
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
