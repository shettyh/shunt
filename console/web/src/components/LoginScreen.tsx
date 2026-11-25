import React, { useState } from 'react';
import { Loader2, LogIn, ShieldCheck } from 'lucide-react';
import { api, ApiProblemError, SystemStatus } from '../lib/api';
import { ShuntMark } from './ui';

export function LoginScreen({
  status,
  onSuccess,
}: {
  status: SystemStatus;
  onSuccess: () => void;
}) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await api.login(email, password);
      onSuccess();
    } catch (err) {
      setError(err instanceof ApiProblemError ? err.message : 'Sign-in failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="min-h-screen flex items-center justify-center p-6"
      style={{ background: 'var(--bg-subtle)' }}
    >
      <div className="surface w-full max-w-sm p-7 shadow-sm">
        <div className="flex items-center gap-3 mb-6">
          <ShuntMark size={30} />
          <div>
            <div className="font-semibold text-base tracking-tight">Shunt Console</div>
            <div className="text-xs mono" style={{ color: 'var(--text-muted)' }}>
              v{status.version} · {status.db_kind}
            </div>
          </div>
        </div>

        <h1 className="m-0 text-lg font-semibold tracking-tight">Sign in</h1>
        <p className="m-0 mt-1 mb-5 text-xs" style={{ color: 'var(--text-muted)' }}>
          Manage your HTTP API, AI, and MCP gateway fleets.
        </p>

        {error && (
          <div
            className="mb-4 p-3 rounded-lg text-xs"
            style={{
              background: 'var(--danger-soft)',
              border: '1px solid var(--danger-border)',
              color: 'var(--danger)',
            }}
          >
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3.5">
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Email
            </label>
            <input
              className="input-base"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@company.com"
              required
              autoFocus
            />
          </div>

          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Password
            </label>
            <input
              className="input-base"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
            />
          </div>

          <button type="submit" className="btn btn-primary w-full mt-1" disabled={loading}>
            {loading ? <Loader2 size={15} className="animate-spin" /> : <LogIn size={15} />}
            <span>{loading ? 'Signing in…' : 'Sign in'}</span>
          </button>
        </form>

        {status.oidc_providers.length > 0 && (
          <div className="mt-5 pt-4" style={{ borderTop: '1px solid var(--border)' }}>
            <div className="text-xs mb-2.5 text-center" style={{ color: 'var(--text-muted)' }}>
              Or continue with SSO
            </div>
            <div className="space-y-2">
              {status.oidc_providers.map((p) => (
                <a
                  key={p.slug}
                  href={`/api/v1/auth/oidc/${encodeURIComponent(p.slug)}/start`}
                  className="btn w-full no-underline"
                >
                  <ShieldCheck size={14} />
                  <span>{p.display_name}</span>
                </a>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
