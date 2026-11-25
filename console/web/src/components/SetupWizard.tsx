import React, { useEffect, useState } from 'react';
import {
  ArrowRight,
  ArrowLeft,
  CheckCircle2,
  Server,
  Shield,
  Sparkles,
  Upload,
  Loader2,
  Radio,
} from 'lucide-react';
import {
  api,
  ApiProblemError,
  InitialBootstrapResult,
  NodeRecord,
  slugify,
} from '../lib/api';
import { ConnectCommandBox, ShuntMark, useToast } from './ui';

const PRESETS = [
  {
    id: 'http-api',
    title: 'HTTP API Gateway',
    desc: 'Includes request-id, Prometheus metrics, a starter upstream, and an /api prefix route.',
    tag: 'Recommended',
  },
  {
    id: 'ai-gateway',
    title: 'AI Gateway Starter',
    desc: 'Pre-wired /v1 route targeting OpenAI upstream, ready for shunt-ai routing & virtual keys.',
    tag: 'AI',
  },
  {
    id: 'empty',
    title: 'Minimal Empty Cluster',
    desc: 'Clean [server] + [admin] listener skeleton. Add routes or import shunt.toml later.',
    tag: 'Minimal',
  },
  {
    id: 'import',
    title: 'Import existing shunt.toml',
    desc: 'Paste or upload your existing shunt.toml to migrate into Console-managed revisions.',
    tag: 'Migrate',
  },
];

export function SetupWizard({ onComplete }: { onComplete: () => void }) {
  const toast = useToast();
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Step 1 fields
  const [adminName, setAdminName] = useState('Platform Admin');
  const [adminEmail, setAdminEmail] = useState('');
  const [adminPassword, setAdminPassword] = useState('');
  const [orgName, setOrgName] = useState('Acme Engineering');
  const [orgSlug, setOrgSlug] = useState('acme-eng');
  const [orgSlugTouched, setOrgSlugTouched] = useState(false);

  // Step 2 fields
  const [clusterName, setClusterName] = useState('Production US');
  const [clusterSlug, setClusterSlug] = useState('prod-us');
  const [clusterSlugTouched, setClusterSlugTouched] = useState(false);
  const [environment, setEnvironment] = useState('production');
  const [preset, setPreset] = useState('http-api');
  const [importToml, setImportToml] = useState('');
  const [autoPublish, setAutoPublish] = useState(true);

  // Step 3 state (after bootstrap succeeds)
  const [bootResult, setBootResult] = useState<InitialBootstrapResult | null>(null);
  const [nodeLabels, setNodeLabels] = useState('ring=stable,region=us-east-1');
  const [connectedNodes, setConnectedNodes] = useState<NodeRecord[]>([]);

  const handleOrgNameChange = (v: string) => {
    setOrgName(v);
    if (!orgSlugTouched) setOrgSlug(slugify(v) || 'default');
  };

  const handleClusterNameChange = (v: string) => {
    setClusterName(v);
    if (!clusterSlugTouched) setClusterSlug(slugify(v) || 'prod');
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setImportToml(String(reader.result || ''));
      setPreset('import');
    };
    reader.readAsText(file);
  };

  const canAdvanceStep1 =
    adminName.trim().length > 0 &&
    adminEmail.includes('@') &&
    adminPassword.length >= 8 &&
    orgSlug.trim().length > 0;

  const handleBootstrap = async () => {
    setError(null);
    setSubmitting(true);
    try {
      const res = await api.bootstrap({
        admin_email: adminEmail.trim(),
        admin_name: adminName.trim(),
        admin_password: adminPassword,
        org_slug: orgSlug.trim(),
        org_name: orgName.trim() || orgSlug.trim(),
        cluster_slug: clusterSlug.trim(),
        cluster_name: clusterName.trim() || clusterSlug.trim(),
        environment,
        starter_preset: preset === 'import' ? 'empty' : preset,
        import_toml: preset === 'import' ? importToml : undefined,
        auto_publish: autoPublish,
      });
      setBootResult(res);
      setStep(3);
      toast.push('Control plane initialized and Revision #1 ready!');
    } catch (err) {
      const msg = err instanceof ApiProblemError ? err.message : String(err);
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  // Poll for first node connection during Step 3!
  useEffect(() => {
    if (step !== 3 || !bootResult) return;
    let active = true;
    const poll = async () => {
      try {
        const nodes = await api.listNodes(bootResult.cluster.slug);
        if (active) setConnectedNodes(nodes);
      } catch {
        // Ignore transient errors during polling
      }
    };
    poll();
    const id = window.setInterval(poll, 2000);
    return () => {
      active = false;
      window.clearInterval(id);
    };
  }, [step, bootResult]);

  const controlPlaneUrl = window.location.origin;

  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center p-6"
      style={{ background: 'var(--bg-subtle)' }}
    >
      <div className="w-full max-w-2xl">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <ShuntMark size={30} />
            <div>
              <div className="font-semibold text-base tracking-tight">Shunt Console</div>
              <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
                First-Run Control Plane Setup
              </div>
            </div>
          </div>

          {/* Stepper pills */}
          <div className="flex items-center gap-1.5 text-xs tabular">
            {[
              { n: 1, label: 'Admin' },
              { n: 2, label: 'Cluster' },
              { n: 3, label: 'Connect Node' },
            ].map((s) => (
              <div
                key={s.n}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-full"
                style={{
                  background: step === s.n ? 'var(--text-primary)' : 'var(--bg-elevated)',
                  color: step === s.n ? 'var(--bg)' : 'var(--text-muted)',
                  border: '1px solid var(--border)',
                  fontWeight: step === s.n ? 600 : 500,
                }}
              >
                {step > s.n ? <CheckCircle2 size={12} style={{ color: 'var(--ok)' }} /> : <span>{s.n}</span>}
                <span>{s.label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="surface p-6 sm:p-8 shadow-sm">
          {error && (
            <div
              className="mb-5 p-3.5 rounded-lg text-sm"
              style={{
                background: 'var(--danger-soft)',
                border: '1px solid var(--danger-border)',
                color: 'var(--danger)',
              }}
            >
              {error}
            </div>
          )}

          {step === 1 && (
            <div className="space-y-5">
              <div>
                <h1 className="m-0 text-xl font-semibold tracking-tight">
                  Create your administrator account
                </h1>
                <p className="m-0 mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                  Everything runs locally on SQLite out of the box—no external services required.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                    Full Name
                  </label>
                  <input
                    className="input-base"
                    value={adminName}
                    onChange={(e) => setAdminName(e.target.value)}
                    placeholder="Alice Chen"
                    autoFocus
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                    Admin Email
                  </label>
                  <input
                    className="input-base"
                    type="email"
                    value={adminEmail}
                    onChange={(e) => setAdminEmail(e.target.value)}
                    placeholder="alice@company.com"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                  Password{' '}
                  <span style={{ color: adminPassword.length >= 8 ? 'var(--ok)' : 'var(--text-muted)' }}>
                    ({adminPassword.length >= 8 ? 'Strong (Argon2id)' : 'minimum 8 characters'})
                  </span>
                </label>
                <input
                  className="input-base"
                  type="password"
                  value={adminPassword}
                  onChange={(e) => setAdminPassword(e.target.value)}
                  placeholder="••••••••••••"
                />
              </div>

              <div className="pt-2" style={{ borderTop: '1px solid var(--border-light)' }}>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                      Organization Name
                    </label>
                    <input
                      className="input-base"
                      value={orgName}
                      onChange={(e) => handleOrgNameChange(e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                      Organization Slug <span className="mono text-[11px]">(/api/v1/orgs/…)</span>
                    </label>
                    <input
                      className="input-base mono text-xs"
                      value={orgSlug}
                      onChange={(e) => {
                        setOrgSlugTouched(true);
                        setOrgSlug(slugify(e.target.value));
                      }}
                    />
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-muted)' }}>
                  <Shield size={14} />
                  <span>Password hashed with Argon2id · Audit log hash-chained</span>
                </div>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={!canAdvanceStep1}
                  onClick={() => setStep(2)}
                >
                  <span>Continue</span>
                  <ArrowRight size={15} />
                </button>
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-5">
              <div>
                <h1 className="m-0 text-xl font-semibold tracking-tight">
                  Configure your first gateway cluster
                </h1>
                <p className="m-0 mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                  Pick a starter topology or import an existing <code className="text-xs">shunt.toml</code>.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                    Cluster Name
                  </label>
                  <input
                    className="input-base"
                    value={clusterName}
                    onChange={(e) => handleClusterNameChange(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                    Cluster Slug
                  </label>
                  <input
                    className="input-base mono text-xs"
                    value={clusterSlug}
                    onChange={(e) => {
                      setClusterSlugTouched(true);
                      setClusterSlug(slugify(e.target.value));
                    }}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                    Environment
                  </label>
                  <select
                    className="input-base"
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value)}
                  >
                    <option value="production">production</option>
                    <option value="staging">staging</option>
                    <option value="development">development</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
                  Starter Topology
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {PRESETS.map((p) => {
                    const selected = preset === p.id;
                    return (
                      <button
                        key={p.id}
                        type="button"
                        onClick={() => setPreset(p.id)}
                        className="text-left p-3.5 rounded-lg cursor-pointer transition-colors"
                        style={{
                          background: selected ? 'var(--accent-soft)' : 'var(--bg)',
                          border: `1px solid ${selected ? 'var(--accent)' : 'var(--border)'}`,
                        }}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>
                            {p.title}
                          </span>
                          <span className={selected ? 'badge badge-accent' : 'badge'}>{p.tag}</span>
                        </div>
                        <p className="m-0 mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                          {p.desc}
                        </p>
                      </button>
                    );
                  })}
                </div>
              </div>

              {preset === 'import' && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
                      Paste or upload shunt.toml
                    </label>
                    <label className="btn text-xs py-1 px-2.5 cursor-pointer">
                      <Upload size={13} />
                      <span>Choose file</span>
                      <input type="file" accept=".toml" className="hidden" onChange={handleFileUpload} />
                    </label>
                  </div>
                  <textarea
                    className="input-base mono text-xs min-h-[130px]"
                    value={importToml}
                    onChange={(e) => setImportToml(e.target.value)}
                    placeholder={`[server]\nlisten = "0.0.0.0:8080"\n\n[[upstreams]]\nname = "api"\nendpoints = ["http://127.0.0.1:3000"]`}
                  />
                </div>
              )}

              <label className="flex items-center gap-2.5 text-sm cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={autoPublish}
                  onChange={(e) => setAutoPublish(e.target.checked)}
                />
                <span>
                  Validate with <code className="text-xs">shunt verify</code> and publish Revision #1 immediately
                </span>
              </label>

              <div className="flex items-center justify-between pt-2">
                <button type="button" className="btn" onClick={() => setStep(1)}>
                  <ArrowLeft size={15} />
                  <span>Back</span>
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={submitting || !clusterSlug.trim() || (preset === 'import' && !importToml.trim())}
                  onClick={handleBootstrap}
                >
                  {submitting ? <Loader2 size={15} className="animate-spin" /> : <Sparkles size={15} />}
                  <span>{submitting ? 'Initializing…' : 'Initialize Control Plane'}</span>
                </button>
              </div>
            </div>
          )}

          {step === 3 && bootResult && (
            <div className="space-y-5">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="badge badge-ok mb-2">
                    <CheckCircle2 size={12} />
                    <span>Control plane ready</span>
                  </div>
                  <h1 className="m-0 text-xl font-semibold tracking-tight">
                    Connect your first <code className="text-lg">shunt</code> node
                  </h1>
                  <p className="m-0 mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    Nodes connect outbound-only over HTTP/HTTPS—no local <code className="text-xs">shunt.toml</code> or open inbound ports required.
                  </p>
                </div>
              </div>

              {/* Labels quick picker */}
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-medium" style={{ color: 'var(--text-muted)' }}>
                  Node labels:
                </span>
                <input
                  className="input-base mono text-xs max-w-xs py-1.5"
                  value={nodeLabels}
                  onChange={(e) => setNodeLabels(e.target.value)}
                  placeholder="ring=stable,region=us-east-1"
                />
                <button
                  type="button"
                  className="btn text-xs py-1 px-2"
                  onClick={() => setNodeLabels('ring=canary,region=us-east-1')}
                >
                  Canary ring
                </button>
                <button
                  type="button"
                  className="btn text-xs py-1 px-2"
                  onClick={() => setNodeLabels('ring=stable,region=us-east-1')}
                >
                  Stable ring
                </button>
              </div>

              {/* Command block */}
              <div>
                <ConnectCommandBox
                  controlPlaneUrl={controlPlaneUrl}
                  clusterSlug={bootResult.cluster.slug}
                  token={bootResult.bootstrap_token.plaintext_token}
                  labels={nodeLabels}
                />
                <p className="m-0 mt-1.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                  Bootstrap token <code className="text-[11px]">{bootResult.bootstrap_token.token.prefix}</code> is shown once here. You can mint additional tokens anytime in <strong>Fleet &amp; Nodes</strong>.
                </p>
              </div>

              {/* Live node detection panel */}
              <div
                className="p-4 rounded-lg flex items-center justify-between gap-4"
                style={{
                  background: connectedNodes.length > 0 ? 'var(--ok-soft)' : 'var(--bg-subtle)',
                  border: `1px solid ${connectedNodes.length > 0 ? 'var(--ok-border)' : 'var(--border)'}`,
                }}
              >
                {connectedNodes.length > 0 ? (
                  <div className="flex items-center gap-3">
                    <CheckCircle2 size={20} style={{ color: 'var(--ok)' }} />
                    <div>
                      <div className="font-semibold text-sm" style={{ color: 'var(--ok)' }}>
                        {connectedNodes.length} node{connectedNodes.length > 1 ? 's' : ''} connected!
                      </div>
                      <div className="text-xs mono mt-0.5" style={{ color: 'var(--text-secondary)' }}>
                        {connectedNodes[0].name} · rev #{connectedNodes[0].active_revision} · {connectedNodes[0].status}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-3">
                    <Radio size={18} className="animate-pulse" style={{ color: 'var(--accent)' }} />
                    <div>
                      <div className="font-medium text-sm">Waiting for first node enrollment…</div>
                      <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
                        This screen updates automatically the instant your node connects.
                      </div>
                    </div>
                  </div>
                )}
                <Server size={16} style={{ color: 'var(--text-muted)' }} />
              </div>

              <div className="flex items-center justify-end gap-2 pt-1">
                <button type="button" className="btn btn-primary" onClick={onComplete}>
                  <span>{connectedNodes.length > 0 ? 'Open Console' : 'Skip for now & Open Console'}</span>
                  <ArrowRight size={15} />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
