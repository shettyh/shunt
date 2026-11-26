import React, { useEffect, useState } from 'react';
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Loader2,
  Radio,
  Server,
  Shield,
  Sparkles,
  Upload,
} from 'lucide-react';
import {
  api,
  ApiProblemError,
  InitialBootstrapResult,
  NodeRecord,
  slugify,
} from '../lib/api';
import { ConnectCommandBox, ShuntMark, TagPill, useToast } from './ui';

export function SetupWizard({ onComplete }: { onComplete: () => void }) {
  const toast = useToast();
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [adminName, setAdminName] = useState('Platform Admin');
  const [adminEmail, setAdminEmail] = useState('');
  const [adminPassword, setAdminPassword] = useState('');
  const [orgName, setOrgName] = useState('Acme Engineering');
  const [orgSlug, setOrgSlug] = useState('acme-eng');
  const [orgSlugTouched, setOrgSlugTouched] = useState(false);

  const [clusterName, setClusterName] = useState('Production US');
  const [clusterSlug, setClusterSlug] = useState('prod-us');
  const [clusterSlugTouched, setClusterSlugTouched] = useState(false);
  const [environment, setEnvironment] = useState('production');
  const [configSource, setConfigSource] = useState<'default' | 'import'>('default');
  const [importToml, setImportToml] = useState('');
  const [autoPublish, setAutoPublish] = useState(true);

  const [bootResult, setBootResult] = useState<InitialBootstrapResult | null>(null);
  const [nodeLabels, setNodeLabels] = useState('ring=stable,region=us-east-1');
  const [connectedNodes, setConnectedNodes] = useState<NodeRecord[]>([]);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setImportToml(String(reader.result || ''));
      setConfigSource('import');
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
        import_toml: configSource === 'import' ? importToml : undefined,
        auto_publish: autoPublish,
      });
      setBootResult(res);
      setStep(3);
      toast.push('Control plane initialized');
    } catch (err) {
      setError(err instanceof ApiProblemError ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  useEffect(() => {
    if (step !== 3 || !bootResult) return;
    let active = true;
    const poll = async () => {
      try {
        const nodes = await api.listNodes(bootResult.cluster.slug);
        if (active) setConnectedNodes(nodes);
      } catch {
        // ignore transient errors
      }
    };
    poll();
    const id = window.setInterval(poll, 2000);
    return () => {
      active = false;
      window.clearInterval(id);
    };
  }, [step, bootResult]);

  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center p-6"
      style={{ background: 'var(--shell)' }}
    >
      <div className="w-full max-w-2xl">
        <div className="flex items-center justify-between mb-5 px-1">
          <div className="flex items-center gap-2.5">
            <ShuntMark size={28} />
            <span className="font-semibold text-[15px] tracking-tight">Shunt Console</span>
          </div>

          <div className="flex items-center gap-1.5 text-[12px] tabular">
            {[
              { n: 1, label: 'Admin' },
              { n: 2, label: 'Cluster' },
              { n: 3, label: 'Connect Node' },
            ].map((s) => (
              <div
                key={s.n}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-full"
                style={{
                  background: step === s.n ? 'var(--ink)' : 'var(--sheet)',
                  color: step === s.n ? 'var(--sheet)' : 'var(--ink-muted)',
                  border: '1px solid var(--border)',
                  fontWeight: step === s.n ? 600 : 500,
                }}
              >
                {step > s.n ? <Check size={12} style={{ color: 'var(--ok)' }} /> : <span>{s.n}</span>}
                <span>{s.label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="app-sheet p-7 sm:p-8">
          {error && (
            <div
              className="mb-5 px-3.5 py-2.5 rounded-lg text-[13px]"
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
                <h1 className="m-0 text-[20px] font-semibold tracking-[-0.02em]">
                  Create administrator account
                </h1>
                <p className="m-0 mt-1 text-[13px]" style={{ color: 'var(--ink-muted)' }}>
                  Runs cleanly on local SQLite out of the box — no external services required.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                <div>
                  <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                    Full Name
                  </label>
                  <input className="input-base" value={adminName} onChange={(e) => setAdminName(e.target.value)} autoFocus />
                </div>
                <div>
                  <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                    Admin Email
                  </label>
                  <input type="email" className="input-base" value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} placeholder="admin@company.com" />
                </div>
              </div>

              <div>
                <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                  Password{' '}
                  <span style={{ color: adminPassword.length >= 8 ? 'var(--ok)' : 'var(--ink-muted)' }}>
                    ({adminPassword.length >= 8 ? 'Argon2id ready' : '8+ characters'})
                  </span>
                </label>
                <input type="password" className="input-base" value={adminPassword} onChange={(e) => setAdminPassword(e.target.value)} placeholder="••••••••••••" />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 pt-3" style={{ borderTop: '1px solid var(--border-row)' }}>
                <div>
                  <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                    Organization
                  </label>
                  <input
                    className="input-base"
                    value={orgName}
                    onChange={(e) => {
                      setOrgName(e.target.value);
                      if (!orgSlugTouched) setOrgSlug(slugify(e.target.value) || 'default');
                    }}
                  />
                </div>
                <div>
                  <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                    Slug
                  </label>
                  <input
                    className="input-base mono text-[13px]"
                    value={orgSlug}
                    onChange={(e) => {
                      setOrgSlugTouched(true);
                      setOrgSlug(slugify(e.target.value));
                    }}
                  />
                </div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <span className="flex items-center gap-1.5 text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                  <Shield size={13} />
                  <span>Argon2id · Ed25519 releases · AES-256-GCM vault</span>
                </span>
                <button type="button" className="btn btn-primary" disabled={!canAdvanceStep1} onClick={() => setStep(2)}>
                  <span>Continue</span>
                  <ArrowRight size={14} />
                </button>
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-5">
              <div>
                <h1 className="m-0 text-[20px] font-semibold tracking-[-0.02em]">
                  Create your first cluster
                </h1>
                <p className="m-0 mt-1 text-[13px]" style={{ color: 'var(--ink-muted)' }}>
                  Every cluster runs AI models, MCP servers, and HTTP APIs side by side on the same fleet.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="block text-[12px] font-medium mb-1">Cluster Name</label>
                  <input
                    className="input-base"
                    value={clusterName}
                    onChange={(e) => {
                      setClusterName(e.target.value);
                      if (!clusterSlugTouched) setClusterSlug(slugify(e.target.value) || 'prod');
                    }}
                  />
                </div>
                <div>
                  <label className="block text-[12px] font-medium mb-1">Slug</label>
                  <input
                    className="input-base mono text-[13px]"
                    value={clusterSlug}
                    onChange={(e) => {
                      setClusterSlugTouched(true);
                      setClusterSlug(slugify(e.target.value));
                    }}
                  />
                </div>
                <div>
                  <label className="block text-[12px] font-medium mb-1">Environment</label>
                  <select className="input-base" value={environment} onChange={(e) => setEnvironment(e.target.value)}>
                    <option value="production">production</option>
                    <option value="staging">staging</option>
                    <option value="development">development</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <button
                  type="button"
                  onClick={() => setConfigSource('default')}
                  className="p-4 rounded-xl text-left cursor-pointer transition-colors"
                  style={{
                    background: configSource === 'default' ? 'var(--brand-soft)' : 'var(--sheet)',
                    border: `1px solid ${configSource === 'default' ? 'var(--brand-border)' : 'var(--border)'}`,
                  }}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-[13.5px]">Start Fresh</span>
                    <TagPill dot={configSource === 'default' ? 'brand' : 'neutral'}>Recommended</TagPill>
                  </div>
                  <p className="m-0 mt-1 text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                    Clean gateway ready to add OpenAI, Anthropic, Bedrock, MCP servers, or HTTP routes visually.
                  </p>
                </button>
                <button
                  type="button"
                  onClick={() => setConfigSource('import')}
                  className="p-4 rounded-xl text-left cursor-pointer transition-colors"
                  style={{
                    background: configSource === 'import' ? 'var(--brand-soft)' : 'var(--sheet)',
                    border: `1px solid ${configSource === 'import' ? 'var(--brand-border)' : 'var(--border)'}`,
                  }}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-[13.5px]">Import shunt.toml</span>
                    <TagPill>Migrate</TagPill>
                  </div>
                  <p className="m-0 mt-1 text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                    Upload an existing shunt.toml and manage its providers &amp; routes in Console.
                  </p>
                </button>
              </div>

              {configSource === 'import' && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[12px] font-medium" style={{ color: 'var(--ink-secondary)' }}>
                      shunt.toml
                    </span>
                    <label className="btn btn-sm cursor-pointer">
                      <Upload size={12} />
                      <span>Upload file</span>
                      <input type="file" accept=".toml" className="hidden" onChange={handleFileUpload} />
                    </label>
                  </div>
                  <textarea
                    className="input-base mono text-[12.5px] min-h-[120px]"
                    value={importToml}
                    onChange={(e) => setImportToml(e.target.value)}
                    placeholder="[server]\nlisten = &quot;0.0.0.0:8080&quot;"
                  />
                </div>
              )}

              <label className="flex items-center gap-2 text-[13px] cursor-pointer">
                <input type="checkbox" checked={autoPublish} onChange={(e) => setAutoPublish(e.target.checked)} />
                <span>Validate and publish Release v1 immediately</span>
              </label>

              <div className="flex items-center justify-between pt-2">
                <button type="button" className="btn" onClick={() => setStep(1)}>
                  <ArrowLeft size={14} />
                  <span>Back</span>
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={submitting || !clusterSlug.trim() || (configSource === 'import' && !importToml.trim())}
                  onClick={handleBootstrap}
                >
                  {submitting ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} />}
                  <span>{submitting ? 'Initializing…' : 'Initialize Console'}</span>
                </button>
              </div>
            </div>
          )}

          {step === 3 && bootResult && (
            <div className="space-y-5">
              <div>
                <TagPill dot="ok">Control plane ready</TagPill>
                <h1 className="m-0 mt-2 text-[20px] font-semibold tracking-[-0.02em]">
                  Connect your first node (optional)
                </h1>
                <p className="m-0 mt-1 text-[13px]" style={{ color: 'var(--ink-muted)' }}>
                  You can connect a stateless <code>shunt</code> node now, or jump straight into Console to add your AI providers first.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[12px]" style={{ color: 'var(--ink-muted)' }}>Labels:</span>
                <input
                  className="input-base mono text-[12.5px] max-w-xs py-1"
                  value={nodeLabels}
                  onChange={(e) => setNodeLabels(e.target.value)}
                />
              </div>

              <ConnectCommandBox
                controlPlaneUrl={window.location.origin}
                clusterSlug={bootResult.cluster.slug}
                token={bootResult.bootstrap_token.plaintext_token}
                labels={nodeLabels}
              />

              <div className="card-subtle px-4 py-3 flex items-center justify-between gap-3">
                {connectedNodes.length > 0 ? (
                  <div className="flex items-center gap-2.5 text-[13px]" style={{ color: 'var(--ok)' }}>
                    <Check size={16} />
                    <span className="font-medium">
                      {connectedNodes.length} node connected ({connectedNodes[0].name})
                    </span>
                  </div>
                ) : (
                  <div className="flex items-center gap-2.5 text-[13px]" style={{ color: 'var(--ink-muted)' }}>
                    <Radio size={15} className="animate-pulse" style={{ color: 'var(--brand)' }} />
                    <span>Listening for first node enrollment…</span>
                  </div>
                )}
                <Server size={15} style={{ color: 'var(--ink-muted)' }} />
              </div>

              <div className="flex justify-end pt-1">
                <button type="button" className="btn btn-primary" onClick={onComplete}>
                  <span>{connectedNodes.length > 0 ? 'Open Shunt Console' : 'Continue to Console'}</span>
                  <ArrowRight size={14} />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
