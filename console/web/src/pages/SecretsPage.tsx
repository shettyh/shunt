import React, { useEffect, useState } from 'react';
import { KeyRound, Lock, Plus, RotateCw, Shield, Trash2 } from 'lucide-react';
import {
  api,
  ApiProblemError,
  Cluster,
  formatRelativeTime,
  Organization,
  SecretDeliveryMode,
  SecretMeta,
  SecretScopeType,
  slugify,
} from '../lib/api';
import { CopyButton, Modal, useToast } from '../components/ui';

export function SecretsPage({
  org,
  cluster,
}: {
  org: Organization;
  cluster: Cluster;
}) {
  const toast = useToast();
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [loading, setLoading] = useState(true);

  const [modalOpen, setModalOpen] = useState(false);
  const [rotatingSecret, setRotatingSecret] = useState<SecretMeta | null>(null);
  const [slug, setSlug] = useState('');
  const [description, setDescription] = useState('');
  const [scopeType, setScopeType] = useState<SecretScopeType>('org');
  const [deliveryMode, setDeliveryMode] = useState<SecretDeliveryMode>('vault');
  const [secretValue, setSecretValue] = useState('');
  const [envVarName, setEnvVarName] = useState('');
  const [saving, setSaving] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      setSecrets(await api.listSecrets(org.slug));
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : 'Failed to load secrets', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [org.slug]);

  const openCreate = () => {
    setRotatingSecret(null);
    setSlug('');
    setDescription('');
    setScopeType('org');
    setDeliveryMode('vault');
    setSecretValue('');
    setEnvVarName('');
    setModalOpen(true);
  };

  const openRotate = (s: SecretMeta) => {
    setRotatingSecret(s);
    setSlug(s.slug);
    setDescription(s.description);
    setScopeType(s.scope_type);
    setDeliveryMode(s.delivery_mode);
    setSecretValue('');
    setEnvVarName(s.env_var_name || '');
    setModalOpen(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const targetSlug = rotatingSecret ? rotatingSecret.slug : slugify(slug);
      await api.upsertSecret(
        org.slug,
        targetSlug,
        {
          description: description.trim(),
          scope_type: scopeType,
          scope_id: scopeType === 'cluster' ? cluster.id : org.id,
          delivery_mode: deliveryMode,
          value: deliveryMode === 'vault' ? secretValue : undefined,
          env_var_name: deliveryMode === 'env_ref' ? envVarName.trim() : undefined,
        },
        rotatingSecret?.etag
      );
      toast.push(
        rotatingSecret
          ? `Rotated secret "${targetSlug}" to v${rotatingSecret.key_version + 1}`
          : `Stored secret "${targetSlug}" securely`
      );
      setModalOpen(false);
      load();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (s: SecretMeta) => {
    if (!window.confirm(`Permanently delete secret "${s.slug}"?`)) return;
    try {
      await api.deleteSecret(org.slug, s.slug);
      toast.push(`Deleted secret "${s.slug}"`);
      load();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="m-0 text-xl font-semibold tracking-tight">Secrets Vault</h1>
          <p className="m-0 mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
            Write-only envelope-encrypted storage (per-secret 256-bit AES-256-GCM DEK) or zero-trust <code>env:VAR</code> passthrough. Plaintext secrets are never returned by the API or shown in diffs/exports.
          </p>
        </div>
        <button type="button" className="btn btn-primary" onClick={openCreate}>
          <Plus size={14} />
          <span>Add Secret</span>
        </button>
      </div>

      {/* Mode Explainer */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 text-xs">
        <div className="surface-subtle p-4 flex items-start gap-3">
          <Lock size={16} style={{ color: 'var(--accent)' }} className="mt-0.5 shrink-0" />
          <div>
            <div className="font-semibold">Managed Vault (<code>vault</code>)</div>
            <p className="m-0 mt-0.5" style={{ color: 'var(--text-muted)' }}>
              Encrypted with a unique DEK + AAD tenant binding. Decrypted only when authenticated <code>shunt</code> nodes fetch signed Channel 1 bundles over TLS.
            </p>
          </div>
        </div>
        <div className="surface-subtle p-4 flex items-start gap-3">
          <Shield size={16} style={{ color: 'var(--ok)' }} className="mt-0.5 shrink-0" />
          <div>
            <div className="font-semibold">Zero-Trust Env Ref (<code>env_ref</code>)</div>
            <p className="m-0 mt-0.5" style={{ color: 'var(--text-muted)' }}>
              Compiles directly to <code>env:VAR_NAME</code> so sensitive provider credentials never touch the control-plane database at all.
            </p>
          </div>
        </div>
      </div>

      {/* Secrets Table */}
      <div className="surface overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
            Loading vault entries…
          </div>
        ) : secrets.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <KeyRound size={26} style={{ color: 'var(--text-muted)' }} className="mx-auto" />
            <div className="font-medium text-sm">No secrets stored in {org.name} yet</div>
            <p className="m-0 text-xs max-w-md mx-auto" style={{ color: 'var(--text-muted)' }}>
              Store upstream provider API keys or TLS private keys once, then reference them safely as <code>secret:&lt;slug&gt;</code> in your cluster topology.
            </p>
            <button type="button" className="btn btn-primary" onClick={openCreate}>
              <Plus size={14} />
              <span>Create First Secret</span>
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="swiss-table text-xs">
              <thead>
                <tr>
                  <th>Slug</th>
                  <th>Reference</th>
                  <th>Delivery Mode</th>
                  <th>Scope</th>
                  <th>Version</th>
                  <th>Updated</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {secrets.map((s) => {
                  const refStr =
                    s.delivery_mode === 'env_ref' && s.env_var_name
                      ? `env:${s.env_var_name}`
                      : `secret:${s.slug}`;
                  return (
                    <tr key={s.id}>
                      <td>
                        <div className="mono font-semibold text-sm">{s.slug}</div>
                        {s.description && (
                          <div className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
                            {s.description}
                          </div>
                        )}
                      </td>
                      <td>
                        <div className="inline-flex items-center gap-1.5">
                          <code className="text-xs px-1.5 py-0.5 rounded" style={{ background: 'var(--bg-code)' }}>
                            {refStr}
                          </code>
                          <CopyButton text={refStr} label="" />
                        </div>
                      </td>
                      <td>
                        {s.delivery_mode === 'vault' ? (
                          <span className="badge badge-accent">AES-256-GCM Vault</span>
                        ) : (
                          <span className="badge badge-ok">Env Passthrough</span>
                        )}
                      </td>
                      <td>
                        <span className="badge mono">{s.scope_type}</span>
                      </td>
                      <td className="mono">v{s.key_version}</td>
                      <td style={{ color: 'var(--text-muted)' }}>{formatRelativeTime(s.updated_at)}</td>
                      <td className="text-right">
                        <div className="inline-flex items-center gap-1">
                          <button
                            type="button"
                            className="btn text-xs py-1 px-2"
                            onClick={() => openRotate(s)}
                          >
                            <RotateCw size={12} />
                            <span>Rotate</span>
                          </button>
                          <button
                            type="button"
                            className="btn-ghost p-1.5 rounded cursor-pointer border-0"
                            style={{ color: 'var(--danger)' }}
                            onClick={() => handleDelete(s)}
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create / Rotate Secret Modal */}
      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title={rotatingSecret ? `Rotate secret "${rotatingSecret.slug}"` : 'Add Secret to Vault'}
        subtitle="Write-only: secret values are envelope-encrypted immediately and cannot be read back via UI or API."
      >
        <form onSubmit={handleSave} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium mb-1">Slug</label>
              <input
                className="input-base mono text-xs"
                value={slug}
                disabled={Boolean(rotatingSecret)}
                onChange={(e) => setSlug(slugify(e.target.value))}
                placeholder="openai-prod-key"
                required
              />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1">Scope</label>
              <select
                className="input-base"
                value={scopeType}
                disabled={Boolean(rotatingSecret)}
                onChange={(e) => setScopeType(e.target.value as SecretScopeType)}
              >
                <option value="org">Organization ({org.slug})</option>
                <option value="cluster">Cluster ({cluster.slug})</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium mb-1">Description</label>
            <input
              className="input-base"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Primary production OpenAI API key"
            />
          </div>

          <div>
            <label className="block text-xs font-medium mb-1.5">Delivery Mode</label>
            <div className="grid grid-cols-2 gap-2.5">
              <button
                type="button"
                onClick={() => setDeliveryMode('vault')}
                className="p-3 rounded-lg text-left cursor-pointer"
                style={{
                  background: deliveryMode === 'vault' ? 'var(--accent-soft)' : 'var(--bg)',
                  border: `1px solid ${deliveryMode === 'vault' ? 'var(--accent)' : 'var(--border)'}`,
                }}
              >
                <div className="font-semibold text-xs">Managed Vault</div>
                <div className="text-[11px] mt-0.5" style={{ color: 'var(--text-muted)' }}>
                  Encrypted at rest (AES-256-GCM)
                </div>
              </button>
              <button
                type="button"
                onClick={() => setDeliveryMode('env_ref')}
                className="p-3 rounded-lg text-left cursor-pointer"
                style={{
                  background: deliveryMode === 'env_ref' ? 'var(--accent-soft)' : 'var(--bg)',
                  border: `1px solid ${deliveryMode === 'env_ref' ? 'var(--accent)' : 'var(--border)'}`,
                }}
              >
                <div className="font-semibold text-xs">Env Passthrough</div>
                <div className="text-[11px] mt-0.5" style={{ color: 'var(--text-muted)' }}>
                  Resolves from node env var
                </div>
              </button>
            </div>
          </div>

          {deliveryMode === 'vault' ? (
            <div>
              <label className="block text-xs font-medium mb-1">
                Secret Value (write-only)
              </label>
              <textarea
                className="input-base mono text-xs min-h-[84px]"
                value={secretValue}
                onChange={(e) => setSecretValue(e.target.value)}
                placeholder="sk-... or PEM private key"
                required
              />
            </div>
          ) : (
            <div>
              <label className="block text-xs font-medium mb-1">
                Data-Plane Environment Variable Name
              </label>
              <input
                className="input-base mono text-xs"
                value={envVarName}
                onChange={(e) => setEnvVarName(e.target.value)}
                placeholder="OPENAI_API_KEY"
                required
              />
            </div>
          )}

          <div className="flex justify-end gap-2 pt-1">
            <button type="button" className="btn" onClick={() => setModalOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              <Lock size={14} />
              <span>{saving ? 'Encrypting…' : rotatingSecret ? 'Rotate Secret' : 'Store Secret'}</span>
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
