import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Key,
  Plus,
  Shield,
  ShieldCheck,
  Trash2,
  UserPlus,
  Users,
  Globe,
  FileSearch,
} from 'lucide-react';
import {
  AdminAuditEntry,
  api,
  ApiProblemError,
  ApiTokenMeta,
  AuditChainVerification,
  CreatedApiToken,
  formatRelativeTime,
  MeResponse,
  OidcProviderRecord,
  Organization,
  Role,
  slugify,
  UserWithRoles,
} from '../lib/api';
import { CopyButton, Modal, useToast } from '../components/ui';

export function AccessAuditPage({
  org,
  me,
}: {
  org: Organization;
  me: MeResponse;
}) {
  const toast = useToast();
  const [tab, setTab] = useState<'users' | 'tokens' | 'oidc' | 'audit'>('users');

  const [users, setUsers] = useState<UserWithRoles[]>([]);
  const [tokens, setTokens] = useState<ApiTokenMeta[]>([]);
  const [oidcProviders, setOidcProviders] = useState<OidcProviderRecord[]>([]);
  const [audit, setAudit] = useState<AdminAuditEntry[]>([]);
  const [verification, setVerification] = useState<AuditChainVerification | null>(null);
  const [verifying, setVerifying] = useState(false);

  // Create User Modal
  const [userModal, setUserModal] = useState(false);
  const [uEmail, setUEmail] = useState('');
  const [uName, setUName] = useState('');
  const [uPass, setUPass] = useState('');
  const [uRole, setURole] = useState<Role>('cluster_operator');

  // Create API Token Modal
  const [tokenModal, setTokenModal] = useState(false);
  const [tName, setTName] = useState('');
  const [tRole, setTRole] = useState<Role>('cluster_operator');
  const [tDays, setTDays] = useState('90');
  const [createdApiToken, setCreatedApiToken] = useState<CreatedApiToken | null>(null);

  // OIDC Modal
  const [oidcModal, setOidcModal] = useState(false);
  const [oSlug, setOSlug] = useState('okta');
  const [oDisplayName, setODisplayName] = useState('Okta SSO');
  const [oIssuer, setOIssuer] = useState('');
  const [oClientId, setOClientId] = useState('');
  const [oGroupClaim, setOGroupClaim] = useState('groups');

  const loadAll = async () => {
    const [u, t, o, a] = await Promise.all([
      api.listUsers(org.slug).catch(() => []),
      api.listApiTokens(org.slug).catch(() => []),
      api.listOidcProviders(org.slug).catch(() => []),
      api.listAdminAudit(100).catch(() => []),
    ]);
    setUsers(u);
    setTokens(t);
    setOidcProviders(o);
    setAudit(a);
  };

  useEffect(() => {
    loadAll();
  }, [org.slug]);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createUser(org.slug, {
        email: uEmail.trim(),
        display_name: uName.trim(),
        password: uPass,
        role: uRole,
      });
      toast.push(`Created user ${uEmail.trim()}`);
      setUserModal(false);
      setUEmail('');
      setUName('');
      setUPass('');
      loadAll();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handleCreateApiToken = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const created = await api.createApiToken(org.slug, {
        name: tName.trim(),
        role: tRole,
        expires_in_days: Number(tDays) > 0 ? Number(tDays) : null,
      });
      setCreatedApiToken(created);
      toast.push('Service API token created — copy it once now');
      loadAll();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handleRevokeApiToken = async (id: string) => {
    try {
      await api.revokeApiToken(org.slug, id);
      toast.push('API token revoked');
      loadAll();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handleSaveOidc = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.upsertOidcProvider(org.slug, slugify(oSlug), {
        display_name: oDisplayName.trim(),
        issuer_url: oIssuer.trim(),
        client_id: oClientId.trim(),
        group_claim: oGroupClaim.trim() || 'groups',
        enabled: true,
      });
      toast.push(`Saved OIDC provider "${oDisplayName}"`);
      setOidcModal(false);
      loadAll();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handleVerifyAudit = async () => {
    setVerifying(true);
    try {
      const res = await api.verifyAdminAudit();
      setVerification(res);
      toast.push(
        res.valid ? `Hash chain verified (${res.checked_entries} entries)` : `Audit tamper detected!`,
        res.valid ? 'success' : 'error'
      );
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="min-w-0">
          <h1 className="m-0 text-[22px] font-semibold tracking-tight">Access &amp; Audit</h1>
          <p className="m-0 mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
            Manage team users, RBAC roles, service API tokens, OIDC/SSO providers, and the tamper-evident audit chain.
          </p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          {tab === 'users' && (
            <button type="button" className="btn btn-primary" onClick={() => setUserModal(true)}>
              <UserPlus size={15} />
              <span>Add User</span>
            </button>
          )}
          {tab === 'tokens' && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => {
                setCreatedApiToken(null);
                setTName('');
                setTokenModal(true);
              }}
            >
              <Plus size={15} />
              <span>Create API Token</span>
            </button>
          )}
          {tab === 'oidc' && (
            <button type="button" className="btn btn-primary" onClick={() => setOidcModal(true)}>
              <Plus size={15} />
              <span>Add OIDC Provider</span>
            </button>
          )}
          {tab === 'audit' && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleVerifyAudit}
              disabled={verifying}
            >
              <ShieldCheck size={15} />
              <span>{verifying ? 'Verifying…' : 'Verify Hash Chain'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Clean Tab Bar */}
      <div className="flex items-center gap-1 overflow-x-auto" style={{ borderBottom: '1px solid var(--border)' }}>
        {[
          { id: 'users' as const, label: `Users & RBAC (${users.length})`, icon: <Users size={15} /> },
          { id: 'tokens' as const, label: `Service API Tokens (${tokens.length})`, icon: <Key size={15} /> },
          { id: 'oidc' as const, label: `OIDC / SSO (${oidcProviders.length})`, icon: <Globe size={15} /> },
          { id: 'audit' as const, label: `Admin Audit Log (${audit.length})`, icon: <FileSearch size={15} /> },
        ].map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className="flex items-center gap-2 px-3.5 py-2.5 text-sm font-medium bg-transparent border-0 cursor-pointer whitespace-nowrap transition-colors"
            style={{
              color: tab === t.id ? 'var(--text-primary)' : 'var(--text-muted)',
              borderBottom: `2px solid ${tab === t.id ? 'var(--accent)' : 'transparent'}`,
              marginBottom: -1,
            }}
          >
            {t.icon}
            <span>{t.label}</span>
          </button>
        ))}
      </div>

      {/* Tab 1: Users & RBAC */}
      {tab === 'users' && (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
          <div className="surface overflow-hidden xl:col-span-8">
            <div className="overflow-x-auto">
              <table className="swiss-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Auth</th>
                    <th>Role Bindings</th>
                    <th>Joined</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.user.id}>
                      <td className="whitespace-nowrap">
                        <div className="font-semibold">{u.user.display_name}</div>
                        <div className="mono text-xs" style={{ color: 'var(--text-muted)' }}>
                          {u.user.email}
                        </div>
                      </td>
                      <td className="whitespace-nowrap">
                        <span className="badge mono">{u.user.auth_provider}</span>
                      </td>
                      <td>
                        <div className="flex flex-wrap gap-1.5">
                          {u.bindings.map((b) => (
                            <span key={b.id} className="badge badge-accent mono">
                              {b.role}
                              {b.cluster_id ? ` (${b.cluster_id.slice(-6)})` : ''}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                        {formatRelativeTime(u.user.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="surface overflow-hidden xl:col-span-4">
            <div
              className="px-4 py-3 flex items-center gap-2 text-sm font-semibold"
              style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-canvas)' }}
            >
              <Shield size={15} style={{ color: 'var(--text-muted)' }} />
              <span>Built-In RBAC Roles</span>
            </div>
            <div className="p-3 space-y-2">
              {me.roles_catalog.map((r) => (
                <div
                  key={r.role}
                  className="px-3 py-2.5 rounded-lg"
                  style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-light)' }}
                >
                  <div className="mono font-semibold text-sm">{r.role}</div>
                  <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    {r.description}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Service API Tokens */}
      {tab === 'tokens' && (
        <div className="surface overflow-hidden">
          {tokens.length === 0 ? (
            <div className="p-12 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
              No service API tokens minted yet. Create a scoped <code>shunt_ct_…</code> bearer token for Terraform or CI/CD.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="swiss-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Prefix</th>
                    <th>Role</th>
                    <th>Last Used</th>
                    <th>Status</th>
                    <th className="text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {tokens.map((t) => (
                    <tr key={t.id}>
                      <td className="font-semibold whitespace-nowrap">{t.name}</td>
                      <td className="mono whitespace-nowrap">{t.prefix}</td>
                      <td className="whitespace-nowrap">
                        <span className="badge badge-accent mono">{t.role}</span>
                      </td>
                      <td className="text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                        {t.last_used_at ? formatRelativeTime(t.last_used_at) : 'never'}
                      </td>
                      <td className="whitespace-nowrap">
                        {t.revoked_at ? (
                          <span className="badge badge-danger">Revoked</span>
                        ) : (
                          <span className="badge badge-ok">Active</span>
                        )}
                      </td>
                      <td className="text-right whitespace-nowrap">
                        {!t.revoked_at && (
                          <button
                            type="button"
                            className="btn btn-sm btn-danger"
                            onClick={() => handleRevokeApiToken(t.id)}
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: OIDC Providers */}
      {tab === 'oidc' && (
        <div className="surface overflow-hidden">
          {oidcProviders.length === 0 ? (
            <div className="p-12 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
              No OIDC/SSO providers configured (Okta, Google Workspace, Entra ID, GitHub, Keycloak). Local authentication is active.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="swiss-table">
                <thead>
                  <tr>
                    <th>Provider</th>
                    <th>Issuer URL</th>
                    <th>Client ID</th>
                    <th>Group Claim</th>
                    <th className="text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {oidcProviders.map((p) => (
                    <tr key={p.id}>
                      <td className="whitespace-nowrap">
                        <div className="font-semibold">{p.display_name}</div>
                        <div className="mono text-xs" style={{ color: 'var(--text-muted)' }}>
                          {p.slug}
                        </div>
                      </td>
                      <td className="mono text-[13px]">{p.issuer_url}</td>
                      <td className="mono text-[13px]">{p.client_id}</td>
                      <td className="mono whitespace-nowrap">{p.group_claim}</td>
                      <td className="text-right whitespace-nowrap">
                        <button
                          type="button"
                          className="btn-ghost p-1.5 rounded-md cursor-pointer border-0"
                          style={{ color: 'var(--danger)' }}
                          onClick={async () => {
                            await api.deleteOidcProvider(org.slug, p.slug);
                            toast.push(`Deleted OIDC provider ${p.slug}`);
                            loadAll();
                          }}
                        >
                          <Trash2 size={15} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 4: Hash-Chained Admin Audit Log */}
      {tab === 'audit' && (
        <div className="space-y-4">
          {verification && (
            <div
              className="surface px-4 py-3 flex items-center gap-3 text-sm"
              style={{
                background: verification.valid ? 'var(--ok-soft)' : 'var(--danger-soft)',
                borderColor: verification.valid ? 'var(--ok-border)' : 'var(--danger-border)',
                color: verification.valid ? 'var(--ok)' : 'var(--danger)',
              }}
            >
              {verification.valid ? <CheckCircle2 size={17} /> : <AlertTriangle size={17} />}
              <span>
                <strong>
                  {verification.valid
                    ? 'Cryptographic Hash Chain Intact'
                    : `Tampering Detected at seq #${verification.first_tampered_seq}`}
                </strong>
                {verification.message ? ` — ${verification.message}` : ''}
              </span>
            </div>
          )}

          <div className="surface overflow-hidden">
            <div className="overflow-x-auto">
              <table className="swiss-table">
                <thead>
                  <tr>
                    <th>Seq</th>
                    <th>Action</th>
                    <th>Resource</th>
                    <th>Actor</th>
                    <th>Entry Hash</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.map((a) => (
                    <tr key={a.seq}>
                      <td className="mono font-semibold whitespace-nowrap">#{a.seq}</td>
                      <td className="whitespace-nowrap">
                        <span className="badge mono">{a.action}</span>
                      </td>
                      <td className="mono text-[13px] whitespace-nowrap">
                        {a.resource_type}/{a.resource_id}
                      </td>
                      <td className="whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>
                        {a.actor_id}
                      </td>
                      <td className="mono text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                        {a.entry_hash.slice(0, 14)}…
                      </td>
                      <td className="text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                        {formatRelativeTime(a.ts)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Add User Modal */}
      <Modal
        open={userModal}
        onClose={() => setUserModal(false)}
        title={`Add user to ${org.name}`}
      >
        <form onSubmit={handleCreateUser} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1.5">Full Name</label>
            <input className="input-base" value={uName} onChange={(e) => setUName(e.target.value)} required />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1.5">Email</label>
            <input
              className="input-base"
              type="email"
              value={uEmail}
              onChange={(e) => setUEmail(e.target.value)}
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1.5">Initial Password (8+ chars)</label>
            <input
              className="input-base"
              type="password"
              value={uPass}
              onChange={(e) => setUPass(e.target.value)}
              minLength={8}
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1.5">RBAC Role</label>
            <select
              className="input-base"
              value={uRole}
              onChange={(e) => setURole(e.target.value as Role)}
            >
              {me.roles_catalog.map((r) => (
                <option key={r.role} value={r.role}>
                  {r.role} — {r.description}
                </option>
              ))}
            </select>
          </div>
          <div className="flex justify-end gap-2.5 pt-2">
            <button type="button" className="btn" onClick={() => setUserModal(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              Create User
            </button>
          </div>
        </form>
      </Modal>

      {/* Create Service API Token Modal */}
      <Modal
        open={tokenModal}
        onClose={() => {
          setCreatedApiToken(null);
          setTokenModal(false);
        }}
        title="Create Service API Token"
        subtitle="For CI/CD pipelines, Terraform, and programmatic control-plane automation."
      >
        {!createdApiToken ? (
          <form onSubmit={handleCreateApiToken} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1.5">Token Name</label>
              <input
                className="input-base"
                value={tName}
                onChange={(e) => setTName(e.target.value)}
                placeholder="terraform-prod-ci"
                required
              />
            </div>
            <div className="grid grid-cols-2 gap-3.5">
              <div>
                <label className="block text-sm font-medium mb-1.5">Role</label>
                <select
                  className="input-base"
                  value={tRole}
                  onChange={(e) => setTRole(e.target.value as Role)}
                >
                  {me.roles_catalog.map((r) => (
                    <option key={r.role} value={r.role}>
                      {r.role}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1.5">Expires (days, 0 = never)</label>
                <input
                  className="input-base mono"
                  type="number"
                  value={tDays}
                  onChange={(e) => setTDays(e.target.value)}
                />
              </div>
            </div>
            <div className="flex justify-end gap-2.5 pt-2">
              <button type="button" className="btn" onClick={() => setTokenModal(false)}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary">
                Mint Token
              </button>
            </div>
          </form>
        ) : (
          <div className="space-y-4">
            <div
              className="p-3.5 rounded-lg text-sm"
              style={{
                background: 'var(--ok-soft)',
                border: '1px solid var(--ok-border)',
                color: 'var(--ok)',
              }}
            >
              Copy this API token now. It is stored strictly as a SHA-256 hash and will never be shown again.
            </div>
            <div className="flex items-center gap-2">
              <code className="code-block flex-1 py-2 break-all">{createdApiToken.plaintext_token}</code>
              <CopyButton text={createdApiToken.plaintext_token} label="Copy" />
            </div>
            <div>
              <div className="text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>
                Example usage
              </div>
              <pre className="code-block m-0 text-xs">
                {`curl -H "Authorization: Bearer ${createdApiToken.plaintext_token}" \\\n  ${window.location.origin}/api/v1/orgs/${org.slug}/clusters`}
              </pre>
            </div>
            <div className="flex justify-end">
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => {
                  setCreatedApiToken(null);
                  setTokenModal(false);
                }}
              >
                Done
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* OIDC Provider Modal */}
      <Modal
        open={oidcModal}
        onClose={() => setOidcModal(false)}
        title="Configure OIDC / SSO Provider"
        subtitle="Authorization Code + PKCE (S256)"
      >
        <form onSubmit={handleSaveOidc} className="space-y-4">
          <div className="grid grid-cols-2 gap-3.5">
            <div>
              <label className="block text-sm font-medium mb-1.5">Slug</label>
              <input
                className="input-base mono"
                value={oSlug}
                onChange={(e) => setOSlug(slugify(e.target.value))}
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1.5">Display Name</label>
              <input
                className="input-base"
                value={oDisplayName}
                onChange={(e) => setODisplayName(e.target.value)}
                required
              />
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1.5">Issuer Discovery Base URL</label>
            <input
              className="input-base mono"
              value={oIssuer}
              onChange={(e) => setOIssuer(e.target.value)}
              placeholder="https://acme.okta.com/oauth2/default"
              required
            />
          </div>
          <div className="grid grid-cols-2 gap-3.5">
            <div>
              <label className="block text-sm font-medium mb-1.5">Client ID</label>
              <input
                className="input-base mono"
                value={oClientId}
                onChange={(e) => setOClientId(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1.5">Groups Claim</label>
              <input
                className="input-base mono"
                value={oGroupClaim}
                onChange={(e) => setOGroupClaim(e.target.value)}
              />
            </div>
          </div>
          <div className="flex justify-end gap-2.5 pt-2">
            <button type="button" className="btn" onClick={() => setOidcModal(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              Save Provider
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
