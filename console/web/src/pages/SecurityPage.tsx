import React, { useEffect, useState } from 'react';
import {
  FileSearch,
  Globe,
  Key,
  KeyRound,
  Lock,
  Plus,
  RotateCw,
  ShieldCheck,
  Trash2,
  UserPlus,
  Users,
} from 'lucide-react';
import {
  AdminAuditEntry,
  api,
  ApiProblemError,
  ApiTokenMeta,
  AuditChainVerification,
  Cluster,
  CreatedApiToken,
  formatRelativeTime,
  MeResponse,
  OidcProviderRecord,
  Organization,
  Role,
  SecretDeliveryMode,
  SecretMeta,
  SecretScopeType,
  slugify,
  UserWithRoles,
} from '../lib/api';
import { ClusterHeaderContext, PageHeader } from '../components/PageHeader';
import {
  CopyButton,
  Drawer,
  EmptyState,
  Modal,
  SearchField,
  SegmentedTabs,
  StatusIndicator,
  TagPill,
  useToast,
} from '../components/ui';

type SecurityTab = 'secrets' | 'users' | 'tokens' | 'oidc' | 'audit';

export function SecurityPage({
  org,
  cluster,
  me,
  headerCtx,
}: {
  org: Organization;
  cluster: Cluster;
  me: MeResponse;
  headerCtx: ClusterHeaderContext;
}) {
  const toast = useToast();
  const [tab, setTab] = useState<SecurityTab>('secrets');
  const [search, setSearch] = useState('');

  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [users, setUsers] = useState<UserWithRoles[]>([]);
  const [tokens, setTokens] = useState<ApiTokenMeta[]>([]);
  const [oidc, setOidc] = useState<OidcProviderRecord[]>([]);
  const [audit, setAudit] = useState<AdminAuditEntry[]>([]);
  const [verification, setVerification] = useState<AuditChainVerification | null>(null);
  const [verifying, setVerifying] = useState(false);

  // Secret Drawer
  const [secOpen, setSecOpen] = useState(false);
  const [rotating, setRotating] = useState<SecretMeta | null>(null);
  const [sSlug, setSSlug] = useState('');
  const [sDesc, setSDesc] = useState('');
  const [sScope, setSScope] = useState<SecretScopeType>('org');
  const [sMode, setSMode] = useState<SecretDeliveryMode>('vault');
  const [sVal, setSVal] = useState('');
  const [sEnv, setSEnv] = useState('');

  // User Modal
  const [userOpen, setUserOpen] = useState(false);
  const [uName, setUName] = useState('');
  const [uEmail, setUEmail] = useState('');
  const [uPass, setUPass] = useState('');
  const [uRole, setURole] = useState<Role>('cluster_operator');

  // API Token Modal
  const [tokOpen, setTokOpen] = useState(false);
  const [tName, setTName] = useState('');
  const [tRole, setTRole] = useState<Role>('cluster_operator');
  const [tDays, setTDays] = useState('90');
  const [createdToken, setCreatedToken] = useState<CreatedApiToken | null>(null);

  // OIDC Modal
  const [oidcOpen, setOidcOpen] = useState(false);
  const [oSlug, setOSlug] = useState('okta');
  const [oName, setOName] = useState('Okta SSO');
  const [oIssuer, setOIssuer] = useState('');
  const [oClientId, setOClientId] = useState('');
  const [oGroupClaim, setOGroupClaim] = useState('groups');

  const loadAll = async () => {
    const [s, u, t, o, a] = await Promise.all([
      api.listSecrets(org.slug).catch(() => []),
      api.listUsers(org.slug).catch(() => []),
      api.listApiTokens(org.slug).catch(() => []),
      api.listOidcProviders(org.slug).catch(() => []),
      api.listAdminAudit(100).catch(() => []),
    ]);
    setSecrets(s);
    setUsers(u);
    setTokens(t);
    setOidc(o);
    setAudit(a);
  };

  useEffect(() => {
    loadAll();
  }, [org.slug]);

  const handleSaveSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const slug = rotating ? rotating.slug : slugify(sSlug);
      await api.upsertSecret(
        org.slug,
        slug,
        {
          description: sDesc.trim(),
          scope_type: sScope,
          scope_id: sScope === 'cluster' ? cluster.id : org.id,
          delivery_mode: sMode,
          value: sMode === 'vault' ? sVal : undefined,
          env_var_name: sMode === 'env_ref' ? sEnv.trim() : undefined,
        },
        rotating?.etag
      );
      toast.push(rotating ? `Rotated secret "${slug}"` : `Stored secret "${slug}"`);
      setSecOpen(false);
      loadAll();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

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
      setUserOpen(false);
      setUName('');
      setUEmail('');
      setUPass('');
      loadAll();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await api.createApiToken(org.slug, {
        name: tName.trim(),
        role: tRole,
        expires_in_days: Number(tDays) > 0 ? Number(tDays) : null,
      });
      setCreatedToken(res);
      toast.push('Service API token minted');
      loadAll();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handleSaveOidc = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.upsertOidcProvider(org.slug, slugify(oSlug), {
        display_name: oName.trim(),
        issuer_url: oIssuer.trim(),
        client_id: oClientId.trim(),
        group_claim: oGroupClaim.trim() || 'groups',
        enabled: true,
      });
      toast.push(`Saved OIDC provider "${oName}"`);
      setOidcOpen(false);
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
        res.valid ? `Hash chain verified (${res.checked_entries} rows)` : 'Tamper detected!',
        res.valid ? 'success' : 'error'
      );
    } finally {
      setVerifying(false);
    }
  };

  const primaryAction =
    tab === 'secrets' ? (
      <button
        type="button"
        className="btn btn-primary h-8"
        onClick={() => {
          setRotating(null);
          setSSlug('');
          setSDesc('');
          setSScope('org');
          setSMode('vault');
          setSVal('');
          setSEnv('');
          setSecOpen(true);
        }}
      >
        <Plus size={14} />
        <span>Add secret</span>
      </button>
    ) : tab === 'users' ? (
      <button type="button" className="btn btn-primary h-8" onClick={() => setUserOpen(true)}>
        <UserPlus size={14} />
        <span>Add user</span>
      </button>
    ) : tab === 'tokens' ? (
      <button
        type="button"
        className="btn btn-primary h-8"
        onClick={() => {
          setCreatedToken(null);
          setTName('');
          setTokOpen(true);
        }}
      >
        <Plus size={14} />
        <span>New token</span>
      </button>
    ) : tab === 'oidc' ? (
      <button type="button" className="btn btn-primary h-8" onClick={() => setOidcOpen(true)}>
        <Plus size={14} />
        <span>Add SSO</span>
      </button>
    ) : (
      <button
        type="button"
        className="btn btn-primary h-8"
        onClick={handleVerifyAudit}
        disabled={verifying}
      >
        <ShieldCheck size={14} />
        <span>{verifying ? 'Verifying…' : 'Verify chain'}</span>
      </button>
    );

  const q = search.trim().toLowerCase();

  return (
    <div>
      <PageHeader
        title="Security"
        ctx={headerCtx}
        primaryAction={primaryAction}
        controlsLeft={
          <SegmentedTabs
            value={tab}
            onChange={setTab}
            items={[
              { id: 'secrets', label: 'Secrets Vault', count: secrets.length },
              { id: 'users', label: 'Team', count: users.length },
              { id: 'tokens', label: 'API Tokens', count: tokens.length },
              { id: 'oidc', label: 'SSO', count: oidc.length },
              { id: 'audit', label: 'Audit Log', count: audit.length },
            ]}
          />
        }
        controlsRight={<SearchField value={search} onChange={setSearch} placeholder="Filter" />}
      />

      {/* SECRETS */}
      {tab === 'secrets' && (
        <div>
          {secrets.filter((s) => !q || s.slug.includes(q)).length === 0 ? (
            <EmptyState
              icon={<KeyRound size={17} />}
              title="No secrets stored yet"
              description="Secrets added during AI Provider or MCP Server setup automatically appear here, encrypted at rest with AES-256-GCM."
            />
          ) : (
            secrets
              .filter((s) => !q || s.slug.includes(q) || s.description.toLowerCase().includes(q))
              .map((s) => {
                const ref =
                  s.delivery_mode === 'env_ref' && s.env_var_name
                    ? `env:${s.env_var_name}`
                    : `secret:${s.slug}`;
                return (
                  <div key={s.id} className="row-item">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="icon-tile">
                        <Lock size={14} />
                      </div>
                      <span className="mono text-[13.5px] font-semibold shrink-0">{s.slug}</span>
                      <TagPill mono dot={s.delivery_mode === 'vault' ? 'brand' : 'ok'}>
                        {ref}
                      </TagPill>
                      {s.description && (
                        <span className="hidden lg:inline text-[12.5px] truncate" style={{ color: 'var(--ink-muted)' }}>
                          {s.description}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2.5 shrink-0">
                      <span className="mono text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                        v{s.key_version}
                      </span>
                      <CopyButton text={ref} label="" />
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => {
                          setRotating(s);
                          setSSlug(s.slug);
                          setSDesc(s.description);
                          setSScope(s.scope_type);
                          setSMode(s.delivery_mode);
                          setSVal('');
                          setSEnv(s.env_var_name || '');
                          setSecOpen(true);
                        }}
                      >
                        <RotateCw size={12} />
                        <span>Rotate</span>
                      </button>
                      <button
                        type="button"
                        className="btn-ghost p-1.5"
                        style={{ color: 'var(--ink-muted)' }}
                        onClick={async () => {
                          if (!window.confirm(`Delete secret "${s.slug}"?`)) return;
                          await api.deleteSecret(org.slug, s.slug);
                          toast.push(`Deleted secret "${s.slug}"`);
                          loadAll();
                        }}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                );
              })
          )}
        </div>
      )}

      {/* TEAM & RBAC */}
      {tab === 'users' && (
        <div>
          {users
            .filter(
              (u) =>
                !q ||
                u.user.display_name.toLowerCase().includes(q) ||
                u.user.email.toLowerCase().includes(q)
            )
            .map((u) => (
              <div key={u.user.id} className="row-item">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="icon-tile">
                    <Users size={14} />
                  </div>
                  <span className="text-[14px] font-medium truncate">{u.user.display_name}</span>
                  <span className="mono text-[12.5px] truncate" style={{ color: 'var(--ink-muted)' }}>
                    {u.user.email}
                  </span>
                  {u.bindings.map((b) => (
                    <TagPill key={b.id} dot="brand" mono>
                      {b.role}
                    </TagPill>
                  ))}
                </div>
                <span className="text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                  {formatRelativeTime(u.user.created_at)}
                </span>
              </div>
            ))}
        </div>
      )}

      {/* API TOKENS */}
      {tab === 'tokens' && (
        <div>
          {tokens.length === 0 ? (
            <EmptyState
              icon={<Key size={17} />}
              title="No service API tokens"
              description="Mint scoped bearer tokens (shunt_ct_…) for CI/CD pipelines and Terraform automation."
            />
          ) : (
            tokens.map((t) => (
              <div key={t.id} className="row-item">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="icon-tile">
                    <Key size={14} />
                  </div>
                  <span className="text-[14px] font-medium">{t.name}</span>
                  <TagPill mono>{t.prefix}</TagPill>
                  <TagPill dot="brand" mono>
                    {t.role}
                  </TagPill>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <StatusIndicator
                    tone={t.revoked_at ? 'danger' : 'ok'}
                    label={t.revoked_at ? 'Revoked' : 'Active'}
                  />
                  {!t.revoked_at && (
                    <button
                      type="button"
                      className="btn btn-sm btn-danger"
                      onClick={async () => {
                        await api.revokeApiToken(org.slug, t.id);
                        toast.push('API token revoked');
                        loadAll();
                      }}
                    >
                      Revoke
                    </button>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* OIDC / SSO */}
      {tab === 'oidc' && (
        <div>
          {oidc.length === 0 ? (
            <EmptyState
              icon={<Globe size={17} />}
              title="No SSO providers configured"
              description="Connect Okta, Google Workspace, Entra ID, GitHub, or Keycloak using OIDC Authorization Code + PKCE."
            />
          ) : (
            oidc.map((p) => (
              <div key={p.id} className="row-item">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="icon-tile">
                    <Globe size={14} />
                  </div>
                  <span className="text-[14px] font-medium">{p.display_name}</span>
                  <span className="mono text-[12px] truncate" style={{ color: 'var(--ink-muted)' }}>
                    {p.issuer_url}
                  </span>
                </div>
                <button
                  type="button"
                  className="btn-ghost p-1.5"
                  style={{ color: 'var(--ink-muted)' }}
                  onClick={async () => {
                    await api.deleteOidcProvider(org.slug, p.slug);
                    toast.push(`Deleted ${p.slug}`);
                    loadAll();
                  }}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))
          )}
        </div>
      )}

      {/* AUDIT LOG */}
      {tab === 'audit' && (
        <div>
          {verification && (
            <div
              className="px-6 py-3 flex items-center gap-2 text-[13px]"
              style={{
                background: verification.valid ? 'var(--ok-soft)' : 'var(--danger-soft)',
                borderBottom: '1px solid var(--border-row)',
                color: verification.valid ? 'var(--ok)' : 'var(--danger)',
              }}
            >
              <ShieldCheck size={15} />
              <span>
                {verification.valid
                  ? `Cryptographic hash chain verified across ${verification.checked_entries} entries.`
                  : `Tampering detected at seq #${verification.first_tampered_seq}`}
              </span>
            </div>
          )}
          {audit
            .filter(
              (a) =>
                !q ||
                a.action.toLowerCase().includes(q) ||
                a.resource_id.toLowerCase().includes(q) ||
                a.actor_id.toLowerCase().includes(q)
            )
            .map((a) => (
              <div key={a.seq} className="row-item">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="icon-tile">
                    <FileSearch size={14} />
                  </div>
                  <span className="mono text-[12px] w-10 shrink-0 tabular" style={{ color: 'var(--ink-muted)' }}>
                    #{a.seq}
                  </span>
                  <span className="text-[13.5px] font-medium truncate">
                    {a.resource_type}/{a.resource_id}
                  </span>
                  <TagPill dot="brand" mono>
                    {a.action}
                  </TagPill>
                </div>
                <div className="flex items-center gap-4 shrink-0 text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                  <span className="hidden md:inline truncate max-w-[160px]">{a.actor_id}</span>
                  <span className="hidden xl:inline mono">{a.entry_hash.slice(0, 12)}…</span>
                  <span className="tabular w-16 text-right">{formatRelativeTime(a.ts)}</span>
                </div>
              </div>
            ))}
        </div>
      )}

      {/* SECRET DRAWER */}
      <Drawer
        open={secOpen}
        onClose={() => setSecOpen(false)}
        title={rotating ? `Rotate "${rotating.slug}"` : 'Store Secret'}
        subtitle="Write-only AES-256-GCM envelope vault or zero-trust node env passthrough."
        widthClass="max-w-lg"
      >
        <form onSubmit={handleSaveSecret} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Slug</label>
              <input
                className="input-base mono"
                value={sSlug}
                disabled={Boolean(rotating)}
                onChange={(e) => setSSlug(slugify(e.target.value))}
                placeholder="openai-prod-key"
                required
              />
            </div>
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Scope</label>
              <select
                className="input-base"
                value={sScope}
                disabled={Boolean(rotating)}
                onChange={(e) => setSScope(e.target.value as SecretScopeType)}
              >
                <option value="org">Org ({org.slug})</option>
                <option value="cluster">Cluster ({cluster.slug})</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-[12.5px] font-medium mb-1">Description</label>
            <input className="input-base" value={sDesc} onChange={(e) => setSDesc(e.target.value)} />
          </div>
          <div className="flex items-center justify-between">
            <span className="text-[12.5px] font-medium">Mode</span>
            <SegmentedTabs
              value={sMode}
              onChange={setSMode}
              items={[
                { id: 'vault', label: 'Vault (AES-256-GCM)' },
                { id: 'env_ref', label: 'Node Env Ref' },
              ]}
            />
          </div>
          {sMode === 'vault' ? (
            <textarea
              className="input-base mono text-[13px] min-h-[100px]"
              value={sVal}
              onChange={(e) => setSVal(e.target.value)}
              placeholder="Paste secret value (write-only)…"
              required
            />
          ) : (
            <input
              className="input-base mono"
              value={sEnv}
              onChange={(e) => setSEnv(e.target.value)}
              placeholder="OPENAI_API_KEY"
              required
            />
          )}
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" className="btn" onClick={() => setSecOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              {rotating ? 'Rotate Secret' : 'Store Secret'}
            </button>
          </div>
        </form>
      </Drawer>

      {/* ADD USER MODAL */}
      <Modal open={userOpen} onClose={() => setUserOpen(false)} title={`Add member to ${org.name}`}>
        <form onSubmit={handleCreateUser} className="space-y-3.5">
          <div>
            <label className="block text-[12.5px] font-medium mb-1">Full Name</label>
            <input className="input-base" value={uName} onChange={(e) => setUName(e.target.value)} required />
          </div>
          <div>
            <label className="block text-[12.5px] font-medium mb-1">Email</label>
            <input type="email" className="input-base" value={uEmail} onChange={(e) => setUEmail(e.target.value)} required />
          </div>
          <div>
            <label className="block text-[12.5px] font-medium mb-1">Password (8+ chars)</label>
            <input type="password" className="input-base" value={uPass} onChange={(e) => setUPass(e.target.value)} minLength={8} required />
          </div>
          <div>
            <label className="block text-[12.5px] font-medium mb-1">Role</label>
            <select className="input-base" value={uRole} onChange={(e) => setURole(e.target.value as Role)}>
              {me.roles_catalog.map((r) => (
                <option key={r.role} value={r.role}>
                  {r.role} — {r.description}
                </option>
              ))}
            </select>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" className="btn" onClick={() => setUserOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              Create User
            </button>
          </div>
        </form>
      </Modal>

      {/* API TOKEN MODAL */}
      <Modal
        open={tokOpen}
        onClose={() => {
          setCreatedToken(null);
          setTokOpen(false);
        }}
        title="Mint Service API Token"
      >
        {!createdToken ? (
          <form onSubmit={handleCreateToken} className="space-y-3.5">
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Name</label>
              <input className="input-base" value={tName} onChange={(e) => setTName(e.target.value)} placeholder="terraform-ci" required />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[12.5px] font-medium mb-1">Role</label>
                <select className="input-base" value={tRole} onChange={(e) => setTRole(e.target.value as Role)}>
                  {me.roles_catalog.map((r) => (
                    <option key={r.role} value={r.role}>
                      {r.role}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-[12.5px] font-medium mb-1">Expires (days)</label>
                <input type="number" className="input-base mono" value={tDays} onChange={(e) => setTDays(e.target.value)} />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button type="button" className="btn" onClick={() => setTokOpen(false)}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary">
                Mint Token
              </button>
            </div>
          </form>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <code className="code-block flex-1 py-2 break-all">{createdToken.plaintext_token}</code>
              <CopyButton text={createdToken.plaintext_token} label="Copy" />
            </div>
            <div className="flex justify-end">
              <button type="button" className="btn btn-primary" onClick={() => setTokOpen(false)}>
                Done
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* OIDC MODAL */}
      <Modal open={oidcOpen} onClose={() => setOidcOpen(false)} title="Configure OIDC / SSO Provider">
        <form onSubmit={handleSaveOidc} className="space-y-3.5">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Slug</label>
              <input className="input-base mono" value={oSlug} onChange={(e) => setOSlug(slugify(e.target.value))} required />
            </div>
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Display Name</label>
              <input className="input-base" value={oName} onChange={(e) => setOName(e.target.value)} required />
            </div>
          </div>
          <div>
            <label className="block text-[12.5px] font-medium mb-1">Issuer Discovery URL</label>
            <input className="input-base mono" value={oIssuer} onChange={(e) => setOIssuer(e.target.value)} required />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Client ID</label>
              <input className="input-base mono" value={oClientId} onChange={(e) => setOClientId(e.target.value)} required />
            </div>
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Group Claim</label>
              <input className="input-base mono" value={oGroupClaim} onChange={(e) => setOGroupClaim(e.target.value)} />
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" className="btn" onClick={() => setOidcOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              Save SSO Provider
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
