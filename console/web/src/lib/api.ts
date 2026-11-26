export type Role =
  | 'super_admin'
  | 'cluster_operator'
  | 'org_admin'
  | 'team_lead'
  | 'developer'
  | 'auditor';

export interface PublicOidcProvider {
  slug: string;
  display_name: string;
  org_slug: string;
}

export interface SystemStatus {
  initialized: boolean;
  version: string;
  db_kind: string;
  public_key_b64: string;
  ephemeral_dev_key: boolean;
  oidc_providers: PublicOidcProvider[];
}

export interface UserSummary {
  id: string;
  email: string;
  display_name: string;
  auth_provider: string;
  active: boolean;
  created_at: string;
}

export interface RoleBinding {
  id: string;
  user_id: string;
  org_id?: string | null;
  cluster_id?: string | null;
  role: Role;
  created_at: string;
}

export interface MeResponse {
  actor_type: string;
  actor_id: string;
  user?: UserSummary;
  bindings: RoleBinding[];
  roles_catalog: { role: Role; description: string }[];
}

export interface Organization {
  id: string;
  slug: string;
  name: string;
  etag: string;
  created_at: string;
  updated_at: string;
}

export interface Cluster {
  id: string;
  org_id: string;
  slug: string;
  name: string;
  description: string;
  environment: string;
  ring_assignments: Record<string, number>;
  etag: string;
  created_at: string;
  updated_at: string;
}

export type NodeStatus = 'synced' | 'converging' | 'drifted' | 'lagging' | 'offline';

export interface NodeRecord {
  id: string;
  cluster_id: string;
  name: string;
  shunt_version: string;
  labels: Record<string, string>;
  active_revision: number;
  target_revision?: number | null;
  active_digest: string;
  last_reload_error?: string | null;
  synced_seqs: Record<string, number>;
  status: NodeStatus;
  runtime_status: Record<string, unknown>;
  last_heartbeat_at: string;
  created_at: string;
}

export interface BootstrapTokenMeta {
  id: string;
  cluster_id: string;
  name: string;
  prefix: string;
  default_labels: Record<string, string>;
  max_uses?: number | null;
  uses_count: number;
  expires_at?: string | null;
  revoked_at?: string | null;
  created_by: string;
  created_at: string;
}

export interface CreatedBootstrapToken {
  token: BootstrapTokenMeta;
  plaintext_token: string;
}

export interface InitialBootstrapResult {
  user: UserSummary;
  organization: Organization;
  cluster: Cluster;
  initial_revision?: TopologyRevision | null;
  bootstrap_token: CreatedBootstrapToken;
  session_token: string;
}

export type TopologyResourceKind =
  | 'server'
  | 'admin'
  | 'state'
  | 'telemetry'
  | 'global_plugin'
  | 'upstream'
  | 'route_group'
  | 'route';

export interface TopologyResource {
  id: string;
  cluster_id: string;
  kind: TopologyResourceKind;
  slug: string;
  sort_order: number;
  version: number;
  etag: string;
  spec: unknown;
  draft_state: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
}

export interface DiagnosticItem {
  severity: 'error' | 'warning' | 'info' | string;
  rule: string;
  subject?: string | null;
  message: string;
}

export interface ValidateDraftResult {
  valid: boolean;
  errors: number;
  warnings: number;
  infos: number;
  digest: string;
  compiled_toml: string;
  diagnostics: DiagnosticItem[];
  route_count: number;
  upstream_count: number;
}

export interface TopologyRevision {
  id: string;
  cluster_id: string;
  revision: number;
  digest: string;
  compiled_toml: string;
  verify_report: Record<string, unknown>;
  signature_b64: string;
  ring_assignments: Record<string, number>;
  notes: string;
  published_by: string;
  created_at: string;
}

export interface NamespaceStateSummary {
  namespace: string;
  head_seq: number;
  item_count: number;
  converged_nodes: number;
  total_online_nodes: number;
}

export interface ControlStateItem {
  cluster_id: string;
  namespace: string;
  item_key: string;
  seq: number;
  payload: unknown;
  updated_at: string;
}

export interface ControlEvent {
  seq: number;
  cluster_id: string;
  namespace: string;
  item_key: string;
  op: 'upsert' | 'delete' | string;
  payload?: unknown;
  created_at: string;
}

export interface NamespaceStateResponse {
  namespace: string;
  head_seq: number;
  items: ControlStateItem[];
  recent_events: ControlEvent[];
}

export type SecretDeliveryMode = 'vault' | 'env_ref';
export type SecretScopeType = 'org' | 'cluster';

export interface SecretMeta {
  id: string;
  org_id: string;
  scope_type: SecretScopeType;
  scope_id: string;
  slug: string;
  description: string;
  delivery_mode: SecretDeliveryMode;
  env_var_name?: string | null;
  key_version: number;
  metadata: Record<string, unknown>;
  etag: string;
  created_at: string;
  updated_at: string;
}

export interface UserWithRoles {
  user: UserSummary;
  bindings: RoleBinding[];
}

export interface ApiTokenMeta {
  id: string;
  org_id: string;
  name: string;
  prefix: string;
  role: Role;
  cluster_id?: string | null;
  created_by: string;
  expires_at?: string | null;
  last_used_at?: string | null;
  revoked_at?: string | null;
  created_at: string;
}

export interface CreatedApiToken {
  token: ApiTokenMeta;
  plaintext_token: string;
}

export interface OidcProviderRecord {
  id: string;
  org_id: string;
  slug: string;
  display_name: string;
  issuer_url: string;
  client_id: string;
  client_secret_ref?: string | null;
  scopes: string;
  group_claim: string;
  role_mappings: Record<string, Role>;
  enabled: boolean;
  etag: string;
  created_at: string;
  updated_at: string;
}

export interface AdminAuditEntry {
  seq: number;
  ts: string;
  actor_type: string;
  actor_id: string;
  actor_ip?: string | null;
  org_id?: string | null;
  cluster_id?: string | null;
  action: string;
  resource_type: string;
  resource_id: string;
  diff?: unknown;
  prev_hash: string;
  entry_hash: string;
}

export interface AuditChainVerification {
  valid: boolean;
  checked_entries: number;
  first_tampered_seq?: number | null;
  message?: string | null;
}

export class ApiProblemError extends Error {
  status: number;
  title: string;
  diagnostics: DiagnosticItem[];

  constructor(status: number, title: string, detail: string, diagnostics: DiagnosticItem[] = []) {
    super(detail || title);
    this.status = status;
    this.title = title;
    this.diagnostics = diagnostics;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const resp = await fetch(path, {
    credentials: 'same-origin',
    ...init,
    headers,
  });

  if (resp.status === 204) {
    return undefined as T;
  }

  const contentType = resp.headers.get('content-type') || '';
  if (!resp.ok) {
    if (contentType.includes('json')) {
      const problem = await resp.json().catch(() => ({}));
      throw new ApiProblemError(
        resp.status,
        problem.title || `HTTP ${resp.status}`,
        problem.detail || resp.statusText,
        problem.diagnostics || []
      );
    }
    const text = await resp.text().catch(() => resp.statusText);
    throw new ApiProblemError(resp.status, `HTTP ${resp.status}`, text);
  }

  if (contentType.includes('json')) {
    return (await resp.json()) as T;
  }
  return (await resp.text()) as unknown as T;
}

export const api = {
  getSystemStatus: () => request<SystemStatus>('/api/v1/system/status'),

  bootstrap: (payload: {
    admin_email: string;
    admin_name: string;
    admin_password: string;
    org_slug: string;
    org_name: string;
    cluster_slug: string;
    cluster_name: string;
    environment: string;
    import_toml?: string;
    auto_publish: boolean;
  }) =>
    request<InitialBootstrapResult>('/api/v1/setup/bootstrap', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  login: (email: string, password: string) =>
    request<UserSummary>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),

  logout: () => request<void>('/api/v1/auth/logout', { method: 'POST' }),
  getMe: () => request<MeResponse>('/api/v1/auth/me'),

  listOrgs: () => request<Organization[]>('/api/v1/orgs'),
  createOrg: (slug: string, name: string) =>
    request<Organization>('/api/v1/orgs', {
      method: 'POST',
      body: JSON.stringify({ slug, name }),
    }),

  listClusters: (org: string) => request<Cluster[]>(`/api/v1/orgs/${org}/clusters`),
  createCluster: (
    org: string,
    payload: {
      slug: string;
      name: string;
      description?: string;
      environment: string;
      import_toml?: string;
    }
  ) =>
    request<Cluster>(`/api/v1/orgs/${org}/clusters`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getCluster: (cluster: string) => request<Cluster>(`/api/v1/clusters/${cluster}`),

  listNodes: (cluster: string) => request<NodeRecord[]>(`/api/v1/clusters/${cluster}/nodes`),
  updateNodeLabels: (cluster: string, nodeId: string, labels: Record<string, string>) =>
    request<void>(`/api/v1/clusters/${cluster}/nodes/${nodeId}/labels`, {
      method: 'PATCH',
      body: JSON.stringify({ labels }),
    }),
  deleteNode: (cluster: string, nodeId: string) =>
    request<void>(`/api/v1/clusters/${cluster}/nodes/${nodeId}`, { method: 'DELETE' }),

  listBootstrapTokens: (cluster: string) =>
    request<BootstrapTokenMeta[]>(`/api/v1/clusters/${cluster}/bootstrap-tokens`),
  createBootstrapToken: (
    cluster: string,
    payload: {
      name: string;
      default_labels?: Record<string, string>;
      max_uses?: number | null;
      expires_in_hours?: number | null;
    }
  ) =>
    request<CreatedBootstrapToken>(`/api/v1/clusters/${cluster}/bootstrap-tokens`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  revokeBootstrapToken: (cluster: string, id: string) =>
    request<void>(`/api/v1/clusters/${cluster}/bootstrap-tokens/${id}`, { method: 'DELETE' }),

  listResources: (cluster: string) =>
    request<TopologyResource[]>(`/api/v1/clusters/${cluster}/resources`),
  upsertResource: (
    cluster: string,
    kind: TopologyResourceKind,
    slug: string,
    spec: unknown,
    opts?: { etag?: string; sortOrder?: number; autoPublish?: boolean }
  ) => {
    const headers: Record<string, string> = {};
    if (opts?.etag) headers['If-Match'] = opts.etag;
    const qs = opts?.autoPublish ? '?auto_publish=true' : '';
    return request<TopologyResource>(`/api/v1/clusters/${cluster}/resources/${kind}/${slug}${qs}`, {
      method: 'PUT',
      headers,
      body: JSON.stringify({ spec, sort_order: opts?.sortOrder }),
    });
  },
  deleteResource: (cluster: string, kind: TopologyResourceKind, slug: string, etag?: string) => {
    const headers: Record<string, string> = {};
    if (etag) headers['If-Match'] = etag;
    return request<void>(`/api/v1/clusters/${cluster}/resources/${kind}/${slug}`, {
      method: 'DELETE',
      headers,
    });
  },
  validateDraft: (cluster: string) =>
    request<ValidateDraftResult>(`/api/v1/clusters/${cluster}/validate`, { method: 'POST' }),
  importToml: (cluster: string, toml: string) =>
    request<ValidateDraftResult>(`/api/v1/clusters/${cluster}/import-toml`, {
      method: 'POST',
      body: JSON.stringify({ toml }),
    }),

  listRevisions: (cluster: string) =>
    request<TopologyRevision[]>(`/api/v1/clusters/${cluster}/revisions`),
  publishRevision: (
    cluster: string,
    payload: { ring_selector: string; notes: string; strict?: boolean }
  ) =>
    request<TopologyRevision>(`/api/v1/clusters/${cluster}/revisions:publish`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  rollbackRevision: (cluster: string, rev: number, ringSelector = '*') =>
    request<Cluster>(`/api/v1/clusters/${cluster}/revisions/${rev}/rollback`, {
      method: 'POST',
      body: JSON.stringify({ ring_selector: ringSelector }),
    }),
  promoteRevision: (cluster: string, rev: number, ringSelector = '*') =>
    request<Cluster>(`/api/v1/clusters/${cluster}/revisions/${rev}/promote`, {
      method: 'POST',
      body: JSON.stringify({ ring_selector: ringSelector }),
    }),

  listStateNamespaces: (cluster: string) =>
    request<NamespaceStateSummary[]>(`/api/v1/clusters/${cluster}/state`),
  getNamespaceState: (cluster: string, namespace: string) =>
    request<NamespaceStateResponse>(
      `/api/v1/clusters/${cluster}/state/${encodeURIComponent(namespace)}`
    ),
  upsertStateItem: (cluster: string, namespace: string, key: string, value: unknown) =>
    request<ControlEvent>(
      `/api/v1/clusters/${cluster}/state/${encodeURIComponent(namespace)}/${encodeURIComponent(key)}`,
      {
        method: 'PUT',
        body: JSON.stringify({ value }),
      }
    ),
  deleteStateItem: (cluster: string, namespace: string, key: string) =>
    request<ControlEvent>(
      `/api/v1/clusters/${cluster}/state/${encodeURIComponent(namespace)}/${encodeURIComponent(key)}`,
      { method: 'DELETE' }
    ),

  listSecrets: (org: string) => request<SecretMeta[]>(`/api/v1/orgs/${org}/secrets`),
  upsertSecret: (
    org: string,
    slug: string,
    payload: {
      description: string;
      scope_type: SecretScopeType;
      scope_id: string;
      delivery_mode: SecretDeliveryMode;
      value?: string;
      env_var_name?: string;
    },
    etag?: string
  ) => {
    const headers: Record<string, string> = {};
    if (etag) headers['If-Match'] = etag;
    return request<SecretMeta>(`/api/v1/orgs/${org}/secrets/${slug}`, {
      method: 'PUT',
      headers,
      body: JSON.stringify(payload),
    });
  },
  deleteSecret: (org: string, slug: string) =>
    request<void>(`/api/v1/orgs/${org}/secrets/${slug}`, { method: 'DELETE' }),

  listUsers: (org: string) => request<UserWithRoles[]>(`/api/v1/orgs/${org}/users`),
  createUser: (
    org: string,
    payload: {
      email: string;
      display_name: string;
      password: string;
      role: Role;
      cluster_id?: string | null;
    }
  ) =>
    request<UserWithRoles>(`/api/v1/orgs/${org}/users`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  createRoleBinding: (
    org: string,
    payload: { user_id: string; role: Role; cluster_id?: string | null }
  ) =>
    request<RoleBinding>(`/api/v1/orgs/${org}/role-bindings`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  deleteRoleBinding: (org: string, id: string) =>
    request<void>(`/api/v1/orgs/${org}/role-bindings/${id}`, { method: 'DELETE' }),

  listApiTokens: (org: string) => request<ApiTokenMeta[]>(`/api/v1/orgs/${org}/api-tokens`),
  createApiToken: (
    org: string,
    payload: {
      name: string;
      role: Role;
      cluster_id?: string | null;
      expires_in_days?: number | null;
    }
  ) =>
    request<CreatedApiToken>(`/api/v1/orgs/${org}/api-tokens`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  revokeApiToken: (org: string, id: string) =>
    request<void>(`/api/v1/orgs/${org}/api-tokens/${id}`, { method: 'DELETE' }),

  listOidcProviders: (org: string) =>
    request<OidcProviderRecord[]>(`/api/v1/orgs/${org}/oidc-providers`),
  upsertOidcProvider: (
    org: string,
    slug: string,
    payload: {
      display_name: string;
      issuer_url: string;
      client_id: string;
      client_secret_ref?: string;
      scopes?: string;
      group_claim?: string;
      role_mappings?: Record<string, Role>;
      enabled?: boolean;
    }
  ) =>
    request<OidcProviderRecord>(`/api/v1/orgs/${org}/oidc-providers/${slug}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  deleteOidcProvider: (org: string, slug: string) =>
    request<void>(`/api/v1/orgs/${org}/oidc-providers/${slug}`, { method: 'DELETE' }),

  listAdminAudit: (limit = 100) =>
    request<AdminAuditEntry[]>(`/api/v1/audit/admin?limit=${limit}`),
  verifyAdminAudit: () => request<AuditChainVerification>('/api/v1/audit/admin:verify'),
};

export function slugify(input: string): string {
  return input
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9-_]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
}

export function formatRelativeTime(iso: string): string {
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return iso;
  const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diffSec < 5) return 'just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const mins = Math.floor(diffSec / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function shortDigest(digest: string): string {
  const raw = digest.replace(/^sha256:/, '');
  return raw ? raw.slice(0, 12) : '—';
}

export type ConnectCommandMode = 'binary' | 'cargo' | 'docker';

export function buildShuntConnectCommand(opts: {
  controlPlaneUrl: string;
  clusterSlug: string;
  token: string;
  labels?: string;
  cacheDir?: string;
  mode?: ConnectCommandMode;
}): string {
  const mode = opts.mode || 'binary';
  const cacheDir = opts.cacheDir || './.shunt-cache';
  const labels = opts.labels?.trim();

  if (mode === 'docker') {
    const cpUrl = opts.controlPlaneUrl.replace('127.0.0.1', 'host.docker.internal').replace('localhost', 'host.docker.internal');
    const lines = [
      `docker run --rm -p 8080:8080 \\`,
      `  -e SHUNT_NODE_TOKEN="${opts.token}" \\`,
      `  ghcr.io/shettyh/shunt:latest run \\`,
      `  --control-plane ${cpUrl} \\`,
      `  --cluster ${opts.clusterSlug} \\`,
      `  --token-env SHUNT_NODE_TOKEN \\`,
      `  --cache-dir /tmp/shunt-cache`,
    ];
    if (labels) {
      lines[lines.length - 1] += ' \\';
      lines.push(`  --node-labels ${labels}`);
    }
    return lines.join('\n');
  }

  const launcher =
    mode === 'cargo'
      ? `SHUNT_NODE_TOKEN="${opts.token}" cargo run -p shunt-cli -- run \\`
      : `SHUNT_NODE_TOKEN="${opts.token}" shunt run \\`;

  const parts = [
    launcher,
    `  --control-plane ${opts.controlPlaneUrl} \\`,
    `  --cluster ${opts.clusterSlug} \\`,
    `  --token-env SHUNT_NODE_TOKEN \\`,
    `  --cache-dir ${cacheDir}`,
  ];
  if (labels) {
    parts[parts.length - 1] += ' \\';
    parts.push(`  --node-labels ${labels}`);
  }
  return parts.join('\n');
}
