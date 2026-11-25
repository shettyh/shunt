import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ChevronRight,
  Command,
  ExternalLink,
  FileCode2,
  KeyRound,
  Layers,
  LogOut,
  Menu,
  Monitor,
  Moon,
  Plus,
  Server,
  Shield,
  Sun,
  Terminal,
  X,
} from 'lucide-react';
import {
  api,
  ApiProblemError,
  Cluster,
  MeResponse,
  Organization,
  slugify,
  SystemStatus,
} from './lib/api';
import { Modal, ShuntMark, ThemeProvider, ToastProvider, useTheme, useToast } from './components/ui';
import { SetupWizard } from './components/SetupWizard';
import { LoginScreen } from './components/LoginScreen';
import { CommandPalette, NavSection } from './components/CommandPalette';
import { OverviewPage } from './pages/OverviewPage';
import { FleetPage } from './pages/FleetPage';
import { TopologyPage } from './pages/TopologyPage';
import { SyncedStatePage } from './pages/SyncedStatePage';
import { SecretsPage } from './pages/SecretsPage';
import { AccessAuditPage } from './pages/AccessAuditPage';

function ConsoleAppInner() {
  const toast = useToast();
  const theme = useTheme();

  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [me, setMe] = useState<MeResponse | null>(null);
  const [booting, setBooting] = useState(true);

  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [selectedOrgSlug, setSelectedOrgSlug] = useState<string>('');
  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [selectedClusterSlug, setSelectedClusterSlug] = useState<string>('');

  const [section, setSection] = useState<NavSection>('overview');
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [connectModalOpen, setConnectModalOpen] = useState(false);

  // Create Cluster Modal
  const [newClusterOpen, setNewClusterOpen] = useState(false);
  const [ncName, setNcName] = useState('');
  const [ncSlug, setNcSlug] = useState('');
  const [ncEnv, setNcEnv] = useState('staging');
  const [ncShowImport, setNcShowImport] = useState(false);
  const [ncImportToml, setNcImportToml] = useState('');

  const hydrateSession = useCallback(async () => {
    setBooting(true);
    try {
      const sys = await api.getSystemStatus();
      setStatus(sys);
      if (!sys.initialized) {
        setMe(null);
        return;
      }
      try {
        const whoami = await api.getMe();
        setMe(whoami);
        const orgList = await api.listOrgs();
        setOrgs(orgList);
        const targetOrg = orgList[0]?.slug || '';
        setSelectedOrgSlug((prev) => (orgList.some((o) => o.slug === prev) ? prev : targetOrg));
      } catch {
        setMe(null);
      }
    } finally {
      setBooting(false);
    }
  }, []);

  useEffect(() => {
    hydrateSession();
  }, [hydrateSession]);

  const loadClusters = useCallback(async (orgSlug: string) => {
    if (!orgSlug) return;
    try {
      const list = await api.listClusters(orgSlug);
      setClusters(list);
      setSelectedClusterSlug((prev) =>
        list.some((c) => c.slug === prev) ? prev : list[0]?.slug || ''
      );
    } catch {
      setClusters([]);
    }
  }, []);

  useEffect(() => {
    if (me && selectedOrgSlug) {
      loadClusters(selectedOrgSlug);
    }
  }, [me, selectedOrgSlug, loadClusters]);

  // Global keyboard shortcut: Cmd+K / Ctrl+K for Command Palette + custom event for Connect Node
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    const onConnect = () => {
      setSection('fleet');
      setConnectModalOpen(true);
    };
    window.addEventListener('keydown', onKey);
    window.addEventListener('shunt-open-connect-node', onConnect);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('shunt-open-connect-node', onConnect);
    };
  }, []);

  const handleLogout = async () => {
    await api.logout();
    setMe(null);
    toast.push('Signed out');
  };

  const handleCreateCluster = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedOrgSlug) return;
    try {
      const created = await api.createCluster(selectedOrgSlug, {
        slug: slugify(ncSlug || ncName),
        name: ncName.trim(),
        environment: ncEnv,
        import_toml: ncShowImport && ncImportToml.trim() ? ncImportToml : undefined,
      });
      toast.push(`Created cluster "${created.name}"`);
      setNewClusterOpen(false);
      setNcName('');
      setNcSlug('');
      setNcShowImport(false);
      setNcImportToml('');
      await loadClusters(selectedOrgSlug);
      setSelectedClusterSlug(created.slug);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  if (booting) {
    return (
      <div className="min-h-screen flex items-center justify-center text-sm" style={{ color: 'var(--text-muted)' }}>
        Connecting to Shunt Console…
      </div>
    );
  }

  if (status && !status.initialized) {
    return <SetupWizard onComplete={hydrateSession} />;
  }

  if (!me && status) {
    return <LoginScreen status={status} onSuccess={hydrateSession} />;
  }

  const currentOrg = orgs.find((o) => o.slug === selectedOrgSlug) || orgs[0];
  const currentCluster = clusters.find((c) => c.slug === selectedClusterSlug) || clusters[0];

  const navItems: { id: NavSection; label: string; group: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview', group: 'Gateway', icon: <Activity size={16} /> },
    { id: 'fleet', label: 'Fleet & Nodes', group: 'Gateway', icon: <Server size={16} /> },
    { id: 'topology', label: 'Config & Releases', group: 'Gateway', icon: <FileCode2 size={16} /> },
    { id: 'state', label: 'Live Policies', group: 'Gateway', icon: <Layers size={16} /> },
    { id: 'secrets', label: 'Secrets Vault', group: 'Security & Governance', icon: <KeyRound size={16} /> },
    { id: 'access', label: 'Access & Audit', group: 'Security & Governance', icon: <Shield size={16} /> },
  ];

  const activeNav = navItems.find((i) => i.id === section) || navItems[0];

  const sidebarContent = (
    <div className="flex flex-col h-full">
      {/* Brand */}
      <div className="px-4 h-14 flex items-center justify-between shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
        <div className="flex items-center gap-2.5">
          <ShuntMark size={28} />
          <div>
            <div className="font-semibold text-[15px] tracking-tight leading-tight">Shunt Console</div>
            <div className="mono text-xs" style={{ color: 'var(--text-muted)' }}>
              v{status?.version} · {status?.db_kind}
            </div>
          </div>
        </div>
        <button
          type="button"
          className="lg:hidden btn-ghost p-1.5 border-0 cursor-pointer"
          onClick={() => setMobileMenuOpen(false)}
        >
          <X size={18} />
        </button>
      </div>

      {/* Org & Cluster Switcher */}
      <div className="p-3.5 space-y-2" style={{ borderBottom: '1px solid var(--border)' }}>
        <div className="flex items-center justify-between text-xs uppercase tracking-wider font-semibold px-0.5" style={{ color: 'var(--text-muted)' }}>
          <span>Cluster</span>
          <button
            type="button"
            className="btn-ghost px-1.5 py-0.5 text-xs flex items-center gap-1 border-0 cursor-pointer rounded"
            onClick={() => setNewClusterOpen(true)}
            title="Create new cluster"
          >
            <Plus size={13} />
            <span>New</span>
          </button>
        </div>
        <select
          className="input-base text-sm py-1.5 font-medium"
          value={selectedClusterSlug}
          onChange={(e) => setSelectedClusterSlug(e.target.value)}
        >
          {clusters.map((c) => (
            <option key={c.id} value={c.slug}>
              {c.name} ({c.slug})
            </option>
          ))}
        </select>

        {orgs.length > 1 && (
          <select
            className="input-base text-sm py-1.5"
            value={selectedOrgSlug}
            onChange={(e) => setSelectedOrgSlug(e.target.value)}
          >
            {orgs.map((o) => (
              <option key={o.id} value={o.slug}>
                Org: {o.name}
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-3.5 space-y-5 overflow-y-auto">
        {['Gateway', 'Security & Governance'].map((group) => (
          <div key={group} className="space-y-1">
            <div
              className="px-2.5 text-xs font-semibold uppercase tracking-wider mb-1.5"
              style={{ color: 'var(--text-muted)' }}
            >
              {group}
            </div>
            {navItems
              .filter((i) => i.group === group)
              .map((item) => {
                const active = section === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setSection(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-sm cursor-pointer border-0 transition-colors text-left"
                    style={{
                      background: active ? 'var(--accent-soft)' : 'transparent',
                      color: active ? 'var(--accent)' : 'var(--text-secondary)',
                      fontWeight: active ? 600 : 500,
                    }}
                  >
                    <span style={{ color: active ? 'var(--accent)' : 'var(--text-muted)' }}>
                      {item.icon}
                    </span>
                    <span>{item.label}</span>
                  </button>
                );
              })}
          </div>
        ))}
      </nav>

      {/* Footer Utilities */}
      <div className="p-3.5 space-y-2.5 text-sm" style={{ borderTop: '1px solid var(--border)' }}>
        <div className="flex items-center justify-between gap-2">
          <div
            className="inline-flex rounded-lg p-0.5"
            style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border)' }}
            role="group"
            aria-label="Theme"
          >
            {[
              { id: 'system' as const, icon: <Monitor size={14} />, label: 'System theme' },
              { id: 'light' as const, icon: <Sun size={14} />, label: 'Light theme' },
              { id: 'dark' as const, icon: <Moon size={14} />, label: 'Dark theme' },
            ].map((t) => (
              <button
                key={t.id}
                type="button"
                title={t.label}
                onClick={() => theme.setPref(t.id)}
                className="p-1.5 rounded-md border-0 cursor-pointer"
                style={{
                  background: theme.pref === t.id ? 'var(--bg-elevated)' : 'transparent',
                  color: theme.pref === t.id ? 'var(--text-primary)' : 'var(--text-muted)',
                }}
              >
                {t.icon}
              </button>
            ))}
          </div>
          <a
            href="/api/v1/openapi.json"
            target="_blank"
            rel="noreferrer"
            className="btn-ghost px-2 py-1 rounded text-xs flex items-center gap-1 no-underline"
            style={{ color: 'var(--text-muted)' }}
          >
            <span>OpenAPI</span>
            <ExternalLink size={12} />
          </a>
        </div>

        <div className="flex items-center justify-between gap-2 pt-2" style={{ borderTop: '1px solid var(--border-light)' }}>
          <div className="min-w-0">
            <div className="font-medium text-sm truncate">{me?.user?.display_name || me?.actor_id}</div>
            <div className="text-xs truncate mono" style={{ color: 'var(--text-muted)' }}>
              {me?.bindings[0]?.role || 'authenticated'}
            </div>
          </div>
          <button
            type="button"
            onClick={handleLogout}
            title="Sign out"
            className="btn-ghost p-1.5 rounded border-0 cursor-pointer"
            style={{ color: 'var(--text-muted)' }}
          >
            <LogOut size={15} />
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen flex" style={{ background: 'var(--bg-canvas)' }}>
      {/* Desktop Sidebar */}
      <aside
        className="hidden lg:block w-64 shrink-0 sticky top-0 h-screen"
        style={{ background: 'var(--bg-sidebar)', borderRight: '1px solid var(--border)' }}
      >
        {sidebarContent}
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 z-40 lg:hidden flex"
          style={{ background: 'rgba(0,0,0,0.45)' }}
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) setMobileMenuOpen(false);
          }}
        >
          <aside className="w-64 h-full" style={{ background: 'var(--bg-sidebar)' }}>
            {sidebarContent}
          </aside>
        </div>
      )}

      {/* Main Workspace */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Clean Sticky Top Bar */}
        <header
          className="sticky top-0 z-20 h-14 px-5 lg:px-8 flex items-center justify-between gap-4 shrink-0"
          style={{ background: 'var(--bg-elevated)', borderBottom: '1px solid var(--border)' }}
        >
          <div className="flex items-center gap-2.5 min-w-0">
            <button
              type="button"
              className="lg:hidden btn-ghost p-1.5 border-0 cursor-pointer"
              onClick={() => setMobileMenuOpen(true)}
            >
              <Menu size={18} />
            </button>
            {currentCluster && (
              <div className="flex items-center gap-2 text-sm min-w-0">
                <span className="font-medium truncate" style={{ color: 'var(--text-muted)' }}>
                  {currentCluster.name}
                </span>
                <span className="badge badge-accent hidden sm:inline-flex">{currentCluster.environment}</span>
                <ChevronRight size={15} style={{ color: 'var(--text-muted)' }} className="shrink-0" />
                <span className="font-semibold truncate">{activeNav.label}</span>
              </div>
            )}
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            {status?.ephemeral_dev_key && (
              <span
                className="badge badge-warn cursor-help hidden md:inline-flex"
                title="Local Dev Mode: Using an auto-generated Secrets Vault KEK. Set SHUNT_CONSOLE_MASTER_KEY for production deployments."
              >
                <AlertTriangle size={13} />
                <span>Dev Key</span>
              </span>
            )}
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              className="btn btn-sm"
              style={{ background: 'var(--bg-subtle)', color: 'var(--text-muted)' }}
              title="Open quick actions"
            >
              <Command size={14} />
              <span className="hidden sm:inline">Quick jump</span>
              <kbd className="mono text-xs">⌘K</kbd>
            </button>
            {currentCluster && (
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => {
                  setSection('fleet');
                  setConnectModalOpen(true);
                }}
              >
                <Terminal size={14} />
                <span className="hidden sm:inline">Connect Node</span>
              </button>
            )}
          </div>
        </header>

        <main className="flex-1 w-full max-w-[1440px] px-5 lg:px-8 py-6">
          {!currentOrg || !currentCluster ? (
            <div className="surface p-10 text-center space-y-3">
              <div className="font-semibold">No clusters found</div>
              <button type="button" className="btn btn-primary" onClick={() => setNewClusterOpen(true)}>
                <Plus size={14} />
                <span>Create First Cluster</span>
              </button>
            </div>
          ) : (
            <>
              {section === 'overview' && (
                <OverviewPage
                  cluster={currentCluster}
                  onNavigate={setSection}
                  onConnectNode={() => {
                    setSection('fleet');
                    setConnectModalOpen(true);
                  }}
                />
              )}
              {section === 'fleet' && (
                <FleetPage
                  cluster={currentCluster}
                  openConnectModal={connectModalOpen}
                  onConnectModalClose={() => setConnectModalOpen(false)}
                />
              )}
              {section === 'topology' && (
                <TopologyPage
                  cluster={currentCluster}
                  onClusterChanged={() => loadClusters(currentOrg.slug)}
                />
              )}
              {section === 'state' && <SyncedStatePage cluster={currentCluster} />}
              {section === 'secrets' && <SecretsPage org={currentOrg} cluster={currentCluster} />}
              {section === 'access' && me && <AccessAuditPage org={currentOrg} me={me} />}
            </>
          )}
        </main>
      </div>

      {/* Command Palette */}
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onNavigate={setSection}
        clusters={clusters}
        onSelectCluster={(slug) => setSelectedClusterSlug(slug)}
        onQuickConnectNode={() => {
          setSection('fleet');
          setConnectModalOpen(true);
        }}
      />

      {/* New Cluster Modal */}
      <Modal
        open={newClusterOpen}
        onClose={() => setNewClusterOpen(false)}
        title="Create Cluster"
        subtitle="Each cluster manages its own gateway configuration, versioned releases, and instant live policies—ready for HTTP APIs, AI models, and MCP tools together."
      >
        <form onSubmit={handleCreateCluster} className="space-y-3.5">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium mb-1">Cluster Name</label>
              <input
                className="input-base"
                value={ncName}
                onChange={(e) => {
                  setNcName(e.target.value);
                  setNcSlug(slugify(e.target.value));
                }}
                placeholder="Staging EU"
                required
              />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1">Slug</label>
              <input
                className="input-base mono text-xs"
                value={ncSlug}
                onChange={(e) => setNcSlug(slugify(e.target.value))}
                placeholder="staging-eu"
                required
              />
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium mb-1">Environment</label>
            <select className="input-base" value={ncEnv} onChange={(e) => setNcEnv(e.target.value)}>
              <option value="production">production</option>
              <option value="staging">staging</option>
              <option value="development">development</option>
            </select>
          </div>
          <label className="flex items-center gap-2 text-xs cursor-pointer select-none pt-1">
            <input
              type="checkbox"
              checked={ncShowImport}
              onChange={(e) => setNcShowImport(e.target.checked)}
            />
            <span>Import an existing <code>shunt.toml</code> instead of starting from a clean skeleton</span>
          </label>
          {ncShowImport && (
            <textarea
              className="input-base mono text-xs min-h-[120px]"
              value={ncImportToml}
              onChange={(e) => setNcImportToml(e.target.value)}
              placeholder={`[server]\nlisten = "0.0.0.0:8080"\n\n[[upstreams]]\nname = "api"\nendpoints = ["http://127.0.0.1:3000"]`}
            />
          )}
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" className="btn" onClick={() => setNewClusterOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              Create Cluster
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <ToastProvider>
        <ConsoleAppInner />
      </ToastProvider>
    </ThemeProvider>
  );
}
