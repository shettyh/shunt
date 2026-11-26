import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Blocks,
  GitBranch,
  History,
  Home,
  LogOut,
  Menu,
  Monitor,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Rocket,
  Search,
  Server,
  Shield,
  Sparkles,
  Sun,
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
  TopologyResource,
  TopologyRevision,
  ValidateDraftResult,
} from './lib/api';
import {
  Modal,
  ShuntMark,
  ThemeProvider,
  ToastProvider,
  useTheme,
  useToast,
} from './components/ui';
import { SetupWizard } from './components/SetupWizard';
import { LoginScreen } from './components/LoginScreen';
import { CommandPalette, NavSection } from './components/CommandPalette';
import { ApiQuickConnectDrawer } from './components/ApiQuickConnectDrawer';
import { ClusterHeaderContext } from './components/PageHeader';
import { OverviewPage } from './pages/OverviewPage';
import { AiGatewayPage } from './pages/AiGatewayPage';
import { McpGatewayPage } from './pages/McpGatewayPage';
import { RoutesPage } from './pages/RoutesPage';
import { FleetPage } from './pages/FleetPage';
import { ReleasesPage } from './pages/ReleasesPage';
import { SecurityPage } from './pages/SecurityPage';

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

  // Shared cluster topology state (powers AI Gateway, MCP Gateway, Routes, Releases, API Drawer & floating Publish bar)
  const [resources, setResources] = useState<TopologyResource[]>([]);
  const [validation, setValidation] = useState<ValidateDraftResult | null>(null);
  const [revisions, setRevisions] = useState<TopologyRevision[]>([]);

  const [section, setSection] = useState<NavSection>('overview');
  const [railCollapsed, setRailCollapsed] = useState<boolean>(() => {
    return localStorage.getItem('shunt_console_rail') === 'collapsed';
  });
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [connectModalOpen, setConnectModalOpen] = useState(false);
  const [apiDrawerOpen, setApiDrawerOpen] = useState(false);
  const [apiDrawerPrefillKey, setApiDrawerPrefillKey] = useState<string | undefined>(undefined);

  // Publish Release Modal
  const [publishOpen, setPublishOpen] = useState(false);
  const [pubRing, setPubRing] = useState('*');
  const [pubNotes, setPubNotes] = useState('');
  const [publishing, setPublishing] = useState(false);

  // Create Cluster Modal
  const [newClusterOpen, setNewClusterOpen] = useState(false);
  const [ncName, setNcName] = useState('');
  const [ncSlug, setNcSlug] = useState('');
  const [ncEnv, setNcEnv] = useState('staging');

  const toggleRail = () => {
    setRailCollapsed((prev) => {
      const next = !prev;
      localStorage.setItem('shunt_console_rail', next ? 'collapsed' : 'expanded');
      return next;
    });
  };

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

  const loadClusterWorkspace = useCallback(async (clusterSlug: string) => {
    if (!clusterSlug) return;
    const [res, val, revs] = await Promise.all([
      api.listResources(clusterSlug).catch(() => []),
      api.validateDraft(clusterSlug).catch(() => null),
      api.listRevisions(clusterSlug).catch(() => []),
    ]);
    setResources(res);
    setValidation(val);
    setRevisions(revs);
  }, []);

  useEffect(() => {
    if (me && selectedClusterSlug) {
      loadClusterWorkspace(selectedClusterSlug);
    }
  }, [me, selectedClusterSlug, loadClusterWorkspace]);

  // Global keyboard shortcut: Cmd+K / Ctrl+K
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const currentOrg = orgs.find((o) => o.slug === selectedOrgSlug) || orgs[0];
  const currentCluster = clusters.find((c) => c.slug === selectedClusterSlug) || clusters[0];

  const hasPendingChanges = useMemo(() => {
    if (!validation || !currentCluster) return false;
    const activeRevNum = currentCluster.ring_assignments['*'];
    const liveRev = revisions.find((r) => r.revision === activeRevNum) || revisions[0];
    if (!liveRev) return resources.length > 0;
    return liveRev.digest !== validation.digest;
  }, [validation, currentCluster, revisions, resources.length]);

  const refreshAll = useCallback(async () => {
    if (selectedOrgSlug) await loadClusters(selectedOrgSlug);
    if (selectedClusterSlug) await loadClusterWorkspace(selectedClusterSlug);
  }, [selectedOrgSlug, selectedClusterSlug, loadClusters, loadClusterWorkspace]);

  const handlePublish = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentCluster) return;
    setPublishing(true);
    try {
      const rev = await api.publishRevision(currentCluster.slug, {
        ring_selector: pubRing.trim() || '*',
        notes: pubNotes.trim(),
      });
      toast.push(`Published Release v${rev.revision} to ring "${pubRing || '*'}"`);
      setPublishOpen(false);
      setPubNotes('');
      await refreshAll();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setPublishing(false);
    }
  };

  const handleCreateCluster = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedOrgSlug) return;
    try {
      const created = await api.createCluster(selectedOrgSlug, {
        slug: slugify(ncSlug || ncName),
        name: ncName.trim(),
        environment: ncEnv,
      });
      toast.push(`Created cluster "${created.name}"`);
      setNewClusterOpen(false);
      setNcName('');
      setNcSlug('');
      await loadClusters(selectedOrgSlug);
      setSelectedClusterSlug(created.slug);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handleLogout = async () => {
    await api.logout();
    setMe(null);
    toast.push('Signed out');
  };

  if (booting) {
    return (
      <div
        className="min-h-screen flex items-center justify-center text-[13px]"
        style={{ color: 'var(--ink-muted)', background: 'var(--shell)' }}
      >
        Connecting to Shunt Console…
      </div>
    );
  }

  if (status && !status.initialized) return <SetupWizard onComplete={hydrateSession} />;
  if (!me && status) return <LoginScreen status={status} onSuccess={hydrateSession} />;

  const navItems: { id: NavSection; label: string; group: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview', group: 'Main', icon: <Home size={16} strokeWidth={1.75} /> },
    { id: 'ai', label: 'AI Gateway', group: 'Gateway', icon: <Sparkles size={16} strokeWidth={1.75} /> },
    { id: 'mcp', label: 'MCP Gateway', group: 'Gateway', icon: <Blocks size={16} strokeWidth={1.75} /> },
    { id: 'routes', label: 'HTTP Routes', group: 'Gateway', icon: <GitBranch size={16} strokeWidth={1.75} /> },
    { id: 'fleet', label: 'Fleet', group: 'Operations', icon: <Server size={16} strokeWidth={1.75} /> },
    { id: 'releases', label: 'Releases', group: 'Operations', icon: <History size={16} strokeWidth={1.75} /> },
    { id: 'security', label: 'Security', group: 'Operations', icon: <Shield size={16} strokeWidth={1.75} /> },
  ];

  const headerCtx: ClusterHeaderContext | null = currentCluster
    ? {
        clusters,
        currentCluster,
        onSelectCluster: (slug) => setSelectedClusterSlug(slug),
        onCreateCluster: () => setNewClusterOpen(true),
        onOpenApiDrawer: () => {
          setApiDrawerPrefillKey(undefined);
          setApiDrawerOpen(true);
        },
      }
    : null;

  const userInitial = (me?.user?.display_name || me?.actor_id || 'A').slice(0, 1).toUpperCase();

  const renderSidebar = (collapsed: boolean) => (
    <div className="flex flex-col h-full select-none py-3 px-2.5">
      {/* Top Brand + Collapse */}
      <div className={`flex items-center ${collapsed ? 'justify-center' : 'justify-between px-1.5'} mb-4`}>
        <button
          type="button"
          onClick={() => setSection('overview')}
          className="flex items-center gap-2.5 bg-transparent border-0 cursor-pointer p-0 text-left"
          title="Shunt Console"
        >
          <ShuntMark size={26} />
          {!collapsed && (
            <div className="min-w-0">
              <div className="font-semibold text-[14px] tracking-tight leading-none" style={{ color: 'var(--ink)' }}>
                Shunt
              </div>
              <div className="mono text-[10.5px] mt-0.5 leading-none" style={{ color: 'var(--ink-muted)' }}>
                {currentOrg?.slug || 'console'}
              </div>
            </div>
          )}
        </button>

        {!collapsed && (
          <button
            type="button"
            onClick={() => setPaletteOpen(true)}
            className="btn-ghost p-1.5"
            style={{ color: 'var(--ink-muted)' }}
            title="Quick jump (⌘K)"
          >
            <Search size={14} />
          </button>
        )}
      </div>

      {/* Product-First Navigation */}
      <nav className="flex-1 space-y-4 overflow-y-auto">
        {['Main', 'Gateway', 'Operations'].map((group) => (
          <div key={group} className="space-y-0.5">
            {!collapsed && group !== 'Main' && (
              <div
                className="px-2 pt-1 pb-1 text-[10.5px] font-semibold uppercase tracking-wider"
                style={{ color: 'var(--ink-muted)' }}
              >
                {group}
              </div>
            )}
            {navItems
              .filter((i) => i.group === group)
              .map((item) => {
                const active = section === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    title={item.label}
                    onClick={() => {
                      setSection(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center ${collapsed ? 'justify-center px-0' : 'gap-2.5 px-2.5'} h-9 rounded-lg border-0 cursor-pointer transition-colors text-[13.5px]`}
                    style={{
                      background: active ? 'var(--surface-active)' : 'transparent',
                      color: active ? 'var(--ink)' : 'var(--ink-secondary)',
                      fontWeight: active ? 600 : 500,
                    }}
                  >
                    <span
                      className="shrink-0 flex items-center justify-center"
                      style={{ color: active ? 'var(--brand)' : 'var(--ink-muted)' }}
                    >
                      {item.icon}
                    </span>
                    {!collapsed && <span className="truncate">{item.label}</span>}
                  </button>
                );
              })}
          </div>
        ))}
      </nav>

      {/* Quiet Footer Utilities (matches Entire's minimal bottom rail) */}
      <div className="pt-3 space-y-1.5">
        {/* Collapse Toggle (desktop) */}
        <button
          type="button"
          onClick={toggleRail}
          title={collapsed ? 'Expand sidebar' : 'Collapse to icon rail'}
          className={`hidden lg:flex w-full items-center ${collapsed ? 'justify-center px-0' : 'gap-2.5 px-2.5'} h-8 rounded-lg btn-ghost text-[12.5px]`}
          style={{ color: 'var(--ink-muted)' }}
        >
          {collapsed ? <PanelLeftOpen size={15} /> : <PanelLeftClose size={15} />}
          {!collapsed && <span>Compact rail</span>}
        </button>

        {/* Theme Cycle */}
        <button
          type="button"
          onClick={() => theme.cycle()}
          title={`Theme: ${theme.pref} (click to cycle)`}
          className={`flex w-full items-center ${collapsed ? 'justify-center px-0' : 'gap-2.5 px-2.5'} h-8 rounded-lg btn-ghost text-[12.5px]`}
          style={{ color: 'var(--ink-muted)' }}
        >
          {theme.pref === 'light' ? (
            <Sun size={15} />
          ) : theme.pref === 'dark' ? (
            <Moon size={15} />
          ) : (
            <Monitor size={15} />
          )}
          {!collapsed && <span className="capitalize">{theme.pref} theme</span>}
        </button>

        {/* User Avatar & Sign Out */}
        <div
          className={`flex items-center ${collapsed ? 'justify-center' : 'justify-between px-1.5'} pt-2`}
          style={{ borderTop: '1px solid var(--border)' }}
        >
          <div className="flex items-center gap-2 min-w-0">
            <div
              className="w-7 h-7 rounded-full flex items-center justify-center text-[11.5px] font-semibold shrink-0"
              style={{
                background: 'var(--brand-soft)',
                color: 'var(--brand)',
                border: '1px solid var(--brand-border)',
              }}
              title={me?.user?.email || me?.actor_id}
            >
              {userInitial}
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <div className="text-[12.5px] font-medium truncate">
                  {me?.user?.display_name || me?.actor_id}
                </div>
                <div className="mono text-[10.5px] truncate" style={{ color: 'var(--ink-muted)' }}>
                  {me?.bindings[0]?.role || 'admin'}
                </div>
              </div>
            )}
          </div>
          {!collapsed && (
            <button
              type="button"
              onClick={handleLogout}
              title="Sign out"
              className="btn-ghost p-1.5"
              style={{ color: 'var(--ink-muted)' }}
            >
              <LogOut size={14} />
            </button>
          )}
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen flex" style={{ background: 'var(--shell)' }}>
      {/* Desktop Collapsible Rail (212px Cloudflare-clear OR 56px Entire icon rail) */}
      <aside
        className={`hidden lg:block shrink-0 sticky top-0 h-screen transition-all duration-150 ${
          railCollapsed ? 'w-[58px]' : 'w-[214px]'
        }`}
      >
        {renderSidebar(railCollapsed)}
      </aside>

      {/* Mobile Nav Drawer */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 z-50 lg:hidden flex"
          style={{ background: 'rgba(17, 17, 19, 0.4)' }}
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) setMobileMenuOpen(false);
          }}
        >
          <aside className="w-60 h-full relative" style={{ background: 'var(--shell)' }}>
            <button
              type="button"
              className="btn-ghost p-1.5 absolute top-3 right-3"
              onClick={() => setMobileMenuOpen(false)}
            >
              <X size={16} />
            </button>
            {renderSidebar(false)}
          </aside>
        </div>
      )}

      {/* Main Framed Single Pure-White Sheet (Signature Entire Aesthetic) */}
      <div className="flex-1 min-w-0 p-2 sm:p-2.5 lg:pl-0 flex flex-col">
        {/* Mobile Bar */}
        <div className="flex lg:hidden items-center justify-between px-2 pb-2">
          <button
            type="button"
            className="btn-ghost p-1.5"
            onClick={() => setMobileMenuOpen(true)}
          >
            <Menu size={18} />
          </button>
          <div className="flex items-center gap-2">
            <ShuntMark size={22} />
            <span className="font-semibold text-[14px]">Shunt</span>
          </div>
          <button type="button" className="btn-ghost p-1.5" onClick={() => setPaletteOpen(true)}>
            <Search size={16} />
          </button>
        </div>

        <main className="app-sheet flex-1 min-h-[calc(100vh-20px)] flex flex-col overflow-hidden relative">
          {!currentOrg || !currentCluster || !headerCtx ? (
            <div className="p-16 text-center space-y-3">
              <div className="font-semibold text-[15px]">No clusters found</div>
              <button type="button" className="btn btn-primary" onClick={() => setNewClusterOpen(true)}>
                Create First Cluster
              </button>
            </div>
          ) : (
            <div className="flex-1 pb-20">
              {section === 'overview' && (
                <OverviewPage
                  cluster={currentCluster}
                  headerCtx={headerCtx}
                  resources={resources}
                  validation={validation}
                  revisions={revisions}
                  hasPendingChanges={hasPendingChanges}
                  onNavigate={setSection}
                  onConnectNode={() => {
                    setSection('fleet');
                    setConnectModalOpen(true);
                  }}
                  onPublish={() => setPublishOpen(true)}
                />
              )}

              {section === 'ai' && (
                <AiGatewayPage
                  org={currentOrg}
                  cluster={currentCluster}
                  headerCtx={headerCtx}
                  resources={resources}
                  onChanged={refreshAll}
                  onOpenApiWithKey={(key) => {
                    setApiDrawerPrefillKey(key);
                    setApiDrawerOpen(true);
                  }}
                />
              )}

              {section === 'mcp' && (
                <McpGatewayPage
                  org={currentOrg}
                  cluster={currentCluster}
                  headerCtx={headerCtx}
                  resources={resources}
                  onChanged={refreshAll}
                />
              )}

              {section === 'routes' && (
                <RoutesPage
                  cluster={currentCluster}
                  headerCtx={headerCtx}
                  resources={resources}
                  validation={validation}
                  onChanged={refreshAll}
                />
              )}

              {section === 'fleet' && (
                <FleetPage
                  cluster={currentCluster}
                  headerCtx={headerCtx}
                  openConnectModal={connectModalOpen}
                  onConnectModalClose={() => setConnectModalOpen(false)}
                  onOpenConnectModal={() => setConnectModalOpen(true)}
                />
              )}

              {section === 'releases' && (
                <ReleasesPage
                  cluster={currentCluster}
                  headerCtx={headerCtx}
                  revisions={revisions}
                  validation={validation}
                  hasPendingChanges={hasPendingChanges}
                  onOpenPublish={() => setPublishOpen(true)}
                  onChanged={refreshAll}
                />
              )}

              {section === 'security' && me && (
                <SecurityPage
                  org={currentOrg}
                  cluster={currentCluster}
                  me={me}
                  headerCtx={headerCtx}
                />
              )}
            </div>
          )}

          {/* Quiet Floating Draft Publish Pill Bar (Zero friction across every page!) */}
          {currentCluster && hasPendingChanges && (
            <div className="sticky bottom-4 z-30 flex justify-center px-4 pointer-events-none">
              <div
                className="pointer-events-auto flex items-center gap-3 px-4 py-2 rounded-full shadow-xl text-[13px]"
                style={{
                  background: 'var(--ink)',
                  color: 'var(--sheet)',
                }}
              >
                <span
                  className="inline-block w-2 h-2 rounded-full shrink-0"
                  style={{ background: validation?.valid === false ? 'var(--danger-dot)' : 'var(--brand)' }}
                />
                <span>
                  {validation?.valid === false
                    ? `${validation.errors} verify error${validation.errors === 1 ? '' : 's'} in draft`
                    : 'Unpublished draft changes'}
                </span>
                <button
                  type="button"
                  onClick={() => setSection('routes')}
                  className="px-2 py-0.5 rounded-md border-0 cursor-pointer text-[12px] bg-transparent opacity-75 hover:opacity-100"
                  style={{ color: 'var(--sheet)' }}
                >
                  Inspect
                </button>
                <button
                  type="button"
                  disabled={!validation?.valid}
                  onClick={() => setPublishOpen(true)}
                  className="btn btn-sm btn-brand rounded-full px-3"
                >
                  <Rocket size={12} />
                  <span>Publish v{(revisions[0]?.revision || 0) + 1}</span>
                </button>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Persistent Cloudflare-style API Quick-Connect Drawer */}
      {currentCluster && (
        <ApiQuickConnectDrawer
          open={apiDrawerOpen}
          onClose={() => setApiDrawerOpen(false)}
          resources={resources}
          clusterSlug={currentCluster.slug}
          prefillKey={apiDrawerPrefillKey}
        />
      )}

      {/* Command Palette (⌘K) */}
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
        onOpenApi={() => {
          setApiDrawerPrefillKey(undefined);
          setApiDrawerOpen(true);
        }}
        onOpenPublish={() => setPublishOpen(true)}
      />

      {/* Publish Release Modal */}
      {currentCluster && (
        <Modal
          open={publishOpen}
          onClose={() => setPublishOpen(false)}
          title={`Publish Release v${(revisions[0]?.revision || 0) + 1}`}
          subtitle={`Compiles, verifies with shunt verify, and signs an immutable Ed25519 release for ${currentCluster.slug}.`}
        >
          <form onSubmit={handlePublish} className="space-y-4">
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Rollout Ring Selector</label>
              <input
                className="input-base mono"
                value={pubRing}
                onChange={(e) => setPubRing(e.target.value)}
                placeholder="*"
              />
              <div className="flex gap-2 mt-2">
                <button type="button" className="btn btn-sm" onClick={() => setPubRing('*')}>
                  * (All Nodes)
                </button>
                <button type="button" className="btn btn-sm" onClick={() => setPubRing('ring=canary')}>
                  ring=canary
                </button>
              </div>
            </div>
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Release Notes</label>
              <input
                className="input-base"
                value={pubNotes}
                onChange={(e) => setPubNotes(e.target.value)}
                placeholder="e.g. Add OpenAI & Anthropic providers with smart fallback"
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button type="button" className="btn" onClick={() => setPublishOpen(false)}>
                Cancel
              </button>
              <button type="submit" className="btn btn-brand" disabled={publishing || !validation?.valid}>
                <Rocket size={14} />
                <span>{publishing ? 'Publishing…' : 'Publish & Roll Out'}</span>
              </button>
            </div>
          </form>
        </Modal>
      )}

      {/* New Cluster Modal */}
      <Modal
        open={newClusterOpen}
        onClose={() => setNewClusterOpen(false)}
        title="New Cluster"
        subtitle="Each cluster manages its own AI providers, MCP servers, HTTP routes, signed releases, and fleet nodes."
      >
        <form onSubmit={handleCreateCluster} className="space-y-3.5">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Cluster Name</label>
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
              <label className="block text-[12.5px] font-medium mb-1">Slug</label>
              <input
                className="input-base mono text-[13px]"
                value={ncSlug}
                onChange={(e) => setNcSlug(slugify(e.target.value))}
                placeholder="staging-eu"
                required
              />
            </div>
          </div>
          <div>
            <label className="block text-[12.5px] font-medium mb-1">Environment</label>
            <select className="input-base" value={ncEnv} onChange={(e) => setNcEnv(e.target.value)}>
              <option value="production">production</option>
              <option value="staging">staging</option>
              <option value="development">development</option>
            </select>
          </div>
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
