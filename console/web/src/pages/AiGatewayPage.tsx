import React, { useEffect, useMemo, useState } from 'react';
import {
  ArrowDown,
  ArrowUp,
  Check,
  Code2,
  Cpu,
  DollarSign,
  Gauge,
  KeyRound,
  Lock,
  Plus,
  RefreshCw,
  Shield,
  Sparkles,
  Trash2,
  Zap,
} from 'lucide-react';
import {
  api,
  ApiProblemError,
  Cluster,
  ControlStateItem,
  formatRelativeTime,
  Organization,
  SecretMeta,
  slugify,
  TopologyResource,
} from '../lib/api';
import { generatePlaintextKey, keyDisplayPrefix, sha256Prefixed } from '../lib/crypto';
import {
  AI_PROVIDER_PRESETS,
  AiModelAliasView,
  AiModelTarget,
  AiProtectionView,
  AiProviderView,
  deleteAiModelEntry,
  deleteAiProvider,
  extractAiGatewayState,
  getPresetMeta,
  ProviderAuthKind,
  ProviderPresetId,
  ProviderPresetMeta,
  saveAiModelEntry,
  saveAiProtection,
  saveAiProvider,
} from '../lib/gateway';
import { ClusterHeaderContext, PageHeader } from '../components/PageHeader';
import {
  CopyButton,
  Drawer,
  EmptyState,
  FeatureToggleRow,
  Modal,
  SearchField,
  SegmentedTabs,
  StatusIndicator,
  TagPill,
  ToggleSwitch,
  useToast,
} from '../components/ui';

type AiTab = 'providers' | 'models' | 'keys' | 'protection';

interface VirtualKeyRecord {
  id: string;
  enabled: boolean;
  team?: string;
  key_prefix?: string;
  key_hashes: string[];
  allowed_models: string[];
  allowed_providers: string[];
  rpm?: number;
  tpm?: number;
  budget_usd?: number;
  budget_window?: 'daily' | 'weekly' | 'monthly';
}

function parseVirtualKeyItem(item: ControlStateItem): VirtualKeyRecord {
  const p = (item.payload && typeof item.payload === 'object' ? item.payload : {}) as Record<string, unknown>;
  return {
    id: item.item_key,
    enabled: p.enabled !== false,
    team: typeof p.team === 'string' ? p.team : undefined,
    key_prefix: typeof p.key_prefix === 'string' ? p.key_prefix : undefined,
    key_hashes: Array.isArray(p.key_hashes) ? p.key_hashes.map(String) : [],
    allowed_models: Array.isArray(p.allowed_models) ? p.allowed_models.map(String) : [],
    allowed_providers: Array.isArray(p.allowed_providers) ? p.allowed_providers.map(String) : [],
    rpm: typeof p.rpm === 'number' ? p.rpm : undefined,
    tpm: typeof p.tpm === 'number' ? p.tpm : undefined,
    budget_usd: typeof p.budget_usd === 'number' ? p.budget_usd : undefined,
    budget_window: (typeof p.budget_window === 'string' ? p.budget_window : 'monthly') as
      | 'daily'
      | 'weekly'
      | 'monthly',
  };
}

export function AiGatewayPage({
  org,
  cluster,
  headerCtx,
  resources,
  onChanged,
  onOpenApiWithKey,
}: {
  org: Organization;
  cluster: Cluster;
  headerCtx: ClusterHeaderContext;
  resources: TopologyResource[];
  onChanged: () => Promise<void>;
  onOpenApiWithKey: (plaintextKey: string) => void;
}) {
  const toast = useToast();
  const ai = useMemo(() => extractAiGatewayState(resources), [resources]);

  const [tab, setTab] = useState<AiTab>('providers');
  const [search, setSearch] = useState('');
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [vkeyItems, setVkeyItems] = useState<ControlStateItem[]>([]);
  const [busy, setBusy] = useState(false);

  // Provider Drawer State
  const [provDrawerOpen, setProvDrawerOpen] = useState(false);
  const [editingProviderSlug, setEditingProviderSlug] = useState<string | null>(null);
  const [presetStep, setPresetStep] = useState<'pick' | 'form'>('pick');
  const [presetSearch, setPresetSearch] = useState('');
  const [pPreset, setPPreset] = useState<ProviderPresetId>('openai');
  const [pSlug, setPSlug] = useState('openai');
  const [pBaseUrl, setPBaseUrl] = useState('https://api.openai.com');
  const [pAuthKind, setPAuthKind] = useState<ProviderAuthKind>('vault');
  const [pVaultMode, setPVaultMode] = useState<'new' | 'existing'>('new');
  const [pSecretInput, setPSecretInput] = useState('');
  const [pBackupSecretInput, setPBackupSecretInput] = useState('');
  const [pExistingSecretRef, setPExistingSecretRef] = useState('');
  const [pEnvVar, setPEnvVar] = useState('OPENAI_API_KEY');
  const [pAwsAccessRef, setPAwsAccessRef] = useState('env:AWS_ACCESS_KEY_ID');
  const [pAwsSecretRef, setPAwsSecretRef] = useState('env:AWS_SECRET_ACCESS_KEY');
  const [pRegion, setPRegion] = useState('us-east-1');
  const [pApiVersion, setPApiVersion] = useState('2024-10-21');
  const [pVertexProject, setPVertexProject] = useState('');
  const [pVertexLocation, setPVertexLocation] = useState('');
  const [pDropParams, setPDropParams] = useState(true);
  const [pSeedRule, setPSeedRule] = useState(true);

  // Model Alias / Rule Drawer State
  const [modelDrawerOpen, setModelDrawerOpen] = useState(false);
  const [editingModel, setEditingModel] = useState<{ name: string; kind: 'alias' | 'rule' } | null>(null);
  const [mKind, setMKind] = useState<'alias' | 'rule'>('alias');
  const [mName, setMName] = useState('smart');
  const [mStrategy, setMStrategy] = useState<'priority' | 'weighted' | 'latency' | 'cost'>('priority');
  const [mTargets, setMTargets] = useState<AiModelTarget[]>([]);

  // Virtual Key Drawer & One-Time Minted Modal State
  const [keyDrawerOpen, setKeyDrawerOpen] = useState(false);
  const [editingKey, setEditingKey] = useState<VirtualKeyRecord | null>(null);
  const [kId, setKId] = useState('');
  const [kTeam, setKTeam] = useState('engineering');
  const [kAllowedModels, setKAllowedModels] = useState<string[]>([]);
  const [kCustomModel, setKCustomModel] = useState('');
  const [kRpm, setKRpm] = useState('60');
  const [kTpm, setKTpm] = useState('100000');
  const [kBudgetUsd, setKBudgetUsd] = useState('100');
  const [kBudgetWindow, setKBudgetWindow] = useState<'daily' | 'weekly' | 'monthly'>('monthly');
  const [mintedKeyModal, setMintedKeyModal] = useState<{ id: string; plaintext: string } | null>(null);

  // Local draft of Protection toggles for responsive inline editing
  const [prot, setProt] = useState<AiProtectionView>(ai.protection);
  useEffect(() => {
    setProt(ai.protection);
  }, [ai.protection]);

  const loadAux = async () => {
    const [sec, vk] = await Promise.all([
      api.listSecrets(org.slug).catch(() => []),
      api.getNamespaceState(cluster.slug, 'ai.virtual_keys').catch(() => null),
    ]);
    setSecrets(sec);
    setVkeyItems(vk?.items || []);
  };

  useEffect(() => {
    loadAux();
  }, [org.slug, cluster.slug]);

  const virtualKeys = useMemo(() => vkeyItems.map(parseVirtualKeyItem), [vkeyItems]);

  const knownModelNames = useMemo(() => {
    const set = new Set<string>();
    for (const m of ai.models) set.add(m.name);
    for (const e of ai.exposedModels) set.add(e);
    for (const p of ai.providers) {
      for (const pop of getPresetMeta(p.preset).popularModels.slice(0, 2)) set.add(pop);
    }
    return Array.from(set);
  }, [ai]);

  // ---------------------------------------------------------------------------
  // Provider Handlers
  // ---------------------------------------------------------------------------

  const startNewProvider = (preset?: ProviderPresetMeta) => {
    setEditingProviderSlug(null);
    setPresetSearch('');
    if (preset) {
      applyPresetDefaults(preset);
      setPresetStep('form');
    } else {
      setPresetStep('pick');
    }
    setProvDrawerOpen(true);
  };

  const applyPresetDefaults = (preset: ProviderPresetMeta) => {
    setPPreset(preset.id);
    setPSlug(preset.defaultSlug);
    setPBaseUrl(preset.defaultBaseUrl);
    setPAuthKind(preset.defaultAuthKind);
    setPVaultMode('new');
    setPSecretInput('');
    setPBackupSecretInput('');
    setPExistingSecretRef(secrets[0] ? `secret:${secrets[0].slug}` : '');
    setPEnvVar(preset.defaultEnvVar || 'API_KEY');
    setPAwsAccessRef('env:AWS_ACCESS_KEY_ID');
    setPAwsSecretRef('env:AWS_SECRET_ACCESS_KEY');
    setPRegion('us-east-1');
    setPApiVersion('2024-10-21');
    setPVertexProject('');
    setPVertexLocation('');
    setPDropParams(true);
    setPSeedRule(true);
  };

  const startEditProvider = (p: AiProviderView) => {
    setEditingProviderSlug(p.slug);
    setPresetStep('form');
    setPPreset(p.preset);
    setPSlug(p.slug);
    setPBaseUrl(p.baseUrl);
    setPAuthKind(p.authKind);
    const firstRef = p.keyRefs[0] || '';
    if (firstRef.startsWith('secret:')) {
      setPVaultMode('existing');
      setPExistingSecretRef(firstRef);
      setPSecretInput('');
    } else if (firstRef.startsWith('env:')) {
      setPEnvVar(firstRef.slice(4));
      setPVaultMode('new');
      setPSecretInput('');
    } else {
      setPVaultMode('new');
      setPSecretInput('');
    }
    setPBackupSecretInput('');
    setPRegion(p.region || 'us-east-1');
    setPApiVersion(p.apiVersion || '2024-10-21');
    setPVertexProject(p.vertexProject || '');
    setPVertexLocation(p.vertexLocation || '');
    setPDropParams(p.dropParams);
    setPSeedRule(false);
    setProvDrawerOpen(true);
  };

  const handleSaveProvider = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanSlug = slugify(pSlug);
    if (!cleanSlug) return;
    setBusy(true);
    try {
      let keyRefs: string[] = [];
      if (pAuthKind === 'vault') {
        if (pVaultMode === 'new') {
          if (pSecretInput.trim()) {
            const secretSlug = slugify(`provider-${cleanSlug}-key`);
            const existingSec = secrets.find((s) => s.slug === secretSlug);
            await api.upsertSecret(
              org.slug,
              secretSlug,
              {
                description: `${getPresetMeta(pPreset).name} API key (${cleanSlug})`,
                scope_type: 'cluster',
                scope_id: cluster.id,
                delivery_mode: 'vault',
                value: pSecretInput.trim(),
              },
              existingSec?.etag
            );
            keyRefs.push(`secret:${secretSlug}`);
          } else if (editingProviderSlug) {
            const cur = ai.providers.find((x) => x.slug === editingProviderSlug);
            keyRefs = cur?.keyRefs || [];
          } else {
            toast.push('Paste an API key or switch to Env Var / Client BYOK mode.', 'error');
            setBusy(false);
            return;
          }

          if (pBackupSecretInput.trim()) {
            const backupSlug = slugify(`provider-${cleanSlug}-key-2`);
            const existingBackup = secrets.find((s) => s.slug === backupSlug);
            await api.upsertSecret(
              org.slug,
              backupSlug,
              {
                description: `${getPresetMeta(pPreset).name} backup pool key (${cleanSlug})`,
                scope_type: 'cluster',
                scope_id: cluster.id,
                delivery_mode: 'vault',
                value: pBackupSecretInput.trim(),
              },
              existingBackup?.etag
            );
            keyRefs.push(`secret:${backupSlug}`);
          }
        } else {
          if (!pExistingSecretRef) {
            toast.push('Select a Vault secret.', 'error');
            setBusy(false);
            return;
          }
          keyRefs.push(pExistingSecretRef);
        }
      } else if (pAuthKind === 'env') {
        const cleanEnv = pEnvVar.trim().replace(/^env:/, '');
        if (!cleanEnv) {
          toast.push('Enter an environment variable name (e.g. OPENAI_API_KEY).', 'error');
          setBusy(false);
          return;
        }
        keyRefs.push(`env:${cleanEnv}`);
      }

      const presetMeta = getPresetMeta(pPreset);
      await saveAiProvider(cluster.slug, resources, {
        slug: cleanSlug,
        preset: pPreset,
        baseUrl: pBaseUrl.trim(),
        authKind: pAuthKind,
        keyRefs,
        awsAccessKeyRef: pAuthKind === 'aws_sigv4' ? pAwsAccessRef.trim() : undefined,
        awsSecretKeyRef: pAuthKind === 'aws_sigv4' ? pAwsSecretRef.trim() : undefined,
        region: presetMeta.requiresRegion ? pRegion : undefined,
        apiVersion: presetMeta.requiresApiVersion ? pApiVersion : undefined,
        vertexProject: presetMeta.supportsVertex && pVertexProject.trim() ? pVertexProject : undefined,
        vertexLocation: presetMeta.supportsVertex && pVertexLocation.trim() ? pVertexLocation : undefined,
        dropParams: pDropParams,
        seedDefaultRule: !editingProviderSlug && pSeedRule,
      });

      toast.push(
        editingProviderSlug
          ? `Updated provider "${cleanSlug}" in draft`
          : `Added ${presetMeta.name} provider "${cleanSlug}" — ready to publish`
      );
      setProvDrawerOpen(false);
      await Promise.all([onChanged(), loadAux()]);
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  const handleDeleteProvider = async (p: AiProviderView) => {
    if (!window.confirm(`Remove AI provider "${p.slug}" and its upstream from draft?`)) return;
    setBusy(true);
    try {
      await deleteAiProvider(cluster.slug, resources, p.slug);
      toast.push(`Removed provider "${p.slug}"`);
      await onChanged();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Model / Fallback Chain Handlers
  // ---------------------------------------------------------------------------

  const startNewModel = () => {
    if (ai.providers.length === 0) {
      toast.push('Add at least one AI provider first.', 'info');
      setTab('providers');
      startNewProvider();
      return;
    }
    const firstProv = ai.providers[0];
    const firstPop = getPresetMeta(firstProv.preset).popularModels[0] || '';
    setEditingModel(null);
    setMKind('alias');
    setMName('smart');
    setMStrategy('priority');
    setMTargets([{ provider: firstProv.slug, upstream: firstProv.upstreamName, model: firstPop }]);
    setModelDrawerOpen(true);
  };

  const startEditModel = (m: AiModelAliasView) => {
    setEditingModel({ name: m.name, kind: m.kind });
    setMKind(m.kind);
    setMName(m.name);
    setMStrategy(m.strategy);
    setMTargets(m.targets.map((t) => ({ ...t })));
    setModelDrawerOpen(true);
  };

  const handleSaveModel = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mName.trim() || mTargets.length === 0) return;
    setBusy(true);
    try {
      await saveAiModelEntry(
        cluster.slug,
        resources,
        { name: mName.trim(), kind: mKind, strategy: mStrategy, targets: mTargets },
        editingModel || undefined
      );
      toast.push(`Saved model route "${mName.trim()}"`);
      setModelDrawerOpen(false);
      await onChanged();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  const handleDeleteModel = async (m: AiModelAliasView) => {
    if (!window.confirm(`Delete model route "${m.name}" from draft?`)) return;
    setBusy(true);
    try {
      await deleteAiModelEntry(cluster.slug, resources, { name: m.name, kind: m.kind });
      toast.push(`Deleted "${m.name}"`);
      await onChanged();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Virtual Keys Handlers (Live Channel 2 `ai.virtual_keys`)
  // ---------------------------------------------------------------------------

  const startNewKey = () => {
    setEditingKey(null);
    setKId('');
    setKTeam('engineering');
    setKAllowedModels([]);
    setKCustomModel('');
    setKRpm('60');
    setKTpm('100000');
    setKBudgetUsd('100');
    setKBudgetWindow('monthly');
    setKeyDrawerOpen(true);
  };

  const startEditKey = (k: VirtualKeyRecord) => {
    setEditingKey(k);
    setKId(k.id);
    setKTeam(k.team || '');
    setKAllowedModels(k.allowed_models);
    setKCustomModel('');
    setKRpm(k.rpm ? String(k.rpm) : '');
    setKTpm(k.tpm ? String(k.tpm) : '');
    setKBudgetUsd(k.budget_usd ? String(k.budget_usd) : '');
    setKBudgetWindow(k.budget_window || 'monthly');
    setKeyDrawerOpen(true);
  };

  const handleSaveKey = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanId = editingKey ? editingKey.id : slugify(kId || `vk-${kTeam || 'app'}-${Date.now().toString(36).slice(-4)}`);
    setBusy(true);
    try {
      let plaintext: string | null = null;
      let keyHashes = editingKey?.key_hashes || [];
      let prefix = editingKey?.key_prefix;

      if (!editingKey) {
        plaintext = generatePlaintextKey('sk-shunt-');
        const hash = await sha256Prefixed(plaintext);
        keyHashes = [hash];
        prefix = keyDisplayPrefix(plaintext);
      }

      const payload: Record<string, unknown> = {
        id: cleanId,
        enabled: editingKey ? editingKey.enabled : true,
        org: org.slug,
        team: kTeam.trim() || undefined,
        key_prefix: prefix,
        key_hashes: keyHashes,
        allowed_models: kAllowedModels,
        rpm: Number(kRpm) > 0 ? Number(kRpm) : undefined,
        tpm: Number(kTpm) > 0 ? Number(kTpm) : undefined,
        budget_usd: Number(kBudgetUsd) > 0 ? Number(kBudgetUsd) : undefined,
        budget_window: kBudgetWindow,
      };

      await api.upsertStateItem(cluster.slug, 'ai.virtual_keys', cleanId, payload);
      setKeyDrawerOpen(false);
      await loadAux();
      if (plaintext) {
        setMintedKeyModal({ id: cleanId, plaintext });
        toast.push(`Minted virtual key "${cleanId}" and synced fleet-wide`);
      } else {
        toast.push(`Updated virtual key "${cleanId}" across fleet`);
      }
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  const handleToggleKey = async (k: VirtualKeyRecord, enabled: boolean) => {
    try {
      const existingItem = vkeyItems.find((i) => i.item_key === k.id);
      const existingPayload = (
        existingItem?.payload && typeof existingItem.payload === 'object' ? existingItem.payload : {}
      ) as Record<string, unknown>;
      await api.upsertStateItem(cluster.slug, 'ai.virtual_keys', k.id, {
        ...existingPayload,
        enabled,
      });
      toast.push(`${enabled ? 'Enabled' : 'Disabled'} key "${k.id}" across fleet`);
      await loadAux();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  const handleRevokeKey = async (k: VirtualKeyRecord) => {
    if (!window.confirm(`Immediately revoke virtual key "${k.id}" across 100% of connected nodes?`)) return;
    try {
      await api.deleteStateItem(cluster.slug, 'ai.virtual_keys', k.id);
      toast.push(`Revoked "${k.id}" fleet-wide`);
      await loadAux();
    } catch (err) {
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    }
  };

  // ---------------------------------------------------------------------------
  // Protection Toggle Handlers (Cloudflare-style immediate save to draft)
  // ---------------------------------------------------------------------------

  const persistProtection = async (next: AiProtectionView, label: string) => {
    setProt(next);
    setBusy(true);
    try {
      await saveAiProtection(cluster.slug, resources, next);
      toast.push(label);
      await onChanged();
    } catch (err) {
      setProt(ai.protection);
      toast.push(err instanceof ApiProblemError ? err.message : String(err), 'error');
    } finally {
      setBusy(false);
    }
  };

  // Filtered lists
  const q = search.trim().toLowerCase();
  const filteredProviders = ai.providers.filter(
    (p) => !q || p.slug.includes(q) || p.preset.includes(q) || p.baseUrl.toLowerCase().includes(q)
  );
  const filteredModels = ai.models.filter(
    (m) =>
      !q ||
      m.name.toLowerCase().includes(q) ||
      m.targets.some((t) => t.provider.includes(q) || (t.model || '').toLowerCase().includes(q))
  );
  const filteredKeys = virtualKeys.filter(
    (k) => !q || k.id.toLowerCase().includes(q) || (k.team || '').toLowerCase().includes(q)
  );

  const primaryAction =
    tab === 'providers' ? (
      <button type="button" className="btn btn-primary h-8" onClick={() => startNewProvider()}>
        <Plus size={14} />
        <span>Add provider</span>
      </button>
    ) : tab === 'models' ? (
      <button type="button" className="btn btn-primary h-8" onClick={startNewModel}>
        <Plus size={14} />
        <span>New model</span>
      </button>
    ) : tab === 'keys' ? (
      <button type="button" className="btn btn-primary h-8" onClick={startNewKey}>
        <Plus size={14} />
        <span>New key</span>
      </button>
    ) : null;

  const activePresetMeta = getPresetMeta(pPreset);
  const filteredPresets = AI_PROVIDER_PRESETS.filter(
    (p) =>
      !presetSearch.trim() ||
      p.name.toLowerCase().includes(presetSearch.toLowerCase()) ||
      p.tagline.toLowerCase().includes(presetSearch.toLowerCase())
  );

  return (
    <div>
      <PageHeader
        title="AI Gateway"
        badge={
          ai.providers.length > 0 ? (
            <TagPill mono dot="brand">
              {ai.routePath}
            </TagPill>
          ) : undefined
        }
        ctx={headerCtx}
        primaryAction={primaryAction}
        controlsLeft={
          <SegmentedTabs
            value={tab}
            onChange={setTab}
            items={[
              { id: 'providers', label: 'Providers', count: ai.providers.length },
              { id: 'models', label: 'Models', count: ai.models.length },
              { id: 'keys', label: 'Virtual Keys', count: virtualKeys.length },
              { id: 'protection', label: 'Protection' },
            ]}
          />
        }
        controlsRight={
          tab !== 'protection' ? (
            <SearchField
              value={search}
              onChange={setSearch}
              placeholder={
                tab === 'providers'
                  ? 'Search providers'
                  : tab === 'models'
                    ? 'Search models'
                    : 'Search keys'
              }
            />
          ) : undefined
        }
      />

      {/* =====================================================================
          TAB 1: PROVIDERS (Cloudflare Provider Keys × Entire Editorial Rows)
          ===================================================================== */}
      {tab === 'providers' && (
        <div>
          {ai.providers.length === 0 ? (
            <div className="px-6 py-10 max-w-3xl mx-auto">
              <div className="text-center mb-8">
                <div className="icon-tile mx-auto mb-3" style={{ width: 40, height: 40, borderRadius: 11 }}>
                  <Sparkles size={18} style={{ color: 'var(--brand)' }} />
                </div>
                <h2 className="m-0 text-[16px] font-semibold tracking-tight">
                  Connect your first AI provider
                </h2>
                <p className="m-0 mt-1 text-[13px]" style={{ color: 'var(--ink-muted)' }}>
                  Shunt auto-wires your unified <code className="mono">/v1</code> endpoint for OpenAI, Anthropic Messages, Responses, and Embeddings with zero manual JSON.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
                {AI_PROVIDER_PRESETS.slice(0, 6).map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => startNewProvider(preset)}
                    className="card-quiet p-3.5 text-left cursor-pointer transition-colors hover:bg-[var(--surface-subtle)] flex items-start gap-3"
                  >
                    <div
                      className="icon-tile mono text-[11px] font-semibold"
                      style={{ color: 'var(--ink)' }}
                    >
                      <span
                        className="inline-block w-2 h-2 rounded-full mr-0.5"
                        style={{ background: preset.accentDot }}
                      />
                      {preset.short}
                    </div>
                    <div className="min-w-0">
                      <div className="text-[13.5px] font-semibold" style={{ color: 'var(--ink)' }}>
                        {preset.name}
                      </div>
                      <div className="text-[12px] mt-0.5 line-clamp-2" style={{ color: 'var(--ink-muted)' }}>
                        {preset.tagline}
                      </div>
                    </div>
                  </button>
                ))}
              </div>

              <div className="mt-5 text-center">
                <button type="button" className="btn btn-sm" onClick={() => startNewProvider()}>
                  <Plus size={13} />
                  <span>Browse all {AI_PROVIDER_PRESETS.length} providers (DeepSeek, Mistral, Ollama, vLLM…)</span>
                </button>
              </div>
            </div>
          ) : filteredProviders.length === 0 ? (
            <EmptyState
              icon={<Sparkles size={17} />}
              title="No matching providers"
              description="Try clearing your search query or add a new provider."
            />
          ) : (
            <div>
              {filteredProviders.map((p) => {
                const meta = getPresetMeta(p.preset);
                return (
                  <div
                    key={p.slug}
                    className="row-item row-item-clickable"
                    onClick={() => startEditProvider(p)}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="icon-tile mono text-[11px] font-semibold">
                        <span
                          className="inline-block w-1.5 h-1.5 rounded-full mr-0.5"
                          style={{ background: meta.accentDot }}
                        />
                        {meta.short}
                      </div>
                      <span className="mono text-[12px] w-24 shrink-0 truncate" style={{ color: 'var(--ink-muted)' }}>
                        {p.slug}
                      </span>
                      <span className="text-[14px] font-medium truncate">{meta.name}</span>
                      <TagPill dot={p.authKind === 'none' ? 'neutral' : 'ok'}>
                        {p.authSummary}
                      </TagPill>
                      {p.region && <TagPill mono>{p.region}</TagPill>}
                      {p.dropParams && <TagPill>drop_params</TagPill>}
                    </div>

                    <div
                      className="flex items-center gap-5 shrink-0"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <span className="hidden lg:inline mono text-[12px] max-w-[240px] truncate" style={{ color: 'var(--ink-muted)' }}>
                        {p.baseUrl.replace(/^https?:\/\//, '')}
                      </span>
                      <StatusIndicator tone="ok" label="Ready" />
                      <button
                        type="button"
                        className="btn-ghost p-1.5"
                        style={{ color: 'var(--ink-muted)' }}
                        title={`Remove ${p.slug}`}
                        onClick={() => handleDeleteProvider(p)}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* =====================================================================
          TAB 2: MODELS & FALLBACK ROUTING
          ===================================================================== */}
      {tab === 'models' && (
        <div>
          {filteredModels.length === 0 ? (
            <EmptyState
              icon={<Cpu size={17} />}
              title={ai.providers.length === 0 ? 'Add a provider first' : 'No model aliases or rules yet'}
              description={
                ai.providers.length === 0
                  ? 'Connect OpenAI, Anthropic, Bedrock, or another provider before designing fallback chains.'
                  : 'Create a logical model alias like "smart" with automatic failover across providers, or a wildcard rule like "claude-*".'
              }
              action={
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={ai.providers.length === 0 ? () => startNewProvider() : startNewModel}
                >
                  <Plus size={14} />
                  <span>{ai.providers.length === 0 ? 'Add Provider' : 'New Model Route'}</span>
                </button>
              }
            />
          ) : (
            <div>
              {filteredModels.map((m) => (
                <div
                  key={`${m.kind}:${m.name}`}
                  className="row-item row-item-clickable"
                  onClick={() => startEditModel(m)}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="icon-tile">
                      <Cpu size={14} style={{ color: m.kind === 'alias' ? 'var(--brand)' : 'var(--ink-secondary)' }} />
                    </div>
                    <span className="mono text-[13.5px] font-semibold shrink-0">{m.name}</span>
                    <TagPill dot={m.kind === 'alias' ? 'brand' : 'info'}>
                      {m.kind === 'alias' ? 'alias' : 'pattern'}
                    </TagPill>
                    <span className="mono text-[12.5px] truncate" style={{ color: 'var(--ink-secondary)' }}>
                      {m.targets
                        .map((t) => `${t.provider}${t.model ? `/${t.model}` : ''}`)
                        .join(' → ')}
                    </span>
                  </div>
                  <div
                    className="flex items-center gap-4 shrink-0"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <TagPill>{m.strategy}</TagPill>
                    <span className="hidden sm:inline text-[12px] tabular" style={{ color: 'var(--ink-muted)' }}>
                      {m.targets.length} target{m.targets.length === 1 ? '' : 's'}
                    </span>
                    <button
                      type="button"
                      className="btn-ghost p-1.5"
                      style={{ color: 'var(--ink-muted)' }}
                      title={`Delete ${m.name}`}
                      onClick={() => handleDeleteModel(m)}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* =====================================================================
          TAB 3: VIRTUAL KEYS (Channel 2 Instant Sync!)
          ===================================================================== */}
      {tab === 'keys' && (
        <div>
          {!ai.protection.virtualKeysEnabled && (
            <div
              className="px-6 py-3 flex flex-wrap items-center justify-between gap-3 text-[13px]"
              style={{
                background: 'var(--brand-soft)',
                borderBottom: '1px solid var(--brand-border)',
              }}
            >
              <div className="flex items-center gap-2">
                <Lock size={14} style={{ color: 'var(--brand)' }} />
                <span>
                  Virtual Key Authentication is currently <strong>off</strong> on <code>{ai.routePath}</code>. Enable it to enforce these keys fleet-wide.
                </span>
              </div>
              {ai.providers.length > 0 && (
                <button
                  type="button"
                  className="btn btn-sm btn-brand"
                  disabled={busy}
                  onClick={() =>
                    persistProtection(
                      { ...prot, virtualKeysEnabled: true },
                      'Enabled Virtual Key Auth (synced via ai.virtual_keys)'
                    )
                  }
                >
                  Enable Virtual Key Auth
                </button>
              )}
            </div>
          )}

          {filteredKeys.length === 0 ? (
            <EmptyState
              icon={<KeyRound size={17} />}
              title="No virtual keys minted yet"
              description="Issue scoped sk-shunt-… keys with per-key model allowlists, RPM/TPM limits, and USD spend caps. Keys sync to 100% of nodes in milliseconds and survive config rollbacks."
              action={
                <button type="button" className="btn btn-primary" onClick={startNewKey}>
                  <Plus size={14} />
                  <span>Mint First Virtual Key</span>
                </button>
              }
            />
          ) : (
            <div>
              {filteredKeys.map((k) => {
                const rawItem = vkeyItems.find((i) => i.item_key === k.id);
                return (
                  <div
                    key={k.id}
                    className="row-item row-item-clickable"
                    onClick={() => startEditKey(k)}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="icon-tile">
                        <KeyRound size={14} style={{ color: k.enabled ? 'var(--brand)' : 'var(--ink-muted)' }} />
                      </div>
                      <span className="mono text-[13px] font-semibold shrink-0">{k.id}</span>
                      {k.key_prefix && (
                        <span className="hidden md:inline mono text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                          {k.key_prefix}
                        </span>
                      )}
                      {k.team && <TagPill dot="info">{k.team}</TagPill>}
                      <TagPill dot={k.allowed_models.length > 0 ? 'brand' : 'neutral'}>
                        {k.allowed_models.length > 0
                          ? k.allowed_models.slice(0, 2).join(', ') +
                            (k.allowed_models.length > 2 ? ` +${k.allowed_models.length - 2}` : '')
                          : 'all models'}
                      </TagPill>
                    </div>

                    <div
                      className="flex items-center gap-4 shrink-0 tabular"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <span className="hidden lg:inline text-[12px]" style={{ color: 'var(--ink-muted)' }}>
                        {[
                          k.rpm ? `${k.rpm} rpm` : null,
                          k.budget_usd ? `$${k.budget_usd}/${k.budget_window || 'mo'}` : null,
                        ]
                          .filter(Boolean)
                          .join(' · ') || 'unlimited'}
                      </span>
                      <StatusIndicator
                        tone={k.enabled ? 'ok' : 'danger'}
                        label={k.enabled ? 'Active' : 'Disabled'}
                      />
                      <ToggleSwitch
                        checked={k.enabled}
                        onChange={(next) => handleToggleKey(k, next)}
                        label={`Toggle ${k.id}`}
                      />
                      {rawItem && (
                        <span className="hidden xl:inline text-[12px] w-14 text-right" style={{ color: 'var(--ink-muted)' }}>
                          {formatRelativeTime(rawItem.updated_at)}
                        </span>
                      )}
                      <button
                        type="button"
                        className="btn-ghost p-1.5"
                        style={{ color: 'var(--ink-muted)' }}
                        title={`Revoke ${k.id}`}
                        onClick={() => handleRevokeKey(k)}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* =====================================================================
          TAB 4: PROTECTION (Cloudflare Progressive-Disclosure Toggle Rows)
          ===================================================================== */}
      {tab === 'protection' && (
        <div>
          {ai.providers.length === 0 ? (
            <EmptyState
              icon={<Shield size={17} />}
              title="Add an AI provider to configure protection"
              description="Once at least one provider is connected, toggle virtual key auth, automatic failover, rate limits, spend budgets, response caching, and PII guardrails here."
              action={
                <button type="button" className="btn btn-primary" onClick={() => startNewProvider()}>
                  <Plus size={14} />
                  <span>Add AI Provider</span>
                </button>
              }
            />
          ) : (
            <div>
              <FeatureToggleRow
                icon={<KeyRound size={15} />}
                title="Virtual Key Authentication"
                description="Require sk-shunt-… keys on /v1 (Bearer or x-api-key), strip client keys before upstream, and sync keys live over Channel 2."
                tag="Instant Sync"
                checked={prot.virtualKeysEnabled}
                disabled={busy}
                onToggle={(v) =>
                  persistProtection(
                    { ...prot, virtualKeysEnabled: v },
                    v ? 'Enabled Virtual Key Authentication' : 'Disabled Virtual Key Authentication'
                  )
                }
              />

              <FeatureToggleRow
                icon={<RefreshCw size={15} />}
                title="Automatic Failover & Circuit Breaker"
                description="Retry 429/5xx provider errors across your model fallback chain with automatic cooldowns."
                tag={`${Math.round(prot.failoverCooldownMs / 1000)}s cooldown`}
                checked={prot.failoverEnabled}
                disabled={busy}
                onToggle={(v) =>
                  persistProtection(
                    { ...prot, failoverEnabled: v },
                    v ? 'Enabled automatic failover' : 'Disabled automatic failover'
                  )
                }
              >
                <div className="flex flex-wrap items-end gap-3">
                  <div className="w-44">
                    <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                      Cooldown (ms)
                    </label>
                    <input
                      type="number"
                      className="input-base mono text-[13px]"
                      value={prot.failoverCooldownMs}
                      onChange={(e) => setProt({ ...prot, failoverCooldownMs: Number(e.target.value) })}
                    />
                  </div>
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    disabled={busy}
                    onClick={() => persistProtection(prot, 'Saved failover settings')}
                  >
                    Save
                  </button>
                </div>
              </FeatureToggleRow>

              <FeatureToggleRow
                icon={<Gauge size={15} />}
                title="Token & Request Rate Limiting"
                description="Enforce RPM and token-aware TPM ceilings per virtual key with post-response usage reconciliation."
                tag={`${prot.rateLimitRpm} rpm`}
                checked={prot.rateLimitEnabled}
                disabled={busy}
                onToggle={(v) =>
                  persistProtection(
                    { ...prot, rateLimitEnabled: v },
                    v ? 'Enabled token rate limiting' : 'Disabled token rate limiting'
                  )
                }
              >
                <div className="flex flex-wrap items-end gap-3">
                  <div className="w-36">
                    <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                      Default RPM
                    </label>
                    <input
                      type="number"
                      className="input-base mono text-[13px]"
                      value={prot.rateLimitRpm}
                      onChange={(e) => setProt({ ...prot, rateLimitRpm: Number(e.target.value) })}
                    />
                  </div>
                  <div className="w-40">
                    <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                      Default TPM
                    </label>
                    <input
                      type="number"
                      className="input-base mono text-[13px]"
                      value={prot.rateLimitTpm}
                      onChange={(e) => setProt({ ...prot, rateLimitTpm: Number(e.target.value) })}
                    />
                  </div>
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    disabled={busy}
                    onClick={() => persistProtection(prot, 'Saved token rate limits')}
                  >
                    Save
                  </button>
                </div>
              </FeatureToggleRow>

              <FeatureToggleRow
                icon={<DollarSign size={15} />}
                title="Spend Budgets & Pricing"
                description="Cap rolling USD spend per virtual key using Shunt's built-in frontier & open model pricing table."
                tag={`$${prot.budgetDefaultUsd}/${prot.budgetWindow}`}
                checked={prot.budgetEnabled}
                disabled={busy}
                onToggle={(v) =>
                  persistProtection(
                    { ...prot, budgetEnabled: v },
                    v ? 'Enabled spend budgets' : 'Disabled spend budgets'
                  )
                }
              >
                <div className="flex flex-wrap items-end gap-3">
                  <div className="w-36">
                    <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                      Default Cap (USD)
                    </label>
                    <input
                      type="number"
                      step="0.5"
                      className="input-base mono text-[13px]"
                      value={prot.budgetDefaultUsd}
                      onChange={(e) => setProt({ ...prot, budgetDefaultUsd: Number(e.target.value) })}
                    />
                  </div>
                  <div className="w-36">
                    <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                      Window
                    </label>
                    <select
                      className="input-base text-[13px]"
                      value={prot.budgetWindow}
                      onChange={(e) =>
                        setProt({ ...prot, budgetWindow: e.target.value as AiProtectionView['budgetWindow'] })
                      }
                    >
                      <option value="daily">Daily</option>
                      <option value="weekly">Weekly</option>
                      <option value="monthly">Monthly</option>
                    </select>
                  </div>
                  <div className="w-32">
                    <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                      Enforcement
                    </label>
                    <select
                      className="input-base text-[13px]"
                      value={prot.budgetMode}
                      onChange={(e) =>
                        setProt({ ...prot, budgetMode: e.target.value as 'hard' | 'soft' })
                      }
                    >
                      <option value="hard">Hard (429)</option>
                      <option value="soft">Soft warn</option>
                    </select>
                  </div>
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    disabled={busy}
                    onClick={() => persistProtection(prot, 'Saved spend budget policy')}
                  >
                    Save
                  </button>
                </div>
              </FeatureToggleRow>

              <FeatureToggleRow
                icon={<Zap size={15} />}
                title="Response Caching"
                description="Serve identical deterministic prompts & embeddings directly from Shunt's in-memory LRU cache to cut latency and cost."
                tag={`${prot.cacheTtlSecs}s TTL`}
                checked={prot.cacheEnabled}
                disabled={busy}
                onToggle={(v) =>
                  persistProtection(
                    { ...prot, cacheEnabled: v },
                    v ? 'Enabled AI response caching' : 'Disabled AI response caching'
                  )
                }
              >
                <div className="flex flex-wrap items-end gap-4">
                  <div className="w-36">
                    <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                      Cache TTL (sec)
                    </label>
                    <input
                      type="number"
                      className="input-base mono text-[13px]"
                      value={prot.cacheTtlSecs}
                      onChange={(e) => setProt({ ...prot, cacheTtlSecs: Number(e.target.value) })}
                    />
                  </div>
                  <label className="flex items-center gap-2 text-[13px] pb-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={prot.cacheStreaming}
                      onChange={(e) => setProt({ ...prot, cacheStreaming: e.target.checked })}
                    />
                    <span>Cache streaming SSE responses</span>
                  </label>
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    disabled={busy}
                    onClick={() => persistProtection(prot, 'Saved response cache settings')}
                  >
                    Save
                  </button>
                </div>
              </FeatureToggleRow>

              <FeatureToggleRow
                icon={<Shield size={15} />}
                title="Guardrails & PII Redaction"
                description="Inline high-speed detection for emails, SSNs, credit cards, leaked API keys, and prompt injections on prompts & responses."
                tag={prot.guardrailsAction}
                checked={prot.guardrailsEnabled}
                disabled={busy}
                onToggle={(v) =>
                  persistProtection(
                    { ...prot, guardrailsEnabled: v },
                    v ? 'Enabled AI guardrails' : 'Disabled AI guardrails'
                  )
                }
              >
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    {[
                      { id: 'pii', label: 'PII (Email, SSN, Cards)' },
                      { id: 'secrets', label: 'API Keys & Secrets' },
                      { id: 'prompt_injection', label: 'Prompt Injection' },
                    ].map((preset) => {
                      const active = prot.guardrailsPresets.includes(preset.id);
                      return (
                        <button
                          key={preset.id}
                          type="button"
                          onClick={() => {
                            const nextPresets = active
                              ? prot.guardrailsPresets.filter((x) => x !== preset.id)
                              : [...prot.guardrailsPresets, preset.id];
                            setProt({ ...prot, guardrailsPresets: nextPresets });
                          }}
                          className="btn btn-sm"
                          style={{
                            background: active ? 'var(--brand-soft)' : 'var(--sheet)',
                            borderColor: active ? 'var(--brand-border)' : 'var(--border)',
                            color: active ? 'var(--brand)' : 'var(--ink-secondary)',
                          }}
                        >
                          {active && <Check size={12} />}
                          <span>{preset.label}</span>
                        </button>
                      );
                    })}
                  </div>
                  <div className="flex flex-wrap items-end gap-3">
                    <div className="w-40">
                      <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                        Action on Match
                      </label>
                      <select
                        className="input-base text-[13px]"
                        value={prot.guardrailsAction}
                        onChange={(e) =>
                          setProt({
                            ...prot,
                            guardrailsAction: e.target.value as 'redact' | 'block' | 'warn',
                          })
                        }
                      >
                        <option value="redact">Redact inline</option>
                        <option value="block">Block request (400)</option>
                        <option value="warn">Warn &amp; log only</option>
                      </select>
                    </div>
                    <button
                      type="button"
                      className="btn btn-sm btn-primary"
                      disabled={busy}
                      onClick={() => persistProtection(prot, 'Saved guardrail rules')}
                    >
                      Save
                    </button>
                  </div>
                </div>
              </FeatureToggleRow>
            </div>
          )}
        </div>
      )}

      {/* =====================================================================
          ADD / EDIT PROVIDER SLIDE-OVER DRAWER
          ===================================================================== */}
      <Drawer
        open={provDrawerOpen}
        onClose={() => setProvDrawerOpen(false)}
        title={
          editingProviderSlug
            ? `Edit Provider · ${editingProviderSlug}`
            : presetStep === 'pick'
              ? 'Add AI Provider'
              : `Configure ${activePresetMeta.name}`
        }
        subtitle={
          presetStep === 'pick'
            ? 'Choose from Shunt’s 17+ built-in provider presets or connect any OpenAI-compatible server.'
            : activePresetMeta.tagline
        }
        widthClass="max-w-xl"
      >
        {presetStep === 'pick' ? (
          <div className="space-y-4">
            <SearchField
              value={presetSearch}
              onChange={setPresetSearch}
              placeholder="Filter providers (OpenAI, Anthropic, Bedrock, Ollama…)"
              className="w-full"
            />
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {filteredPresets.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  onClick={() => {
                    applyPresetDefaults(preset);
                    setPresetStep('form');
                  }}
                  className="card-quiet p-3 text-left cursor-pointer hover:bg-[var(--surface-subtle)] transition-colors flex items-start gap-2.5"
                >
                  <div className="icon-tile mono text-[11px] font-semibold">
                    <span
                      className="inline-block w-1.5 h-1.5 rounded-full mr-0.5"
                      style={{ background: preset.accentDot }}
                    />
                    {preset.short}
                  </div>
                  <div className="min-w-0">
                    <div className="text-[13.5px] font-semibold">{preset.name}</div>
                    <div className="text-[11.5px] mt-0.5 line-clamp-2" style={{ color: 'var(--ink-muted)' }}>
                      {preset.tagline}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        ) : (
          <form onSubmit={handleSaveProvider} className="space-y-4">
            {!editingProviderSlug && (
              <button
                type="button"
                className="btn-ghost px-2 py-1 -ml-2 text-[12.5px]"
                onClick={() => setPresetStep('pick')}
              >
                ← Change provider preset
              </button>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <div>
                <label className="block text-[12.5px] font-medium mb-1">Provider ID</label>
                <input
                  className="input-base mono"
                  value={pSlug}
                  disabled={Boolean(editingProviderSlug)}
                  onChange={(e) => setPSlug(slugify(e.target.value))}
                  required
                />
              </div>
              <div>
                <label className="block text-[12.5px] font-medium mb-1">Base Endpoint URL</label>
                <input
                  className="input-base mono text-[13px]"
                  value={pBaseUrl}
                  onChange={(e) => setPBaseUrl(e.target.value)}
                  placeholder="https://api.openai.com"
                  required
                />
              </div>
            </div>

            {/* Auth Configuration */}
            <div className="card-subtle p-4 space-y-3.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="text-[12.5px] font-semibold">Authentication</label>
                <SegmentedTabs
                  value={pAuthKind}
                  onChange={setPAuthKind}
                  items={[
                    { id: 'vault', label: 'Vault' },
                    { id: 'env', label: 'Env Var' },
                    { id: 'aws_sigv4', label: 'AWS SigV4' },
                    { id: 'client_passthrough', label: 'BYOK' },
                    { id: 'none', label: 'None' },
                  ]}
                />
              </div>

              {pAuthKind === 'vault' && (
                <div className="space-y-3">
                  {secrets.length > 0 && (
                    <div className="flex items-center gap-4 text-[12.5px]">
                      <label className="flex items-center gap-1.5 cursor-pointer">
                        <input
                          type="radio"
                          checked={pVaultMode === 'new'}
                          onChange={() => setPVaultMode('new')}
                        />
                        <span>Paste new key (auto-encrypt)</span>
                      </label>
                      <label className="flex items-center gap-1.5 cursor-pointer">
                        <input
                          type="radio"
                          checked={pVaultMode === 'existing'}
                          onChange={() => setPVaultMode('existing')}
                        />
                        <span>Reuse Vault secret</span>
                      </label>
                    </div>
                  )}

                  {pVaultMode === 'new' ? (
                    <>
                      <div>
                        <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                          Primary API Key {editingProviderSlug ? '(leave blank to keep current)' : '(encrypted with AES-256-GCM)'}
                        </label>
                        <input
                          type="password"
                          className="input-base mono"
                          value={pSecretInput}
                          onChange={(e) => setPSecretInput(e.target.value)}
                          placeholder="sk-…"
                        />
                      </div>
                      <div>
                        <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                          Backup API Key (optional — enables automatic 429 pool rotation)
                        </label>
                        <input
                          type="password"
                          className="input-base mono"
                          value={pBackupSecretInput}
                          onChange={(e) => setPBackupSecretInput(e.target.value)}
                          placeholder="Optional second key for multi-key pool"
                        />
                      </div>
                    </>
                  ) : (
                    <div>
                      <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                        Select Vault Secret
                      </label>
                      <select
                        className="input-base mono text-[13px]"
                        value={pExistingSecretRef}
                        onChange={(e) => setPExistingSecretRef(e.target.value)}
                      >
                        <option value="">Choose secret…</option>
                        {secrets.map((s) => (
                          <option key={s.id} value={`secret:${s.slug}`}>
                            secret:{s.slug} {s.description ? `— ${s.description}` : ''}
                          </option>
                        ))}
                      </select>
                    </div>
                  )}
                </div>
              )}

              {pAuthKind === 'env' && (
                <div>
                  <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                    Node Environment Variable (resolved in data-plane memory)
                  </label>
                  <input
                    className="input-base mono"
                    value={pEnvVar}
                    onChange={(e) => setPEnvVar(e.target.value)}
                    placeholder="OPENAI_API_KEY"
                    required
                  />
                </div>
              )}

              {pAuthKind === 'aws_sigv4' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                      Access Key Ref
                    </label>
                    <input
                      className="input-base mono text-[12.5px]"
                      value={pAwsAccessRef}
                      onChange={(e) => setPAwsAccessRef(e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                      Secret Key Ref
                    </label>
                    <input
                      className="input-base mono text-[12.5px]"
                      value={pAwsSecretRef}
                      onChange={(e) => setPAwsSecretRef(e.target.value)}
                    />
                  </div>
                </div>
              )}

              {pAuthKind === 'client_passthrough' && (
                <p className="m-0 text-[12.5px]" style={{ color: 'var(--ink-muted)' }}>
                  Forwards the caller’s own API key directly into {activePresetMeta.name}’s expected auth header.
                </p>
              )}

              {pAuthKind === 'none' && (
                <p className="m-0 text-[12.5px]" style={{ color: 'var(--ink-muted)' }}>
                  No upstream auth header will be sent (ideal for local Ollama or private vLLM instances).
                </p>
              )}
            </div>

            {/* Cloud-specific fields when applicable */}
            {activePresetMeta.requiresRegion && (
              <div>
                <label className="block text-[12.5px] font-medium mb-1">AWS Region</label>
                <input
                  className="input-base mono"
                  value={pRegion}
                  onChange={(e) => setPRegion(e.target.value)}
                  placeholder="us-east-1"
                />
              </div>
            )}

            {activePresetMeta.requiresApiVersion && (
              <div>
                <label className="block text-[12.5px] font-medium mb-1">Azure API Version</label>
                <input
                  className="input-base mono"
                  value={pApiVersion}
                  onChange={(e) => setPApiVersion(e.target.value)}
                  placeholder="2024-10-21"
                />
              </div>
            )}

            {activePresetMeta.supportsVertex && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                    GCP Vertex Project (optional)
                  </label>
                  <input
                    className="input-base mono text-[13px]"
                    value={pVertexProject}
                    onChange={(e) => setPVertexProject(e.target.value)}
                    placeholder="my-gcp-project"
                  />
                </div>
                <div>
                  <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--ink-secondary)' }}>
                    Vertex Location (optional)
                  </label>
                  <input
                    className="input-base mono text-[13px]"
                    value={pVertexLocation}
                    onChange={(e) => setPVertexLocation(e.target.value)}
                    placeholder="us-central1"
                  />
                </div>
              </div>
            )}

            <div className="space-y-2 pt-1">
              <label className="flex items-center gap-2 text-[13px] cursor-pointer">
                <input
                  type="checkbox"
                  checked={pDropParams}
                  onChange={(e) => setPDropParams(e.target.checked)}
                />
                <span>Drop unsupported cross-provider request params (<code>drop_params</code>)</span>
              </label>
              {!editingProviderSlug && activePresetMeta.defaultModelPattern && (
                <label className="flex items-center gap-2 text-[13px] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={pSeedRule}
                    onChange={(e) => setPSeedRule(e.target.checked)}
                  />
                  <span>
                    Auto-route <code>{activePresetMeta.defaultModelPattern}</code> requests to this provider
                  </span>
                </label>
              )}
            </div>

            <div className="flex justify-end gap-2.5 pt-3" style={{ borderTop: '1px solid var(--border-row)' }}>
              <button type="button" className="btn" onClick={() => setProvDrawerOpen(false)}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={busy}>
                {busy ? 'Saving…' : editingProviderSlug ? 'Save Provider' : 'Add Provider'}
              </button>
            </div>
          </form>
        )}
      </Drawer>

      {/* =====================================================================
          ADD / EDIT MODEL ALIAS & FALLBACK CHAIN DRAWER
          ===================================================================== */}
      <Drawer
        open={modelDrawerOpen}
        onClose={() => setModelDrawerOpen(false)}
        title={editingModel ? `Edit Model · ${editingModel.name}` : 'New Model Route'}
        subtitle="Map a logical model alias or wildcard glob to an ordered failover or smart-routing chain."
        widthClass="max-w-xl"
      >
        <form onSubmit={handleSaveModel} className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <SegmentedTabs
              value={mKind}
              onChange={setMKind}
              items={[
                { id: 'alias', label: 'Model Alias' },
                { id: 'rule', label: 'Wildcard Rule' },
              ]}
            />
            <SegmentedTabs
              value={mStrategy}
              onChange={setMStrategy}
              items={[
                { id: 'priority', label: 'Priority' },
                { id: 'weighted', label: 'Weighted' },
                { id: 'latency', label: 'Latency' },
                { id: 'cost', label: 'Cost' },
              ]}
            />
          </div>

          <div>
            <label className="block text-[12.5px] font-medium mb-1">
              {mKind === 'alias' ? 'Alias Name (sent as `"model"` by clients)' : 'Glob Pattern'}
            </label>
            <input
              className="input-base mono"
              value={mName}
              onChange={(e) => setMName(e.target.value)}
              placeholder={mKind === 'alias' ? 'smart' : 'claude-*'}
              required
            />
          </div>

          <div className="space-y-2.5">
            <div className="flex items-center justify-between">
              <label className="text-[12.5px] font-semibold">
                {mStrategy === 'priority' ? 'Fallback Chain (Primary → Backups)' : 'Routing Targets'}
              </label>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => {
                  const fallbackProv = ai.providers[mTargets.length % ai.providers.length];
                  if (!fallbackProv) return;
                  setMTargets([
                    ...mTargets,
                    {
                      provider: fallbackProv.slug,
                      upstream: fallbackProv.upstreamName,
                      model: getPresetMeta(fallbackProv.preset).popularModels[0] || '',
                    },
                  ]);
                }}
              >
                <Plus size={12} />
                <span>Add fallback</span>
              </button>
            </div>

            {mTargets.map((target, idx) => {
              const prov = ai.providers.find((p) => p.slug === target.provider);
              const suggestions = prov ? getPresetMeta(prov.preset).popularModels : [];
              return (
                <div key={idx} className="card-subtle p-3.5 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[12px] font-semibold" style={{ color: idx === 0 ? 'var(--brand)' : 'var(--ink-muted)' }}>
                      {idx === 0 ? '1 · Primary Target' : `${idx + 1} · Fallback`}
                    </span>
                    <div className="flex items-center gap-1">
                      {idx > 0 && (
                        <button
                          type="button"
                          className="btn-ghost p-1"
                          onClick={() => {
                            const copy = [...mTargets];
                            [copy[idx - 1], copy[idx]] = [copy[idx], copy[idx - 1]];
                            setMTargets(copy);
                          }}
                        >
                          <ArrowUp size={13} />
                        </button>
                      )}
                      {idx < mTargets.length - 1 && (
                        <button
                          type="button"
                          className="btn-ghost p-1"
                          onClick={() => {
                            const copy = [...mTargets];
                            [copy[idx + 1], copy[idx]] = [copy[idx], copy[idx + 1]];
                            setMTargets(copy);
                          }}
                        >
                          <ArrowDown size={13} />
                        </button>
                      )}
                      {mTargets.length > 1 && (
                        <button
                          type="button"
                          className="btn-ghost p-1"
                          style={{ color: 'var(--danger)' }}
                          onClick={() => setMTargets(mTargets.filter((_, i) => i !== idx))}
                        >
                          <Trash2 size={13} />
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                    <div>
                      <label className="block text-[11.5px] mb-1" style={{ color: 'var(--ink-muted)' }}>
                        Provider
                      </label>
                      <select
                        className="input-base mono text-[13px]"
                        value={target.provider}
                        onChange={(e) => {
                          const nextProv = ai.providers.find((p) => p.slug === e.target.value);
                          const copy = [...mTargets];
                          copy[idx] = {
                            ...target,
                            provider: e.target.value,
                            upstream: nextProv?.upstreamName || e.target.value,
                          };
                          setMTargets(copy);
                        }}
                      >
                        {ai.providers.map((p) => (
                          <option key={p.slug} value={p.slug}>
                            {p.slug} ({getPresetMeta(p.preset).name})
                          </option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="block text-[11.5px] mb-1" style={{ color: 'var(--ink-muted)' }}>
                        Upstream Model {mKind === 'rule' ? '(blank = pass through)' : ''}
                      </label>
                      <input
                        className="input-base mono text-[13px]"
                        value={target.model || ''}
                        onChange={(e) => {
                          const copy = [...mTargets];
                          copy[idx] = { ...target, model: e.target.value };
                          setMTargets(copy);
                        }}
                        placeholder={suggestions[0] || 'gpt-4o'}
                      />
                    </div>
                  </div>

                  {suggestions.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {suggestions.map((s) => (
                        <button
                          key={s}
                          type="button"
                          className="btn btn-sm py-0.5 px-2 text-[11.5px] mono"
                          onClick={() => {
                            const copy = [...mTargets];
                            copy[idx] = { ...target, model: s };
                            setMTargets(copy);
                          }}
                        >
                          {s}
                        </button>
                      ))}
                    </div>
                  )}

                  {mStrategy === 'weighted' && (
                    <div className="w-32">
                      <label className="block text-[11.5px] mb-1" style={{ color: 'var(--ink-muted)' }}>
                        Weight
                      </label>
                      <input
                        type="number"
                        min={1}
                        className="input-base mono text-[13px]"
                        value={target.weight || 1}
                        onChange={(e) => {
                          const copy = [...mTargets];
                          copy[idx] = { ...target, weight: Math.max(1, Number(e.target.value)) };
                          setMTargets(copy);
                        }}
                      />
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          <div className="flex justify-end gap-2.5 pt-3" style={{ borderTop: '1px solid var(--border-row)' }}>
            <button type="button" className="btn" onClick={() => setModelDrawerOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Saving…' : 'Save Model Route'}
            </button>
          </div>
        </form>
      </Drawer>

      {/* =====================================================================
          NEW / EDIT VIRTUAL KEY DRAWER
          ===================================================================== */}
      <Drawer
        open={keyDrawerOpen}
        onClose={() => setKeyDrawerOpen(false)}
        title={editingKey ? `Edit Key · ${editingKey.id}` : 'Mint Virtual API Key'}
        subtitle="Synced fleet-wide in milliseconds over Channel 2. Plaintext secrets are shown once and stored strictly as SHA-256 hashes."
        widthClass="max-w-lg"
      >
        <form onSubmit={handleSaveKey} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Key Name / ID</label>
              <input
                className="input-base mono"
                value={kId}
                disabled={Boolean(editingKey)}
                onChange={(e) => setKId(slugify(e.target.value))}
                placeholder="vk-search-prod"
                required
              />
            </div>
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Team</label>
              <input
                className="input-base"
                value={kTeam}
                onChange={(e) => setKTeam(e.target.value)}
                placeholder="engineering"
              />
            </div>
          </div>

          {/* Allowed Models Picker */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-[12.5px] font-medium">Allowed Models</label>
              <span className="text-[11.5px]" style={{ color: 'var(--ink-muted)' }}>
                {kAllowedModels.length === 0 ? 'Empty = all models allowed' : `${kAllowedModels.length} selected`}
              </span>
            </div>
            {knownModelNames.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {knownModelNames.map((m) => {
                  const selected = kAllowedModels.includes(m);
                  return (
                    <button
                      key={m}
                      type="button"
                      onClick={() =>
                        setKAllowedModels(
                          selected ? kAllowedModels.filter((x) => x !== m) : [...kAllowedModels, m]
                        )
                      }
                      className="btn btn-sm mono text-[12px]"
                      style={{
                        background: selected ? 'var(--brand-soft)' : 'var(--sheet)',
                        borderColor: selected ? 'var(--brand-border)' : 'var(--border)',
                        color: selected ? 'var(--brand)' : 'var(--ink-secondary)',
                      }}
                    >
                      {selected && <Check size={11} />}
                      <span>{m}</span>
                    </button>
                  );
                })}
              </div>
            )}
            <div className="flex gap-2">
              <input
                className="input-base mono text-[12.5px]"
                value={kCustomModel}
                onChange={(e) => setKCustomModel(e.target.value)}
                placeholder="Add custom glob e.g. gpt-4o*"
              />
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => {
                  if (kCustomModel.trim() && !kAllowedModels.includes(kCustomModel.trim())) {
                    setKAllowedModels([...kAllowedModels, kCustomModel.trim()]);
                    setKCustomModel('');
                  }
                }}
              >
                Add
              </button>
            </div>
          </div>

          {/* Rate & Spend Caps */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[12.5px] font-medium mb-1">RPM Limit</label>
              <input
                type="number"
                className="input-base mono"
                value={kRpm}
                onChange={(e) => setKRpm(e.target.value)}
                placeholder="60"
              />
            </div>
            <div>
              <label className="block text-[12.5px] font-medium mb-1">TPM Limit</label>
              <input
                type="number"
                className="input-base mono"
                value={kTpm}
                onChange={(e) => setKTpm(e.target.value)}
                placeholder="100000"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Spend Cap (USD)</label>
              <input
                type="number"
                step="0.5"
                className="input-base mono"
                value={kBudgetUsd}
                onChange={(e) => setKBudgetUsd(e.target.value)}
                placeholder="100"
              />
            </div>
            <div>
              <label className="block text-[12.5px] font-medium mb-1">Budget Window</label>
              <select
                className="input-base"
                value={kBudgetWindow}
                onChange={(e) => setKBudgetWindow(e.target.value as 'daily' | 'weekly' | 'monthly')}
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>
          </div>

          <div className="flex justify-end gap-2.5 pt-3" style={{ borderTop: '1px solid var(--border-row)' }}>
            <button type="button" className="btn" onClick={() => setKeyDrawerOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              <Zap size={13} />
              <span>{busy ? 'Syncing…' : editingKey ? 'Save & Sync' : 'Mint & Sync Key'}</span>
            </button>
          </div>
        </form>
      </Drawer>

      {/* =====================================================================
          ONE-TIME MINTED KEY MODAL + DIRECT SDK SNIPPETS
          ===================================================================== */}
      <Modal
        open={Boolean(mintedKeyModal)}
        onClose={() => setMintedKeyModal(null)}
        title={`Virtual key "${mintedKeyModal?.id}" is live`}
        subtitle="Copy this secret now — Shunt only stored its SHA-256 hash and cannot display it again."
      >
        {mintedKeyModal && (
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <code className="code-block flex-1 py-2.5 break-all">{mintedKeyModal.plaintext}</code>
              <CopyButton text={mintedKeyModal.plaintext} label="Copy" />
            </div>
            <div className="flex items-center justify-between pt-2">
              <button
                type="button"
                className="btn"
                onClick={() => {
                  const key = mintedKeyModal.plaintext;
                  setMintedKeyModal(null);
                  onOpenApiWithKey(key);
                }}
              >
                <Code2 size={14} style={{ color: 'var(--brand)' }} />
                <span>Open SDK &amp; cURL Snippets</span>
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setMintedKeyModal(null)}
              >
                Done
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
