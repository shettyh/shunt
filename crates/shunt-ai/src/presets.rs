//! Built-in AI provider presets and reload-persistent multi-key upstream pools.
//!
//! Presets live strictly inside `shunt-ai` (`ai-provider-adapter`) so `shunt-core` and
//! `shunt-config` remain completely AI-agnostic while eliminating repetitive dialect/path/auth
//! boilerplate for common LLM providers.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use shunt_plugin_sdk::{HeaderName, header};

use crate::types::ProviderDialect;

/// Default authentication header convention implied by a [`ProviderPreset`] or [`ProviderDialect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAuthShape {
    /// No authentication header by default (e.g., local Ollama / vLLM).
    None,
    /// `Authorization: Bearer <key>`.
    Bearer,
    /// Custom static header without prefix (e.g., `x-api-key`, `x-goog-api-key`, `api-key`).
    Header(&'static str),
}

impl DefaultAuthShape {
    pub fn header_name(self) -> Option<HeaderName> {
        match self {
            DefaultAuthShape::None => None,
            DefaultAuthShape::Bearer => Some(header::AUTHORIZATION),
            DefaultAuthShape::Header(name) => Some(HeaderName::from_static(name)),
        }
    }

    pub const fn prefix(self) -> Option<&'static str> {
        match self {
            DefaultAuthShape::Bearer => Some("Bearer "),
            DefaultAuthShape::None | DefaultAuthShape::Header(_) => None,
        }
    }
}

/// Resolved defaults supplied by a [`ProviderPreset`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresetDefaults {
    pub dialect: ProviderDialect,
    pub chat_path: &'static str,
    pub embeddings_path: &'static str,
    pub responses_path: Option<&'static str>,
    pub default_auth: DefaultAuthShape,
    pub include_stream_usage: bool,
}

/// Built-in provider presets reducing configuration boilerplate in `ai-provider-adapter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderPreset {
    #[serde(rename = "openai")]
    OpenAi,
    Anthropic,
    Gemini,
    #[serde(rename = "azure_openai", alias = "azure")]
    AzureOpenAi,
    Bedrock,
    Groq,
    #[serde(rename = "deepseek")]
    DeepSeek,
    Fireworks,
    Together,
    Mistral,
    Cohere,
    Xai,
    #[serde(rename = "openrouter")]
    OpenRouter,
    Ollama,
    Vllm,
}

impl ProviderPreset {
    pub const fn as_str(self) -> &'static str {
        match self {
            ProviderPreset::OpenAi => "openai",
            ProviderPreset::Anthropic => "anthropic",
            ProviderPreset::Gemini => "gemini",
            ProviderPreset::AzureOpenAi => "azure_openai",
            ProviderPreset::Bedrock => "bedrock",
            ProviderPreset::Groq => "groq",
            ProviderPreset::DeepSeek => "deepseek",
            ProviderPreset::Fireworks => "fireworks",
            ProviderPreset::Together => "together",
            ProviderPreset::Mistral => "mistral",
            ProviderPreset::Cohere => "cohere",
            ProviderPreset::Xai => "xai",
            ProviderPreset::OpenRouter => "openrouter",
            ProviderPreset::Ollama => "ollama",
            ProviderPreset::Vllm => "vllm",
        }
    }

    /// Returns canonical dialect, endpoint paths, and default authentication shape for this preset.
    pub const fn defaults(self) -> PresetDefaults {
        match self {
            ProviderPreset::OpenAi => PresetDefaults {
                dialect: ProviderDialect::OpenAiCompatible,
                chat_path: "/v1/chat/completions",
                embeddings_path: "/v1/embeddings",
                responses_path: Some("/v1/responses"),
                default_auth: DefaultAuthShape::Bearer,
                include_stream_usage: true,
            },
            ProviderPreset::Anthropic => PresetDefaults {
                dialect: ProviderDialect::Anthropic,
                chat_path: "/v1/messages",
                embeddings_path: "/v1/embeddings",
                responses_path: None,
                default_auth: DefaultAuthShape::Header("x-api-key"),
                include_stream_usage: true,
            },
            ProviderPreset::Gemini => PresetDefaults {
                dialect: ProviderDialect::Gemini,
                chat_path: "/v1/chat/completions",
                embeddings_path: "/v1/embeddings",
                responses_path: None,
                default_auth: DefaultAuthShape::Header("x-goog-api-key"),
                include_stream_usage: true,
            },
            ProviderPreset::AzureOpenAi => PresetDefaults {
                dialect: ProviderDialect::AzureOpenAi,
                chat_path: "/v1/chat/completions",
                embeddings_path: "/v1/embeddings",
                responses_path: None,
                default_auth: DefaultAuthShape::Header("api-key"),
                include_stream_usage: true,
            },
            ProviderPreset::Bedrock => PresetDefaults {
                dialect: ProviderDialect::Bedrock,
                chat_path: "/v1/chat/completions",
                embeddings_path: "/v1/embeddings",
                responses_path: None,
                default_auth: DefaultAuthShape::None,
                include_stream_usage: true,
            },
            ProviderPreset::Groq => PresetDefaults {
                dialect: ProviderDialect::OpenAiCompatible,
                chat_path: "/openai/v1/chat/completions",
                embeddings_path: "/openai/v1/embeddings",
                responses_path: None,
                default_auth: DefaultAuthShape::Bearer,
                include_stream_usage: true,
            },
            ProviderPreset::DeepSeek => PresetDefaults {
                dialect: ProviderDialect::OpenAiCompatible,
                chat_path: "/chat/completions",
                embeddings_path: "/embeddings",
                responses_path: None,
                default_auth: DefaultAuthShape::Bearer,
                include_stream_usage: true,
            },
            ProviderPreset::Fireworks => PresetDefaults {
                dialect: ProviderDialect::OpenAiCompatible,
                chat_path: "/inference/v1/chat/completions",
                embeddings_path: "/inference/v1/embeddings",
                responses_path: None,
                default_auth: DefaultAuthShape::Bearer,
                include_stream_usage: true,
            },
            ProviderPreset::Together => PresetDefaults {
                dialect: ProviderDialect::OpenAiCompatible,
                chat_path: "/v1/chat/completions",
                embeddings_path: "/v1/embeddings",
                responses_path: None,
                default_auth: DefaultAuthShape::Bearer,
                include_stream_usage: true,
            },
            ProviderPreset::Mistral => PresetDefaults {
                dialect: ProviderDialect::OpenAiCompatible,
                chat_path: "/v1/chat/completions",
                embeddings_path: "/v1/embeddings",
                responses_path: None,
                default_auth: DefaultAuthShape::Bearer,
                include_stream_usage: false,
            },
            ProviderPreset::Cohere => PresetDefaults {
                dialect: ProviderDialect::OpenAiCompatible,
                chat_path: "/compatibility/v1/chat/completions",
                embeddings_path: "/compatibility/v1/embeddings",
                responses_path: None,
                default_auth: DefaultAuthShape::Bearer,
                include_stream_usage: true,
            },
            ProviderPreset::Xai => PresetDefaults {
                dialect: ProviderDialect::OpenAiCompatible,
                chat_path: "/v1/chat/completions",
                embeddings_path: "/v1/embeddings",
                responses_path: None,
                default_auth: DefaultAuthShape::Bearer,
                include_stream_usage: true,
            },
            ProviderPreset::OpenRouter => PresetDefaults {
                dialect: ProviderDialect::OpenAiCompatible,
                chat_path: "/api/v1/chat/completions",
                embeddings_path: "/api/v1/embeddings",
                responses_path: None,
                default_auth: DefaultAuthShape::Bearer,
                include_stream_usage: true,
            },
            ProviderPreset::Ollama => PresetDefaults {
                dialect: ProviderDialect::OpenAiCompatible,
                chat_path: "/v1/chat/completions",
                embeddings_path: "/v1/embeddings",
                responses_path: None,
                default_auth: DefaultAuthShape::None,
                include_stream_usage: true,
            },
            ProviderPreset::Vllm => PresetDefaults {
                dialect: ProviderDialect::OpenAiCompatible,
                chat_path: "/v1/chat/completions",
                embeddings_path: "/v1/embeddings",
                responses_path: None,
                default_auth: DefaultAuthShape::None,
                include_stream_usage: true,
            },
        }
    }
}

/// Returns the default authentication header shape for a raw [`ProviderDialect`]
/// (taking Vertex AI OAuth2 bearer convention into account).
pub const fn default_auth_shape_for_dialect(
    dialect: ProviderDialect,
    is_vertex: bool,
) -> DefaultAuthShape {
    match dialect {
        ProviderDialect::OpenAiCompatible => DefaultAuthShape::Bearer,
        ProviderDialect::Anthropic => {
            if is_vertex {
                DefaultAuthShape::Bearer
            } else {
                DefaultAuthShape::Header("x-api-key")
            }
        }
        ProviderDialect::AzureOpenAi => DefaultAuthShape::Header("api-key"),
        ProviderDialect::Gemini => {
            if is_vertex {
                DefaultAuthShape::Bearer
            } else {
                DefaultAuthShape::Header("x-goog-api-key")
            }
        }
        ProviderDialect::Bedrock => DefaultAuthShape::None,
    }
}

/// Read-only point-in-time snapshot of a provider's multi-key pool for Admin Inspector APIs.
#[derive(Debug, Clone, Serialize)]
pub struct KeyPoolSnapshot {
    pub provider: String,
    pub total_keys: usize,
    pub healthy_keys: usize,
    pub cooled_down_keys: usize,
    pub min_cooldown_remaining_ms: u64,
}

#[derive(Debug)]
struct ProviderKeyPoolState {
    cursor: AtomicUsize,
    cooldowns: RwLock<Vec<Option<Duration>>>,
}

impl ProviderKeyPoolState {
    fn new(pool_len: usize) -> Self {
        Self {
            cursor: AtomicUsize::new(0),
            cooldowns: RwLock::new(vec![None; pool_len.max(1)]),
        }
    }

    fn ensure_len(&self, pool_len: usize) {
        let target = pool_len.max(1);
        let needs_resize = self.cooldowns.read().expect("KeyPoolTable poisoned").len() != target;
        if needs_resize {
            let mut guard = self.cooldowns.write().expect("KeyPoolTable poisoned");
            guard.resize(target, None);
        }
    }

    /// Selects the next non-cooled-down key index in round-robin order, skipping any
    /// indices already tried on the current request (`exclude_mask` bitset for indices < 64).
    ///
    /// If all keys are currently cooled down, selects the key with the earliest cooldown expiry
    /// (preferring untried keys first) so traffic never deadlocks.
    fn select_key(&self, pool_len: usize, now: Duration, tried: &[usize]) -> usize {
        if pool_len <= 1 {
            return 0;
        }
        self.ensure_len(pool_len);
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % pool_len;
        let guard = self.cooldowns.read().expect("KeyPoolTable poisoned");

        // Pass 1: healthy & not yet tried on this request.
        for offset in 0..pool_len {
            let idx = (start + offset) % pool_len;
            if tried.contains(&idx) {
                continue;
            }
            let in_cd = guard[idx].is_some_and(|until| now < until);
            if !in_cd {
                if idx != start {
                    self.cursor.store(idx.wrapping_add(1), Ordering::Relaxed);
                }
                return idx;
            }
        }

        // Pass 2: healthy (even if tried).
        for offset in 0..pool_len {
            let idx = (start + offset) % pool_len;
            let in_cd = guard[idx].is_some_and(|until| now < until);
            if !in_cd {
                if idx != start {
                    self.cursor.store(idx.wrapping_add(1), Ordering::Relaxed);
                }
                return idx;
            }
        }

        // Pass 3: all keys cooled down -> pick earliest expiring untried key, else earliest overall.
        let mut best_idx = start;
        let mut best_until = Duration::MAX;
        let mut found_untried = false;
        for offset in 0..pool_len {
            let idx = (start + offset) % pool_len;
            let untried = !tried.contains(&idx);
            let until = guard[idx].unwrap_or(Duration::ZERO);
            if (untried && !found_untried) || (untried == found_untried && until < best_until) {
                found_untried = untried;
                best_until = until;
                best_idx = idx;
            }
        }
        best_idx
    }

    /// Returns `true` if there is at least one key in `0..pool_len` that is NOT in cooldown
    /// and NOT present in `tried`.
    fn has_untried_healthy_key(&self, pool_len: usize, now: Duration, tried: &[usize]) -> bool {
        if pool_len <= 1 {
            return false;
        }
        self.ensure_len(pool_len);
        let guard = self.cooldowns.read().expect("KeyPoolTable poisoned");
        for (idx, cd) in guard.iter().enumerate().take(pool_len) {
            if tried.contains(&idx) {
                continue;
            }
            if !cd.is_some_and(|until| now < until) {
                return true;
            }
        }
        false
    }

    fn record_cooldown(
        &self,
        pool_len: usize,
        key_index: usize,
        cooldown: Duration,
        now: Duration,
    ) {
        if key_index >= pool_len {
            return;
        }
        self.ensure_len(pool_len);
        let until = now.saturating_add(cooldown);
        let mut guard = self.cooldowns.write().expect("KeyPoolTable poisoned");
        if let Some(slot) = guard.get_mut(key_index) {
            *slot = Some(match *slot {
                Some(prev) => prev.max(until),
                None => until,
            });
        }
    }

    fn record_success(&self, pool_len: usize, key_index: usize) {
        if key_index >= pool_len {
            return;
        }
        let guard = self.cooldowns.read().expect("KeyPoolTable poisoned");
        if guard.get(key_index).copied().flatten().is_none() {
            return;
        }
        drop(guard);
        let mut guard = self.cooldowns.write().expect("KeyPoolTable poisoned");
        if let Some(slot) = guard.get_mut(key_index) {
            *slot = None;
        }
    }

    fn snapshot(&self, provider: &str, now: Duration) -> KeyPoolSnapshot {
        let guard = self.cooldowns.read().expect("KeyPoolTable poisoned");
        let total_keys = guard.len();
        let mut cooled_down_keys = 0usize;
        let mut min_rem = u64::MAX;
        for cd in guard.iter() {
            if let Some(rem) = cd.and_then(|u| u.checked_sub(now))
                && !rem.is_zero()
            {
                cooled_down_keys += 1;
                min_rem = min_rem.min(rem.as_millis() as u64);
            }
        }
        KeyPoolSnapshot {
            provider: provider.to_owned(),
            total_keys,
            healthy_keys: total_keys.saturating_sub(cooled_down_keys),
            cooled_down_keys,
            min_cooldown_remaining_ms: if cooled_down_keys > 0 { min_rem } else { 0 },
        }
    }
}

/// Reload-persistent multi-key rotation & cooldown state stored in `StateStore`.
#[derive(Debug, Default)]
pub struct KeyPoolTable {
    pools: RwLock<HashMap<String, Arc<ProviderKeyPoolState>>>,
}

impl KeyPoolTable {
    fn get_or_create(&self, provider: &str, pool_len: usize) -> Arc<ProviderKeyPoolState> {
        if let Some(existing) = self
            .pools
            .read()
            .expect("KeyPoolTable poisoned")
            .get(provider)
        {
            return Arc::clone(existing);
        }
        let mut guard = self.pools.write().expect("KeyPoolTable poisoned");
        Arc::clone(
            guard
                .entry(provider.to_owned())
                .or_insert_with(|| Arc::new(ProviderKeyPoolState::new(pool_len))),
        )
    }

    pub fn select_key(
        &self,
        provider: &str,
        pool_len: usize,
        now: Duration,
        tried: &[usize],
    ) -> usize {
        self.get_or_create(provider, pool_len)
            .select_key(pool_len, now, tried)
    }

    pub fn has_untried_healthy_key(
        &self,
        provider: &str,
        pool_len: usize,
        now: Duration,
        tried: &[usize],
    ) -> bool {
        self.get_or_create(provider, pool_len)
            .has_untried_healthy_key(pool_len, now, tried)
    }

    pub fn record_cooldown(
        &self,
        provider: &str,
        pool_len: usize,
        key_index: usize,
        cooldown: Duration,
        now: Duration,
    ) {
        self.get_or_create(provider, pool_len)
            .record_cooldown(pool_len, key_index, cooldown, now);
    }

    pub fn record_success(&self, provider: &str, pool_len: usize, key_index: usize) {
        if let Some(pool) = self
            .pools
            .read()
            .expect("KeyPoolTable poisoned")
            .get(provider)
            .cloned()
        {
            pool.record_success(pool_len, key_index);
        }
    }

    pub fn snapshot_pools(&self, now: Duration) -> Vec<KeyPoolSnapshot> {
        let guard = self.pools.read().expect("KeyPoolTable poisoned");
        let mut out: Vec<KeyPoolSnapshot> = guard
            .iter()
            .map(|(provider, state)| state.snapshot(provider, now))
            .collect();
        out.sort_by(|a, b| a.provider.cmp(&b.provider));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_expose_expected_dialects_and_paths() {
        assert_eq!(
            ProviderPreset::Groq.defaults().chat_path,
            "/openai/v1/chat/completions"
        );
        assert_eq!(
            ProviderPreset::DeepSeek.defaults().chat_path,
            "/chat/completions"
        );
        assert_eq!(
            ProviderPreset::OpenRouter.defaults().chat_path,
            "/api/v1/chat/completions"
        );
        assert_eq!(
            ProviderPreset::Anthropic.defaults().default_auth,
            DefaultAuthShape::Header("x-api-key")
        );
        assert_eq!(
            ProviderPreset::Gemini.defaults().default_auth,
            DefaultAuthShape::Header("x-goog-api-key")
        );
        assert_eq!(
            ProviderPreset::OpenAi.defaults().responses_path,
            Some("/v1/responses")
        );
    }

    #[test]
    fn key_pool_round_robins_skips_cooled_keys_and_recovers() {
        let table = KeyPoolTable::default();
        let t0 = Duration::from_secs(10);

        assert_eq!(table.select_key("openai", 3, t0, &[]), 0);
        assert_eq!(table.select_key("openai", 3, t0, &[]), 1);
        assert_eq!(table.select_key("openai", 3, t0, &[]), 2);

        // Cool down key 0 for 30s
        table.record_cooldown("openai", 3, 0, Duration::from_secs(30), t0);
        assert!(table.has_untried_healthy_key("openai", 3, t0, &[0]));
        assert_eq!(table.select_key("openai", 3, t0, &[0]), 1);

        // Cool down keys 1 and 2 as well -> picks earliest expiring
        table.record_cooldown("openai", 3, 1, Duration::from_secs(60), t0);
        table.record_cooldown("openai", 3, 2, Duration::from_secs(90), t0);
        assert!(!table.has_untried_healthy_key("openai", 3, t0, &[0]));
        assert_eq!(table.select_key("openai", 3, t0, &[]), 0);

        // Advance past key 0's 30s cooldown -> key 0 recovers
        let t1 = Duration::from_secs(41);
        assert!(table.has_untried_healthy_key("openai", 3, t1, &[1, 2]));
        assert_eq!(table.select_key("openai", 3, t1, &[]), 0);

        let snap = table.snapshot_pools(t1);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].total_keys, 3);
        assert_eq!(snap[0].healthy_keys, 1);
        assert_eq!(snap[0].cooled_down_keys, 2);
    }
}
