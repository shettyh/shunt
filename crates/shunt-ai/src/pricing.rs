use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::wildcard_match;

/// One USD expressed in integer nano-USD (`1e-9` USD) for exact, drift-free accounting.
pub const NANO_USD_PER_USD: u64 = 1_000_000_000;

/// Converts USD (`f64`) into non-negative integer nano-USD, clamping NaN/Inf/negative safely.
pub fn usd_to_nano_usd(usd: f64) -> u64 {
    if !usd.is_finite() || usd <= 0.0 {
        return 0;
    }
    let scaled = (usd * (NANO_USD_PER_USD as f64)).round();
    if !scaled.is_finite() || scaled <= 0.0 {
        0
    } else if scaled >= (i64::MAX as f64) {
        i64::MAX as u64
    } else {
        scaled as u64
    }
}

/// Converts integer nano-USD back into USD (`f64`).
pub fn nano_usd_to_usd(nano: u64) -> f64 {
    (nano as f64) / (NANO_USD_PER_USD as f64)
}

/// Per-model token pricing expressed in USD per 1,000,000 tokens.
///
/// Supports prompt cache reads (`cached_input_per_million_usd`), prompt cache writes
/// (`cache_write_per_million_usd`), and optional long-context tiered pricing when total
/// `prompt_tokens > long_context_threshold_tokens` (e.g., `>200_000` tokens for Claude 4 / Gemini 2.5 Pro).
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
pub struct ModelPricing {
    /// Input (prompt) token price in USD per 1M tokens.
    pub input_per_million_usd: f64,
    /// Output (completion) token price in USD per 1M tokens.
    #[serde(default)]
    pub output_per_million_usd: f64,
    /// Optional cached prompt read token price in USD per 1M tokens (defaults to `input_per_million_usd`).
    #[serde(default)]
    pub cached_input_per_million_usd: Option<f64>,
    /// Optional prompt cache write (creation) token price in USD per 1M tokens
    /// (defaults to `input_per_million_usd`).
    #[serde(default)]
    pub cache_write_per_million_usd: Option<f64>,
    /// Optional prompt token threshold above which long-context tiered rates apply.
    #[serde(default)]
    pub long_context_threshold_tokens: Option<u64>,
    /// Optional long-context input token price in USD per 1M tokens.
    #[serde(default)]
    pub long_context_input_per_million_usd: Option<f64>,
    /// Optional long-context output token price in USD per 1M tokens.
    #[serde(default)]
    pub long_context_output_per_million_usd: Option<f64>,
    /// Optional long-context cached input read token price in USD per 1M tokens.
    #[serde(default)]
    pub long_context_cached_input_per_million_usd: Option<f64>,
    /// Optional long-context cache write token price in USD per 1M tokens.
    #[serde(default)]
    pub long_context_cache_write_per_million_usd: Option<f64>,
    /// Optional model maximum input/context window length in tokens.
    #[serde(default)]
    pub max_input_tokens: Option<u64>,
    /// Optional model maximum output/completion token limit.
    #[serde(default)]
    pub max_output_tokens: Option<u64>,
}

impl ModelPricing {
    pub const fn new(
        input_per_million_usd: f64,
        output_per_million_usd: f64,
        cached_input_per_million_usd: Option<f64>,
    ) -> Self {
        Self {
            input_per_million_usd,
            output_per_million_usd,
            cached_input_per_million_usd,
            cache_write_per_million_usd: None,
            long_context_threshold_tokens: None,
            long_context_input_per_million_usd: None,
            long_context_output_per_million_usd: None,
            long_context_cached_input_per_million_usd: None,
            long_context_cache_write_per_million_usd: None,
            max_input_tokens: None,
            max_output_tokens: None,
        }
    }

    pub const fn with_context_window(
        mut self,
        max_input_tokens: u64,
        max_output_tokens: u64,
    ) -> Self {
        self.max_input_tokens = Some(max_input_tokens);
        self.max_output_tokens = Some(max_output_tokens);
        self
    }

    pub const fn with_cache_write(mut self, cache_write_per_million_usd: f64) -> Self {
        self.cache_write_per_million_usd = Some(cache_write_per_million_usd);
        self
    }

    pub const fn with_long_context_tier(
        mut self,
        threshold_tokens: u64,
        input_per_million_usd: f64,
        output_per_million_usd: f64,
        cached_input_per_million_usd: Option<f64>,
        cache_write_per_million_usd: Option<f64>,
    ) -> Self {
        self.long_context_threshold_tokens = Some(threshold_tokens);
        self.long_context_input_per_million_usd = Some(input_per_million_usd);
        self.long_context_output_per_million_usd = Some(output_per_million_usd);
        self.long_context_cached_input_per_million_usd = cached_input_per_million_usd;
        self.long_context_cache_write_per_million_usd = cache_write_per_million_usd;
        self
    }

    pub fn validate(&self, label: &str) -> Result<(), String> {
        let check = |field: &str, v: f64| -> Result<(), String> {
            if !v.is_finite() || v < 0.0 {
                return Err(format!(
                    "pricing `{label}`: `{field}` must be a non-negative finite number"
                ));
            }
            Ok(())
        };
        check("input_per_million_usd", self.input_per_million_usd)?;
        check("output_per_million_usd", self.output_per_million_usd)?;
        if let Some(c) = self.cached_input_per_million_usd {
            check("cached_input_per_million_usd", c)?;
        }
        if let Some(c) = self.cache_write_per_million_usd {
            check("cache_write_per_million_usd", c)?;
        }
        if let Some(c) = self.long_context_input_per_million_usd {
            check("long_context_input_per_million_usd", c)?;
        }
        if let Some(c) = self.long_context_output_per_million_usd {
            check("long_context_output_per_million_usd", c)?;
        }
        if let Some(c) = self.long_context_cached_input_per_million_usd {
            check("long_context_cached_input_per_million_usd", c)?;
        }
        if let Some(c) = self.long_context_cache_write_per_million_usd {
            check("long_context_cache_write_per_million_usd", c)?;
        }
        Ok(())
    }

    /// Computes total request cost in exact integer nano-USD (without cache-write tokens).
    ///
    /// Note: `$1.00 / 1M tokens` == `1_000 nano-USD / token`.
    /// `cached_prompt_tokens` is clamped to `<= prompt_tokens` so uncached prompt tokens
    /// never underflow.
    pub fn cost_nano_usd(
        &self,
        prompt_tokens: u64,
        cached_prompt_tokens: u64,
        completion_tokens: u64,
    ) -> u64 {
        self.cost_nano_usd_detailed(prompt_tokens, cached_prompt_tokens, 0, completion_tokens)
    }

    /// Computes total request cost in exact integer nano-USD accounting for prompt cache reads,
    /// prompt cache writes (`cache_creation_prompt_tokens`), and long-context tiered pricing.
    ///
    /// `cached_prompt_tokens` and `cache_creation_prompt_tokens` are clamped against
    /// `prompt_tokens` so uncached prompt tokens never underflow.
    pub fn cost_nano_usd_detailed(
        &self,
        prompt_tokens: u64,
        cached_prompt_tokens: u64,
        cache_creation_prompt_tokens: u64,
        completion_tokens: u64,
    ) -> u64 {
        let cached = cached_prompt_tokens.min(prompt_tokens);
        let rem_after_read = prompt_tokens.saturating_sub(cached);
        let written = cache_creation_prompt_tokens.min(rem_after_read);
        let uncached = rem_after_read.saturating_sub(written);

        let is_long_context = self
            .long_context_threshold_tokens
            .is_some_and(|threshold| prompt_tokens > threshold);

        let eff_input = if is_long_context {
            self.long_context_input_per_million_usd
                .unwrap_or(self.input_per_million_usd)
        } else {
            self.input_per_million_usd
        };
        let eff_output = if is_long_context {
            self.long_context_output_per_million_usd
                .unwrap_or(self.output_per_million_usd)
        } else {
            self.output_per_million_usd
        };
        let eff_cached = if is_long_context {
            self.long_context_cached_input_per_million_usd
                .or(self.cached_input_per_million_usd)
                .unwrap_or(eff_input)
        } else {
            self.cached_input_per_million_usd.unwrap_or(eff_input)
        };
        let eff_write = if is_long_context {
            self.long_context_cache_write_per_million_usd
                .or(self.cache_write_per_million_usd)
                .unwrap_or(eff_input)
        } else {
            self.cache_write_per_million_usd.unwrap_or(eff_input)
        };

        let input_rate = usd_per_million_to_nano_per_token(eff_input);
        let cached_rate = usd_per_million_to_nano_per_token(eff_cached);
        let write_rate = usd_per_million_to_nano_per_token(eff_write);
        let output_rate = usd_per_million_to_nano_per_token(eff_output);

        let uncached_cost = (uncached as u128).saturating_mul(input_rate as u128);
        let cached_cost = (cached as u128).saturating_mul(cached_rate as u128);
        let write_cost = (written as u128).saturating_mul(write_rate as u128);
        let output_cost = (completion_tokens as u128).saturating_mul(output_rate as u128);

        let total = uncached_cost
            .saturating_add(cached_cost)
            .saturating_add(write_cost)
            .saturating_add(output_cost);
        total.min(i64::MAX as u128) as u64
    }
}

fn usd_per_million_to_nano_per_token(usd_per_million: f64) -> u64 {
    if !usd_per_million.is_finite() || usd_per_million <= 0.0 {
        return 0;
    }
    let nano = (usd_per_million * 1_000.0).round();
    if !nano.is_finite() || nano <= 0.0 {
        0
    } else if nano >= (u64::MAX as f64) {
        u64::MAX
    } else {
        nano as u64
    }
}

/// Bundled reference model pricing table (USD per 1M tokens) and context metadata.
/// Users can override any entry, supply an external `pricing_file`, or disable built-ins via
/// `use_builtin_pricing = false`.
const BUILTIN_PRICING: &[(&str, ModelPricing)] = &[
    // OpenAI
    (
        "gpt-4o",
        ModelPricing::new(2.50, 10.00, Some(1.25)).with_context_window(128_000, 16_384),
    ),
    (
        "gpt-4o-*",
        ModelPricing::new(2.50, 10.00, Some(1.25)).with_context_window(128_000, 16_384),
    ),
    (
        "gpt-4o-mini",
        ModelPricing::new(0.15, 0.60, Some(0.075)).with_context_window(128_000, 16_384),
    ),
    (
        "gpt-4o-mini-*",
        ModelPricing::new(0.15, 0.60, Some(0.075)).with_context_window(128_000, 16_384),
    ),
    (
        "gpt-4.1",
        ModelPricing::new(2.00, 8.00, Some(0.50)).with_context_window(1_047_576, 32_768),
    ),
    (
        "gpt-4.1-mini",
        ModelPricing::new(0.40, 1.60, Some(0.10)).with_context_window(1_047_576, 32_768),
    ),
    (
        "gpt-4.1-nano",
        ModelPricing::new(0.10, 0.40, Some(0.025)).with_context_window(1_047_576, 32_768),
    ),
    (
        "o3-mini",
        ModelPricing::new(1.10, 4.40, Some(0.55)).with_context_window(200_000, 100_000),
    ),
    (
        "o3-mini-*",
        ModelPricing::new(1.10, 4.40, Some(0.55)).with_context_window(200_000, 100_000),
    ),
    (
        "text-embedding-3-small",
        ModelPricing::new(0.02, 0.0, None).with_context_window(8_191, 0),
    ),
    (
        "text-embedding-3-large",
        ModelPricing::new(0.13, 0.0, None).with_context_window(8_191, 0),
    ),
    // Anthropic (direct + Bedrock + Vertex model IDs; 1.25x prompt-cache write, >200k tiered)
    (
        "claude-sonnet-4*",
        ModelPricing::new(3.00, 15.00, Some(0.30))
            .with_cache_write(3.75)
            .with_long_context_tier(200_000, 6.00, 22.50, Some(0.60), Some(7.50))
            .with_context_window(200_000, 64_000),
    ),
    (
        "claude-opus-4*",
        ModelPricing::new(15.00, 75.00, Some(1.50))
            .with_cache_write(18.75)
            .with_long_context_tier(200_000, 30.00, 112.50, Some(3.00), Some(37.50))
            .with_context_window(200_000, 32_000),
    ),
    (
        "claude-3-7-sonnet*",
        ModelPricing::new(3.00, 15.00, Some(0.30))
            .with_cache_write(3.75)
            .with_context_window(200_000, 64_000),
    ),
    (
        "claude-3-5-sonnet*",
        ModelPricing::new(3.00, 15.00, Some(0.30))
            .with_cache_write(3.75)
            .with_context_window(200_000, 8_192),
    ),
    (
        "claude-3-5-haiku*",
        ModelPricing::new(0.80, 4.00, Some(0.08))
            .with_cache_write(1.00)
            .with_context_window(200_000, 8_192),
    ),
    (
        "anthropic.claude-3-5-sonnet*",
        ModelPricing::new(3.00, 15.00, Some(0.30))
            .with_cache_write(3.75)
            .with_context_window(200_000, 8_192),
    ),
    (
        "anthropic.claude-3-5-haiku*",
        ModelPricing::new(0.80, 4.00, Some(0.08))
            .with_cache_write(1.00)
            .with_context_window(200_000, 8_192),
    ),
    // Google Gemini (>200k tiered pricing for Gemini 2.5 Pro)
    (
        "gemini-2.5-pro*",
        ModelPricing::new(1.25, 10.00, Some(0.3125))
            .with_long_context_tier(200_000, 2.50, 15.00, Some(0.625), None)
            .with_context_window(1_048_576, 65_536),
    ),
    (
        "gemini-2.5-flash*",
        ModelPricing::new(0.15, 0.60, Some(0.0375)).with_context_window(1_048_576, 65_536),
    ),
    (
        "gemini-2.0-flash*",
        ModelPricing::new(0.10, 0.40, Some(0.025)).with_context_window(1_048_576, 8_192),
    ),
    (
        "text-embedding-004",
        ModelPricing::new(0.00, 0.0, None).with_context_window(2_048, 0),
    ),
    // DeepSeek
    (
        "deepseek-chat",
        ModelPricing::new(0.27, 1.10, Some(0.07)).with_context_window(128_000, 8_192),
    ),
    (
        "deepseek-reasoner",
        ModelPricing::new(0.55, 2.19, Some(0.14)).with_context_window(128_000, 8_192),
    ),
];

/// Parses an external JSON pricing catalog supporting both:
/// 1. Shunt's canonical per-million format (`input_per_million_usd`, `output_per_million_usd`, ...)
/// 2. LiteLLM's `model_prices_and_context_window.json` format (`input_cost_per_token`,
///    `output_cost_per_token`, `cache_read_input_token_cost`, `cache_creation_input_token_cost`,
///    `max_input_tokens` / `max_tokens`, `max_output_tokens`, and `*_above_200k_tokens` /
///    `*_above_128k_tokens`).
pub fn parse_external_pricing_json(raw: &str) -> Result<HashMap<String, ModelPricing>, String> {
    let root: Value = serde_json::from_str(raw)
        .map_err(|e| format!("failed to parse external pricing JSON: {e}"))?;
    let Some(obj) = root.as_object() else {
        return Err(
            "external pricing JSON must be a top-level object mapping model IDs to pricing entries"
                .to_owned(),
        );
    };

    let mut out = HashMap::with_capacity(obj.len());
    for (model_key, entry) in obj {
        if model_key == "sample_spec" {
            continue;
        }
        let Some(map) = entry.as_object() else {
            continue;
        };

        let pricing = if map.contains_key("input_per_million_usd") {
            let parsed: ModelPricing = serde_json::from_value(entry.clone()).map_err(|e| {
                format!("pricing_file `{model_key}`: invalid Shunt pricing entry: {e}")
            })?;
            parsed.validate(model_key)?;
            parsed
        } else if let Some(in_per_tok) = map.get("input_cost_per_token").and_then(Value::as_f64) {
            let out_per_tok = map
                .get("output_cost_per_token")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let cache_read = map
                .get("cache_read_input_token_cost")
                .and_then(Value::as_f64)
                .map(|v| v * 1_000_000.0);
            let cache_write = map
                .get("cache_creation_input_token_cost")
                .and_then(Value::as_f64)
                .map(|v| v * 1_000_000.0);

            let (lc_threshold, lc_in, lc_out, lc_read, lc_write) = if let Some(in_200k) = map
                .get("input_cost_per_token_above_200k_tokens")
                .and_then(Value::as_f64)
            {
                (
                    Some(200_000),
                    Some(in_200k * 1_000_000.0),
                    map.get("output_cost_per_token_above_200k_tokens")
                        .and_then(Value::as_f64)
                        .map(|v| v * 1_000_000.0),
                    map.get("cache_read_input_token_cost_above_200k_tokens")
                        .and_then(Value::as_f64)
                        .map(|v| v * 1_000_000.0),
                    map.get("cache_creation_input_token_cost_above_200k_tokens")
                        .and_then(Value::as_f64)
                        .map(|v| v * 1_000_000.0),
                )
            } else if let Some(in_128k) = map
                .get("input_cost_per_token_above_128k_tokens")
                .and_then(Value::as_f64)
            {
                (
                    Some(128_000),
                    Some(in_128k * 1_000_000.0),
                    map.get("output_cost_per_token_above_128k_tokens")
                        .and_then(Value::as_f64)
                        .map(|v| v * 1_000_000.0),
                    map.get("cache_read_input_token_cost_above_128k_tokens")
                        .and_then(Value::as_f64)
                        .map(|v| v * 1_000_000.0),
                    map.get("cache_creation_input_token_cost_above_128k_tokens")
                        .and_then(Value::as_f64)
                        .map(|v| v * 1_000_000.0),
                )
            } else {
                (None, None, None, None, None)
            };

            let max_input_tokens = map
                .get("max_input_tokens")
                .and_then(Value::as_u64)
                .or_else(|| map.get("max_tokens").and_then(Value::as_u64));
            let max_output_tokens = map.get("max_output_tokens").and_then(Value::as_u64);

            let parsed = ModelPricing {
                input_per_million_usd: in_per_tok * 1_000_000.0,
                output_per_million_usd: out_per_tok * 1_000_000.0,
                cached_input_per_million_usd: cache_read,
                cache_write_per_million_usd: cache_write,
                long_context_threshold_tokens: lc_threshold,
                long_context_input_per_million_usd: lc_in,
                long_context_output_per_million_usd: lc_out,
                long_context_cached_input_per_million_usd: lc_read,
                long_context_cache_write_per_million_usd: lc_write,
                max_input_tokens,
                max_output_tokens,
            };
            parsed.validate(model_key)?;
            parsed
        } else {
            // Skip metadata-only entries (e.g., image/audio-only LiteLLM rows without token costs).
            continue;
        };

        out.insert(model_key.clone(), pricing);
    }

    Ok(out)
}

/// Compiled model pricing lookup catalog combining inline overrides, an optional external JSON
/// pricing file, and optional built-in pricing.
#[derive(Debug, Clone)]
pub struct PricingCatalog {
    exact_overrides: HashMap<String, ModelPricing>,
    wildcard_overrides: Vec<(String, ModelPricing)>,
    use_builtin: bool,
    default_pricing: Option<ModelPricing>,
}

impl PricingCatalog {
    pub fn new(
        overrides: HashMap<String, ModelPricing>,
        use_builtin: bool,
        default_pricing: Option<ModelPricing>,
    ) -> Result<Self, String> {
        Self::new_with_file(overrides, use_builtin, default_pricing, None)
    }

    /// Compiles a pricing catalog with optional external JSON pricing file (`pricing_file`).
    /// Precedence: inline `overrides` > `pricing_file` > built-in table > `default_pricing`.
    pub fn new_with_file(
        overrides: HashMap<String, ModelPricing>,
        use_builtin: bool,
        default_pricing: Option<ModelPricing>,
        pricing_file: Option<&Path>,
    ) -> Result<Self, String> {
        let mut merged = match pricing_file {
            Some(path) => {
                let raw = std::fs::read_to_string(path).map_err(|e| {
                    format!("failed to read pricing_file `{}`: {e}", path.display())
                })?;
                parse_external_pricing_json(&raw)?
            }
            None => HashMap::new(),
        };
        for (k, v) in overrides {
            merged.insert(k, v);
        }

        let mut exact_overrides = HashMap::new();
        let mut wildcard_overrides = Vec::new();
        for (pattern, pricing) in merged {
            pricing.validate(&pattern)?;
            if pattern.contains('*') {
                wildcard_overrides.push((pattern, pricing));
            } else {
                exact_overrides.insert(pattern, pricing);
            }
        }
        // Sort wildcard patterns by descending specificity (longer non-wildcard prefix first),
        // then lexicographically for deterministic matching.
        wildcard_overrides.sort_by(|a, b| {
            let spec_a = a.0.bytes().filter(|&c| c != b'*').count();
            let spec_b = b.0.bytes().filter(|&c| c != b'*').count();
            spec_b.cmp(&spec_a).then_with(|| a.0.cmp(&b.0))
        });

        if let Some(dp) = &default_pricing {
            dp.validate("default_pricing")?;
        }

        Ok(Self {
            exact_overrides,
            wildcard_overrides,
            use_builtin,
            default_pricing,
        })
    }

    /// Looks up pricing for `served_model` first, falling back to `requested_model`.
    pub fn lookup(&self, served_model: &str, requested_model: &str) -> Option<ModelPricing> {
        self.lookup_single(served_model)
            .or_else(|| {
                if requested_model != served_model {
                    self.lookup_single(requested_model)
                } else {
                    None
                }
            })
            .or(self.default_pricing)
    }

    fn lookup_single(&self, model: &str) -> Option<ModelPricing> {
        if let Some(p) = self.exact_overrides.get(model) {
            return Some(*p);
        }
        for (pat, p) in &self.wildcard_overrides {
            if wildcard_match(pat, model) {
                return Some(*p);
            }
        }
        if self.use_builtin {
            // Check exact builtin first so `gpt-4o-mini` isn't shadowed by `gpt-4o-*`.
            for &(pat, p) in BUILTIN_PRICING {
                if !pat.contains('*') && pat == model {
                    return Some(p);
                }
            }
            for &(pat, p) in BUILTIN_PRICING {
                if pat.contains('*') && wildcard_match(pat, model) {
                    return Some(p);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_exact_nano_usd_with_cached_tokens() {
        // $2.50 / 1M input, $10.00 / 1M output, $1.25 / 1M cached
        let p = ModelPricing::new(2.50, 10.00, Some(1.25));
        // 1000 prompt tokens (400 cached, 600 uncached) + 500 output tokens:
        // uncached: 600 * 2500 = 1_500_000 nano ($0.0015)
        // cached:   400 * 1250 =   500_000 nano ($0.0005)
        // output:   500 * 10000 = 5_000_000 nano ($0.0050)
        // total = 7_000_000 nano = $0.007
        let cost = p.cost_nano_usd(1000, 400, 500);
        assert_eq!(cost, 7_000_000);
        assert!((nano_usd_to_usd(cost) - 0.007).abs() < 1e-12);
    }

    #[test]
    fn catalog_prefers_exact_override_then_wildcard_then_builtin() {
        let mut overrides = HashMap::new();
        overrides.insert("gpt-4o".to_owned(), ModelPricing::new(5.0, 20.0, None));
        overrides.insert("custom-*".to_owned(), ModelPricing::new(1.0, 2.0, None));

        let cat = PricingCatalog::new(overrides, true, None).unwrap();
        assert_eq!(
            cat.lookup("gpt-4o", "gpt-4o")
                .unwrap()
                .input_per_million_usd,
            5.0
        );
        assert_eq!(
            cat.lookup("gpt-4o-mini", "gpt-4o-mini")
                .unwrap()
                .input_per_million_usd,
            0.15
        );
        assert_eq!(
            cat.lookup("custom-v1", "custom-v1")
                .unwrap()
                .input_per_million_usd,
            1.0
        );
        assert_eq!(
            cat.lookup("claude-3-5-sonnet-20241022", "smart")
                .unwrap()
                .input_per_million_usd,
            3.0
        );
        assert!(
            cat.lookup("unknown-local-model", "unknown-local-model")
                .is_none()
        );
    }

    #[test]
    fn computes_cache_write_and_long_context_tiered_pricing() {
        // Claude Sonnet 4: $3/M input, $15/M output, $0.30/M cache read, $3.75/M cache write
        // Long context (>200k): $6/M input, $22.50/M output, $0.60/M cache read, $7.50/M cache write
        let cat = PricingCatalog::new(HashMap::new(), true, None).unwrap();
        let p = cat
            .lookup("claude-sonnet-4-20250514", "claude-sonnet-4")
            .unwrap();

        // Standard tier (10_000 prompt = 5_000 uncached + 3_000 cache_read + 2_000 cache_write, 1_000 output):
        // uncached: 5_000 * 3_000 = 15_000_000
        // read:     3_000 *   300 =    900_000
        // write:    2_000 * 3_750 =  7_500_000
        // output:   1_000 * 15_000 = 15_000_000
        // total = 38_400_000 nano ($0.0384)
        let std_cost = p.cost_nano_usd_detailed(10_000, 3_000, 2_000, 1_000);
        assert_eq!(std_cost, 38_400_000);

        // Long-context tier (250_000 prompt = 100_000 uncached + 100_000 read + 50_000 write, 1_000 output):
        // uncached: 100_000 * 6_000 = 600_000_000
        // read:     100_000 *   600 =  60_000_000
        // write:     50_000 * 7_500 = 375_000_000
        // output:     1_000 * 22_500 = 22_500_000
        // total = 1_057_500_000 nano ($1.0575)
        let long_cost = p.cost_nano_usd_detailed(250_000, 100_000, 50_000, 1_000);
        assert_eq!(long_cost, 1_057_500_000);
    }

    #[test]
    fn parses_shunt_and_litellm_external_pricing_json() {
        let json = r#"{
            "sample_spec": { "description": "ignored" },
            "custom-shunt-model": {
                "input_per_million_usd": 1.5,
                "output_per_million_usd": 6.0,
                "cached_input_per_million_usd": 0.15,
                "max_input_tokens": 256000,
                "max_output_tokens": 16384
            },
            "litellm-pro": {
                "input_cost_per_token": 0.000003,
                "output_cost_per_token": 0.000015,
                "cache_read_input_token_cost": 0.0000003,
                "cache_creation_input_token_cost": 0.00000375,
                "input_cost_per_token_above_200k_tokens": 0.000006,
                "output_cost_per_token_above_200k_tokens": 0.0000225,
                "max_input_tokens": 200000,
                "max_output_tokens": 64000
            },
            "image-only": {
                "mode": "image_generation",
                "output_cost_per_image": 0.04
            }
        }"#;

        let parsed = parse_external_pricing_json(json).unwrap();
        assert_eq!(parsed.len(), 2);

        let s = parsed.get("custom-shunt-model").unwrap();
        assert!((s.input_per_million_usd - 1.5).abs() < 1e-9);
        assert!((s.output_per_million_usd - 6.0).abs() < 1e-9);
        assert_eq!(s.max_input_tokens, Some(256_000));
        assert_eq!(s.max_output_tokens, Some(16_384));

        let l = parsed.get("litellm-pro").unwrap();
        assert!((l.input_per_million_usd - 3.0).abs() < 1e-6);
        assert!((l.output_per_million_usd - 15.0).abs() < 1e-6);
        assert!((l.cached_input_per_million_usd.unwrap() - 0.3).abs() < 1e-6);
        assert!((l.cache_write_per_million_usd.unwrap() - 3.75).abs() < 1e-6);
        assert_eq!(l.long_context_threshold_tokens, Some(200_000));
        assert!((l.long_context_input_per_million_usd.unwrap() - 6.0).abs() < 1e-6);
        assert_eq!(l.max_input_tokens, Some(200_000));
        assert_eq!(l.max_output_tokens, Some(64_000));
    }
}
