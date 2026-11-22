use std::collections::HashMap;

use serde::{Deserialize, Serialize};

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
        }
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

/// Bundled reference model pricing table (USD per 1M tokens).
/// Users can override any entry or disable built-ins via `use_builtin_pricing = false`.
const BUILTIN_PRICING: &[(&str, ModelPricing)] = &[
    // OpenAI
    ("gpt-4o", ModelPricing::new(2.50, 10.00, Some(1.25))),
    ("gpt-4o-*", ModelPricing::new(2.50, 10.00, Some(1.25))),
    ("gpt-4o-mini", ModelPricing::new(0.15, 0.60, Some(0.075))),
    ("gpt-4o-mini-*", ModelPricing::new(0.15, 0.60, Some(0.075))),
    ("gpt-4.1", ModelPricing::new(2.00, 8.00, Some(0.50))),
    ("gpt-4.1-mini", ModelPricing::new(0.40, 1.60, Some(0.10))),
    ("gpt-4.1-nano", ModelPricing::new(0.10, 0.40, Some(0.025))),
    ("o3-mini", ModelPricing::new(1.10, 4.40, Some(0.55))),
    ("o3-mini-*", ModelPricing::new(1.10, 4.40, Some(0.55))),
    ("text-embedding-3-small", ModelPricing::new(0.02, 0.0, None)),
    ("text-embedding-3-large", ModelPricing::new(0.13, 0.0, None)),
    // Anthropic (direct + Bedrock + Vertex model IDs; 1.25x prompt-cache write, >200k tiered)
    (
        "claude-sonnet-4*",
        ModelPricing::new(3.00, 15.00, Some(0.30))
            .with_cache_write(3.75)
            .with_long_context_tier(200_000, 6.00, 22.50, Some(0.60), Some(7.50)),
    ),
    (
        "claude-opus-4*",
        ModelPricing::new(15.00, 75.00, Some(1.50))
            .with_cache_write(18.75)
            .with_long_context_tier(200_000, 30.00, 112.50, Some(3.00), Some(37.50)),
    ),
    (
        "claude-3-7-sonnet*",
        ModelPricing::new(3.00, 15.00, Some(0.30)).with_cache_write(3.75),
    ),
    (
        "claude-3-5-sonnet*",
        ModelPricing::new(3.00, 15.00, Some(0.30)).with_cache_write(3.75),
    ),
    (
        "claude-3-5-haiku*",
        ModelPricing::new(0.80, 4.00, Some(0.08)).with_cache_write(1.00),
    ),
    (
        "anthropic.claude-3-5-sonnet*",
        ModelPricing::new(3.00, 15.00, Some(0.30)).with_cache_write(3.75),
    ),
    (
        "anthropic.claude-3-5-haiku*",
        ModelPricing::new(0.80, 4.00, Some(0.08)).with_cache_write(1.00),
    ),
    // Google Gemini (>200k tiered pricing for Gemini 2.5 Pro)
    (
        "gemini-2.5-pro*",
        ModelPricing::new(1.25, 10.00, Some(0.3125)).with_long_context_tier(
            200_000,
            2.50,
            15.00,
            Some(0.625),
            None,
        ),
    ),
    (
        "gemini-2.5-flash*",
        ModelPricing::new(0.15, 0.60, Some(0.0375)),
    ),
    (
        "gemini-2.0-flash*",
        ModelPricing::new(0.10, 0.40, Some(0.025)),
    ),
    ("text-embedding-004", ModelPricing::new(0.00, 0.0, None)),
    // DeepSeek
    ("deepseek-chat", ModelPricing::new(0.27, 1.10, Some(0.07))),
    (
        "deepseek-reasoner",
        ModelPricing::new(0.55, 2.19, Some(0.14)),
    ),
];

/// Compiled model pricing lookup catalog combining user overrides and optional built-in pricing.
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
        let mut exact_overrides = HashMap::new();
        let mut wildcard_overrides = Vec::new();
        for (pattern, pricing) in overrides {
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
}
