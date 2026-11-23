---
title: Providers, Presets & Cloud IAM
description: Configure 5 upstream dialects, 17 built-in provider presets, multi-key pools, BYOK passthrough, and zero-SDK AWS, GCP, and Azure Cloud IAM.
---

`ai-provider-adapter` handles upstream authentication, URL rewriting, parameter normalization (`drop_params`), and live JSON/SSE/EventStream dialect translation.

## 5 Upstream Dialects

| Dialect | Covers |
| --- | --- |
| `openai_compatible` | OpenAI, Ollama, vLLM, SGLang, Groq, DeepSeek, Fireworks, Together, Mistral, xAI, OpenRouter, Cohere, Jina, Voyage |
| `anthropic` | Anthropic Messages API + **Claude on Google Cloud Vertex AI** (`vertex_project` + `vertex_location`) |
| `azure_openai` | Azure OpenAI deployment-scoped routing (`api_version`) |
| `gemini` | Google AI Studio & **Vertex AI Gemini** (`vertex_project` + `vertex_location`) |
| `bedrock` | AWS Bedrock `Converse`, `ConverseStream` (pure-Rust SigV4 + binary EventStream), and Bedrock Embeddings |

## 17 Built-in Provider Presets

Use `preset = "<name>"` to skip repetitive dialect, endpoint path, and auth header boilerplate:

`openai`, `anthropic`, `gemini`, `azure_openai` (alias `azure`), `bedrock`, `groq`, `deepseek`, `fireworks`, `together`, `mistral`, `cohere`, `jina`, `voyage`, `xai`, `openrouter`, `ollama`, `vllm`.

```toml
[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config]
response_headers = true

[routes.plugins.config.providers.groq]
preset = "groq"
api_key = "env:GROQ_API_KEY"
drop_params = true

[routes.plugins.config.providers.deepseek]
preset = "deepseek"
api_key = "env:DEEPSEEK_API_KEY"

[routes.plugins.config.providers.ollama]
preset = "ollama" # defaults to auth = { type = "none" }
```

### Multi-Key Pools & BYOK Passthrough

Distribute load across multiple upstream API keys with automatic cooldown rotation on `429`, or let callers bring their own upstream key (`client_passthrough`):

```toml
[routes.plugins.config.providers.openai_pool]
preset = "openai"
api_keys = ["env:OPENAI_KEY_1", "env:OPENAI_KEY_2"]
key_cooldown_ms = 30000
drop_params = true

[routes.plugins.config.providers.openai_byok]
preset = "openai"
auth = { type = "client_passthrough" }
```

### Protocol Parity Features

- **`drop_params = true`**: Cleanly strips provider-unsupported parameters instead of failing with upstream `400` errors.
- **Cross-provider reasoning / extended thinking**: Maps `reasoning_effort` ↔ Anthropic `thinking` ↔ Gemini `thinkingConfig` ↔ Bedrock, preserving `reasoning_content` and `reasoning_tokens`.
- **Structured outputs**: Translates `response_format` (`json_schema`) for Anthropic and Bedrock.
- **Prompt caching**: Tracks `cache_creation_input_tokens` and translates `cache_control` ↔ Bedrock `cachePoint`.

---

## Dynamic Cloud IAM (Zero SDKs)

Shunt refreshes cloud credentials natively using its internal `HttpClient` and caches tokens across hot reloads—zero AWS/GCP/Azure SDK bloat required.

### AWS Bedrock (`aws_iam`)

Supports `mode = "auto"` (env → EKS IRSA `web_identity` → ECS Task Role → EC2 IMDSv2) plus optional cross-account STS `role_arn`:

```toml
[routes.plugins.config.providers.bedrock]
preset = "bedrock"
region = "us-east-1"
[routes.plugins.config.providers.bedrock.auth]
type = "aws_iam"
mode = "auto" # "auto" | "imds" | "ecs" | "web_identity" | "env"
# role_arn = "arn:aws:iam::123456789012:role/shunt-bedrock-access"
refresh_margin_secs = 300
```

### Google Cloud Vertex AI (`gcp_iam`)

Works for both Gemini on Vertex and Claude on Vertex via GCE/GKE Workload Identity Metadata Server or Service Account JSON RS256 JWT assertion:

```toml
[routes.plugins.config.providers.vertex_gemini]
preset = "gemini"
vertex_project = "my-gcp-project"
vertex_location = "us-central1"
[routes.plugins.config.providers.vertex_gemini.auth]
type = "gcp_iam"
mode = "auto" # checks credentials_json -> credentials_file/GOOGLE_APPLICATION_CREDENTIALS -> metadata
refresh_margin_secs = 300
```

### Azure OpenAI (`azure_ad`)

Supports AKS Workload Identity, `client_credentials`, and Azure IMDS Managed Identity:

```toml
[routes.plugins.config.providers.azure_openai]
preset = "azure_openai"
api_version = "2024-10-21"
[routes.plugins.config.providers.azure_openai.auth]
type = "azure_ad"
mode = "auto" # "auto" | "workload_identity" | "client_credentials" | "managed_identity"
scope = "https://cognitiveservices.azure.com/.default"
refresh_margin_secs = 300
```
