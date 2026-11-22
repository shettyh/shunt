//! Model Context Protocol (MCP) & Agentic Governance plugin pack (`shunt-mcp`).
//!
//! Implemented **100% through `shunt-plugin-sdk`** with zero dependencies on `shunt-core`,
//! providing Streamable HTTP MCP routing, multi-server multiplexing, per-agent tool/resource/prompt
//! ACLs, session hijacking protection, argument/output guardrails (PII, secrets, indirect prompt
//! injection), stuck-agent loop breaking, and Prometheus + OTLP observability.
//!
//! ## Included Plugins
//! - `mcp-auth`: Constant-time SHA-256 virtual keys or upstream identity-header (`jwt-auth` / `mtls-auth`)
//!   authentication, RFC 9728 `/.well-known/oauth-protected-resource` discovery, per-agent ACLs, and
//!   `Mcp-Session-Id` principal binding.
//! - `mcp-router`: Streamable HTTP JSON-RPC 2.0 protocol handler supporting both single-server
//!   passthrough governance and multi-server virtual MCP multiplexing (`initialize`, concurrent
//!   cached `tools/list` / `resources/list` / `prompts/list` fan-out with ACL filtering, namespaced
//!   `tools/call` / `prompts/get` / `resources/read` routing, and stateful upstream session handshakes).
//! - `mcp-guardrails`: Tool allow/deny policies, high-risk tool approval gating, per-tool JSON
//!   argument validation (`required_args`, `forbidden_args`, `allow_patterns`, `deny_patterns`,
//!   `max_arg_bytes`), outbound PII/secret blocking & redaction, inbound indirect prompt-injection
//!   & secret scanning (JSON + SSE), and optional external policy webhooks (OPA / HTTP).
//! - `mcp-rate-limit`: Per-principal RPM & `tools/call` RPM, per-tool rate limits, per-session call
//!   budgets, identical-call agent loop breaker, and RAII in-flight concurrency caps (in-memory or Redis/Valkey).
//! - `mcp-telemetry`: Prometheus exposition metrics (`shunt_mcp_*`), OTLP span enrichment,
//!   structured redacted audit logs, and Admin Inspector `/api/status` runtime introspection.

pub mod auth;
pub mod guardrails;
pub mod rate_limit;
pub mod router;
pub mod telemetry;
pub mod types;

use std::sync::Arc;

use shunt_plugin_sdk::PluginRegistry;

pub use auth::{
    McpAuthFactory, McpAuthPlugin, McpSessionBindingTable, SessionBindingStatsSnapshot,
};
pub use guardrails::{
    BuiltinMcpDetector, GuardrailAction, McpGuardrailStatsSnapshot, McpGuardrailStatsTable,
    McpGuardrailsFactory, McpGuardrailsPlugin, lookup_json_dot_path, redact_text_for_detector,
    scan_and_optionally_redact_value, scan_text_for_detector,
};
pub use rate_limit::{
    McpRateLimitFactory, McpRateLimitPlugin, McpRateLimitStatsSnapshot, McpRateLimitTable,
};
pub use router::{
    McpCatalogStatsSnapshot, McpCatalogTable, McpRouterFactory, McpRouterPlugin,
    McpSessionStatsSnapshot, McpSessionTable,
};
pub use telemetry::{
    McpMetrics, McpMetricsSnapshot, McpTelemetryFactory, McpTelemetryPlugin, inspect_mcp_runtime,
};
pub use types::{
    DEFAULT_PROTOCOL_VERSION, JSONRPC_INTERNAL_ERROR, JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST, JSONRPC_METHOD_NOT_FOUND, JSONRPC_PARSE_ERROR,
    MCP_ERR_APPROVAL_REQUIRED, MCP_ERR_FORBIDDEN, MCP_ERR_GUARDRAIL_BLOCKED, MCP_ERR_RATE_LIMITED,
    MCP_ERR_UNAUTHORIZED, MCP_ERR_UPSTREAM_ERROR, MCP_NAME_HEADER, MCP_PROTOCOL_VERSION_HEADER,
    MCP_SESSION_HEADER, McpGuardrailFinding, McpGuardrailSummary, McpLoopBreakInfo, McpParseError,
    McpParsedRequest, McpPrincipal, McpRequestMeta, McpUpstreamAuth, ResolvedUpstreamAuth,
    SUPPORTED_PROTOCOL_VERSIONS, canonical_json_bytes, extract_mcp_response_payloads,
    extract_sse_json_events, glob_match, join_namespaced, jsonrpc_error_response,
    jsonrpc_result_response, parse_mcp_jsonrpc_request, split_namespaced,
};

/// Registers all built-in `shunt-mcp` plugin factories into the given [`PluginRegistry`].
pub fn register_mcp_plugins(registry: &mut PluginRegistry, metrics: Arc<McpMetrics>) {
    registry.register(McpAuthFactory);
    registry.register(McpRouterFactory);
    registry.register(McpGuardrailsFactory::new(Arc::clone(&metrics)));
    registry.register(McpRateLimitFactory::new(Arc::clone(&metrics)));
    registry.register(McpTelemetryFactory::new(metrics));
}
