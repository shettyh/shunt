//! Kubernetes Gateway API v1 status models (`GatewayClass`, `Gateway`, `HTTPRoute`)
//! and pure-`std` RFC3339 UTC timestamp formatting.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::types::{K8sParentRef, K8sRouteGroupKind};

/// Official SIG-Network Gateway API `GATEWAY-HTTP` features supported by Shunt,
/// published in `GatewayClass.status.supportedFeatures` (GEP-2162).
pub const SUPPORTED_GATEWAY_FEATURES: &[&str] = &[
    // Core GATEWAY-HTTP
    "Gateway",
    "HTTPRoute",
    "ReferenceGrant",
    // Extended GATEWAY-HTTP
    "GatewayPort8080",
    "HTTPRouteQueryParamMatching",
    "HTTPRouteMethodMatching",
    "HTTPRouteResponseHeaderModification",
    "HTTPRouteBackendRequestHeaderModification",
    "HTTPRoutePortRedirect",
    "HTTPRouteSchemeRedirect",
    "HTTPRoutePathRedirect",
    "HTTPRouteHostRewrite",
    "HTTPRoutePathRewrite",
    "HTTPRouteRequestMirror",
    "HTTPRouteRequestMultipleMirrors",
    "HTTPRouteBackendTimeout",
    "HTTPRouteRequestTimeout",
    "HTTPRoute303RedirectStatusCode",
    "HTTPRoute307RedirectStatusCode",
    "HTTPRoute308RedirectStatusCode",
];

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct K8sCondition {
    #[serde(rename = "type")]
    pub condition_type: String,
    /// `"True"`, `"False"`, or `"Unknown"`.
    pub status: String,
    pub observed_generation: i64,
    pub last_transition_time: String,
    pub reason: String,
    pub message: String,
}

impl K8sCondition {
    pub fn new(
        condition_type: impl Into<String>,
        status: bool,
        observed_generation: i64,
        reason: impl Into<String>,
        message: impl Into<String>,
        timestamp: &str,
    ) -> Self {
        Self {
            condition_type: condition_type.into(),
            status: if status {
                "True".to_owned()
            } else {
                "False".to_owned()
            },
            observed_generation,
            last_transition_time: timestamp.to_owned(),
            reason: reason.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct K8sSupportedFeature {
    pub name: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct K8sGatewayClassStatus {
    pub conditions: Vec<K8sCondition>,
    pub supported_features: Vec<K8sSupportedFeature>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct K8sGatewayAddress {
    #[serde(rename = "type")]
    pub address_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct K8sListenerStatus {
    pub name: String,
    pub supported_kinds: Vec<K8sRouteGroupKind>,
    pub attached_routes: i32,
    pub conditions: Vec<K8sCondition>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct K8sGatewayStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<K8sGatewayAddress>,
    pub conditions: Vec<K8sCondition>,
    pub listeners: Vec<K8sListenerStatus>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct K8sRouteParentStatus {
    pub parent_ref: K8sParentRef,
    pub controller_name: String,
    pub conditions: Vec<K8sCondition>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct K8sHttpRouteStatus {
    pub parents: Vec<K8sRouteParentStatus>,
}

/// Complete computed Kubernetes `.status` plan emitted by [`super::compile_k8s_gateway_cluster`].
#[derive(Debug, Clone, Default)]
pub struct K8sStatusPlan {
    /// Keyed by `GatewayClass.metadata.name`.
    pub gateway_classes: BTreeMap<String, K8sGatewayClassStatus>,
    /// Keyed by `(Gateway.namespace, Gateway.name)`.
    pub gateways: BTreeMap<(String, String), K8sGatewayStatus>,
    /// Keyed by `(HTTPRoute.namespace, HTTPRoute.name)`.
    pub http_routes: BTreeMap<(String, String), K8sHttpRouteStatus>,
    /// Existing parent status entries from OTHER controllers preserved during merge-patch.
    pub foreign_route_parents: BTreeMap<(String, String), Vec<JsonValue>>,
}

/// Formats `SystemTime::now()` as RFC3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`) with zero external crates.
pub fn format_rfc3339_utc(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;

    // Howard Hinnant's civil-from-days algorithm (exact Gregorian proleptic calendar).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn rfc3339_utc_formats_known_epochs_exactly() {
        assert_eq!(format_rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // 2024-02-29T12:34:56Z (leap day!) = 1709210096
        let leap = UNIX_EPOCH + Duration::from_secs(1_709_210_096);
        assert_eq!(format_rfc3339_utc(leap), "2024-02-29T12:34:56Z");
    }
}
