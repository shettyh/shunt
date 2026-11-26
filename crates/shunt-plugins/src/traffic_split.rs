//! General-purpose weighted traffic-splitting, synthetic-status, and per-backend
//! header-rewrite plugin (`traffic-split`).
//!
//! Runs strictly on the synchronous fast path (`HookResult::Ready`) using `HookMask::ON_UPSTREAM_SELECT`
//! and opts into `ON_UPSTREAM_REQUEST` / `ON_RESPONSE_HEADERS` only when at least one target
//! configures per-target header modifiers.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Flow, HookMask, HookResult, HttpPlugin, PluginBuildError,
    PluginConfig, PluginFactory, RequestCtx, ResponseHead, StatusCode, UpstreamRequest,
    UpstreamSelection,
};

use crate::header_rewrite::{
    HeaderOps, HeaderValueOrList, compile_multi_pairs, compile_names, compile_pairs,
};

const MAX_SMOOTH_SCHEDULE_LEN: u64 = 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrafficSplitConfig {
    targets: Vec<TrafficSplitTargetConfig>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct TrafficSplitTargetConfig {
    /// Relative traffic weight (default: `1`; `0` disables selection of this target).
    #[serde(default = "default_weight")]
    weight: u32,
    /// Target upstream pool name (mutually exclusive with `status`).
    upstream: Option<String>,
    /// Synthetic HTTP status code to return directly (mutually exclusive with `upstream`).
    status: Option<u16>,
    /// Optional response body when `status` is configured.
    body: Option<String>,
    /// Per-target upstream request header sets.
    request_set: HashMap<String, String>,
    /// Per-target upstream request header appends.
    request_add: HashMap<String, HeaderValueOrList>,
    /// Per-target upstream request header removals.
    request_remove: Vec<String>,
    /// Per-target response header sets.
    response_set: HashMap<String, String>,
    /// Per-target response header appends.
    response_add: HashMap<String, HeaderValueOrList>,
    /// Per-target response header removals.
    response_remove: Vec<String>,
}

fn default_weight() -> u32 {
    1
}

enum SplitAction {
    Upstream(String),
    Synthetic { status: StatusCode, body: String },
}

struct CompiledTarget {
    action: SplitAction,
    req_ops: HeaderOps,
    res_ops: HeaderOps,
}

enum DispatchPlan {
    /// Total positive weight across all targets is zero -> always respond with HTTP 500.
    AlwaysInternalError,
    /// Precomputed smooth weighted round-robin schedule for O(1) interleaved selection.
    SmoothSchedule(Box<[usize]>),
    /// Cumulative weight table fallback when GCD-reduced weight sum exceeds [`MAX_SMOOTH_SCHEDULE_LEN`].
    Cumulative {
        total_weight: u64,
        entries: Box<[(u64, usize)]>,
    },
}

#[derive(Clone, Copy)]
struct SelectedSplitTarget(usize);

pub struct TrafficSplitFactory;

impl PluginFactory for TrafficSplitFactory {
    fn name(&self) -> &str {
        "traffic-split"
    }

    fn build(
        &self,
        config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: TrafficSplitConfig = config.deserialize(self.name())?;
        if cfg.targets.is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`targets` must contain at least one entry".to_owned(),
            });
        }

        let mut targets = Vec::with_capacity(cfg.targets.len());
        let mut weighted_indices: Vec<(usize, u64)> = Vec::new();
        let mut has_req_ops = false;
        let mut has_res_ops = false;

        for (idx, t) in cfg.targets.into_iter().enumerate() {
            let action = match (t.upstream, t.status) {
                (Some(up), None) => {
                    if up.trim().is_empty() {
                        return Err(PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message: format!("targets[{idx}].upstream must not be empty"),
                        });
                    }
                    SplitAction::Upstream(up)
                }
                (None, Some(code)) => {
                    let status =
                        StatusCode::from_u16(code).map_err(|_| PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message: format!(
                                "targets[{idx}].status `{code}` is not a valid HTTP status code"
                            ),
                        })?;
                    SplitAction::Synthetic {
                        status,
                        body: t.body.unwrap_or_default(),
                    }
                }
                (Some(_), Some(_)) => {
                    return Err(PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!(
                            "targets[{idx}] cannot specify both `upstream` and `status`"
                        ),
                    });
                }
                (None, None) => {
                    return Err(PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!(
                            "targets[{idx}] must specify either `upstream` or `status`"
                        ),
                    });
                }
            };

            let req_ops = HeaderOps {
                set: compile_pairs(self.name(), t.request_set)?,
                add: compile_multi_pairs(self.name(), t.request_add)?,
                remove: compile_names(self.name(), t.request_remove)?,
            };
            let res_ops = HeaderOps {
                set: compile_pairs(self.name(), t.response_set)?,
                add: compile_multi_pairs(self.name(), t.response_add)?,
                remove: compile_names(self.name(), t.response_remove)?,
            };
            if !req_ops.is_empty() {
                has_req_ops = true;
            }
            if !res_ops.is_empty() {
                has_res_ops = true;
            }
            if t.weight > 0 {
                weighted_indices.push((idx, u64::from(t.weight)));
            }
            targets.push(CompiledTarget {
                action,
                req_ops,
                res_ops,
            });
        }

        let plan = build_dispatch_plan(&weighted_indices);

        let mut mask = HookMask::ON_UPSTREAM_SELECT;
        if has_req_ops {
            mask |= HookMask::ON_UPSTREAM_REQUEST;
        }
        if has_res_ops {
            mask |= HookMask::ON_RESPONSE_HEADERS;
        }

        Ok(Arc::new(TrafficSplitPlugin {
            mask,
            targets: targets.into_boxed_slice(),
            plan,
            track_selection: has_req_ops || has_res_ops,
            cursor: AtomicU64::new(0),
        }))
    }
}

fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a.max(1)
}

fn build_dispatch_plan(weighted: &[(usize, u64)]) -> DispatchPlan {
    if weighted.is_empty() {
        return DispatchPlan::AlwaysInternalError;
    }

    let mut divisor = weighted[0].1;
    for &(_, w) in &weighted[1..] {
        divisor = gcd_u64(divisor, w);
    }

    let reduced: Vec<(usize, u64)> = weighted
        .iter()
        .map(|&(idx, w)| (idx, (w / divisor).max(1)))
        .collect();
    let total: u64 = reduced
        .iter()
        .fold(0u64, |acc, &(_, w)| acc.saturating_add(w));

    if total == 0 {
        return DispatchPlan::AlwaysInternalError;
    }

    if total <= MAX_SMOOTH_SCHEDULE_LEN {
        // Nginx smooth weighted round-robin precomputation for even distribution over small samples.
        let total_i64 = total as i64;
        let mut current: Vec<i64> = vec![0; reduced.len()];
        let mut schedule = Vec::with_capacity(total as usize);
        for _ in 0..total {
            let mut best_pos = 0usize;
            let mut best_val = i64::MIN;
            for (pos, &(_, eff_w)) in reduced.iter().enumerate() {
                current[pos] += eff_w as i64;
                if current[pos] > best_val {
                    best_val = current[pos];
                    best_pos = pos;
                }
            }
            current[best_pos] -= total_i64;
            schedule.push(reduced[best_pos].0);
        }
        DispatchPlan::SmoothSchedule(schedule.into_boxed_slice())
    } else {
        let mut acc = 0u64;
        let mut entries = Vec::with_capacity(reduced.len());
        for (idx, w) in reduced {
            acc = acc.saturating_add(w);
            entries.push((acc, idx));
        }
        DispatchPlan::Cumulative {
            total_weight: acc,
            entries: entries.into_boxed_slice(),
        }
    }
}

pub struct TrafficSplitPlugin {
    mask: HookMask,
    targets: Box<[CompiledTarget]>,
    plan: DispatchPlan,
    track_selection: bool,
    cursor: AtomicU64,
}

impl TrafficSplitPlugin {
    #[inline]
    fn select_target_idx(&self) -> Option<usize> {
        match &self.plan {
            DispatchPlan::AlwaysInternalError => None,
            DispatchPlan::SmoothSchedule(sched) => {
                let tick = self.cursor.fetch_add(1, Ordering::Relaxed) as usize;
                Some(sched[tick % sched.len()])
            }
            DispatchPlan::Cumulative {
                total_weight,
                entries,
            } => {
                let slot = self.cursor.fetch_add(1, Ordering::Relaxed) % *total_weight;
                let pos = entries.partition_point(|&(cum, _)| cum <= slot);
                entries
                    .get(pos)
                    .or_else(|| entries.last())
                    .map(|&(_, idx)| idx)
            }
        }
    }
}

impl HttpPlugin for TrafficSplitPlugin {
    fn name(&self) -> &str {
        "traffic-split"
    }

    fn hook_mask(&self) -> HookMask {
        self.mask
    }

    fn on_upstream_select<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        selection: &'a mut UpstreamSelection,
    ) -> HookResult<'a, Flow> {
        let Some(target_idx) = self.select_target_idx() else {
            return HookResult::Ready(Flow::Respond(BufferedResponse::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "no active backend targets",
            )));
        };
        let target = &self.targets[target_idx];
        match &target.action {
            SplitAction::Upstream(up) => {
                selection.upstream = up.clone();
                if self.track_selection {
                    ctx.insert_ext(SelectedSplitTarget(target_idx));
                }
                HookResult::Ready(Flow::Continue)
            }
            SplitAction::Synthetic { status, body } => {
                HookResult::Ready(Flow::Respond(BufferedResponse::new(*status, body.clone())))
            }
        }
    }

    fn on_upstream_request<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut UpstreamRequest,
    ) -> HookResult<'a, Flow> {
        if let Some(SelectedSplitTarget(idx)) = ctx.get_ext::<SelectedSplitTarget>().copied()
            && let Some(target) = self.targets.get(idx)
            && !target.req_ops.is_empty()
        {
            target.req_ops.apply(&mut req.headers, &ctx.path_params);
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if let Some(SelectedSplitTarget(idx)) = ctx.get_ext::<SelectedSplitTarget>().copied()
            && let Some(target) = self.targets.get(idx)
            && !target.res_ops.is_empty()
        {
            target.res_ops.apply(&mut res.headers, &ctx.path_params);
        }
        HookResult::Ready(Flow::Continue)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::sync::RwLock;

    use shunt_plugin_sdk::{HeaderMap, Method, StateStore, Uri, Version};

    use super::*;

    fn build_split(cfg: serde_json::Value) -> Arc<dyn HttpPlugin> {
        let build_ctx = BuildContext::new(
            "route:test:traffic-split",
            Arc::new(StateStore::new()),
            Arc::new(RwLock::new(HashSet::new())),
        );
        TrafficSplitFactory
            .build(&PluginConfig::new(cfg), &build_ctx)
            .unwrap()
    }

    fn test_selection() -> UpstreamSelection {
        UpstreamSelection {
            upstream: "default".to_owned(),
            endpoint_override: None,
            attempt: 1,
            max_attempts: 1,
            response_headers_timeout_override: None,
        }
    }

    #[test]
    fn smooth_weighted_split_distributes_proportionally_with_synthetic_500() {
        let plugin = build_split(serde_json::json!({
            "targets": [
                { "weight": 80, "upstream": "svc_a", "request_set": { "x-target": "a" } },
                { "weight": 20, "status": 500, "body": "bad backend" }
            ]
        }));
        assert!(plugin.hook_mask().contains(HookMask::ON_UPSTREAM_SELECT));
        assert!(plugin.hook_mask().contains(HookMask::ON_UPSTREAM_REQUEST));
        assert!(!plugin.hook_mask().contains(HookMask::ON_RESPONSE_HEADERS));

        let addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let mut a_count = 0usize;
        let mut err_count = 0usize;
        for i in 0..10 {
            let mut ctx = RequestCtx::new(i, addr, None);
            let mut sel = test_selection();
            let flow = match plugin.on_upstream_select(&mut ctx, &mut sel) {
                HookResult::Ready(f) => f,
                _ => panic!("expected Ready"),
            };
            match flow {
                Flow::Continue => {
                    assert_eq!(sel.upstream, "svc_a");
                    let mut up_req = UpstreamRequest {
                        method: Method::GET,
                        uri: Uri::from_static("/"),
                        headers: HeaderMap::new(),
                        body: None,
                        endpoint_uri: None,
                    };
                    let _ = plugin.on_upstream_request(&mut ctx, &mut up_req);
                    assert_eq!(up_req.headers.get("x-target").unwrap(), "a");
                    a_count += 1;
                }
                Flow::Respond(resp) => {
                    assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
                    err_count += 1;
                }
                _ => panic!("unexpected result"),
            }
        }
        assert_eq!(a_count, 8);
        assert_eq!(err_count, 2);
    }

    #[test]
    fn zero_total_weight_returns_500() {
        let plugin = build_split(serde_json::json!({
            "targets": [
                { "weight": 0, "upstream": "svc_a" }
            ]
        }));
        assert_eq!(plugin.hook_mask(), HookMask::ON_UPSTREAM_SELECT);
        let addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let mut ctx = RequestCtx::new(1, addr, None);
        let mut sel = test_selection();
        match plugin.on_upstream_select(&mut ctx, &mut sel) {
            HookResult::Ready(Flow::Respond(resp)) => {
                assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
            }
            _ => panic!("expected 500 response"),
        }
    }

    #[test]
    fn per_target_response_headers_apply_only_to_selected_target() {
        let plugin = build_split(serde_json::json!({
            "targets": [
                { "weight": 1, "upstream": "svc_a", "response_add": { "x-v": ["1", "2"] } },
                { "weight": 1, "upstream": "svc_b", "response_set": { "x-v": "b" } }
            ]
        }));
        let addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let mut seen_a = false;
        let mut seen_b = false;
        for i in 0..2 {
            let mut ctx = RequestCtx::new(i, addr, None);
            let mut sel = test_selection();
            assert!(matches!(
                plugin.on_upstream_select(&mut ctx, &mut sel),
                HookResult::Ready(Flow::Continue)
            ));
            let mut res = ResponseHead {
                status: StatusCode::OK,
                version: Version::HTTP_11,
                headers: HeaderMap::new(),
            };
            let _ = plugin.on_response_headers(&mut ctx, &mut res);
            if sel.upstream == "svc_a" {
                let vals: Vec<&str> = res
                    .headers
                    .get_all("x-v")
                    .iter()
                    .map(|v| v.to_str().unwrap())
                    .collect();
                assert_eq!(vals, vec!["1", "2"]);
                seen_a = true;
            } else {
                assert_eq!(res.headers.get("x-v").unwrap(), "b");
                seen_b = true;
            }
        }
        assert!(seen_a && seen_b);
    }
}
