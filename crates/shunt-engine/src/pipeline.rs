use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{self, HeaderName};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Uri};
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use shunt_plugin_sdk::{
    BufferedResponse, ClientCertInfo, Flow, HookMask, HttpPlugin, RequestCtx, RequestHead,
    RequestSummary, ResponseHead, RouteDecision, StreamFlow, UpstreamRequest, UpstreamSelection,
};
use tokio::sync::mpsc;
use tracing::warn;

use crate::body::{IdleTimeoutBody, ShuntBody, TrackedPassthroughBody, collect_body_limited};
use crate::catch::run_hook_isolated;
use crate::error::CoreError;
use crate::snapshot::GatewaySnapshot;
use crate::upstream::build_target_uri;
use crate::ws::{handle_websocket_upgrade, is_websocket_upgrade};

/// Bounded channel capacity for hooked streaming bodies (provides natural backpressure).
const STREAM_CHANNEL_CAPACITY: usize = 16;

/// Executes a single incoming HTTP request end-to-end against an immutable [`GatewaySnapshot`].
#[allow(clippy::too_many_arguments)]
pub async fn execute_request(
    snapshot: Arc<GatewaySnapshot>,
    mut req: Request<hyper::body::Incoming>,
    request_id: u64,
    client_addr: SocketAddr,
    is_tls: bool,
    tls_sni: Option<String>,
    client_cert: Option<Arc<ClientCertInfo>>,
    trace_enabled: bool,
) -> Response<ShuntBody> {
    let mut ctx = RequestCtx::new(request_id, client_addr, tls_sni)
        .with_tls(is_tls)
        .with_client_cert(client_cert);
    ctx.trace_enabled = trace_enabled;

    let Some(route) = snapshot.match_route(&req).cloned() else {
        return build_error_response(StatusCode::NOT_FOUND, "no matching route");
    };

    ctx.route_id = Some(route.id.clone());
    if !route.hook_mask.is_empty() && route.matcher.path.has_params() {
        ctx.path_params = route.matcher.path.extract_params(req.uri().path());
    }
    let plugins = Arc::clone(&route.plugins);
    let mask = route.hook_mask;

    // Capture WebSocket upgrade handle BEFORE splitting request parts.
    let ws_upgrade = if route.allow_websockets && is_websocket_upgrade(req.method(), req.headers())
    {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let (parts, incoming_body) = req.into_parts();
    let mut req_head = RequestHead {
        method: parts.method,
        uri: parts.uri,
        version: parts.version,
        headers: parts.headers,
    };

    // -------------------------------------------------------------------------
    // Stage 1: on_request_headers
    // -------------------------------------------------------------------------
    if mask.contains(HookMask::ON_REQUEST_HEADERS) {
        for plugin in plugins.iter() {
            if !plugin.hook_mask().contains(HookMask::ON_REQUEST_HEADERS) {
                continue;
            }
            let start = ctx.trace_enabled.then(Instant::now);
            let res =
                run_hook_isolated(|| plugin.on_request_headers(&mut ctx, &mut req_head)).await;
            if let Some(s) = start {
                ctx.record_timing(plugin.name(), "on_request_headers", s.elapsed());
            }
            match res {
                Ok(Flow::Continue) => {}
                Ok(Flow::Respond(resp)) => {
                    return finish_short_circuit(&plugins, mask, ctx, &route.id, resp, 0, None);
                }
                Ok(Flow::RetryUpstream) | Ok(Flow::InspectResponseBody { .. }) => {
                    warn!(
                        plugin = plugin.name(),
                        "RetryUpstream/InspectResponseBody ignored in on_request_headers"
                    );
                }
                Err(panic_msg) => {
                    warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked in on_request_headers");
                    return finish_error(
                        &plugins,
                        mask,
                        ctx,
                        &route.id,
                        None,
                        None,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal plugin error",
                        format!(
                            "plugin `{}` panicked in on_request_headers: {panic_msg}",
                            plugin.name()
                        ),
                        0,
                        None,
                    );
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Stage 2: Optional Request Body Buffering (strictly opt-in via HookMask or sampled mirror)
    // -------------------------------------------------------------------------
    let sampled_mirrors: Vec<Arc<crate::snapshot::CompiledMirror>> =
        if ws_upgrade.is_none() && !route.mirrors.is_empty() {
            route
                .mirrors
                .iter()
                .filter(|m| m.should_sample())
                .cloned()
                .collect()
        } else {
            Vec::new()
        };

    let mut buffered_body: Option<Bytes> = None;
    let mut unbuffered_incoming: Option<hyper::body::Incoming> = None;
    let mut request_bytes: u64 = 0;

    let needs_buffer =
        mask.contains(HookMask::REQUEST_BODY_BUFFERED) || !sampled_mirrors.is_empty();

    // Upfront Content-Length enforcement whenever buffering OR an explicit route/plugin cap is set.
    let upfront_cap = if needs_buffer {
        Some(route.max_body_bytes)
    } else {
        route.explicit_max_body_bytes
    };
    if ws_upgrade.is_none()
        && let Some(cap) = upfront_cap
        && let Some(cl) = req_head
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
        && cl > cap
    {
        return finish_error(
            &plugins,
            mask,
            ctx,
            &route.id,
            None,
            None,
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large",
            CoreError::BodyTooLarge(cap).to_string(),
            0,
            None,
        );
    }

    if ws_upgrade.is_none() && needs_buffer {
        let mut body_bytes = match collect_body_limited(incoming_body, route.max_body_bytes).await {
            Ok(b) => b,
            Err(CoreError::BodyTooLarge(cap)) => {
                return finish_error(
                    &plugins,
                    mask,
                    ctx,
                    &route.id,
                    None,
                    None,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body too large",
                    CoreError::BodyTooLarge(cap).to_string(),
                    0,
                    None,
                );
            }
            Err(e) => {
                return finish_error(
                    &plugins,
                    mask,
                    ctx,
                    &route.id,
                    None,
                    None,
                    StatusCode::BAD_REQUEST,
                    "failed to read request body",
                    e.to_string(),
                    0,
                    None,
                );
            }
        };

        request_bytes = body_bytes.len() as u64;

        if mask.contains(HookMask::REQUEST_BODY_BUFFERED) {
            for plugin in plugins.iter() {
                if !plugin.hook_mask().contains(HookMask::REQUEST_BODY_BUFFERED) {
                    continue;
                }
                let start = ctx.trace_enabled.then(Instant::now);
                let res = run_hook_isolated(|| {
                    plugin.on_request_body_buffered(&mut ctx, &mut body_bytes)
                })
                .await;
                if let Some(s) = start {
                    ctx.record_timing(plugin.name(), "on_request_body_buffered", s.elapsed());
                }
                match res {
                    Ok(Flow::Continue) => {}
                    Ok(Flow::Respond(resp)) => {
                        return finish_short_circuit(
                            &plugins,
                            mask,
                            ctx,
                            &route.id,
                            resp,
                            request_bytes,
                            None,
                        );
                    }
                    Ok(Flow::RetryUpstream) | Ok(Flow::InspectResponseBody { .. }) => {
                        warn!(
                            plugin = plugin.name(),
                            "RetryUpstream/InspectResponseBody ignored in on_request_body_buffered"
                        );
                    }
                    Err(panic_msg) => {
                        warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked in on_request_body_buffered");
                        return finish_error(
                            &plugins,
                            mask,
                            ctx,
                            &route.id,
                            None,
                            None,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal plugin error",
                            format!(
                                "plugin `{}` panicked in on_request_body_buffered: {panic_msg}",
                                plugin.name()
                            ),
                            request_bytes,
                            None,
                        );
                    }
                }
            }
        }

        request_bytes = body_bytes.len() as u64;
        buffered_body = Some(body_bytes);
    } else if ws_upgrade.is_none() {
        if let Some(exact) = incoming_body.size_hint().exact() {
            request_bytes = exact;
        }
        unbuffered_incoming = Some(incoming_body);
    }

    // -------------------------------------------------------------------------
    // Stage 3: on_route
    // -------------------------------------------------------------------------
    let mut decision = RouteDecision {
        route_id: route.id.clone(),
        upstream: route.upstream.clone(),
        max_attempts: route.max_attempts.max(1),
    };

    if mask.contains(HookMask::ON_ROUTE) {
        for plugin in plugins.iter() {
            if !plugin.hook_mask().contains(HookMask::ON_ROUTE) {
                continue;
            }
            let start = ctx.trace_enabled.then(Instant::now);
            let res = run_hook_isolated(|| plugin.on_route(&mut ctx, &mut decision)).await;
            if let Some(s) = start {
                ctx.record_timing(plugin.name(), "on_route", s.elapsed());
            }
            match res {
                Ok(Flow::Continue) => {}
                Ok(Flow::Respond(resp)) => {
                    return finish_short_circuit(
                        &plugins,
                        mask,
                        ctx,
                        &route.id,
                        resp,
                        request_bytes,
                        None,
                    );
                }
                Ok(Flow::RetryUpstream) | Ok(Flow::InspectResponseBody { .. }) => {
                    warn!(
                        plugin = plugin.name(),
                        "RetryUpstream/InspectResponseBody ignored in on_route"
                    );
                }
                Err(panic_msg) => {
                    warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked in on_route");
                    return finish_error(
                        &plugins,
                        mask,
                        ctx,
                        &route.id,
                        None,
                        None,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal plugin error",
                        format!(
                            "plugin `{}` panicked in on_route: {panic_msg}",
                            plugin.name()
                        ),
                        request_bytes,
                        None,
                    );
                }
            }
        }
    }

    // Apply optional route strip_prefix on the canonical URI.
    if let Some(prefix) = &route.strip_prefix {
        req_head.uri = strip_uri_prefix(&req_head.uri, prefix);
    }

    // Append client IP to X-Forwarded-For.
    append_forwarded_for(&mut req_head.headers, client_addr);

    // Delegate WebSocket upgrades to the dedicated H1 upgrade tunnel handler.
    if let Some(downstream_upgrade) = ws_upgrade {
        return handle_websocket_upgrade(
            snapshot,
            route,
            ctx,
            req_head,
            decision,
            downstream_upgrade,
        )
        .await;
    }

    // Sanitize hop-by-hop headers once on the canonical request head.
    strip_hop_by_hop_headers(&mut req_head.headers);
    // Remove downstream Host so hyper derives Host/:authority from the chosen upstream URI
    // (plugins may still set a custom Host header inside `on_upstream_request`).
    req_head.headers.remove(header::HOST);

    // Fire-and-forget sampled HTTP traffic mirroring (bounded concurrency, never blocks primary).
    if !sampled_mirrors.is_empty() {
        spawn_traffic_mirrors(
            &snapshot,
            &sampled_mirrors,
            &req_head,
            buffered_body.clone(),
        );
    }

    let max_attempts = decision.max_attempts.max(1);
    let body_is_replayable = buffered_body.is_some()
        || unbuffered_incoming
            .as_ref()
            .map(|b| b.is_end_stream())
            .unwrap_or(true);

    // -------------------------------------------------------------------------
    // Stage 4: Per-Attempt Upstream Loop
    // -------------------------------------------------------------------------
    let mut tried_endpoints_by_upstream: Vec<(String, usize)> = Vec::new();
    let mut last_error: Option<(StatusCode, String)> = None;
    let mut last_upstream_name = Some(decision.upstream.clone());
    let mut last_endpoint_label: Option<String> = None;

    for attempt in 1..=max_attempts {
        ctx.attempt = attempt;

        let mut selection = UpstreamSelection {
            upstream: decision.upstream.clone(),
            endpoint_override: None,
            attempt,
            max_attempts,
            response_headers_timeout_override: None,
        };

        // 4a: on_upstream_select
        if mask.contains(HookMask::ON_UPSTREAM_SELECT) {
            for plugin in plugins.iter() {
                if !plugin.hook_mask().contains(HookMask::ON_UPSTREAM_SELECT) {
                    continue;
                }
                let start = ctx.trace_enabled.then(Instant::now);
                let res =
                    run_hook_isolated(|| plugin.on_upstream_select(&mut ctx, &mut selection)).await;
                if let Some(s) = start {
                    ctx.record_timing(plugin.name(), "on_upstream_select", s.elapsed());
                }
                match res {
                    Ok(Flow::Continue) => {}
                    Ok(Flow::Respond(resp)) => {
                        return finish_short_circuit(
                            &plugins,
                            mask,
                            ctx,
                            &route.id,
                            resp,
                            request_bytes,
                            Some(selection.upstream),
                        );
                    }
                    Ok(Flow::RetryUpstream) | Ok(Flow::InspectResponseBody { .. }) => {
                        warn!(
                            plugin = plugin.name(),
                            "RetryUpstream/InspectResponseBody ignored in on_upstream_select"
                        );
                    }
                    Err(panic_msg) => {
                        warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked in on_upstream_select");
                        return finish_error(
                            &plugins,
                            mask,
                            ctx,
                            &route.id,
                            Some(selection.upstream),
                            None,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal plugin error",
                            format!(
                                "plugin `{}` panicked in on_upstream_select: {panic_msg}",
                                plugin.name()
                            ),
                            request_bytes,
                            None,
                        );
                    }
                }
            }
        }

        last_upstream_name = Some(selection.upstream.clone());

        let Some(pool) = snapshot.upstream(&selection.upstream) else {
            let msg = format!("unknown upstream `{}`", selection.upstream);
            return finish_error(
                &plugins,
                mask,
                ctx,
                &route.id,
                Some(selection.upstream),
                None,
                StatusCode::BAD_GATEWAY,
                "unknown upstream",
                msg,
                request_bytes,
                None,
            );
        };

        let tried_for_this_upstream: Vec<usize> = tried_endpoints_by_upstream
            .iter()
            .filter_map(|(up, idx)| (up == &selection.upstream).then_some(*idx))
            .collect();

        let (ep_idx, base_uri, endpoint_label) =
            if let Some(override_url) = &selection.endpoint_override {
                match override_url.parse::<Uri>() {
                    Ok(u) => (None, u, override_url.clone()),
                    Err(e) => {
                        let msg = format!("invalid endpoint_override `{override_url}`: {e}");
                        return finish_error(
                            &plugins,
                            mask,
                            ctx,
                            &route.id,
                            Some(selection.upstream),
                            Some(override_url.clone()),
                            StatusCode::BAD_GATEWAY,
                            "invalid upstream endpoint override",
                            msg,
                            request_bytes,
                            None,
                        );
                    }
                }
            } else {
                let (idx, ep) = pool.select_endpoint(&tried_for_this_upstream);
                tried_endpoints_by_upstream.push((selection.upstream.clone(), idx));
                (Some(idx), ep.base_uri.clone(), ep.raw_url.clone())
            };

        last_endpoint_label = Some(endpoint_label.clone());

        // 4b: Clone canonical request head (+ cheap O(1) Bytes refcount clone if buffered)
        let mut up_req = UpstreamRequest {
            method: req_head.method.clone(),
            uri: req_head.uri.clone(),
            headers: req_head.headers.clone(),
            body: buffered_body.clone(),
            endpoint_uri: Some(base_uri.clone()),
        };

        // 4c: on_upstream_request
        if mask.contains(HookMask::ON_UPSTREAM_REQUEST) {
            for plugin in plugins.iter() {
                if !plugin.hook_mask().contains(HookMask::ON_UPSTREAM_REQUEST) {
                    continue;
                }
                let start = ctx.trace_enabled.then(Instant::now);
                let res =
                    run_hook_isolated(|| plugin.on_upstream_request(&mut ctx, &mut up_req)).await;
                if let Some(s) = start {
                    ctx.record_timing(plugin.name(), "on_upstream_request", s.elapsed());
                }
                match res {
                    Ok(Flow::Continue) => {}
                    Ok(Flow::Respond(resp)) => {
                        return finish_short_circuit(
                            &plugins,
                            mask,
                            ctx,
                            &route.id,
                            resp,
                            request_bytes,
                            Some(selection.upstream),
                        );
                    }
                    Ok(Flow::RetryUpstream) | Ok(Flow::InspectResponseBody { .. }) => {
                        warn!(
                            plugin = plugin.name(),
                            "RetryUpstream/InspectResponseBody ignored in on_upstream_request"
                        );
                    }
                    Err(panic_msg) => {
                        warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked in on_upstream_request");
                        return finish_error(
                            &plugins,
                            mask,
                            ctx,
                            &route.id,
                            Some(selection.upstream),
                            Some(endpoint_label),
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal plugin error",
                            format!(
                                "plugin `{}` panicked in on_upstream_request: {panic_msg}",
                                plugin.name()
                            ),
                            request_bytes,
                            None,
                        );
                    }
                }
            }
        }

        let target_uri = match build_target_uri(&base_uri, &up_req.uri) {
            Ok(u) => u,
            Err(e) => {
                return finish_error(
                    &plugins,
                    mask,
                    ctx,
                    &route.id,
                    Some(selection.upstream),
                    Some(endpoint_label),
                    StatusCode::BAD_GATEWAY,
                    "invalid upstream URI",
                    e.to_string(),
                    request_bytes,
                    None,
                );
            }
        };

        // Construct outgoing request body.
        let mut streaming_body_exceeded: Option<Arc<AtomicBool>> = None;
        let out_body = if let Some(body_bytes) = up_req.body {
            // Ensure Content-Length matches the (potentially rewritten) buffered body.
            up_req.headers.remove(header::TRANSFER_ENCODING);
            if let Ok(len_val) = HeaderValue::from_str(&body_bytes.len().to_string()) {
                up_req.headers.insert(header::CONTENT_LENGTH, len_val);
            }
            ShuntBody::full(body_bytes)
        } else if let Some(incoming) = unbuffered_incoming.take() {
            if mask.contains(HookMask::REQUEST_BODY_STREAM) {
                up_req.headers.remove(header::CONTENT_LENGTH);
                let flag = route
                    .explicit_max_body_bytes
                    .map(|_| Arc::new(AtomicBool::new(false)));
                streaming_body_exceeded = flag.clone();
                spawn_request_body_stream_pump(
                    incoming,
                    Arc::clone(&plugins),
                    ctx.request_id,
                    ctx.client_addr,
                    ctx.tls_sni.clone(),
                    ctx.client_cert.clone(),
                    ctx.route_id.clone(),
                    attempt,
                    route.explicit_max_body_bytes,
                    flag,
                )
            } else if let Some(cap) = route.explicit_max_body_bytes {
                let flag = Arc::new(AtomicBool::new(false));
                streaming_body_exceeded = Some(Arc::clone(&flag));
                ShuntBody::limited_passthrough(incoming, cap, flag)
            } else {
                ShuntBody::passthrough(incoming)
            }
        } else {
            ShuntBody::empty()
        };

        let mut hyper_req_builder = Request::builder().method(up_req.method).uri(target_uri);
        if let Some(h) = hyper_req_builder.headers_mut() {
            *h = up_req.headers;
        }
        let hyper_req = match hyper_req_builder.body(out_body) {
            Ok(r) => r,
            Err(e) => {
                return finish_error(
                    &plugins,
                    mask,
                    ctx,
                    &route.id,
                    Some(selection.upstream),
                    Some(endpoint_label),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to build upstream request",
                    e.to_string(),
                    request_bytes,
                    None,
                );
            }
        };

        // 4d: Send request to upstream pool with split connect + response_headers timeouts.
        let effective_headers_timeout = selection
            .response_headers_timeout_override
            .or(route.timeouts.response_headers_timeout);
        let upstream_res = match pool
            .send_request(hyper_req, effective_headers_timeout)
            .await
        {
            Ok(res) => {
                if let Some(idx) = ep_idx {
                    pool.record_success(idx);
                }
                res
            }
            Err(err) => {
                let err_str = err.to_string();
                let is_body_too_large = matches!(err, CoreError::BodyTooLarge(_))
                    || streaming_body_exceeded
                        .as_ref()
                        .map(|f| f.load(Ordering::Acquire))
                        .unwrap_or(false);
                if !is_body_too_large && let Some(idx) = ep_idx {
                    pool.record_failure(idx);
                }
                let status = if is_body_too_large {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    match &err {
                        CoreError::ConnectTimeout(_) | CoreError::ResponseHeadersTimeout(_) => {
                            StatusCode::GATEWAY_TIMEOUT
                        }
                        _ => StatusCode::BAD_GATEWAY,
                    }
                };
                ctx.last_upstream_error = Some(err_str.clone());
                ctx.last_upstream_status = Some(status);
                last_error = Some((status, err_str));

                if !is_body_too_large && attempt < max_attempts && body_is_replayable {
                    continue;
                }
                let (st, msg) = last_error.unwrap();
                return finish_error(
                    &plugins,
                    mask,
                    ctx,
                    &route.id,
                    Some(selection.upstream),
                    Some(endpoint_label),
                    st,
                    if st == StatusCode::PAYLOAD_TOO_LARGE {
                        "request body too large"
                    } else if st == StatusCode::GATEWAY_TIMEOUT {
                        "upstream timed out"
                    } else {
                        "upstream request failed"
                    },
                    msg,
                    request_bytes,
                    None,
                );
            }
        };

        let ttfb = Some(ctx.started_at.elapsed());
        let (res_parts, res_incoming) = upstream_res.into_parts();
        let mut res_head = ResponseHead {
            status: res_parts.status,
            version: res_parts.version,
            headers: res_parts.headers,
        };
        strip_hop_by_hop_headers(&mut res_head.headers);
        ctx.last_upstream_status = Some(res_head.status);
        ctx.last_upstream_error = None;

        // 4e: on_response_headers (can short-circuit Respond, trigger Flow::RetryUpstream,
        // or request bounded pre-flush body inspection via Flow::InspectResponseBody)
        let mut retry_requested = false;
        let mut inspect_max_bytes: Option<usize> = None;
        if mask.contains(HookMask::ON_RESPONSE_HEADERS) {
            for plugin in plugins.iter() {
                if !plugin.hook_mask().contains(HookMask::ON_RESPONSE_HEADERS) {
                    continue;
                }
                let start = ctx.trace_enabled.then(Instant::now);
                let res =
                    run_hook_isolated(|| plugin.on_response_headers(&mut ctx, &mut res_head)).await;
                if let Some(s) = start {
                    ctx.record_timing(plugin.name(), "on_response_headers", s.elapsed());
                }
                match res {
                    Ok(Flow::Continue) => {}
                    Ok(Flow::Respond(resp)) => {
                        return finish_short_circuit(
                            &plugins,
                            mask,
                            ctx,
                            &route.id,
                            resp,
                            request_bytes,
                            Some(selection.upstream),
                        );
                    }
                    Ok(Flow::RetryUpstream) => {
                        if attempt < max_attempts && body_is_replayable {
                            retry_requested = true;
                            break;
                        } else {
                            warn!(
                                plugin = plugin.name(),
                                attempt,
                                max_attempts,
                                body_is_replayable,
                                "RetryUpstream cannot retry (attempts exhausted or unbuffered non-empty body)"
                            );
                        }
                    }
                    Ok(Flow::InspectResponseBody { max_bytes }) => {
                        let cap = max_bytes.max(1);
                        inspect_max_bytes = Some(inspect_max_bytes.map_or(cap, |p| p.max(cap)));
                    }
                    Err(panic_msg) => {
                        warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked in on_response_headers");
                        return finish_error(
                            &plugins,
                            mask,
                            ctx,
                            &route.id,
                            Some(selection.upstream),
                            Some(endpoint_label),
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal plugin error",
                            format!(
                                "plugin `{}` panicked in on_response_headers: {panic_msg}",
                                plugin.name()
                            ),
                            request_bytes,
                            ttfb,
                        );
                    }
                }
            }
        }

        if retry_requested {
            drop(res_incoming);
            continue;
        }

        // 4f: Conditional bounded pre-flush response-body inspection
        if let Some(max_bytes) = inspect_max_bytes {
            let mut inspected_body = match collect_body_limited(res_incoming, max_bytes).await {
                Ok(b) => b,
                Err(CoreError::BodyTooLarge(cap)) => {
                    return finish_error(
                        &plugins,
                        mask,
                        ctx,
                        &route.id,
                        Some(selection.upstream),
                        Some(endpoint_label),
                        StatusCode::BAD_GATEWAY,
                        "upstream response exceeded inspection limit",
                        CoreError::BodyTooLarge(cap).to_string(),
                        request_bytes,
                        ttfb,
                    );
                }
                Err(err) => {
                    return finish_error(
                        &plugins,
                        mask,
                        ctx,
                        &route.id,
                        Some(selection.upstream),
                        Some(endpoint_label),
                        StatusCode::BAD_GATEWAY,
                        "failed to read upstream response body",
                        err.to_string(),
                        request_bytes,
                        ttfb,
                    );
                }
            };

            if mask.contains(HookMask::ON_RESPONSE_BODY_INSPECTED) {
                for plugin in plugins.iter() {
                    if !plugin
                        .hook_mask()
                        .contains(HookMask::ON_RESPONSE_BODY_INSPECTED)
                    {
                        continue;
                    }
                    let start = ctx.trace_enabled.then(Instant::now);
                    let res = run_hook_isolated(|| {
                        plugin.on_response_body_inspected(&mut ctx, &mut res_head, &inspected_body)
                    })
                    .await;
                    if let Some(s) = start {
                        ctx.record_timing(plugin.name(), "on_response_body_inspected", s.elapsed());
                    }
                    match res {
                        Ok(Flow::Continue) => {}
                        Ok(Flow::Respond(resp)) => {
                            return finish_short_circuit(
                                &plugins,
                                mask,
                                ctx,
                                &route.id,
                                resp,
                                request_bytes,
                                Some(selection.upstream),
                            );
                        }
                        Ok(Flow::RetryUpstream) => {
                            if attempt < max_attempts && body_is_replayable {
                                retry_requested = true;
                                break;
                            } else {
                                warn!(
                                    plugin = plugin.name(),
                                    attempt,
                                    max_attempts,
                                    body_is_replayable,
                                    "RetryUpstream cannot retry after response body inspection"
                                );
                            }
                        }
                        Ok(Flow::InspectResponseBody { .. }) => {
                            warn!(
                                plugin = plugin.name(),
                                "InspectResponseBody ignored in on_response_body_inspected"
                            );
                        }
                        Err(panic_msg) => {
                            warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked in on_response_body_inspected");
                            return finish_error(
                                &plugins,
                                mask,
                                ctx,
                                &route.id,
                                Some(selection.upstream),
                                Some(endpoint_label),
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "internal plugin error",
                                format!(
                                    "plugin `{}` panicked in on_response_body_inspected: {panic_msg}",
                                    plugin.name()
                                ),
                                request_bytes,
                                ttfb,
                            );
                        }
                    }
                }
            }

            if retry_requested {
                continue;
            }

            // No retry triggered: flush the inspected response downstream cleanly.
            // Still pass through any RESPONSE_BODY_STREAM plugins so usage/guardrails see it.
            let mut error_msg: Option<String> = None;
            let mut aborted_mid_stream = false;
            if mask.contains(HookMask::RESPONSE_BODY_STREAM) {
                for plugin in plugins.iter() {
                    if !plugin.hook_mask().contains(HookMask::RESPONSE_BODY_STREAM) {
                        continue;
                    }
                    match run_hook_isolated(|| {
                        plugin.on_response_body_chunk(&mut ctx, &mut inspected_body, false)
                    })
                    .await
                    {
                        Ok(StreamFlow::Continue) => {}
                        Ok(StreamFlow::Abort(reason)) => {
                            aborted_mid_stream = true;
                            error_msg = Some(reason);
                            break;
                        }
                        Err(panic_msg) => {
                            aborted_mid_stream = true;
                            error_msg = Some(format!(
                                "plugin `{}` panicked in on_response_body_chunk: {panic_msg}",
                                plugin.name()
                            ));
                            break;
                        }
                    }
                }
                if !aborted_mid_stream {
                    let mut flush = Bytes::new();
                    for plugin in plugins.iter() {
                        if !plugin.hook_mask().contains(HookMask::RESPONSE_BODY_STREAM) {
                            continue;
                        }
                        match run_hook_isolated(|| {
                            plugin.on_response_body_chunk(&mut ctx, &mut flush, true)
                        })
                        .await
                        {
                            Ok(StreamFlow::Continue) => {}
                            Ok(StreamFlow::Abort(reason)) => {
                                aborted_mid_stream = true;
                                error_msg = Some(reason);
                                break;
                            }
                            Err(panic_msg) => {
                                aborted_mid_stream = true;
                                error_msg = Some(format!(
                                    "plugin `{}` panicked in on_response_body_chunk: {panic_msg}",
                                    plugin.name()
                                ));
                                break;
                            }
                        }
                    }
                    if !flush.is_empty() {
                        let mut combined =
                            Vec::with_capacity(inspected_body.len().saturating_add(flush.len()));
                        combined.extend_from_slice(&inspected_body);
                        combined.extend_from_slice(&flush);
                        inspected_body = Bytes::from(combined);
                    }
                }
            }

            let final_status = res_head.status;
            let response_bytes = inspected_body.len() as u64;
            let out = build_buffered_response(BufferedResponse {
                status: final_status,
                headers: res_head.headers,
                body: inspected_body,
            });
            if mask.contains(HookMask::ON_COMPLETE) {
                let summary = RequestSummary {
                    request_id: ctx.request_id,
                    route_id: Some(route.id.clone()),
                    upstream: Some(selection.upstream),
                    endpoint: Some(endpoint_label),
                    status: Some(final_status),
                    attempts: attempt,
                    request_bytes,
                    response_bytes,
                    ttfb,
                    total_duration: ctx.started_at.elapsed(),
                    error: error_msg,
                    aborted_mid_stream,
                    hook_timings: ctx.hook_timings.clone(),
                };
                spawn_on_complete(Arc::clone(&plugins), mask, ctx, summary);
            }
            return out;
        }

        // ---------------------------------------------------------------------
        // Stage 5 & 6: Commit response headers downstream & stream body
        // ---------------------------------------------------------------------
        let idle_timeout = route.timeouts.idle_chunk_timeout;
        let final_status = res_head.status;

        if mask.contains(HookMask::RESPONSE_BODY_STREAM) {
            // Chunk rewriting may change response byte length; let HTTP/1.1 use chunked
            // encoding and HTTP/2 stream freely.
            res_head.headers.remove(header::CONTENT_LENGTH);

            let stream_body = spawn_response_body_stream_pump(
                res_incoming,
                idle_timeout,
                Arc::clone(&plugins),
                mask,
                ctx,
                route.id.clone(),
                selection.upstream,
                endpoint_label,
                final_status,
                attempt,
                request_bytes,
                ttfb,
            );

            let mut out = Response::builder().status(final_status);
            if let Some(h) = out.headers_mut() {
                *h = res_head.headers;
            }
            return out.body(stream_body).unwrap();
        }

        // Zero-copy passthrough path (no RESPONSE_BODY_STREAM plugins).
        let out_body = if mask.contains(HookMask::ON_COMPLETE) {
            let route_id = route.id.clone();
            let upstream_name = selection.upstream;
            let ep_label = endpoint_label;
            let plugins_cb = Arc::clone(&plugins);
            let tracked = TrackedPassthroughBody::new(
                res_incoming,
                idle_timeout,
                Box::new(move |response_bytes, error, aborted_mid_stream| {
                    let summary = RequestSummary {
                        request_id: ctx.request_id,
                        route_id: Some(route_id),
                        upstream: Some(upstream_name),
                        endpoint: Some(ep_label),
                        status: Some(final_status),
                        attempts: attempt,
                        request_bytes,
                        response_bytes,
                        ttfb,
                        total_duration: ctx.started_at.elapsed(),
                        error,
                        aborted_mid_stream,
                        hook_timings: ctx.hook_timings.clone(),
                    };
                    spawn_on_complete(plugins_cb, mask, ctx, summary);
                }),
            );
            ShuntBody::TrackedPassthrough(Box::new(tracked))
        } else if let Some(dur) = idle_timeout {
            ShuntBody::with_idle_timeout(res_incoming, dur)
        } else {
            ShuntBody::passthrough(res_incoming)
        };

        let mut out = Response::builder().status(final_status);
        if let Some(h) = out.headers_mut() {
            *h = res_head.headers;
        }
        return out.body(out_body).unwrap();
    }

    // Fallback if loop exits unexpectedly.
    let (status, msg) = last_error.unwrap_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            "all upstream attempts failed".to_owned(),
        )
    });
    finish_error(
        &plugins,
        mask,
        ctx,
        &route.id,
        last_upstream_name,
        last_endpoint_label,
        status,
        "upstream attempts exhausted",
        msg,
        request_bytes,
        None,
    )
}

/// Spawns a bounded-backpressure streaming pump that runs `on_request_body_chunk` on
/// outgoing request chunks (only used when `REQUEST_BODY_STREAM` is set without buffering).
#[allow(clippy::too_many_arguments)]
fn spawn_request_body_stream_pump(
    mut incoming: hyper::body::Incoming,
    plugins: Arc<[Arc<dyn HttpPlugin>]>,
    request_id: u64,
    client_addr: SocketAddr,
    tls_sni: Option<String>,
    client_cert: Option<Arc<ClientCertInfo>>,
    route_id: Option<String>,
    attempt: usize,
    max_body_bytes: Option<usize>,
    exceeded_flag: Option<Arc<AtomicBool>>,
) -> ShuntBody {
    let (tx, rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);

    tokio::spawn(async move {
        let mut ctx =
            RequestCtx::new(request_id, client_addr, tls_sni).with_client_cert(client_cert);
        ctx.route_id = route_id;
        ctx.attempt = attempt;
        let mut bytes_read: usize = 0;

        while let Some(frame_res) = incoming.frame().await {
            match frame_res {
                Ok(frame) => {
                    if frame.is_data() {
                        let mut data = match frame.into_data() {
                            Ok(b) => b,
                            Err(_) => continue,
                        };
                        if let Some(cap) = max_body_bytes {
                            bytes_read = bytes_read.saturating_add(data.len());
                            if bytes_read > cap {
                                if let Some(ref f) = exceeded_flag {
                                    f.store(true, Ordering::Release);
                                }
                                let _ = tx.send(Err(CoreError::BodyTooLarge(cap))).await;
                                return;
                            }
                        }
                        for plugin in plugins.iter() {
                            if !plugin.hook_mask().contains(HookMask::REQUEST_BODY_STREAM) {
                                continue;
                            }
                            match run_hook_isolated(|| {
                                plugin.on_request_body_chunk(&mut ctx, &mut data, false)
                            })
                            .await
                            {
                                Ok(StreamFlow::Continue) => {}
                                Ok(StreamFlow::Abort(reason)) => {
                                    let _ = tx.send(Err(CoreError::StreamAborted(reason))).await;
                                    return;
                                }
                                Err(panic_msg) => {
                                    warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked in on_request_body_chunk");
                                    let _ = tx
                                        .send(Err(CoreError::PluginPanic {
                                            plugin: plugin.name().to_owned(),
                                            hook: "on_request_body_chunk",
                                            message: panic_msg,
                                        }))
                                        .await;
                                    return;
                                }
                            }
                        }
                        if !data.is_empty() && tx.send(Ok(Frame::data(data))).await.is_err() {
                            return;
                        }
                    } else if tx.send(Ok(frame)).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(CoreError::Hyper(e))).await;
                    return;
                }
            }
        }

        // Flush pass with end_of_stream = true.
        let mut flush = Bytes::new();
        for plugin in plugins.iter() {
            if !plugin.hook_mask().contains(HookMask::REQUEST_BODY_STREAM) {
                continue;
            }
            match run_hook_isolated(|| plugin.on_request_body_chunk(&mut ctx, &mut flush, true))
                .await
            {
                Ok(StreamFlow::Continue) => {}
                Ok(StreamFlow::Abort(reason)) => {
                    let _ = tx.send(Err(CoreError::StreamAborted(reason))).await;
                    return;
                }
                Err(panic_msg) => {
                    warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked in on_request_body_chunk(eof)");
                    let _ = tx
                        .send(Err(CoreError::PluginPanic {
                            plugin: plugin.name().to_owned(),
                            hook: "on_request_body_chunk",
                            message: panic_msg,
                        }))
                        .await;
                    return;
                }
            }
        }
        if !flush.is_empty() {
            let _ = tx.send(Ok(Frame::data(flush))).await;
        }
    });

    ShuntBody::channel(rx)
}

/// Spawns a bounded-backpressure streaming pump that enforces `idle_chunk_timeout`,
/// invokes `on_response_body_chunk(ctx, &mut Bytes, end_of_stream)` per chunk and on EOF,
/// isolates panics mid-stream, and always invokes `on_complete`.
#[allow(clippy::too_many_arguments)]
fn spawn_response_body_stream_pump(
    incoming: hyper::body::Incoming,
    idle_timeout: Option<Duration>,
    plugins: Arc<[Arc<dyn HttpPlugin>]>,
    mask: HookMask,
    mut ctx: RequestCtx,
    route_id: String,
    upstream: String,
    endpoint: String,
    status: StatusCode,
    attempts: usize,
    request_bytes: u64,
    ttfb: Option<Duration>,
) -> ShuntBody {
    let (tx, rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);

    tokio::spawn(async move {
        let mut body = match idle_timeout {
            Some(dur) => ShuntBody::IdleTimeout(IdleTimeoutBody::new(incoming, dur)),
            None => ShuntBody::Passthrough(incoming),
        };

        let mut response_bytes: u64 = 0;
        let mut error_msg: Option<String> = None;
        let mut aborted_mid_stream = false;

        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if frame.is_data() {
                        let mut chunk = match frame.into_data() {
                            Ok(b) => b,
                            Err(_) => continue,
                        };
                        let mut failed = false;
                        for plugin in plugins.iter() {
                            if !plugin.hook_mask().contains(HookMask::RESPONSE_BODY_STREAM) {
                                continue;
                            }
                            let start = ctx.trace_enabled.then(Instant::now);
                            let res = run_hook_isolated(|| {
                                plugin.on_response_body_chunk(&mut ctx, &mut chunk, false)
                            })
                            .await;
                            if let Some(s) = start {
                                ctx.record_timing(
                                    plugin.name(),
                                    "on_response_body_chunk",
                                    s.elapsed(),
                                );
                            }
                            match res {
                                Ok(StreamFlow::Continue) => {}
                                Ok(StreamFlow::Abort(reason)) => {
                                    aborted_mid_stream = true;
                                    error_msg = Some(reason.clone());
                                    let _ = tx.send(Err(CoreError::StreamAborted(reason))).await;
                                    failed = true;
                                    break;
                                }
                                Err(panic_msg) => {
                                    warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked mid-stream in on_response_body_chunk");
                                    aborted_mid_stream = true;
                                    error_msg = Some(format!(
                                        "plugin `{}` panicked in on_response_body_chunk: {panic_msg}",
                                        plugin.name()
                                    ));
                                    let _ = tx
                                        .send(Err(CoreError::PluginPanic {
                                            plugin: plugin.name().to_owned(),
                                            hook: "on_response_body_chunk",
                                            message: panic_msg,
                                        }))
                                        .await;
                                    failed = true;
                                    break;
                                }
                            }
                        }
                        if failed {
                            break;
                        }
                        if !chunk.is_empty() {
                            response_bytes += chunk.len() as u64;
                            if tx.send(Ok(Frame::data(chunk))).await.is_err() {
                                aborted_mid_stream = true;
                                error_msg =
                                    Some("downstream client disconnected mid-stream".to_owned());
                                break;
                            }
                        }
                    } else if tx.send(Ok(frame)).await.is_err() {
                        aborted_mid_stream = true;
                        error_msg = Some("downstream client disconnected mid-stream".to_owned());
                        break;
                    }
                }
                Some(Err(err)) => {
                    aborted_mid_stream = true;
                    error_msg = Some(err.to_string());
                    let _ = tx.send(Err(err)).await;
                    break;
                }
                None => {
                    // Clean EOF: invoke final end_of_stream = true pass so plugins can flush
                    // partial line buffers (e.g., SSE frames).
                    let mut flush = Bytes::new();
                    let mut failed = false;
                    for plugin in plugins.iter() {
                        if !plugin.hook_mask().contains(HookMask::RESPONSE_BODY_STREAM) {
                            continue;
                        }
                        let start = ctx.trace_enabled.then(Instant::now);
                        let res = run_hook_isolated(|| {
                            plugin.on_response_body_chunk(&mut ctx, &mut flush, true)
                        })
                        .await;
                        if let Some(s) = start {
                            ctx.record_timing(plugin.name(), "on_response_body_chunk", s.elapsed());
                        }
                        match res {
                            Ok(StreamFlow::Continue) => {}
                            Ok(StreamFlow::Abort(reason)) => {
                                aborted_mid_stream = true;
                                error_msg = Some(reason.clone());
                                let _ = tx.send(Err(CoreError::StreamAborted(reason))).await;
                                failed = true;
                                break;
                            }
                            Err(panic_msg) => {
                                warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked in on_response_body_chunk(eof)");
                                aborted_mid_stream = true;
                                error_msg = Some(format!(
                                    "plugin `{}` panicked in on_response_body_chunk: {panic_msg}",
                                    plugin.name()
                                ));
                                let _ = tx
                                    .send(Err(CoreError::PluginPanic {
                                        plugin: plugin.name().to_owned(),
                                        hook: "on_response_body_chunk",
                                        message: panic_msg,
                                    }))
                                    .await;
                                failed = true;
                                break;
                            }
                        }
                    }
                    if !failed && !flush.is_empty() {
                        response_bytes += flush.len() as u64;
                        if tx.send(Ok(Frame::data(flush))).await.is_err() {
                            aborted_mid_stream = true;
                            error_msg = Some(
                                "downstream client disconnected during final flush".to_owned(),
                            );
                        }
                    }
                    break;
                }
            }
        }

        // Drop sender so hyper sees EOF / error immediately before running on_complete.
        drop(tx);

        if mask.contains(HookMask::ON_COMPLETE) {
            let summary = RequestSummary {
                request_id: ctx.request_id,
                route_id: Some(route_id),
                upstream: Some(upstream),
                endpoint: Some(endpoint),
                status: Some(status),
                attempts,
                request_bytes,
                response_bytes,
                ttfb,
                total_duration: ctx.started_at.elapsed(),
                error: error_msg,
                aborted_mid_stream,
                hook_timings: ctx.hook_timings.clone(),
            };
            run_on_complete_inner(&plugins, &ctx, &summary).await;
        }
    });

    ShuntBody::channel(rx)
}

/// Spawns `on_complete` hooks off the hot path (if `HookMask::ON_COMPLETE` is set).
pub fn spawn_on_complete(
    plugins: Arc<[Arc<dyn HttpPlugin>]>,
    mask: HookMask,
    ctx: RequestCtx,
    summary: RequestSummary,
) {
    if !mask.contains(HookMask::ON_COMPLETE) {
        return;
    }
    tokio::spawn(async move {
        run_on_complete_inner(&plugins, &ctx, &summary).await;
    });
}

async fn run_on_complete_inner(
    plugins: &[Arc<dyn HttpPlugin>],
    ctx: &RequestCtx,
    summary: &RequestSummary,
) {
    for plugin in plugins {
        if !plugin.hook_mask().contains(HookMask::ON_COMPLETE) {
            continue;
        }
        if let Err(panic_msg) = run_hook_isolated(|| plugin.on_complete(ctx, summary)).await {
            warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked in on_complete");
        }
    }
}

fn finish_short_circuit(
    plugins: &Arc<[Arc<dyn HttpPlugin>]>,
    mask: HookMask,
    ctx: RequestCtx,
    route_id: &str,
    resp: BufferedResponse,
    request_bytes: u64,
    upstream: Option<String>,
) -> Response<ShuntBody> {
    let status = resp.status;
    let response_bytes = resp.body.len() as u64;
    let out = build_buffered_response(resp);

    if mask.contains(HookMask::ON_COMPLETE) {
        let summary = RequestSummary {
            request_id: ctx.request_id,
            route_id: Some(route_id.to_owned()),
            upstream,
            endpoint: None,
            status: Some(status),
            attempts: ctx.attempt,
            request_bytes,
            response_bytes,
            ttfb: Some(ctx.started_at.elapsed()),
            total_duration: ctx.started_at.elapsed(),
            error: None,
            aborted_mid_stream: false,
            hook_timings: ctx.hook_timings.clone(),
        };
        spawn_on_complete(Arc::clone(plugins), mask, ctx, summary);
    }

    out
}

#[allow(clippy::too_many_arguments)]
fn finish_error(
    plugins: &Arc<[Arc<dyn HttpPlugin>]>,
    mask: HookMask,
    ctx: RequestCtx,
    route_id: &str,
    upstream: Option<String>,
    endpoint: Option<String>,
    status: StatusCode,
    public_message: &'static str,
    internal_error: String,
    request_bytes: u64,
    ttfb: Option<Duration>,
) -> Response<ShuntBody> {
    if mask.contains(HookMask::ON_COMPLETE) {
        let summary = RequestSummary {
            request_id: ctx.request_id,
            route_id: Some(route_id.to_owned()),
            upstream,
            endpoint,
            status: Some(status),
            attempts: ctx.attempt,
            request_bytes,
            response_bytes: public_message.len() as u64,
            ttfb,
            total_duration: ctx.started_at.elapsed(),
            error: Some(internal_error),
            aborted_mid_stream: false,
            hook_timings: ctx.hook_timings.clone(),
        };
        spawn_on_complete(Arc::clone(plugins), mask, ctx, summary);
    }

    build_error_response(status, public_message)
}

pub fn build_buffered_response(resp: BufferedResponse) -> Response<ShuntBody> {
    let mut builder = Response::builder().status(resp.status);
    if let Some(headers) = builder.headers_mut() {
        *headers = resp.headers;
        if let Ok(len_val) = HeaderValue::from_str(&resp.body.len().to_string()) {
            headers.insert(header::CONTENT_LENGTH, len_val);
        }
    }
    builder.body(ShuntBody::full(resp.body)).unwrap()
}

pub fn build_error_response(status: StatusCode, message: &'static str) -> Response<ShuntBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, message.len().to_string())
        .body(ShuntBody::full(Bytes::from_static(message.as_bytes())))
        .unwrap()
}

/// Strips RFC 9110 hop-by-hop headers (preserving `te: trailers` for gRPC / HTTP/2).
pub fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
    // Collect any extra header names nominated by `Connection: ...`.
    let extra: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(|tok| HeaderName::from_bytes(tok.trim().as_bytes()).ok())
        .collect();

    for name in extra {
        headers.remove(&name);
    }

    let hop_by_hop = [
        header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ];

    for h in &hop_by_hop {
        headers.remove(h);
    }

    // Preserve `te: trailers` for gRPC/H2; remove any other `te` values.
    if let Some(te) = headers.get(header::TE) {
        let is_trailers = te
            .to_str()
            .map(|s| s.eq_ignore_ascii_case("trailers"))
            .unwrap_or(false);
        if !is_trailers {
            headers.remove(header::TE);
        }
    }
}

fn append_forwarded_for(headers: &mut HeaderMap, client_addr: SocketAddr) {
    let ip = client_addr.ip().to_string();
    let xff_name = HeaderName::from_static("x-forwarded-for");
    let new_val = match headers.get(&xff_name).and_then(|v| v.to_str().ok()) {
        Some(existing) if !existing.is_empty() => format!("{existing}, {ip}"),
        _ => ip,
    };
    if let Ok(val) = HeaderValue::from_str(&new_val) {
        headers.insert(xff_name, val);
    }
}

/// Dispatches fire-and-forget sampled copies of the incoming HTTP request to configured
/// route traffic mirrors inside a concurrency-bounded detached task pool.
fn spawn_traffic_mirrors(
    snapshot: &Arc<GatewaySnapshot>,
    mirrors: &[Arc<crate::snapshot::CompiledMirror>],
    req_head: &RequestHead,
    body: Option<Bytes>,
) {
    use std::sync::atomic::Ordering;

    for mirror in mirrors {
        let Ok(permit) = mirror.semaphore.clone().try_acquire_owned() else {
            mirror.dropped_total.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let Some(pool) = snapshot.upstream(&mirror.upstream).cloned() else {
            mirror.errors_total.fetch_add(1, Ordering::Relaxed);
            continue;
        };

        let (_, ep) = pool.select_endpoint(&[]);
        let target_uri = match build_target_uri(&ep.base_uri, &req_head.uri) {
            Ok(u) => u,
            Err(_) => {
                mirror.errors_total.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };

        let mut headers = req_head.headers.clone();
        headers.remove(header::HOST);
        headers.remove(header::TRANSFER_ENCODING);
        for (k, v) in &mirror.headers {
            headers.insert(k.clone(), v.clone());
        }

        let out_body = match body.clone() {
            Some(bytes) => {
                if let Ok(len_val) = HeaderValue::from_str(&bytes.len().to_string()) {
                    headers.insert(header::CONTENT_LENGTH, len_val);
                }
                ShuntBody::full(bytes)
            }
            None => ShuntBody::empty(),
        };

        let mut builder = Request::builder()
            .method(req_head.method.clone())
            .uri(target_uri);
        if let Some(h) = builder.headers_mut() {
            *h = headers;
        }
        let Ok(mirror_req) = builder.body(out_body) else {
            mirror.errors_total.fetch_add(1, Ordering::Relaxed);
            continue;
        };

        let mirror = Arc::clone(mirror);
        tokio::spawn(async move {
            let _permit = permit;
            match pool.send_request(mirror_req, Some(mirror.timeout)).await {
                Ok(_resp) => {
                    mirror.sent_total.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    mirror.errors_total.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }
}

/// Strips a leading path segment prefix from `uri`, preserving query strings verbatim
/// and always producing a path beginning with `/`.
pub fn strip_uri_prefix(uri: &Uri, prefix: &str) -> Uri {
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        return uri.clone();
    }
    let path = uri.path();
    let Some(rest) = path.strip_prefix(trimmed) else {
        return uri.clone();
    };
    if !rest.is_empty() && !rest.starts_with('/') {
        return uri.clone();
    }
    let new_path = if rest.is_empty() { "/" } else { rest };
    let new_pq = match uri.query() {
        Some(q) => format!("{new_path}?{q}"),
        None => new_path.to_owned(),
    };
    new_pq.parse().unwrap_or_else(|_| uri.clone())
}
