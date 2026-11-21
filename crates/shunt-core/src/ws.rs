use std::sync::Arc;
use std::time::Instant;

use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version, header};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use shunt_plugin_sdk::{
    Flow, HookMask, HttpPlugin, RequestCtx, RequestHead, RequestSummary, ResponseHead,
    RouteDecision, UpstreamRequest, UpstreamSelection,
};
use tracing::{debug, warn};

use crate::body::ShuntBody;
use crate::catch::run_hook_isolated;
use crate::error::CoreError;
use crate::pipeline::{build_buffered_response, build_error_response, spawn_on_complete};
use crate::snapshot::{CompiledRoute, GatewaySnapshot};
use crate::upstream::build_target_uri;

/// Returns `true` if the incoming HTTP request is a WebSocket upgrade request.
pub fn is_websocket_upgrade(method: &Method, headers: &HeaderMap) -> bool {
    if method != Method::GET {
        return false;
    }
    let has_upgrade_ws = headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if !has_upgrade_ws {
        return false;
    }

    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        })
}

/// Handles a WebSocket upgrade end-to-end: upstream H1 handshake, `101 Switching Protocols`
/// relay, bidirectional frame tunnel via `hyper::upgrade::on`, and `on_complete`.
#[allow(clippy::too_many_arguments)]
pub async fn handle_websocket_upgrade(
    snapshot: Arc<GatewaySnapshot>,
    route: Arc<CompiledRoute>,
    mut ctx: RequestCtx,
    canonical_head: RequestHead,
    decision: RouteDecision,
    downstream_upgrade: OnUpgrade,
) -> Response<ShuntBody> {
    let plugins = Arc::clone(&route.plugins);
    let mask = route.hook_mask;

    ctx.attempt = 1;
    let mut selection = UpstreamSelection {
        upstream: decision.upstream.clone(),
        endpoint_override: None,
        attempt: 1,
        max_attempts: 1,
    };

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
                Ok(Flow::Continue) | Ok(Flow::RetryUpstream) => {}
                Ok(Flow::Respond(resp)) => {
                    let status = resp.status;
                    let bytes = resp.body.len() as u64;
                    let out = build_buffered_response(resp);
                    fire_ws_complete(
                        &plugins,
                        mask,
                        ctx,
                        &route.id,
                        Some(selection.upstream),
                        None,
                        Some(status),
                        bytes,
                        None,
                        None,
                    );
                    return out;
                }
                Err(panic_msg) => {
                    warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked in on_upstream_select");
                    let err = format!(
                        "plugin `{}` panicked in on_upstream_select: {panic_msg}",
                        plugin.name()
                    );
                    fire_ws_complete(
                        &plugins,
                        mask,
                        ctx,
                        &route.id,
                        Some(selection.upstream),
                        None,
                        Some(StatusCode::INTERNAL_SERVER_ERROR),
                        0,
                        None,
                        Some(err),
                    );
                    return build_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal plugin error",
                    );
                }
            }
        }
    }

    let Some(pool) = snapshot.upstream(&selection.upstream) else {
        let msg = format!("unknown upstream `{}`", selection.upstream);
        fire_ws_complete(
            &plugins,
            mask,
            ctx,
            &route.id,
            Some(selection.upstream),
            None,
            Some(StatusCode::BAD_GATEWAY),
            0,
            None,
            Some(msg),
        );
        return build_error_response(StatusCode::BAD_GATEWAY, "unknown upstream");
    };

    let (ep_idx, base_uri, endpoint_label) = if let Some(override_url) =
        &selection.endpoint_override
    {
        match override_url.parse::<http::Uri>() {
            Ok(uri) => (None, uri, override_url.clone()),
            Err(e) => {
                let msg = format!("invalid endpoint_override `{override_url}`: {e}");
                fire_ws_complete(
                    &plugins,
                    mask,
                    ctx,
                    &route.id,
                    Some(selection.upstream),
                    Some(override_url.clone()),
                    Some(StatusCode::BAD_GATEWAY),
                    0,
                    None,
                    Some(msg),
                );
                return build_error_response(StatusCode::BAD_GATEWAY, "invalid upstream override");
            }
        }
    } else {
        let (idx, ep) = pool.select_endpoint(&[]);
        (Some(idx), ep.base_uri.clone(), ep.raw_url.clone())
    };

    let mut up_req = UpstreamRequest {
        method: canonical_head.method,
        uri: canonical_head.uri,
        headers: canonical_head.headers,
        body: None,
        endpoint_uri: Some(base_uri.clone()),
    };

    if mask.contains(HookMask::ON_UPSTREAM_REQUEST) {
        for plugin in plugins.iter() {
            if !plugin.hook_mask().contains(HookMask::ON_UPSTREAM_REQUEST) {
                continue;
            }
            let start = ctx.trace_enabled.then(Instant::now);
            let res = run_hook_isolated(|| plugin.on_upstream_request(&mut ctx, &mut up_req)).await;
            if let Some(s) = start {
                ctx.record_timing(plugin.name(), "on_upstream_request", s.elapsed());
            }
            match res {
                Ok(Flow::Continue) | Ok(Flow::RetryUpstream) => {}
                Ok(Flow::Respond(resp)) => {
                    let status = resp.status;
                    let bytes = resp.body.len() as u64;
                    let out = build_buffered_response(resp);
                    fire_ws_complete(
                        &plugins,
                        mask,
                        ctx,
                        &route.id,
                        Some(selection.upstream),
                        Some(endpoint_label),
                        Some(status),
                        bytes,
                        None,
                        None,
                    );
                    return out;
                }
                Err(panic_msg) => {
                    warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked in on_upstream_request");
                    let err = format!(
                        "plugin `{}` panicked in on_upstream_request: {panic_msg}",
                        plugin.name()
                    );
                    fire_ws_complete(
                        &plugins,
                        mask,
                        ctx,
                        &route.id,
                        Some(selection.upstream),
                        Some(endpoint_label),
                        Some(StatusCode::INTERNAL_SERVER_ERROR),
                        0,
                        None,
                        Some(err),
                    );
                    return build_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal plugin error",
                    );
                }
            }
        }
    }

    let target_uri = match build_target_uri(&base_uri, &up_req.uri) {
        Ok(u) => u,
        Err(e) => {
            fire_ws_complete(
                &plugins,
                mask,
                ctx,
                &route.id,
                Some(selection.upstream),
                Some(endpoint_label),
                Some(StatusCode::BAD_GATEWAY),
                0,
                None,
                Some(e.to_string()),
            );
            return build_error_response(StatusCode::BAD_GATEWAY, "invalid upstream URI");
        }
    };

    let io = match pool.connect_for_upgrade(&target_uri).await {
        Ok(s) => s,
        Err(e) => {
            if let Some(idx) = ep_idx {
                pool.record_failure(idx);
            }
            let status = if matches!(e, CoreError::ConnectTimeout(_)) {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            fire_ws_complete(
                &plugins,
                mask,
                ctx,
                &route.id,
                Some(selection.upstream),
                Some(endpoint_label),
                Some(status),
                0,
                None,
                Some(e.to_string()),
            );
            return build_error_response(status, "upstream WebSocket connect failed");
        }
    };

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(e) => {
            if let Some(idx) = ep_idx {
                pool.record_failure(idx);
            }
            fire_ws_complete(
                &plugins,
                mask,
                ctx,
                &route.id,
                Some(selection.upstream),
                Some(endpoint_label),
                Some(StatusCode::BAD_GATEWAY),
                0,
                None,
                Some(e.to_string()),
            );
            return build_error_response(
                StatusCode::BAD_GATEWAY,
                "upstream HTTP/1.1 handshake failed",
            );
        }
    };

    tokio::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            debug!(error = %err, "upstream WebSocket connection closed with error");
        }
    });

    let origin_uri = target_uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let mut req_builder = Request::builder()
        .method(up_req.method)
        .uri(origin_uri)
        .version(Version::HTTP_11);

    if let Some(headers_mut) = req_builder.headers_mut() {
        *headers_mut = up_req.headers;
        if let Some(auth) = target_uri.authority()
            && let Ok(host_val) = HeaderValue::from_str(auth.as_str())
        {
            headers_mut.insert(header::HOST, host_val);
        }
    }

    let hyper_req = match req_builder.body(ShuntBody::empty()) {
        Ok(r) => r,
        Err(e) => {
            fire_ws_complete(
                &plugins,
                mask,
                ctx,
                &route.id,
                Some(selection.upstream),
                Some(endpoint_label),
                Some(StatusCode::INTERNAL_SERVER_ERROR),
                0,
                None,
                Some(e.to_string()),
            );
            return build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build upstream upgrade request",
            );
        }
    };

    let send_fut = sender.send_request(hyper_req);
    let mut upstream_res = match route.timeouts.response_headers_timeout {
        Some(dur) => match tokio::time::timeout(dur, send_fut).await {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => {
                if let Some(idx) = ep_idx {
                    pool.record_failure(idx);
                }
                fire_ws_complete(
                    &plugins,
                    mask,
                    ctx,
                    &route.id,
                    Some(selection.upstream),
                    Some(endpoint_label),
                    Some(StatusCode::BAD_GATEWAY),
                    0,
                    None,
                    Some(e.to_string()),
                );
                return build_error_response(
                    StatusCode::BAD_GATEWAY,
                    "upstream WebSocket request failed",
                );
            }
            Err(_) => {
                if let Some(idx) = ep_idx {
                    pool.record_failure(idx);
                }
                let err = CoreError::ResponseHeadersTimeout(dur).to_string();
                fire_ws_complete(
                    &plugins,
                    mask,
                    ctx,
                    &route.id,
                    Some(selection.upstream),
                    Some(endpoint_label),
                    Some(StatusCode::GATEWAY_TIMEOUT),
                    0,
                    None,
                    Some(err),
                );
                return build_error_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream WebSocket handshake timed out",
                );
            }
        },
        None => match send_fut.await {
            Ok(res) => res,
            Err(e) => {
                if let Some(idx) = ep_idx {
                    pool.record_failure(idx);
                }
                fire_ws_complete(
                    &plugins,
                    mask,
                    ctx,
                    &route.id,
                    Some(selection.upstream),
                    Some(endpoint_label),
                    Some(StatusCode::BAD_GATEWAY),
                    0,
                    None,
                    Some(e.to_string()),
                );
                return build_error_response(
                    StatusCode::BAD_GATEWAY,
                    "upstream WebSocket request failed",
                );
            }
        },
    };

    if let Some(idx) = ep_idx {
        pool.record_success(idx);
    }
    let ttfb = Some(ctx.started_at.elapsed());

    let upstream_upgrade = if upstream_res.status() == StatusCode::SWITCHING_PROTOCOLS {
        Some(hyper::upgrade::on(&mut upstream_res))
    } else {
        None
    };

    let (parts, body) = upstream_res.into_parts();
    let mut res_head = ResponseHead {
        status: parts.status,
        version: parts.version,
        headers: parts.headers,
    };

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
                Ok(Flow::Continue) | Ok(Flow::RetryUpstream) => {}
                Ok(Flow::Respond(resp)) => {
                    let status = resp.status;
                    let bytes = resp.body.len() as u64;
                    let out = build_buffered_response(resp);
                    fire_ws_complete(
                        &plugins,
                        mask,
                        ctx,
                        &route.id,
                        Some(selection.upstream),
                        Some(endpoint_label),
                        Some(status),
                        bytes,
                        ttfb,
                        None,
                    );
                    return out;
                }
                Err(panic_msg) => {
                    warn!(plugin = plugin.name(), panic = %panic_msg, "plugin panicked in on_response_headers");
                    let err = format!(
                        "plugin `{}` panicked in on_response_headers: {panic_msg}",
                        plugin.name()
                    );
                    fire_ws_complete(
                        &plugins,
                        mask,
                        ctx,
                        &route.id,
                        Some(selection.upstream),
                        Some(endpoint_label),
                        Some(StatusCode::INTERNAL_SERVER_ERROR),
                        0,
                        ttfb,
                        Some(err),
                    );
                    return build_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal plugin error",
                    );
                }
            }
        }
    }

    if let Some(up_upgrade) = upstream_upgrade {
        let route_id = route.id.clone();
        let upstream_name = selection.upstream.clone();
        let ep_label = endpoint_label.clone();
        let plugins_bg = Arc::clone(&plugins);

        tokio::spawn(async move {
            let (req_bytes, res_bytes, err_msg) =
                match tokio::try_join!(downstream_upgrade, up_upgrade) {
                    Ok((down, up)) => {
                        let mut down_io = TokioIo::new(down);
                        let mut up_io = TokioIo::new(up);
                        match tokio::io::copy_bidirectional(&mut down_io, &mut up_io).await {
                            Ok((to_up, to_down)) => (to_up, to_down, None),
                            Err(e) => (0, 0, Some(format!("WebSocket tunnel I/O error: {e}"))),
                        }
                    }
                    Err(e) => (0, 0, Some(format!("WebSocket upgrade failed: {e}"))),
                };

            let summary = RequestSummary {
                request_id: ctx.request_id,
                route_id: Some(route_id),
                upstream: Some(upstream_name),
                endpoint: Some(ep_label),
                status: Some(StatusCode::SWITCHING_PROTOCOLS),
                attempts: 1,
                request_bytes: req_bytes,
                response_bytes: res_bytes,
                ttfb,
                total_duration: ctx.started_at.elapsed(),
                error: err_msg.clone(),
                aborted_mid_stream: err_msg.is_some(),
                hook_timings: ctx.hook_timings.clone(),
            };
            spawn_on_complete(plugins_bg, mask, ctx, summary);
        });

        let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
        if let Some(h) = builder.headers_mut() {
            *h = res_head.headers;
        }
        builder.body(ShuntBody::empty()).unwrap()
    } else {
        let status = res_head.status;
        fire_ws_complete(
            &plugins,
            mask,
            ctx,
            &route.id,
            Some(selection.upstream),
            Some(endpoint_label),
            Some(status),
            0,
            ttfb,
            None,
        );
        let mut builder = Response::builder().status(status);
        if let Some(h) = builder.headers_mut() {
            *h = res_head.headers;
        }
        builder.body(ShuntBody::passthrough(body)).unwrap()
    }
}

#[allow(clippy::too_many_arguments)]
fn fire_ws_complete(
    plugins: &Arc<[Arc<dyn HttpPlugin>]>,
    mask: HookMask,
    ctx: RequestCtx,
    route_id: &str,
    upstream: Option<String>,
    endpoint: Option<String>,
    status: Option<StatusCode>,
    response_bytes: u64,
    ttfb: Option<std::time::Duration>,
    error: Option<String>,
) {
    if !mask.contains(HookMask::ON_COMPLETE) {
        return;
    }
    let summary = RequestSummary {
        request_id: ctx.request_id,
        route_id: Some(route_id.to_owned()),
        upstream,
        endpoint,
        status,
        attempts: ctx.attempt,
        request_bytes: 0,
        response_bytes,
        ttfb,
        total_duration: ctx.started_at.elapsed(),
        error,
        aborted_mid_stream: false,
        hook_timings: ctx.hook_timings.clone(),
    };
    spawn_on_complete(Arc::clone(plugins), mask, ctx, summary);
}
