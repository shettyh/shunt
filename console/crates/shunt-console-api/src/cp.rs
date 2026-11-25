use std::collections::{BTreeMap, HashSet};
use std::convert::Infallible;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::stream::Stream;
use serde::Deserialize;
use shunt_config::{
    NodeHeartbeatRequest, NodeRegisterRequest, NodeRegisterResponse, StateDeltaEvent,
    StateFullSyncEvent, TopologyRevisionEvent,
};
use shunt_console_core::{ClusterBusEvent, ConsoleError, resolve_target_revision};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::AppState;
use crate::auth::{AuthNode, extract_bearer};
use crate::problem::ApiError;

/// `POST /cp/v1/nodes/register` — Enrolls a `shunt` node with a cluster bootstrap token.
pub async fn register_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<NodeRegisterRequest>,
) -> Result<(StatusCode, Json<NodeRegisterResponse>), ApiError> {
    let Some(token) = extract_bearer(&headers) else {
        return Err(ApiError(ConsoleError::Unauthorized(
            "missing bootstrap token in Authorization header".to_owned(),
        )));
    };
    let (node, node_token, hb_secs) = state
        .store
        .register_node_with_bootstrap_token(
            &token,
            &req.cluster,
            req.node_name,
            req.shunt_version,
            req.labels,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(NodeRegisterResponse {
            node_id: node.id,
            node_token,
            cluster: req.cluster,
            heartbeat_interval_secs: hb_secs,
            public_key_b64: Some(state.store.signer().public_key_b64().to_owned()),
            target_revision: node.target_revision,
        }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct TopologyWatchQuery {
    #[serde(default)]
    pub node_id: Option<String>,
}

/// `GET /cp/v1/clusters/{cluster}/topology/watch` — Channel 1 SSE stream emitting `event: revision`.
pub async fn watch_topology(
    State(state): State<AppState>,
    auth: AuthNode,
    Path(cluster_slug): Path<String>,
    Query(_q): Query<TopologyWatchQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    if cluster.id != auth.cluster_id {
        return Err(ApiError(ConsoleError::Forbidden(
            "node token is not authorized for this cluster".to_owned(),
        )));
    }

    // Subscribe BEFORE checking current revision so zero transitions are missed.
    let mut rx = state.store.subscribe_events();
    let (tx, out_rx) = mpsc::channel::<Result<Event, Infallible>>(32);
    let store = state.store.clone();
    let node_id = auth.node_id.clone();
    let cluster_id = cluster.id.clone();
    let cluster_slug_owned = cluster.slug.clone();

    tokio::spawn(async move {
        // Emit initial assigned revision immediately on connect (if any).
        let mut last_sent: Option<(u64, String)> = None;
        if let Ok(cls) = store.get_cluster_by_id(&cluster_id).await
            && let Ok(nodes) = store.list_cluster_nodes(&cluster_id).await
            && let Some(node) = nodes.into_iter().find(|n| n.id == node_id)
            && let Some(target_rev) = resolve_target_revision(&cls.ring_assignments, &node.labels)
            && let Ok(rev) = store.get_revision(&cluster_id, target_rev).await
        {
            let ev = TopologyRevisionEvent {
                revision: rev.revision,
                digest: rev.digest.clone(),
                url: format!(
                    "/cp/v1/clusters/{cluster_slug_owned}/topology/revisions/{target_rev}"
                ),
            };
            if let Ok(json) = serde_json::to_string(&ev) {
                let _ = tx
                    .send(Ok(Event::default().event("revision").data(json)))
                    .await;
                last_sent = Some((rev.revision, rev.digest));
            }
        }

        loop {
            match rx.recv().await {
                Ok(ClusterBusEvent::TopologyChanged {
                    cluster_id: ev_cid, ..
                }) if ev_cid == cluster_id => {
                    // Re-evaluate this node's ring assignment (supports canary rollouts & rollbacks!).
                    let Ok(cls) = store.get_cluster_by_id(&cluster_id).await else {
                        continue;
                    };
                    let Ok(nodes) = store.list_cluster_nodes(&cluster_id).await else {
                        continue;
                    };
                    let Some(node) = nodes.into_iter().find(|n| n.id == node_id) else {
                        break;
                    };
                    let Some(target_rev) =
                        resolve_target_revision(&cls.ring_assignments, &node.labels)
                    else {
                        continue;
                    };
                    let Ok(rev) = store.get_revision(&cluster_id, target_rev).await else {
                        continue;
                    };
                    let pair = (rev.revision, rev.digest.clone());
                    if last_sent.as_ref() == Some(&pair) {
                        continue;
                    }
                    let ev = TopologyRevisionEvent {
                        revision: rev.revision,
                        digest: rev.digest.clone(),
                        url: format!(
                            "/cp/v1/clusters/{cluster_slug_owned}/topology/revisions/{target_rev}"
                        ),
                    };
                    if let Ok(json) = serde_json::to_string(&ev) {
                        if tx
                            .send(Ok(Event::default().event("revision").data(json)))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        last_sent = Some(pair);
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // Re-check assigned revision after lag.
                    if let Ok(cls) = store.get_cluster_by_id(&cluster_id).await
                        && let Ok(nodes) = store.list_cluster_nodes(&cluster_id).await
                        && let Some(node) = nodes.into_iter().find(|n| n.id == node_id)
                        && let Some(target_rev) =
                            resolve_target_revision(&cls.ring_assignments, &node.labels)
                        && let Ok(rev) = store.get_revision(&cluster_id, target_rev).await
                    {
                        let ev = TopologyRevisionEvent {
                            revision: rev.revision,
                            digest: rev.digest.clone(),
                            url: format!(
                                "/cp/v1/clusters/{cluster_slug_owned}/topology/revisions/{target_rev}"
                            ),
                        };
                        if let Ok(json) = serde_json::to_string(&ev)
                            && tx
                                .send(Ok(Event::default().event("revision").data(json)))
                                .await
                                .is_err()
                        {
                            break;
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    Ok(Sse::new(ReceiverStream::new(out_rx)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

/// `GET /cp/v1/clusters/{cluster}/topology/revisions/assigned` — Pulls the node's assigned revision.
pub async fn get_assigned_revision_bundle(
    State(state): State<AppState>,
    auth: AuthNode,
    headers: HeaderMap,
    Path(cluster_slug): Path<String>,
) -> Result<Response, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    if cluster.id != auth.cluster_id {
        return Err(ApiError(ConsoleError::Forbidden(
            "node token is not authorized for this cluster".to_owned(),
        )));
    }
    let Some(target_rev) = resolve_target_revision(&cluster.ring_assignments, &auth.labels) else {
        return Err(ApiError(ConsoleError::NotFound(
            "no topology revision assigned yet".to_owned(),
        )));
    };
    deliver_revision_bundle(&state, &cluster.id, target_rev, &headers).await
}

/// `GET /cp/v1/clusters/{cluster}/topology/revisions/{rev}` — Pulls a signed topology bundle.
pub async fn get_revision_bundle(
    State(state): State<AppState>,
    auth: AuthNode,
    headers: HeaderMap,
    Path((cluster_slug, rev)): Path<(String, u64)>,
) -> Result<Response, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    if cluster.id != auth.cluster_id {
        return Err(ApiError(ConsoleError::Forbidden(
            "node token is not authorized for this cluster".to_owned(),
        )));
    }
    deliver_revision_bundle(&state, &cluster.id, rev, &headers).await
}

async fn deliver_revision_bundle(
    state: &AppState,
    cluster_id: &str,
    rev: u64,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    let bundle = state
        .store
        .build_node_delivery_bundle(cluster_id, rev)
        .await?;
    let etag = format!("\"{}\"", bundle.digest);
    if let Some(inm) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        let trimmed = inm.trim().trim_matches('"');
        if trimmed == bundle.digest
            || trimmed.strip_prefix("sha256:") == bundle.digest.strip_prefix("sha256:")
        {
            return Ok(StatusCode::NOT_MODIFIED.into_response());
        }
    }

    let mut resp = Json(bundle).into_response();
    if let Ok(val) = HeaderValue::from_str(&etag) {
        resp.headers_mut().insert(header::ETAG, val);
    }
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

#[derive(Debug, Deserialize)]
pub struct StateStreamQuery {
    #[serde(default)]
    pub namespaces: String,
    #[serde(default)]
    pub cursors: String,
}

/// `GET /cp/v1/clusters/{cluster}/state/stream` — Channel 2 monotonic SSE delta + `full_sync` stream.
pub async fn stream_synced_state(
    State(state): State<AppState>,
    auth: AuthNode,
    headers: HeaderMap,
    Path(cluster_slug): Path<String>,
    Query(q): Query<StateStreamQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    if cluster.id != auth.cluster_id {
        return Err(ApiError(ConsoleError::Forbidden(
            "node token is not authorized for this cluster".to_owned(),
        )));
    }

    let mut requested_ns: Vec<String> = q
        .namespaces
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    if requested_ns.is_empty() {
        requested_ns = vec![
            "ai.virtual_keys".to_owned(),
            "ai.budgets".to_owned(),
            "ai.pricing".to_owned(),
            "mcp.agent_acls".to_owned(),
            "mcp.kill_switch".to_owned(),
            "mcp.approvals".to_owned(),
        ];
    }
    let ns_filter: HashSet<String> = requested_ns.iter().cloned().collect();

    let mut cursors: BTreeMap<String, u64> = BTreeMap::new();
    for pair in q
        .cursors
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some((ns, seq_str)) = pair.split_once(':')
            && let Ok(seq) = seq_str.parse::<u64>()
        {
            cursors.insert(ns.to_owned(), seq);
        }
    }
    let last_event_id: Option<u64> = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());

    // Subscribe to live bus BEFORE reading DB state so zero deltas are lost during catch-up.
    let mut rx = state.store.subscribe_events();
    let (tx, out_rx) = mpsc::channel::<Result<Event, Infallible>>(128);
    let store = state.store.clone();
    let cluster_id = cluster.id.clone();

    tokio::spawn(async move {
        let mut sent_seqs: BTreeMap<String, u64> = BTreeMap::new();

        // Phase 1: Catch up each requested namespace via delta replay or FULL_SYNC.
        for ns in &requested_ns {
            let client_cursor = cursors
                .get(ns)
                .copied()
                .unwrap_or_else(|| last_event_id.unwrap_or(0));

            match store
                .replay_namespace_deltas(&cluster_id, ns, client_cursor)
                .await
            {
                Ok(Some(deltas)) => {
                    let mut last_seq = client_cursor;
                    for d in deltas {
                        let ev = StateDeltaEvent {
                            seq: d.seq,
                            ns: d.namespace.clone(),
                            op: d.op,
                            key: d.item_key,
                            value: d.payload,
                        };
                        if let Ok(json) = serde_json::to_string(&ev) {
                            let frame = Event::default()
                                .event("delta")
                                .id(d.seq.to_string())
                                .data(json);
                            if tx.send(Ok(frame)).await.is_err() {
                                return;
                            }
                            last_seq = d.seq;
                        }
                    }
                    sent_seqs.insert(ns.clone(), last_seq);
                }
                Ok(None) => {
                    // Cold start (cursor == 0) or compacted cursor gap -> send authoritative FULL_SYNC.
                    if let Ok((head_seq, entries)) =
                        store.get_namespace_full_sync(&cluster_id, ns).await
                    {
                        let fs = StateFullSyncEvent {
                            seq: head_seq,
                            ns: ns.clone(),
                            entries,
                        };
                        if let Ok(json) = serde_json::to_string(&fs) {
                            let frame = Event::default()
                                .event("full_sync")
                                .id(head_seq.to_string())
                                .data(json);
                            if tx.send(Ok(frame)).await.is_err() {
                                return;
                            }
                        }
                        sent_seqs.insert(ns.clone(), head_seq);
                    }
                }
                Err(_) => return,
            }
        }

        // Phase 2: Stream live monotonic deltas with seq deduplication.
        loop {
            match rx.recv().await {
                Ok(ClusterBusEvent::StateDelta {
                    cluster_id: ev_cid,
                    seq,
                    namespace,
                    item_key,
                    op,
                    payload,
                }) if ev_cid == cluster_id && ns_filter.contains(&namespace) => {
                    let prev = sent_seqs.get(&namespace).copied().unwrap_or(0);
                    if seq <= prev {
                        continue;
                    }
                    let ev = StateDeltaEvent {
                        seq,
                        ns: namespace.clone(),
                        op,
                        key: item_key,
                        value: payload,
                    };
                    if let Ok(json) = serde_json::to_string(&ev) {
                        let frame = Event::default()
                            .event("delta")
                            .id(seq.to_string())
                            .data(json);
                        if tx.send(Ok(frame)).await.is_err() {
                            break;
                        }
                        sent_seqs.insert(namespace, seq);
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // Recover cleanly from broadcast lag by emitting FULL_SYNC for every namespace.
                    for ns in &requested_ns {
                        if let Ok((head_seq, entries)) =
                            store.get_namespace_full_sync(&cluster_id, ns).await
                        {
                            let fs = StateFullSyncEvent {
                                seq: head_seq,
                                ns: ns.clone(),
                                entries,
                            };
                            if let Ok(json) = serde_json::to_string(&fs) {
                                let frame = Event::default()
                                    .event("full_sync")
                                    .id(head_seq.to_string())
                                    .data(json);
                                if tx.send(Ok(frame)).await.is_err() {
                                    return;
                                }
                            }
                            sent_seqs.insert(ns.clone(), head_seq);
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    Ok(Sse::new(ReceiverStream::new(out_rx)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

/// `POST /cp/v1/nodes/{node_id}/heartbeat` — Updates node status, active revision, and synced seqs.
pub async fn node_heartbeat(
    State(state): State<AppState>,
    auth: AuthNode,
    Path(node_id): Path<String>,
    Json(req): Json<NodeHeartbeatRequest>,
) -> Result<StatusCode, ApiError> {
    if auth.node_id != node_id {
        return Err(ApiError(ConsoleError::Forbidden(
            "node token does not match node_id path".to_owned(),
        )));
    }
    state
        .store
        .record_node_heartbeat(
            &node_id,
            &req.shunt_version,
            &req.labels,
            req.active_revision,
            &req.active_digest,
            req.last_reload_error.as_deref(),
            &req.synced_seqs,
            &req.status,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
