use std::collections::BTreeMap;

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use axum_extra::extract::cookie::{Cookie, CookieJar};
use shunt_console_core::{AuthenticatedPrincipal, ConsoleError};

use crate::AppState;
use crate::problem::ApiError;

pub const SESSION_COOKIE_NAME: &str = "shunt_console_session";

/// Axum extractor resolving a valid session cookie or Bearer token (`shunt_ct_...` / `shunt_sess_...`).
pub struct AuthPrincipal(pub AuthenticatedPrincipal);

impl FromRequestParts<AppState> for AuthPrincipal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer(&parts.headers).or_else(|| {
            let jar = CookieJar::from_headers(&parts.headers);
            jar.get(SESSION_COOKIE_NAME).map(|c| c.value().to_owned())
        });

        let Some(token) = token else {
            return Err(ApiError(ConsoleError::Unauthorized(
                "authentication required".to_owned(),
            )));
        };

        let ip = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim().to_owned());

        let principal = state.store.authenticate_token(&token, ip).await?;
        Ok(AuthPrincipal(principal))
    }
}

/// Axum extractor authenticating an enrolled `shunt` node via `Authorization: Bearer shunt_nt_...`.
pub struct AuthNode {
    pub node_id: String,
    pub cluster_id: String,
    pub labels: BTreeMap<String, String>,
}

impl FromRequestParts<AppState> for AuthNode {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(token) = extract_bearer(&parts.headers) else {
            return Err(ApiError(ConsoleError::Unauthorized(
                "missing node bearer token".to_owned(),
            )));
        };
        let (node_id, cluster_id, labels) = state.store.authenticate_node_token(&token).await?;
        Ok(AuthNode {
            node_id,
            cluster_id,
            labels,
        })
    }
}

pub fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<String> {
    let val = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    val.strip_prefix("Bearer ")
        .or_else(|| val.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

pub fn extract_if_match(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
}

pub fn build_session_cookie(token: String, secure: bool) -> Cookie<'static> {
    let raw = format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800{}",
        if secure { "; Secure" } else { "" }
    );
    Cookie::parse(raw)
        .expect("valid session cookie")
        .into_owned()
}

pub fn clear_session_cookie() -> Cookie<'static> {
    Cookie::parse(format!(
        "{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
    ))
    .expect("valid clear cookie")
    .into_owned()
}
