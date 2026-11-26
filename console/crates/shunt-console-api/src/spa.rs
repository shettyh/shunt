use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "../../web/dist/"]
struct WebAssets;

/// Serves the embedded React SPA with strict security headers and client-side routing fallback.
pub async fn serve_spa(uri: Uri) -> Response {
    let raw_path = uri.path().trim_start_matches('/');
    let candidate = if raw_path.is_empty() {
        "index.html"
    } else {
        raw_path
    };

    if let Some(file) = WebAssets::get(candidate) {
        let is_hashed_asset = candidate.starts_with("assets/");
        return build_asset_response(candidate, file.data.into_owned(), is_hashed_asset);
    }

    // SPA client-side route fallback (never hijack `/api/*` or `/cp/*` 404s).
    if !raw_path.starts_with("api/")
        && !raw_path.starts_with("cp/")
        && let Some(index) = WebAssets::get("index.html")
    {
        return build_asset_response("index.html", index.data.into_owned(), false);
    }

    (StatusCode::NOT_FOUND, "not found").into_response()
}

fn build_asset_response(path: &str, bytes: Vec<u8>, immutable: bool) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let mut resp = (StatusCode::OK, bytes).into_response();
    let headers = resp.headers_mut();
    if let Ok(ct) = HeaderValue::from_str(mime.as_ref()) {
        headers.insert(header::CONTENT_TYPE, ct);
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if immutable {
            "public, max-age=31536000, immutable"
        } else {
            "no-store"
        }),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    resp
}
