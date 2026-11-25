use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use shunt_console_core::{ConsoleError, DiagnosticItem};
use utoipa::ToSchema;

/// RFC 9457 `application/problem+json` error envelope returned by all `shunt-console` APIs.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<DiagnosticItem>,
}

/// Wrapper converting [`ConsoleError`] cleanly into an RFC 9457 Axum response.
#[derive(Debug)]
pub struct ApiError(pub ConsoleError);

impl From<ConsoleError> for ApiError {
    fn from(value: ConsoleError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, problem_type, title, detail, diagnostics) = match self.0 {
            ConsoleError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                "https://shunt.dev/problems/not-found",
                "Resource Not Found",
                msg,
                Vec::new(),
            ),
            ConsoleError::Conflict(msg) => (
                StatusCode::CONFLICT,
                "https://shunt.dev/problems/conflict",
                "Conflict",
                msg,
                Vec::new(),
            ),
            ConsoleError::PreconditionFailed { expected, actual } => (
                StatusCode::PRECONDITION_FAILED,
                "https://shunt.dev/problems/etag-mismatch",
                "Precondition Failed",
                format!(
                    "Resource was modified concurrently (If-Match `{expected}` != current ETag `{actual}`). Reload and retry."
                ),
                Vec::new(),
            ),
            ConsoleError::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                "https://shunt.dev/problems/unauthorized",
                "Unauthorized",
                msg,
                Vec::new(),
            ),
            ConsoleError::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                "https://shunt.dev/problems/forbidden",
                "Forbidden",
                msg,
                Vec::new(),
            ),
            ConsoleError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                "https://shunt.dev/problems/bad-request",
                "Bad Request",
                msg,
                Vec::new(),
            ),
            ConsoleError::Validation {
                message,
                diagnostics,
            } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "https://shunt.dev/problems/validation-failed",
                "Configuration Validation Failed",
                message,
                diagnostics,
            ),
            ConsoleError::Database(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "https://shunt.dev/problems/database-error",
                "Database Error",
                msg,
                Vec::new(),
            ),
            ConsoleError::Vault(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "https://shunt.dev/problems/vault-error",
                "Secrets Vault Error",
                msg,
                Vec::new(),
            ),
            ConsoleError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "https://shunt.dev/problems/internal-error",
                "Internal Server Error",
                msg,
                Vec::new(),
            ),
        };

        let body = ProblemDetails {
            problem_type: problem_type.to_owned(),
            title: title.to_owned(),
            status: status.as_u16(),
            detail,
            diagnostics,
        };
        let json = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        (
            status,
            [(
                header::CONTENT_TYPE,
                "application/problem+json; charset=utf-8",
            )],
            json,
        )
            .into_response()
    }
}
