use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;

/// Structured diagnostic surfaced inside RFC 9457 `application/problem+json` validation errors.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DiagnosticItem {
    pub severity: String,
    pub rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub message: String,
}

/// Core error enum for `shunt-console-core`, mapping cleanly to RFC 9457 Problem Details.
#[derive(Debug, Error)]
pub enum ConsoleError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error(
        "precondition failed: resource changed (expected ETag `{expected}`, actual `{actual}`)"
    )]
    PreconditionFailed { expected: String, actual: String },

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("validation failed: {message}")]
    Validation {
        message: String,
        diagnostics: Vec<DiagnosticItem>,
    },

    #[error("database error: {0}")]
    Database(String),

    #[error("vault error: {0}")]
    Vault(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl From<sqlx::Error> for ConsoleError {
    fn from(err: sqlx::Error) -> Self {
        match &err {
            sqlx::Error::RowNotFound => Self::NotFound("requested record not found".to_owned()),
            sqlx::Error::Database(db_err) if db_err.is_unique_violation() => {
                Self::Conflict(format!("unique constraint violated: {}", db_err.message()))
            }
            _ => Self::Database(err.to_string()),
        }
    }
}
