//! Embedded read-only Admin Inspector Web UI assets (gated behind the `admin-ui` Cargo feature).

/// Single self-contained, zero-dependency HTML/CSS/JS Inspector UI document.
pub const INSPECTOR_HTML: &str = include_str!("../assets/inspector.html");
