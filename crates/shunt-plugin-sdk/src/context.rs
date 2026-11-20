use std::net::SocketAddr;
use std::time::{Duration, Instant};

use http::{Extensions, StatusCode};

use crate::http_types::HookTiming;

/// Per-request context threaded through every lifecycle hook.
///
/// Plugins communicate across hooks (and across plugins) via typed values stored
/// in `extensions`.
#[derive(Debug)]
pub struct RequestCtx {
    pub request_id: u64,
    pub client_addr: SocketAddr,
    pub tls_sni: Option<String>,
    pub route_id: Option<String>,
    pub attempt: usize,
    pub started_at: Instant,
    pub extensions: Extensions,
    pub trace_enabled: bool,
    pub hook_timings: Vec<HookTiming>,
    pub last_upstream_error: Option<String>,
    pub last_upstream_status: Option<StatusCode>,
}

impl RequestCtx {
    pub fn new(request_id: u64, client_addr: SocketAddr, tls_sni: Option<String>) -> Self {
        Self {
            request_id,
            client_addr,
            tls_sni,
            route_id: None,
            attempt: 0,
            started_at: Instant::now(),
            extensions: Extensions::new(),
            trace_enabled: false,
            hook_timings: Vec::new(),
            last_upstream_error: None,
            last_upstream_status: None,
        }
    }

    /// Inserts a typed value into the per-request extension map.
    #[inline]
    pub fn insert_ext<T: Clone + Send + Sync + 'static>(&mut self, val: T) -> Option<T> {
        self.extensions.insert(val)
    }

    /// Gets a shared reference to a typed value from the per-request extension map.
    #[inline]
    pub fn get_ext<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.extensions.get::<T>()
    }

    /// Gets a mutable reference to a typed value from the per-request extension map.
    #[inline]
    pub fn get_ext_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.extensions.get_mut::<T>()
    }

    /// Removes a typed value from the per-request extension map.
    #[inline]
    pub fn remove_ext<T: Send + Sync + 'static>(&mut self) -> Option<T> {
        self.extensions.remove::<T>()
    }

    /// Records a hook timing entry when tracing is enabled.
    #[inline]
    pub fn record_timing(&mut self, plugin: &str, hook: &'static str, duration: Duration) {
        if self.trace_enabled {
            self.hook_timings.push(HookTiming {
                plugin: plugin.to_owned(),
                hook,
                duration,
            });
        }
    }
}
