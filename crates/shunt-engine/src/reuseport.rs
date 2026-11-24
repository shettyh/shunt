//! Per-core `SO_REUSEPORT` listener sharding and listen-backlog configuration.
//!
//! - **Default (`reuseport = false`)**: Single `TcpListener` bound to `addr`.
//! - **Opt-in `SO_REUSEPORT` (`reuseport = true`, Unix)**: Binds `N` independent listener sockets
//!   (`accept_shards.unwrap_or_else(available_parallelism)`, clamped to `1..=MAX_REUSEPORT_SHARDS`)
//!   with `SO_REUSEADDR` + `SO_REUSEPORT` so each shard runs its own accept loop and shares the
//!   resolved port (including ephemeral port `0`).
//! - **Graceful fallback**: On platforms without `SO_REUSEPORT` (e.g., Windows), logs a warning
//!   and falls back cleanly to a single listener socket.

use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpSocket};

use crate::error::CoreError;

/// Maximum listener accept shards permitted when `reuseport = true`.
pub const MAX_REUSEPORT_SHARDS: usize = 128;

/// Default TCP listen backlog per listener socket.
pub const DEFAULT_LISTEN_BACKLOG: u32 = 4096;

/// Listener socket configuration for [`crate::GatewayServer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerConfig {
    /// Enable `SO_REUSEPORT` multi-shard listeners (default: `false`).
    pub reuseport: bool,
    /// Explicit number of listener accept shards when `reuseport = true`.
    /// `None` resolves automatically to `std::thread::available_parallelism()` clamped to
    /// `1..=MAX_REUSEPORT_SHARDS`.
    pub accept_shards: Option<usize>,
    /// TCP listen backlog per listener socket (default: [`DEFAULT_LISTEN_BACKLOG`]).
    pub backlog: u32,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            reuseport: false,
            accept_shards: None,
            backlog: DEFAULT_LISTEN_BACKLOG,
        }
    }
}

impl ListenerConfig {
    /// Resolves the target accept shard count given a detected host `parallelism`.
    #[inline]
    pub const fn resolved_shards_with_parallelism(&self, parallelism: usize) -> usize {
        if !self.reuseport {
            return 1;
        }
        let raw = match self.accept_shards {
            Some(n) => n,
            None => parallelism,
        };
        if raw < 1 {
            1
        } else if raw > MAX_REUSEPORT_SHARDS {
            MAX_REUSEPORT_SHARDS
        } else {
            raw
        }
    }

    /// Resolves the target accept shard count for the current host.
    pub fn resolved_shards(&self) -> usize {
        let parallelism = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        self.resolved_shards_with_parallelism(parallelism)
    }

    /// Resolves the effective listen backlog (`>= 1`).
    #[inline]
    pub const fn resolved_backlog(&self) -> u32 {
        if self.backlog < 1 { 1 } else { self.backlog }
    }
}

/// Runtime summary of the bound gateway listener group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerInfo {
    pub local_addr: SocketAddr,
    pub reuseport: bool,
    pub accept_shards: usize,
    pub backlog: u32,
}

/// Bound listener sockets and runtime metadata.
pub(crate) struct BoundListeners {
    pub listeners: Vec<TcpListener>,
    pub info: ListenerInfo,
}

/// Binds one or more TCP listeners according to `config`.
pub(crate) fn bind_listeners(
    addr: SocketAddr,
    config: &ListenerConfig,
) -> Result<BoundListeners, CoreError> {
    let backlog = config.resolved_backlog();

    if !config.reuseport {
        let listener = bind_single_socket(addr, false, backlog)?;
        let local_addr = listener.local_addr()?;
        return Ok(BoundListeners {
            listeners: vec![listener],
            info: ListenerInfo {
                local_addr,
                reuseport: false,
                accept_shards: 1,
                backlog,
            },
        });
    }

    #[cfg(not(unix))]
    {
        tracing::warn!(
            "SO_REUSEPORT is not supported on this platform; falling back to a single listener socket"
        );
        let listener = bind_single_socket(addr, false, backlog)?;
        let local_addr = listener.local_addr()?;
        Ok(BoundListeners {
            listeners: vec![listener],
            info: ListenerInfo {
                local_addr,
                reuseport: false,
                accept_shards: 1,
                backlog,
            },
        })
    }

    #[cfg(unix)]
    {
        let shards = config.resolved_shards();
        let mut listeners = Vec::with_capacity(shards);

        // Bind shard 0 first so ephemeral port `0` resolves to a concrete port shared by all shards.
        let first = bind_single_socket(addr, true, backlog)?;
        let local_addr = first.local_addr()?;
        listeners.push(first);

        for _ in 1..shards {
            listeners.push(bind_single_socket(local_addr, true, backlog)?);
        }

        Ok(BoundListeners {
            listeners,
            info: ListenerInfo {
                local_addr,
                reuseport: true,
                accept_shards: shards,
                backlog,
            },
        })
    }
}

fn bind_single_socket(
    addr: SocketAddr,
    reuseport: bool,
    backlog: u32,
) -> Result<TcpListener, CoreError> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    let _ = socket.set_reuseaddr(true);
    if reuseport {
        #[cfg(unix)]
        socket.set_reuseport(true)?;
    }
    socket.bind(addr)?;
    Ok(socket.listen(backlog)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_config_resolution_clamps_shards_and_backlog() {
        let default_cfg = ListenerConfig::default();
        assert!(!default_cfg.reuseport);
        assert_eq!(default_cfg.resolved_shards(), 1);
        assert_eq!(default_cfg.resolved_backlog(), DEFAULT_LISTEN_BACKLOG);

        let per_core = ListenerConfig {
            reuseport: true,
            accept_shards: None,
            backlog: 0,
        };
        assert_eq!(per_core.resolved_shards_with_parallelism(0), 1);
        assert_eq!(per_core.resolved_shards_with_parallelism(8), 8);
        assert_eq!(
            per_core.resolved_shards_with_parallelism(999),
            MAX_REUSEPORT_SHARDS
        );
        assert_eq!(per_core.resolved_backlog(), 1);

        let clamped = ListenerConfig {
            reuseport: true,
            accept_shards: Some(999),
            backlog: 2048,
        };
        assert_eq!(clamped.resolved_shards(), MAX_REUSEPORT_SHARDS);
        assert_eq!(clamped.resolved_backlog(), 2048);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{ListenerConfig, MAX_REUSEPORT_SHARDS};

    #[kani::proof]
    fn listener_config_resolution_bounds_and_monotonicity() {
        let reuseport: bool = kani::any();
        let has_explicit: bool = kani::any();
        let explicit_shards: usize = kani::any();
        let parallelism: usize = kani::any();
        let backlog: u32 = kani::any();

        let cfg = ListenerConfig {
            reuseport,
            accept_shards: has_explicit.then_some(explicit_shards),
            backlog,
        };

        let resolved = cfg.resolved_shards_with_parallelism(parallelism);
        assert!(resolved >= 1);
        assert!(resolved <= MAX_REUSEPORT_SHARDS);
        if !reuseport {
            assert_eq!(resolved, 1);
        }

        let resolved_backlog = cfg.resolved_backlog();
        assert!(resolved_backlog >= 1);
        if backlog >= 1 {
            assert_eq!(resolved_backlog, backlog);
        }
    }

    #[kani::proof]
    fn explicit_shard_resolution_is_monotonic() {
        let a: usize = kani::any();
        let b: usize = kani::any();
        kani::assume(a <= b);

        let cfg_a = ListenerConfig {
            reuseport: true,
            accept_shards: Some(a),
            backlog: 1,
        };
        let cfg_b = ListenerConfig {
            reuseport: true,
            accept_shards: Some(b),
            backlog: 1,
        };
        assert!(
            cfg_a.resolved_shards_with_parallelism(1) <= cfg_b.resolved_shards_with_parallelism(1)
        );
    }
}
