#![no_main]

use libfuzzer_sys::fuzz_target;
use shunt_config::{GatewayConfig, host_pattern_subsumes, join_route_paths};
use shunt_engine::MAX_REUSEPORT_SHARDS;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(cfg) = toml::from_str::<GatewayConfig>(text) {
            let _ = cfg.validate();
            let listener = cfg.server.to_listener_config();
            assert!((1..=MAX_REUSEPORT_SHARDS).contains(&listener.resolved_shards()));
            assert!(listener.resolved_backlog() >= 1);
            for route in &cfg.routes {
                let _ = cfg.resolve_route(route);
            }
        }
        if let Ok(cfg) = serde_yaml::from_str::<GatewayConfig>(text) {
            let _ = cfg.validate();
            let listener = cfg.server.to_listener_config();
            assert!((1..=MAX_REUSEPORT_SHARDS).contains(&listener.resolved_shards()));
            assert!(listener.resolved_backlog() >= 1);
            for route in &cfg.routes {
                let _ = cfg.resolve_route(route);
            }
        }
        if let Some((a, b)) = text.split_once('\n') {
            let joined = join_route_paths(a, b);
            assert!(joined.starts_with('/'));
            let _ = host_pattern_subsumes(a, b);
        }
    }
});
