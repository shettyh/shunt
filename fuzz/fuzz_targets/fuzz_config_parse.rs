#![no_main]

use libfuzzer_sys::fuzz_target;
use shunt_config::GatewayConfig;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(cfg) = toml::from_str::<GatewayConfig>(text) {
            let _ = cfg.validate();
        }
        if let Ok(cfg) = serde_yaml::from_str::<GatewayConfig>(text) {
            let _ = cfg.validate();
        }
    }
});
