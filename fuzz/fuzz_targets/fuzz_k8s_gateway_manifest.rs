#![no_main]
use libfuzzer_sys::fuzz_target;
use shunt_config::{
    K8sClusterSnapshot, K8sGatewayOptions, compile_k8s_gateway_snapshot, parse_k8s_duration_ms,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_k8s_duration_ms(s);
        if let Ok(snap) = K8sClusterSnapshot::from_yaml_str(s) {
            let _ = compile_k8s_gateway_snapshot(&snap, &K8sGatewayOptions::default());
        }
    }
});
