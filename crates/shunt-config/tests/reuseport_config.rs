use std::sync::Arc;

use shunt_config::{ConfigProvider, InlineConfigProvider, SnapshotCompiler};
use shunt_engine::{DEFAULT_LISTEN_BACKLOG, MAX_REUSEPORT_SHARDS, RuntimeRegistry};
use shunt_plugin_sdk::PluginRegistry;

fn compile_toml(toml: &str) -> Result<shunt_config::CompiledBundle, shunt_config::ConfigError> {
    let provider = InlineConfigProvider::from_toml("test.toml", toml);
    let loaded = provider.load()?;
    let compiler = SnapshotCompiler::new(
        Arc::new(PluginRegistry::new()),
        Arc::new(RuntimeRegistry::new()),
    );
    compiler.compile(&loaded)
}

#[test]
fn parses_default_and_explicit_reuseport_server_config() {
    let default_toml = r#"
[server]
listen = "127.0.0.1:8080"

[[upstreams]]
name = "api"
endpoints = ["http://127.0.0.1:9000"]

[[routes]]
id = "r1"
path_prefix = "/"
upstream = "api"
"#;
    let bundle = compile_toml(default_toml).unwrap();
    assert!(!bundle.config.server.reuseport);
    assert_eq!(bundle.config.server.accept_shards, None);
    assert_eq!(bundle.config.server.backlog, DEFAULT_LISTEN_BACKLOG);

    let full_toml = r#"
[server]
listen = "0.0.0.0:8080"
reuseport = true
accept_shards = 8
backlog = 8192

[[upstreams]]
name = "api"
endpoints = ["http://127.0.0.1:9000"]

[[routes]]
id = "r1"
path_prefix = "/"
upstream = "api"
"#;
    let bundle = compile_toml(full_toml).unwrap();
    let listener = bundle.config.server.to_listener_config();
    assert!(listener.reuseport);
    assert_eq!(listener.accept_shards, Some(8));
    assert_eq!(listener.backlog, 8192);
}

#[test]
fn rejects_invalid_reuseport_configurations() {
    // accept_shards without reuseport = true
    let err = compile_toml(
        r#"
[server]
listen = "127.0.0.1:8080"
accept_shards = 4
[[upstreams]]
name = "api"
endpoints = ["http://127.0.0.1:9000"]
[[routes]]
id = "r1"
upstream = "api"
"#,
    )
    .err()
    .unwrap();
    assert!(
        err.to_string()
            .contains("requires `server.reuseport = true`")
    );

    // accept_shards = 0 and > MAX_REUSEPORT_SHARDS
    for bad in [0usize, MAX_REUSEPORT_SHARDS + 1] {
        let err = compile_toml(&format!(
            r#"
[server]
listen = "127.0.0.1:8080"
reuseport = true
accept_shards = {bad}
[[upstreams]]
name = "api"
endpoints = ["http://127.0.0.1:9000"]
[[routes]]
id = "r1"
upstream = "api"
"#
        ))
        .err()
        .unwrap();
        assert!(err.to_string().contains("server.accept_shards"));
    }

    // backlog = 0
    let err = compile_toml(
        r#"
[server]
listen = "127.0.0.1:8080"
backlog = 0
[[upstreams]]
name = "api"
endpoints = ["http://127.0.0.1:9000"]
[[routes]]
id = "r1"
upstream = "api"
"#,
    )
    .err()
    .unwrap();
    assert!(err.to_string().contains("server.backlog"));
}
