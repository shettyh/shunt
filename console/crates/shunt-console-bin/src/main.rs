use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use shunt_console_api::{AppState, build_router};
use shunt_console_core::{ConsoleStore, ConsoleStoreConfig, InitialBootstrapInput};
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "shunt-console",
    version,
    about = "Single-binary Admin Console & Control Plane for Shunt fleets"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the `shunt-console` control plane server and embedded Web UI.
    Serve {
        /// Address to bind the HTTP control plane and Web UI server.
        #[arg(
            long = "listen",
            env = "SHUNT_CONSOLE_LISTEN",
            default_value = "127.0.0.1:8443"
        )]
        listen: String,
        /// Database connection URL (`sqlite://./shunt-console.db` or `postgres://...`).
        #[arg(
            long = "db",
            alias = "database-url",
            env = "SHUNT_CONSOLE_DATABASE_URL",
            default_value = "sqlite://./shunt-console.db"
        )]
        database_url: String,
        /// Environment variable holding the 32-byte hex/base64 Secrets Vault Master KEK.
        #[arg(long = "master-key-env", default_value = "SHUNT_CONSOLE_MASTER_KEY")]
        master_key_env: String,
        /// Public base URL used for OIDC callbacks and node enrollment snippets.
        #[arg(long = "public-url", env = "SHUNT_CONSOLE_PUBLIC_URL")]
        public_url: Option<String>,
        /// Enable permissive CORS headers (for Vite local frontend development).
        #[arg(long = "dev-cors")]
        dev_cors: bool,
        /// Mark session cookies with the `Secure` attribute (recommended behind HTTPS).
        #[arg(long = "secure-cookies")]
        secure_cookies: bool,
    },
    /// Run database migrations and exit.
    Migrate {
        /// Database connection URL (`sqlite://...` or `postgres://...`).
        #[arg(
            long = "db",
            alias = "database-url",
            env = "SHUNT_CONSOLE_DATABASE_URL",
            default_value = "sqlite://./shunt-console.db"
        )]
        database_url: String,
        /// Environment variable holding the Secrets Vault Master KEK.
        #[arg(long = "master-key-env", default_value = "SHUNT_CONSOLE_MASTER_KEY")]
        master_key_env: String,
    },
    /// Non-interactive first-run bootstrap creating initial SuperAdmin, org, cluster & node token.
    Bootstrap {
        /// Database connection URL (`sqlite://...` or `postgres://...`).
        #[arg(
            long = "db",
            alias = "database-url",
            env = "SHUNT_CONSOLE_DATABASE_URL",
            default_value = "sqlite://./shunt-console.db"
        )]
        database_url: String,
        /// Environment variable holding the Secrets Vault Master KEK.
        #[arg(long = "master-key-env", default_value = "SHUNT_CONSOLE_MASTER_KEY")]
        master_key_env: String,
        /// Initial SuperAdmin email address.
        #[arg(long = "email")]
        email: String,
        /// Initial SuperAdmin display name.
        #[arg(long = "name", default_value = "Admin")]
        name: String,
        /// Initial SuperAdmin password (min 8 chars).
        #[arg(long = "password", env = "SHUNT_CONSOLE_ADMIN_PASSWORD")]
        password: String,
        /// Initial organization slug.
        #[arg(long = "org", default_value = "default")]
        org: String,
        /// Initial organization display name.
        #[arg(long = "org-name", default_value = "Default Organization")]
        org_name: String,
        /// Initial cluster slug.
        #[arg(long = "cluster", default_value = "prod")]
        cluster: String,
        /// Initial cluster display name.
        #[arg(long = "cluster-name", default_value = "Production")]
        cluster_name: String,
        /// Optional path to an existing `shunt.toml` to import into the initial cluster.
        #[arg(long = "import-toml")]
        import_toml: Option<std::path::PathBuf>,
    },
    /// Export a cluster's active or specific revision as a standalone redacted `shunt.toml`.
    Export {
        /// Database connection URL (`sqlite://...` or `postgres://...`).
        #[arg(
            long = "db",
            alias = "database-url",
            env = "SHUNT_CONSOLE_DATABASE_URL",
            default_value = "sqlite://./shunt-console.db"
        )]
        database_url: String,
        /// Environment variable holding the Secrets Vault Master KEK.
        #[arg(long = "master-key-env", default_value = "SHUNT_CONSOLE_MASTER_KEY")]
        master_key_env: String,
        /// Cluster slug to export.
        #[arg(long = "cluster")]
        cluster: String,
        /// Specific revision number (defaults to the cluster's latest revision).
        #[arg(long = "revision")]
        revision: Option<u64>,
    },
    /// Tamper-evident audit log maintenance commands.
    Audit {
        #[command(subcommand)]
        action: AuditCommands,
    },
}

#[derive(Subcommand, Debug)]
enum AuditCommands {
    /// Walk the hash-chained `admin_audit_log` and verify zero tampering or gaps.
    Verify {
        /// Database connection URL (`sqlite://...` or `postgres://...`).
        #[arg(
            long = "db",
            alias = "database-url",
            env = "SHUNT_CONSOLE_DATABASE_URL",
            default_value = "sqlite://./shunt-console.db"
        )]
        database_url: String,
        /// Environment variable holding the Secrets Vault Master KEK.
        #[arg(long = "master-key-env", default_value = "SHUNT_CONSOLE_MASTER_KEY")]
        master_key_env: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,tower_http=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Serve {
            listen,
            database_url,
            master_key_env,
            public_url,
            dev_cors,
            secure_cookies,
        } => {
            let store = match connect_store(&database_url, &master_key_env).await {
                Ok(s) => s,
                Err(code) => return code,
            };
            let addr: SocketAddr = match listen.parse() {
                Ok(a) => a,
                Err(err) => {
                    eprintln!("error: invalid --listen address `{listen}`: {err}");
                    return ExitCode::FAILURE;
                }
            };
            let resolved_public_url = public_url.unwrap_or_else(|| format!("http://{addr}"));
            let status = match store.system_status().await {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("error: failed to query system status: {err}");
                    return ExitCode::FAILURE;
                }
            };

            let state = AppState::new(
                Arc::clone(&store),
                resolved_public_url.clone(),
                secure_cookies,
            );
            let app = build_router(state, dev_cors);

            let listener = match TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(err) => {
                    error!(addr = %addr, error = %err, "failed to bind shunt-console listener");
                    return ExitCode::FAILURE;
                }
            };
            let bound = listener.local_addr().unwrap_or(addr);
            let url = format!("http://{bound}");

            println!();
            println!("  shunt-console v{}", status.version);
            println!("  -------------------------------------------------------");
            println!("  Console UI   : {url}");
            println!("  OpenAPI 3.1  : {url}/api/v1/openapi.json");
            println!("  Database     : {} ({database_url})", status.db_kind);
            println!("  Bundle Key   : {}", status.public_key_b64);
            if !status.initialized {
                println!("  First Run    : Open {url} to launch the Setup Wizard");
            }
            if status.ephemeral_dev_key {
                warn!(
                    "SHUNT_CONSOLE_MASTER_KEY is unset; using auto-generated local dev KEK. Set SHUNT_CONSOLE_MASTER_KEY in production."
                );
            }
            println!();

            info!(listen = %bound, "shunt-console control plane listening");
            if let Err(err) = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
            {
                error!(error = %err, "server exited with error");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Commands::Migrate {
            database_url,
            master_key_env,
        } => match connect_store(&database_url, &master_key_env).await {
            Ok(store) => {
                println!(
                    "Migrations applied successfully ({})",
                    store.db_kind().as_str()
                );
                ExitCode::SUCCESS
            }
            Err(code) => code,
        },
        Commands::Bootstrap {
            database_url,
            master_key_env,
            email,
            name,
            password,
            org,
            org_name,
            cluster,
            cluster_name,
            import_toml,
        } => {
            let imported = match import_toml {
                Some(path) => match std::fs::read_to_string(&path) {
                    Ok(content) => Some(content),
                    Err(err) => {
                        eprintln!("error: failed to read `{}`: {err}", path.display());
                        return ExitCode::FAILURE;
                    }
                },
                None => None,
            };
            let store = match connect_store(&database_url, &master_key_env).await {
                Ok(s) => s,
                Err(code) => return code,
            };
            match store
                .initial_bootstrap(InitialBootstrapInput {
                    admin_email: email,
                    admin_name: name,
                    admin_password: password,
                    org_slug: org,
                    org_name,
                    cluster_slug: cluster.clone(),
                    cluster_name,
                    environment: "production".to_owned(),
                    import_toml: imported,
                    auto_publish: true,
                })
                .await
            {
                Ok(res) => {
                    println!("Bootstrap complete!");
                    println!("  Admin Email     : {}", res.user.email);
                    println!("  Organization    : {}", res.organization.slug);
                    println!("  Cluster         : {}", res.cluster.slug);
                    println!(
                        "  Bootstrap Token : {}  (save once — never shown again)",
                        res.bootstrap_token.plaintext_token
                    );
                    println!(
                        "\nConnect a data-plane node:\n  SHUNT_NODE_TOKEN={} shunt run --control-plane http://127.0.0.1:8443 --cluster {}",
                        res.bootstrap_token.plaintext_token, cluster
                    );
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Commands::Export {
            database_url,
            master_key_env,
            cluster,
            revision,
        } => {
            let store = match connect_store(&database_url, &master_key_env).await {
                Ok(s) => s,
                Err(code) => return code,
            };
            let cls = match store.get_cluster_by_slug(&cluster).await {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            };
            let rev_num = match revision {
                Some(r) => r,
                None => match store.list_revisions(&cls.id).await {
                    Ok(revs) if !revs.is_empty() => revs[0].revision,
                    Ok(_) => {
                        eprintln!("error: cluster `{cluster}` has no published revisions");
                        return ExitCode::FAILURE;
                    }
                    Err(err) => {
                        eprintln!("error: {err}");
                        return ExitCode::FAILURE;
                    }
                },
            };
            match store.get_revision(&cls.id, rev_num).await {
                Ok(rev) => {
                    print!("{}", rev.compiled_toml);
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            }
        }
        Commands::Audit { action } => match action {
            AuditCommands::Verify {
                database_url,
                master_key_env,
            } => {
                let store = match connect_store(&database_url, &master_key_env).await {
                    Ok(s) => s,
                    Err(code) => return code,
                };
                match store.verify_admin_audit_chain().await {
                    Ok(v) => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".to_owned())
                        );
                        if v.valid {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::FAILURE
                        }
                    }
                    Err(err) => {
                        eprintln!("error: {err}");
                        ExitCode::FAILURE
                    }
                }
            }
        },
    }
}

async fn connect_store(
    database_url: &str,
    master_key_env: &str,
) -> Result<Arc<ConsoleStore>, ExitCode> {
    let master_key_encoded = std::env::var(master_key_env).ok().filter(|s| !s.is_empty());
    match ConsoleStore::connect(ConsoleStoreConfig {
        database_url: database_url.to_owned(),
        master_key_encoded,
    })
    .await
    {
        Ok(s) => Ok(Arc::new(s)),
        Err(err) => {
            eprintln!("error: failed to connect to database `{database_url}`: {err}");
            Err(ExitCode::FAILURE)
        }
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("shutdown signal received; stopping shunt-console");
}
